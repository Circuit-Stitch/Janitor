//! The concrete SSM tail (ADR 0025 §3, B4): the real `DescribeInstanceInformation`
//! / `StartSession` / `GetDocument` SDK calls and the pure-Rust Session Manager
//! transport that wires `StartSession`'s `StreamUrl` into the [`mgs`](crate::mgs)
//! data-channel driver.
//!
//! Coverage discipline (ADR 0016 / ADR 0027): the SDK calls are exercised against
//! canned HTTP (`StaticReplayClient`) and every shaping/mapping helper is pure and
//! unit-tested, so the only genuinely untested lines are the real-credential client
//! build and the live WebSocket connect + driver call (the socket shell, ADR 0010
//! §5), verified by `live-verify-ssm`.
//!
//! Nothing here logs or returns a Value: a read's bytes go straight into a
//! zeroizing [`RawSecret`]; failures mask through [`SessionError`] (THREAT-MODEL).

use std::collections::HashMap;

use async_trait::async_trait;
use base64::Engine as _;
use uuid::Uuid;

use aws_sdk_resourcegroupstagging as tagging;
use aws_sdk_ssm::config::{BehaviorVersion, Credentials, Region};
use aws_smithy_types::error::metadata::ProvideErrorMetadata;

use janitor_aws_auth::aws_impl::map_aws_err;
use janitor_aws_auth::error::SessionError;
use janitor_aws_auth::types::Credential;
use janitor_aws_auth::wire::RawSecret;

use crate::logging::{parse_logging, LoggingPreference, LoggingState};
use crate::mgs::{
    read_command_output, write_command_output, MgsError, TungsteniteChannel, WriteOutcome,
};
use crate::wire::{InstanceCatalog, InstanceSummary, RemoteFileReader, RemoteFileWriter};

/// The SSM document that runs one shell command and streams its stdout over the
/// data channel (no `SendCommand` S3 archival; ADR 0025). The session runs the
/// command through `sudo`/PAM/a PTY, which can fold banner/relay bytes into the
/// stream — [`build_read_command`] reads the file as `base64` so those bytes are
/// non-alphabet noise that [`decode_base64_output`] drops.
const NONINTERACTIVE_DOCUMENT: &str = "AWS-StartNonInteractiveCommand";
/// The SSM document that runs a command under a **pty** (ADR 0029). Unlike the
/// non-interactive document, the agent writes client `input_stream_data` to the
/// command's stdin here — the only route that lets the write stream its content
/// over the data channel (off the CloudTrail-logged `StartSession` `Parameters`).
const INTERACTIVE_DOCUMENT: &str = "AWS-StartInteractiveCommand";
/// The Session Manager preferences document that holds the org's session
/// logging/encryption config (read with `GetDocument`).
const SESSION_PREFS_DOCUMENT: &str = "SSM-SessionManagerRunShell";

/// Build a credential-scoped SSM client for `region`. Mirrors the per-call build
/// `janitor-aws` uses for `GetSecretValue` (ADR 0010 §10: explicit Credential, no
/// ambient provider). Untested shell — the SDK calls themselves are replay-tested
/// through [`client_with_replay`](tests::client_with_replay).
fn build_client(cred: &Credential, region: &str) -> aws_sdk_ssm::Client {
    let creds = Credentials::new(
        cred.access_key_id(),
        cred.secret_access_key(),
        Some(cred.session_token().to_string()),
        None,
        "janitor",
    );
    let conf = aws_sdk_ssm::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region.to_string()))
        .credentials_provider(creds)
        .build();
    aws_sdk_ssm::Client::from_conf(conf)
}

/// Build a credential-scoped Resource Groups Tagging client for `region` (mirrors
/// [`build_client`]). Used only to enrich the instance picker with EC2 `Name` tags.
fn build_tagging_client(cred: &Credential, region: &str) -> tagging::Client {
    let creds = Credentials::new(
        cred.access_key_id(),
        cred.secret_access_key(),
        Some(cred.session_token().to_string()),
        None,
        "janitor",
    );
    let conf = tagging::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region.to_string()))
        .credentials_provider(creds)
        .build();
    tagging::Client::from_conf(conf)
}

/// `DescribeInstanceInformation` (paginated) → SDK-free [`InstanceSummary`]s.
/// Replay-tested.
async fn describe_instances_with(
    client: &aws_sdk_ssm::Client,
) -> Result<Vec<InstanceSummary>, SessionError> {
    let mut out = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let resp = client
            .describe_instance_information()
            .set_next_token(next.clone())
            .send()
            .await
            .map_err(|e| map_aws_err("DescribeInstanceInformation", e))?;
        for info in resp.instance_information_list() {
            let id = info.instance_id().unwrap_or_default();
            if id.is_empty() {
                continue;
            }
            out.push(instance_summary(id, info.name(), info.computer_name()));
        }
        match resp.next_token() {
            Some(t) if !t.is_empty() => next = Some(t.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

/// `StartSession` running `command` under `document` → the data-channel
/// `(stream_url, token)`. The read uses [`NONINTERACTIVE_DOCUMENT`]; the write uses
/// [`INTERACTIVE_DOCUMENT`] (pty, ADR 0029). Replay-tested.
async fn start_session_with(
    client: &aws_sdk_ssm::Client,
    instance_id: &str,
    document: &str,
    command: String,
) -> Result<Started, SessionError> {
    let resp = client
        .start_session()
        .target(instance_id)
        .document_name(document)
        .parameters("command", vec![command])
        .send()
        .await
        .map_err(|e| map_aws_err("StartSession", e))?;
    let stream_url = resp
        .stream_url()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| SessionError::Sdk {
            context: "StartSession returned no stream url".into(),
        })?
        .to_string();
    let token_value = resp
        .token_value()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| SessionError::Sdk {
            context: "StartSession returned no token".into(),
        })?
        .to_string();
    tracing::debug!(target: "janitor::ssm", instance_id, "StartSession ok; opening data channel");
    Ok(Started {
        stream_url,
        token_value,
    })
}

/// `GetDocument(SSM-SessionManagerRunShell)` → the org's [`LoggingState`].
/// Replay-tested; the body parse is [`parse_logging`].
async fn get_logging_with(client: &aws_sdk_ssm::Client) -> Result<LoggingState, SessionError> {
    match client
        .get_document()
        .name(SESSION_PREFS_DOCUMENT)
        .send()
        .await
    {
        Ok(resp) => Ok(parse_logging(resp.content().unwrap_or_default())),
        // A *missing* prefs document is the common, benign case — an org that never
        // customized Session Manager (SSM returns `InvalidDocument`; some paths return
        // `ResourceNotFoundException`). It means "default ⇒ no logging", so route it to
        // `NotFound` at debug — which the advisory reads as "no logging" — instead of
        // through the WARN-logging error mapper, which would read as a failure.
        Err(e)
            if matches!(
                e.as_service_error().and_then(|s| s.code()),
                Some("InvalidDocument") | Some("ResourceNotFoundException")
            ) =>
        {
            tracing::debug!(target: "janitor::ssm", "no Session Manager prefs document — logging defaults to off");
            Err(SessionError::NotFound)
        }
        Err(e) => Err(map_aws_err("GetDocument", e)),
    }
}

/// The data-channel coordinates from `StartSession`.
struct Started {
    stream_url: String,
    token_value: String,
}

/// Friendly name for an Instance: the node `Name`, else the `ComputerName`, else
/// the instance id (so the label never reads `i-… (i-…)`). Pure.
fn instance_summary(id: &str, name: Option<&str>, computer_name: Option<&str>) -> InstanceSummary {
    let friendly = name
        .filter(|s| !s.is_empty())
        .or_else(|| computer_name.filter(|s| !s.is_empty()))
        .unwrap_or(id);
    InstanceSummary {
        id: id.to_string(),
        name: friendly.to_string(),
    }
}

/// Best-effort EC2 `Name` tags by instance id, via the Resource Groups Tagging API
/// (`tag:GetResources`). SSM's `DescribeInstanceInformation` never returns EC2 tags,
/// so without this the picker shows the host's `ComputerName`
/// (`ip-….compute.internal`) rather than the console "Name". **Any failure returns an
/// empty map** — the role may lack `tag:GetResources`, and names are a convenience
/// that must never break Discovery (a Value is never involved either way).
///
/// ponytail: filters to all `ec2:instance`s carrying a `Name` tag, then the caller
///           joins by id (GetResources can't filter to a specific id set). Fine for
///           the handful an SSM picker shows; revisit if an account has thousands.
async fn name_tags_with(client: &tagging::Client) -> HashMap<String, String> {
    let mut names = HashMap::new();
    let mut token: Option<String> = None;
    loop {
        let resp = match client
            .get_resources()
            .resource_type_filters("ec2:instance")
            .tag_filters(tagging::types::TagFilter::builder().key("Name").build())
            .set_pagination_token(token.clone())
            .send()
            .await
        {
            Ok(r) => r,
            // Best-effort: keep whatever we collected (often nothing). Surface the
            // real (error-safe) AWS code at WARN via the shared mapper — exactly like
            // every other SDK call (e.g. GetDocument) — so the Diagnostic Log shows
            // whether this is still AccessDenied (permission not yet provisioned) or a
            // different error, then add a human-readable INFO hint.
            Err(e) => {
                let _ = map_aws_err("GetResources", e);
                tracing::info!(target: "janitor::ssm", "EC2 Name-tag lookup unavailable — grant tag:GetResources to show console names");
                break;
            }
        };
        for m in resp.resource_tag_mapping_list() {
            let Some(id) = m.resource_arn().and_then(instance_id_from_arn) else {
                continue;
            };
            if let Some(name) = m
                .tags()
                .iter()
                .find(|t| t.key() == "Name")
                .map(|t| t.value())
            {
                if !name.is_empty() {
                    names.insert(id.to_string(), name.to_string());
                }
            }
        }
        match resp.pagination_token() {
            Some(t) if !t.is_empty() => token = Some(t.to_string()),
            _ => break,
        }
    }
    names
}

/// Extract the instance id from an EC2 instance ARN
/// (`arn:aws:ec2:<region>:<acct>:instance/i-0abc…`). Pure.
fn instance_id_from_arn(arn: &str) -> Option<&str> {
    let (prefix, id) = arn.rsplit_once('/')?;
    (prefix.ends_with(":instance") && id.starts_with("i-")).then_some(id)
}

/// Overlay best-effort EC2 `Name` tags onto the SSM summaries: a present tag wins
/// over the `ComputerName` fallback (it is what the AWS console shows). Pure.
fn apply_name_tags(
    mut items: Vec<InstanceSummary>,
    names: &HashMap<String, String>,
) -> Vec<InstanceSummary> {
    for it in &mut items {
        if let Some(name) = names.get(&it.id) {
            it.name = name.clone();
        }
    }
    items
}

/// The remote read command. A Session Manager session runs as the unprivileged
/// `ssm-user`, which cannot read a root-owned `600` secrets file, so we read via
/// passwordless `sudo` (the SSM agent grants `ssm-user` NOPASSWD sudo by default),
/// falling back to a plain read where the file is already readable without it:
///
/// ```text
/// sudo -n sh -c 'base64 -- '\''<path>'\''' 2>/dev/null || sh -c 'base64 -- '\''<path>'\'''
/// ```
///
/// **Why `base64`.** The SSM session runs the command through `sudo`/PAM/a PTY,
/// which can fold in banner/relay bytes and mangle a raw `cat` of binary or CRLF
/// content (live-verified: a 3.5 KB file came back as ~44 KB of mixed text+binary —
/// ADR 0025 §3). `base64`'s output alphabet (`A–Za–z0–9+/=`) excludes every
/// control/high-bit byte, so [`decode_base64_output`] keeps only those bytes and
/// decodes strictly: any banner noise is dropped, and a corrupt/aborted read fails
/// the decode (masked) instead of being parsed as a truncated `.env`.
///
/// `sudo -n` is non-interactive — if sudo is disallowed it fails immediately (never
/// hangs for a password), and its `2>/dev/null` keeps that message off the stream so
/// the `||` fallback runs. `sh -c` isolates the command so the session adds no noise
/// (verified). `--` stops option parsing (a path starting with `-` is safe) and
/// single-quoting handles spaces/metacharacters. Pure.
fn build_read_command(path: &str) -> String {
    let inner = format!("base64 -- {}", shell_single_quote(path));
    let inner_q = shell_single_quote(&inner);
    format!("sudo -n sh -c {inner_q} 2>/dev/null || sh -c {inner_q}")
}

/// Decode the remote `base64` stream back to the file's bytes. Keeps only the
/// standard base64 alphabet — dropping the line wraps `base64` inserts and any
/// non-alphabet banner noise the session might add — then decodes strictly, so a
/// truncated/garbled read surfaces as `Err` rather than a silently-wrong `.env`.
/// Pure (no Value ever logged — the decoded bytes flow straight into a zeroizing
/// `RawSecret`).
fn decode_base64_output(raw: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    let filtered: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        .collect();
    base64::engine::general_purpose::STANDARD.decode(filtered)
}

/// POSIX single-quote a string: wrap in `'…'`, rendering any embedded `'` as the
/// `'\''` idiom. Pure.
fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Build the remote **write** command (ADR 0029): tame the pty, then a single
/// `sudo -n sh -c` script that does the `sha256`-guarded (ADR 0001 CAS) atomic
/// replace, reading exactly `n` bytes of base64 from stdin:
///
/// ```text
/// stty raw -echo -isig 2>/dev/null; sudo -n sh -c '<script>'
/// ```
///
/// **Why `stty raw -echo -isig`.** The interactive document runs under a pty; raw,
/// no-echo, no-ISIG mode stops the line discipline from echoing our streamed bytes
/// back, cooking CR/LF, enforcing the `MAX_CANON` line limit, or interpreting
/// control chars — so the base64 passes through verbatim.
///
/// **Why `head -c n`.** It reads *exactly* `n` bytes (`n` = the base64 length, not
/// secret) then closes the pipe, so `base64 -d` sees EOF deterministically — no
/// reliance on tty `Ctrl-D`/`VEOF` (mode-dependent and fragile).
///
/// **CAS + atomic replace.** `sha256sum` must equal `expected_sha256` (the file as
/// read) or the command prints `JANITOR_CONFLICT` and exits before writing;
/// otherwise the new content is decoded into a temp file **co-located in the
/// target's own directory**, given the target's owner/mode (`--reference`, with a
/// `stat -c` fallback for an image lacking it), then `mv -f` atomically replaces and
/// prints `JANITOR_OK`. `sudo -n` only — the stdin is consumed once, so there is no
/// non-sudo `||` fallback to re-read it (root-owned `600` files need sudo anyway).
///
/// Three subtleties, each a real correctness fix:
/// - **`sha256sum < PATH`, not `sha256sum -- PATH`.** GNU `sha256sum` *escapes* a
///   filename containing a backslash or newline (prepending a `\` to the output
///   line), which `cut` would then return as part of the "hash" — so the CAS would
///   never match and every write to such a path would false-conflict. Reading the
///   file on stdin emits `<hash>  -` (no filename), so the digest is clean for any
///   path. The redirect is local to the command-substitution subshell, so it does
///   **not** consume the pty stdin the later `head -c N` reads.
/// - **`mktemp` in the target's directory.** A default `mktemp` lands in `/tmp`
///   (often a separate filesystem / tmpfs), which makes `mv` a non-atomic
///   copy-then-unlink — a reader could see a partial file. Co-locating the temp
///   (`mktemp -- "$(dirname PATH)/.janitor.XXXXXX"`) keeps `mv` a same-filesystem
///   atomic rename. A `trap … EXIT` removes the temp on any failure (after a
///   successful `mv` it is already gone, so the `rm` is a harmless no-op).
/// - **Split status-token literals.** The emitted tokens are `JANITOR_OK` /
///   `JANITOR_CONFLICT`, but the command *source* writes them split
///   (`printf "…JANITOR""_OK…"`) so the command body itself never contains the
///   contiguous token — defense-in-depth, so even if the agent ever folded the
///   command text into stdout the [`super::mgs`] token scan could not false-positive.
///
/// Single-quoting (twice — once for the path inside the script, once for the whole
/// script under `sh -c`) follows [`build_read_command`]. Pure; `expected_sha256`
/// (hex) and `n` are not secret, and the file content rides stdin, never here.
fn build_write_command(path: &str, expected_sha256: &str, n: usize) -> String {
    let p = shell_single_quote(path);
    // One line, `;`-separated, so the command parameter carries no embedded newline.
    let script = format!(
        "cur=$(sha256sum < {p} | cut -d\" \" -f1); \
         [ \"$cur\" = \"{expected_sha256}\" ] || {{ printf \"\\nJANITOR\"\"_CONFLICT\\n\"; exit 3; }}; \
         t=$(mktemp -- \"$(dirname -- {p})/.janitor.XXXXXX\") || exit 1; \
         trap 'rm -f \"$t\" 2>/dev/null' EXIT; \
         head -c {n} | base64 -d > \"$t\" || exit 1; \
         {{ chown --reference={p} \"$t\" || chown \"$(stat -c %u:%g {p})\" \"$t\"; }} && \
         {{ chmod --reference={p} \"$t\" || chmod \"$(stat -c %a {p})\" \"$t\"; }} || exit 1; \
         mv -f \"$t\" {p} && printf \"\\nJANITOR\"\"_OK\\n\""
    );
    let script_q = shell_single_quote(&script);
    format!("stty raw -echo -isig 2>/dev/null; sudo -n sh -c {script_q}")
}

/// Base64-encode the new file content for streaming over the data channel into the
/// remote `head -c N | base64 -d` (ADR 0029). The standard alphabet's bytes survive
/// the pty intact. Returns the ASCII base64 bytes (what we stream); the count is
/// the `N` the write command reads. The result encodes secret bytes, so the caller
/// holds it zeroizing. Pure.
fn encode_file_base64(content: &[u8]) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .encode(content)
        .into_bytes()
}

/// Map a masked [`MgsError`] onto the shared [`SessionError`] taxonomy. The masked
/// port hides the category, so log it here for the live harness — the `MgsError`
/// variants carry only structural context (a fixed label), never a payload, so the
/// `Display` is error-safe.
fn mgs_error_to_session(e: MgsError) -> SessionError {
    tracing::warn!(target: "janitor::ssm", "ssm read failed — {e}");
    match e {
        MgsError::KmsEncryptionUnsupported => SessionError::Unsupported,
        // A non-zero `cat` (missing/denied path) reads as "no readable file there".
        MgsError::CommandFailed => SessionError::NotFound,
        MgsError::Channel(_) | MgsError::Protocol(_) | MgsError::ClosedEarly => SessionError::Sdk {
            context: "ssm data channel".into(),
        },
    }
}

/// Map a masked write-side [`MgsError`] onto [`SessionError`] (ADR 0029). Unlike a
/// read, a `CommandFailed` here is "the command ran but confirmed no token" (e.g.
/// `sudo`/`mktemp` failed) — a write failure, not a missing file — so it maps to a
/// generic masked `Sdk` error rather than `NotFound`. (A `JANITOR_CONFLICT` is a
/// successful [`WriteOutcome::Conflict`], never an error.)
fn mgs_write_error_to_session(e: MgsError) -> SessionError {
    tracing::warn!(target: "janitor::ssm", "ssm write failed — {e}");
    match e {
        MgsError::KmsEncryptionUnsupported => SessionError::Unsupported,
        MgsError::Channel(_)
        | MgsError::Protocol(_)
        | MgsError::ClosedEarly
        | MgsError::CommandFailed => SessionError::Sdk {
            context: "ssm write".into(),
        },
    }
}

/// A byte-category census of a raw read, used by the diagnostic trace to tell a
/// text-with-stray-bytes read apart from a binary/encrypted one. `first_invalid_utf8`
/// is the byte offset where UTF-8 decoding first fails (`None` if valid). Pure;
/// carries only counts/offsets, never bytes (THREAT-MODEL).
#[derive(Debug, PartialEq, Eq)]
struct ByteCensus {
    printable: usize,
    whitespace: usize,
    control: usize,
    high_bit: usize,
    first_invalid_utf8: Option<usize>,
}

fn byte_census(bytes: &[u8]) -> ByteCensus {
    let (mut printable, mut whitespace, mut control, mut high_bit) = (0, 0, 0, 0);
    for &b in bytes {
        match b {
            b'\t' | b'\n' | b'\r' => whitespace += 1,
            0x20..=0x7e => printable += 1,
            0x80..=0xff => high_bit += 1,
            _ => control += 1,
        }
    }
    ByteCensus {
        printable,
        whitespace,
        control,
        high_bit,
        first_invalid_utf8: std::str::from_utf8(bytes).err().map(|e| e.valid_up_to()),
    }
}

/// Structural trace of the raw command output, for the live harness to diagnose a
/// non-UTF-8 / unexpectedly-large read **without logging content** (THREAT-MODEL):
/// only the [`ByteCensus`] (counts + the offset where UTF-8 first fails) — never a
/// byte of the payload. A first-invalid offset near the file's real size means clean
/// text followed by trailing garbage; a high `high_bit`/`control` share means binary/
/// encrypted output. Logged at `debug` on every read (the census is content-free, so
/// it needs no opt-in) under the `janitor::ssm` target the live harness already shows.
fn diag_raw_bytes(bytes: &[u8]) {
    let c = byte_census(bytes);
    tracing::debug!(
        target: "janitor::ssm",
        len = bytes.len(),
        printable = c.printable,
        whitespace = c.whitespace,
        control = c.control,
        high_bit = c.high_bit,
        first_invalid_utf8 = ?c.first_invalid_utf8,
        "diag raw read"
    );
}

/// Wrap the command's stdout bytes as a [`RawSecret`]: valid UTF-8 (a `.env` is
/// text) becomes `secret_string`; anything else becomes opaque `secret_binary`
/// (`Unsupported` downstream). Pure.
fn raw_from_bytes(bytes: Vec<u8>) -> RawSecret {
    match String::from_utf8(bytes) {
        Ok(text) => RawSecret {
            secret_string: Some(text),
            secret_binary: None,
        },
        Err(e) => RawSecret {
            secret_string: None,
            secret_binary: Some(e.into_bytes()),
        },
    }
}

/// Epoch-millis now, for the outgoing AgentMessage timestamps (coerced non-zero in
/// the driver). The single real-clock read in this crate's transport.
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1)
}

/// `DescribeInstanceInformation`-backed [`InstanceCatalog`].
pub struct AwsInstanceCatalog;

#[async_trait]
impl InstanceCatalog for AwsInstanceCatalog {
    async fn describe_instances(
        &self,
        cred: &Credential,
        region: &str,
    ) -> Result<Vec<InstanceSummary>, SessionError> {
        let items = describe_instances_with(&build_client(cred, region)).await?;
        // Enrich with EC2 `Name` tags (best-effort — empty map on any failure).
        let names = name_tags_with(&build_tagging_client(cred, region)).await;
        tracing::info!(target: "janitor::ssm", matched = names.len(), instances = items.len(), "EC2 Name-tag enrichment");
        Ok(apply_name_tags(items, &names))
    }
}

/// Session-Manager-backed [`RemoteFileReader`]: `StartSession` → the MGS data
/// channel → the command's stdout. The `StartSession` SDK call and all the
/// protocol logic are tested; only the live WebSocket connect + driver call are
/// the untested shell.
pub struct SsmFileReader;

#[async_trait]
impl RemoteFileReader for SsmFileReader {
    async fn read_file(
        &self,
        cred: &Credential,
        instance_id: &str,
        region: &str,
        path: &str,
    ) -> Result<RawSecret, SessionError> {
        let client = build_client(cred, region);
        let started = start_session_with(
            &client,
            instance_id,
            NONINTERACTIVE_DOCUMENT,
            build_read_command(path),
        )
        .await?;
        let mut channel = TungsteniteChannel::connect(&started.stream_url)
            .await
            .map_err(mgs_error_to_session)?;
        let raw = read_command_output(
            &mut channel,
            &started.token_value,
            Uuid::new_v4(),
            &now_millis,
        )
        .await
        .map_err(mgs_error_to_session)?;
        diag_raw_bytes(&raw);
        // Decode the base64 stream back to the file's bytes, dropping any session
        // banner noise (ADR 0025 §3). A decode failure ⇒ a corrupt/aborted read:
        // surface it masked rather than parsing garbage as a `.env`.
        let content = decode_base64_output(&raw).map_err(|_| {
            tracing::warn!(target: "janitor::ssm", "ssm read base64 decode failed — incomplete read");
            SessionError::Sdk {
                context: "ssm read decode".into(),
            }
        })?;
        tracing::debug!(target: "janitor::ssm", bytes = content.len(), "ssm read decoded");
        Ok(raw_from_bytes(content))
    }
}

/// Session-Manager-backed [`RemoteFileWriter`] (ADR 0029): `StartSession` on the
/// **interactive** document → the MGS data channel → stream the base64 content into
/// the `sha256`-guarded atomic replace → the typed [`WriteOutcome`]. The
/// `StartSession` SDK call and all the protocol logic are tested; only the live
/// WebSocket connect + driver call are the untested shell.
pub struct SsmFileWriter;

#[async_trait]
impl RemoteFileWriter for SsmFileWriter {
    async fn write_file(
        &self,
        cred: &Credential,
        instance_id: &str,
        region: &str,
        path: &str,
        expected_sha256: &str,
        content: &[u8],
    ) -> Result<WriteOutcome, SessionError> {
        // Base64-encode in a zeroizing buffer (it encodes the secret file). `n` (its
        // length) is the non-secret byte count the remote `head -c n` reads.
        let b64 = zeroize::Zeroizing::new(encode_file_base64(content));
        let n = b64.len();
        let command = build_write_command(path, expected_sha256, n);
        let client = build_client(cred, region);
        let started =
            start_session_with(&client, instance_id, INTERACTIVE_DOCUMENT, command).await?;
        let mut channel = TungsteniteChannel::connect(&started.stream_url)
            .await
            .map_err(mgs_write_error_to_session)?;
        write_command_output(
            &mut channel,
            &started.token_value,
            Uuid::new_v4(),
            b64.to_vec(),
            &now_millis,
        )
        .await
        .map_err(mgs_write_error_to_session)
    }
}

/// `GetDocument`-backed [`LoggingPreference`].
pub struct AwsLoggingPreference;

#[async_trait]
impl LoggingPreference for AwsLoggingPreference {
    async fn session_logging(
        &self,
        cred: &Credential,
        region: &str,
    ) -> Result<LoggingState, SessionError> {
        get_logging_with(&build_client(cred, region)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- pure helpers ----

    #[test]
    fn instance_summary_prefers_name_then_computer_name_then_id() {
        assert_eq!(
            instance_summary("i-1", Some("web"), Some("host")).name,
            "web"
        );
        assert_eq!(
            instance_summary("i-1", Some(""), Some("host")).name,
            "host",
            "empty Name falls back to ComputerName"
        );
        assert_eq!(
            instance_summary("i-1", None, None).name,
            "i-1",
            "neither set falls back to the id"
        );
    }

    #[test]
    fn instance_id_from_arn_extracts_only_instance_arns() {
        assert_eq!(
            instance_id_from_arn("arn:aws:ec2:us-west-2:123456789012:instance/i-0abc"),
            Some("i-0abc")
        );
        // Not an instance ARN (e.g. a volume) → None, so a stray tag can't mis-map.
        assert_eq!(
            instance_id_from_arn("arn:aws:ec2:us-west-2:123456789012:volume/vol-0abc"),
            None
        );
        assert_eq!(instance_id_from_arn("not-an-arn"), None);
    }

    #[test]
    fn apply_name_tags_overrides_computer_name_but_leaves_unmatched() {
        let items = vec![
            InstanceSummary {
                id: "i-0abc".into(),
                name: "ip-10-0-0-1.compute.internal".into(),
            },
            InstanceSummary {
                id: "i-0def".into(),
                name: "ip-10-0-0-2.compute.internal".into(),
            },
        ];
        let names = HashMap::from([("i-0abc".to_string(), "deferno-prod".to_string())]);
        let got = apply_name_tags(items, &names);
        assert_eq!(got[0].name, "deferno-prod", "the Name tag wins");
        assert_eq!(
            got[1].name, "ip-10-0-0-2.compute.internal",
            "no tag → unchanged"
        );
    }

    #[test]
    fn read_command_is_a_sudo_base64_with_a_fallback() {
        let cmd = build_read_command("/app/.env");
        // Exact shape: `base64 -- '<path>'`, single-quoted for `sh -c` (so the
        // path's own quotes become the '\'' idiom), run under sudo with a non-sudo
        // `||` fallback.
        let inner_q = shell_single_quote("base64 -- '/app/.env'");
        assert!(
            inner_q.contains("'\\''/app/.env'\\''"),
            "path quotes escaped once more"
        );
        assert_eq!(
            cmd,
            format!("sudo -n sh -c {inner_q} 2>/dev/null || sh -c {inner_q}")
        );
        // The path text is embedded (a space cannot word-split it), and `base64 --`
        // guards a leading '-'.
        assert!(build_read_command("/a b/.env").contains("/a b/.env"));
        assert!(build_read_command("-rf").contains("base64 -- "));
        assert!(build_read_command("-rf").contains("-rf"));
    }

    #[test]
    fn decode_base64_output_recovers_the_file_and_drops_noise() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"A=1\nB=two\n");
        // A plain stream decodes back to the file.
        assert_eq!(
            decode_base64_output(b64.as_bytes()).unwrap(),
            b"A=1\nB=two\n"
        );
        // Line wraps (base64 wraps at 76 cols) and stray control/high-bit banner
        // noise are filtered out before the strict decode.
        let mut noisy = vec![0x1b, b'['];
        for (i, ch) in b64.bytes().enumerate() {
            noisy.push(ch);
            if i % 8 == 7 {
                noisy.push(b'\n'); // pretend wrapping
            }
        }
        noisy.extend_from_slice(&[0x00, 0xff, 0x1b]); // trailing binary junk
        assert_eq!(decode_base64_output(&noisy).unwrap(), b"A=1\nB=two\n");
        // Empty file → empty base64 → empty bytes.
        assert_eq!(decode_base64_output(b"").unwrap(), b"");
        // A truncated/garbled stream fails the strict decode (masked, not parsed).
        assert!(decode_base64_output(b"QQ").is_err()); // 2 chars, no padding → invalid
    }

    #[test]
    fn mgs_errors_map_to_masked_session_errors() {
        assert!(matches!(
            mgs_error_to_session(MgsError::KmsEncryptionUnsupported),
            SessionError::Unsupported
        ));
        assert!(matches!(
            mgs_error_to_session(MgsError::CommandFailed),
            SessionError::NotFound
        ));
        let leak = mgs_error_to_session(MgsError::Protocol("SECRET=hunter2".into()));
        // The masked SessionError must not carry the protocol detail string.
        assert!(!format!("{leak}").contains("hunter2"));
    }

    #[test]
    fn write_command_is_a_stty_sudo_cas_atomic_replace() {
        let cmd = build_write_command("/app/.env", "abc123", 128);
        // Tames the pty, runs under sudo -n, reads exactly N bytes, CAS-guards on the
        // expected hash, decodes base64, and replaces atomically — printing tokens.
        assert!(cmd.starts_with("stty raw -echo -isig 2>/dev/null; sudo -n sh -c "));
        for needle in [
            "sha256sum < ", // stdin redirect (no filename to escape) — not `--`
            "\"$cur\" =",   // the CAS comparison
            "abc123",       // against the expected hash
            "head -c 128",
            "base64 -d",
            "mktemp -- ",
            "dirname -- ", // temp co-located in the target's dir (atomic mv)
            "trap ",       // cleanup of the temp on any failure
            "--reference=",
            "stat -c %u:%g", // the chown fallback
            "stat -c %a",    // the chmod fallback
            "mv -f",
        ] {
            assert!(cmd.contains(needle), "command missing {needle:?}:\n{cmd}");
        }
        // The path is embedded (single-quoted, double-nested for `sh -c`) and a
        // path that would word-split or look like a flag is safe.
        assert!(build_write_command("/a b/.env", "h", 1).contains("/a b/.env"));
        assert!(build_write_command("-rf", "h", 1).contains("-rf"));
        // No raw newline in the command (it must ride one Parameters value cleanly).
        assert!(!cmd.contains('\n'), "the command must be a single line");
    }

    #[test]
    fn write_command_body_cannot_false_positive_the_token_scan() {
        // The emitted tokens are JANITOR_OK / JANITOR_CONFLICT, but the command
        // SOURCE writes them split (printf "…JANITOR""_OK…"), so the command body
        // itself contains NEITHER contiguous token — defense-in-depth, so even if the
        // agent ever echoed the command text into stdout the token scan (which looks
        // for the contiguous token) could not mis-report a result.
        let cmd = build_write_command("/app/.env", "abc123", 1);
        assert!(
            !cmd.contains("JANITOR_OK"),
            "the command body must not contain the contiguous OK token"
        );
        assert!(
            !cmd.contains("JANITOR_CONFLICT"),
            "the command body must not contain the contiguous CONFLICT token"
        );
        // …but it does carry the split pieces that printf concatenates at runtime.
        assert!(cmd.contains("JANITOR\"\"_OK"));
        assert!(cmd.contains("JANITOR\"\"_CONFLICT"));
    }

    #[test]
    fn encode_file_base64_round_trips_through_the_read_decoder() {
        // What we stream (base64) must decode back to the file via the read path's
        // strict decoder — the two halves of the wire format agree.
        for content in [b"A=1\nB=two\n".as_slice(), b"".as_slice(), &[0u8, 159, 200]] {
            let b64 = encode_file_base64(content);
            assert_eq!(decode_base64_output(&b64).unwrap(), content);
        }
    }

    #[test]
    fn write_mgs_errors_map_to_masked_session_errors() {
        assert!(matches!(
            mgs_write_error_to_session(MgsError::KmsEncryptionUnsupported),
            SessionError::Unsupported
        ));
        // CommandFailed on write is a write failure (Sdk), NOT NotFound (unlike read).
        assert!(matches!(
            mgs_write_error_to_session(MgsError::CommandFailed),
            SessionError::Sdk { .. }
        ));
        let leak = mgs_write_error_to_session(MgsError::Protocol("SECRET=hunter2".into()));
        assert!(!format!("{leak}").contains("hunter2"));
    }

    #[test]
    fn byte_census_categorizes_and_finds_first_invalid_utf8() {
        // Clean ASCII text: all printable/whitespace, valid UTF-8.
        let text = byte_census(b"A=1\nB=two\n");
        assert_eq!(
            text,
            ByteCensus {
                printable: 8,
                whitespace: 2,
                control: 0,
                high_bit: 0,
                first_invalid_utf8: None,
            }
        );
        // Text then a stray invalid byte: the offset points at the real content's
        // end (the signature of clean text followed by trailing garbage).
        let trailing = byte_census(b"A=1\n\xff\xfe");
        assert_eq!(trailing.high_bit, 2);
        assert_eq!(trailing.first_invalid_utf8, Some(4));
        // A NUL/control byte counts as control, not printable.
        assert_eq!(byte_census(b"\x00\x07").control, 2);
    }

    #[test]
    fn raw_from_bytes_splits_text_from_binary() {
        let text = raw_from_bytes(b"A=1".to_vec());
        assert_eq!(text.secret_string.as_deref(), Some("A=1"));
        let bin = raw_from_bytes(vec![0xff, 0xfe, 0x00]);
        assert!(bin.secret_string.is_none());
        assert!(bin.secret_binary.is_some());
    }

    // ---- replay-tested SDK seams (StaticReplayClient, ADR 0027) ----

    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    /// An awsJson1.1 200 response carrying `body`.
    fn ok_json(body: &str) -> ReplayEvent {
        ReplayEvent::new(
            http::Request::builder()
                .uri("https://replay.test/")
                .body(SdkBody::empty())
                .unwrap(),
            http::Response::builder()
                .status(200)
                .header("content-type", "application/x-amz-json-1.1")
                .body(SdkBody::from(body.to_owned()))
                .unwrap(),
        )
    }

    /// An awsJson1.1 error response: the SDK resolves the code from
    /// `x-amzn-errortype`, which `map_aws_err`/`classify_aws` switch on.
    fn err_json(status: u16, code: &str) -> ReplayEvent {
        ReplayEvent::new(
            http::Request::builder()
                .uri("https://replay.test/")
                .body(SdkBody::empty())
                .unwrap(),
            http::Response::builder()
                .status(status)
                .header("content-type", "application/x-amz-json-1.1")
                .header("x-amzn-errortype", code)
                .body(SdkBody::from(format!(
                    "{{\"__type\":\"{code}\",\"message\":\"{code} (replayed)\"}}"
                )))
                .unwrap(),
        )
    }

    fn client_with_replay(events: Vec<ReplayEvent>) -> aws_sdk_ssm::Client {
        let creds = Credentials::new("ak", "sk", Some("st".into()), None, "test");
        let conf = aws_sdk_ssm::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(creds)
            .http_client(StaticReplayClient::new(events))
            .retry_config(aws_smithy_types::retry::RetryConfig::disabled())
            .build();
        aws_sdk_ssm::Client::from_conf(conf)
    }

    fn tagging_client_with_replay(events: Vec<ReplayEvent>) -> tagging::Client {
        let creds = Credentials::new("ak", "sk", Some("st".into()), None, "test");
        let conf = tagging::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(creds)
            .http_client(StaticReplayClient::new(events))
            .retry_config(aws_smithy_types::retry::RetryConfig::disabled())
            .build();
        tagging::Client::from_conf(conf)
    }

    #[tokio::test]
    async fn name_tags_maps_instance_arns_to_their_name_tag() {
        let body = r#"{"ResourceTagMappingList":[
            {"ResourceARN":"arn:aws:ec2:us-west-2:111:instance/i-0abc","Tags":[{"Key":"Name","Value":"deferno-prod"},{"Key":"env","Value":"prod"}]},
            {"ResourceARN":"arn:aws:ec2:us-west-2:111:instance/i-0def","Tags":[{"Key":"Name","Value":""}]}
        ]}"#;
        let names = name_tags_with(&tagging_client_with_replay(vec![ok_json(body)])).await;
        assert_eq!(
            names.get("i-0abc").map(String::as_str),
            Some("deferno-prod")
        );
        assert!(
            !names.contains_key("i-0def"),
            "an empty Name tag is dropped"
        );
    }

    #[tokio::test]
    async fn name_tags_is_empty_when_the_lookup_is_denied() {
        // Best-effort: a missing `tag:GetResources` yields an empty map, never an error.
        let names = name_tags_with(&tagging_client_with_replay(vec![err_json(
            400,
            "AccessDeniedException",
        )]))
        .await;
        assert!(names.is_empty());
    }

    #[tokio::test]
    async fn describe_instances_maps_the_list() {
        let body = r#"{"InstanceInformationList":[
            {"InstanceId":"i-0abc","ComputerName":"host-a","Name":"web"},
            {"InstanceId":"i-0def","ComputerName":"host-b","Name":""}
        ]}"#;
        let got = describe_instances_with(&client_with_replay(vec![ok_json(body)]))
            .await
            .unwrap();
        assert_eq!(
            got,
            vec![
                InstanceSummary {
                    id: "i-0abc".into(),
                    name: "web".into()
                },
                InstanceSummary {
                    id: "i-0def".into(),
                    name: "host-b".into()
                },
            ]
        );
    }

    #[tokio::test]
    async fn describe_instances_maps_access_denied() {
        let err = describe_instances_with(&client_with_replay(vec![err_json(
            400,
            "AccessDeniedException",
        )]))
        .await
        .unwrap_err();
        assert!(matches!(err, SessionError::AccessDenied));
    }

    #[tokio::test]
    async fn start_session_extracts_stream_url_and_token() {
        let body =
            r#"{"SessionId":"s-1","StreamUrl":"wss://ssm.example/data","TokenValue":"tok-xyz"}"#;
        let started = start_session_with(
            &client_with_replay(vec![ok_json(body)]),
            "i-0abc",
            NONINTERACTIVE_DOCUMENT,
            "cat -- '/app/.env'".into(),
        )
        .await
        .unwrap();
        assert_eq!(started.stream_url, "wss://ssm.example/data");
        assert_eq!(started.token_value, "tok-xyz");
    }

    #[tokio::test]
    async fn start_session_without_a_stream_url_is_an_sdk_error() {
        let body = r#"{"SessionId":"s-1","TokenValue":"tok"}"#;
        // `Started` holds the session token, so it is intentionally non-`Debug`
        // (no `unwrap_err`): match on the result instead.
        let result = start_session_with(
            &client_with_replay(vec![ok_json(body)]),
            "i-0abc",
            INTERACTIVE_DOCUMENT,
            "stty raw; sudo -n sh -c '…'".into(),
        )
        .await;
        assert!(matches!(result, Err(SessionError::Sdk { .. })));
    }

    #[tokio::test]
    async fn get_document_parses_logging_preferences() {
        // GetDocument's Content is a JSON *string* (escaped) inside the response.
        let content =
            r#"{"inputs":{"s3BucketName":"logs","cloudWatchLogGroupName":"","kmsKeyId":""}}"#;
        let body = serde_json::json!({
            "Name": SESSION_PREFS_DOCUMENT,
            "DocumentType": "Session",
            "Content": content,
        })
        .to_string();
        let state = get_logging_with(&client_with_replay(vec![ok_json(&body)]))
            .await
            .unwrap();
        assert_eq!(
            state,
            LoggingState {
                s3: true,
                cloudwatch: false,
                kms: false
            }
        );
    }

    #[tokio::test]
    async fn get_document_absent_is_not_found() {
        // SSM returns `InvalidDocument` for a missing document; older/other paths use
        // `ResourceNotFoundException`. Both mean "no prefs ⇒ no logging" → NotFound
        // (routed at debug, not the WARN mapper, so the panel shows no failure).
        for code in ["InvalidDocument", "ResourceNotFoundException"] {
            let err = get_logging_with(&client_with_replay(vec![err_json(400, code)]))
                .await
                .unwrap_err();
            assert!(matches!(err, SessionError::NotFound), "{code} → NotFound");
        }
    }
}
