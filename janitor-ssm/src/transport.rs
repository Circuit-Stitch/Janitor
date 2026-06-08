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

use async_trait::async_trait;
use base64::Engine as _;
use uuid::Uuid;

use aws_sdk_ssm::config::{BehaviorVersion, Credentials, Region};

use janitor_aws_auth::aws_impl::map_aws_err;
use janitor_aws_auth::error::SessionError;
use janitor_aws_auth::types::Credential;
use janitor_aws_auth::wire::RawSecret;

use crate::logging::{parse_logging, LoggingPreference, LoggingState};
use crate::mgs::{read_command_output, MgsError, TungsteniteChannel};
use crate::wire::{InstanceCatalog, InstanceSummary, RemoteFileReader};

/// The SSM document that runs one shell command and streams its stdout over the
/// data channel (no `SendCommand` S3 archival; ADR 0025). The session runs the
/// command through `sudo`/PAM/a PTY, which can fold banner/relay bytes into the
/// stream — [`build_read_command`] reads the file as `base64` so those bytes are
/// non-alphabet noise that [`decode_base64_output`] drops.
const NONINTERACTIVE_DOCUMENT: &str = "AWS-StartNonInteractiveCommand";
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

/// `StartSession` for a one-shot `cat` → the data-channel `(stream_url, token)`.
/// Replay-tested.
async fn start_session_with(
    client: &aws_sdk_ssm::Client,
    instance_id: &str,
    command: String,
) -> Result<Started, SessionError> {
    let resp = client
        .start_session()
        .target(instance_id)
        .document_name(NONINTERACTIVE_DOCUMENT)
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
    let resp = client
        .get_document()
        .name(SESSION_PREFS_DOCUMENT)
        .send()
        .await
        .map_err(|e| map_aws_err("GetDocument", e))?;
    Ok(parse_logging(resp.content().unwrap_or_default()))
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
        describe_instances_with(&build_client(cred, region)).await
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
        let started = start_session_with(&client, instance_id, build_read_command(path)).await?;
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
            "cat -- '/x'".into(),
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
        let err = get_logging_with(&client_with_replay(vec![err_json(
            400,
            "ResourceNotFoundException",
        )]))
        .await
        .unwrap_err();
        assert!(matches!(err, SessionError::NotFound));
    }
}
