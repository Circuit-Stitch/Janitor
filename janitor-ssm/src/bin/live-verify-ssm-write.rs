//! Human-gated live verification of the remote-`.env`-over-SSM **write** path
//! (ADR 0029, B5 / #70). Run by a human against a real Identity Center org with at
//! least one SSM-managed EC2 instance whose `.env` you are willing to edit:
//!
//!   cargo run -p janitor-ssm --bin live-verify-ssm-write
//!
//! It mirrors `live-verify-ssm` (the read harness) but drives the **write**: browser
//! Sign-in → the guided [`SsmDiscovery`] walk (account → role → mint → instance →
//! free-text `.env` path) → prompt for a few surgical edits → read-modify-write over
//! the interactive (pty) Session Manager command + data-channel content stream
//! ([`SsmWriter`]) → print the **masked** outcome → re-read and print a masked
//! confirmation. The CAS guard (ADR 0001) means a concurrent change surfaces as
//! `Conflict`, never a stomp.
//!
//! Output discipline (THREAT-MODEL): it never prints a Value, raw SSM/SDK protocol
//! text, or any plaintext — only masked outcomes, masked location strings, and
//! masked entry presence/length. **Caveat:** the new value you type for a `set`
//! edit echoes in your terminal (you are typing your own secret into your own
//! session); nothing is logged or persisted by Janitor.
//!
//! First run prompts once for the org (SSO start URL, SSO region, secret region) and
//! saves them to Config. `--reset-config` clears the saved Config first.

use std::env;
use std::io::{self, Write};
use std::sync::Arc;

use janitor_aws_auth::authenticator::Authenticator;
use janitor_aws_auth::aws_impl::{AwsOidcClient, AwsRoleClient};
use janitor_aws_auth::broker::CredentialBroker;
use janitor_aws_auth::types::{Credential, SystemClock};
use janitor_core::config::{Config, Mapping};
use janitor_core::provider::{Step, What};
use janitor_core::secret::SecretShape;
use janitor_ssm::wire::RemoteFileReader;
use janitor_ssm::{
    parse_dotenv, AwsInstanceCatalog, AwsLoggingPreference, DotenvWriteError, EnvEdit,
    SsmDiscovery, SsmFileReader, SsmFileWriter, SsmWriter, WriteOutcome,
};

fn arg(flag: &str) -> Option<String> {
    let args: Vec<String> = env::args().collect();
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn has_flag(flag: &str) -> bool {
    env::args().any(|a| a == flag)
}

/// Read a non-empty line of free text for `prompt` from stdin.
fn prompt_line(prompt: &str) -> String {
    loop {
        print!("{prompt}: ");
        io::stdout().flush().ok();
        let mut s = String::new();
        io::stdin().read_line(&mut s).expect("read stdin");
        let s = s.trim().to_string();
        if !s.is_empty() {
            return s;
        }
    }
}

/// Read one line, stripping only the trailing newline (preserving any other typed
/// characters) — used for a secret value, which may legitimately be empty or carry
/// surrounding spaces.
fn read_raw_line(prompt: &str) -> String {
    print!("{prompt}");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).expect("read stdin");
    s.trim_end_matches(['\n', '\r']).to_string()
}

/// Present a `Step::Ask` menu and return the chosen index (blank line = default).
fn prompt_choice(what: What, choices: &[String], default: Option<usize>) -> usize {
    println!("\nChoose {}:", what_word(what));
    for (i, c) in choices.iter().enumerate() {
        let star = if Some(i) == default { " (default)" } else { "" };
        println!("  [{i}] {c}{star}");
    }
    loop {
        print!("index: ");
        io::stdout().flush().ok();
        let mut s = String::new();
        io::stdin().read_line(&mut s).expect("read stdin");
        let s = s.trim();
        if s.is_empty() {
            if let Some(d) = default {
                return d;
            }
            continue;
        }
        if let Ok(i) = s.parse::<usize>() {
            if i < choices.len() {
                return i;
            }
        }
        println!("enter a number 0..{}", choices.len() - 1);
    }
}

/// Present a free-text `Step::Input` and return the typed value (blank = default).
fn prompt_input(prompt: &str, default: Option<&str>) -> String {
    match default {
        Some(d) => {
            print!("{prompt} [{d}]: ");
            io::stdout().flush().ok();
            let mut s = String::new();
            io::stdin().read_line(&mut s).expect("read stdin");
            let s = s.trim();
            if s.is_empty() {
                d.to_string()
            } else {
                s.to_string()
            }
        }
        None => prompt_line(prompt),
    }
}

fn what_word(what: What) -> &'static str {
    match what {
        What::Accounts => "accounts",
        What::Roles => "roles",
        What::Secrets => "secrets",
        What::Instances => "instances",
        What::FilePath => "paths",
    }
}

/// Drain + print any session-logging advisory the walk surfaced — the masked policy
/// note that this write may be archived to S3/CloudWatch (ADR 0025).
fn drain_advisory(discovery: &mut SsmDiscovery) {
    if let Some(w) = discovery.take_advisory() {
        println!("⚠ session-logging: {w}");
    }
}

/// Prompt for a list of surgical edits: `KEY` (then a value) to set, `-KEY` to
/// remove, blank to finish. Returns the edits (the values are secret — held only in
/// the returned `EnvEdit`s, never printed back).
fn prompt_edits() -> Vec<EnvEdit> {
    println!("\nEnter edits. For each: a KEY to set, or '-KEY' to remove. Blank line to finish.");
    println!("(NOTE: a set value echoes as you type it — it is your own secret.)");
    let mut edits = Vec::new();
    loop {
        let line = read_raw_line("edit key: ");
        if line.is_empty() {
            break;
        }
        if let Some(key) = line.strip_prefix('-') {
            edits.push(EnvEdit::remove(key.to_string()));
            println!("  will remove {key}");
        } else {
            let value = read_raw_line(&format!("  new value for {line}: "));
            edits.push(EnvEdit::set(line.clone(), value));
            println!("  will set {line} (value masked)");
        }
    }
    edits
}

/// Split a `<instance-id>:<path>` location on its first `:` (an instance id has none).
fn split_location(secret_id: &str) -> Option<(&str, &str)> {
    secret_id.split_once(':')
}

/// Re-read the file and print a MASKED confirmation: the entry count and, for each
/// edited key, whether it is now present and its value length (never the value).
async fn confirm_masked(broker: &CredentialBroker, mapping: &Mapping, edits: &[EnvEdit]) {
    let Some((instance_id, path)) = split_location(&mapping.secret_id) else {
        return;
    };
    let cred: Arc<Credential> = match broker.credentials_for(mapping).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("(confirm re-read skipped: mint failed: {e})");
            return;
        }
    };
    let mut raw = match SsmFileReader
        .read_file(cred.as_ref(), instance_id, &mapping.region, path)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("(confirm re-read failed: {e})");
            return;
        }
    };
    let Some(text) = raw.secret_string.take() else {
        eprintln!("(confirm re-read: not text)");
        return;
    };
    match parse_dotenv(&text) {
        Ok(SecretShape::Json(map)) => {
            println!(
                "\nMASKED confirmation: {} entries now in the file.",
                map.len()
            );
            for e in edits {
                let key = e.key();
                let name = janitor_core::secret::EntryName::from_path(&[key.to_string()]);
                match map.get(&name) {
                    Some(v) => println!("  {key}: present (value length {})", v.expose().len()),
                    None => println!("  {key}: absent"),
                }
            }
        }
        Ok(_) => println!("(confirm re-read: unexpected shape)"),
        Err(e) => eprintln!("(confirm re-read parse failed: {})", e),
    }
}

#[tokio::main]
async fn main() {
    // Surface the scrubbed SDK error detail the masked port hides (janitor=debug on
    // stderr; error-safe by construction). Override with RUST_LOG.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("janitor=debug")),
        )
        .with_writer(std::io::stderr)
        .init();

    if has_flag("--reset-config") {
        let path = Config::config_path().expect("resolve config path");
        match std::fs::remove_file(&path) {
            Ok(()) => println!("Removed saved config: {}", path.display()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                println!("No saved config at {} (nothing to reset)", path.display());
            }
            Err(e) => panic!("could not remove config {}: {e}", path.display()),
        }
    }

    // 1. Load Config; prompt+save any missing org fields (flags override).
    let mut config = Config::load().unwrap_or_default();
    if let Some(v) = arg("--start-url") {
        config.sso_start_url = v;
    }
    if config.sso_start_url.is_empty() {
        config.sso_start_url = prompt_line("IAM Identity Center start URL");
    }
    if let Some(v) = arg("--sso-region") {
        config.sso_region = v;
    }
    if config.sso_region.is_empty() {
        config.sso_region = prompt_line("SSO region (e.g. us-east-1)");
    }
    if let Some(v) = arg("--secret-region") {
        config.secret_region = v;
    }
    if config.secret_region.is_empty() {
        config.secret_region = prompt_line("Region to browse for instances");
    }
    config.save().expect("save config");

    // 2. Build the real adapters (no ambient credentials — ADR 0010 §10).
    let oidc = Arc::new(AwsOidcClient::new(config.sso_region.clone()).await);
    let role_client = Arc::new(AwsRoleClient::new(config.sso_region.clone()).await);
    let clock = Arc::new(SystemClock);
    let authenticator = Authenticator::new(oidc, config.sso_start_url.clone());

    // 3. Sign in (opens the browser); the one SSO token feeds both the walk and the
    //    write broker, so there is exactly one Sign-in.
    println!("Signing in (a browser tab will open)...");
    let token = Arc::new(authenticator.sign_in_once().await.expect("sign-in"));
    println!("Signed in. SSO token acquired (held in memory only).");

    // 4. Guided walk over SsmDiscovery (instance + path), driven on stdin.
    let mut discovery = SsmDiscovery::new(
        "live-write".into(),
        config.secret_region.clone(),
        Arc::clone(&token),
        role_client.clone(),
        role_client.clone(),
        Arc::new(AwsInstanceCatalog),
        Arc::new(SsmFileReader),
        Arc::new(AwsLoggingPreference),
        config.last_pick.clone(),
    );
    let mut step = discovery.start().await;
    let mapping = loop {
        drain_advisory(&mut discovery);
        match step {
            Step::Done(m) => {
                println!(
                    "\nTarget: account {} / role {} / location {}",
                    m.account_id, m.permission_set, m.secret_id
                );
                break m;
            }
            Step::Ask {
                what,
                choices,
                default,
            } => {
                let choice = prompt_choice(what, &choices, default);
                step = discovery.advance(choice).await;
            }
            Step::Input {
                what: _,
                prompt,
                default,
            } => {
                let text = prompt_input(&prompt, default.as_deref());
                step = discovery.provide_input(text).await;
            }
            Step::Empty(what) => {
                eprintln!("Nothing to target: no {} you can access.", what_word(what));
                std::process::exit(1);
            }
            Step::Failed(reason) => {
                eprintln!("Discovery failed: {}.", reason.describe());
                std::process::exit(1);
            }
            Step::Reauth => {
                eprintln!("Session expired — run again to sign in.");
                std::process::exit(1);
            }
        }
    };
    drain_advisory(&mut discovery);

    // 5. Prompt for the edits, then read-modify-write under the CAS guard.
    let edits = prompt_edits();
    if edits.is_empty() {
        println!("No edits entered — nothing to write.");
        std::process::exit(0);
    }
    println!(
        "\n⚠ This will MODIFY {} on a real instance.",
        mapping.secret_id
    );
    let go = prompt_line("Type 'WRITE' to proceed");
    if go != "WRITE" {
        println!("Aborted.");
        std::process::exit(0);
    }

    let broker = CredentialBroker::new(Arc::clone(&token), role_client.clone(), clock);
    let ssm_writer = SsmWriter::new(broker, Arc::new(SsmFileReader), Arc::new(SsmFileWriter));

    match ssm_writer.write(&mapping, &edits).await {
        Ok(WriteOutcome::Applied) => {
            println!("\n✅ JANITOR_OK — the atomic CAS replace committed.");
            // 6. Confirm with a masked re-read (a second broker so the cache is fresh).
            let broker2 = CredentialBroker::new(
                Arc::clone(&token),
                role_client.clone(),
                Arc::new(SystemClock),
            );
            confirm_masked(&broker2, &mapping, &edits).await;
        }
        Ok(WriteOutcome::Conflict) => {
            eprintln!(
                "\n⚠ JANITOR_CONFLICT — the file changed under us and the bounded \
                 re-read/retry could not converge. Nothing was written (CAS held). \
                 Re-run to pick up the latest."
            );
            std::process::exit(2);
        }
        Err(DotenvWriteError::Edit(e)) => {
            eprintln!("\nEdit rejected (fail-closed, nothing written): {e}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("\nWrite failed [{}]: {}", e.reason().describe(), e.detail());
            std::process::exit(1);
        }
    }

    // 7. Remember this pick for next time.
    config.last_pick = Some(mapping);
    config.save().expect("save config");

    println!("\n--- ADR 0029 verify checklist (force these by hand) ---");
    println!("[ ] interactive pty: AWS-StartInteractiveCommand streams stdin (the read used non-interactive)");
    println!(
        "[ ] stty raw -echo: no echoed base64 folds into the result; JANITOR_OK parses cleanly"
    );
    println!("[ ] head -c N: the streamed byte count matches; base64 -d writes the whole file");
    println!(
        "[ ] CAS: edit the file out-of-band between read and write → JANITOR_CONFLICT (no stomp)"
    );
    println!(
        "[ ] --reference: owner/mode (600) preserved on the replaced file (else the stat fallback)"
    );
    println!("[ ] masked: no Value or raw SSM text printed anywhere above");
}
