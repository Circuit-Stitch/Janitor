//! Human-gated live verification of the Secrets Manager **write** path (ADR 0001 +
//! Amendment 2026-06-25, #89). Run by a human against a real Identity Center org
//! with a Secrets Manager Set you are willing to edit:
//!
//!   cargo run -p janitor-aws --bin live-verify-sm-write
//!
//! It mirrors `live-verify` (the read harness) but drives the **write**: browser
//! Sign-in → the guided [`Discovery`] walk (account → role → secret) → prompt for a
//! few surgical edits → read-modify-write through the staged-put / atomic-CAS engine
//! ([`SecretsManagerWriter`]) → print the **masked** outcome → re-read and print a
//! masked confirmation. The CAS guard (ADR 0001) means a concurrent change surfaces
//! as `Conflict`, never a stomp.
//!
//! Output discipline (THREAT-MODEL): it never prints a Value, raw SDK text, or any
//! plaintext — only masked outcomes and masked entry presence/length. **Caveat:** the
//! new value you type for a `set` edit echoes in your terminal (you are typing your
//! own secret into your own session); nothing is logged or persisted by Janitor.
//!
//! First run prompts once for the org (SSO start URL, SSO region, secret region) and
//! saves them to Config. `--reset-config` clears the saved Config first.

use std::env;
use std::io::{self, Write};
use std::sync::Arc;

use janitor_aws::aws_impl::AwsSecretsApi;
use janitor_aws::discovery::Discovery;
use janitor_aws::method::SecretsManagerMethod;
use janitor_aws::presenter::drive_discovery;
use janitor_aws::{EnvEdit, SecretWriteError, SecretsManagerWriter, WriteOutcome};
use janitor_aws_auth::authenticator::Authenticator;
use janitor_aws_auth::aws_impl::{AwsOidcClient, AwsRoleClient};
use janitor_aws_auth::broker::CredentialBroker;
use janitor_aws_auth::method::ResourceMethod;
use janitor_aws_auth::types::SystemClock;
use janitor_core::config::{Config, Mapping};
use janitor_core::provider::{Step, What};
use janitor_core::secret::{EntryName, SecretShape};

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

/// Read one line, stripping only the trailing newline (a secret value may
/// legitimately be empty or carry surrounding spaces).
fn read_raw_line(prompt: &str) -> String {
    print!("{prompt}");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).expect("read stdin");
    s.trim_end_matches(['\n', '\r']).to_string()
}

fn what_word(what: What) -> &'static str {
    match what {
        What::Accounts => "accounts",
        What::Roles => "roles",
        What::Secrets => "secrets",
        // The SM walk never poses these; present for exhaustiveness only.
        What::Instances => "instances",
        What::FilePath => "paths",
    }
}

/// Prompt for surgical edits: a `KEY` (then a value) to set, `-KEY` to remove, blank
/// to finish. The set values are secret — held only in the returned `EnvEdit`s.
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

/// Re-read the Set and print a MASKED confirmation: for each edited key, whether it
/// is now present and its value length (never the value).
async fn confirm_masked(
    method: &SecretsManagerMethod,
    broker: &CredentialBroker,
    mapping: &Mapping,
    edits: &[EnvEdit],
) {
    let cred = match broker.credentials_for(mapping).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("(confirm re-read skipped: mint failed: {e})");
            return;
        }
    };
    match method.fetch(cred.as_ref(), mapping).await {
        Ok(SecretShape::Json(map)) => {
            println!(
                "\nMASKED confirmation: {} entries now in the Set.",
                map.len()
            );
            for e in edits {
                let key = e.key();
                let name = EntryName::from_path(&[key.to_string()]);
                match map.get(&name) {
                    Some(v) => println!("  {key}: present (value length {})", v.expose().len()),
                    None => println!("  {key}: absent"),
                }
            }
        }
        Ok(_) => println!("(confirm re-read: unexpected shape)"),
        Err(e) => eprintln!(
            "(confirm re-read failed [{}]: {})",
            e.reason().describe(),
            e.detail()
        ),
    }
}

#[tokio::main]
async fn main() {
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
        config.secret_region = prompt_line("Secrets Manager region to browse");
    }
    config.save().expect("save config");

    // 2. Build the real adapters (no ambient credentials — ADR 0010 §10).
    let oidc = Arc::new(AwsOidcClient::new(config.sso_region.clone()).await);
    let role_client = Arc::new(AwsRoleClient::new(config.sso_region.clone()).await);
    let secrets_api = Arc::new(AwsSecretsApi::new());
    let clock = Arc::new(SystemClock);
    let authenticator = Authenticator::new(oidc, config.sso_start_url.clone());

    // 3. Sign in (opens the browser); the one SSO token feeds both the walk and the
    //    write broker, so there is exactly one Sign-in.
    println!("Signing in (a browser tab will open)...");
    let token = Arc::new(authenticator.sign_in_once().await.expect("sign-in"));
    println!("Signed in. SSO token acquired (held in memory only).");

    // 4. Guided account → role → secret walk over the SAME `Discovery` step-machine
    //    the GUI uses, presented over stdin.
    let mapping = {
        let mut discovery = Discovery::new(
            "live-write".into(),
            config.secret_region.clone(),
            token.clone(),
            role_client.clone(), // AccountCatalog
            role_client.clone(), // RoleCredentialClient
            secrets_api.clone(), // SecretsApi
            config.last_pick.clone(),
        );
        let stdin = io::stdin();
        let mut input = stdin.lock();
        let mut output = io::stdout();
        match drive_discovery(&mut discovery, &mut input, &mut output)
            .await
            .expect("discovery i/o")
        {
            Step::Done(m) => {
                println!(
                    "\nTarget: account {} / role {} / secret {}",
                    m.account_id, m.permission_set, m.secret_id
                );
                m
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
            Step::Ask { .. } => unreachable!("drive_discovery resolves all Ask steps"),
            Step::Input { .. } => unreachable!("drive_discovery resolves all Input steps"),
        }
    };

    // 5. Prompt for the edits, then read-modify-write under the CAS guard.
    let edits = prompt_edits();
    if edits.is_empty() {
        println!("No edits entered — nothing to write.");
        std::process::exit(0);
    }
    println!(
        "\n⚠ This will MODIFY secret {} in a real account.",
        mapping.secret_id
    );
    let go = prompt_line("Type 'WRITE' to proceed");
    if go != "WRITE" {
        println!("Aborted.");
        std::process::exit(0);
    }

    let broker = CredentialBroker::new(Arc::clone(&token), role_client.clone(), clock);
    let writer = SecretsManagerWriter::new(broker, secrets_api.clone());

    match writer.write(&mapping, &edits).await {
        Ok(WriteOutcome::Applied) => {
            println!("\n✅ Applied — the atomic CAS replace committed.");
            // 6. Confirm with a masked re-read (a fresh broker so the cache is fresh).
            let method =
                SecretsManagerMethod::new(role_client.clone(), role_client.clone(), secrets_api);
            let broker2 = CredentialBroker::new(
                Arc::clone(&token),
                role_client.clone(),
                Arc::new(SystemClock),
            );
            confirm_masked(&method, &broker2, &mapping, &edits).await;
        }
        Ok(WriteOutcome::Conflict) => {
            eprintln!(
                "\n⚠ Conflict — the Set changed under us and the bounded re-read/retry \
                 could not converge (a key you edited changed, or persistent contention). \
                 Nothing was written (CAS held). Re-run to pick up the latest."
            );
            std::process::exit(2);
        }
        Err(SecretWriteError::Edit(e)) => {
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

    println!("\n--- ADR 0001 verify checklist (force these by hand) ---");
    println!(
        "[ ] staged put: a new version appears under a janitor-pending-* label, AWSCURRENT unmoved"
    );
    println!(
        "[ ] atomic CAS: AWSCURRENT moves to the new version; AWSPREVIOUS auto-moves correctly"
    );
    println!("[ ] settle: the janitor-pending-* label is stripped from the committed version");
    println!(
        "[ ] CAS conflict: edit the Set out-of-band between read and commit → Conflict (no stomp)"
    );
    println!(
        "[ ] cleanup: after a forced conflict, no orphaned janitor-pending-* label is left behind"
    );
    println!("[ ] non-flat: point at a nested/array/binary Set → Unsupported (no write attempted)");
    println!("[ ] masked: no Value or raw SDK text printed anywhere above");
}
