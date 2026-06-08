//! Guided sign-in + live verification harness for the remote-`.env`-over-SSM
//! Provider (ADR 0025 §3, B4 / Milestone B). Run by a human against a real
//! Identity Center org with at least one SSM-managed EC2 instance:
//!
//!   cargo run -p janitor-ssm --bin live-verify-ssm
//!
//! It mirrors `janitor-aws`'s `live-verify`, but drives the **`SsmProvider`**
//! through the `core::provider::Provider` port: browser Sign-in → the guided walk
//! (account → role → mint → instance → free-text `.env` path) → a read over the
//! pure-Rust Session Manager (MGS) data channel → `parse_dotenv` → a **masked**
//! single-Environment matrix. It also prints the org's session-logging advisory
//! state (the `GetDocument` probe).
//!
//! Output discipline (THREAT-MODEL): it never prints a Value, raw SSM/SDK protocol
//! text, or any plaintext — only the masked matrix (presence/length/hash group),
//! masked location strings, and the masked logging advisory.
//!
//! First run prompts once for the org (SSO start URL, SSO region, secret region)
//! and saves them to Config. `--reset-config` clears the saved Config first.

use std::env;
use std::io::{self, Write};
use std::sync::Arc;

use janitor_aws_auth::authenticator::Authenticator;
use janitor_aws_auth::aws_impl::{AwsOidcClient, AwsRoleClient};
use janitor_aws_auth::types::SystemClock;
use janitor_core::config::{Application, Config};
use janitor_core::provider::{Provider, Step, What};
use janitor_ssm::{AwsInstanceCatalog, AwsLoggingPreference, SsmFileReader, SsmProvider};

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

/// Print (and drain) any session-logging advisories the Provider surfaced — the
/// masked policy note about org-wide SSM logging (ADR 0025).
async fn drain_advisories(provider: &mut SsmProvider) {
    for w in provider.take_advisories().await {
        println!("⚠ session-logging: {w}");
    }
}

#[tokio::main]
async fn main() {
    // Surface the real (already-scrubbed) SDK error detail the masked Provider port
    // hides: `map_aws_err` logs the failing op + AWS error code under the `janitor`
    // target. Default to `janitor=debug` on stderr (no SDK/hyper noise, no secret —
    // janitor logs are error-safe by construction); override with RUST_LOG.
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

    // 2. Build the real adapters (no ambient credentials — ADR 0010 §10) and the
    //    SsmProvider with the B4 SSM tail (DescribeInstanceInformation, the MGS
    //    file read, GetDocument logging detection).
    let oidc = Arc::new(AwsOidcClient::new(config.sso_region.clone()).await);
    let role_client = Arc::new(AwsRoleClient::new(config.sso_region.clone()).await);
    let clock = Arc::new(SystemClock);
    let authenticator = Arc::new(Authenticator::new(oidc, config.sso_start_url.clone()));
    let mut provider = SsmProvider::new(
        authenticator,
        role_client.clone(),
        role_client,
        Arc::new(AwsInstanceCatalog),
        Arc::new(SsmFileReader),
        Arc::new(AwsLoggingPreference),
        clock,
    );

    // 3. Sign in (opens the browser).
    println!("Signing in (a browser tab will open)...");
    provider.sign_in().await.expect("sign-in");
    println!("Signed in. SSO token acquired (held in memory only).");

    // 4. Guided walk over the Provider port, presented on stdin. The instance/path
    //    steps are auto-picked when there is one, menued otherwise; the path is
    //    free-text with the remembered default. Logging advisories print as they
    //    surface (at the credential mint).
    let mut step = provider
        .begin_discovery(
            "live".into(),
            config.secret_region.clone(),
            config.last_pick.clone(),
        )
        .await
        .expect("begin discovery");
    let mapping = loop {
        drain_advisories(&mut provider).await;
        match step {
            Step::Done(m) => {
                println!(
                    "\nDiscovered: account {} / role {} / location {}",
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
                step = provider.advance_discovery(choice).await.expect("advance");
            }
            Step::Input {
                what: _,
                prompt,
                default,
            } => {
                let text = prompt_input(&prompt, default.as_deref());
                step = provider.provide_input(text).await.expect("provide input");
            }
            Step::Empty(what) => {
                eprintln!("Nothing to verify: no {} you can access.", what_word(what));
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
    drain_advisories(&mut provider).await;

    // 5. Load the single Environment through the Provider (this re-reads the file
    //    over the MGS transport) and print the MASKED matrix it projects — never a
    //    Value, never raw SSM/SDK text.
    let app = Application {
        name: "live".into(),
        environments: vec![mapping.clone()],
    };
    let loaded = match provider.load(&app).await {
        Ok(l) => l,
        Err(e) => {
            for f in &e.failures {
                eprintln!("Load failed [{}]: {}", f.environment, f.detail);
            }
            std::process::exit(1);
        }
    };
    drain_advisories(&mut provider).await;

    let view = loaded.view;
    println!("\nMASKED MATRIX (single environment):");
    println!("environments: {:?}", view.environments);
    for row in &view.rows {
        println!("  {} [{:?}] -> {:?}", row.name, row.state, row.cells);
    }

    // 6. Remember this pick for next time.
    config.last_pick = Some(mapping);
    config.save().expect("save config");
    println!("\nRemembered this pick for next run.");

    println!("\n--- ADR 0025 §3 (transport b) verify checklist (force these by hand) ---");
    println!("[ ] AWS-StartNonInteractiveCommand: confirm StartSession accepts the document name");
    println!("[ ] clean streaming: the masked Entries match the file's KEY=VALUE lines (no truncation/garble)");
    println!("[ ] exit code: a bad path prints \"secret not found\" (cat non-zero → NotFound), not a hang");
    println!("[ ] session logging: with S3/CloudWatch logging ON the ⚠ advisory prints; with it OFF none does");
    println!("[ ] KMS encryption: if the org enables session-data KMS, the read fails masked, not a hang");
    println!(
        "[ ] GetDocument: confirm ssm:GetDocument on SSM-SessionManagerRunShell is the right probe"
    );
}
