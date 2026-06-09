//! Guided sign-in + live verification harness (ADR 0011, ADR 0010 §5 Milestone B).
//! Run by a human against a real Identity Center org:
//!
//!   cargo run -p janitor-aws --bin live-verify
//!
//! First run prompts once for the org (SSO start URL, SSO region, secret region)
//! and saves them to Config. Then the browser opens; after sign-in the tool
//! runs the shared [`Discovery`] step-machine (ADR 0013) via a stdin presenter
//! to walk account → role → secret (auto-picking when there is only one,
//! offering the remembered pick as the default otherwise), fetches the chosen
//! secret, and prints a MASKED single-environment matrix (never a Value). The
//! chosen account/role/secret is remembered for next time.
//!
//! Optional overrides skip a config prompt: `--start-url`, `--sso-region`,
//! `--secret-region`. (The old per-step `--account-id`/`--role`/`--secret-id`
//! overrides are gone — the step-machine auto-picks singletons and menus the
//! rest; issue #11.)
//!
//! `--reset-config` deletes the saved Config first (org URL, regions, last
//! pick), so the next run re-prompts from scratch.

use std::env;
use std::io::{self, Write};
use std::sync::Arc;

use janitor_aws::aws_impl::AwsSecretsApi;
use janitor_aws::discovery::Discovery;
use janitor_aws::method::SecretsManagerMethod;
use janitor_aws::presenter::drive_discovery;
use janitor_aws_auth::authenticator::Authenticator;
use janitor_aws_auth::aws_impl::{AwsOidcClient, AwsRoleClient};
use janitor_aws_auth::broker::CredentialBroker;
use janitor_aws_auth::method::ResourceMethod;
use janitor_aws_auth::types::SystemClock;
use janitor_core::compare::Comparison;
use janitor_core::config::Config;
use janitor_core::provider::{Step, What};
use janitor_core::view::project;

fn arg(flag: &str) -> Option<String> {
    let args: Vec<String> = env::args().collect();
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Whether a bare flag (no value) is present on the command line.
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

/// Name the thing a `Step::Empty` could not offer, for a masked message.
fn what_word(what: What) -> &'static str {
    match what {
        What::Accounts => "accounts",
        What::Roles => "roles",
        What::Secrets => "secrets",
        // The Secrets Manager walk never poses these (ADR 0025's SSM tail does);
        // present for exhaustiveness only.
        What::Instances => "instances",
        What::FilePath => "paths",
    }
}

#[tokio::main]
async fn main() {
    // 0. `--reset-config`: delete the saved Config so this run starts clean.
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
    let authenticator = Arc::new(Authenticator::new(oidc, config.sso_start_url.clone()));

    // 3. Sign in (opens the browser).
    println!("Signing in (a browser tab will open)...");
    let token = Arc::new(authenticator.sign_in_once().await.expect("sign-in"));
    println!("Signed in. SSO token acquired (held in memory only).");

    // 4. Guided account → role → secret walk: drive the SAME `Discovery`
    //    step-machine the GUI uses (ADR 0013), presented over stdin. It
    //    auto-picks singletons and menus the rest, offering the remembered pick
    //    as the default; the secret region is the browse region.
    let secret_region = config.secret_region.clone();
    let mut discovery = Discovery::new(
        "live".into(),
        secret_region.clone(),
        token.clone(),
        role_client.clone(), // AccountCatalog
        role_client.clone(), // RoleCredentialClient
        secrets_api.clone(), // SecretsApi
        config.last_pick.clone(),
    );
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut output = io::stdout();
    let mapping = match drive_discovery(&mut discovery, &mut input, &mut output)
        .await
        .expect("discovery i/o")
    {
        Step::Done(m) => {
            println!(
                "\nDiscovered: account {} / role {} / secret {}",
                m.account_id, m.permission_set, m.secret_id
            );
            m
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
        // `drive_discovery` loops on every `Ask`/`Input`, so it only ever hands
        // back a terminal step (and the SM walk never poses an `Input` anyway).
        Step::Ask { .. } => unreachable!("drive_discovery resolves all Ask steps"),
        Step::Input { .. } => unreachable!("drive_discovery resolves all Input steps"),
    };

    // 5. Fetch the chosen Mapping through the Secrets Manager method: mint a role
    //    Credential off the live token, then read+shape (the auth ladder this smoke
    //    test does not need is unit-tested in `janitor-aws-auth::AwsFamilyProvider`).
    let broker = CredentialBroker::new(token.clone(), role_client.clone(), clock.clone());
    let cred = broker
        .credentials_for(&mapping)
        .await
        .expect("mint role credential");
    let method = SecretsManagerMethod::new(role_client.clone(), role_client.clone(), secrets_api);
    let shape = method.fetch(cred.as_ref(), &mapping).await.expect("fetch");

    // 6. Output discipline: project to a MASKED matrix, never print a Value.
    let sets = vec![(mapping.environment.clone(), shape)];
    let comparison = Comparison::build(&sets);
    let view = project(&comparison);
    println!("\nMASKED MATRIX (single environment):");
    println!("environments: {:?}", view.environments);
    for row in &view.rows {
        println!("  {} [{:?}] -> {:?}", row.name, row.state, row.cells);
    }

    // 7. Remember this pick for next time.
    config.last_pick = Some(mapping);
    config.save().expect("save config");
    println!("\nRemembered this pick (account/role/secret) for next run.");

    println!("\n--- ADR 0010/0011 verify checklist (force these by hand) ---");
    println!("[ ] issuerUrl accepted: confirm the start URL works as RegisterClient issuerUrl (else try the Issuer URL)");
    println!("[ ] endpoint-from-response: confirm sign-in works with NO --authorize-endpoint flag");
    println!(
        "[ ] single account/role auto-picks; multiple shows a menu with the remembered default"
    );
    println!("[ ] token-expiry → re-Sign-in: confirm the walk reports \"Session expired\" (Reauth), no loop");
    println!("[ ] access-denied: pick a denied secret, confirm \"Discovery failed: access denied\" (not a loop)");
    println!("[ ] empty step: an account/role/secret with no choices prints \"no … you can access\" and exits");
    println!("[ ] confirm roleCredentials.expiration is read (not a hardcoded 1h)");
}
