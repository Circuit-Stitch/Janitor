//! Guided sign-in + live verification harness (ADR 0011, ADR 0010 §5 Milestone B).
//! Run by a human against a real Identity Center org:
//!
//!   cargo run -p janitor-aws --bin live-verify
//!
//! First run prompts once for the org (SSO start URL, SSO region, secret region)
//! and saves them to Config. Then the browser opens; after sign-in the tool
//! auto-discovers the account, role, and secret (auto-picking when there is only
//! one, offering the remembered pick as the default otherwise), fetches the
//! chosen secret, and prints a MASKED single-environment matrix (never a Value).
//! The chosen account/role/secret is remembered for next time.
//!
//! Optional overrides skip a step: `--start-url`, `--sso-region`,
//! `--secret-region`, `--account-id`, `--role`, `--secret-id`.
//!
//! `--reset-config` deletes the saved Config first (org URL, regions, last
//! pick), so the next run re-prompts from scratch.

use std::env;
use std::io::{self, Write};
use std::sync::Arc;

use janitor_aws::authenticator::Authenticator;
use janitor_aws::aws_impl::{AwsOidcClient, AwsRoleClient, AwsSecretsApi};
use janitor_aws::broker::CredentialBroker;
use janitor_aws::secrets::SecretsClient;
use janitor_aws::select::{resolve, Chooser};
use janitor_aws::source::AuthenticatedSource;
use janitor_aws::types::SystemClock;
use janitor_aws::wire::{AccountCatalog, SecretsApi};
use janitor_core::compare::Comparison;
use janitor_core::config::{Config, Mapping};
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

/// The real `Chooser`: prints a numbered menu and reads the choice from stdin.
struct StdinChooser;
impl Chooser for StdinChooser {
    fn choose(&self, labels: &[String], default: Option<usize>) -> usize {
        loop {
            println!();
            for (i, label) in labels.iter().enumerate() {
                let marker = if Some(i) == default { " (default)" } else { "" };
                println!("  [{}] {label}{marker}", i + 1);
            }
            let hint = match default {
                Some(i) => format!("choose 1-{} [default {}]", labels.len(), i + 1),
                None => format!("choose 1-{}", labels.len()),
            };
            print!("{hint}: ");
            io::stdout().flush().ok();
            let mut s = String::new();
            io::stdin().read_line(&mut s).expect("read stdin");
            let s = s.trim();
            if s.is_empty() {
                if let Some(i) = default {
                    return i;
                }
                continue;
            }
            if let Ok(n) = s.parse::<usize>() {
                if (1..=labels.len()).contains(&n) {
                    return n - 1;
                }
            }
            println!("  invalid choice, try again");
        }
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

    let chooser = StdinChooser;
    let remembered = config.last_pick.clone();

    // 2. Build the real adapters (no ambient credentials — ADR 0010 §10).
    let oidc = Arc::new(AwsOidcClient::new(config.sso_region.clone()).await);
    let role_client = Arc::new(AwsRoleClient::new(config.sso_region.clone()).await);
    let secrets_api = Arc::new(AwsSecretsApi::new());
    let clock = Arc::new(SystemClock);
    let authenticator = Arc::new(Authenticator::new(oidc, config.sso_start_url.clone()));

    // 3. Sign in (opens the browser).
    println!("Signing in (a browser tab will open)...");
    let token = authenticator.sign_in_once().await.expect("sign-in");
    println!("Signed in. SSO token acquired (held in memory only).");

    // 4. Discover account (override flag short-circuits the listing).
    let account_id = match arg("--account-id") {
        Some(id) => id,
        None => {
            let accounts = role_client
                .list_accounts(&token)
                .await
                .expect("list accounts");
            let acct = resolve(
                accounts,
                remembered.as_ref().map(|m| m.account_id.as_str()),
                &chooser,
                "accounts",
            )
            .expect("choose account");
            println!("Account: {} ({})", acct.name, acct.id);
            acct.id
        }
    };

    // 5. Discover role for that account.
    let role = match arg("--role") {
        Some(r) => r,
        None => {
            let roles = role_client
                .list_account_roles(&token, &account_id)
                .await
                .expect("list roles");
            let role = resolve(
                roles,
                remembered.as_ref().map(|m| m.permission_set.as_str()),
                &chooser,
                "roles",
            )
            .expect("choose role");
            println!("Role: {}", role.name);
            role.name
        }
    };

    // 6. Mint a role credential for (account, role, secret-region), then list
    //    secrets in that region and pick one (override flag short-circuits).
    let secret_region = config.secret_region.clone();
    let probe = Mapping {
        environment: "live".into(),
        account_id: account_id.clone(),
        region: secret_region.clone(),
        secret_id: String::new(), // unused for minting; broker keys on acct|role|region
        permission_set: role.clone(),
    };
    let broker = CredentialBroker::new(token, role_client.clone(), clock.clone());
    let cred = broker
        .credentials_for(&probe)
        .await
        .expect("mint role credential");

    let secret_id = match arg("--secret-id") {
        Some(s) => s,
        None => {
            let secrets = secrets_api
                .list_secrets(&cred, &secret_region)
                .await
                .expect("list secrets");
            let secret = resolve(
                secrets,
                remembered.as_ref().map(|m| m.secret_id.as_str()),
                &chooser,
                "secrets",
            )
            .expect("choose secret");
            println!("Secret: {}", secret.name);
            // Use the ARN as the stable id; GetSecretValue accepts name or ARN.
            secret.arn
        }
    };

    // 7. Assemble the full Mapping and fetch through the facade.
    let mapping = Mapping {
        environment: "live".into(),
        account_id,
        region: secret_region,
        secret_id,
        permission_set: role,
    };
    let secrets = SecretsClient::new(secrets_api);
    let mut source = AuthenticatedSource::new(broker, secrets, authenticator, role_client, clock);
    let shape = source.fetch(&mapping).await.expect("fetch");

    // 8. Output discipline: project to a MASKED matrix, never print a Value.
    let sets = vec![(mapping.environment.clone(), shape)];
    let comparison = Comparison::build(&sets);
    let view = project(&comparison);
    println!("\nMASKED MATRIX (single environment):");
    println!("environments: {:?}", view.environments);
    for row in &view.rows {
        println!("  {} [{:?}] -> {:?}", row.name, row.state, row.cells);
    }

    // 9. Remember this pick for next time.
    config.last_pick = Some(mapping);
    config.save().expect("save config");
    println!("\nRemembered this pick (account/role/secret) for next run.");

    println!("\n--- ADR 0010/0011 verify checklist (force these by hand) ---");
    println!("[ ] issuerUrl accepted: confirm the start URL works as RegisterClient issuerUrl (else try the Issuer URL)");
    println!("[ ] endpoint-from-response: confirm sign-in works with NO --authorize-endpoint flag");
    println!(
        "[ ] single account/role auto-picks; multiple shows a menu with the remembered default"
    );
    println!("[ ] token-expiry → re-Sign-in: confirm ONE browser reopen, no loop");
    println!("[ ] access-denied: point --secret-id at a denied secret, confirm AccessDenied (not a loop)");
    println!("[ ] not-found: point --secret-id at a missing name, confirm NotFound");
    println!("[ ] confirm roleCredentials.expiration is read (not a hardcoded 1h)");
}
