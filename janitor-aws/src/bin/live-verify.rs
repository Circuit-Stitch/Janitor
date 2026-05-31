//! Live verification harness (ADR 0010 §5, Milestone B). Run by a human against
//! a real Identity Center org:
//!
//!   cargo run -p janitor-aws --bin live-verify -- \
//!       --authorize-endpoint https://oidc.<region>.amazonaws.com/authorize \
//!       --sso-region <region> \
//!       --account-id <acct> --role <permission-set> \
//!       --secret-region <region> --secret-id <name-or-arn>
//!
//! Prints only a MASKED single-environment matrix (never a Value), then a
//! checklist of error paths to force by hand to close the ADR 0010 verify list.

use std::env;
use std::sync::Arc;

use janitor_aws::authenticator::Authenticator;
use janitor_aws::aws_impl::{AwsOidcClient, AwsRoleClient, AwsSecretsApi};
use janitor_aws::broker::CredentialBroker;
use janitor_aws::secrets::SecretsClient;
use janitor_aws::source::AuthenticatedSource;
use janitor_aws::types::SystemClock;
use janitor_core::compare::Comparison;
use janitor_core::config::Mapping;
use janitor_core::view::project;

fn arg(flag: &str) -> Option<String> {
    let args: Vec<String> = env::args().collect();
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

#[tokio::main]
async fn main() {
    let authorize_endpoint = arg("--authorize-endpoint").expect("--authorize-endpoint");
    let sso_region = arg("--sso-region").expect("--sso-region");
    let account_id = arg("--account-id").expect("--account-id");
    let role = arg("--role").expect("--role");
    let secret_region = arg("--secret-region").expect("--secret-region");
    let secret_id = arg("--secret-id").expect("--secret-id");

    let mapping = Mapping {
        environment: "live".into(),
        account_id,
        region: secret_region.clone(),
        secret_id,
        permission_set: role,
    };

    let oidc = Arc::new(AwsOidcClient::new(sso_region.clone()).await);
    let role_client = Arc::new(AwsRoleClient::new(sso_region).await);
    let secrets_api = Arc::new(AwsSecretsApi::new());
    let clock = Arc::new(SystemClock);

    let authenticator = Arc::new(Authenticator::new(oidc, authorize_endpoint));

    // Initial Sign-in (this opens the browser).
    println!("Signing in (a browser tab will open)...");
    let token = authenticator.sign_in_once().await.expect("sign-in");
    println!("Signed in. SSO token acquired (held in memory only).");

    let broker = CredentialBroker::new(token, role_client.clone(), clock.clone());
    let secrets = SecretsClient::new(secrets_api);
    let mut source = AuthenticatedSource::new(broker, secrets, authenticator, role_client, clock);

    let shape = source.fetch(&mapping).await.expect("fetch");

    // Output discipline: project to a MASKED matrix, never print a Value.
    let sets = vec![(mapping.environment.clone(), shape)];
    let comparison = Comparison::build(&sets);
    let view = project(&comparison);
    println!("\nMASKED MATRIX (single environment):");
    println!("environments: {:?}", view.environments);
    for row in &view.rows {
        println!("  {} [{:?}] -> {:?}", row.name, row.state, row.cells);
    }

    println!("\n--- ADR 0010 verify checklist (force these by hand) ---");
    println!("[ ] token-expiry → re-Sign-in: wait out / revoke the SSO token, re-run, confirm ONE browser reopen");
    println!("[ ] access-denied: point --secret-id at a denied secret, confirm AccessDenied (not a browser loop)");
    println!("[ ] not-found: point --secret-id at a missing name, confirm NotFound");
    println!("[ ] throttle: (optional) hammer GetSecretValue, confirm Throttled surfaces");
    println!("[ ] confirm roleCredentials.expiration is read (not a hardcoded 1h)");
    println!("[ ] confirm loopback redirect_uri exact-match accepted by /authorize + CreateToken");
}
