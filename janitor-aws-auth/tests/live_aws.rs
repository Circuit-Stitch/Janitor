//! Live-AWS integration suite for the shared auth shell (ADR 0027 Layer 2).
//!
//! These tests drive the **real** Identity Center org to confirm the canned
//! shapes the replay/local tests (Layer 1) assert actually match AWS, resolving
//! the [ADR 0010] §5 verify list with assertions rather than a manual checklist.
//!
//! **Env-gated, not `#[ignore]`d** (ADR 0027): unset, each test prints why it
//! skipped and returns — so it stays visible in a normal `cargo test` run and is
//! flipped on by an env var, not a `--ignored` flag a reader must know to pass.
//!
//! Run against a real org (the second test opens a browser and waits for a human):
//! ```bash
//! JANITOR_LIVE_AWS=1 \
//!   JANITOR_LIVE_SSO_START_URL='https://identitycenter.amazonaws.com/ssoins-…' \
//!   JANITOR_LIVE_SSO_REGION=us-east-1 \
//!   JANITOR_LIVE_SECRET_REGION=us-east-1 \
//!   cargo test -p janitor-aws-auth --test live_aws -- --nocapture --test-threads=1
//! ```
//!
//! [ADR 0010]: ../../docs/adr/0010-aws-adapter-crate-and-auth-object-model.md

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use janitor_aws_auth::authenticator::Authenticator;
use janitor_aws_auth::aws_impl::{AwsOidcClient, AwsRoleClient};
use janitor_aws_auth::loopback::redirect_uris;
use janitor_aws_auth::wire::{AccountCatalog, OidcClient, RoleCredentialClient};

struct LiveCfg {
    start_url: String,
    sso_region: String,
    secret_region: String,
}

/// `Some` only when `JANITOR_LIVE_AWS=1`; otherwise prints a skip notice and
/// returns `None` so the calling test no-ops (visibly, on `--nocapture`).
fn live_config() -> Option<LiveCfg> {
    if std::env::var("JANITOR_LIVE_AWS").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP (ADR 0027 Layer 2): set JANITOR_LIVE_AWS=1 + JANITOR_LIVE_SSO_START_URL \
             [+ JANITOR_LIVE_SSO_REGION / JANITOR_LIVE_SECRET_REGION] to run against a real org."
        );
        return None;
    }
    let start_url = std::env::var("JANITOR_LIVE_SSO_START_URL")
        .expect("JANITOR_LIVE_SSO_START_URL must be set when JANITOR_LIVE_AWS=1");
    let sso_region =
        std::env::var("JANITOR_LIVE_SSO_REGION").unwrap_or_else(|_| "us-east-1".into());
    let secret_region =
        std::env::var("JANITOR_LIVE_SECRET_REGION").unwrap_or_else(|_| sso_region.clone());
    Some(LiveCfg {
        start_url,
        sso_region,
        secret_region,
    })
}

/// Verify-list item: the SSO **start URL** is accepted as `RegisterClient`'s
/// `issuerUrl`, and an authorize endpoint resolves (from the response, or the
/// regional fallback when AWS returns null). This is a **pre-auth** call — no
/// browser, no human — so it is the fully-automatable half of the live suite.
#[tokio::test]
async fn live_register_client_accepts_start_url_as_issuer() {
    let Some(cfg) = live_config() else { return };
    let oidc = AwsOidcClient::new(cfg.sso_region.clone()).await;
    let reg = oidc
        .register_client(&cfg.start_url, &redirect_uris())
        .await
        .expect("RegisterClient should accept the SSO start URL as issuerUrl");
    assert!(
        !reg.client_id.is_empty(),
        "registration returned a client_id"
    );
    assert!(
        reg.authorization_endpoint.starts_with("https://"),
        "authorize endpoint resolved (response or regional fallback): {}",
        reg.authorization_endpoint
    );
    eprintln!(
        "[verify] issuerUrl accepted; authorize endpoint = {}",
        reg.authorization_endpoint
    );
}

/// Verify-list items behind a real sign-in (opens a browser, waits for a human):
/// the SSO token is acquired, accounts/roles enumerate, and a role Credential is
/// minted with a **real** expiration (fresh on arrival — never a hardcoded 1h).
#[tokio::test]
async fn live_full_sign_in_mints_role_credentials_with_real_expiration() {
    let Some(cfg) = live_config() else { return };
    eprintln!("[live] a browser tab will open — complete sign-in to finish this test.");

    let oidc = Arc::new(AwsOidcClient::new(cfg.sso_region.clone()).await);
    let token = Authenticator::new(oidc, cfg.start_url.clone())
        .sign_in_once()
        .await
        .expect("browser sign-in");
    assert!(!token.expose().is_empty(), "SSO token acquired");

    let role_client = AwsRoleClient::new(cfg.sso_region.clone()).await;
    let accounts = role_client
        .list_accounts(&token)
        .await
        .expect("ListAccounts");
    assert!(!accounts.is_empty(), "at least one account enumerated");
    let account = &accounts[0];
    let roles = role_client
        .list_account_roles(&token, &account.id)
        .await
        .expect("ListAccountRoles");
    assert!(
        !roles.is_empty(),
        "at least one role in account {}",
        account.id
    );
    let role = &roles[0];

    let cred = role_client
        .get_role_credentials(&token, &account.id, &role.name, &cfg.secret_region)
        .await
        .expect("GetRoleCredentials");
    // A real `roleCredentials.expiration` came back — a freshly minted credential
    // is not already stale (it would be if expiry were mis-parsed or zeroed).
    assert!(
        !cred.is_stale(SystemTime::now(), Duration::from_secs(60)),
        "freshly minted credential must not already be stale"
    );

    eprintln!(
        "[verify] signed in; {} account(s); minted role {} on {}; expiration honored.",
        accounts.len(),
        role.name,
        account.id
    );
}
