//! The SDK seam (ADR 0010 §5). Each trait wraps the AWS ops we use; all I/O are
//! our own SDK-free types, so the brokering/orchestration logic is tested
//! against the fakes here without any AWS dependency. Real impls live in
//! `aws_impl.rs` (untested shell).

use async_trait::async_trait;

use crate::error::{SessionError, SignInError};
use crate::select::Selectable;
use crate::types::{Credential, SsoToken};

/// A public-client registration from `RegisterClient`. The `client_secret` is a
/// public-client secret (not confidential — PKCE is what protects the flow), but
/// we still hold it as an opaque string and never log it.
#[derive(Clone)]
pub struct ClientRegistration {
    pub client_id: String,
    pub client_secret: String,
    /// The `/authorize` endpoint AWS returns for this registration (ADR 0011);
    /// used to build the browser URL instead of a hardcoded host.
    pub authorization_endpoint: String,
}

/// Inputs needed to exchange an auth code for an SSO token.
pub struct TokenExchange<'a> {
    pub registration: &'a ClientRegistration,
    pub code: &'a str,
    pub code_verifier: &'a str,
    pub redirect_uri: &'a str,
}

/// Wraps the unauthenticated OIDC ops: `RegisterClient` + `CreateToken`.
#[async_trait]
pub trait OidcClient: Send + Sync {
    /// `RegisterClient` for a public client with the org `issuer_url`, the given
    /// loopback redirect URIs, and the `authorization_code` + `refresh_token`
    /// grants. The returned registration carries the authorize endpoint.
    async fn register_client(
        &self,
        issuer_url: &str,
        redirect_uris: &[String],
    ) -> Result<ClientRegistration, SignInError>;

    /// `CreateToken` with `grant_type=authorization_code` + PKCE `code_verifier`.
    /// Returns the SSO access token + its expiry.
    async fn create_token(&self, ex: TokenExchange<'_>) -> Result<SsoToken, SignInError>;
}

/// Wraps `GetRoleCredentials` (mints a role Credential from the SSO token).
#[async_trait]
pub trait RoleCredentialClient: Send + Sync {
    /// `GetRoleCredentials` for `(account_id, permission_set)` using `token`.
    /// Maps `UnauthorizedException` (dead token) → `SessionError::ReauthRequired`.
    async fn get_role_credentials(
        &self,
        token: &SsoToken,
        account_id: &str,
        permission_set: &str,
        region: &str,
    ) -> Result<Credential, SessionError>;
}

/// The raw payload of one `GetSecretValue` response, SDK-free. Exactly one of
/// the two fields is `Some` (mirrors the AWS API).
pub struct RawSecret {
    pub secret_string: Option<String>,
    pub secret_binary: Option<Vec<u8>>,
}

/// One account the signed-in user is entitled to (`ListAccounts`).
#[derive(Debug, Clone, PartialEq)]
pub struct AccountSummary {
    pub id: String,
    pub name: String,
}
impl Selectable for AccountSummary {
    fn key(&self) -> &str {
        &self.id
    }
    fn label(&self) -> String {
        format!("{} ({})", self.name, self.id)
    }
}

/// One permission-set role available in an account (`ListAccountRoles`).
#[derive(Debug, Clone, PartialEq)]
pub struct RoleSummary {
    pub name: String,
}
impl Selectable for RoleSummary {
    fn key(&self) -> &str {
        &self.name
    }
    fn label(&self) -> String {
        self.name.clone()
    }
}

/// One secret in a region (`ListSecrets`). `arn` is the stable identity; `name`
/// is the friendly label.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretSummary {
    pub name: String,
    pub arn: String,
}
impl Selectable for SecretSummary {
    fn key(&self) -> &str {
        &self.arn
    }
    fn label(&self) -> String {
        self.name.clone()
    }
}

/// Wraps the SSO-token-authorized account/role enumeration ops.
#[async_trait]
pub trait AccountCatalog: Send + Sync {
    /// `ListAccounts` for everything `token` is entitled to.
    async fn list_accounts(&self, token: &SsoToken) -> Result<Vec<AccountSummary>, SessionError>;

    /// `ListAccountRoles` for one account.
    async fn list_account_roles(
        &self,
        token: &SsoToken,
        account_id: &str,
    ) -> Result<Vec<RoleSummary>, SessionError>;
}

/// Wraps `GetSecretValue` and `ListSecrets`.
#[async_trait]
pub trait SecretsApi: Send + Sync {
    /// `GetSecretValue` for `secret_id` in `region`, authorized by `cred`.
    async fn get_secret_value(
        &self,
        cred: &Credential,
        secret_id: &str,
        region: &str,
    ) -> Result<RawSecret, SessionError>;

    /// `ListSecrets` in `region`, authorized by `cred`. Returns name+ARN only —
    /// never a Value.
    async fn list_secrets(
        &self,
        cred: &Credential,
        region: &str,
    ) -> Result<Vec<SecretSummary>, SessionError>;
}

// ----------------------------------------------------------------------------
// Fakes for unit tests. Behind `cfg(test)` so they never ship.
// ----------------------------------------------------------------------------
#[cfg(test)]
pub mod fakes {
    use super::*;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    /// A scripted role-credential client: each call pops the next scripted
    /// outcome, and records how many times it was called (to assert "exactly
    /// once" re-mint behavior).
    pub struct FakeRoleClient {
        pub outcomes: Mutex<Vec<Result<CredSpec, SessionError>>>,
        pub calls: Mutex<u32>,
    }

    /// A description of a Credential to mint (fakes can't build real secrets
    /// meaningfully; they just need distinguishable expiries).
    #[derive(Clone)]
    pub struct CredSpec {
        pub expires_in: Duration,
        pub tag: &'static str, // distinguishes successive mints in assertions
    }

    impl FakeRoleClient {
        pub fn new(outcomes: Vec<Result<CredSpec, SessionError>>) -> Self {
            FakeRoleClient {
                outcomes: Mutex::new(outcomes),
                calls: Mutex::new(0),
            }
        }
        pub fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl RoleCredentialClient for FakeRoleClient {
        async fn get_role_credentials(
            &self,
            _token: &SsoToken,
            _account_id: &str,
            _permission_set: &str,
            _region: &str,
        ) -> Result<Credential, SessionError> {
            *self.calls.lock().unwrap() += 1;
            let next = {
                let mut v = self.outcomes.lock().unwrap();
                if v.is_empty() {
                    panic!("FakeRoleClient called more times than scripted");
                }
                v.remove(0)
            };
            next.map(|spec| {
                // Use a fixed base instant so tests are deterministic; the broker
                // is driven by an injected clock, not real time.
                let base = SystemTime::UNIX_EPOCH;
                Credential::new(
                    format!("AKIA-{}", spec.tag),
                    format!("secret-{}", spec.tag),
                    format!("session-{}", spec.tag),
                    base + spec.expires_in,
                )
            })
        }
    }

    /// A scripted secrets client.
    pub struct FakeSecretsApi {
        pub outcomes: Mutex<Vec<Result<RawSecret, SessionError>>>,
        pub list_outcomes: Mutex<Vec<Result<Vec<SecretSummary>, SessionError>>>,
        pub calls: Mutex<u32>,
    }
    impl FakeSecretsApi {
        pub fn new(outcomes: Vec<Result<RawSecret, SessionError>>) -> Self {
            FakeSecretsApi {
                outcomes: Mutex::new(outcomes),
                list_outcomes: Mutex::new(Vec::new()),
                calls: Mutex::new(0),
            }
        }
        /// Build a fake whose `list_secrets` returns `lists` (one per call).
        pub fn with_lists(lists: Vec<Result<Vec<SecretSummary>, SessionError>>) -> Self {
            FakeSecretsApi {
                outcomes: Mutex::new(Vec::new()),
                list_outcomes: Mutex::new(lists),
                calls: Mutex::new(0),
            }
        }
        pub fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }
    #[async_trait]
    impl SecretsApi for FakeSecretsApi {
        async fn get_secret_value(
            &self,
            _cred: &Credential,
            _secret_id: &str,
            _region: &str,
        ) -> Result<RawSecret, SessionError> {
            *self.calls.lock().unwrap() += 1;
            let mut v = self.outcomes.lock().unwrap();
            if v.is_empty() {
                panic!("FakeSecretsApi called more times than scripted");
            }
            v.remove(0)
        }

        async fn list_secrets(
            &self,
            _cred: &Credential,
            _region: &str,
        ) -> Result<Vec<SecretSummary>, SessionError> {
            let mut v = self.list_outcomes.lock().unwrap();
            if v.is_empty() {
                panic!("FakeSecretsApi::list_secrets called more times than scripted");
            }
            v.remove(0)
        }
    }

    /// A controllable clock for broker/facade tests.
    pub struct FakeClock {
        pub now: Mutex<SystemTime>,
    }
    impl FakeClock {
        pub fn at(secs_after_epoch: u64) -> Self {
            FakeClock {
                now: Mutex::new(SystemTime::UNIX_EPOCH + Duration::from_secs(secs_after_epoch)),
            }
        }
        pub fn advance(&self, by: Duration) {
            let mut n = self.now.lock().unwrap();
            *n += by;
        }
    }
    impl crate::types::Clock for FakeClock {
        fn now(&self) -> SystemTime {
            *self.now.lock().unwrap()
        }
    }

    /// A scripted re-/sign-in: yields a fresh token (or a failure) and counts
    /// calls, so the Session's "sign in exactly once" contract is assertable.
    /// Additive — mirrors the private fake in `source.rs` tests; kept here so
    /// `session.rs` tests can share it without duplication.
    pub struct FakeReauth {
        pub calls: Mutex<u32>,
        pub fail: bool,
    }
    impl FakeReauth {
        pub fn ok() -> Self {
            FakeReauth { calls: Mutex::new(0), fail: false }
        }
        pub fn failing() -> Self {
            FakeReauth { calls: Mutex::new(0), fail: true }
        }
        pub fn count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }
    #[async_trait]
    impl crate::source::Reauth for FakeReauth {
        async fn sign_in(&self) -> Result<SsoToken, crate::error::SignInError> {
            *self.calls.lock().unwrap() += 1;
            if self.fail {
                Err(crate::error::SignInError::TokenEndpoint)
            } else {
                Ok(SsoToken::new(
                    "session-token".into(),
                    SystemTime::UNIX_EPOCH + Duration::from_secs(28800),
                ))
            }
        }
    }

    #[test]
    fn fake_role_client_counts_calls_and_scripts_outcomes() {
        // A tiny self-test of the fake itself, so later tasks can trust it.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let fake = FakeRoleClient::new(vec![
            Ok(CredSpec {
                expires_in: Duration::from_secs(3600),
                tag: "first",
            }),
            Err(SessionError::ReauthRequired),
        ]);
        let token = SsoToken::new("t".into(), SystemTime::UNIX_EPOCH);
        rt.block_on(async {
            let c = fake
                .get_role_credentials(&token, "acct", "ps", "us-east-1")
                .await
                .unwrap();
            assert_eq!(c.access_key_id(), "AKIA-first");
            let e = fake
                .get_role_credentials(&token, "acct", "ps", "us-east-1")
                .await
                .unwrap_err();
            assert!(matches!(e, SessionError::ReauthRequired));
        });
        assert_eq!(fake.call_count(), 2);
    }

    #[test]
    fn summaries_expose_keys_and_labels() {
        let a = AccountSummary {
            id: "111".into(),
            name: "Prod".into(),
        };
        assert_eq!(a.key(), "111");
        assert_eq!(a.label(), "Prod (111)");

        let r = RoleSummary {
            name: "ReadOnly".into(),
        };
        assert_eq!(r.key(), "ReadOnly");
        assert_eq!(r.label(), "ReadOnly");

        let s = SecretSummary {
            name: "myapp/prod".into(),
            arn: "arn:aws:...:myapp/prod".into(),
        };
        assert_eq!(s.key(), "arn:aws:...:myapp/prod");
        assert_eq!(s.label(), "myapp/prod");
    }

    #[test]
    fn fake_secrets_api_scripts_list_outcomes() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let fake = FakeSecretsApi::with_lists(vec![Ok(vec![SecretSummary {
            name: "n".into(),
            arn: "a".into(),
        }])]);
        let cred = Credential::new("a".into(), "b".into(), "c".into(), SystemTime::UNIX_EPOCH);
        rt.block_on(async {
            let list = fake.list_secrets(&cred, "us-east-1").await.unwrap();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].name, "n");
        });
    }

    #[test]
    fn fake_reauth_counts_and_can_fail() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let ok = FakeReauth::ok();
        rt.block_on(async {
            assert!(crate::source::Reauth::sign_in(&ok).await.is_ok());
        });
        assert_eq!(ok.count(), 1);

        let bad = FakeReauth::failing();
        rt.block_on(async {
            assert!(crate::source::Reauth::sign_in(&bad).await.is_err());
        });
        assert_eq!(bad.count(), 1);
    }
}
