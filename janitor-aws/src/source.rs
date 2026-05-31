//! `AuthenticatedSource` (ADR 0010 §4): composes the broker + secrets client and
//! owns the chained escalation — at most one force-refresh and at most one
//! re-Sign-in per `fetch`. Re-Sign-in is behind the `Reauth` seam so the whole
//! orchestration is tested without a browser.

use std::sync::Arc;

use async_trait::async_trait;
use janitor_core::config::Mapping;
use janitor_core::secret::SecretShape;

use crate::broker::CredentialBroker;
use crate::error::{SessionError, SignInError};
use crate::secrets::SecretsClient;
use crate::types::{Clock, SsoToken};
use crate::wire::RoleCredentialClient;

/// The capability to perform a fresh browser Sign-in and yield a new SSO token.
/// Real impl drives the browser (Task 11); the test fake yields a scripted token.
#[async_trait]
pub trait Reauth: Send + Sync {
    async fn sign_in(&self) -> Result<SsoToken, SignInError>;
}

/// An authenticated data source over one Identity Center Session.
pub struct AuthenticatedSource {
    broker: CredentialBroker,
    secrets: SecretsClient,
    reauth: Arc<dyn Reauth>,
    role_client: Arc<dyn RoleCredentialClient>,
    clock: Arc<dyn Clock>,
}

impl AuthenticatedSource {
    pub fn new(
        broker: CredentialBroker,
        secrets: SecretsClient,
        reauth: Arc<dyn Reauth>,
        role_client: Arc<dyn RoleCredentialClient>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        AuthenticatedSource {
            broker,
            secrets,
            reauth,
            role_client,
            clock,
        }
    }

    /// Fetch and shape the Set for `mapping`, handling the two refreshes with
    /// at-most-once caps (ADR 0010 §4):
    ///
    /// 1. credentials_for → GetSecretValue. On success, done.
    /// 2. On an auth-class GetSecretValue failure, force_refresh once, retry.
    ///    - forced refresh OK but retry still auth-fails → AccessDenied.
    ///    - forced refresh itself raises ReauthRequired → step 3.
    /// 3. credentials_for raising ReauthRequired (in step 1 or 2): re-Sign-in
    ///    once, rebuild the broker on the fresh token, retry from step 1. Still
    ///    ReauthRequired after a fresh Sign-in → fatal (AccessDenied).
    pub async fn fetch(&mut self, mapping: &Mapping) -> Result<SecretShape, SessionError> {
        match self.try_once(mapping).await {
            Ok(shape) => Ok(shape),
            Err(SessionError::ReauthRequired) => {
                // One re-Sign-in, rebuild broker on the fresh token, one retry.
                let token = self
                    .reauth
                    .sign_in()
                    .await
                    .map_err(|_| SessionError::ReauthRequired)?;
                self.broker = CredentialBroker::new(
                    token,
                    Arc::clone(&self.role_client),
                    Arc::clone(&self.clock),
                );
                match self.try_once(mapping).await {
                    Ok(shape) => Ok(shape),
                    // Still unauthorized even after a fresh Sign-in → fatal.
                    Err(SessionError::ReauthRequired) => Err(SessionError::AccessDenied),
                    Err(other) => Err(other),
                }
            }
            Err(other) => Err(other),
        }
    }

    /// One pass: mint/get a credential, GetSecretValue, and on an auth-class
    /// failure force_refresh **once** then retry. Surfaces ReauthRequired up to
    /// `fetch` (which owns the re-Sign-in).
    async fn try_once(&self, mapping: &Mapping) -> Result<SecretShape, SessionError> {
        let cred = self.broker.credentials_for(mapping).await?; // may be ReauthRequired
        match self.secrets.fetch(&cred, mapping).await {
            Ok(shape) => Ok(shape),
            Err(SessionError::AccessDenied) => {
                // Could be a stale cached credential AWS now rejects, OR a true
                // policy denial — indistinguishable at this layer (ADR 0010 §4).
                // Force one re-mint and retry; a true denial costs one wasted mint.
                let cred = self.broker.force_refresh(mapping).await?; // may be ReauthRequired
                match self.secrets.fetch(&cred, mapping).await {
                    Ok(shape) => Ok(shape),
                    Err(SessionError::AccessDenied) => Err(SessionError::AccessDenied),
                    Err(other) => Err(other),
                }
            }
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SsoToken;
    use crate::wire::fakes::{CredSpec, FakeClock, FakeRoleClient, FakeSecretsApi};
    use crate::wire::RawSecret;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    fn mapping() -> Mapping {
        Mapping {
            environment: "prod".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: "myapp/prod".into(),
            permission_set: "ReadOnly".into(),
        }
    }

    /// A scripted re-Sign-in: records calls, yields a fresh token each time.
    struct FakeReauth {
        calls: Mutex<u32>,
        fail: bool,
    }
    impl FakeReauth {
        fn ok() -> Self {
            FakeReauth {
                calls: Mutex::new(0),
                fail: false,
            }
        }
        fn count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }
    #[async_trait]
    impl Reauth for FakeReauth {
        async fn sign_in(&self) -> Result<SsoToken, SignInError> {
            *self.calls.lock().unwrap() += 1;
            if self.fail {
                Err(SignInError::TokenEndpoint)
            } else {
                Ok(SsoToken::new(
                    "fresh-token".into(),
                    SystemTime::UNIX_EPOCH + Duration::from_secs(28800),
                ))
            }
        }
    }

    fn build(
        role: Arc<FakeRoleClient>,
        api: Arc<FakeSecretsApi>,
        reauth: Arc<FakeReauth>,
    ) -> AuthenticatedSource {
        let clock = Arc::new(FakeClock::at(0));
        let token = SsoToken::new(
            "t0".into(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(28800),
        );
        let broker = CredentialBroker::new(token, role.clone(), clock.clone());
        let secrets = SecretsClient::new(api);
        AuthenticatedSource::new(broker, secrets, reauth, role, clock)
    }

    #[tokio::test]
    async fn happy_path_fetches_without_refresh_or_reauth() {
        let role = Arc::new(FakeRoleClient::new(vec![Ok(CredSpec {
            expires_in: Duration::from_secs(3600),
            tag: "a",
        })]));
        let api = Arc::new(FakeSecretsApi::new(vec![Ok(RawSecret {
            secret_string: Some(r#"{"A":"1"}"#.into()),
            secret_binary: None,
        })]));
        let reauth = Arc::new(FakeReauth::ok());
        let mut src = build(role.clone(), api.clone(), reauth.clone());
        let shape = src.fetch(&mapping()).await.unwrap();
        assert!(matches!(shape, SecretShape::Json(_)));
        assert_eq!(role.call_count(), 1);
        assert_eq!(api.call_count(), 1);
        assert_eq!(reauth.count(), 0);
    }

    #[tokio::test]
    async fn stale_credential_force_refreshes_once_then_succeeds() {
        // First GetSecretValue → AccessDenied (stale cred); force_refresh mints a
        // second credential; retry succeeds.
        let role = Arc::new(FakeRoleClient::new(vec![
            Ok(CredSpec {
                expires_in: Duration::from_secs(3600),
                tag: "stale",
            }),
            Ok(CredSpec {
                expires_in: Duration::from_secs(3600),
                tag: "fresh",
            }),
        ]));
        let api = Arc::new(FakeSecretsApi::new(vec![
            Err(SessionError::AccessDenied),
            Ok(RawSecret {
                secret_string: Some(r#"{"A":"1"}"#.into()),
                secret_binary: None,
            }),
        ]));
        let reauth = Arc::new(FakeReauth::ok());
        let mut src = build(role.clone(), api.clone(), reauth.clone());
        let shape = src.fetch(&mapping()).await.unwrap();
        assert!(matches!(shape, SecretShape::Json(_)));
        assert_eq!(role.call_count(), 2, "one initial mint + one force_refresh");
        assert_eq!(api.call_count(), 2, "one denied + one retry");
        assert_eq!(reauth.count(), 0, "no browser for a stale role credential");
    }

    #[tokio::test]
    async fn true_denial_force_refreshes_once_then_gives_access_denied() {
        let role = Arc::new(FakeRoleClient::new(vec![
            Ok(CredSpec {
                expires_in: Duration::from_secs(3600),
                tag: "a",
            }),
            Ok(CredSpec {
                expires_in: Duration::from_secs(3600),
                tag: "b",
            }),
        ]));
        let api = Arc::new(FakeSecretsApi::new(vec![
            Err(SessionError::AccessDenied),
            Err(SessionError::AccessDenied),
        ]));
        let reauth = Arc::new(FakeReauth::ok());
        let mut src = build(role.clone(), api.clone(), reauth.clone());
        let err = src.fetch(&mapping()).await.unwrap_err();
        assert!(matches!(err, SessionError::AccessDenied));
        assert_eq!(role.call_count(), 2, "exactly one wasted re-mint, no loop");
        assert_eq!(api.call_count(), 2);
        assert_eq!(reauth.count(), 0);
    }

    #[tokio::test]
    async fn dead_token_re_signs_in_once_then_succeeds() {
        // First credentials_for → ReauthRequired (dead token). After re-Sign-in
        // the rebuilt broker mints OK and the fetch succeeds.
        let role = Arc::new(FakeRoleClient::new(vec![
            Err(SessionError::ReauthRequired),
            Ok(CredSpec {
                expires_in: Duration::from_secs(3600),
                tag: "after-reauth",
            }),
        ]));
        let api = Arc::new(FakeSecretsApi::new(vec![Ok(RawSecret {
            secret_string: Some(r#"{"A":"1"}"#.into()),
            secret_binary: None,
        })]));
        let reauth = Arc::new(FakeReauth::ok());
        let mut src = build(role.clone(), api.clone(), reauth.clone());
        let shape = src.fetch(&mapping()).await.unwrap();
        assert!(matches!(shape, SecretShape::Json(_)));
        assert_eq!(reauth.count(), 1, "exactly one browser Sign-in");
        assert_eq!(role.call_count(), 2);
    }

    #[tokio::test]
    async fn still_unauthorized_after_reauth_is_fatal() {
        // Both before and after re-Sign-in the role client says ReauthRequired
        // (e.g. a not-entitled Mapping). Must NOT loop the browser; classify fatal.
        let role = Arc::new(FakeRoleClient::new(vec![
            Err(SessionError::ReauthRequired),
            Err(SessionError::ReauthRequired),
        ]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let reauth = Arc::new(FakeReauth::ok());
        let mut src = build(role.clone(), api.clone(), reauth.clone());
        let err = src.fetch(&mapping()).await.unwrap_err();
        assert!(
            matches!(err, SessionError::AccessDenied),
            "fatal, not another browser"
        );
        assert_eq!(reauth.count(), 1, "browser opened at most once");
    }
}
