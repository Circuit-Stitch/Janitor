//! `CredentialBroker` (ADR 0010 §3/§4): owns the SSO token, brokers one role
//! Credential per Environment from it, silently re-minting near expiry. No
//! browser — a dead token surfaces as `SessionError::ReauthRequired` from the
//! role-credential client and is propagated for the facade to handle.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::error::SessionError;
use crate::types::{Clock, Credential, SsoToken};
use crate::wire::RoleCredentialClient;
use janitor_core::config::Mapping;

/// Re-mint a role Credential when it is within this window of expiry.
pub const REFRESH_SKEW: Duration = Duration::from_secs(60);

/// Brokers per-Environment Credentials from one SSO token.
pub struct CredentialBroker {
    token: SsoToken,
    role_client: Arc<dyn RoleCredentialClient>,
    clock: Arc<dyn Clock>,
    cache: Mutex<HashMap<String, Arc<Credential>>>,
}

impl CredentialBroker {
    pub fn new(
        token: SsoToken,
        role_client: Arc<dyn RoleCredentialClient>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        CredentialBroker { token, role_client, clock, cache: Mutex::new(HashMap::new()) }
    }

    fn cache_key(m: &Mapping) -> String {
        format!("{}|{}|{}", m.account_id, m.permission_set, m.region)
    }

    /// Return a currently-valid Credential for `mapping`, minting or re-minting
    /// via `GetRoleCredentials` when the cache is empty or the cached Credential
    /// is within `REFRESH_SKEW` of expiry. `&self`: the cache is interior.
    pub async fn credentials_for(&self, mapping: &Mapping) -> Result<Arc<Credential>, SessionError> {
        let key = Self::cache_key(mapping);
        let now = self.clock.now();
        {
            let cache = self.cache.lock().await;
            if let Some(cred) = cache.get(&key) {
                if !cred.is_stale(now, REFRESH_SKEW) {
                    return Ok(Arc::clone(cred));
                }
            }
        }
        // Stale or absent → mint. (A dead token returns ReauthRequired here.)
        let fresh = self
            .role_client
            .get_role_credentials(&self.token, &mapping.account_id, &mapping.permission_set, &mapping.region)
            .await?;
        let fresh = Arc::new(fresh);
        self.cache.lock().await.insert(key, Arc::clone(&fresh));
        Ok(fresh)
    }

    /// Force a re-mint for `mapping` regardless of cache freshness (used by the
    /// facade when `GetSecretValue` rejects a not-yet-expired cached Credential).
    pub async fn force_refresh(&self, mapping: &Mapping) -> Result<Arc<Credential>, SessionError> {
        let fresh = Arc::new(
            self.role_client
                .get_role_credentials(&self.token, &mapping.account_id, &mapping.permission_set, &mapping.region)
                .await?,
        );
        self.cache.lock().await.insert(Self::cache_key(mapping), Arc::clone(&fresh));
        Ok(fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::fakes::{CredSpec, FakeClock, FakeRoleClient};

    fn mapping() -> Mapping {
        Mapping {
            environment: "prod".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: "myapp/prod".into(),
            permission_set: "ReadOnly".into(),
        }
    }

    #[tokio::test]
    async fn first_call_mints_and_second_call_hits_cache() {
        let role = Arc::new(FakeRoleClient::new(vec![Ok(CredSpec {
            expires_in: Duration::from_secs(3600),
            tag: "first",
        })]));
        let clock = Arc::new(FakeClock::at(0));
        let broker = CredentialBroker::new(
            SsoToken::new("token".into(), std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(28800)),
            role.clone(),
            clock,
        );
        let c1 = broker.credentials_for(&mapping()).await.unwrap();
        let c2 = broker.credentials_for(&mapping()).await.unwrap();
        assert_eq!(c1.access_key_id(), "AKIA-first");
        assert_eq!(c2.access_key_id(), "AKIA-first");
        assert_eq!(role.call_count(), 1, "second call must hit cache, not re-mint");
    }

    #[tokio::test]
    async fn near_expiry_triggers_remint() {
        let role = Arc::new(FakeRoleClient::new(vec![
            Ok(CredSpec { expires_in: Duration::from_secs(3600), tag: "first" }),
            Ok(CredSpec { expires_in: Duration::from_secs(7200), tag: "second" }),
        ]));
        let clock = Arc::new(FakeClock::at(0));
        let broker = CredentialBroker::new(
            SsoToken::new("token".into(), std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(28800)),
            role.clone(),
            clock.clone(),
        );
        let first = broker.credentials_for(&mapping()).await.unwrap();
        assert_eq!(first.access_key_id(), "AKIA-first");
        // Advance to within REFRESH_SKEW of the first credential's expiry (3600).
        clock.advance(Duration::from_secs(3550));
        let second = broker.credentials_for(&mapping()).await.unwrap();
        assert_eq!(second.access_key_id(), "AKIA-second", "stale → re-minted");
        assert_eq!(role.call_count(), 2);
    }

    #[tokio::test]
    async fn dead_token_surfaces_reauth_required() {
        let role = Arc::new(FakeRoleClient::new(vec![Err(SessionError::ReauthRequired)]));
        let clock = Arc::new(FakeClock::at(0));
        let broker = CredentialBroker::new(
            SsoToken::new("token".into(), std::time::SystemTime::UNIX_EPOCH),
            role,
            clock,
        );
        let err = broker.credentials_for(&mapping()).await.unwrap_err();
        assert!(matches!(err, SessionError::ReauthRequired));
    }
}
