//! In-memory, zeroizing auth material + an injectable clock.
//!
//! `SsoToken` and `Credential` hold secret strings in `secrecy::SecretString`
//! so they are zeroized on drop and never `Debug`/`Display` the plaintext. The
//! `Clock` seam lets the broker's near-expiry math be tested without sleeping.

use std::time::{Duration, SystemTime};

use secrecy::{ExposeSecret, SecretString};

/// The SSO access token from `CreateToken`. Drives `GetRoleCredentials` until it
/// expires; its in-memory lifetime *is* the Session (CONTEXT.md). Never cached.
pub struct SsoToken {
    access_token: SecretString,
    /// When the SSO token itself expires (a fresh Sign-in is needed after this).
    pub expires_at: SystemTime,
}

impl SsoToken {
    pub fn new(access_token: String, expires_at: SystemTime) -> Self {
        SsoToken {
            access_token: SecretString::from(access_token),
            expires_at,
        }
    }
    /// Expose the token for a `GetRoleCredentials` call. Callers must not retain.
    pub fn expose(&self) -> &str {
        self.access_token.expose_secret()
    }
}

impl std::fmt::Debug for SsoToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoToken")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// One Environment's short-lived role Credential from `GetRoleCredentials`.
/// All three secret fields are zeroizing; `expiration` is read from AWS, never
/// hardcoded (ADR 0002).
pub struct Credential {
    access_key_id: SecretString,
    secret_access_key: SecretString,
    session_token: SecretString,
    pub expiration: SystemTime,
}

impl Credential {
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        expiration: SystemTime,
    ) -> Self {
        Credential {
            access_key_id: SecretString::from(access_key_id),
            secret_access_key: SecretString::from(secret_access_key),
            session_token: SecretString::from(session_token),
            expiration,
        }
    }
    pub fn access_key_id(&self) -> &str {
        self.access_key_id.expose_secret()
    }
    pub fn secret_access_key(&self) -> &str {
        self.secret_access_key.expose_secret()
    }
    pub fn session_token(&self) -> &str {
        self.session_token.expose_secret()
    }

    /// True when this Credential is within `skew` of expiry (or already past),
    /// per the clock — i.e. it should be re-minted before use.
    pub fn is_stale(&self, now: SystemTime, skew: Duration) -> bool {
        match self.expiration.checked_sub(skew) {
            Some(deadline) => now >= deadline,
            None => true, // expiration - skew underflows → treat as stale
        }
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Injectable clock so expiry logic is testable without real time.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// Production clock.
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_and_credential_debug_redact_secrets() {
        let t = SsoToken::new("super-secret-token".into(), SystemTime::UNIX_EPOCH);
        assert!(!format!("{t:?}").contains("super-secret-token"));

        let c = Credential::new(
            "AKIA".into(),
            "wJalr-secret".into(),
            "sess".into(),
            SystemTime::UNIX_EPOCH,
        );
        let shown = format!("{c:?}");
        assert!(!shown.contains("wJalr-secret"));
        assert!(!shown.contains("AKIA"));
    }

    #[test]
    fn is_stale_respects_skew() {
        let base = SystemTime::UNIX_EPOCH;
        let exp = base + Duration::from_secs(3600);
        let c = Credential::new("a".into(), "b".into(), "c".into(), exp);
        let skew = Duration::from_secs(60);

        // Well before expiry-minus-skew → fresh.
        assert!(!c.is_stale(base + Duration::from_secs(3000), skew));
        // Exactly at expiry-minus-skew (3600-60=3540) → stale (>=).
        assert!(c.is_stale(base + Duration::from_secs(3540), skew));
        // Past expiry → stale.
        assert!(c.is_stale(base + Duration::from_secs(4000), skew));
    }
}
