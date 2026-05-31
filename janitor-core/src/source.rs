//! The data-source seam: where Secret Sets enter the comparison pipeline.
//!
//! [`SecretSource`] is the boundary the real AWS Secrets Manager adapter will
//! implement (see this crate's `lib.rs`: "core logic must depend on an
//! AWS-client trait"). It is **synchronous on purpose**: the only impl today is
//! an in-memory mock that returns instantly, so async↔GUI threading would be
//! premature.
//!
//! ASYNC SEAM (deferred): the real AWS SDK is async. When it lands, `fetch`
//! becomes async (or returns a boxed future) and every caller threads the
//! await. That change is intentionally out of scope for the tracer-bullet slice.

use crate::config::Mapping;
use crate::secret::SecretShape;

/// Fetches the Secret Set backing one Environment's [`Mapping`].
pub trait SecretSource {
    /// Fetch and parse the Set that `mapping` points at.
    fn fetch(&self, mapping: &Mapping) -> Result<SecretShape, FetchError>;
}

/// Why a [`SecretSource::fetch`] failed.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// No Set is known for this Mapping's `secret_id`.
    #[error("no secret found for {0}")]
    NotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mapping;

    fn mapping(secret_id: &str) -> Mapping {
        Mapping {
            environment: "prod".into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
            secret_id: secret_id.into(),
            permission_set: "ReadOnly".into(),
        }
    }

    /// A stub source proving the trait shape: it knows exactly one secret_id.
    struct OneSecret;
    impl SecretSource for OneSecret {
        fn fetch(&self, m: &Mapping) -> Result<SecretShape, FetchError> {
            if m.secret_id == "known" {
                Ok(SecretShape::from_secret_string(r#"{"A":"1"}"#))
            } else {
                Err(FetchError::NotFound(m.secret_id.clone()))
            }
        }
    }

    #[test]
    fn source_returns_shape_or_not_found() {
        let s = OneSecret;
        assert!(s.fetch(&mapping("known")).is_ok());
        let err = s.fetch(&mapping("missing")).unwrap_err();
        assert!(matches!(err, FetchError::NotFound(id) if id == "missing"));
    }
}
