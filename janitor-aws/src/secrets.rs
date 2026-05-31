//! `SecretsClient` (ADR 0010 §3): fetch one Set via the `SecretsApi` seam and
//! map it to a core `SecretShape`. The mapping is the first thing to get right,
//! so it is tested here against fakes; binary stays opaque (ADR 0004).

use std::sync::Arc;

use janitor_core::config::Mapping;
use janitor_core::secret::SecretShape;

use crate::error::SessionError;
use crate::types::Credential;
use crate::wire::SecretsApi;

/// Fetches and shapes one Secret Set.
pub struct SecretsClient {
    api: Arc<dyn SecretsApi>,
}

impl SecretsClient {
    pub fn new(api: Arc<dyn SecretsApi>) -> Self {
        SecretsClient { api }
    }

    /// `GetSecretValue` for `mapping`, authorized by `cred`, mapped to a shape.
    pub async fn fetch(
        &self,
        cred: &Credential,
        mapping: &Mapping,
    ) -> Result<SecretShape, SessionError> {
        let raw = self.api.get_secret_value(cred, &mapping.secret_id, &mapping.region).await?;
        match (raw.secret_string, raw.secret_binary) {
            (Some(s), _) => Ok(SecretShape::from_secret_string(&s)),
            (None, Some(b)) => Ok(SecretShape::from_secret_binary(b)),
            (None, None) => Err(SessionError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::fakes::FakeSecretsApi;
    use crate::wire::RawSecret;
    use std::time::SystemTime;

    fn cred() -> Credential {
        Credential::new("a".into(), "b".into(), "c".into(), SystemTime::UNIX_EPOCH)
    }
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
    async fn json_object_string_becomes_json_shape() {
        let api = Arc::new(FakeSecretsApi::new(vec![Ok(RawSecret {
            secret_string: Some(r#"{"A":"1"}"#.into()),
            secret_binary: None,
        })]));
        let shape = SecretsClient::new(api).fetch(&cred(), &mapping()).await.unwrap();
        assert!(matches!(shape, SecretShape::Json(_)));
    }

    #[tokio::test]
    async fn non_json_string_becomes_raw_shape() {
        let api = Arc::new(FakeSecretsApi::new(vec![Ok(RawSecret {
            secret_string: Some("just-a-token".into()),
            secret_binary: None,
        })]));
        let shape = SecretsClient::new(api).fetch(&cred(), &mapping()).await.unwrap();
        assert!(matches!(shape, SecretShape::Raw(_)));
    }

    #[tokio::test]
    async fn binary_becomes_binary_shape() {
        let api = Arc::new(FakeSecretsApi::new(vec![Ok(RawSecret {
            secret_string: None,
            secret_binary: Some(vec![1, 2, 3, 4]),
        })]));
        let shape = SecretsClient::new(api).fetch(&cred(), &mapping()).await.unwrap();
        match shape {
            SecretShape::Binary(b) => assert_eq!(b.len(), 4),
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_response_is_not_found() {
        let api = Arc::new(FakeSecretsApi::new(vec![Ok(RawSecret {
            secret_string: None,
            secret_binary: None,
        })]));
        let err = SecretsClient::new(api).fetch(&cred(), &mapping()).await.unwrap_err();
        assert!(matches!(err, SessionError::NotFound));
    }

    #[tokio::test]
    async fn propagates_access_denied() {
        let api = Arc::new(FakeSecretsApi::new(vec![Err(SessionError::AccessDenied)]));
        let err = SecretsClient::new(api).fetch(&cred(), &mapping()).await.unwrap_err();
        assert!(matches!(err, SessionError::AccessDenied));
    }
}
