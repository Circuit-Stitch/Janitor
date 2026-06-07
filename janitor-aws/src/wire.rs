//! The Secrets Manager tail's SDK seam (ADR 0010 §5, ADR 0024). The
//! `SecretsApi` trait wraps the SM ops we use; its I/O are our own SDK-free
//! types, so the shaping/orchestration logic is tested against `FakeSecretsApi`
//! without any AWS dependency. The shared front-half seams
//! (`RoleCredentialClient`, `AccountCatalog`, `OidcClient`, `Reauth`, the
//! summaries, `RawSecret`) live in `janitor_aws_auth::wire`. The real impl
//! (`AwsSecretsApi`) lives in `aws_impl.rs` (untested shell).

use async_trait::async_trait;

use janitor_aws_auth::error::SessionError;
use janitor_aws_auth::types::Credential;
use janitor_aws_auth::wire::RawSecret;
use janitor_core::select::Selectable;

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
// Fakes for unit tests. Behind `cfg(test)` so they never ship. The front-half
// fakes come from `janitor_aws_auth::wire::fakes` (its `test-support` feature).
// ----------------------------------------------------------------------------
#[cfg(test)]
pub mod fakes {
    use super::*;
    use std::sync::Mutex;
    use std::time::SystemTime;

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

    #[test]
    fn summaries_expose_keys_and_labels() {
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
}
