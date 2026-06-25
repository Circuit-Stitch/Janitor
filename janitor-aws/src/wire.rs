//! The Secrets Manager tail's SDK seam (ADR 0010 §5, ADR 0024). The
//! `SecretsApi` trait wraps the SM ops we use; its I/O are our own SDK-free
//! types, so the shaping/orchestration logic is tested against `FakeSecretsApi`
//! without any AWS dependency. The shared front-half seams
//! (`RoleCredentialClient`, `AccountCatalog`, `OidcClient`, `Reauth`, the
//! summaries, `RawSecret`) live in `janitor_aws_auth::wire`. The real impl
//! (`AwsSecretsApi`) lives in `aws_impl.rs` (untested shell).

use async_trait::async_trait;
use zeroize::Zeroizing;

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

/// One `GetSecretValue` result: the zeroize-on-drop payload plus the read
/// `AWSCURRENT` `VersionId` (ADR 0001 — the compare-and-swap `base` the write's
/// commit removes the label from). The version id is a non-secret opaque id (OK
/// to log); the payload is secret (held in the zeroizing [`RawSecret`]).
pub struct ReadSecret {
    pub raw: RawSecret,
    pub version_id: Option<String>,
}

/// The outcome of the atomic compare-and-swap commit (`UpdateSecretVersionStage`
/// moving `AWSCURRENT`, ADR 0001 step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasOutcome {
    /// `AWSCURRENT` moved to the staged version — the commit succeeded.
    Committed,
    /// `AWSCURRENT` had already moved off the version we tried to remove it from
    /// (a concurrent write), so the CAS precondition failed. The caller cleans up
    /// the orphaned pending label, re-reads, replays, and retries (ADR 0001).
    Mismatch,
}

/// Wraps the Secrets Manager ops Janitor uses: `GetSecretValue` + `ListSecrets`
/// (read) and `PutSecretValue` + `UpdateSecretVersionStage` (the staged-put / CAS
/// write, ADR 0001). All I/O are SDK-free types so the engine is tested against
/// [`fakes::FakeSecretsApi`].
#[async_trait]
pub trait SecretsApi: Send + Sync {
    /// `GetSecretValue` for `secret_id` in `region`, authorized by `cred`. Surfaces
    /// the read `VersionId` (ADR 0001) alongside the payload.
    async fn get_secret_value(
        &self,
        cred: &Credential,
        secret_id: &str,
        region: &str,
    ) -> Result<ReadSecret, SessionError>;

    /// `ListSecrets` in `region`, authorized by `cred`. Returns name+ARN only —
    /// never a Value.
    async fn list_secrets(
        &self,
        cred: &Credential,
        region: &str,
    ) -> Result<Vec<SecretSummary>, SessionError>;

    /// `PutSecretValue` staging the merged `secret_string` as a **new** version
    /// under `version_stages` (ADR 0001 step 3 — passing explicit stages means
    /// `AWSCURRENT` is *not* moved). `client_request_token` is the idempotency
    /// token (it becomes the new `VersionId`). Returns the new version id (a
    /// non-secret opaque id). The payload is secret (zeroizing) and reaches only
    /// the writer.
    async fn put_secret_value(
        &self,
        cred: &Credential,
        secret_id: &str,
        region: &str,
        secret_string: Zeroizing<String>,
        client_request_token: &str,
        version_stages: &[String],
    ) -> Result<String, SessionError>;

    /// `UpdateSecretVersionStage` for `secret_id` in `region`: move `version_stage`
    /// to `move_to` and/or remove it from `remove_from`. The commit (ADR 0001 step
    /// 4) passes `version_stage="AWSCURRENT"`, `move_to=Some(new)`,
    /// `remove_from=Some(current)` and is a true CAS — a [`CasOutcome::Mismatch`]
    /// means `AWSCURRENT` moved under us. The settle/cleanup (steps 5–6) pass only
    /// `remove_from` to strip a `janitor-pending-*` label.
    async fn update_secret_version_stage(
        &self,
        cred: &Credential,
        secret_id: &str,
        region: &str,
        version_stage: &str,
        move_to: Option<&str>,
        remove_from: Option<&str>,
    ) -> Result<CasOutcome, SessionError>;
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

    /// One recorded `PutSecretValue` (the *test* may inspect the secret string —
    /// it is fake data; THREAT-MODEL governs production code, not test doubles).
    #[derive(Debug, Clone)]
    pub struct PutCall {
        pub secret_string: String,
        pub token: String,
        pub version_stages: Vec<String>,
    }

    /// One recorded `UpdateSecretVersionStage` (the commit, the settle, or a cleanup).
    #[derive(Debug, Clone)]
    pub struct StageCall {
        pub version_stage: String,
        pub move_to: Option<String>,
        pub remove_from: Option<String>,
    }

    /// A scripted secrets client. Reads/puts/stage-commits each pop the next
    /// scripted outcome; label-strips (settle/cleanup, `move_to == None`) always
    /// succeed and are only recorded. Build with [`new`](Self::new) (read-only,
    /// from `RawSecret`s) or the write builders below.
    pub struct FakeSecretsApi {
        pub reads: Mutex<Vec<Result<ReadSecret, SessionError>>>,
        pub list_outcomes: Mutex<Vec<Result<Vec<SecretSummary>, SessionError>>>,
        pub put_outcomes: Mutex<Vec<Result<String, SessionError>>>,
        pub stage_outcomes: Mutex<Vec<Result<CasOutcome, SessionError>>>,
        pub calls: Mutex<u32>,
        pub put_calls: Mutex<Vec<PutCall>>,
        pub stage_calls: Mutex<Vec<StageCall>>,
    }
    impl FakeSecretsApi {
        fn empty() -> Self {
            FakeSecretsApi {
                reads: Mutex::new(Vec::new()),
                list_outcomes: Mutex::new(Vec::new()),
                put_outcomes: Mutex::new(Vec::new()),
                stage_outcomes: Mutex::new(Vec::new()),
                calls: Mutex::new(0),
                put_calls: Mutex::new(Vec::new()),
                stage_calls: Mutex::new(Vec::new()),
            }
        }
        /// Read-only fake: each `get_secret_value` returns the next `RawSecret`
        /// (with no `VersionId`). Back-compat shape for the read-path tests.
        pub fn new(outcomes: Vec<Result<RawSecret, SessionError>>) -> Self {
            let reads = outcomes
                .into_iter()
                .map(|r| {
                    r.map(|raw| ReadSecret {
                        raw,
                        version_id: None,
                    })
                })
                .collect();
            let fake = Self::empty();
            *fake.reads.lock().unwrap() = reads;
            fake
        }
        /// Build a fake whose `list_secrets` returns `lists` (one per call).
        pub fn with_lists(lists: Vec<Result<Vec<SecretSummary>, SessionError>>) -> Self {
            let fake = Self::empty();
            *fake.list_outcomes.lock().unwrap() = lists;
            fake
        }
        /// Builder: script the `get_secret_value` outcomes (with `VersionId`s, for
        /// the write CAS).
        pub fn reads(self, reads: Vec<Result<ReadSecret, SessionError>>) -> Self {
            *self.reads.lock().unwrap() = reads;
            self
        }
        /// Builder: script the `put_secret_value` outcomes (the new version ids).
        pub fn puts(self, puts: Vec<Result<String, SessionError>>) -> Self {
            *self.put_outcomes.lock().unwrap() = puts;
            self
        }
        /// Builder: script the CAS-commit outcomes (one per `AWSCURRENT` move).
        pub fn stages(self, stages: Vec<Result<CasOutcome, SessionError>>) -> Self {
            *self.stage_outcomes.lock().unwrap() = stages;
            self
        }
        pub fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
        pub fn put_calls(&self) -> Vec<PutCall> {
            self.put_calls.lock().unwrap().clone()
        }
        pub fn stage_calls(&self) -> Vec<StageCall> {
            self.stage_calls.lock().unwrap().clone()
        }
    }

    /// A scripted `Ok(ReadSecret)` for a JSON-string secret at `version_id`.
    pub fn read_json(secret_string: &str, version_id: &str) -> Result<ReadSecret, SessionError> {
        Ok(ReadSecret {
            raw: RawSecret {
                secret_string: Some(secret_string.to_string()),
                secret_binary: None,
            },
            version_id: Some(version_id.to_string()),
        })
    }

    #[async_trait]
    impl SecretsApi for FakeSecretsApi {
        async fn get_secret_value(
            &self,
            _cred: &Credential,
            _secret_id: &str,
            _region: &str,
        ) -> Result<ReadSecret, SessionError> {
            *self.calls.lock().unwrap() += 1;
            let mut v = self.reads.lock().unwrap();
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

        async fn put_secret_value(
            &self,
            _cred: &Credential,
            _secret_id: &str,
            _region: &str,
            secret_string: Zeroizing<String>,
            client_request_token: &str,
            version_stages: &[String],
        ) -> Result<String, SessionError> {
            self.put_calls.lock().unwrap().push(PutCall {
                secret_string: secret_string.to_string(),
                token: client_request_token.to_string(),
                version_stages: version_stages.to_vec(),
            });
            let mut v = self.put_outcomes.lock().unwrap();
            if v.is_empty() {
                panic!("FakeSecretsApi::put_secret_value called more times than scripted");
            }
            v.remove(0)
        }

        async fn update_secret_version_stage(
            &self,
            _cred: &Credential,
            _secret_id: &str,
            _region: &str,
            version_stage: &str,
            move_to: Option<&str>,
            remove_from: Option<&str>,
        ) -> Result<CasOutcome, SessionError> {
            self.stage_calls.lock().unwrap().push(StageCall {
                version_stage: version_stage.to_string(),
                move_to: move_to.map(str::to_string),
                remove_from: remove_from.map(str::to_string),
            });
            // A label-strip (settle/cleanup) moves nothing — it always succeeds in
            // the fake; only a CAS commit (an `AWSCURRENT` move) pops a scripted
            // outcome, so write tests script just the commit results.
            if move_to.is_none() {
                return Ok(CasOutcome::Committed);
            }
            let mut v = self.stage_outcomes.lock().unwrap();
            if v.is_empty() {
                panic!("FakeSecretsApi::update_secret_version_stage(commit) called more times than scripted");
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
