//! The SSM tail's SDK seams (ADR 0010 §5, ADR 0025). Each trait wraps the SSM
//! ops the remote-`.env` walk uses; its I/O are our own SDK-free types, so the
//! orchestration / parsing / error mapping is tested against the fakes here
//! without any AWS dependency. The shared front-half seams
//! (`RoleCredentialClient`, `AccountCatalog`, `Reauth`, the summaries,
//! `RawSecret`) live in `janitor_aws_auth::wire`. The real impls (the concrete
//! `DescribeInstanceInformation` + Session Manager transport) are the untested
//! shell deferred to B4 (ADR 0025 §3); they live in the GUI's worker shell until
//! then, so this crate stays pure tested logic.

use async_trait::async_trait;

use janitor_aws_auth::error::SessionError;
use janitor_aws_auth::types::Credential;
use janitor_aws_auth::wire::RawSecret;
use janitor_core::select::Selectable;

/// One SSM-managed Instance (`DescribeInstanceInformation`). `id` is the stable
/// identity (the instance id, e.g. `i-0abc…`); `name` is the friendly label
/// (the `Name` tag or `ComputerName`, falling back to `id` when neither is set).
/// `Selectable` by `id` so a remembered instance pre-selects across launches.
#[derive(Debug, Clone, PartialEq)]
pub struct InstanceSummary {
    pub id: String,
    pub name: String,
}
impl Selectable for InstanceSummary {
    fn key(&self) -> &str {
        &self.id
    }
    fn label(&self) -> String {
        // Show both when a friendly name exists (instances often share a `Name`
        // tag, so the id disambiguates); bare id when `name` fell back to it.
        if self.name == self.id {
            self.id.clone()
        } else {
            format!("{} ({})", self.name, self.id)
        }
    }
}

/// Wraps `DescribeInstanceInformation`: lists the SSM-managed Instances the
/// minted Credential can reach in `region`. Returns id+name summaries only —
/// never a Value.
#[async_trait]
pub trait InstanceCatalog: Send + Sync {
    /// `DescribeInstanceInformation` in `region`, authorized by `cred`.
    async fn describe_instances(
        &self,
        cred: &Credential,
        region: &str,
    ) -> Result<Vec<InstanceSummary>, SessionError>;
}

/// Reads a file's bytes off `instance_id` over SSM Session Manager, authorized
/// by `cred` in `region`. Returns the raw payload in a zeroizing [`RawSecret`]
/// on success (ADR 0024); a read failure surfaces as a [`SessionError`] that the
/// caller masks. The concrete transport (`AWS-StartNonInteractiveCommand` /
/// the MGS data-channel) is the untested shell chosen + committed in B4
/// (ADR 0025 §3); the orchestration that drives this seam is tested against
/// `FakeRemoteFileReader`.
#[async_trait]
pub trait RemoteFileReader: Send + Sync {
    /// Read `path` off `instance_id` over SSM, using `cred` in `region`.
    async fn read_file(
        &self,
        cred: &Credential,
        instance_id: &str,
        region: &str,
        path: &str,
    ) -> Result<RawSecret, SessionError>;
}

// ----------------------------------------------------------------------------
// Fakes for unit tests. Available to this crate's own tests (the `test` cfg)
// and, via the `test-support` feature, to dependent crates' tests (the GUI
// worker's offline end-to-end test) — never compiled into a normal build
// (ADR 0024). The front-half fakes (FakeReauth/FakeAccountCatalog/…) come from
// `janitor_aws_auth::wire::fakes`.
// ----------------------------------------------------------------------------
#[cfg(any(test, feature = "test-support"))]
pub mod fakes {
    use super::*;
    use std::sync::Mutex;

    /// A scripted instance catalog: each `describe_instances` call pops the next
    /// scripted outcome (so a discovery walk's instance listing is driven without
    /// AWS), panicking if called more often than scripted.
    pub struct FakeInstanceCatalog {
        pub lists: Mutex<Vec<Result<Vec<InstanceSummary>, SessionError>>>,
        pub calls: Mutex<u32>,
    }
    impl FakeInstanceCatalog {
        pub fn new(lists: Vec<Result<Vec<InstanceSummary>, SessionError>>) -> Self {
            FakeInstanceCatalog {
                lists: Mutex::new(lists),
                calls: Mutex::new(0),
            }
        }
        pub fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }
    #[async_trait]
    impl InstanceCatalog for FakeInstanceCatalog {
        async fn describe_instances(
            &self,
            _cred: &Credential,
            _region: &str,
        ) -> Result<Vec<InstanceSummary>, SessionError> {
            *self.calls.lock().unwrap() += 1;
            let mut v = self.lists.lock().unwrap();
            if v.is_empty() {
                panic!("FakeInstanceCatalog called more times than scripted");
            }
            v.remove(0)
        }
    }

    /// A scripted remote-file reader: each `read_file` call pops the next scripted
    /// outcome and records the `(instance_id, path)` it was handed (so a test can
    /// assert the discovered location round-tripped through the walk), panicking
    /// if called more often than scripted.
    pub struct FakeRemoteFileReader {
        pub reads: Mutex<Vec<Result<RawSecret, SessionError>>>,
        pub seen: Mutex<Vec<(String, String)>>,
        pub calls: Mutex<u32>,
    }
    impl FakeRemoteFileReader {
        pub fn new(reads: Vec<Result<RawSecret, SessionError>>) -> Self {
            FakeRemoteFileReader {
                reads: Mutex::new(reads),
                seen: Mutex::new(Vec::new()),
                calls: Mutex::new(0),
            }
        }
        /// Convenience: a reader that returns the given `.env` text for every
        /// scripted call (one entry per `texts` item), as a `secret_string`.
        pub fn with_dotenv(texts: Vec<&str>) -> Self {
            Self::new(
                texts
                    .into_iter()
                    .map(|t| {
                        Ok(RawSecret {
                            secret_string: Some(t.to_string()),
                            secret_binary: None,
                        })
                    })
                    .collect(),
            )
        }
        pub fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
        pub fn seen(&self) -> Vec<(String, String)> {
            self.seen.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl RemoteFileReader for FakeRemoteFileReader {
        async fn read_file(
            &self,
            _cred: &Credential,
            instance_id: &str,
            _region: &str,
            path: &str,
        ) -> Result<RawSecret, SessionError> {
            *self.calls.lock().unwrap() += 1;
            self.seen
                .lock()
                .unwrap()
                .push((instance_id.to_string(), path.to_string()));
            let mut v = self.reads.lock().unwrap();
            if v.is_empty() {
                panic!("FakeRemoteFileReader called more times than scripted");
            }
            v.remove(0)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn instance_summary_exposes_key_and_label() {
            let i = InstanceSummary {
                id: "i-0abc".into(),
                name: "web-server".into(),
            };
            assert_eq!(i.key(), "i-0abc", "key is the stable instance id");
            assert_eq!(
                i.label(),
                "web-server (i-0abc)",
                "label shows the friendly name and the id"
            );
        }

        #[test]
        fn instance_summary_label_is_bare_id_when_name_fell_back() {
            // `name` falls back to `id` when there is no `Name` tag / `ComputerName`;
            // the label must not read "i-0abc (i-0abc)".
            let i = InstanceSummary {
                id: "i-0abc".into(),
                name: "i-0abc".into(),
            };
            assert_eq!(i.label(), "i-0abc");
        }

        #[test]
        fn fake_remote_file_reader_records_location_and_scripts_reads() {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let reader = FakeRemoteFileReader::with_dotenv(vec!["A=1"]);
            let cred = Credential::new(
                "a".into(),
                "b".into(),
                "c".into(),
                std::time::SystemTime::UNIX_EPOCH,
            );
            rt.block_on(async {
                let mut raw = reader
                    .read_file(&cred, "i-0abc", "us-east-1", "/app/.env")
                    .await
                    .unwrap();
                assert_eq!(raw.secret_string.take().as_deref(), Some("A=1"));
            });
            assert_eq!(reader.call_count(), 1);
            assert_eq!(reader.seen(), vec![("i-0abc".into(), "/app/.env".into())]);
        }
    }
}
