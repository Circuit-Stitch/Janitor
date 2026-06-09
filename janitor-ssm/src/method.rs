//! `SsmDotenvMethod` (ADR 0031): the remote-`.env`-over-SSM [`ResourceMethod`] —
//! read+parse one `.env`, the non-stomping CAS write, the session-logging advisory,
//! and the `instance → .env path` Discovery tail, all behind the shared
//! `ResourceMethod` seam so the generic `AwsFamilyProvider` shell drives it.
//!
//! This is what remains of the old `janitor-ssm::SsmProvider` after the auth shell
//! (sign-in, broker, **and now** the force-refresh + re-Sign-in ladder + ADR 0018
//! stale-role recovery) moved into `janitor-aws-auth::AwsFamilyProvider`. The key
//! behaviour change of this slice: SSM **gains** that resilience for free — a stale
//! role on an SSM Environment now auto-corrects instead of failing the matrix.

use std::sync::Arc;

use async_trait::async_trait;

use janitor_aws_auth::error::SessionError;
use janitor_aws_auth::method::{MethodError, ResourceMethod};
use janitor_aws_auth::types::{Credential, SsoToken};
use janitor_aws_auth::wire::{AccountCatalog, RoleCredentialClient};
use janitor_aws_auth::write::{EnvEdit, WriteOutcome};
use janitor_core::config::{Mapping, Method};
use janitor_core::discovery::Steps;
use janitor_core::secret::SecretShape;

use crate::discovery::SsmSteps;
use crate::logging::{session_logging_advisory, LoggingPreference};
use crate::source::{read_and_parse, split_secret_id, write_dotenv, DotenvWriteError};
use crate::wire::{InstanceCatalog, RemoteFileReader, RemoteFileWriter};

/// The remote-`.env`-over-SSM resource method. Holds the account/role catalog, the
/// SSM tail seams (instance catalog, the file reader + writer, the session-logging
/// probe), and supplies the `instance → .env path → read+parse` Discovery tail.
pub struct SsmDotenvMethod {
    catalog: Arc<dyn AccountCatalog>,
    role_client: Arc<dyn RoleCredentialClient>,
    instances: Arc<dyn InstanceCatalog>,
    reader: Arc<dyn RemoteFileReader>,
    writer: Arc<dyn RemoteFileWriter>,
    logging: Arc<dyn LoggingPreference>,
}

impl SsmDotenvMethod {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        catalog: Arc<dyn AccountCatalog>,
        role_client: Arc<dyn RoleCredentialClient>,
        instances: Arc<dyn InstanceCatalog>,
        reader: Arc<dyn RemoteFileReader>,
        writer: Arc<dyn RemoteFileWriter>,
        logging: Arc<dyn LoggingPreference>,
    ) -> Self {
        SsmDotenvMethod {
            catalog,
            role_client,
            instances,
            reader,
            writer,
            logging,
        }
    }
}

#[async_trait]
impl ResourceMethod for SsmDotenvMethod {
    fn kind(&self) -> Method {
        Method::SsmDotenv
    }

    /// Always probes the org's SSM session-logging policy before a read (the runtime
    /// answer may still be "no logging").
    fn has_advisory(&self) -> bool {
        true
    }

    /// Read `mapping`'s remote `.env` (authorized by `cred`) and parse it: split the
    /// `<instance-id>:<path>` location, then read+parse. A read failure masks to
    /// [`MethodError::Session`]; a malformed `.env` to [`MethodError::Content`]
    /// (preserving `"malformed .env line N"`). An unresolvable location is `NotFound`.
    async fn fetch(
        &self,
        cred: &Credential,
        mapping: &Mapping,
    ) -> Result<SecretShape, MethodError> {
        let (instance_id, path) = split_secret_id(&mapping.secret_id)
            // A Mapping whose location is not `<instance-id>:<path>` resolves to
            // nothing — surface it masked, never echoing the malformed string.
            .ok_or(MethodError::Session(SessionError::NotFound))?;
        read_and_parse(
            self.reader.as_ref(),
            cred,
            instance_id,
            &mapping.region,
            path,
        )
        .await
    }

    /// Apply `edits` to `mapping`'s remote `.env` under the non-stomping CAS guard
    /// (ADR 0029 / ADR 0001), authorized by `cred`: split the location, then
    /// read-modify-write. The Provider port never calls this in v1 (read-only); it
    /// is the seam the write path (B5) rides. `SsmWriter::write` is the same `split →
    /// write_dotenv` mapped onto its own broker mint.
    async fn write(
        &self,
        cred: &Credential,
        mapping: &Mapping,
        edits: &[EnvEdit],
    ) -> Result<WriteOutcome, MethodError> {
        let (instance_id, path) = split_secret_id(&mapping.secret_id)
            .ok_or(MethodError::Session(SessionError::NotFound))?;
        write_dotenv(
            self.reader.as_ref(),
            self.writer.as_ref(),
            cred,
            instance_id,
            &mapping.region,
            path,
            edits,
        )
        .await
        .map_err(|e| match e {
            DotenvWriteError::Session(se) => MethodError::Session(se),
            // NotText / invalid-key → an unusable payload, masked Unsupported with
            // its error-safe detail (never a Value or `.env` line content).
            other => MethodError::Content {
                detail: other.detail(),
            },
        })
    }

    /// Probe the org's SSM session-logging policy (authorized by `cred`) and distil
    /// it to an operator advisory (ADR 0025). `None` means "no logging configured"
    /// (or the doc is absent); the shell only calls this on a successful mint.
    async fn advisory(&self, cred: &Credential, mapping: &Mapping) -> Option<String> {
        let probe = self.logging.session_logging(cred, &mapping.region).await;
        session_logging_advisory(&probe)
    }

    /// The `account → role → instance → .env path → read+parse` Discovery tail. The
    /// shell wraps this in an `Orchestrator`, drains the mid-walk logging advisory,
    /// and stamps `Method::SsmDotenv` onto the `Done` Mapping.
    fn discovery_steps(
        &self,
        environment: String,
        region: String,
        token: Arc<SsoToken>,
        remembered: Option<Mapping>,
    ) -> Box<dyn Steps> {
        Box::new(SsmSteps::new(
            token,
            Arc::clone(&self.catalog),
            Arc::clone(&self.role_client),
            Arc::clone(&self.instances),
            Arc::clone(&self.reader),
            Arc::clone(&self.logging),
            environment,
            region,
            remembered,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::fakes::FakeLoggingPreference;
    use crate::logging::LoggingState;
    use crate::wire::fakes::{FakeInstanceCatalog, FakeRemoteFileReader, FakeRemoteFileWriter};
    use crate::wire::InstanceSummary;
    use janitor_aws_auth::wire::fakes::{
        CredSpec, FakeAccountCatalog, FakeClock, FakeReauth, FakeRoleClient,
    };
    use janitor_aws_auth::wire::{AccountSummary, RawSecret, RoleSummary};
    use janitor_aws_auth::AwsFamilyProvider;
    use janitor_core::config::Application;
    use janitor_core::provider::{FetchFailReason, Provider};
    use std::collections::BTreeMap;
    use std::time::{Duration, SystemTime};

    fn cred() -> Credential {
        Credential::new("a".into(), "b".into(), "c".into(), SystemTime::UNIX_EPOCH)
    }
    fn mapping(secret_id: &str) -> Mapping {
        Mapping {
            environment: "prod".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: secret_id.into(),
            permission_set: "ReadOnly".into(),
            method: Method::SsmDotenv,
        }
    }
    fn cred_ok() -> Result<CredSpec, SessionError> {
        Ok(CredSpec {
            expires_in: Duration::from_secs(3600),
            tag: "t",
        })
    }
    fn role_not_entitled() -> Result<CredSpec, SessionError> {
        Err(SessionError::RoleNotEntitled {
            context: "ForbiddenException: No access".into(),
        })
    }

    /// A method with a scripted reader/writer/logging; catalog + instances are empty
    /// (fetch/write/advisory tests don't drive discovery).
    fn method(
        reader: Arc<FakeRemoteFileReader>,
        writer: Arc<FakeRemoteFileWriter>,
        logging: Arc<FakeLoggingPreference>,
    ) -> SsmDotenvMethod {
        SsmDotenvMethod::new(
            Arc::new(FakeAccountCatalog::new(vec![], vec![])),
            Arc::new(FakeRoleClient::new(vec![])),
            Arc::new(FakeInstanceCatalog::new(vec![])),
            reader,
            writer,
            logging,
        )
    }

    #[test]
    fn kind_is_ssm_dotenv_and_has_advisory() {
        let m = method(
            Arc::new(FakeRemoteFileReader::new(vec![])),
            Arc::new(FakeRemoteFileWriter::new(vec![])),
            Arc::new(FakeLoggingPreference::off()),
        );
        assert_eq!(m.kind(), Method::SsmDotenv);
        assert!(m.has_advisory(), "SSM always probes session logging");
    }

    #[tokio::test]
    async fn fetch_splits_the_location_then_reads_and_parses() {
        let reader = Arc::new(FakeRemoteFileReader::with_dotenv(vec!["A=1\nB=two"]));
        let m = method(
            reader.clone(),
            Arc::new(FakeRemoteFileWriter::new(vec![])),
            Arc::new(FakeLoggingPreference::off()),
        );
        let shape = m
            .fetch(&cred(), &mapping("i-0abc:/app/.env"))
            .await
            .unwrap();
        assert!(matches!(shape, SecretShape::Json(_)));
        assert_eq!(reader.seen(), vec![("i-0abc".into(), "/app/.env".into())]);
    }

    #[tokio::test]
    async fn fetch_unresolvable_location_is_not_found_without_reading() {
        let reader = Arc::new(FakeRemoteFileReader::new(vec![]));
        let m = method(
            reader.clone(),
            Arc::new(FakeRemoteFileWriter::new(vec![])),
            Arc::new(FakeLoggingPreference::off()),
        );
        let err = m
            .fetch(&cred(), &mapping("i-0abc-no-colon"))
            .await
            .unwrap_err();
        assert_eq!(err.reason(), FetchFailReason::NotFound);
        assert_eq!(
            reader.call_count(),
            0,
            "no read for an unresolvable location"
        );
    }

    #[tokio::test]
    async fn fetch_malformed_dotenv_is_content_with_the_line_detail() {
        let reader = Arc::new(FakeRemoteFileReader::with_dotenv(vec![
            "A=1\nNOEQUALS_secret",
        ]));
        let m = method(
            reader,
            Arc::new(FakeRemoteFileWriter::new(vec![])),
            Arc::new(FakeLoggingPreference::off()),
        );
        let err = m
            .fetch(&cred(), &mapping("i-0abc:/app/.env"))
            .await
            .unwrap_err();
        assert!(matches!(err, MethodError::Content { .. }));
        assert_eq!(err.detail(), "malformed .env line 2");
        assert!(
            !err.detail().contains("NOEQUALS_secret"),
            "no line content leaks"
        );
    }

    #[tokio::test]
    async fn write_splits_then_writes_under_the_cas_guard() {
        let reader = Arc::new(FakeRemoteFileReader::with_dotenv(vec!["A=1\n"]));
        let writer = Arc::new(FakeRemoteFileWriter::new(vec![Ok(WriteOutcome::Applied)]));
        let m = method(
            reader,
            writer.clone(),
            Arc::new(FakeLoggingPreference::off()),
        );
        let outcome = m
            .write(
                &cred(),
                &mapping("i-0abc:/app/.env"),
                &[EnvEdit::set("A", "2")],
            )
            .await
            .unwrap();
        assert_eq!(outcome, WriteOutcome::Applied);
        assert_eq!(writer.seen()[0].content, b"A=2\n");
        assert_eq!(writer.seen()[0].path, "/app/.env");
    }

    #[tokio::test]
    async fn write_invalid_key_is_content_unsupported() {
        let m = method(
            Arc::new(FakeRemoteFileReader::new(vec![])),
            Arc::new(FakeRemoteFileWriter::new(vec![])),
            Arc::new(FakeLoggingPreference::off()),
        );
        let err = m
            .write(
                &cred(),
                &mapping("i-0abc:/app/.env"),
                &[EnvEdit::set("A=B", "v")],
            )
            .await
            .unwrap_err();
        assert_eq!(err.reason(), FetchFailReason::Unsupported);
        assert!(matches!(err, MethodError::Content { .. }));
    }

    #[tokio::test]
    async fn write_unresolvable_location_is_not_found() {
        let m = method(
            Arc::new(FakeRemoteFileReader::new(vec![])),
            Arc::new(FakeRemoteFileWriter::new(vec![])),
            Arc::new(FakeLoggingPreference::off()),
        );
        let err = m
            .write(&cred(), &mapping("no-colon"), &[EnvEdit::set("A", "2")])
            .await
            .unwrap_err();
        assert_eq!(err.reason(), FetchFailReason::NotFound);
    }

    #[tokio::test]
    async fn advisory_warns_when_logging_is_on_and_is_silent_when_off() {
        let on = method(
            Arc::new(FakeRemoteFileReader::new(vec![])),
            Arc::new(FakeRemoteFileWriter::new(vec![])),
            Arc::new(FakeLoggingPreference::always(LoggingState {
                cloudwatch: true,
                ..Default::default()
            })),
        );
        let adv = on
            .advisory(&cred(), &mapping("i-0abc:/app/.env"))
            .await
            .expect("logging-on yields an advisory");
        assert!(adv.contains("CloudWatch"));

        let off = method(
            Arc::new(FakeRemoteFileReader::new(vec![])),
            Arc::new(FakeRemoteFileWriter::new(vec![])),
            Arc::new(FakeLoggingPreference::off()),
        );
        assert!(off
            .advisory(&cred(), &mapping("i-0abc:/app/.env"))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn discovery_steps_pose_the_path_input_then_done_with_ssm_tag() {
        use janitor_core::discovery::Orchestrator;
        use janitor_core::provider::Step;
        let m = SsmDotenvMethod::new(
            Arc::new(FakeAccountCatalog::new(
                vec![Ok(vec![AccountSummary {
                    id: "111".into(),
                    name: "Prod".into(),
                }])],
                vec![Ok(vec![RoleSummary {
                    name: "ReadOnly".into(),
                }])],
            )),
            Arc::new(FakeRoleClient::new(vec![cred_ok()])),
            Arc::new(FakeInstanceCatalog::new(vec![Ok(vec![InstanceSummary {
                id: "i-0abc".into(),
                name: "web".into(),
            }])])),
            Arc::new(FakeRemoteFileReader::new(vec![Ok(RawSecret {
                secret_string: Some("A=1".into()),
                secret_binary: None,
            })])),
            Arc::new(FakeRemoteFileWriter::new(vec![])),
            Arc::new(FakeLoggingPreference::off()),
        );
        let token = Arc::new(SsoToken::new(
            "session".into(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(28800),
        ));
        let steps = m.discovery_steps("prod".into(), "us-west-2".into(), token, None);
        let mut orch: Orchestrator<Box<dyn Steps>> = Orchestrator::new(steps);
        assert!(matches!(orch.start().await, Step::Input { .. }));
        let Step::Done(mapping) = orch.provide_input("/srv/.env".into()).await else {
            panic!("expected Done after the path input");
        };
        assert_eq!(mapping.secret_id, "i-0abc:/srv/.env");
        assert_eq!(mapping.method, Method::SsmDotenv);
    }

    // ---- the headline behaviour change: SSM GAINS the recovery ladder ----

    #[tokio::test]
    async fn ssm_method_gains_stale_role_recovery_through_the_shell() {
        // Previously the SSM Provider had NO stale-role recovery — a de-assigned
        // role failed the matrix. Behind the unified shell it auto-corrects, exactly
        // like Secrets Manager (ADR 0031 Consequences; a strict improvement).
        //
        // SSM has_advisory=true, so the load probes first: probe mint → RoleNotEntitled
        // (swallowed), fetch mint → RoleNotEntitled (recovery), re-list → PowerUser,
        // corrected mint → ok, then the read succeeds.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![
            role_not_entitled(), // advisory probe mint
            role_not_entitled(), // fetch mint → triggers recovery
            cred_ok(),           // corrected (PowerUser) mint
        ]));
        let catalog = Arc::new(FakeAccountCatalog::new(
            vec![],
            vec![Ok(vec![RoleSummary {
                name: "PowerUser".into(),
            }])],
        ));
        let ssm = Arc::new(SsmDotenvMethod::new(
            catalog.clone(),
            role.clone(),
            Arc::new(FakeInstanceCatalog::new(vec![])),
            Arc::new(FakeRemoteFileReader::with_dotenv(vec!["A=1"])),
            Arc::new(FakeRemoteFileWriter::new(vec![])),
            Arc::new(FakeLoggingPreference::off()),
        ));
        let mut methods: BTreeMap<Method, Arc<dyn ResourceMethod>> = BTreeMap::new();
        methods.insert(Method::SsmDotenv, ssm);
        let mut provider = AwsFamilyProvider::new(
            reauth,
            role.clone(),
            catalog.clone(),
            Arc::new(FakeClock::at(0)),
            methods,
        );

        let app = Application {
            name: "app".into(),
            environments: vec![mapping("i-0abc:/app/.env")],
        };
        let loaded = provider.load(&app).await.expect("recovered load");
        assert_eq!(loaded.view.environments, vec!["prod"]);
        assert_eq!(loaded.corrected.len(), 1, "the SSM env was auto-corrected");
        assert_eq!(loaded.corrected[0].permission_set, "PowerUser");
        assert_eq!(
            loaded.corrected[0].method,
            Method::SsmDotenv,
            "the method tag survives recovery"
        );
        assert_eq!(catalog.role_call_count(), 1, "exactly one re-list");
        assert_eq!(role.call_count(), 3, "probe + fetch + corrected mints");
    }
}
