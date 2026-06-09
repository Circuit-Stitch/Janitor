//! `SsmDiscovery` (ADR 0013 / ADR 0025 / ADR 0026): the remote-`.env`-over-SSM
//! guided walk, expressed as a `janitor_core::discovery` *method* ([`Steps`]) driven
//! by the shared [`Orchestrator`].
//!
//! It mirrors `janitor-aws::Discovery`'s shared front half — `account → role → mint
//! Credential` (via [`front_half`] over the same `janitor-aws-auth` primitives, ADR
//! 0024 Decision 6) — then walks its own tail: `instance → .env path → read+parse`.
//! Like the SM walk it is presenter-agnostic: `start()`/`advance()`/`provide_input()`
//! return a `Step` describing what to ask next or a terminal outcome, and each
//! consumer writes a thin presenter. The walk *sequencing* (auto-pick collapsing,
//! stop-at-first-`Ask`/`Input`, resume, index clamping) now lives once in the
//! provider-agnostic [`Orchestrator`] (ADR 0026, #33); this file supplies only the
//! SSM *method*.
//!
//! Two things differ from the SM tail. The Instance step lists with the **minted
//! Credential** (not the SSO token), exactly as the SM walk lists secrets. And the
//! `.env path` step is **free-text** (`StepPlan::Input`, fed back via
//! [`Orchestrator::provide_input`]), not a list pick — then the file is read +
//! parsed **at the end of the walk**, so an unreadable or unparseable path fails *in
//! the wizard* (masked), not later at load (ADR 0025). Fully tested against the
//! front-half `wire::fakes` plus `FakeInstanceCatalog` / `FakeRemoteFileReader`.

use std::sync::Arc;

use async_trait::async_trait;

use janitor_core::config::{Mapping, Method};
use janitor_core::discovery::{Choice, Orchestrator, StepPlan, Steps};
use janitor_core::provider::{Step, What};

use janitor_aws_auth::authwalk::{front_half, terminal_for, FrontHalf};
use janitor_aws_auth::types::{Credential, SsoToken};
use janitor_aws_auth::wire::{AccountCatalog, RoleCredentialClient};

use crate::logging::{session_logging_advisory, LoggingPreference};
use crate::source::{read_and_parse, split_secret_id};
use crate::wire::{InstanceCatalog, RemoteFileReader};

/// The conventional default `.env` path, pre-filled into the path `Input` when no
/// remembered path exists for this Environment (ADR 0025 §2).
const DEFAULT_DOTENV_PATH: &str = "/app/.env";

/// The remote-`.env`-over-SSM Discovery method. Holds the SSO token and the AWS
/// seams; the state it carries across the (re-entrant) walk is the once-minted
/// Credential and the session-logging advisory — the chosen account/role/instance
/// keys and the typed path live in the orchestrator's `chosen`.
/// `pub(crate)` so [`SsmDotenvMethod`](crate::method::SsmDotenvMethod) can build it
/// as its Discovery tail (ADR 0031) — the same steps the `SsmDiscovery` handle the
/// live-verify binary uses drives.
pub(crate) struct SsmSteps {
    token: Arc<SsoToken>,
    catalog: Arc<dyn AccountCatalog>,
    role_client: Arc<dyn RoleCredentialClient>,
    instances: Arc<dyn InstanceCatalog>,
    reader: Arc<dyn RemoteFileReader>,
    logging: Arc<dyn LoggingPreference>,
    /// Environment name being added (typed by the user; not discovered).
    environment: String,
    /// Resolved browse region (`config.secret_region` else `sso_region`).
    region: String,
    /// The previous guided pick, offered as the default on a `many`/`Input` step.
    remembered: Option<Mapping>,
    /// The role Credential, minted once when account+role are chosen (guards the
    /// one-shot front-half mint + logging probe against a re-entrant `next`).
    cred: Option<Credential>,
    /// The session-logging advisory computed at the mint (probed once we hold a
    /// credential), pulled up by the shell after each step (ADR 0025).
    advisory: Option<String>,
}

impl SsmSteps {
    /// Build the remote-`.env`-over-SSM Discovery method (no I/O until driven).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        token: Arc<SsoToken>,
        catalog: Arc<dyn AccountCatalog>,
        role_client: Arc<dyn RoleCredentialClient>,
        instances: Arc<dyn InstanceCatalog>,
        reader: Arc<dyn RemoteFileReader>,
        logging: Arc<dyn LoggingPreference>,
        environment: String,
        region: String,
        remembered: Option<Mapping>,
    ) -> Self {
        SsmSteps {
            token,
            catalog,
            role_client,
            instances,
            reader,
            logging,
            environment,
            region,
            remembered,
            cred: None,
            advisory: None,
        }
    }

    fn remembered_account(&self) -> Option<&str> {
        self.remembered.as_ref().map(|m| m.account_id.as_str())
    }
    fn remembered_role(&self) -> Option<&str> {
        self.remembered.as_ref().map(|m| m.permission_set.as_str())
    }
    /// The remembered Instance id, parsed out of the remembered Mapping's
    /// `<instance-id>:<path>` location.
    fn remembered_instance(&self) -> Option<&str> {
        self.remembered
            .as_ref()
            .and_then(|m| split_secret_id(&m.secret_id))
            .map(|(instance, _)| instance)
    }
    /// The remembered `.env` path, parsed out of the remembered Mapping's
    /// `<instance-id>:<path>` location.
    fn remembered_path(&self) -> Option<String> {
        self.remembered
            .as_ref()
            .and_then(|m| split_secret_id(&m.secret_id))
            .map(|(_, path)| path.to_string())
    }

    /// Assemble the completed Mapping from the chosen keys. `secret_id` is
    /// `<instance-id>:<path>` (the remote-`.env` Provider's "where the Set lives");
    /// `region` is the resolved browse region; `permission_set` is the role (ADR 0025).
    fn build_mapping(
        &self,
        account_id: &str,
        role: &str,
        instance_id: &str,
        path: &str,
    ) -> Mapping {
        Mapping {
            environment: self.environment.clone(),
            account_id: account_id.to_string(),
            region: self.region.clone(),
            secret_id: format!("{instance_id}:{path}"),
            permission_set: role.to_string(),
            method: Method::SsmDotenv,
        }
    }
}

#[async_trait]
impl Steps for SsmSteps {
    /// `chosen` accumulates `[account_id, role, instance_id, path]`. The shared front
    /// half owns the first two (and the credential mint, after which we probe the
    /// org's SSM logging policy); the tail lists Instances, asks for the free-text
    /// path, then reads+parses to validate before assembling the Mapping.
    async fn next(&mut self, chosen: &[String]) -> StepPlan {
        // Front half: account → role → mint (runs only until we hold a Credential).
        if self.cred.is_none() {
            match front_half(
                chosen,
                &self.token,
                self.catalog.as_ref(),
                self.role_client.as_ref(),
                &self.region,
                self.remembered_account(),
                self.remembered_role(),
            )
            .await
            {
                FrontHalf::Plan(plan) => return plan,
                FrontHalf::Ready { cred, .. } => {
                    self.cred = Some(cred);
                    // Now we hold a credential, probe the org's SSM session-logging
                    // policy *before* the instance/path steps and the read, so the
                    // wizard can warn — while it is still open — that a read may be
                    // archived to S3/CloudWatch (ADR 0025 / THREAT-MODEL). A probe
                    // failure biases toward warning; it never blocks the walk.
                    let probe = self
                        .logging
                        .session_logging(self.cred.as_ref().unwrap(), &self.region)
                        .await;
                    self.advisory = session_logging_advisory(&probe);
                }
            }
        }

        // Tail: list Instances with the minted Credential (chosen[2]).
        if chosen.len() < 3 {
            let cred = self.cred.as_ref().unwrap();
            return match self.instances.describe_instances(cred, &self.region).await {
                Ok(items) => StepPlan::List {
                    what: What::Instances,
                    choices: Choice::project(&items),
                    remembered: self.remembered_instance().map(str::to_string),
                },
                Err(e) => StepPlan::Terminal(terminal_for(&e)),
            };
        }

        // Instance chosen → ask for the free-text `.env` path (chosen[3]): a
        // remembered path for this Environment, else the conventional default.
        if chosen.len() < 4 {
            return StepPlan::Input {
                what: What::FilePath,
                prompt: format!("Path to {}'s remote .env file", self.environment),
                default: Some(
                    self.remembered_path()
                        .unwrap_or_else(|| DEFAULT_DOTENV_PATH.to_string()),
                ),
            };
        }

        // Path supplied → read the file now so an unreadable/unparseable path fails
        // masked in the wizard (ADR 0025), not later at load. The parsed Set is
        // validation-only here — `load` re-reads every Environment.
        let cred = self.cred.as_ref().unwrap();
        match read_and_parse(
            self.reader.as_ref(),
            cred,
            &chosen[2],
            &self.region,
            &chosen[3],
        )
        .await
        {
            Ok(_shape) => {
                StepPlan::Done(self.build_mapping(&chosen[0], &chosen[1], &chosen[2], &chosen[3]))
            }
            Err(e) if e.is_reauth() => StepPlan::Terminal(Step::Reauth),
            Err(e) => StepPlan::Terminal(Step::Failed(e.reason())),
        }
    }

    /// Drain the session-logging advisory computed at the credential mint (the
    /// wizard surfaces it). `None` until the walk has minted, or if logging is off.
    /// The shell pulls it after each step via [`Orchestrator::take_advisory`].
    fn take_advisory(&mut self) -> Option<String> {
        self.advisory.take()
    }
}

/// The guided remote-`.env`-over-SSM discovery walk for one Environment: a thin
/// handle over the shared [`Orchestrator`] driving an [`SsmSteps`] method. The
/// public `new`/`start`/`advance`/`provide_input`/`take_advisory` surface is
/// unchanged (the worker/presenter are untouched).
pub struct SsmDiscovery {
    orch: Orchestrator<SsmSteps>,
}

impl SsmDiscovery {
    /// Build a walk. No I/O happens until [`start`](Self::start).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        environment: String,
        region: String,
        token: Arc<SsoToken>,
        catalog: Arc<dyn AccountCatalog>,
        role_client: Arc<dyn RoleCredentialClient>,
        instances: Arc<dyn InstanceCatalog>,
        reader: Arc<dyn RemoteFileReader>,
        logging: Arc<dyn LoggingPreference>,
        remembered: Option<Mapping>,
    ) -> Self {
        SsmDiscovery {
            orch: Orchestrator::new(SsmSteps::new(
                token,
                catalog,
                role_client,
                instances,
                reader,
                logging,
                environment,
                region,
                remembered,
            )),
        }
    }

    /// Take the session-logging advisory computed during the walk (the wizard
    /// surfaces it). Drained so the Provider surfaces it at most once.
    pub fn take_advisory(&mut self) -> Option<String> {
        self.orch.take_advisory()
    }

    /// Begin the walk: collapse singleton steps until the first `many` choice (an
    /// `Ask`), the free-text path `Input`, or a terminal outcome.
    pub async fn start(&mut self) -> Step {
        self.orch.start().await
    }

    /// Feed back the user's chosen index for the list step the walk is blocked on,
    /// then continue. Out-of-range indices are clamped.
    pub async fn advance(&mut self, choice: usize) -> Step {
        self.orch.advance(choice).await
    }

    /// Feed the user's typed `.env` path into a walk paused on the path `Input`, then
    /// read+parse the file to reach `Done`/`Failed`/`Reauth`.
    pub async fn provide_input(&mut self, text: String) -> Step {
        self.orch.provide_input(text).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::fakes::FakeLoggingPreference;
    use crate::logging::LoggingState;
    use crate::wire::fakes::{FakeInstanceCatalog, FakeRemoteFileReader};
    use crate::wire::InstanceSummary;
    use janitor_aws_auth::error::SessionError;
    use janitor_aws_auth::wire::fakes::{CredSpec, FakeAccountCatalog, FakeRoleClient};
    use janitor_aws_auth::wire::{AccountSummary, RoleSummary};
    use janitor_core::provider::FetchFailReason;
    use std::time::{Duration, SystemTime};

    fn token() -> Arc<SsoToken> {
        Arc::new(SsoToken::new(
            "session".into(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(28800),
        ))
    }
    fn account(id: &str, name: &str) -> AccountSummary {
        AccountSummary {
            id: id.into(),
            name: name.into(),
        }
    }
    fn role(name: &str) -> RoleSummary {
        RoleSummary { name: name.into() }
    }
    fn instance(id: &str, name: &str) -> InstanceSummary {
        InstanceSummary {
            id: id.into(),
            name: name.into(),
        }
    }
    fn cred_ok() -> Result<CredSpec, SessionError> {
        Ok(CredSpec {
            expires_in: Duration::from_secs(3600),
            tag: "t",
        })
    }

    /// Build a walk over the four fakes with the given scripted outcomes.
    #[allow(clippy::too_many_arguments)]
    fn discovery(
        environment: &str,
        region: &str,
        accounts: Vec<Result<Vec<AccountSummary>, SessionError>>,
        roles: Vec<Result<Vec<RoleSummary>, SessionError>>,
        creds: Vec<Result<CredSpec, SessionError>>,
        instances: Vec<Result<Vec<InstanceSummary>, SessionError>>,
        reads: Vec<Result<janitor_aws_auth::wire::RawSecret, SessionError>>,
        remembered: Option<Mapping>,
    ) -> SsmDiscovery {
        SsmDiscovery::new(
            environment.into(),
            region.into(),
            token(),
            Arc::new(FakeAccountCatalog::new(accounts, roles)),
            Arc::new(FakeRoleClient::new(creds)),
            Arc::new(FakeInstanceCatalog::new(instances)),
            Arc::new(FakeRemoteFileReader::new(reads)),
            Arc::new(FakeLoggingPreference::off()),
            remembered,
        )
    }

    fn dotenv(text: &str) -> Result<janitor_aws_auth::wire::RawSecret, SessionError> {
        Ok(janitor_aws_auth::wire::RawSecret {
            secret_string: Some(text.into()),
            secret_binary: None,
        })
    }

    #[tokio::test]
    async fn singletons_auto_pick_then_input_path_then_done_carries_instance_and_path() {
        // One account/role/instance auto-collapse; the walk pauses on the path
        // Input; the typed path round-trips into `<instance-id>:<path>`.
        let mut d = discovery(
            "prod",
            "us-west-2",
            vec![Ok(vec![account("111111111111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![cred_ok()],
            vec![Ok(vec![instance("i-0abc", "web")])],
            vec![dotenv("A=1\nB=two")],
            None,
        );

        let Step::Input {
            what,
            prompt,
            default,
        } = d.start().await
        else {
            panic!("expected the free-text path Input");
        };
        assert_eq!(what, What::FilePath);
        assert_eq!(prompt, "Path to prod's remote .env file");
        assert_eq!(
            default.as_deref(),
            Some("/app/.env"),
            "no remembered path → the conventional default is pre-filled"
        );

        let Step::Done(m) = d.provide_input("/srv/app/.env".into()).await else {
            panic!("expected Done after providing the path");
        };
        assert_eq!(m.environment, "prod");
        assert_eq!(m.account_id, "111111111111");
        assert_eq!(m.region, "us-west-2");
        assert_eq!(m.permission_set, "ReadOnly");
        assert_eq!(
            m.secret_id, "i-0abc:/srv/app/.env",
            "secret_id is exactly <instance-id>:<path>"
        );
    }

    #[tokio::test]
    async fn many_instances_ask_carries_labels_and_remembered_default() {
        // Singleton account+role auto-pick and the credential mints; the Instance
        // step has many → Ask, pre-selecting the remembered instance.
        let remembered = Mapping {
            environment: "live".into(),
            account_id: "111".into(),
            region: "us-east-1".into(),
            secret_id: "i-second:/app/.env".into(),
            permission_set: "ReadOnly".into(),
            method: Method::SsmDotenv,
        };
        let mut d = discovery(
            "staging",
            "us-east-1",
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![cred_ok()],
            vec![Ok(vec![
                instance("i-first", "alpha"),
                instance("i-second", "beta"),
            ])],
            vec![],
            Some(remembered),
        );

        let Step::Ask {
            what,
            choices,
            default,
        } = d.start().await
        else {
            panic!("expected Ask instances");
        };
        assert_eq!(what, What::Instances);
        assert_eq!(
            choices,
            vec!["alpha (i-first)".to_string(), "beta (i-second)".to_string()],
            "instances are labelled name (id), in list order"
        );
        assert_eq!(default, Some(1), "remembered instance i-second pre-selects");
    }

    #[tokio::test]
    async fn remembered_path_pre_fills_the_input_default() {
        // A prior pick on this instance remembered `/etc/app/.env`; the path Input
        // pre-fills it rather than the conventional default.
        let remembered = Mapping {
            environment: "live".into(),
            account_id: "111".into(),
            region: "us-east-1".into(),
            secret_id: "i-0abc:/etc/app/.env".into(),
            permission_set: "ReadOnly".into(),
            method: Method::SsmDotenv,
        };
        let mut d = discovery(
            "prod",
            "us-east-1",
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![cred_ok()],
            vec![Ok(vec![instance("i-0abc", "web")])],
            vec![],
            Some(remembered),
        );
        let Step::Input { default, .. } = d.start().await else {
            panic!("expected the path Input");
        };
        assert_eq!(default.as_deref(), Some("/etc/app/.env"));
    }

    #[tokio::test]
    async fn many_instances_advance_picks_then_input_then_done() {
        // Choosing the second instance continues to the path Input, then Done.
        let mut d = discovery(
            "prod",
            "us-east-1",
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![cred_ok()],
            vec![Ok(vec![
                instance("i-first", "alpha"),
                instance("i-second", "beta"),
            ])],
            vec![dotenv("A=1")],
            None,
        );
        assert!(matches!(
            d.start().await,
            Step::Ask {
                what: What::Instances,
                ..
            }
        ));
        assert!(matches!(d.advance(1).await, Step::Input { .. }));
        let Step::Done(m) = d.provide_input("/app/.env".into()).await else {
            panic!("expected Done");
        };
        assert_eq!(
            m.secret_id, "i-second:/app/.env",
            "chosen instance lands in the Mapping"
        );
    }

    #[tokio::test]
    async fn does_not_list_instances_or_read_before_the_account_is_chosen() {
        // Two accounts → Ask first, having listed nothing downstream.
        let instances = Arc::new(FakeInstanceCatalog::new(vec![]));
        let reader = Arc::new(FakeRemoteFileReader::new(vec![]));
        let rolec = Arc::new(FakeRoleClient::new(vec![]));
        let mut d = SsmDiscovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            Arc::new(FakeAccountCatalog::new(
                vec![Ok(vec![account("111", "Prod"), account("222", "Staging")])],
                vec![Ok(vec![role("ReadOnly")])],
            )),
            rolec.clone(),
            instances.clone(),
            reader.clone(),
            Arc::new(FakeLoggingPreference::off()),
            None,
        );
        assert!(matches!(
            d.start().await,
            Step::Ask {
                what: What::Accounts,
                ..
            }
        ));
        assert_eq!(
            rolec.call_count(),
            0,
            "no mint before the account is chosen"
        );
        assert_eq!(instances.call_count(), 0, "no instance listing yet");
        assert_eq!(reader.call_count(), 0, "no read yet");
    }

    #[tokio::test]
    async fn no_instances_is_empty_for_that_step() {
        let mut d = discovery(
            "prod",
            "us-east-1",
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![cred_ok()],
            vec![Ok(vec![])],
            vec![],
            None,
        );
        assert!(matches!(d.start().await, Step::Empty(What::Instances)));
    }

    #[tokio::test]
    async fn unreadable_path_fails_masked_in_the_wizard_not_at_load() {
        // The read happens at the end of the walk; a read failure surfaces as a
        // masked terminal `Failed` (no SDK text), not a `Done` deferred to load.
        let mut d = discovery(
            "prod",
            "us-east-1",
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![cred_ok()],
            vec![Ok(vec![instance("i-0abc", "web")])],
            vec![Err(SessionError::Sdk {
                context: "hunter2".into(),
            })],
            None,
        );
        assert!(matches!(d.start().await, Step::Input { .. }));
        let Step::Failed(reason) = d.provide_input("/app/.env".into()).await else {
            panic!("expected Failed for an unreadable path");
        };
        assert_eq!(reason, FetchFailReason::Other);
        assert!(!reason.describe().contains("hunter2"), "no SDK text leaks");
    }

    #[tokio::test]
    async fn malformed_dotenv_fails_unsupported_in_the_wizard() {
        let mut d = discovery(
            "prod",
            "us-east-1",
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![cred_ok()],
            vec![Ok(vec![instance("i-0abc", "web")])],
            vec![dotenv("A=1\nthisline_has_no_equals")],
            None,
        );
        assert!(matches!(d.start().await, Step::Input { .. }));
        let Step::Failed(reason) = d.provide_input("/app/.env".into()).await else {
            panic!("expected Failed for a malformed .env");
        };
        assert_eq!(reason, FetchFailReason::Unsupported);
    }

    #[tokio::test]
    async fn reauth_reading_the_path_is_reauth_step() {
        // A dead token surfaced by the file read routes back to Sign-in.
        let mut d = discovery(
            "prod",
            "us-east-1",
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![cred_ok()],
            vec![Ok(vec![instance("i-0abc", "web")])],
            vec![Err(SessionError::ReauthRequired)],
            None,
        );
        assert!(matches!(d.start().await, Step::Input { .. }));
        assert!(matches!(
            d.provide_input("/app/.env".into()).await,
            Step::Reauth
        ));
    }

    #[tokio::test]
    async fn no_accounts_is_empty_and_reauth_minting_is_reauth() {
        // The shared front half behaves exactly as the SM walk does.
        let mut empty = discovery(
            "prod",
            "us-east-1",
            vec![Ok(vec![])],
            vec![],
            vec![],
            vec![],
            vec![],
            None,
        );
        assert!(matches!(empty.start().await, Step::Empty(What::Accounts)));

        let mut dead = discovery(
            "prod",
            "us-east-1",
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![Err(SessionError::ReauthRequired)],
            vec![],
            vec![],
            None,
        );
        assert!(matches!(dead.start().await, Step::Reauth));
    }

    #[tokio::test]
    async fn reauth_listing_instances_is_reauth_step() {
        let mut d = discovery(
            "prod",
            "us-east-1",
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![cred_ok()],
            vec![Err(SessionError::ReauthRequired)],
            vec![],
            None,
        );
        assert!(matches!(d.start().await, Step::Reauth));
    }

    #[tokio::test]
    async fn throttled_listing_instances_is_failed_with_that_reason() {
        let mut d = discovery(
            "prod",
            "us-east-1",
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![cred_ok()],
            vec![Err(SessionError::Throttled)],
            vec![],
            None,
        );
        let Step::Failed(reason) = d.start().await else {
            panic!("expected Failed");
        };
        assert_eq!(reason, FetchFailReason::Throttled);
    }

    #[tokio::test]
    async fn advance_clamps_out_of_range_instance_choice() {
        let mut d = discovery(
            "prod",
            "us-east-1",
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![cred_ok()],
            vec![Ok(vec![
                instance("i-first", "alpha"),
                instance("i-second", "beta"),
            ])],
            vec![dotenv("A=1")],
            None,
        );
        assert!(matches!(d.start().await, Step::Ask { .. }));
        assert!(matches!(d.advance(99).await, Step::Input { .. }));
        let Step::Done(m) = d.provide_input("/app/.env".into()).await else {
            panic!("expected Done");
        };
        assert_eq!(
            m.secret_id, "i-second:/app/.env",
            "out-of-range clamps to the last instance"
        );
    }

    #[tokio::test]
    async fn read_probes_logging_and_exposes_an_advisory_when_on() {
        // The walk probes the org's SSM logging policy at the read; logging-on
        // yields a wizard advisory the Provider drains.
        let mut d = SsmDiscovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            Arc::new(FakeAccountCatalog::new(
                vec![Ok(vec![account("111", "Prod")])],
                vec![Ok(vec![role("ReadOnly")])],
            )),
            Arc::new(FakeRoleClient::new(vec![cred_ok()])),
            Arc::new(FakeInstanceCatalog::new(vec![Ok(vec![instance(
                "i-0abc", "web",
            )])])),
            Arc::new(FakeRemoteFileReader::new(vec![dotenv("A=1")])),
            Arc::new(FakeLoggingPreference::always(LoggingState {
                s3: true,
                ..Default::default()
            })),
            None,
        );
        assert!(matches!(d.start().await, Step::Input { .. }));
        // The probe runs at the credential mint, so the advisory is available *now*
        // — while the wizard is still posing the path Input, not only at the read.
        let adv = d
            .take_advisory()
            .expect("logging-on yields an advisory at mint time");
        assert!(adv.contains("S3"), "the advisory names the destination");
        assert!(matches!(
            d.provide_input("/app/.env".into()).await,
            Step::Done(_)
        ));
        assert!(
            d.take_advisory().is_none(),
            "drained — surfaced at most once"
        );
    }

    #[tokio::test]
    async fn no_advisory_when_logging_is_off() {
        let mut d = discovery(
            "prod",
            "us-east-1",
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
            vec![cred_ok()],
            vec![Ok(vec![instance("i-0abc", "web")])],
            vec![dotenv("A=1")],
            None,
        );
        assert!(matches!(d.start().await, Step::Input { .. }));
        assert!(matches!(
            d.provide_input("/app/.env".into()).await,
            Step::Done(_)
        ));
        assert!(d.take_advisory().is_none(), "logging off → no advisory");
    }
}
