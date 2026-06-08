//! `SsmDiscovery` (ADR 0013 / ADR 0025): the remote-`.env`-over-SSM guided walk.
//! It mirrors `janitor-aws::Discovery`'s shared front half — `account → role →
//! mint Credential` (over the same `janitor-aws-auth` primitives) — then walks
//! its own tail: `instance → .env path → read+parse`. Like the SM walk it is
//! presenter-agnostic: `start()`/`advance()`/`provide_input()` return a `Step`
//! describing what to ask next or a terminal outcome, and it reuses the pure
//! `select::plan_selection` to collapse `0/1` choices and pre-select a remembered
//! default on `many`. Fully tested against the front-half `wire::fakes` plus
//! `FakeInstanceCatalog` / `FakeRemoteFileReader`.
//!
//! Two things differ from the SM walk. The Instance step lists with the **minted
//! Credential** (not the SSO token), exactly as the SM walk lists secrets. And
//! the `.env path` step is **free-text** (`Step::Input`, fed back via
//! [`SsmDiscovery::provide_input`]), not a list pick — then the file is read +
//! parsed **at the end of the walk**, so an unreadable or unparseable path fails
//! *in the wizard* (masked), not later at load (ADR 0025).
//!
//! The `account → role → mint` sequencing is deliberately duplicated with
//! `janitor-aws::Discovery` (ADR 0024/0025): that duplication across two *real*
//! shapes is the evidence #33/ADR 0026 extracts a shared `core` orchestrator from.

use std::sync::Arc;

use janitor_core::config::Mapping;
use janitor_core::provider::{Step, What};
use janitor_core::select::{plan_selection, Selectable, SelectionPlan};

use janitor_aws_auth::types::{Credential, SsoToken};
use janitor_aws_auth::wire::{AccountCatalog, AccountSummary, RoleCredentialClient, RoleSummary};

use crate::logging::{session_logging_advisory, LoggingPreference};
use crate::source::{read_and_parse, split_secret_id};
use crate::wire::{InstanceCatalog, InstanceSummary, RemoteFileReader};

/// The conventional default `.env` path, pre-filled into the path `Input` when no
/// remembered path exists for this Environment (ADR 0025 §2).
const DEFAULT_DOTENV_PATH: &str = "/app/.env";

/// What the machine is currently blocked on. The list variants hold the items
/// they listed so [`SsmDiscovery::advance`] resolves a chosen index back to the
/// item without re-listing; `Path` marks a walk paused on the free-text path
/// `Input`, answered through [`SsmDiscovery::provide_input`].
enum Awaiting {
    Account(Vec<AccountSummary>),
    Role(Vec<RoleSummary>),
    Instance(Vec<InstanceSummary>),
    Path,
}

/// The guided remote-`.env`-over-SSM walk for one Environment. Holds the SSO
/// token and the AWS seams; accumulates the account/role/credential/instance
/// picks and the typed path as it advances.
pub struct SsmDiscovery {
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
    account: Option<AccountSummary>,
    role: Option<RoleSummary>,
    cred: Option<Credential>,
    instance: Option<InstanceSummary>,
    path: Option<String>,
    awaiting: Option<Awaiting>,
    /// The session-logging advisory computed at the read (probed once we hold a
    /// credential), pulled up by the Provider after each step (ADR 0025).
    advisory: Option<String>,
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
            token,
            catalog,
            role_client,
            instances,
            reader,
            logging,
            environment,
            region,
            remembered,
            account: None,
            role: None,
            cred: None,
            instance: None,
            path: None,
            awaiting: None,
            advisory: None,
        }
    }

    /// Take the session-logging advisory computed during the read (the wizard
    /// surfaces it). `None` until the walk has reached the read, or if logging is
    /// off. Drained so the Provider surfaces it at most once.
    pub fn take_advisory(&mut self) -> Option<String> {
        self.advisory.take()
    }

    /// Begin the walk: collapse singleton steps until the first `many` choice (an
    /// `Ask`), the free-text path `Input`, or a terminal outcome.
    pub async fn start(&mut self) -> Step {
        self.resume().await
    }

    /// Feed back the user's chosen index for the list step the machine is blocked
    /// on, then continue. Out-of-range indices are clamped (mirrors
    /// `select::resolve`). An index fed while the walk awaits the path `Input` (or
    /// nothing) is a presenter bug; re-drive so we never wedge.
    pub async fn advance(&mut self, choice: usize) -> Step {
        match self.awaiting.take() {
            Some(Awaiting::Account(items)) => {
                self.account = Some(pick(items, choice));
                self.resume().await
            }
            Some(Awaiting::Role(items)) => {
                self.role = Some(pick(items, choice));
                self.resume().await
            }
            Some(Awaiting::Instance(items)) => {
                self.instance = Some(pick(items, choice));
                self.resume().await
            }
            // The path step wants text, not an index; re-drive re-emits the Input
            // (instance already chosen, so no re-listing). Nothing pending → same.
            Some(Awaiting::Path) | None => self.resume().await,
        }
    }

    /// Feed the user's typed `.env` path into a walk paused on the path `Input`,
    /// then read+parse the file to reach `Done`/`Failed`/`Reauth`. Text fed while
    /// a list `Ask` is pending (or nothing) is a presenter bug; re-drive.
    pub async fn provide_input(&mut self, text: String) -> Step {
        match self.awaiting.take() {
            Some(Awaiting::Path) => {
                self.path = Some(text);
                self.resume().await
            }
            other => {
                self.awaiting = other;
                self.resume().await
            }
        }
    }

    /// The shared forward drive: process whichever step is not yet decided,
    /// auto-picking singletons and falling through, stopping at the first
    /// `Ask`/`Input`/terminal state.
    async fn resume(&mut self) -> Step {
        if self.account.is_none() {
            let items = match self.catalog.list_accounts(&self.token).await {
                Ok(v) => v,
                Err(e) => return terminal_for(&e),
            };
            match plan_selection(&items, self.remembered_account()) {
                SelectionPlan::Empty => return Step::Empty(What::Accounts),
                SelectionPlan::Ask { default } => {
                    let step = ask(What::Accounts, &items, default);
                    self.awaiting = Some(Awaiting::Account(items));
                    return step;
                }
                SelectionPlan::Auto(i) => self.account = Some(pick(items, i)),
            }
        }

        if self.role.is_none() {
            let account_id = self.account.as_ref().unwrap().id.clone();
            let items = match self
                .catalog
                .list_account_roles(&self.token, &account_id)
                .await
            {
                Ok(v) => v,
                Err(e) => return terminal_for(&e),
            };
            match plan_selection(&items, self.remembered_role()) {
                SelectionPlan::Empty => return Step::Empty(What::Roles),
                SelectionPlan::Ask { default } => {
                    let step = ask(What::Roles, &items, default);
                    self.awaiting = Some(Awaiting::Role(items));
                    return step;
                }
                SelectionPlan::Auto(i) => self.role = Some(pick(items, i)),
            }
        }

        // Mint one role Credential for the chosen account+role+region so we can
        // list Instances and read the file. A dead token / policy refusal is terminal.
        if self.cred.is_none() {
            let account_id = self.account.as_ref().unwrap().id.clone();
            let role = self.role.as_ref().unwrap().name.clone();
            match self
                .role_client
                .get_role_credentials(&self.token, &account_id, &role, &self.region)
                .await
            {
                Ok(c) => self.cred = Some(c),
                Err(e) => return terminal_for(&e),
            }
            // Now we hold a credential, probe the org's SSM session-logging policy
            // *before* the instance/path steps and the read, so the wizard can warn
            // — while it is still open — that a read may be archived to S3/CloudWatch
            // (ADR 0025 / THREAT-MODEL). A probe failure biases toward warning; it
            // never blocks the walk.
            let probe = self
                .logging
                .session_logging(self.cred.as_ref().unwrap(), &self.region)
                .await;
            self.advisory = session_logging_advisory(&probe);
        }

        if self.instance.is_none() {
            let cred = self.cred.as_ref().unwrap();
            let items = match self.instances.describe_instances(cred, &self.region).await {
                Ok(v) => v,
                Err(e) => return terminal_for(&e),
            };
            match plan_selection(&items, self.remembered_instance()) {
                SelectionPlan::Empty => return Step::Empty(What::Instances),
                SelectionPlan::Ask { default } => {
                    let step = ask(What::Instances, &items, default);
                    self.awaiting = Some(Awaiting::Instance(items));
                    return step;
                }
                SelectionPlan::Auto(i) => self.instance = Some(pick(items, i)),
            }
        }

        // Instance chosen → ask for the free-text `.env` path (a remembered path
        // for this Environment, else the conventional default).
        if self.path.is_none() {
            self.awaiting = Some(Awaiting::Path);
            return Step::Input {
                what: What::FilePath,
                prompt: format!("Path to {}'s remote .env file", self.environment),
                default: Some(
                    self.remembered_path()
                        .unwrap_or_else(|| DEFAULT_DOTENV_PATH.to_string()),
                ),
            };
        }

        // Path supplied → read the file now so an unreadable/unparseable path
        // fails masked in the wizard (ADR 0025), not later at load.
        self.read_and_finish().await
    }

    /// Read+parse the chosen path to validate it, then build the `Done` Mapping
    /// (the parsed Set is validation-only here — `load` re-reads every Environment).
    async fn read_and_finish(&mut self) -> Step {
        let cred = self.cred.as_ref().unwrap();
        let instance_id = self.instance.as_ref().unwrap().id.clone();
        let path = self.path.as_ref().unwrap().clone();
        match read_and_parse(
            self.reader.as_ref(),
            cred,
            &instance_id,
            &self.region,
            &path,
        )
        .await
        {
            Ok(_shape) => Step::Done(self.build_mapping(&instance_id, &path)),
            Err(e) if e.is_reauth() => Step::Reauth,
            Err(e) => Step::Failed(e.reason()),
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

    /// Assemble the completed Mapping. `secret_id` is `<instance-id>:<path>` (the
    /// remote-`.env` Provider's "where the Set lives"); `region` is the resolved
    /// browse region; `permission_set` is the role (ADR 0025).
    fn build_mapping(&self, instance_id: &str, path: &str) -> Mapping {
        let account = self.account.as_ref().expect("account chosen before Done");
        let role = self.role.as_ref().expect("role chosen before Done");
        Mapping {
            environment: self.environment.clone(),
            account_id: account.id.clone(),
            region: self.region.clone(),
            secret_id: format!("{instance_id}:{path}"),
            permission_set: role.name.clone(),
        }
    }
}

/// Build a presenter-ready `Step::Ask`: project the listed items to their
/// `Selectable::label` lines (in list order, so the returned index maps straight
/// back to the kept items) and carry the remembered `default`.
fn ask<T: Selectable>(what: What, items: &[T], default: Option<usize>) -> Step {
    Step::Ask {
        what,
        choices: items.iter().map(|it| it.label()).collect(),
        default,
    }
}

/// Classify a `SessionError` into the right terminal `Step` (shared with the SM
/// walk's logic): `ReauthRequired` → `Reauth` so the presenter routes back to
/// Sign-in; everything else → a masked, retryable `Failed` carrying only the
/// tested `FetchFailReason` (no SDK text — THREAT-MODEL).
fn terminal_for(e: &janitor_aws_auth::error::SessionError) -> Step {
    match e {
        janitor_aws_auth::error::SessionError::ReauthRequired => Step::Reauth,
        _ => Step::Failed(e.into()),
    }
}

/// Resolve a chosen index against a listed set, clamping out-of-range to the last
/// item (a misbehaving presenter must never panic the walk).
fn pick<T>(mut items: Vec<T>, choice: usize) -> T {
    let i = choice.min(items.len() - 1);
    items.swap_remove(i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::fakes::FakeLoggingPreference;
    use crate::logging::LoggingState;
    use crate::wire::fakes::{FakeInstanceCatalog, FakeRemoteFileReader};
    use janitor_aws_auth::error::SessionError;
    use janitor_aws_auth::wire::fakes::{CredSpec, FakeAccountCatalog, FakeRoleClient};
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
