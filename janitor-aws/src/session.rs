//! `Session` (GUI↔AWS bridge): lazy browser sign-in + per-Application,
//! multi-Environment fetch, behind the same ADR 0010 §5 seam the rest of the
//! crate uses. Lives in the GUI's worker thread; never crosses threads. All
//! orchestration here is unit-tested against the `wire::fakes`; only the real
//! adapters + browser are untested shell.

use crate::error::SessionError;

/// Why one Environment's fetch failed — a masked, owned classification of
/// `SessionError` (no SDK text; THREAT-MODEL). `Copy` so it is trivial to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchFailReason {
    /// A fresh browser Sign-in is required (dead/again-rejected token).
    NeedsSignIn,
    /// AWS refused under policy.
    AccessDenied,
    /// The secret id/region does not resolve.
    NotFound,
    /// Throttled or transient.
    Throttled,
    /// Content we cannot handle (e.g. binary for an op that needs text).
    Unsupported,
    /// Anything else (the scrubbed `Sdk` catch-all).
    Other,
}

impl FetchFailReason {
    /// A short, user-facing phrase. Never contains SDK/secret text.
    pub fn describe(self) -> &'static str {
        match self {
            FetchFailReason::NeedsSignIn => "session expired — sign in again",
            FetchFailReason::AccessDenied => "access denied",
            FetchFailReason::NotFound => "secret not found",
            FetchFailReason::Throttled => "throttled, try again",
            FetchFailReason::Unsupported => "unsupported secret content",
            FetchFailReason::Other => "AWS error",
        }
    }
}

impl From<&SessionError> for FetchFailReason {
    fn from(e: &SessionError) -> Self {
        match e {
            SessionError::ReauthRequired => FetchFailReason::NeedsSignIn,
            SessionError::AccessDenied => FetchFailReason::AccessDenied,
            // An un-recovered role denial surfaces as plain "access denied" — the
            // recovery attempt (ADR 0018) is upstream in `Session::load`; by the
            // time it becomes a `Failure`, recovery has already declined/failed.
            SessionError::RoleNotEntitled { .. } => FetchFailReason::AccessDenied,
            SessionError::NotFound => FetchFailReason::NotFound,
            SessionError::Throttled => FetchFailReason::Throttled,
            SessionError::Unsupported => FetchFailReason::Unsupported,
            SessionError::Sdk { .. } => FetchFailReason::Other,
        }
    }
}

/// One Environment's failure within a whole-Application load: the Environment
/// name, the classified `reason` (drives control flow + a fallback label), and
/// the real, error-safe `detail` (AWS `code: message`; ADR 0017). `detail` is
/// what the banner and Diagnostic Log show — never a Value/Credential/token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub environment: String,
    pub reason: FetchFailReason,
    pub detail: String,
}

/// A whole-Application load failure: at least one Environment failed, so no
/// matrix is shown (spec Decision 8 — never a partial matrix, never a fake Gap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppError {
    pub failures: Vec<Failure>,
}

impl AppError {
    /// The synthetic "you must sign in first" error (no real Environment failed).
    pub fn needs_sign_in() -> Self {
        AppError {
            failures: vec![Failure {
                environment: "(sign-in)".to_string(),
                reason: FetchFailReason::NeedsSignIn,
                detail: "a fresh Sign-in is required".to_string(),
            }],
        }
    }
}

use std::sync::Arc;

use janitor_core::compare::Comparison;
use janitor_core::compare::RowKey;
use janitor_core::config::{Application, Mapping};
use janitor_core::secret::SecretShape;
use janitor_core::view::{project, reveal_value, MatrixView};

use crate::broker::CredentialBroker;
use crate::discovery::{Discovery, Step};
use crate::error::SignInError;
use crate::secrets::SecretsClient;
use crate::select::{plan_selection, SelectionPlan};
use crate::source::{AuthenticatedSource, Reauth};
use crate::types::{Clock, SsoToken};
use crate::wire::{AccountCatalog, RoleCredentialClient, SecretsApi};

/// A successful `Session::load`: the masked matrix plus any Mappings whose
/// `permission_set` was auto-corrected this load (ADR 0018 stale-role recovery).
/// `corrected` is empty on the common path; when non-empty the GUI persists those
/// permission-set changes to Config (locations only).
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    pub view: MatrixView,
    pub corrected: Vec<Mapping>,
}

/// The outcome of re-resolving an account's entitled roles during recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RoleResolution {
    /// Exactly one entitled role — the unambiguous correction (its permission-set
    /// name). Recovery rewrites + retries only when this differs from the stored.
    Single(String),
    /// Two or more entitled roles — Janitor must never auto-pick (carry the count
    /// for logging only).
    Ambiguous(usize),
    /// Zero entitled roles on the account.
    None,
    /// `list_account_roles` itself errored.
    ListFailed,
}

/// Re-resolve which permission set the signed-in user is entitled to on
/// `account_id`, reusing the live SSO token (no browser). Pure decision via the
/// shared [`plan_selection`] with **no remembered default** — the stored role is
/// the one that just got denied, so it must not bias the choice.
async fn recover_role(
    catalog: &dyn AccountCatalog,
    token: &SsoToken,
    account_id: &str,
) -> RoleResolution {
    let roles = match catalog.list_account_roles(token, account_id).await {
        Ok(r) => r,
        Err(_) => return RoleResolution::ListFailed,
    };
    match plan_selection(&roles, None) {
        SelectionPlan::Empty => RoleResolution::None,
        SelectionPlan::Auto(i) => RoleResolution::Single(roles[i].name.clone()),
        SelectionPlan::Ask { .. } => RoleResolution::Ambiguous(roles.len()),
    }
}

/// Build a `Failure` from an Environment's Mapping + the `SessionError` that
/// failed it. `detail` is the error-safe `Display` (never a Value/Credential).
fn fail(m: &Mapping, e: &SessionError) -> Failure {
    Failure {
        environment: m.environment.clone(),
        reason: FetchFailReason::from(e),
        detail: e.to_string(),
    }
}

/// Log why a stale-role recovery declined (error-safe: only locations + counts).
fn log_recovery_declined(m: &Mapping, resolution: &RoleResolution) {
    match resolution {
        RoleResolution::Ambiguous(n) => tracing::warn!(
            target: "janitor::aws",
            env = %m.environment,
            account = %m.account_id,
            count = *n,
            "multiple entitled roles; not auto-selecting — surfacing access denied"
        ),
        RoleResolution::None => tracing::warn!(
            target: "janitor::aws",
            env = %m.environment,
            account = %m.account_id,
            "no entitled roles on this account"
        ),
        RoleResolution::ListFailed => tracing::warn!(
            target: "janitor::aws",
            env = %m.environment,
            account = %m.account_id,
            "could not list roles for recovery — keeping original denial"
        ),
        // Single-but-equal: the denial wasn't a stale-role problem.
        RoleResolution::Single(_) => tracing::info!(
            target: "janitor::aws",
            env = %m.environment,
            "stored role is the only entitled one; denial is not a stale-role problem"
        ),
    }
}

/// The GUI's authenticated session. Built from the same `Arc<dyn …>` seams as
/// `live-verify`; signs in lazily and caches the current Application's fetched
/// Sets (the only place plaintext lives on the worker side).
pub struct Session {
    reauth: Arc<dyn Reauth>,
    role_client: Arc<dyn RoleCredentialClient>,
    secrets_api: Arc<dyn SecretsApi>,
    catalog: Arc<dyn AccountCatalog>,
    clock: Arc<dyn Clock>,
    facade: Option<AuthenticatedSource>,
    /// The Session's one SSO token, shared (`Arc`) with both the fetch broker
    /// and any in-progress `Discovery` so neither triggers a second Sign-in.
    /// `Some` once signed in.
    token: Option<Arc<SsoToken>>,
    /// The in-progress guided `Discovery` (ADR 0013). Owned here, independent of
    /// the fetched-secret cache, so the wizard survives across `Command`s.
    discovery: Option<Discovery>,
    cached: Vec<(String, SecretShape)>,
}

impl Session {
    /// Construct from the adapters. No I/O, no sign-in (lazy). `catalog` is the
    /// account/role enumeration seam used by guided `Discovery` (the real
    /// `AwsRoleClient` implements both it and `RoleCredentialClient`).
    pub fn new(
        reauth: Arc<dyn Reauth>,
        role_client: Arc<dyn RoleCredentialClient>,
        secrets_api: Arc<dyn SecretsApi>,
        catalog: Arc<dyn AccountCatalog>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Session {
            reauth,
            role_client,
            secrets_api,
            catalog,
            clock,
            facade: None,
            token: None,
            discovery: None,
            cached: Vec::new(),
        }
    }

    /// Whether a browser Sign-in has already happened this session.
    pub fn is_signed_in(&self) -> bool {
        self.facade.is_some()
    }

    /// Idempotent browser Sign-in: builds the broker + facade on first call
    /// from a fresh SSO token; a no-op once signed in (so it doubles as
    /// `ensure_signed_in`). The initial token comes through the same `Reauth`
    /// seam the facade uses for re-Sign-in, which is what makes this fakeable.
    pub async fn sign_in(&mut self) -> Result<(), crate::error::SignInError> {
        if self.facade.is_some() {
            return Ok(());
        }
        let token = Arc::new(self.reauth.sign_in().await?);
        let broker = CredentialBroker::new(
            Arc::clone(&token),
            Arc::clone(&self.role_client),
            Arc::clone(&self.clock),
        );
        let secrets = SecretsClient::new(Arc::clone(&self.secrets_api));
        self.facade = Some(AuthenticatedSource::new(
            broker,
            secrets,
            Arc::clone(&self.reauth),
            Arc::clone(&self.role_client),
            Arc::clone(&self.clock),
        ));
        self.token = Some(token);
        Ok(())
    }

    /// Begin a guided `Discovery` walk for one new Environment (ADR 0013):
    /// ensure signed in, then build and start the machine on the Session's SSO
    /// token. The returned `Step` is the first `Ask`/terminal state; subsequent
    /// picks go through [`advance_discovery`](Self::advance_discovery). A failed
    /// Sign-in surfaces as `Err` (the worker maps it to "sign in again").
    ///
    /// `region` is the resolved browse region (`config.secret_region` else
    /// `sso_region`); `remembered` is `config.last_pick`.
    pub async fn begin_discovery(
        &mut self,
        environment: String,
        region: String,
        remembered: Option<Mapping>,
    ) -> Result<Step, SignInError> {
        self.sign_in().await?;
        let token = Arc::clone(self.token.as_ref().expect("token set by sign_in"));
        let mut discovery = Discovery::new(
            environment,
            region,
            token,
            Arc::clone(&self.catalog),
            Arc::clone(&self.role_client),
            Arc::clone(&self.secrets_api),
            remembered,
        );
        let step = discovery.start().await;
        self.discovery = Some(discovery);
        self.reset_if_reauth(&step);
        Ok(step)
    }

    /// Feed the user's chosen index into the in-progress `Discovery`. `None` if
    /// no walk is in progress (a presenter bug — there is nothing to advance).
    pub async fn advance_discovery(&mut self, choice: usize) -> Option<Step> {
        let step = self.discovery.as_mut()?.advance(choice).await;
        self.reset_if_reauth(&step);
        Some(step)
    }

    /// On a discovery `Step::Reauth` (a dead SSO token the facade could not
    /// silently refresh), drop the cached sign-in + any in-progress walk so the
    /// next `sign_in()` re-opens the browser instead of reusing the dead token.
    /// No-op for any other Step.
    fn reset_if_reauth(&mut self, step: &Step) {
        if matches!(step, Step::Reauth) {
            self.facade = None;
            self.token = None;
            self.discovery = None;
        }
    }

    /// Load one Application: ensure signed in, fetch every Environment, and —
    /// if ANY Environment fails — return a whole-app error naming the failures
    /// (spec Decision 8). On full success, cache the Sets and return the masked
    /// view plus any Mappings whose `permission_set` was auto-corrected this load.
    /// The Sets (plaintext) never leave `self.cached`.
    ///
    /// **Stale-role recovery (ADR 0018):** if an Environment's fetch fails with
    /// [`SessionError::RoleNotEntitled`] (the stored permission set is no longer
    /// assigned), re-resolve the account's entitled roles from the *live* session
    /// (no browser) and, **only** when exactly one role is entitled and it differs
    /// from the stored one, rewrite that Mapping's `permission_set` and retry the
    /// fetch **once**. Zero / many / same-as-stored roles, or a re-list error, keep
    /// the original denial. At most one list + one retry per Environment — never a
    /// loop, never an auto-pick among several roles.
    pub async fn load(&mut self, app: &Application) -> Result<Loaded, AppError> {
        self.sign_in()
            .await
            .map_err(|_| AppError::needs_sign_in())?;
        // Arc clone for recovery's `list_account_roles`, taken before the `&mut
        // self.facade` borrow below so it doesn't conflict (disjoint handle). The
        // recovery *token* is read from the facade at recovery time — see below —
        // not captured here, so it reflects any re-Sign-in the fetch performed.
        let catalog = Arc::clone(&self.catalog);
        let facade = self.facade.as_mut().expect("facade exists after sign_in");

        let mut sets: Vec<(String, SecretShape)> = Vec::new();
        let mut failures: Vec<Failure> = Vec::new();
        let mut corrected: Vec<Mapping> = Vec::new();
        for m in &app.environments {
            match facade.fetch(m).await {
                Ok(shape) => sets.push((m.environment.clone(), shape)),
                Err(SessionError::RoleNotEntitled { context }) => {
                    tracing::info!(
                        target: "janitor::aws",
                        env = %m.environment,
                        account = %m.account_id,
                        "role not entitled — attempting auto-correct"
                    );
                    // Re-list under the facade's LIVE token (post any re-Sign-in
                    // this fetch did), not a token captured before the fetch.
                    let token = facade.current_token();
                    match recover_role(catalog.as_ref(), &token, &m.account_id).await {
                        // Exactly one entitled role, different from the stored one:
                        // the unambiguous correction. Rewrite + retry ONCE.
                        RoleResolution::Single(new_ps) if new_ps != m.permission_set => {
                            tracing::info!(
                                target: "janitor::aws",
                                env = %m.environment,
                                from = %m.permission_set,
                                to = %new_ps,
                                "auto-corrected permission set"
                            );
                            let patched = Mapping {
                                permission_set: new_ps,
                                ..m.clone()
                            };
                            match facade.fetch(&patched).await {
                                Ok(shape) => {
                                    sets.push((m.environment.clone(), shape));
                                    corrected.push(patched);
                                }
                                // Retry failed — final, NEVER a second recovery.
                                Err(e2) => failures.push(fail(m, &e2)),
                            }
                        }
                        // Zero / many / same-as-stored / re-list error: decline and
                        // keep the original denial (surfaces as "access denied").
                        resolution => {
                            log_recovery_declined(m, &resolution);
                            failures.push(Failure {
                                environment: m.environment.clone(),
                                reason: FetchFailReason::AccessDenied,
                                detail: context,
                            });
                        }
                    }
                }
                Err(e) => failures.push(fail(m, &e)),
            }
        }
        if !failures.is_empty() {
            return Err(AppError { failures });
        }
        let view = project(&Comparison::build(&sets));
        self.cached = sets;
        Ok(Loaded { view, corrected })
    }

    /// Momentary reveal of one cell's plaintext from the cached Sets, returned
    /// as an owned `String` so plaintext crosses to the UI thread only here and
    /// only on explicit request (ADR 0003). `None` if the cell is gone/absent/
    /// binary.
    pub fn reveal(&self, key: &RowKey, col: usize) -> Option<String> {
        reveal_value(&self.cached, key, col).map(|v| v.expose().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::fakes::{
        CredSpec, FakeAccountCatalog, FakeClock, FakeReauth, FakeRoleClient, FakeSecretsApi,
    };
    use crate::wire::{AccountSummary, RawSecret, RoleSummary, SecretSummary};
    use janitor_core::compare::{EntryState, RowKey};
    use janitor_core::config::{Application, Mapping};
    use janitor_core::secret::EntryName;
    use std::sync::Arc;
    use std::time::Duration;

    fn mapping(env: &str, secret_id: &str) -> Mapping {
        Mapping {
            environment: env.into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: secret_id.into(),
            permission_set: "ReadOnly".into(),
        }
    }
    fn cred_ok() -> Result<CredSpec, SessionError> {
        Ok(CredSpec {
            expires_in: Duration::from_secs(3600),
            tag: "t",
        })
    }
    fn secret_json(json: &str) -> Result<RawSecret, SessionError> {
        Ok(RawSecret {
            secret_string: Some(json.into()),
            secret_binary: None,
        })
    }
    fn session(
        reauth: Arc<FakeReauth>,
        role: Arc<FakeRoleClient>,
        api: Arc<FakeSecretsApi>,
    ) -> Session {
        // Most tests do not touch discovery; an empty catalog suffices.
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![]));
        Session::new(reauth, role, api, catalog, Arc::new(FakeClock::at(0)))
    }

    #[test]
    fn maps_every_session_error_to_a_reason() {
        assert_eq!(
            FetchFailReason::from(&SessionError::ReauthRequired),
            FetchFailReason::NeedsSignIn
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::AccessDenied),
            FetchFailReason::AccessDenied
        );
        // An un-recovered role denial surfaces as plain "access denied".
        assert_eq!(
            FetchFailReason::from(&SessionError::RoleNotEntitled {
                context: "Forbidden".into()
            }),
            FetchFailReason::AccessDenied
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::NotFound),
            FetchFailReason::NotFound
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::Throttled),
            FetchFailReason::Throttled
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::Unsupported),
            FetchFailReason::Unsupported
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::Sdk {
                context: "GetSecretValue".into()
            }),
            FetchFailReason::Other
        );
    }

    #[test]
    fn describe_never_leaks_sdk_text() {
        // The Sdk catch-all carries a context string; describe() must not surface it.
        let r = FetchFailReason::from(&SessionError::Sdk {
            context: "hunter2".into(),
        });
        assert!(!r.describe().contains("hunter2"));
        assert_eq!(r.describe(), "AWS error");
    }

    #[test]
    fn needs_sign_in_names_a_synthetic_environment() {
        let e = AppError::needs_sign_in();
        assert_eq!(e.failures.len(), 1);
        assert_eq!(e.failures[0].reason, FetchFailReason::NeedsSignIn);
    }

    #[tokio::test]
    async fn sign_in_is_idempotent_one_browser() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let mut s = session(reauth.clone(), role, api);
        assert!(!s.is_signed_in());
        s.sign_in().await.unwrap();
        s.sign_in().await.unwrap();
        assert!(s.is_signed_in());
        assert_eq!(reauth.count(), 1, "second sign_in must be a no-op");
    }

    #[tokio::test]
    async fn load_all_envs_succeed_returns_view_and_caches() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let api = Arc::new(FakeSecretsApi::new(vec![
            secret_json(r#"{"A":"1","B":"x"}"#),
            secret_json(r#"{"A":"1"}"#),
        ]));
        let mut s = session(reauth, role, api);
        let app = Application {
            name: "app".into(),
            environments: vec![
                mapping("prod", "app/prod"),
                mapping("staging", "app/staging"),
            ],
        };
        let loaded = s.load(&app).await.unwrap();
        assert!(loaded.corrected.is_empty(), "no recovery on the happy path");
        let view = loaded.view;
        assert_eq!(view.environments, vec!["prod", "staging"]);
        let b = view.rows.iter().find(|r| r.name == "B").unwrap();
        assert_eq!(b.state, EntryState::Gap);
        let key = RowKey::Entry(EntryName::from_path(&["A".to_string()]));
        assert_eq!(s.reveal(&key, 0), Some("1".to_string()));
    }

    #[tokio::test]
    async fn load_one_env_fails_is_whole_app_error_naming_it() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let api = Arc::new(FakeSecretsApi::new(vec![
            secret_json(r#"{"A":"1"}"#),
            Err(SessionError::AccessDenied),
            Err(SessionError::AccessDenied), // force_refresh retry consumes this
        ]));
        let mut s = session(reauth, role, api);
        let app = Application {
            name: "app".into(),
            environments: vec![
                mapping("prod", "app/prod"),
                mapping("staging", "app/staging"),
            ],
        };
        let err = s.load(&app).await.unwrap_err();
        assert_eq!(err.failures.len(), 1);
        assert_eq!(err.failures[0].environment, "staging");
        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
    }

    #[tokio::test]
    async fn load_maps_signin_failure_to_needs_sign_in() {
        let reauth = Arc::new(FakeReauth::failing());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let mut s = session(reauth, role, api);
        let app = Application {
            name: "a".into(),
            environments: vec![mapping("prod", "a/prod")],
        };
        let err = s.load(&app).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::NeedsSignIn);
    }

    // ---- Stale-role recovery (ADR 0018) ----

    fn role_not_entitled() -> Result<CredSpec, SessionError> {
        Err(SessionError::RoleNotEntitled {
            context: "ForbiddenException: No access".into(),
        })
    }
    fn roles(names: &[&str]) -> Result<Vec<RoleSummary>, SessionError> {
        Ok(names
            .iter()
            .map(|n| RoleSummary { name: (*n).into() })
            .collect())
    }
    fn one_env(secret_id: &str) -> Application {
        Application {
            name: "app".into(),
            environments: vec![mapping("prod", secret_id)],
        }
    }

    #[tokio::test]
    async fn single_role_auto_corrects_retries_and_persists_corrected_mapping() {
        // Stored ReadOnly is denied; the account has exactly one entitled role
        // (PowerUser) → silent rewrite + one retry → success, no second sign-in.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![role_not_entitled(), cred_ok()]));
        let api = Arc::new(FakeSecretsApi::new(vec![secret_json(r#"{"A":"1"}"#)]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&["PowerUser"])]));
        let mut s = Session::new(
            reauth.clone(),
            role.clone(),
            api,
            catalog.clone(),
            Arc::new(FakeClock::at(0)),
        );
        let loaded = s.load(&one_env("app/prod")).await.unwrap();

        assert_eq!(loaded.view.environments, vec!["prod"]);
        assert_eq!(loaded.corrected.len(), 1);
        let c = &loaded.corrected[0];
        assert_eq!(c.environment, "prod");
        assert_eq!(c.permission_set, "PowerUser", "role rewritten");
        assert_eq!(c.account_id, "111111111111", "ONLY permission_set changed");
        assert_eq!(c.secret_id, "app/prod");
        assert_eq!(catalog.role_call_count(), 1, "exactly one re-list");
        assert_eq!(role.call_count(), 2, "denied mint + corrected mint");
        assert_eq!(
            reauth.count(),
            1,
            "recovery reuses the session token — no 2nd sign-in"
        );
    }

    #[tokio::test]
    async fn ambiguous_roles_keeps_failure_and_never_auto_picks() {
        // Two entitled roles → Janitor must NOT pick. Keep the denial, no retry.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![role_not_entitled()]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&["A", "B"])]));
        let mut s = Session::new(
            reauth,
            role.clone(),
            api,
            catalog.clone(),
            Arc::new(FakeClock::at(0)),
        );
        let err = s.load(&one_env("app/prod")).await.unwrap_err();

        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
        assert_eq!(
            err.failures[0].detail, "ForbiddenException: No access",
            "keeps the real denial detail"
        );
        assert_eq!(role.call_count(), 1, "no retry mint proves no silent pick");
        assert_eq!(catalog.role_call_count(), 1);
    }

    #[tokio::test]
    async fn no_entitled_roles_keeps_failure() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![role_not_entitled()]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&[])]));
        let mut s = Session::new(
            reauth,
            role.clone(),
            api,
            catalog,
            Arc::new(FakeClock::at(0)),
        );
        let err = s.load(&one_env("app/prod")).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
        assert_eq!(role.call_count(), 1, "no retry");
    }

    #[tokio::test]
    async fn single_role_equal_to_stored_is_a_noop() {
        // The one entitled role IS the stored one → the denial wasn't a stale-role
        // problem; no pointless rewrite/retry that would just fail again.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![role_not_entitled()]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&["ReadOnly"])]));
        let mut s = Session::new(
            reauth,
            role.clone(),
            api,
            catalog,
            Arc::new(FakeClock::at(0)),
        );
        let err = s.load(&one_env("app/prod")).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
        assert_eq!(
            role.call_count(),
            1,
            "no retry for a same-role 'correction'"
        );
    }

    #[tokio::test]
    async fn recovery_retry_failure_surfaces_and_never_recovers_again() {
        // Stored denied → re-resolve to PowerUser → retry ALSO denied → final.
        // Crucially: NO second re-list (no recovery loop).
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![
            role_not_entitled(),
            role_not_entitled(),
        ]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&["PowerUser"])]));
        let mut s = Session::new(
            reauth,
            role.clone(),
            api,
            catalog.clone(),
            Arc::new(FakeClock::at(0)),
        );
        let err = s.load(&one_env("app/prod")).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
        assert_eq!(role.call_count(), 2, "denied + one retry, no more");
        assert_eq!(
            catalog.role_call_count(),
            1,
            "at-most-once: no second re-list"
        );
    }

    #[tokio::test]
    async fn reauth_at_role_step_does_not_trigger_recovery() {
        // A dead token (ReauthRequired) is handled by the facade's re-sign-in tier,
        // NOT by role recovery — list_account_roles is never called.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![
            Err(SessionError::ReauthRequired),
            cred_ok(),
        ]));
        let api = Arc::new(FakeSecretsApi::new(vec![secret_json(r#"{"A":"1"}"#)]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![]));
        let mut s = Session::new(
            reauth.clone(),
            role,
            api,
            catalog.clone(),
            Arc::new(FakeClock::at(0)),
        );
        let loaded = s.load(&one_env("app/prod")).await.unwrap();
        assert!(loaded.corrected.is_empty());
        assert_eq!(
            catalog.role_call_count(),
            0,
            "recovery never entered for a dead token"
        );
        assert_eq!(reauth.count(), 2, "load sign-in + facade re-sign-in");
    }

    #[tokio::test]
    async fn list_roles_error_during_recovery_keeps_original_failure() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![role_not_entitled()]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let catalog = Arc::new(FakeAccountCatalog::new(
            vec![],
            vec![Err(SessionError::Throttled)],
        ));
        let mut s = Session::new(
            reauth,
            role.clone(),
            api,
            catalog.clone(),
            Arc::new(FakeClock::at(0)),
        );
        let err = s.load(&one_env("app/prod")).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
        assert_eq!(
            role.call_count(),
            1,
            "no retry when the re-list itself fails"
        );
        assert_eq!(catalog.role_call_count(), 1);
    }

    #[tokio::test]
    async fn multi_env_only_the_failing_env_recovers() {
        // env A (acct 111) is denied + recovers; env B (acct 222) loads normally.
        let reauth = Arc::new(FakeReauth::ok());
        // A: denied mint, then PowerUser mint; B: ReadOnly mint.
        let role = Arc::new(FakeRoleClient::new(vec![
            role_not_entitled(),
            cred_ok(),
            cred_ok(),
        ]));
        let api = Arc::new(FakeSecretsApi::new(vec![
            secret_json(r#"{"A":"1"}"#),
            secret_json(r#"{"A":"1"}"#),
        ]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&["PowerUser"])]));
        let mut s = Session::new(
            reauth,
            role,
            api,
            catalog.clone(),
            Arc::new(FakeClock::at(0)),
        );
        let m_a = Mapping {
            environment: "prod".into(),
            account_id: "111".into(),
            region: "us-east-1".into(),
            secret_id: "app/prod".into(),
            permission_set: "ReadOnly".into(),
        };
        let m_b = Mapping {
            account_id: "222".into(),
            environment: "staging".into(),
            ..m_a.clone()
        };
        let app = Application {
            name: "app".into(),
            environments: vec![m_a, m_b],
        };
        let loaded = s.load(&app).await.unwrap();
        assert_eq!(loaded.view.environments, vec!["prod", "staging"]);
        assert_eq!(
            loaded.corrected.len(),
            1,
            "only the failing env was corrected"
        );
        assert_eq!(loaded.corrected[0].environment, "prod");
        assert_eq!(loaded.corrected[0].permission_set, "PowerUser");
        assert_eq!(catalog.role_call_count(), 1, "only one env needed recovery");
    }

    #[tokio::test]
    async fn recovery_after_a_resign_in_uses_the_live_token() {
        // A dead token then a de-assigned role in ONE fetch: the facade re-signs-in
        // (fresh token), the retry mint returns RoleNotEntitled, and recovery must
        // re-list under the facade's LIVE token (current_token), not the one
        // captured before the fetch — and still succeed. (The fakes ignore the
        // token value, so this guards the control flow / accessor wiring.)
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![
            Err(SessionError::ReauthRequired), // dead token
            role_not_entitled(),               // post-re-sign-in: role de-assigned
            cred_ok(),                         // corrected role mints
        ]));
        let api = Arc::new(FakeSecretsApi::new(vec![secret_json(r#"{"A":"1"}"#)]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&["PowerUser"])]));
        let mut s = Session::new(
            reauth.clone(),
            role.clone(),
            api,
            catalog.clone(),
            Arc::new(FakeClock::at(0)),
        );
        let loaded = s.load(&one_env("app/prod")).await.unwrap();
        assert_eq!(loaded.corrected.len(), 1);
        assert_eq!(loaded.corrected[0].permission_set, "PowerUser");
        assert_eq!(reauth.count(), 2, "initial sign-in + one re-sign-in");
        assert_eq!(catalog.role_call_count(), 1, "recovery re-listed once");
        assert_eq!(role.call_count(), 3, "dead + de-assigned + corrected mint");
    }

    #[tokio::test]
    async fn reveal_is_none_before_load_and_for_absent() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let s = session(reauth, role, api);
        let key = RowKey::Entry(EntryName::from_path(&["A".to_string()]));
        assert!(s.reveal(&key, 0).is_none(), "nothing cached yet");
    }

    #[test]
    fn matrixview_and_shape_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<MatrixView>();
        assert_send::<SecretShape>();
        assert_send::<AppError>();
    }

    #[tokio::test]
    async fn begin_discovery_signs_in_then_auto_picks_to_done() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![Ok(vec![SecretSummary {
            name: "app/prod".into(),
            arn: "arn:secret:app/prod".into(),
        }])]));
        let catalog = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![AccountSummary {
                id: "111".into(),
                name: "Prod".into(),
            }])],
            vec![Ok(vec![RoleSummary {
                name: "ReadOnly".into(),
            }])],
        ));
        let mut s = Session::new(
            reauth.clone(),
            role,
            api,
            catalog,
            Arc::new(FakeClock::at(0)),
        );

        let step = s
            .begin_discovery("prod".into(), "us-west-2".into(), None)
            .await
            .unwrap();
        let Step::Done(m) = step else {
            panic!("expected Done, got {step:?}");
        };
        assert_eq!(m.environment, "prod");
        assert_eq!(m.account_id, "111");
        assert_eq!(m.region, "us-west-2");
        assert_eq!(m.secret_id, "arn:secret:app/prod");
        assert_eq!(reauth.count(), 1, "discovery signs in exactly once");
        assert!(s.is_signed_in());
    }

    #[tokio::test]
    async fn discovery_reuses_the_load_token_without_a_second_sign_in() {
        // Signing in (via load) then discovering must NOT open a second browser:
        // both share the Session's one Arc<SsoToken>.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let api = Arc::new(FakeSecretsApi {
            outcomes: std::sync::Mutex::new(vec![secret_json(r#"{"A":"1"}"#)]),
            list_outcomes: std::sync::Mutex::new(vec![Ok(vec![SecretSummary {
                name: "app/staging".into(),
                arn: "arn:secret:app/staging".into(),
            }])]),
            calls: std::sync::Mutex::new(0),
        });
        let catalog = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![AccountSummary {
                id: "222".into(),
                name: "Staging".into(),
            }])],
            vec![Ok(vec![RoleSummary {
                name: "ReadOnly".into(),
            }])],
        ));
        let mut s = Session::new(
            reauth.clone(),
            role,
            api,
            catalog,
            Arc::new(FakeClock::at(0)),
        );

        let app = Application {
            name: "app".into(),
            environments: vec![mapping("prod", "app/prod")],
        };
        s.load(&app).await.unwrap();
        let step = s
            .begin_discovery("staging".into(), "us-east-1".into(), None)
            .await
            .unwrap();
        assert!(matches!(step, Step::Done(_)));
        assert_eq!(reauth.count(), 1, "load + discovery share one Sign-in");
    }

    #[tokio::test]
    async fn discovery_reauth_clears_sign_in_so_next_sign_in_reauthenticates() {
        // A dead token surfaced by discovery (Step::Reauth) must reset the
        // Session's sign-in, so the GUI's "Sign in again" actually re-opens the
        // browser instead of reusing the dead token (ADR 0013 reauth routing).
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![]));
        let catalog = Arc::new(FakeAccountCatalog::new(
            vec![Err(SessionError::ReauthRequired)],
            vec![],
        ));
        let mut s = Session::new(
            reauth.clone(),
            role,
            api,
            catalog,
            Arc::new(FakeClock::at(0)),
        );

        let step = s
            .begin_discovery("prod".into(), "us-east-1".into(), None)
            .await
            .unwrap();
        assert!(matches!(step, Step::Reauth));
        assert!(
            !s.is_signed_in(),
            "a dead-token discovery clears the session"
        );

        s.sign_in().await.unwrap();
        assert_eq!(
            reauth.count(),
            2,
            "re-sign-in re-authenticates against a fresh token, not a no-op"
        );
    }

    #[tokio::test]
    async fn advance_discovery_is_none_without_a_walk() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let mut s = session(reauth, role, api);
        assert!(s.advance_discovery(0).await.is_none());
    }
}
