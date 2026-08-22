//! `AwsFamilyProvider` (ADR 0031): the generic AWS-family [`Provider`] shell. It
//! owns everything provider-agnostic — the `Arc<SsoToken>`, the idempotent
//! `sign_in` (token → [`CredentialBroker`]), the per-Environment `load` loop +
//! `project`/cache, `reveal`, the Discovery handle (`Orchestrator<Box<dyn Steps>>`),
//! the operator-advisory queue, the at-most-once force-refresh + re-Sign-in fetch
//! ladder (ADR 0010 §4), and ADR 0018 stale-role recovery — and dispatches the one
//! divergent thing, *how a minted Credential turns a `Mapping` into a `SecretShape`*,
//! to a per-Mapping [`ResourceMethod`] (ADR 0031 Decision 4).
//!
//! It speaks only `Mapping`/`Method`/`SecretShape`/`Step`/`Failure`/`Credential` —
//! no Secrets-Manager or SSM vocabulary — so a mixed-method matrix and its reveals
//! fall out for free (the cache is just `(env_name, SecretShape)` and `reveal` is
//! method-agnostic). The two old parallel Providers (`janitor-aws::Session`,
//! `janitor-ssm::SsmProvider`) collapse into this one shell + two methods; the SSM
//! method *gains* the resilience ladder it previously lacked.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;

use janitor_core::compare::{Comparison, RowKey};
use janitor_core::config::{Application, Mapping, Method};
use janitor_core::discovery::{Orchestrator, Steps};
use janitor_core::provider::{
    AppError, Failure, FetchFailReason, Loaded, Provider, SignInFailed, Step,
};
use janitor_core::secret::{Plaintext, SecretShape};
use janitor_core::select::{plan_selection, SelectionPlan};
use janitor_core::view::{project, reveal_value};
use janitor_core::write::{EnvEdit, WriteOutcome};

use crate::broker::CredentialBroker;
use crate::error::SessionError;
use crate::method::{MethodError, ResourceMethod};
use crate::types::{Clock, SsoToken};
use crate::wire::{AccountCatalog, Reauth, RoleCredentialClient};

/// The outcome of re-resolving an account's entitled roles during recovery
/// (ADR 0018). Relocated here from `janitor-aws::session` with the ladder, so both
/// AWS-family methods share it.
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

/// Build a `Failure` from an Environment's Mapping + the masked [`MethodError`].
/// `detail` is error-safe (never a Value/Credential/SDK text; THREAT-MODEL).
fn fail_method(m: &Mapping, e: &MethodError) -> Failure {
    Failure {
        environment: m.environment.clone(),
        reason: e.reason(),
        detail: e.detail(),
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

/// The generic AWS-family Provider. Built from the shared front-half seams plus a
/// registry of [`ResourceMethod`]s keyed by [`Method`]; signs in lazily and caches
/// the current Application's fetched Sets (the only place plaintext lives on the
/// worker side).
pub struct AwsFamilyProvider {
    reauth: Arc<dyn Reauth>,
    role_client: Arc<dyn RoleCredentialClient>,
    catalog: Arc<dyn AccountCatalog>,
    clock: Arc<dyn Clock>,
    /// The swappable resource methods, one per [`Method`] (Decision 4). The
    /// composition root (`build_provider`) is the only place both tails are named.
    methods: BTreeMap<Method, Arc<dyn ResourceMethod>>,
    /// The per-Environment Credential broker over the session token. `Some` once
    /// signed in (rebuilt on a re-Sign-in); doubles as the "is signed in" flag.
    broker: Option<CredentialBroker>,
    /// The session's one SSO token, shared (`Arc`) with the broker and any walk so
    /// neither triggers a second Sign-in. `Some` once signed in.
    token: Option<Arc<SsoToken>>,
    /// The in-progress guided walk + the [`Method`] it runs (used to stamp the
    /// chosen method onto the `Done` Mapping, Decision 5). Owned here, independent
    /// of the fetched-Set cache, so the wizard survives across `Command`s.
    discovery: Option<(Method, Orchestrator<Box<dyn Steps>>)>,
    cached: Vec<(String, SecretShape)>,
    /// Operator advisories pending surfacing (drained by `take_advisories`), and the
    /// set already surfaced so an advisory shows at most once (ADR 0025).
    advisories: Vec<String>,
    seen_advisories: HashSet<String>,
}

impl AwsFamilyProvider {
    /// Construct from the shared front-half seams + the method registry. No I/O, no
    /// Sign-in (lazy). `role_client` mints role Credentials and (as the real
    /// `AwsRoleClient` implements both) lists accounts/roles via `catalog`.
    pub fn new(
        reauth: Arc<dyn Reauth>,
        role_client: Arc<dyn RoleCredentialClient>,
        catalog: Arc<dyn AccountCatalog>,
        clock: Arc<dyn Clock>,
        methods: BTreeMap<Method, Arc<dyn ResourceMethod>>,
    ) -> Self {
        AwsFamilyProvider {
            reauth,
            role_client,
            catalog,
            clock,
            methods,
            broker: None,
            token: None,
            discovery: None,
            cached: Vec::new(),
            advisories: Vec::new(),
            seen_advisories: HashSet::new(),
        }
    }

    /// Whether a browser Sign-in has already happened this session.
    pub fn is_signed_in(&self) -> bool {
        self.broker.is_some()
    }

    /// The registered method for `method`, cloned out so the caller can hold it
    /// across a `&mut self` borrow (the load loop mints/recovers on `self`).
    fn method_for(&self, method: &Method) -> Option<Arc<dyn ResourceMethod>> {
        self.methods.get(method).cloned()
    }

    /// Queue an advisory to surface, deduped so the same note shows at most once
    /// this session (ADR 0025).
    fn push_advisory(&mut self, advisory: String) {
        if self.seen_advisories.insert(advisory.clone()) {
            self.advisories.push(advisory);
        }
    }

    /// Pull any advisory the in-progress walk produced (at its credential mint) up
    /// into the surface queue.
    fn pull_discovery_advisory(&mut self) {
        if let Some(w) = self.discovery.as_mut().and_then(|(_, o)| o.take_advisory()) {
            self.push_advisory(w);
        }
    }

    /// On a discovery `Step::Reauth` (a dead SSO token), drop the cached Sign-in +
    /// any in-progress walk so the next `sign_in()` re-opens the browser instead of
    /// reusing the dead token. No-op for any other Step.
    fn reset_if_reauth(&mut self, step: &Step) {
        if matches!(step, Step::Reauth) {
            self.broker = None;
            self.token = None;
            self.discovery = None;
        }
    }

    /// Probe each *distinct* Method present in `app` for a load-time advisory, once
    /// (Decision 4). Only a successful credential mint warrants a probe — a mint
    /// failure is the load's real error (surfaced per-Environment below), not a
    /// logging-policy uncertainty. Returns the notes to queue (kept `&self` so it
    /// composes before the `&mut self` fetch loop).
    async fn probe_advisories(&self, app: &Application) -> Vec<String> {
        let mut out = Vec::new();
        let Some(broker) = self.broker.as_ref() else {
            return out;
        };
        let mut probed: HashSet<Method> = HashSet::new();
        for m in &app.environments {
            if !probed.insert(m.method) {
                continue;
            }
            let Some(method) = self.methods.get(&m.method) else {
                continue;
            };
            // A Method without operator advisories (Secrets Manager) costs no probe
            // mint — gating here is what keeps `load` from minting a credential it
            // has no use for, and from racing the recovery path's first mint.
            if !method.has_advisory() {
                continue;
            }
            if let Ok(cred) = broker.credentials_for(m).await {
                if let Some(w) = method.advisory(&cred, m).await {
                    out.push(w);
                }
            }
        }
        out
    }

    /// One pass over `method`: mint/get a Credential, read+shape, and on an
    /// auth-class (`AccessDenied`) failure force-refresh **once** then retry
    /// (ADR 0010 §4). A `ReauthRequired` (dead token, from the mint) surfaces up to
    /// [`fetch_with_ladder`](Self::fetch_with_ladder), which owns the re-Sign-in. A
    /// [`MethodError::Content`] (unusable payload) passes straight through — never
    /// force-refreshed, never recovered.
    async fn try_once(
        &self,
        method: &dyn ResourceMethod,
        mapping: &Mapping,
    ) -> Result<SecretShape, MethodError> {
        let broker = self.broker.as_ref().expect("signed in before try_once");
        let cred = broker
            .credentials_for(mapping)
            .await
            .map_err(MethodError::Session)?; // may be ReauthRequired / RoleNotEntitled
        match method.fetch(&cred, mapping).await {
            Ok(shape) => Ok(shape),
            Err(MethodError::Session(SessionError::AccessDenied)) => {
                // Stale cached credential AWS now rejects, OR a true policy denial —
                // indistinguishable here. Force one re-mint and retry.
                let cred = broker
                    .force_refresh(mapping)
                    .await
                    .map_err(MethodError::Session)?;
                match method.fetch(&cred, mapping).await {
                    Ok(shape) => Ok(shape),
                    Err(MethodError::Session(SessionError::AccessDenied)) => {
                        Err(MethodError::Session(SessionError::AccessDenied))
                    }
                    Err(other) => Err(other),
                }
            }
            Err(other) => Err(other),
        }
    }

    /// The full fetch ladder (ADR 0010 §4, lifted from `janitor-aws::AuthenticatedSource`
    /// into the shell so **both** methods get it): [`try_once`](Self::try_once); on a
    /// `ReauthRequired` re-Sign-in **once**, rebuild the broker on the fresh token,
    /// and retry once. Still `ReauthRequired` after a fresh Sign-in → fatal
    /// (`AccessDenied`); a failed re-Sign-in → `ReauthRequired`.
    async fn fetch_with_ladder(
        &mut self,
        method: &dyn ResourceMethod,
        mapping: &Mapping,
    ) -> Result<SecretShape, MethodError> {
        match self.try_once(method, mapping).await {
            Ok(shape) => Ok(shape),
            Err(MethodError::Session(SessionError::ReauthRequired)) => {
                let token = self
                    .reauth
                    .sign_in()
                    .await
                    .map_err(|_| MethodError::Session(SessionError::ReauthRequired))?;
                let token = Arc::new(token);
                self.broker = Some(CredentialBroker::new(
                    Arc::clone(&token),
                    Arc::clone(&self.role_client),
                    Arc::clone(&self.clock),
                ));
                self.token = Some(token);
                match self.try_once(method, mapping).await {
                    Ok(shape) => Ok(shape),
                    // Still unauthorized even after a fresh Sign-in → fatal.
                    Err(MethodError::Session(SessionError::ReauthRequired)) => {
                        Err(MethodError::Session(SessionError::AccessDenied))
                    }
                    Err(other) => Err(other),
                }
            }
            Err(other) => Err(other),
        }
    }

    /// One write pass over `method` (the `fetch` analogue, ADR 0032): mint/get a
    /// Credential, dispatch `method.write`, and on an `AccessDenied` force-refresh the
    /// Credential **once** then retry (ADR 0010 §4 — a stale cached Credential AWS now
    /// rejects). A `ReauthRequired` (dead token) surfaces to
    /// [`write_with_ladder`](Self::write_with_ladder), which owns the re-Sign-in.
    /// Unlike `load`, a write does **not** run ADR 0018 stale-role recovery — it never
    /// rewrites/persists a Mapping's role (that is load-time Config state); a
    /// `RoleNotEntitled` masks straight to `AccessDenied`.
    async fn try_write_once(
        &self,
        method: &dyn ResourceMethod,
        mapping: &Mapping,
        edits: &[EnvEdit],
    ) -> Result<WriteOutcome, MethodError> {
        let broker = self
            .broker
            .as_ref()
            .expect("signed in before try_write_once");
        let cred = broker
            .credentials_for(mapping)
            .await
            .map_err(MethodError::Session)?;
        match method.write(&cred, mapping, edits).await {
            Err(MethodError::Session(SessionError::AccessDenied)) => {
                let cred = broker
                    .force_refresh(mapping)
                    .await
                    .map_err(MethodError::Session)?;
                // The retry is final — its result (incl. a second AccessDenied or a
                // Conflict) passes straight through; never a force-refresh loop.
                method.write(&cred, mapping, edits).await
            }
            other => other,
        }
    }

    /// The full write ladder (the `fetch_with_ladder` analogue, ADR 0032):
    /// [`try_write_once`](Self::try_write_once); on a `ReauthRequired` re-Sign-in
    /// **once**, rebuild the broker on the fresh token, and retry once. Still
    /// `ReauthRequired` after a fresh Sign-in → fatal (`AccessDenied`); a failed
    /// re-Sign-in → `ReauthRequired`. A `Conflict` is a normal outcome, not an error,
    /// so it is returned as-is for the caller (and the user) to act on.
    async fn write_with_ladder(
        &mut self,
        method: &dyn ResourceMethod,
        mapping: &Mapping,
        edits: &[EnvEdit],
    ) -> Result<WriteOutcome, MethodError> {
        match self.try_write_once(method, mapping, edits).await {
            Err(MethodError::Session(SessionError::ReauthRequired)) => {
                let token = self
                    .reauth
                    .sign_in()
                    .await
                    .map_err(|_| MethodError::Session(SessionError::ReauthRequired))?;
                let token = Arc::new(token);
                self.broker = Some(CredentialBroker::new(
                    Arc::clone(&token),
                    Arc::clone(&self.role_client),
                    Arc::clone(&self.clock),
                ));
                self.token = Some(token);
                match self.try_write_once(method, mapping, edits).await {
                    // Still unauthorized even after a fresh Sign-in → fatal.
                    Err(MethodError::Session(SessionError::ReauthRequired)) => {
                        Err(MethodError::Session(SessionError::AccessDenied))
                    }
                    other => other,
                }
            }
            other => other,
        }
    }
}

#[async_trait]
impl Provider for AwsFamilyProvider {
    /// Idempotent browser Sign-in: builds the broker on first call from a fresh SSO
    /// token; a no-op once signed in (so it doubles as `ensure_signed_in`). A failed
    /// Sign-in is masked into the agnostic [`SignInFailed`].
    async fn sign_in(&mut self) -> Result<(), SignInFailed> {
        if self.broker.is_some() {
            return Ok(());
        }
        let token = Arc::new(self.reauth.sign_in().await?);
        let broker = CredentialBroker::new(
            Arc::clone(&token),
            Arc::clone(&self.role_client),
            Arc::clone(&self.clock),
        );
        self.broker = Some(broker);
        self.token = Some(token);
        Ok(())
    }

    /// Load one Application: ensure signed in, fetch every Environment through its
    /// Mapping's [`Method`], and — if ANY Environment fails — return a whole-app
    /// error naming the failures (spec Decision 8). On full success, cache the Sets
    /// and return the masked view plus any Mappings whose `permission_set` was
    /// auto-corrected (ADR 0018). Plaintext never leaves `self.cached`.
    ///
    /// A mixed-method matrix falls out for free: the per-Environment dispatch is the
    /// only method-aware step; `project`/cache/`reveal` are method-agnostic.
    async fn load(&mut self, app: &Application) -> Result<Loaded, AppError> {
        self.sign_in()
            .await
            .map_err(|_| AppError::needs_sign_in())?;

        // Warn once per distinct method whose reads have an operator-visible side
        // effect (e.g. SSM session logging), before any read (ADR 0025).
        for w in self.probe_advisories(app).await {
            self.push_advisory(w);
        }

        // Arc clone for recovery's `list_account_roles`, taken before the `&mut self`
        // fetch loop so it does not conflict (disjoint handle).
        let catalog = Arc::clone(&self.catalog);

        let mut sets: Vec<(String, SecretShape)> = Vec::new();
        let mut failures: Vec<Failure> = Vec::new();
        let mut corrected: Vec<Mapping> = Vec::new();
        for m in &app.environments {
            let Some(method) = self.method_for(&m.method) else {
                // The registry is missing this Method — a composition-root bug, not
                // a real fetch failure. Surface it masked rather than panicking.
                failures.push(Failure {
                    environment: m.environment.clone(),
                    reason: FetchFailReason::Other,
                    detail: "no method configured for this Environment".to_string(),
                });
                continue;
            };
            match self.fetch_with_ladder(method.as_ref(), m).await {
                Ok(shape) => sets.push((m.environment.clone(), shape)),
                Err(MethodError::Session(SessionError::RoleNotEntitled { context })) => {
                    tracing::info!(
                        target: "janitor::aws",
                        env = %m.environment,
                        account = %m.account_id,
                        "role not entitled — attempting auto-correct"
                    );
                    // Re-list under the broker's LIVE token (post any re-Sign-in this
                    // fetch did), not one captured before the fetch.
                    let token = self.broker.as_ref().expect("signed in").token();
                    match recover_role(catalog.as_ref(), &token, &m.account_id).await {
                        // Exactly one entitled role, different from stored: the
                        // unambiguous correction. Rewrite + retry ONCE.
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
                            match self.fetch_with_ladder(method.as_ref(), &patched).await {
                                Ok(shape) => {
                                    sets.push((m.environment.clone(), shape));
                                    corrected.push(patched);
                                }
                                // Retry failed — final, NEVER a second recovery.
                                Err(e2) => failures.push(fail_method(m, &e2)),
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
                Err(e) => failures.push(fail_method(m, &e)),
            }
        }
        if !failures.is_empty() {
            return Err(AppError { failures });
        }
        let view = project(&Comparison::build(&sets));
        self.cached = sets;
        Ok(Loaded { view, corrected })
    }

    /// Momentary reveal of one cell's plaintext from the cached Sets, returned as an
    /// owned [`Plaintext`] so plaintext crosses to the UI thread only here and only
    /// on explicit request (ADR 0003). Method-agnostic — the cache is just
    /// `(env, SecretShape)`. `None` if the cell is gone/absent/binary.
    fn reveal(&self, key: &RowKey, col: usize) -> Option<Plaintext> {
        reveal_value(&self.cached, key, col).map(|v| Plaintext::new(v.expose()))
    }

    /// Begin a guided walk for one new Environment using `method` (ADR 0031): ensure
    /// signed in, build that method's discovery tail on the session token, drive it,
    /// and stamp the chosen `method` onto a `Done` Mapping (Decision 5).
    async fn begin_discovery(
        &mut self,
        method: Method,
        environment: String,
        region: String,
        remembered: Option<Mapping>,
    ) -> Result<Step, SignInFailed> {
        self.sign_in().await?;
        let token = Arc::clone(self.token.as_ref().expect("token set by sign_in"));
        let Some(resource) = self.method_for(&method) else {
            // Unknown method (composition-root bug) — surface masked, not a panic.
            return Ok(Step::Failed(FetchFailReason::Other));
        };
        let steps = resource.discovery_steps(environment, region, token, remembered);
        let mut orch: Orchestrator<Box<dyn Steps>> = Orchestrator::new(steps);
        let step = stamp_method(orch.start().await, method);
        self.discovery = Some((method, orch));
        self.pull_discovery_advisory();
        self.reset_if_reauth(&step);
        Ok(step)
    }

    /// Feed the user's chosen index into the in-progress walk. `None` if no walk is
    /// in progress.
    async fn advance_discovery(&mut self, choice: usize) -> Option<Step> {
        let (method, orch) = self.discovery.as_mut()?;
        let method = *method;
        let step = stamp_method(orch.advance(choice).await, method);
        self.pull_discovery_advisory();
        self.reset_if_reauth(&step);
        Some(step)
    }

    /// Feed the user's typed text into a walk paused on a `Step::Input` (ADR 0025).
    /// `None` if no walk is in progress. The text is a location (a path), never a
    /// Value.
    async fn provide_input(&mut self, text: String) -> Option<Step> {
        let (method, orch) = self.discovery.as_mut()?;
        let method = *method;
        let step = stamp_method(orch.provide_input(text).await, method);
        self.pull_discovery_advisory();
        self.reset_if_reauth(&step);
        Some(step)
    }

    /// Drain the queued operator advisories (ADR 0025). The worker surfaces each to
    /// the Diagnostic Log + Discovery wizard once.
    async fn take_advisories(&mut self) -> Vec<String> {
        std::mem::take(&mut self.advisories)
    }

    /// Apply `edits` to `mapping`'s Set under the non-stomping CAS engine, dispatched
    /// to its [`Method`]'s [`ResourceMethod::write`] through the **same broker + ladder**
    /// `load` uses for `fetch` (ADR 0032): ensure signed in, mint a Credential, and run
    /// the force-refresh + re-Sign-in resilience ladder. The rich [`MethodError`] is
    /// masked into the agnostic [`Failure`] (never a Value/Credential/SDK text —
    /// THREAT-MODEL); a [`WriteOutcome::Conflict`] is returned as `Ok` for the caller
    /// to surface (the remote Set changed under us — re-read and retry).
    ///
    /// Reached only in deliberately-unlocked read-write mode (ADR 0004); the worker is
    /// the lock and refuses a write otherwise.
    async fn write(
        &mut self,
        mapping: &Mapping,
        edits: &[EnvEdit],
    ) -> Result<WriteOutcome, Failure> {
        self.sign_in().await.map_err(|_| Failure {
            environment: mapping.environment.clone(),
            reason: FetchFailReason::NeedsSignIn,
            detail: "a fresh Sign-in is required".to_string(),
        })?;
        let Some(method) = self.method_for(&mapping.method) else {
            // The registry lacks this Method — a composition-root bug, masked rather
            // than panicking (mirrors the `load` arm).
            return Err(Failure {
                environment: mapping.environment.clone(),
                reason: FetchFailReason::Other,
                detail: "no method configured for this Environment".to_string(),
            });
        };
        self.write_with_ladder(method.as_ref(), mapping, edits)
            .await
            .map_err(|e| fail_method(mapping, &e))
    }
}

/// Stamp the chosen [`Method`] onto a `Done` Mapping (Decision 5) so the discovered
/// Environment dispatches to the same method on the next load — the method is known
/// before the walk, so `core`'s `Step`/`What` surface need not carry it. A no-op for
/// any non-`Done` step.
fn stamp_method(step: Step, method: Method) -> Step {
    match step {
        Step::Done(mut m) => {
            m.method = method;
            Step::Done(m)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method::MethodError;
    use crate::types::SsoToken;
    use crate::wire::fakes::{CredSpec, FakeAccountCatalog, FakeClock, FakeReauth, FakeRoleClient};
    use crate::wire::RoleSummary;
    use crate::write::{EnvEdit, WriteOutcome};
    use janitor_core::compare::{EntryState, RowKey};
    use janitor_core::config::{Application, Mapping};
    use janitor_core::discovery::StepPlan;
    use janitor_core::provider::What;
    use janitor_core::secret::EntryName;
    use std::sync::Mutex;
    use std::time::Duration;

    // ---- Fake ResourceMethod + discovery steps -----------------------------

    /// How a fake method's discovery tail behaves (cloned into `ScriptedSteps`).
    #[derive(Clone)]
    enum Disco {
        /// Auto-collapse straight to `Done`, optionally surfacing an advisory.
        DoneNow { advisory: Option<String> },
        /// A dead token mid-walk → `Reauth`.
        Reauth,
        /// Pose a free-text path `Input`, then `Done` once it is provided.
        InputThenDone,
    }

    /// A scripted Discovery tail driven by the orchestrator (no AWS).
    struct ScriptedSteps {
        disco: Disco,
        environment: String,
        region: String,
        advisory: Option<String>,
    }
    impl ScriptedSteps {
        fn done_mapping(&self, chosen: &[String]) -> Mapping {
            Mapping {
                environment: self.environment.clone(),
                account_id: "111".into(),
                region: self.region.clone(),
                secret_id: chosen.last().cloned().unwrap_or_else(|| "loc".into()),
                permission_set: "ReadOnly".into(),
                // Deliberately the default — the shell must stamp the chosen method.
                method: Method::SecretsManager,
            }
        }
    }
    #[async_trait]
    impl Steps for ScriptedSteps {
        async fn next(&mut self, chosen: &[String]) -> StepPlan {
            match &self.disco {
                Disco::DoneNow { .. } => StepPlan::Done(self.done_mapping(chosen)),
                Disco::Reauth => StepPlan::Terminal(Step::Reauth),
                Disco::InputThenDone => {
                    if chosen.is_empty() {
                        StepPlan::Input {
                            what: What::FilePath,
                            prompt: "path".into(),
                            default: Some("/app/.env".into()),
                        }
                    } else {
                        StepPlan::Done(self.done_mapping(chosen))
                    }
                }
            }
        }
        fn take_advisory(&mut self) -> Option<String> {
            self.advisory.take()
        }
    }

    /// A scripted [`ResourceMethod`]: fetches are popped per call; `advisory` is a
    /// fixed probe answer; `disco` drives discovery. `write` is scripted too (the
    /// shell never calls it, but a direct test pins the seam).
    struct FakeMethod {
        kind: Method,
        fetches: Mutex<Vec<Result<SecretShape, MethodError>>>,
        fetch_calls: Mutex<u32>,
        advisory: Option<String>,
        advisory_calls: Mutex<u32>,
        disco: Disco,
        writes: Mutex<Vec<Result<WriteOutcome, MethodError>>>,
        write_calls: Mutex<u32>,
    }
    impl FakeMethod {
        fn new(kind: Method) -> Self {
            FakeMethod {
                kind,
                fetches: Mutex::new(Vec::new()),
                fetch_calls: Mutex::new(0),
                advisory: None,
                advisory_calls: Mutex::new(0),
                disco: Disco::DoneNow { advisory: None },
                writes: Mutex::new(Vec::new()),
                write_calls: Mutex::new(0),
            }
        }
        fn fetches(mut self, outcomes: Vec<Result<SecretShape, MethodError>>) -> Self {
            self.fetches = Mutex::new(outcomes);
            self
        }
        fn advisory(mut self, note: &str) -> Self {
            self.advisory = Some(note.into());
            self
        }
        fn disco(mut self, disco: Disco) -> Self {
            self.disco = disco;
            self
        }
        fn writes(mut self, outcomes: Vec<Result<WriteOutcome, MethodError>>) -> Self {
            self.writes = Mutex::new(outcomes);
            self
        }
        fn fetch_count(&self) -> u32 {
            *self.fetch_calls.lock().unwrap()
        }
        fn advisory_count(&self) -> u32 {
            *self.advisory_calls.lock().unwrap()
        }
        fn write_count(&self) -> u32 {
            *self.write_calls.lock().unwrap()
        }
    }
    #[async_trait]
    impl ResourceMethod for FakeMethod {
        fn kind(&self) -> Method {
            self.kind
        }
        fn has_advisory(&self) -> bool {
            self.advisory.is_some()
        }
        async fn fetch(
            &self,
            _cred: &crate::types::Credential,
            _mapping: &Mapping,
        ) -> Result<SecretShape, MethodError> {
            *self.fetch_calls.lock().unwrap() += 1;
            let mut v = self.fetches.lock().unwrap();
            if v.is_empty() {
                panic!("FakeMethod::fetch called more times than scripted");
            }
            v.remove(0)
        }
        async fn write(
            &self,
            _cred: &crate::types::Credential,
            _mapping: &Mapping,
            _edits: &[EnvEdit],
        ) -> Result<WriteOutcome, MethodError> {
            *self.write_calls.lock().unwrap() += 1;
            let mut v = self.writes.lock().unwrap();
            if v.is_empty() {
                panic!("FakeMethod::write called more times than scripted");
            }
            v.remove(0)
        }
        async fn advisory(
            &self,
            _cred: &crate::types::Credential,
            _mapping: &Mapping,
        ) -> Option<String> {
            *self.advisory_calls.lock().unwrap() += 1;
            self.advisory.clone()
        }
        fn discovery_steps(
            &self,
            environment: String,
            region: String,
            _token: Arc<SsoToken>,
            _remembered: Option<Mapping>,
        ) -> Box<dyn Steps> {
            let advisory = match &self.disco {
                Disco::DoneNow { advisory } => advisory.clone(),
                _ => None,
            };
            Box::new(ScriptedSteps {
                disco: self.disco.clone(),
                environment,
                region,
                advisory,
            })
        }
    }

    // ---- builders ----------------------------------------------------------

    fn mapping(env: &str, secret_id: &str) -> Mapping {
        Mapping {
            environment: env.into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: secret_id.into(),
            permission_set: "ReadOnly".into(),
            method: Method::SecretsManager,
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
    fn json(s: &str) -> Result<SecretShape, MethodError> {
        Ok(SecretShape::from_secret_string(s))
    }
    fn roles(names: &[&str]) -> Result<Vec<RoleSummary>, SessionError> {
        Ok(names
            .iter()
            .map(|n| RoleSummary { name: (*n).into() })
            .collect())
    }

    /// One Secrets Manager method registry around a single fake method.
    fn registry(method: Arc<FakeMethod>) -> BTreeMap<Method, Arc<dyn ResourceMethod>> {
        let mut m: BTreeMap<Method, Arc<dyn ResourceMethod>> = BTreeMap::new();
        m.insert(method.kind(), method);
        m
    }

    /// A provider with one fake method and an empty catalog (recovery untouched).
    fn provider(
        reauth: Arc<FakeReauth>,
        role: Arc<FakeRoleClient>,
        method: Arc<FakeMethod>,
    ) -> AwsFamilyProvider {
        AwsFamilyProvider::new(
            reauth,
            role,
            Arc::new(FakeAccountCatalog::new(vec![], vec![])),
            Arc::new(FakeClock::at(0)),
            registry(method),
        )
    }

    /// A provider with a catalog (for recovery tests).
    fn provider_with_catalog(
        reauth: Arc<FakeReauth>,
        role: Arc<FakeRoleClient>,
        catalog: Arc<FakeAccountCatalog>,
        method: Arc<FakeMethod>,
    ) -> AwsFamilyProvider {
        AwsFamilyProvider::new(
            reauth,
            role,
            catalog,
            Arc::new(FakeClock::at(0)),
            registry(method),
        )
    }

    fn one_env(secret_id: &str) -> Application {
        Application {
            name: "app".into(),
            environments: vec![mapping("prod", secret_id)],
        }
    }

    // ---- sign-in / load / reveal -------------------------------------------

    #[tokio::test]
    async fn sign_in_is_idempotent_one_browser() {
        let reauth = Arc::new(FakeReauth::ok());
        let mut p = provider(
            reauth.clone(),
            Arc::new(FakeRoleClient::new(vec![])),
            Arc::new(FakeMethod::new(Method::SecretsManager)),
        );
        assert!(!p.is_signed_in());
        p.sign_in().await.unwrap();
        p.sign_in().await.unwrap();
        assert!(p.is_signed_in());
        assert_eq!(reauth.count(), 1, "second sign_in must be a no-op");
    }

    #[tokio::test]
    async fn load_all_envs_succeed_returns_view_and_caches() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let method = Arc::new(
            FakeMethod::new(Method::SecretsManager)
                .fetches(vec![json(r#"{"A":"1","B":"x"}"#), json(r#"{"A":"1"}"#)]),
        );
        let mut p = provider(reauth, role, method);
        let app = Application {
            name: "app".into(),
            environments: vec![
                mapping("prod", "app/prod"),
                mapping("staging", "app/staging"),
            ],
        };
        let loaded = p.load(&app).await.unwrap();
        assert!(loaded.corrected.is_empty(), "no recovery on the happy path");
        assert_eq!(loaded.view.environments, vec!["prod", "staging"]);
        let b = loaded.view.rows.iter().find(|r| r.name == "B").unwrap();
        assert_eq!(b.state, EntryState::Gap);
        let key = RowKey::Entry(EntryName::from_path(&["A".to_string()]));
        assert_eq!(
            p.reveal(&key, 0).map(|v| v.expose_owned()),
            Some("1".to_string())
        );
    }

    #[tokio::test]
    async fn load_one_env_fails_is_whole_app_error_naming_it() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok(), cred_ok()]));
        let method = Arc::new(FakeMethod::new(Method::SecretsManager).fetches(vec![
            json(r#"{"A":"1"}"#),
            Err(MethodError::Session(SessionError::AccessDenied)),
            // force_refresh retry consumes this second denial.
            Err(MethodError::Session(SessionError::AccessDenied)),
        ]));
        let mut p = provider(reauth, role, method);
        let app = Application {
            name: "app".into(),
            environments: vec![
                mapping("prod", "app/prod"),
                mapping("staging", "app/staging"),
            ],
        };
        let err = p.load(&app).await.unwrap_err();
        assert_eq!(err.failures.len(), 1);
        assert_eq!(err.failures[0].environment, "staging");
        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
    }

    #[tokio::test]
    async fn load_maps_signin_failure_to_needs_sign_in() {
        let reauth = Arc::new(FakeReauth::failing());
        let mut p = provider(
            reauth,
            Arc::new(FakeRoleClient::new(vec![])),
            Arc::new(FakeMethod::new(Method::SecretsManager)),
        );
        let err = p.load(&one_env("a/prod")).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::NeedsSignIn);
    }

    #[tokio::test]
    async fn reveal_is_none_before_load() {
        let p = provider(
            Arc::new(FakeReauth::ok()),
            Arc::new(FakeRoleClient::new(vec![])),
            Arc::new(FakeMethod::new(Method::SecretsManager)),
        );
        let key = RowKey::Entry(EntryName::from_path(&["A".to_string()]));
        assert!(p.reveal(&key, 0).is_none(), "nothing cached yet");
    }

    #[tokio::test]
    async fn content_error_is_unsupported_and_never_force_refreshed() {
        // A malformed payload (Content) must NOT trigger the force-refresh/recovery
        // ladder — exactly one fetch, surfaced Unsupported with its precise detail.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let method = Arc::new(FakeMethod::new(Method::SsmDotenv).fetches(vec![Err(
            MethodError::Content {
                detail: "malformed .env line 2".into(),
            },
        )]));
        let mut p = provider(reauth, role, method.clone());
        let mut m = mapping("prod", "i-0abc:/app/.env");
        m.method = Method::SsmDotenv;
        let app = Application {
            name: "app".into(),
            environments: vec![m],
        };
        let err = p.load(&app).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::Unsupported);
        assert_eq!(err.failures[0].detail, "malformed .env line 2");
        assert_eq!(
            method.fetch_count(),
            1,
            "no force-refresh on a Content error"
        );
    }

    // ---- the fetch ladder (lifted from AuthenticatedSource) ----------------

    #[tokio::test]
    async fn stale_credential_force_refreshes_once_then_succeeds() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let method = Arc::new(FakeMethod::new(Method::SecretsManager).fetches(vec![
            Err(MethodError::Session(SessionError::AccessDenied)),
            json(r#"{"A":"1"}"#),
        ]));
        let mut p = provider(reauth.clone(), role.clone(), method.clone());
        p.load(&one_env("app/prod")).await.unwrap();
        assert_eq!(role.call_count(), 2, "one initial mint + one force_refresh");
        assert_eq!(method.fetch_count(), 2, "one denied + one retry");
        assert_eq!(reauth.count(), 1, "no extra browser for a stale credential");
    }

    #[tokio::test]
    async fn true_denial_force_refreshes_once_then_gives_access_denied() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let method = Arc::new(FakeMethod::new(Method::SecretsManager).fetches(vec![
            Err(MethodError::Session(SessionError::AccessDenied)),
            Err(MethodError::Session(SessionError::AccessDenied)),
        ]));
        let mut p = provider(reauth, role.clone(), method.clone());
        let err = p.load(&one_env("app/prod")).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
        assert_eq!(role.call_count(), 2, "exactly one wasted re-mint, no loop");
        assert_eq!(method.fetch_count(), 2);
    }

    #[tokio::test]
    async fn dead_token_re_signs_in_once_then_succeeds() {
        // First mint → ReauthRequired (dead token). After re-Sign-in the rebuilt
        // broker mints OK and the fetch succeeds.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![
            Err(SessionError::ReauthRequired),
            cred_ok(),
        ]));
        let method =
            Arc::new(FakeMethod::new(Method::SecretsManager).fetches(vec![json(r#"{"A":"1"}"#)]));
        let mut p = provider(reauth.clone(), role.clone(), method.clone());
        p.load(&one_env("app/prod")).await.unwrap();
        assert_eq!(reauth.count(), 2, "load sign-in + one re-sign-in");
        assert_eq!(role.call_count(), 2);
        assert_eq!(method.fetch_count(), 1, "fetch only after a good mint");
    }

    #[tokio::test]
    async fn still_unauthorized_after_reauth_is_fatal_no_browser_loop() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![
            Err(SessionError::ReauthRequired),
            Err(SessionError::ReauthRequired),
        ]));
        let method = Arc::new(FakeMethod::new(Method::SecretsManager));
        let mut p = provider(reauth.clone(), role, method);
        let err = p.load(&one_env("app/prod")).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
        assert_eq!(reauth.count(), 2, "load sign-in + at most one re-sign-in");
    }

    // ---- stale-role recovery (ADR 0018), now in the shell ------------------

    #[tokio::test]
    async fn single_role_auto_corrects_retries_and_persists_corrected_mapping() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![role_not_entitled(), cred_ok()]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&["PowerUser"])]));
        let method =
            Arc::new(FakeMethod::new(Method::SecretsManager).fetches(vec![json(r#"{"A":"1"}"#)]));
        let mut p = provider_with_catalog(reauth.clone(), role.clone(), catalog.clone(), method);
        let loaded = p.load(&one_env("app/prod")).await.unwrap();
        assert_eq!(loaded.view.environments, vec!["prod"]);
        assert_eq!(loaded.corrected.len(), 1);
        let c = &loaded.corrected[0];
        assert_eq!(c.permission_set, "PowerUser", "role rewritten");
        assert_eq!(c.account_id, "111111111111", "ONLY permission_set changed");
        assert_eq!(
            c.method,
            Method::SecretsManager,
            "the method tag is preserved"
        );
        assert_eq!(catalog.role_call_count(), 1, "exactly one re-list");
        assert_eq!(role.call_count(), 2, "denied mint + corrected mint");
        assert_eq!(
            reauth.count(),
            1,
            "recovery reuses the token — no 2nd sign-in"
        );
    }

    #[tokio::test]
    async fn ambiguous_roles_keeps_failure_and_never_auto_picks() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![role_not_entitled()]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&["A", "B"])]));
        let method = Arc::new(FakeMethod::new(Method::SecretsManager));
        let mut p = provider_with_catalog(reauth, role.clone(), catalog.clone(), method);
        let err = p.load(&one_env("app/prod")).await.unwrap_err();
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
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&[])]));
        let mut p = provider_with_catalog(
            reauth,
            role.clone(),
            catalog,
            Arc::new(FakeMethod::new(Method::SecretsManager)),
        );
        let err = p.load(&one_env("app/prod")).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
        assert_eq!(role.call_count(), 1, "no retry");
    }

    #[tokio::test]
    async fn single_role_equal_to_stored_is_a_noop() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![role_not_entitled()]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&["ReadOnly"])]));
        let mut p = provider_with_catalog(
            reauth,
            role.clone(),
            catalog,
            Arc::new(FakeMethod::new(Method::SecretsManager)),
        );
        let err = p.load(&one_env("app/prod")).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
        assert_eq!(
            role.call_count(),
            1,
            "no retry for a same-role 'correction'"
        );
    }

    #[tokio::test]
    async fn recovery_retry_failure_surfaces_and_never_recovers_again() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![
            role_not_entitled(),
            role_not_entitled(),
        ]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&["PowerUser"])]));
        let mut p = provider_with_catalog(
            reauth,
            role.clone(),
            catalog.clone(),
            Arc::new(FakeMethod::new(Method::SecretsManager)),
        );
        let err = p.load(&one_env("app/prod")).await.unwrap_err();
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
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![
            Err(SessionError::ReauthRequired),
            cred_ok(),
        ]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![]));
        let method =
            Arc::new(FakeMethod::new(Method::SecretsManager).fetches(vec![json(r#"{"A":"1"}"#)]));
        let mut p = provider_with_catalog(reauth.clone(), role, catalog.clone(), method);
        let loaded = p.load(&one_env("app/prod")).await.unwrap();
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
        let catalog = Arc::new(FakeAccountCatalog::new(
            vec![],
            vec![Err(SessionError::Throttled)],
        ));
        let mut p = provider_with_catalog(
            reauth,
            role.clone(),
            catalog.clone(),
            Arc::new(FakeMethod::new(Method::SecretsManager)),
        );
        let err = p.load(&one_env("app/prod")).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
        assert_eq!(
            role.call_count(),
            1,
            "no retry when the re-list itself fails"
        );
        assert_eq!(catalog.role_call_count(), 1);
    }

    #[tokio::test]
    async fn recovery_after_a_resign_in_uses_the_live_token() {
        // A dead token then a de-assigned role in ONE fetch: re-Sign-in (fresh
        // token), retry mint → RoleNotEntitled, recovery re-lists under the LIVE
        // token and still succeeds.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![
            Err(SessionError::ReauthRequired), // dead token
            role_not_entitled(),               // post-re-sign-in: de-assigned
            cred_ok(),                         // corrected role mints
        ]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&["PowerUser"])]));
        let method =
            Arc::new(FakeMethod::new(Method::SecretsManager).fetches(vec![json(r#"{"A":"1"}"#)]));
        let mut p = provider_with_catalog(reauth.clone(), role.clone(), catalog.clone(), method);
        let loaded = p.load(&one_env("app/prod")).await.unwrap();
        assert_eq!(loaded.corrected.len(), 1);
        assert_eq!(loaded.corrected[0].permission_set, "PowerUser");
        assert_eq!(reauth.count(), 2, "initial sign-in + one re-sign-in");
        assert_eq!(catalog.role_call_count(), 1, "recovery re-listed once");
        assert_eq!(role.call_count(), 3, "dead + de-assigned + corrected mint");
    }

    // ---- per-Mapping method dispatch (the headline capability) -------------

    #[tokio::test]
    async fn mixed_method_matrix_dispatches_per_mapping_and_reveals() {
        // One Application comparing a Secrets Manager prod against an SSM staging in
        // one masked matrix — the registry dispatches per Mapping; the cache + reveal
        // are method-agnostic, so it falls out for free (ADR 0031 Decision 4).
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let sm = Arc::new(
            FakeMethod::new(Method::SecretsManager).fetches(vec![json(r#"{"A":"1","B":"x"}"#)]),
        );
        let ssm = Arc::new(FakeMethod::new(Method::SsmDotenv).fetches(vec![json(r#"{"A":"1"}"#)]));
        let mut methods: BTreeMap<Method, Arc<dyn ResourceMethod>> = BTreeMap::new();
        methods.insert(Method::SecretsManager, sm.clone());
        methods.insert(Method::SsmDotenv, ssm.clone());
        let mut p = AwsFamilyProvider::new(
            reauth,
            role,
            Arc::new(FakeAccountCatalog::new(vec![], vec![])),
            Arc::new(FakeClock::at(0)),
            methods,
        );
        let mut prod = mapping("prod", "arn:prod");
        prod.method = Method::SecretsManager;
        let mut staging = mapping("staging", "i-stg:/app/.env");
        staging.method = Method::SsmDotenv;
        let app = Application {
            name: "app".into(),
            environments: vec![prod, staging],
        };
        let loaded = p.load(&app).await.unwrap();
        assert_eq!(loaded.view.environments, vec!["prod", "staging"]);
        let b = loaded.view.rows.iter().find(|r| r.name == "B").unwrap();
        assert_eq!(b.state, EntryState::Gap, "B is prod-only across stores");
        assert_eq!(sm.fetch_count(), 1, "SM method fetched prod");
        assert_eq!(ssm.fetch_count(), 1, "SSM method fetched staging");
        // Reveal works on either column regardless of the backing method.
        let key = RowKey::Entry(EntryName::from_path(&["A".to_string()]));
        assert_eq!(
            p.reveal(&key, 1).map(|v| v.expose_owned()),
            Some("1".to_string()),
            "reveal the SSM cell"
        );
    }

    #[tokio::test]
    async fn load_with_no_method_in_registry_is_a_masked_failure() {
        // A Mapping tagged for a method the registry lacks (composition bug) surfaces
        // masked, never a panic.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        // Registry has only SecretsManager; the env asks for SsmDotenv.
        let mut p = provider(
            reauth,
            role,
            Arc::new(FakeMethod::new(Method::SecretsManager)),
        );
        let mut m = mapping("prod", "x");
        m.method = Method::SsmDotenv;
        let app = Application {
            name: "app".into(),
            environments: vec![m],
        };
        let err = p.load(&app).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::Other);
    }

    // ---- load-time advisory probe ------------------------------------------

    #[tokio::test]
    async fn load_surfaces_one_advisory_per_distinct_method_then_dedupes() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let method = Arc::new(
            FakeMethod::new(Method::SsmDotenv)
                .advisory("logged to CloudWatch")
                // two loads × two envs each re-read.
                .fetches(vec![
                    json(r#"{"A":"1"}"#),
                    json(r#"{"A":"1"}"#),
                    json(r#"{"A":"1"}"#),
                    json(r#"{"A":"1"}"#),
                ]),
        );
        let mut p = provider(reauth, role, method.clone());
        let app = Application {
            name: "app".into(),
            environments: vec![
                {
                    let mut m = mapping("prod", "i-a:/app/.env");
                    m.method = Method::SsmDotenv;
                    m
                },
                {
                    let mut m = mapping("staging", "i-b:/app/.env");
                    m.method = Method::SsmDotenv;
                    m
                },
            ],
        };
        p.load(&app).await.unwrap();
        assert_eq!(
            method.advisory_count(),
            1,
            "probed once per DISTINCT method, not once per env"
        );
        let adv = p.take_advisories().await;
        assert_eq!(adv.len(), 1);
        assert!(adv[0].contains("CloudWatch"));
        assert!(p.take_advisories().await.is_empty(), "advisories drained");
        // A second load re-probes, but the identical advisory is deduped.
        p.load(&app).await.unwrap();
        assert!(
            p.take_advisories().await.is_empty(),
            "the same advisory is not surfaced twice"
        );
    }

    #[tokio::test]
    async fn no_advisory_from_the_secrets_manager_method() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let method =
            Arc::new(FakeMethod::new(Method::SecretsManager).fetches(vec![json(r#"{"A":"1"}"#)]));
        let mut p = provider(reauth, role, method);
        p.load(&one_env("app/prod")).await.unwrap();
        assert!(
            p.take_advisories().await.is_empty(),
            "SM has no side-effect advisory"
        );
    }

    // ---- discovery handle --------------------------------------------------

    #[tokio::test]
    async fn begin_discovery_signs_in_drives_to_done_and_stamps_the_method() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let method =
            Arc::new(FakeMethod::new(Method::SsmDotenv).disco(Disco::DoneNow { advisory: None }));
        let mut methods: BTreeMap<Method, Arc<dyn ResourceMethod>> = BTreeMap::new();
        methods.insert(Method::SsmDotenv, method);
        let mut p = AwsFamilyProvider::new(
            reauth.clone(),
            role,
            Arc::new(FakeAccountCatalog::new(vec![], vec![])),
            Arc::new(FakeClock::at(0)),
            methods,
        );
        let step = p
            .begin_discovery(Method::SsmDotenv, "prod".into(), "us-west-2".into(), None)
            .await
            .unwrap();
        let Step::Done(m) = step else {
            panic!("expected Done, got {step:?}");
        };
        assert_eq!(m.environment, "prod");
        assert_eq!(
            m.method,
            Method::SsmDotenv,
            "the chosen method is stamped onto the discovered Mapping"
        );
        assert_eq!(reauth.count(), 1, "discovery signs in exactly once");
        assert!(p.is_signed_in());
    }

    #[tokio::test]
    async fn discovery_surfaces_a_mid_walk_advisory() {
        let reauth = Arc::new(FakeReauth::ok());
        let method = Arc::new(FakeMethod::new(Method::SsmDotenv).disco(Disco::DoneNow {
            advisory: Some("logged to S3".into()),
        }));
        let mut methods: BTreeMap<Method, Arc<dyn ResourceMethod>> = BTreeMap::new();
        methods.insert(Method::SsmDotenv, method);
        let mut p = AwsFamilyProvider::new(
            reauth,
            Arc::new(FakeRoleClient::new(vec![])),
            Arc::new(FakeAccountCatalog::new(vec![], vec![])),
            Arc::new(FakeClock::at(0)),
            methods,
        );
        p.begin_discovery(Method::SsmDotenv, "prod".into(), "us-east-1".into(), None)
            .await
            .unwrap();
        let adv = p.take_advisories().await;
        assert_eq!(adv.len(), 1);
        assert!(adv[0].contains("S3"));
    }

    #[tokio::test]
    async fn provide_input_completes_a_walk_and_stamps_the_method() {
        let reauth = Arc::new(FakeReauth::ok());
        let method = Arc::new(FakeMethod::new(Method::SsmDotenv).disco(Disco::InputThenDone));
        let mut methods: BTreeMap<Method, Arc<dyn ResourceMethod>> = BTreeMap::new();
        methods.insert(Method::SsmDotenv, method);
        let mut p = AwsFamilyProvider::new(
            reauth,
            Arc::new(FakeRoleClient::new(vec![])),
            Arc::new(FakeAccountCatalog::new(vec![], vec![])),
            Arc::new(FakeClock::at(0)),
            methods,
        );
        let step = p
            .begin_discovery(Method::SsmDotenv, "prod".into(), "us-east-1".into(), None)
            .await
            .unwrap();
        assert!(matches!(step, Step::Input { .. }));
        let Some(Step::Done(m)) = p.provide_input("/srv/.env".into()).await else {
            panic!("expected Done from provide_input");
        };
        assert_eq!(m.secret_id, "/srv/.env");
        assert_eq!(m.method, Method::SsmDotenv);
    }

    #[tokio::test]
    async fn discovery_reauth_clears_sign_in_so_next_sign_in_reauthenticates() {
        let reauth = Arc::new(FakeReauth::ok());
        let method = Arc::new(FakeMethod::new(Method::SecretsManager).disco(Disco::Reauth));
        let mut p = provider(
            reauth.clone(),
            Arc::new(FakeRoleClient::new(vec![])),
            method,
        );
        let step = p
            .begin_discovery(
                Method::SecretsManager,
                "prod".into(),
                "us-east-1".into(),
                None,
            )
            .await
            .unwrap();
        assert!(matches!(step, Step::Reauth));
        assert!(
            !p.is_signed_in(),
            "a dead-token discovery clears the session"
        );
        p.sign_in().await.unwrap();
        assert_eq!(
            reauth.count(),
            2,
            "re-sign-in against a fresh token, not a no-op"
        );
    }

    #[tokio::test]
    async fn advance_and_provide_input_are_none_without_a_walk() {
        let mut p = provider(
            Arc::new(FakeReauth::ok()),
            Arc::new(FakeRoleClient::new(vec![])),
            Arc::new(FakeMethod::new(Method::SecretsManager)),
        );
        assert!(p.advance_discovery(0).await.is_none());
        assert!(p.provide_input("/app/.env".into()).await.is_none());
    }

    #[tokio::test]
    async fn begin_discovery_with_unknown_method_is_a_masked_failed() {
        // The registry lacks the requested method (composition bug) → masked Failed,
        // never a panic.
        let mut p = provider(
            Arc::new(FakeReauth::ok()),
            Arc::new(FakeRoleClient::new(vec![])),
            Arc::new(FakeMethod::new(Method::SecretsManager)),
        );
        let step = p
            .begin_discovery(Method::SsmDotenv, "prod".into(), "us-east-1".into(), None)
            .await
            .unwrap();
        assert!(matches!(step, Step::Failed(FetchFailReason::Other)));
    }

    // ---- the write path through the port (ADR 0032) ------------------------

    #[tokio::test]
    async fn write_dispatches_through_the_method_and_returns_the_cas_outcome() {
        // The headline B5 wiring: `Provider::write` signs in, mints a Credential via
        // the broker, and dispatches to the Mapping's method — returning the CAS
        // outcome unchanged.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let method =
            Arc::new(FakeMethod::new(Method::SsmDotenv).writes(vec![Ok(WriteOutcome::Applied)]));
        let mut p = provider(reauth.clone(), role.clone(), method.clone());
        let mut m = mapping("prod", "i-a:/app/.env");
        m.method = Method::SsmDotenv;
        let outcome = p.write(&m, &[EnvEdit::set("A", "2")]).await.unwrap();
        assert_eq!(outcome, WriteOutcome::Applied);
        assert_eq!(reauth.count(), 1, "write signs in once");
        assert_eq!(role.call_count(), 1, "one Credential minted for the write");
        assert_eq!(method.write_count(), 1, "the method's write ran once");
    }

    #[tokio::test]
    async fn write_surfaces_a_cas_conflict_as_ok_not_an_error() {
        // A Conflict (the remote Set changed under us) is a normal outcome the user
        // must see — not a masked Failure.
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let method =
            Arc::new(FakeMethod::new(Method::SsmDotenv).writes(vec![Ok(WriteOutcome::Conflict)]));
        let mut p = provider(Arc::new(FakeReauth::ok()), role, method);
        let mut m = mapping("prod", "i-a:/app/.env");
        m.method = Method::SsmDotenv;
        assert_eq!(
            p.write(&m, &[EnvEdit::set("A", "2")]).await.unwrap(),
            WriteOutcome::Conflict
        );
    }

    #[tokio::test]
    async fn write_force_refreshes_once_on_access_denied_then_succeeds() {
        // A stale cached Credential AWS now rejects: force-refresh once, retry, win —
        // the same ladder `fetch` runs, now on the write path.
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let method = Arc::new(FakeMethod::new(Method::SsmDotenv).writes(vec![
            Err(MethodError::Session(SessionError::AccessDenied)),
            Ok(WriteOutcome::Applied),
        ]));
        let mut p = provider(Arc::new(FakeReauth::ok()), role.clone(), method.clone());
        let mut m = mapping("prod", "i-a:/app/.env");
        m.method = Method::SsmDotenv;
        assert_eq!(
            p.write(&m, &[EnvEdit::set("A", "2")]).await.unwrap(),
            WriteOutcome::Applied
        );
        assert_eq!(role.call_count(), 2, "initial mint + one force_refresh");
        assert_eq!(method.write_count(), 2, "one denied + one retry");
    }

    #[tokio::test]
    async fn write_true_denial_force_refreshes_once_then_masks_access_denied() {
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let method = Arc::new(FakeMethod::new(Method::SsmDotenv).writes(vec![
            Err(MethodError::Session(SessionError::AccessDenied)),
            Err(MethodError::Session(SessionError::AccessDenied)),
        ]));
        let mut p = provider(Arc::new(FakeReauth::ok()), role.clone(), method.clone());
        let mut m = mapping("prod", "i-a:/app/.env");
        m.method = Method::SsmDotenv;
        let err = p.write(&m, &[EnvEdit::set("A", "2")]).await.unwrap_err();
        assert_eq!(err.reason, FetchFailReason::AccessDenied);
        assert_eq!(err.environment, "prod");
        assert_eq!(role.call_count(), 2, "exactly one wasted re-mint, no loop");
        assert_eq!(method.write_count(), 2);
    }

    #[tokio::test]
    async fn write_re_signs_in_once_on_dead_token_then_succeeds() {
        // First mint → ReauthRequired (dead token). After re-Sign-in the rebuilt
        // broker mints OK and the write applies.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![
            Err(SessionError::ReauthRequired),
            cred_ok(),
        ]));
        let method =
            Arc::new(FakeMethod::new(Method::SsmDotenv).writes(vec![Ok(WriteOutcome::Applied)]));
        let mut p = provider(reauth.clone(), role.clone(), method.clone());
        let mut m = mapping("prod", "i-a:/app/.env");
        m.method = Method::SsmDotenv;
        assert_eq!(
            p.write(&m, &[EnvEdit::set("A", "2")]).await.unwrap(),
            WriteOutcome::Applied
        );
        assert_eq!(reauth.count(), 2, "write sign-in + one re-sign-in");
        assert_eq!(method.write_count(), 1, "write only after a good mint");
    }

    #[tokio::test]
    async fn write_still_unauthorized_after_reauth_is_fatal_no_loop() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![
            Err(SessionError::ReauthRequired),
            Err(SessionError::ReauthRequired),
        ]));
        let method = Arc::new(FakeMethod::new(Method::SsmDotenv));
        let mut p = provider(reauth.clone(), role, method);
        let mut m = mapping("prod", "i-a:/app/.env");
        m.method = Method::SsmDotenv;
        let err = p.write(&m, &[EnvEdit::set("A", "2")]).await.unwrap_err();
        assert_eq!(err.reason, FetchFailReason::AccessDenied);
        assert_eq!(reauth.count(), 2, "write sign-in + at most one re-sign-in");
    }

    #[tokio::test]
    async fn write_role_not_entitled_masks_access_denied_without_recovery() {
        // Unlike `load`, a write never runs stale-role recovery (it would rewrite +
        // persist a Mapping's role — load-time Config state). A RoleNotEntitled mint
        // masks straight to AccessDenied; the catalog is never re-listed.
        let role = Arc::new(FakeRoleClient::new(vec![role_not_entitled()]));
        let catalog = Arc::new(FakeAccountCatalog::new(vec![], vec![roles(&["PowerUser"])]));
        let method = Arc::new(FakeMethod::new(Method::SsmDotenv));
        let mut p = provider_with_catalog(
            Arc::new(FakeReauth::ok()),
            role.clone(),
            catalog.clone(),
            method.clone(),
        );
        let mut m = mapping("prod", "i-a:/app/.env");
        m.method = Method::SsmDotenv;
        let err = p.write(&m, &[EnvEdit::set("A", "2")]).await.unwrap_err();
        assert_eq!(err.reason, FetchFailReason::AccessDenied);
        assert_eq!(
            catalog.role_call_count(),
            0,
            "no recovery re-list on a write"
        );
        assert_eq!(
            method.write_count(),
            0,
            "the mint denial precedes any write"
        );
    }

    #[tokio::test]
    async fn write_with_no_method_in_registry_is_a_masked_other_failure() {
        // A Mapping tagged for a method the registry lacks (composition bug) surfaces
        // masked, never a panic — and never reaches a write.
        let mut p = provider(
            Arc::new(FakeReauth::ok()),
            Arc::new(FakeRoleClient::new(vec![])),
            Arc::new(FakeMethod::new(Method::SecretsManager)),
        );
        let mut m = mapping("prod", "x");
        m.method = Method::SsmDotenv; // registry has only SecretsManager
        let err = p.write(&m, &[EnvEdit::set("A", "2")]).await.unwrap_err();
        assert_eq!(err.reason, FetchFailReason::Other);
    }

    #[tokio::test]
    async fn write_maps_a_sign_in_failure_to_needs_sign_in() {
        let mut p = provider(
            Arc::new(FakeReauth::failing()),
            Arc::new(FakeRoleClient::new(vec![])),
            Arc::new(FakeMethod::new(Method::SecretsManager)),
        );
        let err = p
            .write(&mapping("prod", "a/prod"), &[EnvEdit::set("A", "2")])
            .await
            .unwrap_err();
        assert_eq!(err.reason, FetchFailReason::NeedsSignIn);
    }
}
