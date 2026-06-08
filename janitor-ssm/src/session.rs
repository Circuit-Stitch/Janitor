//! `SsmProvider` (ADR 0025): the remote-`.env`-over-SSM [`Provider`] — the second
//! real Provider. It mirrors `janitor-aws::Session`: lazy browser Sign-in (over
//! the shared `janitor-aws-auth` front half), per-Application multi-Environment
//! fetch into a masked matrix, momentary reveal from a worker-resident cache, and
//! the guided [`SsmDiscovery`] walk. Lives in the GUI's worker thread; never
//! crosses threads. All orchestration is unit-tested against fakes; only the
//! concrete SSM transport (behind the `wire` seams) is untested shell (B4).
//!
//! Unlike the SM Session, this Provider **does** pose a free-text `Step::Input`
//! (the `.env` path), so [`provide_input`](Provider::provide_input) drives the
//! walk forward rather than returning `None`. It carries **no** stale-role
//! recovery (ADR 0018): a denial surfaces as a masked whole-app `Failure` that
//! routes the GUI back to Sign-in, which is sufficient for this Provider's scope.
//!
//! The rich AWS error taxonomy (`SessionError`) never crosses the port: it is
//! masked into the agnostic `core::provider` types at the boundary
//! (`SessionError`/`DotenvError` → `FetchFailReason`; ADR 0019 / ADR 0024).

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use janitor_core::compare::{Comparison, RowKey};
use janitor_core::config::{Application, Mapping};
use janitor_core::provider::{AppError, Failure, Loaded, Provider, SignInFailed, Step};
use janitor_core::secret::SecretShape;
use janitor_core::view::{project, reveal_value};

use janitor_aws_auth::broker::CredentialBroker;
use janitor_aws_auth::types::{Clock, SsoToken};
use janitor_aws_auth::wire::{AccountCatalog, Reauth, RoleCredentialClient};

use crate::discovery::SsmDiscovery;
use crate::logging::LoggingPreference;
use crate::source::{DotenvFetchError, SsmSource};
use crate::wire::{InstanceCatalog, RemoteFileReader};

/// Build a `Failure` from an Environment's Mapping + the masked fetch error.
/// `detail` is error-safe (no Value/Credential/SSM text; THREAT-MODEL).
fn fail(m: &Mapping, e: &DotenvFetchError) -> Failure {
    Failure {
        environment: m.environment.clone(),
        reason: e.reason(),
        detail: e.detail(),
    }
}

/// The GUI's authenticated remote-`.env`-over-SSM session. Built from the same
/// `Arc<dyn …>` seams the (B4) `live-verify-ssm` will use; signs in lazily and
/// caches the current Application's fetched Sets (the only place plaintext lives
/// on the worker side).
pub struct SsmProvider {
    reauth: Arc<dyn Reauth>,
    role_client: Arc<dyn RoleCredentialClient>,
    catalog: Arc<dyn AccountCatalog>,
    instances: Arc<dyn InstanceCatalog>,
    reader: Arc<dyn RemoteFileReader>,
    logging: Arc<dyn LoggingPreference>,
    clock: Arc<dyn Clock>,
    source: Option<SsmSource>,
    /// The session's one SSO token, shared (`Arc`) with both the fetch broker and
    /// any in-progress walk so neither triggers a second Sign-in. `Some` once
    /// signed in.
    token: Option<Arc<SsoToken>>,
    /// The in-progress guided `SsmDiscovery` (ADR 0013). Owned here, independent
    /// of the fetched-Set cache, so the wizard survives across `Command`s.
    discovery: Option<SsmDiscovery>,
    cached: Vec<(String, SecretShape)>,
    /// Session-logging advisories pending surfacing (drained by `take_advisories`),
    /// and the set already surfaced so an advisory shows at most once (ADR 0025).
    advisories: Vec<String>,
    seen_advisories: HashSet<String>,
}

impl SsmProvider {
    /// Construct from the adapters. No I/O, no Sign-in (lazy). `role_client` mints
    /// role Credentials and (as the real `AwsRoleClient` implements both) lists
    /// accounts/roles via `catalog`; `instances` + `reader` are the SSM tail seams.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reauth: Arc<dyn Reauth>,
        role_client: Arc<dyn RoleCredentialClient>,
        catalog: Arc<dyn AccountCatalog>,
        instances: Arc<dyn InstanceCatalog>,
        reader: Arc<dyn RemoteFileReader>,
        logging: Arc<dyn LoggingPreference>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        SsmProvider {
            reauth,
            role_client,
            catalog,
            instances,
            reader,
            logging,
            clock,
            source: None,
            token: None,
            discovery: None,
            cached: Vec::new(),
            advisories: Vec::new(),
            seen_advisories: HashSet::new(),
        }
    }

    /// Queue an advisory to surface, deduped so the same note shows at most once
    /// this session (ADR 0025).
    fn push_advisory(&mut self, advisory: String) {
        if self.seen_advisories.insert(advisory.clone()) {
            self.advisories.push(advisory);
        }
    }

    /// Pull any session-logging advisory the in-progress walk produced at its read
    /// (where it minted a credential and probed) up into the surface queue.
    fn pull_discovery_advisory(&mut self) {
        if let Some(w) = self.discovery.as_mut().and_then(|d| d.take_advisory()) {
            self.push_advisory(w);
        }
    }

    /// Whether a browser Sign-in has already happened this session.
    pub fn is_signed_in(&self) -> bool {
        self.source.is_some()
    }

    /// On a discovery `Step::Reauth` (a dead SSO token), drop the cached Sign-in +
    /// any in-progress walk so the next `sign_in()` re-opens the browser instead
    /// of reusing the dead token. No-op for any other Step.
    fn reset_if_reauth(&mut self, step: &Step) {
        if matches!(step, Step::Reauth) {
            self.source = None;
            self.token = None;
            self.discovery = None;
        }
    }
}

#[async_trait]
impl Provider for SsmProvider {
    /// Idempotent browser Sign-in: builds the broker + source on first call from a
    /// fresh SSO token; a no-op once signed in. The initial token comes through
    /// the same `Reauth` seam any re-Sign-in uses, which is what makes this fakeable.
    async fn sign_in(&mut self) -> Result<(), SignInFailed> {
        if self.source.is_some() {
            return Ok(());
        }
        let token = Arc::new(self.reauth.sign_in().await?);
        let broker = CredentialBroker::new(
            Arc::clone(&token),
            Arc::clone(&self.role_client),
            Arc::clone(&self.clock),
        );
        self.source = Some(SsmSource::new(broker, Arc::clone(&self.reader)));
        self.token = Some(token);
        Ok(())
    }

    /// Load one Application: ensure signed in, read+parse every Environment's
    /// `.env`, and — if ANY Environment fails — return a whole-app error naming
    /// the failures with masked reason/detail (ADR 0012, never a partial matrix).
    /// On full success, cache the Sets and return the masked view. The Sets
    /// (plaintext) never leave `self.cached`. This Provider never auto-corrects, so
    /// `corrected` is always empty.
    async fn load(&mut self, app: &Application) -> Result<Loaded, AppError> {
        self.sign_in()
            .await
            .map_err(|_| AppError::needs_sign_in())?;

        // Warn once if this Application's reads may be archived by org-wide SSM
        // session logging — probed against its first Environment's credential
        // before any read happens (ADR 0025 / THREAT-MODEL).
        let advisory = {
            let source = self.source.as_ref().expect("source exists after sign_in");
            match app.environments.first() {
                Some(first) => source.logging_advisory(first, self.logging.as_ref()).await,
                None => None,
            }
        };
        if let Some(w) = advisory {
            self.push_advisory(w);
        }

        let source = self.source.as_ref().expect("source exists after sign_in");

        let mut sets: Vec<(String, SecretShape)> = Vec::new();
        let mut failures: Vec<Failure> = Vec::new();
        for m in &app.environments {
            match source.fetch(m).await {
                Ok(shape) => sets.push((m.environment.clone(), shape)),
                Err(e) => failures.push(fail(m, &e)),
            }
        }
        if !failures.is_empty() {
            return Err(AppError { failures });
        }
        let view = project(&Comparison::build(&sets));
        self.cached = sets;
        Ok(Loaded {
            view,
            corrected: Vec::new(),
        })
    }

    /// Momentary reveal of one cell's plaintext from the cached Sets, returned as
    /// an owned `String` so plaintext crosses to the UI thread only here and only
    /// on explicit request (ADR 0003). `None` if the cell is gone/absent/binary.
    fn reveal(&self, key: &RowKey, col: usize) -> Option<String> {
        reveal_value(&self.cached, key, col).map(|v| v.expose().to_string())
    }

    /// Begin a guided `SsmDiscovery` walk for one new Environment (ADR 0013):
    /// ensure signed in, then build + start the machine on the session's SSO
    /// token. The first `Step` is an `Ask`/`Input`/terminal state; subsequent
    /// picks go through [`advance_discovery`](Self::advance_discovery) and
    /// [`provide_input`](Self::provide_input).
    async fn begin_discovery(
        &mut self,
        environment: String,
        region: String,
        remembered: Option<Mapping>,
    ) -> Result<Step, SignInFailed> {
        self.sign_in().await?;
        let token = Arc::clone(self.token.as_ref().expect("token set by sign_in"));
        let mut discovery = SsmDiscovery::new(
            environment,
            region,
            token,
            Arc::clone(&self.catalog),
            Arc::clone(&self.role_client),
            Arc::clone(&self.instances),
            Arc::clone(&self.reader),
            Arc::clone(&self.logging),
            remembered,
        );
        let step = discovery.start().await;
        self.discovery = Some(discovery);
        self.pull_discovery_advisory();
        self.reset_if_reauth(&step);
        Ok(step)
    }

    /// Feed the user's chosen index into the in-progress walk. `None` if no walk
    /// is in progress.
    async fn advance_discovery(&mut self, choice: usize) -> Option<Step> {
        let step = self.discovery.as_mut()?.advance(choice).await;
        self.pull_discovery_advisory();
        self.reset_if_reauth(&step);
        Some(step)
    }

    /// Feed the user's typed `.env` path into a walk paused on the path `Input`
    /// (ADR 0025) — the rail the SM Session leaves as `None`. `None` if no walk is
    /// in progress. The text is a location (a path), never a Value.
    async fn provide_input(&mut self, text: String) -> Option<Step> {
        let step = self.discovery.as_mut()?.provide_input(text).await;
        self.pull_discovery_advisory();
        self.reset_if_reauth(&step);
        Some(step)
    }

    /// Drain the queued session-logging advisories (ADR 0025). The worker surfaces
    /// each to the Diagnostic Log + Discovery wizard once.
    async fn take_advisories(&mut self) -> Vec<String> {
        std::mem::take(&mut self.advisories)
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
    use janitor_aws_auth::wire::fakes::{
        CredSpec, FakeAccountCatalog, FakeClock, FakeReauth, FakeRoleClient,
    };
    use janitor_aws_auth::wire::{AccountSummary, RawSecret, RoleSummary};
    use janitor_core::compare::{EntryState, RowKey};
    use janitor_core::config::{Application, Mapping};
    use janitor_core::provider::FetchFailReason;
    use janitor_core::secret::EntryName;
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
    fn dotenv(text: &str) -> Result<RawSecret, SessionError> {
        Ok(RawSecret {
            secret_string: Some(text.into()),
            secret_binary: None,
        })
    }

    /// A provider whose front-half + tail fakes are seeded for `load` (no
    /// discovery): an empty account catalog suffices when the walk is untouched.
    fn provider(
        reauth: Arc<FakeReauth>,
        role: Arc<FakeRoleClient>,
        reader: Arc<FakeRemoteFileReader>,
    ) -> SsmProvider {
        SsmProvider::new(
            reauth,
            role,
            Arc::new(FakeAccountCatalog::new(vec![], vec![])),
            Arc::new(FakeInstanceCatalog::new(vec![])),
            reader,
            Arc::new(FakeLoggingPreference::off()),
            Arc::new(FakeClock::at(0)),
        )
    }

    #[tokio::test]
    async fn sign_in_is_idempotent_one_browser() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let reader = Arc::new(FakeRemoteFileReader::new(vec![]));
        let mut p = provider(reauth.clone(), role, reader);
        assert!(!p.is_signed_in());
        p.sign_in().await.unwrap();
        p.sign_in().await.unwrap();
        assert!(p.is_signed_in());
        assert_eq!(reauth.count(), 1, "second sign_in must be a no-op");
    }

    #[tokio::test]
    async fn load_all_envs_succeed_returns_masked_view_and_caches() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        // prod has A,B; staging has only A → B is a Gap.
        let reader = Arc::new(FakeRemoteFileReader::new(vec![
            dotenv("A=1\nB=x"),
            dotenv("A=1"),
        ]));
        let mut p = provider(reauth, role, reader);
        let app = Application {
            name: "app".into(),
            environments: vec![
                mapping("prod", "i-prod:/app/.env"),
                mapping("staging", "i-stg:/app/.env"),
            ],
        };
        let loaded = p.load(&app).await.unwrap();
        assert!(
            loaded.corrected.is_empty(),
            "this Provider never auto-corrects"
        );
        let view = loaded.view;
        assert_eq!(view.environments, vec!["prod", "staging"]);
        let b = view.rows.iter().find(|r| r.name == "B").unwrap();
        assert_eq!(b.state, EntryState::Gap);
        let key = RowKey::Entry(EntryName::from_path(&["A".to_string()]));
        assert_eq!(
            p.reveal(&key, 0),
            Some("1".to_string()),
            "reveal serves plaintext from the worker-resident cache"
        );
    }

    #[tokio::test]
    async fn load_one_env_fails_is_whole_app_error_naming_it_with_masked_detail() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let reader = Arc::new(FakeRemoteFileReader::new(vec![
            dotenv("A=1"),
            Err(SessionError::AccessDenied),
        ]));
        let mut p = provider(reauth, role, reader);
        let app = Application {
            name: "app".into(),
            environments: vec![
                mapping("prod", "i-prod:/app/.env"),
                mapping("staging", "i-stg:/app/.env"),
            ],
        };
        let err = p.load(&app).await.unwrap_err();
        assert_eq!(err.failures.len(), 1);
        assert_eq!(err.failures[0].environment, "staging");
        assert_eq!(err.failures[0].reason, FetchFailReason::AccessDenied);
        // `detail` is the masked `SessionError`'s already-scrubbed `Display`
        // (ADR 0017) — a fixed error-safe phrase carrying no raw SSM/SDK text or
        // secret material. (The producer's Sdk-context scrubbing contract is
        // proven in janitor-aws-auth; this layer never adds raw protocol text.)
        assert_eq!(err.failures[0].detail, "access denied for this Mapping");
    }

    #[tokio::test]
    async fn load_malformed_env_is_whole_app_error_with_no_line_content() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let reader = Arc::new(FakeRemoteFileReader::new(vec![dotenv(
            "A=1\nNAUGHTY_secret_line",
        )]));
        let mut p = provider(reauth, role, reader);
        let app = Application {
            name: "app".into(),
            environments: vec![mapping("prod", "i-prod:/app/.env")],
        };
        let err = p.load(&app).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::Unsupported);
        assert!(
            !err.failures[0].detail.contains("NAUGHTY_secret_line"),
            "no .env line content leaks into the detail"
        );
    }

    #[tokio::test]
    async fn load_maps_signin_failure_to_needs_sign_in() {
        let reauth = Arc::new(FakeReauth::failing());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let reader = Arc::new(FakeRemoteFileReader::new(vec![]));
        let mut p = provider(reauth, role, reader);
        let app = Application {
            name: "a".into(),
            environments: vec![mapping("prod", "i-prod:/app/.env")],
        };
        let err = p.load(&app).await.unwrap_err();
        assert_eq!(err.failures[0].reason, FetchFailReason::NeedsSignIn);
    }

    #[tokio::test]
    async fn reveal_is_none_before_load() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let reader = Arc::new(FakeRemoteFileReader::new(vec![]));
        let p = provider(reauth, role, reader);
        let key = RowKey::Entry(EntryName::from_path(&["A".to_string()]));
        assert!(p.reveal(&key, 0).is_none(), "nothing cached yet");
    }

    /// A provider seeded for a full single-instance discovery walk.
    fn discovering_provider(
        reauth: Arc<FakeReauth>,
        reads: Vec<Result<RawSecret, SessionError>>,
    ) -> SsmProvider {
        SsmProvider::new(
            reauth,
            Arc::new(FakeRoleClient::new(vec![cred_ok()])),
            Arc::new(FakeAccountCatalog::new(
                vec![Ok(vec![AccountSummary {
                    id: "111".into(),
                    name: "Prod".into(),
                }])],
                vec![Ok(vec![RoleSummary {
                    name: "ReadOnly".into(),
                }])],
            )),
            Arc::new(FakeInstanceCatalog::new(vec![Ok(vec![InstanceSummary {
                id: "i-0abc".into(),
                name: "web".into(),
            }])])),
            Arc::new(FakeRemoteFileReader::new(reads)),
            Arc::new(FakeLoggingPreference::off()),
            Arc::new(FakeClock::at(0)),
        )
    }

    #[tokio::test]
    async fn begin_discovery_signs_in_then_poses_the_path_input() {
        let reauth = Arc::new(FakeReauth::ok());
        let mut p = discovering_provider(reauth.clone(), vec![dotenv("A=1")]);
        let step = p
            .begin_discovery("prod".into(), "us-west-2".into(), None)
            .await
            .unwrap();
        let Step::Input { what, .. } = step else {
            panic!("expected the path Input, got {step:?}");
        };
        assert_eq!(what, janitor_core::provider::What::FilePath);
        assert_eq!(reauth.count(), 1, "discovery signs in exactly once");
        assert!(p.is_signed_in());
    }

    #[tokio::test]
    async fn provide_input_completes_the_walk_with_the_typed_path() {
        let reauth = Arc::new(FakeReauth::ok());
        let mut p = discovering_provider(reauth, vec![dotenv("A=1")]);
        assert!(matches!(
            p.begin_discovery("prod".into(), "us-east-1".into(), None)
                .await
                .unwrap(),
            Step::Input { .. }
        ));
        let Some(Step::Done(m)) = p.provide_input("/srv/.env".into()).await else {
            panic!("expected Done from provide_input");
        };
        assert_eq!(m.secret_id, "i-0abc:/srv/.env");
        assert_eq!(m.environment, "prod");
    }

    #[tokio::test]
    async fn discovery_reuses_the_load_token_without_a_second_sign_in() {
        // Signing in (via load) then discovering must NOT open a second browser:
        // both share the session's one Arc<SsoToken>.
        let reauth = Arc::new(FakeReauth::ok());
        let mut p = SsmProvider::new(
            reauth.clone(),
            Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()])),
            Arc::new(FakeAccountCatalog::new(
                vec![Ok(vec![AccountSummary {
                    id: "111".into(),
                    name: "Prod".into(),
                }])],
                vec![Ok(vec![RoleSummary {
                    name: "ReadOnly".into(),
                }])],
            )),
            Arc::new(FakeInstanceCatalog::new(vec![Ok(vec![InstanceSummary {
                id: "i-0abc".into(),
                name: "web".into(),
            }])])),
            // one read for load, one for the discovery validation.
            Arc::new(FakeRemoteFileReader::new(vec![
                dotenv("A=1"),
                dotenv("A=1"),
            ])),
            Arc::new(FakeLoggingPreference::off()),
            Arc::new(FakeClock::at(0)),
        );
        let app = Application {
            name: "app".into(),
            environments: vec![mapping("prod", "i-0abc:/app/.env")],
        };
        p.load(&app).await.unwrap();
        assert!(matches!(
            p.begin_discovery("staging".into(), "us-east-1".into(), None)
                .await
                .unwrap(),
            Step::Input { .. }
        ));
        assert_eq!(reauth.count(), 1, "load + discovery share one Sign-in");
    }

    #[tokio::test]
    async fn discovery_reauth_clears_sign_in_so_next_sign_in_reauthenticates() {
        // A dead token surfaced mid-walk (here at the file read) clears the session
        // so the GUI's "Sign in again" re-opens the browser (ADR 0013 routing).
        let reauth = Arc::new(FakeReauth::ok());
        let mut p = discovering_provider(reauth.clone(), vec![Err(SessionError::ReauthRequired)]);
        assert!(matches!(
            p.begin_discovery("prod".into(), "us-east-1".into(), None)
                .await
                .unwrap(),
            Step::Input { .. }
        ));
        let step = p.provide_input("/app/.env".into()).await;
        assert!(matches!(step, Some(Step::Reauth)));
        assert!(!p.is_signed_in(), "a dead-token read clears the session");

        p.sign_in().await.unwrap();
        assert_eq!(
            reauth.count(),
            2,
            "re-sign-in against a fresh token, not a no-op"
        );
    }

    #[tokio::test]
    async fn advance_and_provide_input_are_none_without_a_walk() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let reader = Arc::new(FakeRemoteFileReader::new(vec![]));
        let mut p = provider(reauth, role, reader);
        assert!(p.advance_discovery(0).await.is_none());
        assert!(
            p.provide_input("/app/.env".into()).await.is_none(),
            "no walk in progress → no input to feed"
        );
    }

    #[tokio::test]
    async fn load_surfaces_a_session_logging_advisory_once_then_dedupes() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let reader = Arc::new(FakeRemoteFileReader::new(vec![
            dotenv("A=1"),
            dotenv("A=1"),
        ]));
        let logging_on = || {
            Ok(LoggingState {
                cloudwatch: true,
                ..Default::default()
            })
        };
        let mut p = SsmProvider::new(
            reauth,
            role,
            Arc::new(FakeAccountCatalog::new(vec![], vec![])),
            Arc::new(FakeInstanceCatalog::new(vec![])),
            reader,
            Arc::new(FakeLoggingPreference::new(vec![logging_on(), logging_on()])),
            Arc::new(FakeClock::at(0)),
        );
        let app = Application {
            name: "app".into(),
            environments: vec![mapping("prod", "i-prod:/app/.env")],
        };
        p.load(&app).await.unwrap();
        let adv = p.take_advisories().await;
        assert_eq!(adv.len(), 1, "logging-on surfaces one advisory");
        assert!(
            adv[0].contains("CloudWatch"),
            "the advisory names the destination"
        );
        assert!(p.take_advisories().await.is_empty(), "advisories drained");
        // A second load re-probes, but the identical advisory is deduped.
        p.load(&app).await.unwrap();
        assert!(
            p.take_advisories().await.is_empty(),
            "the same advisory is not surfaced twice"
        );
    }

    #[tokio::test]
    async fn no_advisory_when_logging_is_off() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let reader = Arc::new(FakeRemoteFileReader::new(vec![dotenv("A=1")]));
        let mut p = provider(reauth, role, reader); // provider() injects logging-off
        let app = Application {
            name: "app".into(),
            environments: vec![mapping("prod", "i-prod:/app/.env")],
        };
        p.load(&app).await.unwrap();
        assert!(
            p.take_advisories().await.is_empty(),
            "logging off → no advisory"
        );
    }
}
