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
            SessionError::NotFound => FetchFailReason::NotFound,
            SessionError::Throttled => FetchFailReason::Throttled,
            SessionError::Unsupported => FetchFailReason::Unsupported,
            SessionError::Sdk { .. } => FetchFailReason::Other,
        }
    }
}

/// A whole-Application load failure: at least one Environment failed, so no
/// matrix is shown (spec Decision 8 — never a partial matrix, never a fake Gap).
/// Each entry is `(environment_name, reason)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppError {
    pub failures: Vec<(String, FetchFailReason)>,
}

impl AppError {
    /// The synthetic "you must sign in first" error (no real Environment failed).
    pub fn needs_sign_in() -> Self {
        AppError {
            failures: vec![("(sign-in)".to_string(), FetchFailReason::NeedsSignIn)],
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
use crate::source::{AuthenticatedSource, Reauth};
use crate::types::{Clock, SsoToken};
use crate::wire::{AccountCatalog, RoleCredentialClient, SecretsApi};

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
        Ok(step)
    }

    /// Feed the user's chosen index into the in-progress `Discovery`. `None` if
    /// no walk is in progress (a presenter bug — there is nothing to advance).
    pub async fn advance_discovery(&mut self, choice: usize) -> Option<Step> {
        let discovery = self.discovery.as_mut()?;
        Some(discovery.advance(choice).await)
    }

    /// Load one Application: ensure signed in, fetch every Environment, and —
    /// if ANY Environment fails — return a whole-app error naming the failures
    /// (spec Decision 8). On full success, cache the Sets and return the masked
    /// view. The Sets (plaintext) never leave `self.cached`.
    pub async fn load(&mut self, app: &Application) -> Result<MatrixView, AppError> {
        self.sign_in()
            .await
            .map_err(|_| AppError::needs_sign_in())?;
        let facade = self.facade.as_mut().expect("facade exists after sign_in");

        let mut sets: Vec<(String, SecretShape)> = Vec::new();
        let mut failures: Vec<(String, FetchFailReason)> = Vec::new();
        for m in &app.environments {
            match facade.fetch(m).await {
                Ok(shape) => sets.push((m.environment.clone(), shape)),
                Err(e) => failures.push((m.environment.clone(), FetchFailReason::from(&e))),
            }
        }
        if !failures.is_empty() {
            return Err(AppError { failures });
        }
        let view = project(&Comparison::build(&sets));
        self.cached = sets;
        Ok(view)
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
        assert_eq!(e.failures[0].1, FetchFailReason::NeedsSignIn);
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
        let view = s.load(&app).await.unwrap();
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
        assert_eq!(err.failures[0].0, "staging");
        assert_eq!(err.failures[0].1, FetchFailReason::AccessDenied);
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
        assert_eq!(err.failures[0].1, FetchFailReason::NeedsSignIn);
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
    async fn advance_discovery_is_none_without_a_walk() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let mut s = session(reauth, role, api);
        assert!(s.advance_discovery(0).await.is_none());
    }
}
