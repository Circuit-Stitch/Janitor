//! The GUI's async bridge (ADR 0019): a worker thread owns a Tokio current-thread
//! runtime and drives a `&mut dyn Provider` (built by [`build_provider`] from the
//! chosen [`ProviderKind`]) — one async path for AWS and the offline mock alike.
//! The UI sends `Command`s; the worker runs the async Provider calls and posts
//! `Event`s back onto the Slint event loop. This is untested I/O shell
//! (ADR 0010 §5); all real logic lives in the `Provider` impls.

use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

use janitor_aws::aws_impl::AwsSecretsApi;
use janitor_aws::session::Session;
use janitor_aws_auth::authenticator::Authenticator;
use janitor_aws_auth::aws_impl::{AwsOidcClient, AwsRoleClient};
use janitor_aws_auth::error::SessionError;
use janitor_aws_auth::types::{Credential, SystemClock};
use janitor_aws_auth::wire::RawSecret;
use janitor_core::compare::RowKey;
use janitor_core::config::{Application, Config, Mapping};
use janitor_core::provider::{AppError, Provider, Step, What};
use janitor_core::view::MatrixView;
use janitor_ssm::wire::{InstanceCatalog, InstanceSummary, RemoteFileReader};
use janitor_ssm::SsmProvider;

/// UI → worker.
pub enum Command {
    SignIn,
    LoadApp(Application),
    Reveal {
        row: usize,
        col: usize,
        key: RowKey,
    },
    /// Fetch a Value cell's plaintext for the clipboard (#59 tracks auto-clear).
    /// Same fetch as Reveal, but the reply is routed to the OS clipboard, not the
    /// view. `row`/`col` let the UI thread name it ("NAME[env]") without the worker
    /// handling any non-secret labels.
    CopyValue {
        row: usize,
        col: usize,
        key: RowKey,
    },
    /// Start a guided `Discovery` walk for one new Environment (ADR 0013). The
    /// resolved browse region + remembered last-pick come from `Config`.
    BeginDiscovery {
        environment: String,
        region: String,
        remembered: Option<Mapping>,
    },
    /// Feed the user's chosen index back into the in-progress walk (sent by the
    /// Manage window's picker when the user selects a row).
    AdvanceDiscovery {
        choice: usize,
    },
    /// Feed the user's typed text back into a walk paused on a `Step::Input`
    /// (ADR 0025) — the free-text counterpart of `AdvanceDiscovery`, sent by the
    /// Manage window's text field. The text is a location (a path), never a Value.
    ProvideInput(String),
    Shutdown,
}

/// Worker → UI. Rendered by `apply_event` on the UI thread.
pub enum Event {
    SignInStarted,
    SignedIn,
    SignInFailed(String),
    AppLoading,
    /// A load succeeded. `corrected` carries any Mappings whose `permission_set`
    /// was auto-corrected this load (ADR 0018 stale-role recovery) — empty on the
    /// common path; the GUI persists them to Config. `app_name` guards the fold
    /// against a mid-load sidebar switch (only apply to the app it was loaded for).
    AppLoaded {
        view: MatrixView,
        corrected: Vec<Mapping>,
        app_name: String,
    },
    AppFailed(AppError),
    Revealed {
        row: usize,
        col: usize,
        text: String,
    },
    RevealUnavailable,
    /// A Value fetched for the clipboard. The UI thread sets the OS clipboard and
    /// logs "NAME[env] copied to clipboard" — never `text` (THREAT-MODEL / ADR 0017).
    CopyValue {
        row: usize,
        col: usize,
        text: String,
    },
    CopyUnavailable,
    /// A guided walk reached `Done`: this Mapping is ready to append to the
    /// Application the Manage window is bound to (THREAT-MODEL: locations only).
    EnvDiscovered(Mapping),
    /// A walk hit a `many` choice: render `labels` (presenter lines — account
    /// `name (id)`, role, secret name; never secret Values) as a selectable list
    /// for `what`, with `default` pre-selected. The pick returns via
    /// `Command::AdvanceDiscovery`.
    DiscoveryChoice {
        what: What,
        labels: Vec<String>,
        default: Option<usize>,
    },
    /// A walk hit a free-text `Step::Input` (ADR 0025): render `prompt` as a text
    /// field pre-filled with `default` (a remembered path — **not** an index, as
    /// `DiscoveryChoice`'s `Option<usize>` is). The typed text returns via
    /// `Command::ProvideInput`. `prompt`/`default` are locations, never Values.
    DiscoveryInput {
        what: What,
        prompt: String,
        default: Option<String>,
    },
    /// A walk could not complete (no choices, session error). Masked text only.
    DiscoveryFailed(String),
    /// A walk hit a dead SSO token (`Step::Reauth`). The GUI routes back to the
    /// Sign-in state rather than offering Back/Close (ADR 0013); no SDK text.
    DiscoveryReauthRequired,
}

/// Which [`Provider`] the GUI runs against. The composition root (`main`) picks
/// this from `JANITOR_MOCK`/`--mock` — its one mock-vs-real decision (ADR 0019).
/// A future Provider adds one arm here and in [`build_provider`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Aws,
    /// The remote-`.env`-over-SSM Provider (ADR 0025). Constructs the real
    /// front-half shell; its SSM tail (instance discovery + file read) is the
    /// B4-deferred transport, so until then the tail seams refuse. The offline
    /// end-to-end path is exercised by the worker tests against the fakes.
    ///
    /// `build_provider` already constructs it, but `main` does not *select* it
    /// yet (the user-facing selector lands in B4 with the real transport) — hence
    /// the allow: the arm is wired ahead of its composition-root entry point.
    #[allow(dead_code)]
    SsmDotenv,
    Mock,
}

/// Spawn the worker. `on_event` is invoked (on the UI thread, via the caller's
/// marshalling) for each emitted Event. Returns the command Sender.
///
/// `kind` selects the Provider; `config` supplies the org locations
/// (`sso_start_url` as the issuer URL, `sso_region` for the SDK clients). The
/// Provider is built once at startup inside the worker runtime; for AWS the
/// browser Sign-in is deferred to the first `SignIn`/`LoadApp` (lazy).
pub fn spawn(
    kind: ProviderKind,
    config: Config,
    on_event: impl Fn(Event) + Send + 'static,
) -> Sender<Command> {
    let (tx, rx) = std::sync::mpsc::channel::<Command>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build worker runtime");
        rt.block_on(async move {
            let mut provider = build_provider(kind, &config).await;
            run_loop(rx, provider.as_mut(), &on_event).await;
        });
    });
    tx
}

/// Build the chosen Provider **inside the worker runtime** (ADR 0019): AWS adapter
/// construction is async, so it must happen here; the mock builds trivially. The
/// boxed `dyn Provider` lets `run_loop` drive one async path for every Provider.
async fn build_provider(kind: ProviderKind, config: &Config) -> Box<dyn Provider> {
    match kind {
        ProviderKind::Aws => Box::new(build_session(config).await),
        ProviderKind::SsmDotenv => Box::new(build_ssm_session(config).await),
        ProviderKind::Mock => Box::new(janitor_mock::MockProvider::new()),
    }
}

/// Build the real adapters (no ambient credentials — ADR 0010 §10) and the
/// lazy `Session`. Mirrors `live-verify` steps 2 + facade assembly, minus
/// discovery.
async fn build_session(config: &Config) -> Session {
    let oidc = Arc::new(AwsOidcClient::new(config.sso_region.clone()).await);
    let role_client = Arc::new(AwsRoleClient::new(config.sso_region.clone()).await);
    let secrets_api = Arc::new(AwsSecretsApi::new());
    let clock = Arc::new(SystemClock);
    // `sso_start_url` holds the SSO start URL (AWS' term); passed as RegisterClient
    // `issuerUrl`. Must be the instance form (…/ssoins-…), not the portal …/start.
    let authenticator = Arc::new(Authenticator::new(oidc, config.sso_start_url.clone()));
    // `AwsRoleClient` implements both `RoleCredentialClient` and `AccountCatalog`,
    // so the same Arc serves credential minting and discovery enumeration.
    Session::new(
        authenticator,
        role_client.clone(),
        secrets_api,
        role_client,
        clock,
    )
}

/// Build the remote-`.env`-over-SSM Provider (ADR 0025). The front half is the
/// same real shell as `build_session` (browser Sign-in + the account/role
/// catalog + credential minting); the SSM tail — `DescribeInstanceInformation`
/// and the Session Manager file read — is the transport spiked and chosen in B4
/// (ADR 0025 §3), so until then it is the [`UnimplementedSsmTail`] placeholder
/// that refuses with a masked error. The Provider therefore signs in for real but
/// cannot list/read yet; the offline end-to-end walk is exercised by the worker
/// tests against the `janitor-ssm` fakes (#64).
async fn build_ssm_session(config: &Config) -> SsmProvider {
    let oidc = Arc::new(AwsOidcClient::new(config.sso_region.clone()).await);
    let role_client = Arc::new(AwsRoleClient::new(config.sso_region.clone()).await);
    let clock = Arc::new(SystemClock);
    let authenticator = Arc::new(Authenticator::new(oidc, config.sso_start_url.clone()));
    let tail = Arc::new(UnimplementedSsmTail);
    // `AwsRoleClient` implements both `RoleCredentialClient` and `AccountCatalog`;
    // the single `tail` Arc serves both SSM-tail seams.
    SsmProvider::new(
        authenticator,
        role_client.clone(),
        role_client,
        tail.clone(),
        tail,
        clock,
    )
}

/// B4 placeholder for the SSM tail seams (ADR 0025 §3): the real
/// `DescribeInstanceInformation` + Session Manager transport land in a later
/// slice. It refuses every call with a masked, error-safe [`SessionError`] (no
/// SDK text), so the SsmDotenv Provider is constructible and signs in but its
/// tail is inert until B4. Untested I/O-boundary shell (ADR 0010 §5).
struct UnimplementedSsmTail;

#[async_trait::async_trait]
impl InstanceCatalog for UnimplementedSsmTail {
    async fn describe_instances(
        &self,
        _cred: &Credential,
        _region: &str,
    ) -> Result<Vec<InstanceSummary>, SessionError> {
        Err(SessionError::Sdk {
            context: "SSM instance discovery not implemented (B4)".into(),
        })
    }
}

#[async_trait::async_trait]
impl RemoteFileReader for UnimplementedSsmTail {
    async fn read_file(
        &self,
        _cred: &Credential,
        _instance_id: &str,
        _region: &str,
        _path: &str,
    ) -> Result<RawSecret, SessionError> {
        Err(SessionError::Sdk {
            context: "SSM file read not implemented (B4)".into(),
        })
    }
}

/// Map a `Discovery` `Step` to the UI Event the worker relays. `Ask` carries the
/// presenter labels + remembered default straight through to the picker;
/// `Empty`/`Failed` carry only masked, tested phrases — never SDK text
/// (THREAT-MODEL).
fn discovery_event(step: Step) -> Event {
    match step {
        Step::Done(mapping) => Event::EnvDiscovered(mapping),
        Step::Ask {
            what,
            choices,
            default,
        } => Event::DiscoveryChoice {
            what,
            labels: choices,
            default,
        },
        Step::Input {
            what,
            prompt,
            default,
        } => Event::DiscoveryInput {
            what,
            prompt,
            default,
        },
        Step::Empty(what) => Event::DiscoveryFailed(
            match what {
                What::Accounts => "no accounts you can access",
                What::Roles => "no roles you can access",
                What::Secrets => "no secrets you can access",
                What::Instances => "no instances you can access",
                // An `Input` never produces `Empty`; present for exhaustiveness.
                What::FilePath => "no path available",
            }
            .to_string(),
        ),
        Step::Failed(reason) => Event::DiscoveryFailed(reason.describe().to_string()),
        Step::Reauth => Event::DiscoveryReauthRequired,
    }
}

async fn run_loop(
    rx: Receiver<Command>,
    provider: &mut dyn Provider,
    on_event: &(impl Fn(Event) + Send + 'static),
) {
    // `recv()` is blocking; that is fine on the worker's own thread.
    while let Ok(cmd) = rx.recv() {
        match cmd {
            Command::Shutdown => break,
            Command::SignIn => {
                tracing::info!(target: "janitor::gui", "Sign-in requested");
                on_event(Event::SignInStarted);
                match provider.sign_in().await {
                    Ok(()) => {
                        tracing::info!(target: "janitor::gui", "Signed in");
                        on_event(Event::SignedIn);
                    }
                    Err(e) => {
                        // SignInError Display is error-safe (static phrases /
                        // scrubbed Sdk label) — never secret material.
                        tracing::warn!(target: "janitor::gui", "Sign-in failed — {e}");
                        on_event(Event::SignInFailed(e.to_string()));
                    }
                }
            }
            Command::LoadApp(app) => {
                tracing::info!(target: "janitor::gui", app = %app.name, "Loading Application");
                on_event(Event::AppLoading);
                match provider.load(&app).await {
                    Ok(loaded) => {
                        tracing::info!(
                            target: "janitor::gui",
                            app = %app.name,
                            entries = loaded.view.rows.len(),
                            corrected = loaded.corrected.len(),
                            "Loaded Application"
                        );
                        on_event(Event::AppLoaded {
                            view: loaded.view,
                            corrected: loaded.corrected,
                            app_name: app.name.clone(),
                        });
                    }
                    Err(e) => {
                        for f in &e.failures {
                            tracing::warn!(
                                target: "janitor::gui",
                                app = %app.name,
                                env = %f.environment,
                                "Load failed — {}",
                                f.detail
                            );
                        }
                        on_event(Event::AppFailed(e));
                    }
                }
            }
            Command::Reveal { row, col, key } => match provider.reveal(&key, col) {
                Some(text) => on_event(Event::Revealed { row, col, text }),
                None => on_event(Event::RevealUnavailable),
            },
            Command::CopyValue { row, col, key } => match provider.reveal(&key, col) {
                Some(text) => on_event(Event::CopyValue { row, col, text }),
                None => on_event(Event::CopyUnavailable),
            },
            Command::BeginDiscovery {
                environment,
                region,
                remembered,
            } => match provider
                .begin_discovery(environment, region, remembered)
                .await
            {
                Ok(step) => on_event(discovery_event(step)),
                // A failed Sign-in is the only Err here; route back to Sign-in
                // (masked), same as a dead token mid-walk.
                Err(_) => on_event(Event::DiscoveryReauthRequired),
            },
            Command::AdvanceDiscovery { choice } => {
                if let Some(step) = provider.advance_discovery(choice).await {
                    on_event(discovery_event(step));
                }
            }
            Command::ProvideInput(text) => {
                if let Some(step) = provider.provide_input(text).await {
                    on_event(discovery_event(step));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn run_loop_drives_a_provider_signing_in_through_the_port() {
        // The single async path (ADR 0019): the worker drives `&mut dyn Provider`,
        // not a concrete Session. SignIn surfaces SignInStarted then SignedIn for
        // any Provider — here the offline MockProvider, whose sign_in is instant.
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Command::SignIn).unwrap();
        tx.send(Command::Shutdown).unwrap();

        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let mut provider = janitor_mock::MockProvider::new();
        run_loop(rx, &mut provider, &move |ev| sink.lock().unwrap().push(ev)).await;

        let events = events.lock().unwrap();
        assert!(
            matches!(events.as_slice(), [Event::SignInStarted, Event::SignedIn]),
            "SignIn must surface SignInStarted then SignedIn through the port"
        );
    }

    #[tokio::test]
    async fn run_loop_loads_an_application_into_a_projected_matrix() {
        use janitor_core::compare::EntryState;
        // LoadApp surfaces AppLoading then AppLoaded with the projected
        // Aligned/Drift/Gap matrix, driven entirely through the port.
        let payments = janitor_mock::seeded_config().applications[0].clone();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Command::LoadApp(payments)).unwrap();
        tx.send(Command::Shutdown).unwrap();

        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let mut provider = janitor_mock::MockProvider::new();
        run_loop(rx, &mut provider, &move |ev| sink.lock().unwrap().push(ev)).await;

        let events = events.lock().unwrap();
        let [Event::AppLoading, Event::AppLoaded {
            view,
            corrected,
            app_name,
        }] = events.as_slice()
        else {
            panic!("LoadApp must surface AppLoading then AppLoaded");
        };
        assert_eq!(app_name, "Payments API");
        assert!(corrected.is_empty(), "the mock never auto-corrects");
        assert_eq!(view.environments, vec!["prod", "staging"]);
        let state = |name: &str| view.rows.iter().find(|r| r.name == name).map(|r| r.state);
        assert_eq!(state("GITHUB_APP_ID"), Some(EntryState::Aligned));
        assert_eq!(state("STRIPE_API_KEY"), Some(EntryState::Drift));
        assert_eq!(state("database.replica.url"), Some(EntryState::Gap));
    }

    #[tokio::test]
    async fn run_loop_reveal_round_trips_plaintext_through_the_port() {
        use janitor_core::secret::EntryName;
        // The one explicit on-demand plaintext crossing (ADR 0003): after a load,
        // Reveal asks the Provider for the cached Value and relays it as Revealed.
        let payments = janitor_mock::seeded_config().applications[0].clone();
        let key = RowKey::Entry(EntryName::from_path(&["STRIPE_API_KEY".to_string()]));
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Command::LoadApp(payments)).unwrap();
        tx.send(Command::Reveal {
            row: 0,
            col: 0,
            key,
        })
        .unwrap();
        tx.send(Command::Shutdown).unwrap();

        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let mut provider = janitor_mock::MockProvider::new();
        run_loop(rx, &mut provider, &move |ev| sink.lock().unwrap().push(ev)).await;

        let revealed = events.lock().unwrap().iter().find_map(|e| match e {
            Event::Revealed { text, row, col } => Some((text.clone(), *row, *col)),
            _ => None,
        });
        assert_eq!(
            revealed,
            Some(("sk_live_prod_b80a0011".to_string(), 0, 0)),
            "reveal round-trips the cached plaintext for the present cell"
        );
    }

    #[tokio::test]
    async fn run_loop_copy_value_round_trips_plaintext_for_the_clipboard() {
        use janitor_core::secret::EntryName;
        // Copy fetches the same cached Value as Reveal, but relays it as CopyValue
        // (the UI thread sets the clipboard and logs the safe "NAME[env]" label —
        // never this plaintext). row/col ride through so the UI can name it.
        let payments = janitor_mock::seeded_config().applications[0].clone();
        let key = RowKey::Entry(EntryName::from_path(&["STRIPE_API_KEY".to_string()]));
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Command::LoadApp(payments)).unwrap();
        tx.send(Command::CopyValue {
            row: 0,
            col: 0,
            key,
        })
        .unwrap();
        tx.send(Command::Shutdown).unwrap();

        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let mut provider = janitor_mock::MockProvider::new();
        run_loop(rx, &mut provider, &move |ev| sink.lock().unwrap().push(ev)).await;

        let copied = events.lock().unwrap().iter().find_map(|e| match e {
            Event::CopyValue { text, row, col } => Some((text.clone(), *row, *col)),
            _ => None,
        });
        assert_eq!(
            copied,
            Some(("sk_live_prod_b80a0011".to_string(), 0, 0)),
            "copy round-trips the cached plaintext for the clipboard"
        );
    }

    #[tokio::test]
    async fn build_provider_mock_arm_yields_a_usable_provider() {
        // The composition root's one decision is `kind`; build_provider wires the
        // chosen adapter inside the worker runtime. The Mock arm builds trivially
        // and signs in instantly — what lets main auto-send SignIn at startup so
        // the offline demo "opens already signed in" (ADR 0019). The Aws arm builds
        // real SDK clients and is untested I/O shell (ADR 0010 §5).
        let config = janitor_mock::seeded_config();
        let mut provider = build_provider(ProviderKind::Mock, &config).await;
        assert!(provider.sign_in().await.is_ok());
    }

    #[test]
    fn ask_step_becomes_discovery_choice_preserving_what_labels_and_default() {
        let step = Step::Ask {
            what: What::Accounts,
            choices: vec!["Prod (111)".into(), "Staging (222)".into()],
            default: Some(1),
        };
        let Event::DiscoveryChoice {
            what,
            labels,
            default,
        } = discovery_event(step)
        else {
            panic!("Ask must surface as DiscoveryChoice");
        };
        assert_eq!(what, What::Accounts);
        assert_eq!(labels, vec!["Prod (111)", "Staging (222)"]);
        assert_eq!(default, Some(1));
    }

    #[test]
    fn empty_step_is_masked_failure_not_a_choice() {
        let Event::DiscoveryFailed(msg) = discovery_event(Step::Empty(What::Secrets)) else {
            panic!("Empty must surface as a masked DiscoveryFailed");
        };
        assert_eq!(msg, "no secrets you can access");
    }

    #[test]
    fn reauth_step_is_its_own_event_not_a_failed_message() {
        // A dead token routes back to Sign-in via a distinct event — not the
        // Back/Close DiscoveryFailed path.
        assert!(
            matches!(
                discovery_event(Step::Reauth),
                Event::DiscoveryReauthRequired
            ),
            "Reauth must surface as DiscoveryReauthRequired"
        );
    }

    #[test]
    fn input_step_becomes_discovery_input_preserving_what_prompt_and_default() {
        // The free-text counterpart of the `Ask -> DiscoveryChoice` mapping: an
        // `Input` carries its prompt and a remembered *path* default (a String,
        // not an index) straight through to the text-field event (#62 / ADR 0025).
        let step = Step::Input {
            what: What::FilePath,
            prompt: "Path to the .env".into(),
            default: Some("/app/.env".into()),
        };
        let Event::DiscoveryInput {
            what,
            prompt,
            default,
        } = discovery_event(step)
        else {
            panic!("Input must surface as DiscoveryInput");
        };
        assert_eq!(what, What::FilePath);
        assert_eq!(prompt, "Path to the .env");
        assert_eq!(default.as_deref(), Some("/app/.env"));
    }

    #[test]
    fn worker_dtos_are_send() {
        // The worker marshals Commands and Events across the thread boundary, so
        // the new free-text Input DTOs (and their peers) must be Send (#62).
        fn assert_send<T: Send>() {}
        assert_send::<Command>();
        assert_send::<Event>();
    }

    /// A fake `Provider` whose walk poses a free-text `Step::Input` — neither the
    /// Secrets Manager `Session` nor the `MockProvider` ever does, so this is how
    /// the worker's Input relay is exercised offline (#62 / ADR 0025).
    /// `begin_discovery` poses the path Input; `provide_input` completes the walk
    /// with the typed path carried in the Mapping's `secret_id`.
    struct InputWalkProvider;

    #[async_trait::async_trait]
    impl Provider for InputWalkProvider {
        async fn sign_in(&mut self) -> Result<(), janitor_core::provider::SignInFailed> {
            Ok(())
        }
        async fn load(
            &mut self,
            _app: &Application,
        ) -> Result<janitor_core::provider::Loaded, AppError> {
            unreachable!("this fake only drives discovery")
        }
        fn reveal(&self, _key: &RowKey, _col: usize) -> Option<String> {
            None
        }
        async fn begin_discovery(
            &mut self,
            environment: String,
            _region: String,
            _remembered: Option<Mapping>,
        ) -> Result<Step, janitor_core::provider::SignInFailed> {
            Ok(Step::Input {
                what: What::FilePath,
                prompt: format!("Path to {environment} .env"),
                default: Some("/app/.env".into()),
            })
        }
        async fn advance_discovery(&mut self, _choice: usize) -> Option<Step> {
            None
        }
        async fn provide_input(&mut self, text: String) -> Option<Step> {
            Some(Step::Done(Mapping {
                environment: "prod".into(),
                account_id: "111111111111".into(),
                region: "us-east-1".into(),
                secret_id: format!("i-0abc:{text}"),
                permission_set: "ReadOnly".into(),
            }))
        }
    }

    #[tokio::test]
    async fn run_loop_input_step_round_trips_typed_text_through_the_port() {
        // The free-text Discovery rail end to end: BeginDiscovery surfaces a
        // DiscoveryInput question; the typed path returns via ProvideInput and the
        // walk completes as EnvDiscovered, carrying the path in the Mapping.
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Command::BeginDiscovery {
            environment: "prod".into(),
            region: "us-east-1".into(),
            remembered: None,
        })
        .unwrap();
        tx.send(Command::ProvideInput("/srv/app/.env".into()))
            .unwrap();
        tx.send(Command::Shutdown).unwrap();

        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let mut provider = InputWalkProvider;
        run_loop(rx, &mut provider, &move |ev| sink.lock().unwrap().push(ev)).await;

        let events = events.lock().unwrap();
        let [Event::DiscoveryInput {
            what,
            prompt,
            default,
        }, Event::EnvDiscovered(mapping)] = events.as_slice()
        else {
            panic!("expected DiscoveryInput then EnvDiscovered");
        };
        assert_eq!(*what, What::FilePath);
        assert_eq!(prompt, "Path to prod .env");
        assert_eq!(default.as_deref(), Some("/app/.env"));
        assert_eq!(
            mapping.secret_id, "i-0abc:/srv/app/.env",
            "the typed path round-tripped into the discovered Mapping"
        );
        assert_eq!(mapping.environment, "prod");
    }

    /// Build a fully-faked `SsmProvider` for the offline end-to-end worker test
    /// (#64 / ADR 0025): the SSM-tail doubles plus the reused front-half doubles,
    /// all from each crate's `test-support` feature (never a normal build). Seeds a
    /// single account/role/instance (so the walk auto-collapses straight to the
    /// path `Input`) and the scripted reads the discovery validation + the two-env
    /// load consume in order.
    fn faked_ssm_provider() -> janitor_ssm::SsmProvider {
        use janitor_aws_auth::wire::fakes::{
            CredSpec, FakeAccountCatalog, FakeClock, FakeReauth, FakeRoleClient,
        };
        use janitor_aws_auth::wire::{AccountSummary, RawSecret, RoleSummary};
        use janitor_ssm::wire::fakes::{FakeInstanceCatalog, FakeRemoteFileReader};
        use janitor_ssm::wire::InstanceSummary;
        use std::time::Duration;

        let cred = || {
            Ok(CredSpec {
                expires_in: Duration::from_secs(3600),
                tag: "t",
            })
        };
        let dotenv = |t: &str| {
            Ok(RawSecret {
                secret_string: Some(t.to_string()),
                secret_binary: None,
            })
        };
        janitor_ssm::SsmProvider::new(
            Arc::new(FakeReauth::ok()),
            // discovery mint + one load mint (the broker caches the second env).
            Arc::new(FakeRoleClient::new(vec![cred(), cred()])),
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
            // reads, in order: discovery validation, then load prod + staging.
            Arc::new(FakeRemoteFileReader::new(vec![
                dotenv("A=1"),
                dotenv("A=1\nB=x"),
                dotenv("A=1"),
            ])),
            Arc::new(FakeClock::at(0)),
        )
    }

    #[tokio::test]
    async fn run_loop_drives_the_ssm_provider_offline_through_discovery_into_a_masked_matrix() {
        use janitor_core::compare::EntryState;
        // The whole remote-`.env` Provider end to end, offline against the fakes,
        // through the same worker `Command`/`Event` loop the real GUI uses (#64):
        // Sign-in → the free-text path Input → an EnvDiscovered Mapping carrying
        // `<instance>:<path>` → a whole-Application load into a masked Aligned/Gap
        // matrix — with no AWS or remote-Instance access.
        let mut provider = faked_ssm_provider();

        // The discovered "prod" Mapping (i-0abc, /app/.env) plus a hand-built
        // "staging" on another instance — the load fans out over both.
        let app = Application {
            name: "app".into(),
            environments: vec![
                Mapping {
                    environment: "prod".into(),
                    account_id: "111".into(),
                    region: "us-east-1".into(),
                    secret_id: "i-0abc:/app/.env".into(),
                    permission_set: "ReadOnly".into(),
                },
                Mapping {
                    environment: "staging".into(),
                    account_id: "111".into(),
                    region: "us-east-1".into(),
                    secret_id: "i-stg:/app/.env".into(),
                    permission_set: "ReadOnly".into(),
                },
            ],
        };

        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Command::SignIn).unwrap();
        tx.send(Command::BeginDiscovery {
            environment: "prod".into(),
            region: "us-east-1".into(),
            remembered: None,
        })
        .unwrap();
        tx.send(Command::ProvideInput("/app/.env".into())).unwrap();
        tx.send(Command::LoadApp(app)).unwrap();
        tx.send(Command::Shutdown).unwrap();

        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        run_loop(rx, &mut provider, &move |ev| sink.lock().unwrap().push(ev)).await;
        let events = events.lock().unwrap();

        // Signed in offline (instant), no browser.
        assert!(
            events.iter().any(|e| matches!(e, Event::SignedIn)),
            "the SSM Provider signs in through the port"
        );
        // The walk auto-collapsed the single account/role/instance straight to the
        // free-text path question.
        assert!(
            events.iter().any(|e| matches!(
                e,
                Event::DiscoveryInput {
                    what: What::FilePath,
                    ..
                }
            )),
            "the walk poses the free-text .env path Input"
        );
        // The typed path round-tripped into a discovered Mapping at <instance>:<path>.
        let discovered = events.iter().find_map(|e| match e {
            Event::EnvDiscovered(m) => Some(m.clone()),
            _ => None,
        });
        assert_eq!(
            discovered.map(|m| m.secret_id),
            Some("i-0abc:/app/.env".to_string()),
            "discovery yields the <instance-id>:<path> location"
        );
        // The whole-Application load projected a masked matrix: A aligned, B a Gap.
        let view = events.iter().find_map(|e| match e {
            Event::AppLoaded { view, .. } => Some(view.clone()),
            _ => None,
        });
        let view = view.expect("the load surfaced AppLoaded");
        assert_eq!(view.environments, vec!["prod", "staging"]);
        let state = |name: &str| view.rows.iter().find(|r| r.name == name).map(|r| r.state);
        assert_eq!(state("A"), Some(EntryState::Aligned));
        assert_eq!(state("B"), Some(EntryState::Gap), "B present only in prod");
    }
}
