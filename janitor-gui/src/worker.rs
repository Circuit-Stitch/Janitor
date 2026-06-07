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
use janitor_aws_auth::types::SystemClock;
use janitor_core::compare::RowKey;
use janitor_core::config::{Application, Config, Mapping};
use janitor_core::provider::{AppError, Provider, Step, What};
use janitor_core::view::MatrixView;

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
        Step::Empty(what) => Event::DiscoveryFailed(
            match what {
                What::Accounts => "no accounts you can access",
                What::Roles => "no roles you can access",
                What::Secrets => "no secrets you can access",
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
}
