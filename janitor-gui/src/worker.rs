//! The GUI's async bridge: a worker thread owns a Tokio current-thread runtime
//! and the `janitor_aws::Session`. The UI sends `Command`s; the worker runs the
//! async Session calls and posts `Event`s back onto the Slint event loop. This
//! is untested I/O shell (ADR 0010 §5); all real logic lives in `Session`.

use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

use janitor_aws::authenticator::Authenticator;
use janitor_aws::aws_impl::{AwsOidcClient, AwsRoleClient, AwsSecretsApi};
use janitor_aws::session::{AppError, Session};
use janitor_aws::types::SystemClock;
use janitor_core::compare::RowKey;
use janitor_core::config::{Application, Config};
use janitor_core::view::MatrixView;

/// UI → worker.
pub enum Command {
    SignIn,
    LoadApp(Application),
    Reveal { row: usize, col: usize, key: RowKey },
    Shutdown,
}

/// Worker → UI. Rendered by `apply_event` on the UI thread.
pub enum Event {
    SignInStarted,
    SignedIn,
    SignInFailed(String),
    AppLoading,
    AppLoaded(MatrixView),
    AppFailed(AppError),
    Revealed {
        row: usize,
        col: usize,
        text: String,
    },
    RevealUnavailable,
}

/// Spawn the worker. `on_event` is invoked (on the UI thread, via the caller's
/// marshalling) for each emitted Event. Returns the command Sender.
///
/// `config` supplies the org locations (`sso_start_url` as the issuer URL,
/// `sso_region` for the SDK clients). Adapters are built once at startup; the
/// browser Sign-in is deferred to the first `SignIn`/`LoadApp` (lazy).
pub fn spawn(config: Config, on_event: impl Fn(Event) + Send + 'static) -> Sender<Command> {
    let (tx, rx) = std::sync::mpsc::channel::<Command>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build worker runtime");
        rt.block_on(async move {
            let mut session = build_session(&config).await;
            run_loop(rx, &mut session, &on_event).await;
        });
    });
    tx
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
    Session::new(authenticator, role_client, secrets_api, clock)
}

async fn run_loop(
    rx: Receiver<Command>,
    session: &mut Session,
    on_event: &(impl Fn(Event) + Send + 'static),
) {
    // `recv()` is blocking; that is fine on the worker's own thread.
    while let Ok(cmd) = rx.recv() {
        match cmd {
            Command::Shutdown => break,
            Command::SignIn => {
                on_event(Event::SignInStarted);
                match session.sign_in().await {
                    Ok(()) => on_event(Event::SignedIn),
                    Err(e) => on_event(Event::SignInFailed(e.to_string())),
                }
            }
            Command::LoadApp(app) => {
                on_event(Event::AppLoading);
                match session.load(&app).await {
                    Ok(view) => on_event(Event::AppLoaded(view)),
                    Err(e) => on_event(Event::AppFailed(e)),
                }
            }
            Command::Reveal { row, col, key } => match session.reveal(&key, col) {
                Some(text) => on_event(Event::Revealed { row, col, text }),
                None => on_event(Event::RevealUnavailable),
            },
        }
    }
}
