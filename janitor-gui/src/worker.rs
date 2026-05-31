//! The GUI's async bridge: a worker thread owns a Tokio current-thread runtime
//! and the `janitor_aws::Session`. The UI sends `Command`s; the worker runs the
//! async Session calls and posts `Event`s back onto the Slint event loop. This
//! is untested I/O shell (ADR 0010 §5); all real logic lives in `Session`.

use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

use janitor_aws::authenticator::Authenticator;
use janitor_aws::aws_impl::{AwsOidcClient, AwsRoleClient, AwsSecretsApi};
use janitor_aws::discovery::{Step, What};
use janitor_aws::session::{AppError, Session};
use janitor_aws::types::SystemClock;
use janitor_core::compare::RowKey;
use janitor_core::config::{Application, Config, Mapping};
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
    AppLoaded(MatrixView),
    AppFailed(AppError),
    Revealed {
        row: usize,
        col: usize,
        text: String,
    },
    RevealUnavailable,
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
            Command::BeginDiscovery {
                environment,
                region,
                remembered,
            } => match session
                .begin_discovery(environment, region, remembered)
                .await
            {
                Ok(step) => on_event(discovery_event(step)),
                // A failed Sign-in is the only Err here; route back to Sign-in
                // (masked), same as a dead token mid-walk.
                Err(_) => on_event(Event::DiscoveryReauthRequired),
            },
            Command::AdvanceDiscovery { choice } => {
                if let Some(step) = session.advance_discovery(choice).await {
                    on_event(discovery_event(step));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
