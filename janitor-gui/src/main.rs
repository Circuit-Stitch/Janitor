slint::include_modules!();
mod worker;

use std::cell::RefCell;
use std::env;
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::time::Duration;

use slint::{ModelRc, SharedString, VecModel};

use janitor_aws::session::AppError;
use janitor_core::compare::{Comparison, EntryState};
use janitor_core::config::{Application, Config, Mapping};
use janitor_core::mock::MockSource;
use janitor_core::secret::SecretShape;
use janitor_core::source::SecretSource;
use janitor_core::view::{
    project, reveal_value, sort_rows, MatrixCell, MatrixRow, MatrixView, SortKey,
};

use worker::{Command, Event};

/// Where matrix data comes from. Both arms feed the one `apply_event` path.
enum Backend {
    /// Real AWS via the worker thread.
    Real(Sender<Command>),
    /// Offline: MockSource, served synchronously on the UI thread. Holds the
    /// last-loaded Sets so reveal works without a worker.
    Mock {
        source: MockSource,
        cached: RefCell<Vec<(String, SecretShape)>>,
    },
}

// The UI-thread-owned shared state. The worker bridge cannot capture an `Rc`
// (its `upgrade_in_event_loop` closure is `Send + 'static`, and `Rc` is
// `!Send`), so the bridge reaches the state through this thread-local — which
// is only ever touched on the UI thread.
thread_local! {
    static STATE: RefCell<Option<Rc<RefCell<AppState>>>> = const { RefCell::new(None) };
}

/// A few seeded Applications. Payments is hand-seeded in MockSource; the others
/// fall back to deterministic fabrication, and some have >2 Environments to show
/// the matrix generalize.
fn seeded_config() -> Config {
    let app = |name: &str, base: &str, envs: &[(&str, &str, &str)]| Application {
        name: name.into(),
        environments: envs
            .iter()
            .map(|(env, account, region)| Mapping {
                environment: (*env).into(),
                account_id: (*account).into(),
                region: (*region).into(),
                secret_id: format!("{base}/{env}"),
                permission_set: "ReadOnly".into(),
            })
            .collect(),
    };
    Config {
        sso_start_url: "https://identitycenter.amazonaws.com/ssoins-mockmock0000".into(),
        sso_region: "us-east-1".into(),
        applications: vec![
            app(
                "Payments API",
                "payments",
                &[
                    ("prod", "914xxxxxx021", "us-east-1"),
                    ("staging", "550xxxxxx118", "us-west-2"),
                ],
            ),
            app(
                "Auth Service",
                "auth",
                &[
                    ("prod", "914xxxxxx021", "us-east-1"),
                    ("staging", "550xxxxxx118", "us-west-2"),
                    ("dev", "330xxxxxx777", "us-west-2"),
                ],
            ),
            app(
                "Billing Worker",
                "billing",
                &[
                    ("prod", "914xxxxxx021", "us-east-1"),
                    ("staging", "550xxxxxx118", "us-west-2"),
                ],
            ),
            app(
                "Notifications",
                "notif",
                &[
                    ("prod", "914xxxxxx021", "us-east-1"),
                    ("staging", "550xxxxxx118", "us-west-2"),
                    ("dev", "330xxxxxx777", "us-west-2"),
                    ("qa", "330xxxxxx777", "us-west-2"),
                ],
            ),
        ],
        // secret_region / last_pick (ADR 0011) default to ""/None — the mock GUI
        // seed needs neither. `..Default::default()` keeps this site from
        // breaking when locations-only Config fields are added.
        ..Default::default()
    }
}

/// Masked length-dots, capped so a long Value does not blow out the row.
fn dots(len: usize) -> String {
    "·".repeat(len.min(40))
}

/// The 2-env equality glyph; blank for N != 2.
fn glyph_for(row: &MatrixRow) -> &'static str {
    if row.cells.len() != 2 {
        return "";
    }
    match (&row.cells[0], &row.cells[1]) {
        (MatrixCell::Absent, _) | (_, MatrixCell::Absent) => "ø",
        (MatrixCell::Present { group: a, .. }, MatrixCell::Present { group: b, .. }) => {
            if a == b {
                "="
            } else {
                "≠"
            }
        }
    }
}

/// Map an owned `MatrixView` into Slint row models.
fn to_row_models(view: &MatrixView) -> ModelRc<RowView> {
    let rows: Vec<RowView> = view
        .rows
        .iter()
        .map(|r| {
            let cells: Vec<CellView> = r
                .cells
                .iter()
                .map(|c| match c {
                    MatrixCell::Present { len, hex, .. } => CellView {
                        absent: false,
                        dots: dots(*len).into(),
                        length: len.to_string().into(),
                        hex: hex.clone().into(),
                    },
                    MatrixCell::Absent => CellView {
                        absent: true,
                        dots: SharedString::new(),
                        length: SharedString::new(),
                        hex: SharedString::new(),
                    },
                })
                .collect();
            RowView {
                name: r.name.clone().into(),
                state: state_label(r.state).into(),
                glyph: glyph_for(r).into(),
                cells: ModelRc::from(Rc::new(VecModel::from(cells))),
            }
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(rows)))
}

fn state_label(state: EntryState) -> &'static str {
    match state {
        EntryState::Aligned => "Aligned",
        EntryState::Drift => "Drift",
        EntryState::Gap => "Gap",
    }
}

fn env_models(view: &MatrixView) -> ModelRc<SharedString> {
    let envs: Vec<SharedString> = view
        .environments
        .iter()
        .map(|e| e.as_str().into())
        .collect();
    ModelRc::from(Rc::new(VecModel::from(envs)))
}

struct Preferences {
    sort: SortKey,
    auto_hide_secs: u64,
    dark: bool,
}

struct AppState {
    backend: Backend,
    config: Config,
    selected: usize,
    prefs: Preferences,
    /// Current masked view (empty until an app loads).
    view: MatrixView,
    /// "unauth" | "signing" | "loading" | "loaded" | "error".
    status: String,
}

/// Send a command to whichever backend is active. Mock serves it inline by
/// invoking `apply_event` synchronously; real forwards to the worker (whose
/// replies arrive via `upgrade_in_event_loop`).
fn dispatch(ui: &MainWindow, state: &Rc<RefCell<AppState>>, cmd: Command) {
    let is_mock = matches!(state.borrow().backend, Backend::Mock { .. });
    if is_mock {
        match cmd {
            Command::SignIn => apply_event(ui, state, Event::SignedIn),
            Command::LoadApp(app) => {
                let view = {
                    let st = state.borrow();
                    let Backend::Mock { source, cached } = &st.backend else {
                        unreachable!()
                    };
                    let sets: Vec<(String, SecretShape)> = app
                        .environments
                        .iter()
                        .map(|m| {
                            (
                                m.environment.clone(),
                                source.fetch(m).expect("mock never fails"),
                            )
                        })
                        .collect();
                    let v = project(&Comparison::build(&sets));
                    *cached.borrow_mut() = sets;
                    v
                };
                apply_event(ui, state, Event::AppLoaded(view));
            }
            Command::Reveal { row, col, key } => {
                let revealed: Option<String> = {
                    let st = state.borrow();
                    let Backend::Mock { cached, .. } = &st.backend else {
                        unreachable!()
                    };
                    // Bind the `Ref` to a named local so it drops before `st`
                    // (named locals drop in reverse declaration order, ahead of
                    // the block's tail temporaries — fixes E0597).
                    let cache = cached.borrow();
                    reveal_value(&cache, &key, col).map(|v| v.expose().to_string())
                };
                let ev = match revealed {
                    Some(text) => Event::Revealed { row, col, text },
                    None => Event::RevealUnavailable,
                };
                apply_event(ui, state, ev);
            }
            Command::Shutdown => {}
        }
    } else if let Backend::Real(tx) = &state.borrow().backend {
        let _ = tx.send(cmd);
    }
}

/// Apply one Event to the UI + state. Called on the UI thread (directly for
/// mock; via `upgrade_in_event_loop` for the worker).
fn apply_event(ui: &MainWindow, state: &Rc<RefCell<AppState>>, ev: Event) {
    match ev {
        Event::SignInStarted => set_status(ui, state, "signing", ""),
        Event::SignedIn => {
            let app = {
                let st = state.borrow();
                st.config.applications.get(st.selected).cloned()
            };
            if let Some(app) = app {
                dispatch(ui, state, Command::LoadApp(app));
            } else {
                set_status(ui, state, "loaded", "");
            }
        }
        Event::SignInFailed(msg) => {
            set_status(ui, state, "error", &format!("Sign-in failed: {msg}"))
        }
        Event::AppLoading => set_status(ui, state, "loading", ""),
        Event::AppLoaded(mut view) => {
            let sort = state.borrow().prefs.sort;
            sort_rows(&mut view, sort);
            state.borrow_mut().view = view;
            set_status(ui, state, "loaded", "");
            push_matrix(ui, state);
        }
        Event::AppFailed(err) => set_status(ui, state, "error", &banner(&err)),
        Event::Revealed { row, col, text } => {
            ui.set_revealed_row(row as i32);
            ui.set_revealed_col(col as i32);
            ui.set_revealed_text(text.into());
            schedule_auto_hide(ui, state);
        }
        Event::RevealUnavailable => { /* leave masked */ }
    }
}

/// "<env>: <reason>; …" — no SDK text (reasons come from the tested describe()).
fn banner(err: &AppError) -> String {
    err.failures
        .iter()
        .map(|(env, r)| format!("{env}: {}", r.describe()))
        .collect::<Vec<_>>()
        .join("; ")
}

fn set_status(ui: &MainWindow, state: &Rc<RefCell<AppState>>, status: &str, msg: &str) {
    state.borrow_mut().status = status.to_string();
    ui.set_status(status.into());
    ui.set_status_message(msg.into());
}

/// Push the current view's rows/envs + sidebar into the UI.
fn push_matrix(ui: &MainWindow, state: &Rc<RefCell<AppState>>) {
    ui.set_revealed_row(-1);
    ui.set_revealed_col(-1);
    ui.set_revealed_text(SharedString::new());
    let st = state.borrow();
    ui.set_environments(env_models(&st.view));
    ui.set_rows(to_row_models(&st.view));
    ui.set_apps(app_models(&st.config, st.selected, &st.view, &st.status));
    ui.set_selected_envs(env_rows(&st.config, st.selected));
}

/// Sidebar items. Drift badge shows ONLY for the selected, loaded app — never a
/// per-app refetch (that would be a sign-in/GetSecretValue storm on real AWS).
fn app_models(
    config: &Config,
    selected: usize,
    view: &MatrixView,
    status: &str,
) -> ModelRc<AppItem> {
    let items: Vec<AppItem> = config
        .applications
        .iter()
        .enumerate()
        .map(|(i, app)| {
            let drift = if i == selected && status == "loaded" {
                let n = view
                    .rows
                    .iter()
                    .filter(|r| r.state == EntryState::Drift)
                    .count();
                if n > 0 {
                    format!("{n} drift").into()
                } else {
                    SharedString::new()
                }
            } else {
                SharedString::new()
            };
            AppItem {
                name: app.name.clone().into(),
                subtitle: format!("{} envs", app.environments.len()).into(),
                drift,
                selected: i == selected,
            }
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(items)))
}

/// Editor rows for the selected app's environments.
fn env_rows(config: &Config, selected: usize) -> ModelRc<EnvRow> {
    let rows: Vec<EnvRow> = config
        .applications
        .get(selected)
        .map(|app| {
            app.environments
                .iter()
                .map(|m| EnvRow {
                    environment: m.environment.clone().into(),
                    account_id: m.account_id.clone().into(),
                    region: m.region.clone().into(),
                    secret_id: m.secret_id.clone().into(),
                    permission_set: m.permission_set.clone().into(),
                })
                .collect()
        })
        .unwrap_or_default();
    ModelRc::from(Rc::new(VecModel::from(rows)))
}

fn schedule_auto_hide(ui: &MainWindow, state: &Rc<RefCell<AppState>>) {
    let secs = state.borrow().prefs.auto_hide_secs;
    let ui_weak = ui.as_weak();
    slint::Timer::single_shot(Duration::from_secs(secs), move || {
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_revealed_text(SharedString::new());
            ui.set_revealed_row(-1);
            ui.set_revealed_col(-1);
        }
    });
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;

    let mock = env::var("JANITOR_MOCK").is_ok() || env::args().any(|a| a == "--mock");
    let config = if mock {
        seeded_config()
    } else {
        Config::load().unwrap_or_default()
    };

    let state = Rc::new(RefCell::new(AppState {
        backend: Backend::Mock {
            source: MockSource::new(),
            cached: RefCell::new(Vec::new()),
        },
        config: config.clone(),
        selected: 0,
        prefs: Preferences {
            sort: SortKey::Name,
            auto_hide_secs: 5,
            dark: true,
        },
        view: MatrixView {
            environments: Vec::new(),
            rows: Vec::new(),
        },
        status: "unauth".to_string(),
    }));

    // Publish the state on the UI thread so the (Send) worker bridge can reach
    // it without capturing the `!Send` `Rc`.
    STATE.with(|s| *s.borrow_mut() = Some(state.clone()));

    // Real backend: spawn the worker, marshalling its Events onto the UI loop.
    if !mock {
        let ui_weak = ui.as_weak();
        let tx = worker::spawn(config.clone(), move |ev| {
            let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                let st = STATE.with(|s| s.borrow().clone());
                if let Some(st) = st {
                    apply_event(&ui, &st, ev);
                }
            });
        });
        state.borrow_mut().backend = Backend::Real(tx);
    }

    // Initial chrome.
    {
        let st = state.borrow();
        ui.set_sso_start_url(st.config.sso_start_url.as_str().into());
        ui.set_sso_region(st.config.sso_region.as_str().into());
        ui.set_dark(st.prefs.dark);
        ui.set_status(st.status.as_str().into());
    }
    push_matrix(&ui, &state);
    // Mock opens already "signed in" → load the first app immediately.
    if mock {
        // Bind first so the `state.borrow()` temporary DROPS before `dispatch`.
        // An `if let` scrutinee would hold the shared borrow across the whole
        // block, and the `AppLoaded` handler's `state.borrow_mut()` would then
        // panic ("already borrowed") — this matches the let-then-if-let pattern
        // the other dispatch call sites use.
        let first_app = state.borrow().config.applications.first().cloned();
        if let Some(app) = first_app {
            dispatch(&ui, &state, Command::LoadApp(app));
        }
    }

    // Sign in.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_sign_in(move || dispatch(&ui_weak.unwrap(), &state, Command::SignIn));
    }
    // Refresh (reload selected app).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_refresh(move || {
            let app = {
                let st = state.borrow();
                st.config.applications.get(st.selected).cloned()
            };
            if let Some(app) = app {
                dispatch(&ui_weak.unwrap(), &state, Command::LoadApp(app));
            }
        });
    }
    // Sidebar selection → load that app (real: only if signed in; else prompt).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_select_app(move |index| {
            let ui = ui_weak.unwrap();
            state.borrow_mut().selected = index as usize;
            let (app, signed) = {
                let st = state.borrow();
                let signed = st.status == "loaded"
                    || st.status == "loading"
                    || matches!(st.backend, Backend::Mock { .. });
                (st.config.applications.get(index as usize).cloned(), signed)
            };
            if let (Some(app), true) = (app, signed) {
                dispatch(&ui, &state, Command::LoadApp(app));
            } else {
                push_matrix(&ui, &state);
            }
        });
    }
    // Reveal → round-trip (real) or inline (mock); both via dispatch.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_reveal_cell(move |row, col| {
            let ui = ui_weak.unwrap();
            let key = {
                let st = state.borrow();
                st.view.rows.get(row as usize).map(|r| r.key.clone())
            };
            if let Some(key) = key {
                dispatch(
                    &ui,
                    &state,
                    Command::Reveal {
                        row: row as usize,
                        col: col as usize,
                        key,
                    },
                );
            }
        });
    }
    // Settings toggle.
    {
        let ui_weak = ui.as_weak();
        ui.on_toggle_settings(move || {
            let ui = ui_weak.unwrap();
            ui.set_settings_open(!ui.get_settings_open());
        });
    }
    // Save SSO fields → config + persist (real only; mock is ephemeral).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_save_sso(move || {
            let ui = ui_weak.unwrap();
            let mut st = state.borrow_mut();
            st.config.sso_start_url = ui.get_sso_start_url().to_string();
            st.config.sso_region = ui.get_sso_region().to_string();
            if !matches!(st.backend, Backend::Mock { .. }) {
                let _ = st.config.save();
            }
        });
    }
    // Add application (empty).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_add_app(move |name| {
            let name = name.trim().to_string();
            if name.is_empty() {
                return;
            }
            {
                let mut st = state.borrow_mut();
                st.config.applications.push(Application {
                    name,
                    environments: Vec::new(),
                });
                st.selected = st.config.applications.len() - 1;
                if !matches!(st.backend, Backend::Mock { .. }) {
                    let _ = st.config.save();
                }
            }
            push_matrix(&ui_weak.unwrap(), &state);
        });
    }
    // Remove application (clamp selection).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_remove_app(move |index| {
            let index = index as usize;
            {
                let mut st = state.borrow_mut();
                if index < st.config.applications.len() {
                    st.config.applications.remove(index);
                    if st.selected >= st.config.applications.len()
                        && !st.config.applications.is_empty()
                    {
                        st.selected = st.config.applications.len() - 1;
                    }
                    if !matches!(st.backend, Backend::Mock { .. }) {
                        let _ = st.config.save();
                    }
                }
            }
            push_matrix(&ui_weak.unwrap(), &state);
        });
    }
    // Add environment to the selected application.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_add_env(move |env, account, region, secret, perm| {
            let env = env.trim().to_string();
            if env.is_empty() {
                return;
            }
            {
                let mut st = state.borrow_mut();
                let selected = st.selected;
                if let Some(app) = st.config.applications.get_mut(selected) {
                    app.environments.push(Mapping {
                        environment: env,
                        account_id: account.trim().to_string(),
                        region: region.trim().to_string(),
                        secret_id: secret.trim().to_string(),
                        permission_set: perm.trim().to_string(),
                    });
                }
                if !matches!(st.backend, Backend::Mock { .. }) {
                    let _ = st.config.save();
                }
            }
            push_matrix(&ui_weak.unwrap(), &state);
        });
    }
    // Remove environment.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_remove_env(move |index| {
            let index = index as usize;
            {
                let mut st = state.borrow_mut();
                let selected = st.selected;
                if let Some(app) = st.config.applications.get_mut(selected) {
                    if index < app.environments.len() {
                        app.environments.remove(index);
                    }
                }
                if !matches!(st.backend, Backend::Mock { .. }) {
                    let _ = st.config.save();
                }
            }
            push_matrix(&ui_weak.unwrap(), &state);
        });
    }
    // Theme / sort / auto-hide.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_set_theme(move |dark| {
            state.borrow_mut().prefs.dark = dark;
            ui_weak.unwrap().set_dark(dark);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_set_sort(move |index| {
            state.borrow_mut().prefs.sort = if index == 1 {
                SortKey::GapFirst
            } else {
                SortKey::Name
            };
            {
                let mut st = state.borrow_mut();
                let sort = st.prefs.sort;
                sort_rows(&mut st.view, sort);
            }
            push_matrix(&ui_weak.unwrap(), &state);
        });
    }
    {
        let state = state.clone();
        ui.on_set_auto_hide(move |secs| {
            state.borrow_mut().prefs.auto_hide_secs = secs.max(1) as u64;
        });
    }

    let run_result = ui.run();

    // App closing: stop the worker loop. No-op in mock mode; harmless if the
    // worker already exited. This is also the one site that *constructs*
    // `Command::Shutdown` — the variant `worker::run_loop` already handles.
    if let Backend::Real(tx) = &state.borrow().backend {
        let _ = tx.send(Command::Shutdown);
    }
    run_result
}
