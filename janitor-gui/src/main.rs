slint::include_modules!();
mod pane;
mod rows;
mod worker;

use std::cell::RefCell;
use std::env;
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use janitor_aws::discovery::What;
use janitor_aws::session::AppError;
use janitor_core::compare::{Comparison, EntryState};
use janitor_core::config::{Application, Config, Mapping};
use janitor_core::mock::MockSource;
use janitor_core::secret::SecretShape;
use janitor_core::source::SecretSource;
use janitor_core::view::{
    project, reveal_value, sort_rows, state_glyph, MatrixCell, MatrixView, SortKey,
};

use rows::{matrix_items, MatrixItem};
use worker::{Command, Event};

/// Where matrix data comes from. Both arms feed the one `apply_event` path.
enum Backend {
    /// Real AWS via the worker thread.
    Real(Sender<Command>),
    /// Offline: MockSource, served synchronously on the UI thread. Holds the
    /// last-loaded Sets so reveal works without a worker, and any guided walk
    /// paused on a choice so the picker can be exercised without a browser.
    Mock {
        source: MockSource,
        cached: RefCell<Vec<(String, SecretShape)>>,
        pending: RefCell<Option<MockWalk>>,
    },
}

/// A mock guided walk paused on the account choice, so `JANITOR_MOCK` can drive
/// the picker offline. `AdvanceDiscovery` finishes it into a `Mapping`.
struct MockWalk {
    environment: String,
    region: String,
    /// Candidate accounts as `(name, id)`, in label order.
    accounts: Vec<(String, String)>,
}

// The UI-thread-owned shared state. The worker bridge cannot capture an `Rc`
// (its `upgrade_in_event_loop` closure is `Send + 'static`, and `Rc` is
// `!Send`), so the bridge reaches the state through this thread-local — which
// is only ever touched on the UI thread.
thread_local! {
    static STATE: RefCell<Option<Rc<RefCell<AppState>>>> = const { RefCell::new(None) };
    // The non-modal Manage window (ADR 0013), created lazily on first open and
    // reused. Held here (not in AppState) so its callbacks can capture `state`
    // strongly without a reference cycle.
    static MANAGE: RefCell<Option<ManageWindow>> = const { RefCell::new(None) };
    // A weak handle to the main window, so commands initiated from the Manage
    // window (which has no MainWindow handle) can still drive `dispatch`/the
    // mock inline path.
    static MAIN: RefCell<Option<slint::Weak<MainWindow>>> = const { RefCell::new(None) };
}

/// Run `f` with the upgraded main window, if it is still alive.
fn with_main_ui(f: impl FnOnce(&MainWindow)) {
    MAIN.with(|m| {
        if let Some(ui) = m.borrow().as_ref().and_then(|w| w.upgrade()) {
            f(&ui);
        }
    });
}

/// Dispatch a command from a context lacking a `MainWindow` (e.g. a Manage
/// callback), reaching the main window via the `MAIN` weak handle.
fn dispatch_via_state(state: &Rc<RefCell<AppState>>, cmd: Command) {
    with_main_ui(|ui| dispatch(ui, state, cmd));
}

/// After mutating the bound app off-window, refresh the matrix and reload it if
/// it is the visible app.
fn dispatch_via_state_refresh(state: &Rc<RefCell<AppState>>, target: usize, reload: bool) {
    with_main_ui(|ui| {
        push_matrix(ui, state);
        if reload {
            let app = state.borrow().config.applications.get(target).cloned();
            if let Some(app) = app {
                dispatch(ui, state, Command::LoadApp(app));
            }
        }
    });
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

/// Map a row's masked cells into Slint cell models.
fn to_cell_views(cells: &[MatrixCell]) -> ModelRc<CellView> {
    let cells: Vec<CellView> = cells
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
    ModelRc::from(Rc::new(VecModel::from(cells)))
}

/// Map an owned `MatrixView` into the flat list of table items the view renders:
/// prefix-cluster headers interleaved with data rows (per the pure `matrix_items`
/// seam), each row carrying its `MatrixView` index for reveal, the muted-prefix /
/// bold-leaf name split, its `LeafKind` badge, the order-independent state glyph,
/// and its zebra parity. `grouped` toggles clustering (default on, issue #20).
fn to_item_models(view: &MatrixView, grouped: bool) -> ModelRc<MatrixItemView> {
    let names: Vec<&str> = view.rows.iter().map(|r| r.name.as_str()).collect();
    let items: Vec<MatrixItemView> = matrix_items(&names, grouped)
        .into_iter()
        .map(|item| match item {
            MatrixItem::Header { label, count } => MatrixItemView {
                is_header: true,
                label: label.into(),
                count: count as i32,
                ..Default::default()
            },
            MatrixItem::Row { index, zebra } => {
                let r = &view.rows[index];
                let (prefix, leaf) = rows::split_name(&r.name);
                MatrixItemView {
                    is_header: false,
                    row_index: index as i32,
                    prefix: prefix.into(),
                    leaf: leaf.into(),
                    badge: rows::badge_label(r.kind).into(),
                    state: state_label(r.state).into(),
                    glyph: state_glyph(r.state).into(),
                    zebra,
                    cells: to_cell_views(&r.cells),
                    ..Default::default()
                }
            }
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(items)))
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
    /// Prefix-cluster grouping toggle — default on (issue #20).
    grouped: bool,
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
    /// The Application index the open Manage window is bound to (ADR 0013).
    /// `Some` while a Manage window targets an app; selecting a different
    /// sidebar app does not change it, so a discovered Environment lands in the
    /// Application the window was opened for.
    manage_app: Option<usize>,
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
                    let Backend::Mock { source, cached, .. } = &st.backend else {
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
            // Offline discovery: no AWS, so fabricate a small multi-account org
            // and ask, exercising the picker (and remembered default) under
            // JANITOR_MOCK without a browser. Role + secret then auto-pick.
            Command::BeginDiscovery {
                environment,
                region,
                remembered,
            } => {
                let accounts = vec![
                    ("Prod".to_string(), "000000000001".to_string()),
                    ("Staging".to_string(), "000000000002".to_string()),
                ];
                let default = remembered
                    .as_ref()
                    .and_then(|m| accounts.iter().position(|(_, id)| *id == m.account_id));
                let labels = accounts
                    .iter()
                    .map(|(name, id)| format!("{name} ({id})"))
                    .collect();
                {
                    let st = state.borrow();
                    let Backend::Mock { pending, .. } = &st.backend else {
                        unreachable!()
                    };
                    *pending.borrow_mut() = Some(MockWalk {
                        environment,
                        region,
                        accounts,
                    });
                }
                apply_event(
                    ui,
                    state,
                    Event::DiscoveryChoice {
                        what: What::Accounts,
                        labels,
                        default,
                    },
                );
            }
            Command::AdvanceDiscovery { choice } => {
                let walk = {
                    let st = state.borrow();
                    let Backend::Mock { pending, .. } = &st.backend else {
                        unreachable!()
                    };
                    let taken = pending.borrow_mut().take();
                    taken
                };
                if let Some(walk) = walk {
                    let i = choice.min(walk.accounts.len() - 1);
                    let (_, account_id) = &walk.accounts[i];
                    let mapping = Mapping {
                        environment: walk.environment.clone(),
                        account_id: account_id.clone(),
                        region: walk.region,
                        secret_id: format!("discovered/{}", walk.environment),
                        permission_set: "ReadOnly".into(),
                    };
                    apply_event(ui, state, Event::EnvDiscovered(mapping));
                }
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
        Event::EnvDiscovered(mapping) => {
            clear_manage_choice();
            on_env_discovered(ui, state, mapping)
        }
        Event::DiscoveryChoice {
            what,
            labels,
            default,
        } => set_manage_choice(what, labels, default),
        Event::DiscoveryFailed(msg) => {
            clear_manage_choice();
            set_manage_terminal(&format!("Could not add: {msg}"))
        }
        // A dead SSO token: the Session already cleared its sign-in, so route the
        // main window back to the Sign-in state (status "error" surfaces the
        // "Sign in" button) and show the masked reason in the wizard. No append,
        // no Config write (only EnvDiscovered does that).
        Event::DiscoveryReauthRequired => {
            clear_manage_choice();
            set_manage_terminal("Session expired — sign in again.");
            set_status(ui, state, "error", "session expired — sign in again");
        }
    }
}

/// A `Discovery` `Done`: append the Mapping to the **bound** Application (not the
/// selected one — ADR 0013), persist Config (locations only), remember the pick,
/// refresh the Manage window, and reload the matrix if it is the visible app.
fn on_env_discovered(ui: &MainWindow, state: &Rc<RefCell<AppState>>, mapping: Mapping) {
    let (target, reload) = {
        let mut st = state.borrow_mut();
        let Some(target) = st.manage_app else {
            return; // no bound window — nothing to attach to
        };
        let Some(app) = st.config.applications.get_mut(target) else {
            return;
        };
        let env_name = mapping.environment.clone();
        // Reject a duplicate Environment name rather than overwrite its Mapping;
        // the no-stomp invariant lives in core (`Application::add_environment`).
        if let Err(e) = app.add_environment(mapping.clone()) {
            drop(st);
            set_manage_status(&format!("Cannot add: {e}."));
            return;
        }
        st.config.last_pick = Some(mapping);
        if !matches!(st.backend, Backend::Mock { .. }) {
            let _ = st.config.save();
        }
        set_manage_status(&format!("Added \"{env_name}\"."));
        (target, target == st.selected)
    };
    refresh_manage_window(state);
    // Update sidebar env counts immediately.
    push_matrix(ui, state);
    // If the bound app is the one on screen, reload so the new column appears.
    if reload {
        let app = state.borrow().config.applications.get(target).cloned();
        if let Some(app) = app {
            dispatch(ui, state, Command::LoadApp(app));
        }
    }
}

/// Open (or rebind) the non-modal Manage window for Application `index`.
fn open_manage(state: &Rc<RefCell<AppState>>, index: usize) {
    {
        let mut st = state.borrow_mut();
        if index >= st.config.applications.len() {
            return;
        }
        st.manage_app = Some(index);
    }
    MANAGE.with(|m| {
        if m.borrow().is_none() {
            *m.borrow_mut() = Some(build_manage_window(state));
        }
    });
    refresh_manage_window(state);
    set_manage_status("");
    MANAGE.with(|m| {
        if let Some(win) = m.borrow().as_ref() {
            let _ = win.show();
        }
    });
}

/// Construct the Manage window once and wire its callbacks (which capture
/// `state` strongly — no cycle, since `AppState` does not hold the window).
fn build_manage_window(state: &Rc<RefCell<AppState>>) -> ManageWindow {
    let win = ManageWindow::new().expect("create Manage window");
    {
        let state = state.clone();
        win.on_add_env_discover(move |env| begin_discovery(&state, env.to_string()));
    }
    {
        let state = state.clone();
        win.on_pick_choice(move |index| advance_discovery(&state, index as usize));
    }
    {
        // Back from a terminal message: dismiss it (and any stale choice) so the
        // user can re-enter an Environment name and try again. Nothing is
        // appended or saved (only a `Done` walk does that).
        win.on_back_discovery(move || {
            clear_manage_choice();
            set_manage_status("");
        });
    }
    {
        let state = state.clone();
        win.on_remove_env(move |index| remove_bound_env(&state, index as usize));
    }
    {
        let state = state.clone();
        win.on_rename_app(move |name| rename_bound_app(&state, name.to_string()));
    }
    {
        let weak = win.as_weak();
        win.on_close_window(move || {
            if let Some(win) = weak.upgrade() {
                let _ = win.hide();
            }
        });
    }
    win
}

/// Start a guided walk for a typed Environment name on the bound Application.
/// Region resolves to `secret_region` else `sso_region` (ADR 0013); the
/// remembered last-pick seeds the defaults.
fn begin_discovery(state: &Rc<RefCell<AppState>>, env: String) {
    let env = env.trim().to_string();
    if env.is_empty() {
        return;
    }
    let cmd = {
        let st = state.borrow();
        let region = if st.config.secret_region.is_empty() {
            st.config.sso_region.clone()
        } else {
            st.config.secret_region.clone()
        };
        Command::BeginDiscovery {
            environment: env,
            region,
            remembered: st.config.last_pick.clone(),
        }
    };
    clear_manage_choice();
    set_manage_status("Discovering…");
    // Dispatch needs a MainWindow handle for the mock inline path; reach it via
    // the live STATE/event loop the same way worker events do.
    dispatch_via_state(state, cmd);
}

/// Feed the user's picked index back into the in-progress walk. Clears the picker
/// while the next step resolves (a fresh `DiscoveryChoice` or terminal Step
/// re-renders it).
fn advance_discovery(state: &Rc<RefCell<AppState>>, choice: usize) {
    clear_manage_choice();
    set_manage_status("Discovering…");
    dispatch_via_state(state, Command::AdvanceDiscovery { choice });
}

/// Remove an Environment from the **bound** Application, persist, refresh.
fn remove_bound_env(state: &Rc<RefCell<AppState>>, index: usize) {
    let (target, reload) = {
        let mut st = state.borrow_mut();
        let Some(target) = st.manage_app else { return };
        if let Some(app) = st.config.applications.get_mut(target) {
            app.remove_environment(index);
        }
        if !matches!(st.backend, Backend::Mock { .. }) {
            let _ = st.config.save();
        }
        (target, target == st.selected)
    };
    refresh_manage_window(state);
    dispatch_via_state_refresh(state, target, reload);
}

/// Rename the **bound** Application (ADR 0013): update Config (locations only),
/// persist, then refresh the Manage window (title + name field) and the sidebar.
/// A blank/invalid name is refused by core and leaves the name untouched.
fn rename_bound_app(state: &Rc<RefCell<AppState>>, name: String) {
    {
        let mut st = state.borrow_mut();
        let Some(target) = st.manage_app else { return };
        if !st.config.rename_application(target, &name) {
            return;
        }
        if !matches!(st.backend, Backend::Mock { .. }) {
            let _ = st.config.save();
        }
    }
    refresh_manage_window(state);
    with_main_ui(|ui| push_matrix(ui, state));
}

/// Push the bound Application's name + Environment rows into the Manage window.
fn refresh_manage_window(state: &Rc<RefCell<AppState>>) {
    let st = state.borrow();
    let Some(target) = st.manage_app else { return };
    let (name, envs) = match st.config.applications.get(target) {
        Some(app) => (app.name.clone(), env_rows(&st.config, target)),
        None => return,
    };
    MANAGE.with(|m| {
        if let Some(win) = m.borrow().as_ref() {
            win.set_app_name(name.into());
            win.set_envs(envs);
        }
    });
}

/// Set the Manage window's status/result line (masked text only). Transient —
/// clears the terminal flag so no Back button shows (e.g. "Discovering…").
fn set_manage_status(msg: &str) {
    MANAGE.with(|m| {
        if let Some(win) = m.borrow().as_ref() {
            win.set_discovery_status(msg.into());
            win.set_discovery_terminal(false);
        }
    });
}

/// Set a terminal, retryable discovery message (no choices / session error /
/// expired) and reveal the Back button so the user can adjust and try again.
/// Masked text only (the reason comes from the tested `describe()`/labels).
fn set_manage_terminal(msg: &str) {
    MANAGE.with(|m| {
        if let Some(win) = m.borrow().as_ref() {
            win.set_discovery_status(msg.into());
            win.set_discovery_terminal(true);
        }
    });
}

/// Render a pending guided choice as the picker: a titled, selectable list with
/// the remembered default pre-selected. `labels` are presenter lines only
/// (account `name (id)`, role, secret name) — never secret Values (THREAT-MODEL).
fn set_manage_choice(what: What, labels: Vec<String>, default: Option<usize>) {
    let prompt = match what {
        What::Accounts => "Choose an account:",
        What::Roles => "Choose a role:",
        What::Secrets => "Choose a secret:",
    };
    let rows: Vec<SharedString> = labels.into_iter().map(Into::into).collect();
    MANAGE.with(|m| {
        if let Some(win) = m.borrow().as_ref() {
            win.set_discovery_status("".into());
            win.set_choice_prompt(prompt.into());
            win.set_choices(ModelRc::from(Rc::new(VecModel::from(rows))));
            win.set_choice_default(default.map(|i| i as i32).unwrap_or(-1));
        }
    });
}

/// Hide the picker (a terminal Step arrived, or a new walk began).
fn clear_manage_choice() {
    MANAGE.with(|m| {
        if let Some(win) = m.borrow().as_ref() {
            win.set_choice_prompt("".into());
            win.set_choices(ModelRc::from(Rc::new(VecModel::<SharedString>::default())));
            win.set_choice_default(-1);
        }
    });
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
    push_pane(ui, state);
}

/// Recompute the main pane from the current status + whether any Applications
/// exist, and push the token the `.slint` view switches on. Called whenever
/// either input changes (status transition or app add/remove).
fn push_pane(ui: &MainWindow, state: &Rc<RefCell<AppState>>) {
    let st = state.borrow();
    let has_apps = !st.config.applications.is_empty();
    ui.set_pane(pane::main_pane(&st.status, has_apps).as_token().into());
}

/// Push the current view's rows/envs + sidebar into the UI.
fn push_matrix(ui: &MainWindow, state: &Rc<RefCell<AppState>>) {
    ui.set_revealed_row(-1);
    ui.set_revealed_col(-1);
    ui.set_revealed_text(SharedString::new());
    {
        let st = state.borrow();
        ui.set_environments(env_models(&st.view));
        ui.set_items(to_item_models(&st.view, st.prefs.grouped));
        ui.set_apps(app_models(&st.config, st.selected, &st.view, &st.status));
    }
    // The app-set may have changed (add/remove), which flips the empty-state.
    push_pane(ui, state);
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
            pending: RefCell::new(None),
        },
        config: config.clone(),
        selected: 0,
        prefs: Preferences {
            sort: SortKey::Name,
            auto_hide_secs: 5,
            dark: true,
            grouped: true,
        },
        view: MatrixView {
            environments: Vec::new(),
            rows: Vec::new(),
        },
        status: "unauth".to_string(),
        manage_app: None,
    }));

    // Publish the state on the UI thread so the (Send) worker bridge can reach
    // it without capturing the `!Send` `Rc`.
    STATE.with(|s| *s.borrow_mut() = Some(state.clone()));
    MAIN.with(|m| *m.borrow_mut() = Some(ui.as_weak()));

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
        ui.set_grouped(st.prefs.grouped);
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
    // Sidebar "+": create an Application (name only) and open its Manage window
    // bound to it (ADR 0013).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_new_app_managed(move |name| {
            let name = name.trim().to_string();
            if name.is_empty() {
                return;
            }
            let index = {
                let mut st = state.borrow_mut();
                st.config.applications.push(Application {
                    name,
                    environments: Vec::new(),
                });
                st.selected = st.config.applications.len() - 1;
                if !matches!(st.backend, Backend::Mock { .. }) {
                    let _ = st.config.save();
                }
                st.selected
            };
            push_matrix(&ui_weak.unwrap(), &state);
            open_manage(&state, index);
        });
    }
    // Header "Manage": open the Manage window for the selected Application.
    {
        let state = state.clone();
        ui.on_manage_selected(move || {
            let index = state.borrow().selected;
            open_manage(&state, index);
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
    // Prefix-cluster grouping toggle (default on). Re-pushes the item models so
    // headers appear/disappear and zebra restripes.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_set_grouped(move |grouped| {
            state.borrow_mut().prefs.grouped = grouped;
            push_matrix(&ui_weak.unwrap(), &state);
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
