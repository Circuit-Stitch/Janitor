slint::include_modules!();
mod logpane;
mod pane;
mod rows;
#[cfg(test)]
mod view_tests;
mod worker;

use std::cell::{Cell, RefCell};
use std::env;
use std::rc::Rc;
use std::sync::mpsc::Sender;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use janitor_core::compare::EntryState;
use janitor_core::config::{Application, Config, Mapping};
use janitor_core::provider::{AppError, What};
use janitor_core::view::{sort_rows, state_glyph, MatrixCell, MatrixView, SortKey};

use rows::{matrix_items, MatrixItem};
use worker::{Command, Event, ProviderKind};

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
    // A weak handle to the main window, so off-window refreshes initiated from
    // the Manage window (which has no MainWindow handle) — `push_matrix` after a
    // rename/remove — can still reach the main window.
    static MAIN: RefCell<Option<slint::Weak<MainWindow>>> = const { RefCell::new(None) };
    // One OS clipboard handle kept alive for the process: X11/Wayland serve the
    // selection from the owning process, so a short-lived handle would lose the
    // copied text on drop. Only ever holds Entry names — metadata, never Values
    // (#40, ADR 0005).
    static CLIPBOARD: RefCell<Option<arboard::Clipboard>> = const { RefCell::new(None) };
}

/// Run `f` with the upgraded main window, if it is still alive.
fn with_main_ui(f: impl FnOnce(&MainWindow)) {
    MAIN.with(|m| {
        if let Some(ui) = m.borrow().as_ref().and_then(|w| w.upgrade()) {
            f(&ui);
        }
    });
}

/// After mutating the bound app off-window, refresh the matrix and reload it if
/// it is the visible app. Reaches the main window via the `MAIN` weak handle.
fn dispatch_via_state_refresh(state: &Rc<RefCell<AppState>>, target: usize, reload: bool) {
    with_main_ui(|ui| {
        push_matrix(ui, state);
        if reload {
            let app = state.borrow().config.applications.get(target).cloned();
            if let Some(app) = app {
                dispatch(state, Command::LoadApp(app));
            }
        }
    });
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
            MatrixItem::Row {
                index,
                zebra,
                group_label,
            } => {
                let r = &view.rows[index];
                // Omit the cluster's common prefix the header already shows, then
                // the muted-prefix / bold-leaf split over what remains (#40). Flat
                // / lone rows (group_label None) keep the full name.
                let (prefix, leaf) = rows::display_name_parts(group_label.as_deref(), &r.name);
                MatrixItemView {
                    is_header: false,
                    row_index: index as i32,
                    prefix: prefix.into(),
                    leaf: leaf.into(),
                    full_name: r.name.as_str().into(),
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

/// Copy a (non-secret) Entry name to the OS clipboard, reusing the long-lived
/// handle (ADR 0005; the name is metadata, so a plain copy with no auto-clear is
/// right — that policy guards Values). Failures surface in the diagnostic log
/// (ADR 0017) and never panic. The `arboard` / OS-clipboard shell here is
/// intentionally untested (ADR 0010 §5) — the branch logic is trivial and the
/// behaviour lives entirely in the platform handle.
fn copy_entry_name(name: &str) {
    CLIPBOARD.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            match arboard::Clipboard::new() {
                Ok(cb) => *slot = Some(cb),
                Err(e) => {
                    tracing::warn!(target: "janitor::gui", "clipboard unavailable — {e}");
                    return;
                }
            }
        }
        if let Some(cb) = slot.as_mut() {
            if let Err(e) = cb.set_text(name.to_string()) {
                tracing::warn!(target: "janitor::gui", "clipboard copy failed — {e}");
            }
        }
    });
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
    /// Commands to the worker thread, which drives the chosen `Provider` and
    /// posts `Event`s back via `upgrade_in_event_loop` (ADR 0019 — one async path).
    tx: Sender<Command>,
    /// Which Provider the worker runs. The GUI is Provider-agnostic except here:
    /// the offline `Mock` Provider is ephemeral, so Config is never persisted for
    /// it (`maybe_save`) — a real-org write must not be stomped by demo data.
    kind: ProviderKind,
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

impl AppState {
    /// Persist Config (locations only — THREAT-MODEL) unless the offline mock
    /// Provider is active, whose seeded demo `Config` must never overwrite a real
    /// org's saved file.
    fn maybe_save(&self) {
        if self.kind != ProviderKind::Mock {
            let _ = self.config.save();
        }
    }
}

/// Send a command to the worker (ADR 0019 — one async path for every Provider).
/// Replies arrive as `Event`s marshalled onto the UI loop via
/// `upgrade_in_event_loop`.
fn dispatch(state: &Rc<RefCell<AppState>>, cmd: Command) {
    let _ = state.borrow().tx.send(cmd);
}

/// Apply one Event to the UI + state. Called on the UI thread via
/// `upgrade_in_event_loop` for the worker's replies.
fn apply_event(ui: &MainWindow, state: &Rc<RefCell<AppState>>, ev: Event) {
    match ev {
        Event::SignInStarted => set_status(ui, state, "signing", ""),
        Event::SignedIn => {
            let app = {
                let st = state.borrow();
                st.config.applications.get(st.selected).cloned()
            };
            if let Some(app) = app {
                dispatch(state, Command::LoadApp(app));
            } else {
                set_status(ui, state, "loaded", "");
            }
        }
        Event::SignInFailed(msg) => {
            set_status(ui, state, "error", &format!("Sign-in failed: {msg}"))
        }
        Event::AppLoading => set_status(ui, state, "loading", ""),
        Event::AppLoaded {
            mut view,
            corrected,
            app_name,
        } => {
            // Drop a stale in-flight load whose app was switched away mid-load:
            // apply the view (and corrections) ONLY to the Application it was
            // loaded for. For distinct names this name check suffices; for two
            // same-named Applications the identity match inside `fold_corrections`
            // is the backstop that prevents a wrong-app Config write.
            let is_current = {
                let st = state.borrow();
                st.config
                    .applications
                    .get(st.selected)
                    .map(|a| a.name == app_name)
                    .unwrap_or(false)
            };
            if !is_current {
                return;
            }
            // Persist any auto-corrected permission sets (ADR 0018) before render.
            if !corrected.is_empty() {
                fold_corrections(state, &corrected);
            }
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
        st.maybe_save();
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
            dispatch(state, Command::LoadApp(app));
        }
    }
}

/// Persist auto-corrected permission sets (ADR 0018) into the selected (= loaded,
/// guarded by the caller) Application. Each correction is applied by full target
/// **identity** (`apply_corrected_role` matches env name + account + secret), so a
/// same-named Environment in another Application can never be mis-written even if
/// the by-name caller guard is fooled by two identically-named Applications.
/// Mock-guarded save, then a Manage-window refresh so an open editor shows the
/// corrected role.
fn fold_corrections(state: &Rc<RefCell<AppState>>, corrected: &[Mapping]) {
    let changed = {
        let mut st = state.borrow_mut();
        let selected = st.selected;
        let Some(app) = st.config.applications.get_mut(selected) else {
            return;
        };
        let mut changed = false;
        for c in corrected {
            if app.apply_corrected_role(c) {
                changed = true;
            }
        }
        if changed {
            st.maybe_save();
        }
        changed
    };
    if changed {
        refresh_manage_window(state);
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
    dispatch(state, cmd);
}

/// Feed the user's picked index back into the in-progress walk. Clears the picker
/// while the next step resolves (a fresh `DiscoveryChoice` or terminal Step
/// re-renders it).
fn advance_discovery(state: &Rc<RefCell<AppState>>, choice: usize) {
    clear_manage_choice();
    set_manage_status("Discovering…");
    dispatch(state, Command::AdvanceDiscovery { choice });
}

/// Remove an Environment from the **bound** Application, persist, refresh.
fn remove_bound_env(state: &Rc<RefCell<AppState>>, index: usize) {
    let (target, reload) = {
        let mut st = state.borrow_mut();
        let Some(target) = st.manage_app else { return };
        if let Some(app) = st.config.applications.get_mut(target) {
            app.remove_environment(index);
        }
        st.maybe_save();
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
        st.maybe_save();
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

/// "<env>: <real AWS detail>; …". ADR 0017: the banner shows the real, error-safe
/// `code: message` (never a Value/Credential/token), not just the masked phrase.
fn banner(err: &AppError) -> String {
    err.failures
        .iter()
        .map(|f| format!("{}: {}", f.environment, f.detail))
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
    // Install the Diagnostic Log first (ADR 0017): global tracing sink into an
    // in-memory buffer + the no-op panic hook (zero stdout/stderr). Done before
    // the worker spawns so its first events are captured.
    let log = logpane::install();

    let ui = MainWindow::new()?;

    // The composition root's one mock-vs-real decision (ADR 0019): pick the
    // Provider `kind`. Mock loads the seeded demo Config (never persisted); real
    // loads the user's saved org.
    let mock = env::var("JANITOR_MOCK").is_ok() || env::args().any(|a| a == "--mock");
    let kind = if mock {
        ProviderKind::Mock
    } else {
        ProviderKind::Aws
    };
    let config = if mock {
        janitor_mock::seeded_config()
    } else {
        Config::load().unwrap_or_default()
    };

    // One async path (ADR 0019): the worker ALWAYS spawns and drives the chosen
    // Provider (built inside its Tokio runtime), marshalling each Event onto the
    // UI loop. The mock runs on the worker exactly like AWS.
    let tx = {
        let ui_weak = ui.as_weak();
        worker::spawn(kind, config.clone(), move |ev| {
            let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                let st = STATE.with(|s| s.borrow().clone());
                if let Some(st) = st {
                    apply_event(&ui, &st, ev);
                }
            });
        })
    };

    let state = Rc::new(RefCell::new(AppState {
        tx,
        kind,
        config,
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
    // Mock opens already "signed in": its `sign_in` returns instantly, so auto-send
    // SignIn at startup and the SignedIn handler loads the first app — the offline
    // demo feel, now via the same worker path the user's Sign-in click uses (ADR
    // 0019). Real AWS waits for that click (it launches the browser).
    if mock {
        dispatch(&state, Command::SignIn);
    }

    // Sign in.
    {
        let state = state.clone();
        ui.on_sign_in(move || dispatch(&state, Command::SignIn));
    }
    // Refresh (reload selected app).
    {
        let state = state.clone();
        ui.on_refresh(move || {
            let app = {
                let st = state.borrow();
                st.config.applications.get(st.selected).cloned()
            };
            if let Some(app) = app {
                dispatch(&state, Command::LoadApp(app));
            }
        });
    }
    // Sidebar selection → load that app (only once signed in; else just show it).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_select_app(move |index| {
            let ui = ui_weak.unwrap();
            state.borrow_mut().selected = index as usize;
            let (app, signed) = {
                let st = state.borrow();
                let signed = st.status == "loaded" || st.status == "loading";
                (st.config.applications.get(index as usize).cloned(), signed)
            };
            if let (Some(app), true) = (app, signed) {
                dispatch(&state, Command::LoadApp(app));
            } else {
                push_matrix(&ui, &state);
            }
        });
    }
    // Reveal → an on-demand round-trip to the Provider via dispatch.
    {
        let state = state.clone();
        ui.on_reveal_cell(move |row, col| {
            let key = {
                let st = state.borrow();
                st.view.rows.get(row as usize).map(|r| r.key.clone())
            };
            if let Some(key) = key {
                dispatch(
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
    // Copy a row's full Entry name to the clipboard (#40). No Provider round-trip
    // and no AppState needed — the name rides in on the callback.
    ui.on_copy_entry(|name| copy_entry_name(name.as_str()));
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
            st.maybe_save();
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
                st.maybe_save();
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
                    st.maybe_save();
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
                st.maybe_save();
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

    // Diagnostic Log (ADR 0017): the level dropdown sets the max verbosity shown;
    // Clear empties the buffer. Both mark the view dirty so the next poll
    // re-renders. Default is the most verbose level (show everything).
    let log_filter = Rc::new(Cell::new(logpane::FilterLevel::MAX));
    let log_dirty = Rc::new(Cell::new(true));
    {
        let log_filter = log_filter.clone();
        let log_dirty = log_dirty.clone();
        ui.on_set_log_filter(move |level| {
            log_filter.set(logpane::FilterLevel::from_ui(level));
            log_dirty.set(true);
        });
    }
    {
        let log = log.clone();
        let log_dirty = log_dirty.clone();
        ui.on_clear_log(move || {
            if let Ok(mut buf) = log.lock() {
                buf.clear();
            }
            log_dirty.set(true);
        });
    }
    // Poll the in-memory buffer into the panel's text. Low frequency (400ms) and
    // version-gated, so an idle Session does no work. Kept alive for the run.
    let log_timer = slint::Timer::default();
    {
        let ui_weak = ui.as_weak();
        let log = log.clone();
        let log_filter = log_filter.clone();
        let log_dirty = log_dirty.clone();
        let last_version = Cell::new(u64::MAX);
        log_timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(400),
            move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let (ver, text) = match log.lock() {
                    Ok(buf) => (buf.version, buf.render(log_filter.get())),
                    Err(_) => return,
                };
                if log_dirty.get() || last_version.get() != ver {
                    log_dirty.set(false);
                    last_version.set(ver);
                    ui.set_log_text(text.into());
                }
            },
        );
    }

    let run_result = ui.run();

    // App closing: stop the worker loop (harmless if it already exited). This is
    // the one site that *constructs* `Command::Shutdown` — the variant
    // `worker::run_loop` already handles.
    let _ = state.borrow().tx.send(Command::Shutdown);
    run_result
}
