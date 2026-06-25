slint::include_modules!();
mod errors;
mod logpane;
mod pane;
mod reveal;
mod rows;
mod scrollbar;
mod sidebar;
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
use janitor_core::config::{Application, Config, Mapping, Method};
use janitor_core::provider::What;
use janitor_core::region;
use janitor_core::view::{sort_rows, state_glyph, MatrixCell, MatrixView, SortKey};

use rows::{matrix_items, MatrixItem};
use worker::{Command, Event, ProviderKind};

/// ENTRY-column resize bounds (#42), in logical px. These MIRROR `entry-min` (the
/// floor) and `entry-w`'s default in `ui/app.slint`, kept in sync the same way
/// `view_tests::ENV_FLOOR` mirrors `env-floor`. The floor also clamps the
/// persisted width in Config (`set_entry_column_width`), so a stored width can
/// never render a sub-floor column.
const ENTRY_MIN_PX: f64 = 200.0;
const ENTRY_DEFAULT_PX: f64 = 300.0;

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
    let items = matrix_items(&names, grouped);
    // Per-item header/row counts so the view can pin sticky group headers (#42)
    // without re-summing heights; index-aligned with `items`.
    let offsets = rows::item_offsets(&items);
    let views: Vec<MatrixItemView> = items
        .into_iter()
        .zip(offsets)
        .map(|(item, off)| {
            let headers_before = off.headers_before as i32;
            let rows_before = off.rows_before as i32;
            match item {
                MatrixItem::Header { label, count } => MatrixItemView {
                    is_header: true,
                    label: label.into(),
                    count: count as i32,
                    headers_before,
                    rows_before,
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
                        headers_before,
                        rows_before,
                        cells: to_cell_views(&r.cells),
                        ..Default::default()
                    }
                }
            }
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(views)))
}

/// Copy a (non-secret) Entry name to the OS clipboard, reusing the long-lived
/// handle (ADR 0005; the name is metadata, so a plain copy with no auto-clear is
/// right — that policy guards Values). Failures surface in the diagnostic log
/// (ADR 0017) and never panic. The `arboard` / OS-clipboard shell here is
/// intentionally untested (ADR 0010 §5) — the branch logic is trivial and the
/// behaviour lives entirely in the platform handle.
/// Set the OS clipboard to `text`, reusing the long-lived handle. Returns whether
/// it succeeded so callers only log "copied" on success. Failures surface in the
/// diagnostic log (ADR 0017) and never panic. **No auto-clear** for a Value yet —
/// issue #59 tracks the ADR 0005 clipboard hardening. The `arboard` / OS-clipboard
/// shell here is intentionally untested (ADR 0010 §5).
fn set_clipboard(text: &str) -> bool {
    CLIPBOARD.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            match arboard::Clipboard::new() {
                Ok(cb) => *slot = Some(cb),
                Err(e) => {
                    tracing::warn!(target: "janitor::gui", "clipboard unavailable — {e}");
                    return false;
                }
            }
        }
        match slot.as_mut() {
            Some(cb) => match cb.set_text(text.to_string()) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(target: "janitor::gui", "clipboard copy failed — {e}");
                    false
                }
            },
            None => false,
        }
    })
}

/// Copy a (non-secret) Entry name and log it (the name IS the safe label). The
/// name is metadata (ADR 0005), so a plain copy with no auto-clear is correct.
fn copy_entry_name(name: &str) {
    if set_clipboard(name) {
        tracing::info!(target: "janitor::gui", "{name} copied to clipboard");
    }
}

fn state_label(state: EntryState) -> &'static str {
    match state {
        EntryState::Aligned => "Aligned",
        EntryState::Drift => "Drift",
        EntryState::Gap => "Gap",
    }
}

/// Count the loaded rows in each state for the bottom-bar legend (issue #23).
/// Derived from the already-masked `MatrixView` — never recomputes secrets.
fn state_counts(view: &MatrixView) -> (i32, i32, i32) {
    let mut aligned = 0;
    let mut drift = 0;
    let mut gap = 0;
    for r in &view.rows {
        match r.state {
            EntryState::Aligned => aligned += 1,
            EntryState::Drift => drift += 1,
            EntryState::Gap => gap += 1,
        }
    }
    (aligned, drift, gap)
}

/// The representative Secret ARN/name shown as the main-header subtitle (issue
/// #23): the first Environment's `secret_id` for the selected Application. A
/// location identifier, not a secret (THREAT-MODEL — OK to show). Empty when the
/// app has no Environments.
fn representative_secret_id(config: &Config, selected: usize) -> String {
    config
        .applications
        .get(selected)
        .and_then(|app| app.environments.first())
        .map(|m| m.secret_id.clone())
        .unwrap_or_default()
}

fn env_models(view: &MatrixView) -> ModelRc<SharedString> {
    let envs: Vec<SharedString> = view
        .environments
        .iter()
        .map(|e| e.as_str().into())
        .collect();
    ModelRc::from(Rc::new(VecModel::from(envs)))
}

/// The browse-region picker's option list (ADR 0015): [`region::region_choices`]
/// as a Slint string model. Pure mapping; the region logic stays in `core`.
fn region_choices_model(config: &Config) -> ModelRc<SharedString> {
    let regions: Vec<SharedString> = region::region_choices(config)
        .into_iter()
        .map(|r| r.into())
        .collect();
    ModelRc::from(Rc::new(VecModel::from(regions)))
}

/// Re-publish the browse-region picker — its choices and current selection — to
/// both surfaces of the one sticky `config.secret_region`: the Settings picker
/// (main window) and the at-hand picker beside `+ Add env` (Manage window), so
/// the two never drift (ADR 0015).
fn publish_browse_region(state: &Rc<RefCell<AppState>>) {
    let st = state.borrow();
    let current: SharedString = region::browse_region(&st.config).into();
    MAIN.with(|m| {
        if let Some(win) = m.borrow().as_ref().and_then(|w| w.upgrade()) {
            win.set_region_choices(region_choices_model(&st.config));
            win.set_browse_region(current.clone());
        }
    });
    MANAGE.with(|m| {
        if let Some(win) = m.borrow().as_ref() {
            win.set_region_choices(region_choices_model(&st.config));
            win.set_browse_region(current.clone());
        }
    });
}

/// Persist a picked browse region as the sticky `config.secret_region` and
/// re-publish it to both pickers (ADR 0015). Real-only — `maybe_save` skips the
/// ephemeral mock Config; a region is a location, never a Value (THREAT-MODEL).
fn set_browse_region(state: &Rc<RefCell<AppState>>, region: String) {
    {
        let mut st = state.borrow_mut();
        st.config.secret_region = region;
        st.maybe_save();
    }
    publish_browse_region(state);
}

struct Preferences {
    sort: SortKey,
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
    /// The cell currently being press-held for reveal, as `(row, col)` into the
    /// view. Set on press, cleared on release. Guards the async reveal: a Value
    /// that returns *after* the user released (a quick tap) is dropped instead of
    /// flashing/sticking. Also names the reveal/hide audit-log lines.
    revealing: Option<(usize, usize)>,
    /// Best-effort "Snapshot HH:MM / N min ago" main-header stamp (issue #23),
    /// stamped in-memory when a matrix loads/refreshes (ADR 0005: the matrix is an
    /// explicit point-in-time snapshot). Never written to disk. `None` until the
    /// first successful load — the header then reads "Not refreshed yet".
    snapshot_at: Option<std::time::SystemTime>,
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
            {
                let mut st = state.borrow_mut();
                st.view = view;
                // Stamp the point-in-time snapshot (issue #23, ADR 0005): the
                // matrix just refreshed. In-memory only — never persisted.
                st.snapshot_at = Some(std::time::SystemTime::now());
            }
            set_status(ui, state, "loaded", "");
            push_matrix(ui, state);
        }
        Event::AppFailed(err) => set_status(ui, state, "error", &errors::banner(&err)),
        Event::Revealed { row, col, text } => {
            // Drop a Value that arrives after the user already released (a quick tap):
            // only show it if this is still the cell being held.
            let name_env = {
                let st = state.borrow();
                if st.revealing != Some((row, col)) {
                    None
                } else {
                    let name = st
                        .view
                        .rows
                        .get(row)
                        .map(|r| r.name.clone())
                        .unwrap_or_default();
                    let env = st.view.environments.get(col).cloned().unwrap_or_default();
                    Some((name, env))
                }
            };
            let Some((name, env)) = name_env else { return };
            // Press-and-hold owns the lifetime: the press set this, release/cancel
            // clears it (no auto-hide timer). Audit line names the Entry + env, never
            // the Value (THREAT-MODEL / ADR 0017).
            ui.set_revealed_row(row as i32);
            ui.set_revealed_col(col as i32);
            ui.set_revealed_text(text.into());
            tracing::info!(target: "janitor::gui", "{name}[{env}] revealed");
        }
        Event::RevealUnavailable => { /* leave masked */ }
        // The Value came back for the clipboard: set it, then log the SAFE label
        // ("NAME[env] copied to clipboard") — never `text` (THREAT-MODEL / ADR 0017).
        // The name/env are derived from row/col on this (UI) thread.
        Event::CopyValue { row, col, text } => {
            let (name, env) = {
                let st = state.borrow();
                let name = st
                    .view
                    .rows
                    .get(row)
                    .map(|r| r.name.clone())
                    .unwrap_or_default();
                let env = st.view.environments.get(col).cloned().unwrap_or_default();
                (name, env)
            };
            if set_clipboard(&text) {
                tracing::info!(target: "janitor::gui", "{name}[{env}] copied to clipboard");
            }
        }
        Event::CopyUnavailable => {
            tracing::warn!(target: "janitor::gui", "could not copy — value unavailable");
        }
        Event::EnvDiscovered(mapping) => {
            clear_manage_choice();
            on_env_discovered(ui, state, mapping)
        }
        Event::DiscoveryChoice {
            what,
            labels,
            default,
        } => set_manage_choice(what, labels, default),
        // A free-text Input step (ADR 0025): render the prompt as a text field
        // pre-filled with the remembered path default. The prompt carries the
        // question, so `what` is not needed for titling — it is logged as a safe
        // diagnostic (an enum kind, never a path/Value) to keep the DTO honest.
        Event::DiscoveryInput {
            what,
            prompt,
            default,
        } => {
            tracing::debug!(target: "janitor::gui", ?what, "discovery asks for free-text input");
            set_manage_input(prompt, default);
        }
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
        // A masked operator advisory (ADR 0025): already written to the Diagnostic
        // Log by the worker. Also surface it in the Discovery wizard if it is open
        // (set_manage_status no-ops when the Manage window is closed). Never a Value.
        Event::Warning(msg) => set_manage_status(&msg),
        // The worker's authoritative read-write lock changed (ADR 0004 / ADR 0032):
        // mirror it onto the Settings toggle so the UI never disagrees with the gate.
        Event::ReadWriteModeChanged(on) => ui.set_read_write(on),
        // Write outcomes (ADR 0032): surface each to the Diagnostic Log — the in-GUI
        // log pane (ADR 0017) IS the visible result surface for this slice. The label
        // names the Environment + the masked outcome only (never an edit Value —
        // THREAT-MODEL). A richer surface (the confirm-diff dialog's result line + a
        // matrix refresh on `WriteApplied`) lands with the in-matrix cell-edit
        // affordance (the next #80 slice), the only producer of `Command::ApplyEdits`.
        Event::WriteApplied { environment } => {
            tracing::info!(target: "janitor::gui", "{environment}: edits applied");
        }
        Event::WriteConflict { environment } => {
            tracing::warn!(
                target: "janitor::gui",
                "{environment}: write conflict — the Set changed underneath; re-read and retry"
            );
        }
        Event::WriteFailed {
            environment,
            detail,
        } => {
            tracing::warn!(target: "janitor::gui", "{environment}: write failed — {detail}");
        }
        Event::WriteRefused { environment } => {
            tracing::warn!(
                target: "janitor::gui",
                "{environment}: write refused — turn on read-write mode in Settings first"
            );
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
        win.on_add_env_discover(move |env, method_index| {
            begin_discovery(&state, env.to_string(), method_index as usize)
        });
    }
    {
        let state = state.clone();
        win.on_pick_choice(move |index| advance_discovery(&state, index as usize));
    }
    {
        let state = state.clone();
        win.on_provide_input(move |text| provide_input(&state, text.to_string()));
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
        // At-hand browse-region picker → the same sticky config.secret_region the
        // Settings picker writes, synced back to both surfaces (ADR 0015).
        let state = state.clone();
        win.on_set_browse_region(move |region| set_browse_region(&state, region.to_string()));
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

/// Short display label for a Mapping's [`Method`] (ADR 0031) — a location tag for
/// the Manage window's Environment rows, never a Value.
fn method_label(method: Method) -> &'static str {
    match method {
        Method::SecretsManager => "SM",
        Method::SsmDotenv => "SSM",
    }
}

/// Map the Manage-window picker index (0 = Secrets Manager, 1 = remote `.env`/SSM)
/// to a [`Method`]; anything else falls back to the Secrets Manager default
/// (ADR 0031 Decision 7).
fn method_from_index(index: usize) -> Method {
    match index {
        1 => Method::SsmDotenv,
        _ => Method::SecretsManager,
    }
}

/// Start a guided walk for a typed Environment name on the bound Application, using
/// the [`Method`] chosen in the per-row picker (ADR 0031). Region is the picker's
/// browse region — `secret_region` else `sso_region` via [`region::browse_region`]
/// (ADR 0013/0015); the remembered last-pick seeds the defaults.
fn begin_discovery(state: &Rc<RefCell<AppState>>, env: String, method_index: usize) {
    let env = env.trim().to_string();
    if env.is_empty() {
        return;
    }
    let cmd = {
        let st = state.borrow();
        Command::BeginDiscovery {
            method: method_from_index(method_index),
            environment: env,
            region: region::browse_region(&st.config).to_string(),
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

/// Feed the user's typed text back into a walk paused on a `Step::Input`
/// (ADR 0025) — the free-text counterpart of `advance_discovery`. The text is a
/// location (a path), never a Value. Clears the field while the next step resolves.
fn provide_input(state: &Rc<RefCell<AppState>>, text: String) {
    clear_manage_choice();
    set_manage_status("Discovering…");
    dispatch(state, Command::ProvideInput(text));
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
    let region_choices = region_choices_model(&st.config);
    let browse_region: SharedString = region::browse_region(&st.config).into();
    MANAGE.with(|m| {
        if let Some(win) = m.borrow().as_ref() {
            win.set_app_name(name.into());
            win.set_envs(envs);
            // Seed the at-hand browse-region picker so the pop-out opens on the
            // current sticky region (ADR 0015).
            win.set_region_choices(region_choices);
            win.set_browse_region(browse_region);
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
        What::Instances => "Choose an instance:",
        // `FilePath` is posed as a free-text `Input`, not a list `Ask`, so it
        // never reaches the picker; present for exhaustiveness only.
        What::FilePath => "Choose a path:",
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

/// Render a pending free-text Input (ADR 0025) as a text field pre-filled with the
/// remembered path `default`. Mutually exclusive with the choice picker, so this
/// also clears any pending choice. `prompt`/`default` are locations, never Values.
fn set_manage_input(prompt: String, default: Option<String>) {
    MANAGE.with(|m| {
        if let Some(win) = m.borrow().as_ref() {
            win.set_discovery_status("".into());
            win.set_choice_prompt("".into());
            win.set_choices(ModelRc::from(Rc::new(VecModel::<SharedString>::default())));
            win.set_choice_default(-1);
            win.set_input_prompt(prompt.into());
            win.set_input_default(default.unwrap_or_default().into());
        }
    });
}

/// Hide both the picker and the text field (a terminal Step arrived, or a new
/// walk began) — the guided question is mutually exclusive, so both are cleared.
fn clear_manage_choice() {
    MANAGE.with(|m| {
        if let Some(win) = m.borrow().as_ref() {
            win.set_choice_prompt("".into());
            win.set_choices(ModelRc::from(Rc::new(VecModel::<SharedString>::default())));
            win.set_choice_default(-1);
            win.set_input_prompt("".into());
            win.set_input_default("".into());
        }
    });
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
    let pane = pane::main_pane(&st.status, has_apps);
    ui.set_pane(pane.as_token().into());
    // Pane-derived chrome (issue #47), extracted from the `app.slint` `?:` ladders:
    // the top-bar title and the centered non-matrix body copy. `body_copy` also
    // folds in the current status message (the error-safe reason), which the UI
    // already holds — read it back so this stays the single push site.
    ui.set_pane_title(pane.title().into());
    ui.set_body_copy(pane.body_copy(ui.get_status_message().as_str()).into());
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
    push_chrome(ui, state);
}

/// Push the non-secret chrome strings + counts (issue #23): the Application
/// title/breadcrumb, the representative Secret ARN subtitle, the legend counts
/// (derived from row states), and the snapshot stamp. Identity strings, ARNs,
/// timestamps, and counts only — never a Value (THREAT-MODEL).
fn push_chrome(ui: &MainWindow, state: &Rc<RefCell<AppState>>) {
    let st = state.borrow();
    let title = st
        .config
        .applications
        .get(st.selected)
        .map(|a| a.name.clone())
        .unwrap_or_default();
    ui.set_app_title(title.into());
    ui.set_secret_arn(representative_secret_id(&st.config, st.selected).into());
    let (aligned, drift, gap) = state_counts(&st.view);
    ui.set_aligned_count(aligned);
    ui.set_drift_count(drift);
    ui.set_gap_count(gap);
    ui.set_snapshot_label(snapshot_label(st.snapshot_at).into());
}

/// Best-effort "Snapshot HH:MM / N min ago" stamp from the in-memory load time
/// (issue #23, ADR 0005). Never read from / written to disk. `None` → "" so the
/// view renders its "Not refreshed yet" placeholder. Wall-clock HH:MM is derived
/// without a date dependency (UTC seconds-of-day); the "N min ago" is the
/// elapsed-since-load delta, which is what the user actually reads.
fn snapshot_label(at: Option<std::time::SystemTime>) -> String {
    let Some(at) = at else {
        return String::new();
    };
    let Ok(since_epoch) = at.duration_since(std::time::UNIX_EPOCH) else {
        return String::new();
    };
    let secs_of_day = since_epoch.as_secs() % 86_400;
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let mins_ago = at.elapsed().map(|d| d.as_secs() / 60).unwrap_or(0);
    let ago = if mins_ago == 0 {
        "just now".to_string()
    } else if mins_ago == 1 {
        "1 min ago".to_string()
    } else {
        format!("{mins_ago} min ago")
    };
    format!("Snapshot {hh:02}:{mm:02} UTC / {ago}")
}

/// Sidebar items. The drift-badge suppression rule (show ONLY for the selected,
/// loaded app — never a per-app refetch, which would be a sign-in/GetSecretValue
/// storm on real AWS) lives in the pure, tested `sidebar::sidebar_apps` seam (#47);
/// this only maps its rows onto Slint `AppItem`s.
fn app_models(
    config: &Config,
    selected: usize,
    view: &MatrixView,
    status: &str,
) -> ModelRc<AppItem> {
    let items: Vec<AppItem> = sidebar::sidebar_apps(config, selected, view, status)
        .into_iter()
        .map(|s| AppItem {
            name: s.name.into(),
            subtitle: s.subtitle.into(),
            drift: s.drift.into(),
            selected: s.selected,
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
                    method: method_label(m.method).into(),
                })
                .collect()
        })
        .unwrap_or_default();
    ModelRc::from(Rc::new(VecModel::from(rows)))
}

fn main() -> Result<(), slint::PlatformError> {
    // Install the Diagnostic Log first (ADR 0017): global tracing sink into an
    // in-memory buffer + the no-op panic hook (zero stdout/stderr). Done before
    // the worker spawns so its first events are captured.
    let log = logpane::install();

    // ponytail: default to Slint's software renderer unless the user picked a
    // backend. The GPU (femtovg) path needs OpenGL 2.0, which RDP sessions and
    // many VMs/headless drivers don't expose — there `MainWindow::new()` fails
    // ("Could not locate glCreateShader symbol") and the app dies before any
    // window shows. This masked-matrix table UI gains nothing from GPU, so
    // software-by-default is the right trade. Escape hatch: SLINT_BACKEND=winit-femtovg.
    if env::var_os("SLINT_BACKEND").is_none() {
        env::set_var("SLINT_BACKEND", "winit-software");
    }

    let ui = MainWindow::new()?;

    // The composition root's one mock-vs-real decision (ADR 0019): pick the
    // Provider `kind`. Mock loads the seeded demo Config (never persisted); real
    // loads the user's saved org.
    let mock = env::var("JANITOR_MOCK").is_ok() || env::args().any(|a| a == "--mock");
    // The real `AwsFamilyProvider` drives both AWS-family methods, chosen per
    // Mapping (ADR 0031); the old session-global `--ssm` toggle is retired — a
    // mixed Secrets Manager / remote-`.env`-over-SSM matrix is now per-row.
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
            dark: true,
            grouped: true,
        },
        view: MatrixView {
            environments: Vec::new(),
            rows: Vec::new(),
        },
        status: "unauth".to_string(),
        manage_app: None,
        revealing: None,
        snapshot_at: None,
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
        // Browse-region picker (ADR 0015): the selectable region list and the
        // current selection (secret_region else sso_region).
        ui.set_region_choices(region_choices_model(&st.config));
        ui.set_browse_region(region::browse_region(&st.config).into());
        ui.set_dark(st.prefs.dark);
        ui.set_grouped(st.prefs.grouped);
        // Restore the persisted ENTRY-column width (#42), floored; falls back to
        // the layout default when never resized. View-state only — never a Value.
        ui.set_entry_w(
            st.config
                .entry_column_width_or(ENTRY_MIN_PX, ENTRY_DEFAULT_PX) as f32,
        );
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
    // The per-cell reveal gate (issue #47): the `.slint` cell binds its `is-revealed`
    // to this pure callback, whose handler IS the exhaustively-tested
    // `reveal::is_revealed` — so the security rule (un-mask exactly one cell, never a
    // whole row/column) lives in tested Rust, not an inline `.slint` predicate. Pure
    // + stateless, so no `state` capture.
    ui.on_is_cell_revealed(reveal::is_revealed);
    // Horizontal env-scrollbar geometry (issue #60): the `.slint` binds the thumb's
    // visibility / length / position and the drag inverse to these pure callbacks,
    // whose handlers ARE the unit-tested `scrollbar::*` functions — so the thumb
    // math (clamping, the min-thumb floor, the divide-by-zero degenerate cases)
    // lives in tested Rust, not inline `.slint` expressions. Pure + stateless.
    ui.on_sb_visible(scrollbar::is_scrollable);
    ui.on_sb_max_scroll(scrollbar::max_scroll);
    ui.on_sb_thumb_len(scrollbar::thumb_len);
    ui.on_sb_thumb_offset(scrollbar::thumb_offset);
    ui.on_sb_scroll_from_thumb(scrollbar::scroll_from_thumb);
    // Reveal → an on-demand round-trip to the Provider via dispatch.
    {
        let state = state.clone();
        ui.on_reveal_cell(move |row, col| {
            let key = {
                let mut st = state.borrow_mut();
                // Mark this cell as the one being held, so a Value that returns after
                // release is dropped and the hide can name what was revealed.
                st.revealing = Some((row as usize, col as usize));
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
    // Release/cancel of a press-held reveal: clear the guard and log "NAME[env]
    // hidden" (never the Value). The view already zeroed revealed-row/col/text.
    {
        let state = state.clone();
        ui.on_hide_cell(move || {
            let name_env = {
                let mut st = state.borrow_mut();
                st.revealing.take().map(|(row, col)| {
                    let name = st
                        .view
                        .rows
                        .get(row)
                        .map(|r| r.name.clone())
                        .unwrap_or_default();
                    let env = st.view.environments.get(col).cloned().unwrap_or_default();
                    (name, env)
                })
            };
            if let Some((name, env)) = name_env {
                tracing::info!(target: "janitor::gui", "{name}[{env}] hidden");
            }
        });
    }
    // Copy a row's full Entry name to the clipboard (#40). No Provider round-trip
    // and no AppState needed — the name rides in on the callback.
    ui.on_copy_entry(|name| copy_entry_name(name.as_str()));
    // Right-click → Copy on a Value cell: fetch the plaintext from the worker (the
    // Value lives only there — ADR 0012) and route it to the clipboard. The reply
    // (Event::CopyValue) sets the clipboard and logs "NAME[env]", never the Value.
    {
        let state = state.clone();
        ui.on_copy_value(move |row, col| {
            let key = {
                let st = state.borrow();
                st.view.rows.get(row as usize).map(|r| r.key.clone())
            };
            if let Some(key) = key {
                dispatch(
                    &state,
                    Command::CopyValue {
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
            {
                let mut st = state.borrow_mut();
                st.config.sso_start_url = ui.get_sso_start_url().to_string();
                st.config.sso_region = ui.get_sso_region().to_string();
                st.maybe_save();
            }
            // A changed SSO region can add a choice and shift the fallback, so
            // re-publish both pickers (ADR 0015).
            publish_browse_region(&state);
        });
    }
    // Settings browse-region picker → sticky config.secret_region, synced to the
    // at-hand picker (ADR 0015).
    {
        let state = state.clone();
        ui.on_set_browse_region(move |region| set_browse_region(&state, region.to_string()));
    }
    // Persist a resized ENTRY column width (#42) on drag release — view-state,
    // never a Value (THREAT-MODEL). Mock-guarded by `maybe_save` (the seeded demo
    // Config is never written to a real org's file). The live width already applies
    // — the drag drives `entry-w` directly — so this only records it for next launch.
    {
        let state = state.clone();
        ui.on_commit_entry_width(move |w| {
            let mut st = state.borrow_mut();
            st.config.set_entry_column_width(w as f64, ENTRY_MIN_PX);
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
    // Read-write mode unlock (ADR 0004 / ADR 0032): forward the deliberate toggle to
    // the worker, which is the authoritative lock (it refuses every write until on).
    // Session-only — never persisted, so a relaunch is read-only again.
    {
        let state = state.clone();
        ui.on_set_read_write(move |on| dispatch(&state, Command::SetReadWrite(on)));
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
                    // Newest-first render → the first line is the latest event, shown
                    // inline on the collapsed Diagnostics strip (the status area).
                    let latest = text.lines().next().unwrap_or("").to_string();
                    ui.set_log_text(text.into());
                    ui.set_log_latest(latest.into());
                }
            },
        );
    }

    // Tick the snapshot label's "N min ago" so it stays honest between manual
    // refreshes (issue #23) — otherwise it's frozen at "just now" forever. A pure
    // clock re-push: no network, no secret activity, consistent with the
    // manual-refresh / no-background-polling model (ADR 0005). Kept alive for the
    // run; no-ops until the first load stamps `snapshot_at`.
    let snapshot_timer = slint::Timer::default();
    {
        let ui_weak = ui.as_weak();
        snapshot_timer.start(
            slint::TimerMode::Repeated,
            Duration::from_secs(30),
            move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let at = STATE.with(|s| s.borrow().as_ref().and_then(|st| st.borrow().snapshot_at));
                if at.is_some() {
                    ui.set_snapshot_label(snapshot_label(at).into());
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

#[cfg(test)]
mod chrome_tests {
    //! Pure-Rust seams for the issue #23 chrome derivations (counts / ARN /
    //! snapshot). These count and format non-secret metadata only — no Values.
    use super::*;
    use janitor_core::compare::{EntryState, RowKey};
    use janitor_core::view::{MatrixRow, MatrixView};

    fn row(state: EntryState) -> MatrixRow {
        MatrixRow {
            key: RowKey::WholeSet,
            name: "x".into(),
            state,
            kind: None,
            cells: Vec::new(),
        }
    }

    #[test]
    fn method_picker_index_maps_to_the_method_and_back_to_a_label() {
        // The Manage-window per-row picker (ADR 0031): index 0 = Secrets Manager
        // (the back-compat default, also for any stray index), 1 = remote .env/SSM.
        assert_eq!(method_from_index(0), Method::SecretsManager);
        assert_eq!(method_from_index(1), Method::SsmDotenv);
        assert_eq!(
            method_from_index(99),
            Method::SecretsManager,
            "out-of-range falls back to the default"
        );
        assert_eq!(method_label(Method::SecretsManager), "SM");
        assert_eq!(method_label(Method::SsmDotenv), "SSM");
    }

    #[test]
    fn state_counts_tallies_each_entry_state() {
        let view = MatrixView {
            environments: vec!["prod".into()],
            rows: vec![
                row(EntryState::Aligned),
                row(EntryState::Aligned),
                row(EntryState::Drift),
                row(EntryState::Gap),
            ],
        };
        assert_eq!(state_counts(&view), (2, 1, 1));
    }

    #[test]
    fn representative_secret_id_is_the_first_env_mapping_or_empty() {
        let mut config = Config::default();
        config.applications.push(Application {
            name: "Payments".into(),
            environments: vec![
                Mapping {
                    environment: "prod".into(),
                    account_id: "111".into(),
                    region: "us-east-1".into(),
                    secret_id: "arn:aws:secretsmanager:us-east-1:111:secret:payments".into(),
                    permission_set: "ps".into(),
                    method: Method::SecretsManager,
                },
                Mapping {
                    environment: "staging".into(),
                    account_id: "222".into(),
                    region: "us-east-1".into(),
                    secret_id: "arn:other".into(),
                    permission_set: "ps".into(),
                    method: Method::SecretsManager,
                },
            ],
        });
        // First env's secret_id is the representative subtitle.
        assert_eq!(
            representative_secret_id(&config, 0),
            "arn:aws:secretsmanager:us-east-1:111:secret:payments"
        );
        // An app with no environments → empty (the view renders "—").
        config.applications.push(Application {
            name: "Empty".into(),
            environments: Vec::new(),
        });
        assert_eq!(representative_secret_id(&config, 1), "");
        // Out-of-range selection → empty (never panics).
        assert_eq!(representative_secret_id(&config, 99), "");
    }

    #[test]
    fn snapshot_label_is_empty_until_first_load_then_renders_a_stamp() {
        // No load yet → empty (the view shows "Not refreshed yet").
        assert_eq!(snapshot_label(None), "");
        // Just loaded → "just now" with a UTC HH:MM stamp.
        let now = std::time::SystemTime::now();
        let label = snapshot_label(Some(now));
        assert!(
            label.starts_with("Snapshot ") && label.contains("just now"),
            "fresh snapshot label was {label:?}"
        );
        // The absolute stamp is the load-bearing, never-stale part: assert the
        // "Snapshot HH:MM UTC" shape (two-digit hour : two-digit minute).
        let after_marker = label.strip_prefix("Snapshot ").unwrap();
        let hhmm = &after_marker[..5];
        let (hh, mm) = hhmm.split_once(':').expect("HH:MM stamp");
        assert!(
            hh.len() == 2
                && mm.len() == 2
                && hh.parse::<u32>().is_ok()
                && mm.parse::<u32>().is_ok(),
            "snapshot stamp is not HH:MM: {label:?}"
        );
        assert!(
            after_marker.contains("UTC"),
            "snapshot stamp missing UTC: {label:?}"
        );

        // The relative clause — "what the user actually reads" — across its branches.
        let ago = |secs| snapshot_label(Some(now - std::time::Duration::from_secs(secs)));
        assert!(ago(90).contains("1 min ago"), "90s ago was {:?}", ago(90));
        assert!(
            ago(7 * 60).contains("7 min ago"),
            "7m ago was {:?}",
            ago(7 * 60)
        );
    }
}
