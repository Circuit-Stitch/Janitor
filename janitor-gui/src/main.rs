slint::include_modules!();
mod worker;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use slint::{ModelRc, SharedString, VecModel};

use janitor_core::compare::{Comparison, EntryState};
use janitor_core::config::{Application, Config, Mapping};
use janitor_core::mock::MockSource;
use janitor_core::secret::SecretShape;
use janitor_core::source::SecretSource;
use janitor_core::view::{
    project, reveal_value, sort_rows, MatrixCell, MatrixRow, MatrixView, SortKey,
};

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
        sso_start_url: "https://acme.awsapps.com/start".into(),
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

/// Fetch every Environment's Set for a set of mappings.
fn fetch_sets(source: &dyn SecretSource, mappings: &[Mapping]) -> Vec<(String, SecretShape)> {
    mappings
        .iter()
        .map(|m| {
            (
                m.environment.clone(),
                source.fetch(m).expect("mock never fails"),
            )
        })
        .collect()
}

/// Build the masked view for one Application from the source.
fn build_app(
    source: &dyn SecretSource,
    app: &Application,
) -> (Vec<(String, SecretShape)>, MatrixView) {
    let sets = fetch_sets(source, &app.environments);
    let view = project(&Comparison::build(&sets));
    (sets, view)
}

fn drift_count(view: &MatrixView) -> usize {
    view.rows
        .iter()
        .filter(|r| r.state == EntryState::Drift)
        .count()
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

/// Sidebar models, marking `selected`.
fn app_models(source: &dyn SecretSource, config: &Config, selected: usize) -> ModelRc<AppItem> {
    let items: Vec<AppItem> = config
        .applications
        .iter()
        .enumerate()
        .map(|(i, app)| {
            let (_, view) = build_app(source, app);
            let n = drift_count(&view);
            AppItem {
                name: app.name.clone().into(),
                subtitle: format!("{} envs", app.environments.len()).into(),
                drift: if n > 0 {
                    format!("{n} drift").into()
                } else {
                    SharedString::new()
                },
                selected: i == selected,
            }
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(items)))
}

struct Preferences {
    sort: SortKey,
    auto_hide_secs: u64,
    dark: bool,
}

/// In-memory state shared across Slint callbacks.
struct AppState {
    source: MockSource,
    config: Config,
    selected: usize,
    prefs: Preferences,
    sets: Vec<(String, SecretShape)>,
    view: MatrixView,
}

/// Rebuild the matrix for the currently-selected Application and push all models.
fn render(ui: &MainWindow, state: &Rc<RefCell<AppState>>) {
    // Any in-flight reveal is stale once the matrix is rebuilt — clear it (ADR 0003).
    ui.set_revealed_row(-1);
    ui.set_revealed_col(-1);
    ui.set_revealed_text(SharedString::new());
    let mut st = state.borrow_mut();
    let selected = st.selected;
    let app = st.config.applications[selected].clone();
    let (sets, mut view) = build_app(&st.source, &app);
    sort_rows(&mut view, st.prefs.sort);
    st.sets = sets;
    st.view = view;
    ui.set_environments(env_models(&st.view));
    ui.set_rows(to_row_models(&st.view));
    ui.set_apps(app_models(&st.source, &st.config, selected));
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;

    let config = seeded_config();
    let state = Rc::new(RefCell::new(AppState {
        source: MockSource::new(),
        config,
        selected: 0,
        prefs: Preferences {
            sort: SortKey::Name,
            auto_hide_secs: 5,
            dark: true,
        },
        sets: Vec::new(),
        view: MatrixView {
            environments: Vec::new(),
            rows: Vec::new(),
        },
    }));

    render(&ui, &state);

    // Sidebar selection.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_select_app(move |index| {
            let ui = ui_weak.unwrap();
            state.borrow_mut().selected = index as usize;
            render(&ui, &state);
        });
    }

    // Reveal: re-borrow plaintext, copy into SharedString, drop borrow, then read prefs.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_reveal_cell(move |row, col| {
            let ui = ui_weak.unwrap();
            // Re-borrow plaintext, copy it into a SharedString, then drop the borrow.
            let revealed: Option<SharedString> = {
                let st = state.borrow();
                st.view
                    .rows
                    .get(row as usize)
                    .and_then(|r| reveal_value(&st.sets, &r.key, col as usize))
                    .map(|v| SharedString::from(v.expose()))
            };
            let Some(text) = revealed else {
                return;
            };

            ui.set_revealed_row(row);
            ui.set_revealed_col(col);
            ui.set_revealed_text(text);

            let secs = state.borrow().prefs.auto_hide_secs;
            let ui_weak = ui.as_weak();
            slint::Timer::single_shot(Duration::from_secs(secs), move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_revealed_text(SharedString::new());
                    ui.set_revealed_row(-1);
                    ui.set_revealed_col(-1);
                }
            });
        });
    }

    // Initialize the SSO fields and theme from config/prefs.
    {
        let st = state.borrow();
        ui.set_sso_start_url(st.config.sso_start_url.as_str().into());
        ui.set_sso_region(st.config.sso_region.as_str().into());
        ui.set_dark(st.prefs.dark);
    }

    // Toggle settings.
    {
        let ui_weak = ui.as_weak();
        ui.on_toggle_settings(move || {
            let ui = ui_weak.unwrap();
            ui.set_settings_open(!ui.get_settings_open());
        });
    }

    // Save SSO fields back into the in-memory config.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_save_sso(move || {
            let ui = ui_weak.unwrap();
            let mut st = state.borrow_mut();
            st.config.sso_start_url = ui.get_sso_start_url().to_string();
            st.config.sso_region = ui.get_sso_region().to_string();
        });
    }

    // Add an Application (auto prod/staging mappings derived from a slug).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_add_app(move |name| {
            let name = name.trim().to_string();
            if name.is_empty() {
                return;
            }
            let slug: String = name
                .to_lowercase()
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '-' })
                .collect();
            let new_app = Application {
                name,
                environments: vec![
                    Mapping {
                        environment: "prod".into(),
                        account_id: "000000000000".into(),
                        region: "us-east-1".into(),
                        secret_id: format!("{slug}/prod"),
                        permission_set: "ReadOnly".into(),
                    },
                    Mapping {
                        environment: "staging".into(),
                        account_id: "000000000000".into(),
                        region: "us-west-2".into(),
                        secret_id: format!("{slug}/staging"),
                        permission_set: "ReadOnly".into(),
                    },
                ],
            };
            {
                let mut st = state.borrow_mut();
                st.config.applications.push(new_app);
            }
            let ui = ui_weak.unwrap();
            render(&ui, &state);
        });
    }

    // Remove an Application, clamping the selection.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_remove_app(move |index| {
            let index = index as usize;
            {
                let mut st = state.borrow_mut();
                if index < st.config.applications.len() && st.config.applications.len() > 1 {
                    st.config.applications.remove(index);
                    if st.selected >= st.config.applications.len() {
                        st.selected = st.config.applications.len() - 1;
                    }
                }
            }
            let ui = ui_weak.unwrap();
            render(&ui, &state);
        });
    }

    // Theme.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_set_theme(move |dark| {
            state.borrow_mut().prefs.dark = dark;
            ui_weak.unwrap().set_dark(dark);
        });
    }

    // Sort.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_set_sort(move |index| {
            state.borrow_mut().prefs.sort = if index == 1 {
                SortKey::GapFirst
            } else {
                SortKey::Name
            };
            let ui = ui_weak.unwrap();
            render(&ui, &state);
        });
    }

    // Auto-hide duration.
    {
        let state = state.clone();
        ui.on_set_auto_hide(move |secs| {
            state.borrow_mut().prefs.auto_hide_secs = secs.max(1) as u64;
        });
    }

    ui.run()
}
