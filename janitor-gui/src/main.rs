slint::include_modules!();

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use slint::{ModelRc, SharedString, VecModel};

use janitor_core::compare::{Comparison, EntryState};
use janitor_core::config::{Application, Config, Mapping};
use janitor_core::mock::MockSource;
use janitor_core::secret::SecretShape;
use janitor_core::source::SecretSource;
use janitor_core::view::{project, reveal_value, MatrixCell, MatrixRow, MatrixView};

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
            app("Payments API", "payments", &[
                ("prod", "914xxxxxx021", "us-east-1"),
                ("staging", "550xxxxxx118", "us-west-2"),
            ]),
            app("Auth Service", "auth", &[
                ("prod", "914xxxxxx021", "us-east-1"),
                ("staging", "550xxxxxx118", "us-west-2"),
                ("dev", "330xxxxxx777", "us-west-2"),
            ]),
            app("Billing Worker", "billing", &[
                ("prod", "914xxxxxx021", "us-east-1"),
                ("staging", "550xxxxxx118", "us-west-2"),
            ]),
            app("Notifications", "notif", &[
                ("prod", "914xxxxxx021", "us-east-1"),
                ("staging", "550xxxxxx118", "us-west-2"),
                ("dev", "330xxxxxx777", "us-west-2"),
                ("qa", "330xxxxxx777", "us-west-2"),
            ]),
        ],
    }
}

/// Fetch every Environment's Set for a set of mappings.
fn fetch_sets(source: &dyn SecretSource, mappings: &[Mapping]) -> Vec<(String, SecretShape)> {
    mappings
        .iter()
        .map(|m| (m.environment.clone(), source.fetch(m).expect("mock never fails")))
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
    let envs: Vec<SharedString> = view.environments.iter().map(|e| e.as_str().into()).collect();
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

/// In-memory state shared across Slint callbacks.
struct AppState {
    source: MockSource,
    config: Config,
    selected: usize,
    sets: Vec<(String, SecretShape)>,
    view: MatrixView,
}

/// Rebuild the matrix for the currently-selected Application and push all models.
fn render(ui: &MainWindow, state: &Rc<RefCell<AppState>>) {
    let mut st = state.borrow_mut();
    let selected = st.selected;
    let app = st.config.applications[selected].clone();
    let (sets, view) = build_app(&st.source, &app);
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

    // Reveal.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_reveal_cell(move |row, col| {
            let ui = ui_weak.unwrap();
            let st = state.borrow();
            let Some(matrix_row) = st.view.rows.get(row as usize) else {
                return;
            };
            if let Some(value) = reveal_value(&st.sets, &matrix_row.key, col as usize) {
                ui.set_revealed_row(row);
                ui.set_revealed_col(col);
                ui.set_revealed_text(SharedString::from(value.expose()));
                let ui_weak = ui.as_weak();
                slint::Timer::single_shot(Duration::from_secs(5), move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_revealed_text(SharedString::new());
                        ui.set_revealed_row(-1);
                        ui.set_revealed_col(-1);
                    }
                });
            }
        });
    }

    ui.run()
}
