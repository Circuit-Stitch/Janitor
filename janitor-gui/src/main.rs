slint::include_modules!();

use std::rc::Rc;

use slint::{ModelRc, SharedString, VecModel};

use janitor_core::compare::{Comparison, EntryState};
use janitor_core::config::Mapping;
use janitor_core::mock::MockSource;
use janitor_core::secret::SecretShape;
use janitor_core::source::SecretSource;
use janitor_core::view::{project, MatrixCell, MatrixRow, MatrixView};

/// Hardcoded Payments App for this task (the sidebar/config arrives in Task 9).
fn payments_mappings() -> Vec<Mapping> {
    vec![
        Mapping {
            environment: "prod".into(),
            account_id: "914xxxxxx021".into(),
            region: "us-east-1".into(),
            secret_id: "payments/prod".into(),
            permission_set: "ReadOnly".into(),
        },
        Mapping {
            environment: "staging".into(),
            account_id: "550xxxxxx118".into(),
            region: "us-west-2".into(),
            secret_id: "payments/staging".into(),
            permission_set: "ReadOnly".into(),
        },
    ]
}

/// Fetch every Environment's Set for a set of mappings.
fn fetch_sets(source: &dyn SecretSource, mappings: &[Mapping]) -> Vec<(String, SecretShape)> {
    mappings
        .iter()
        .map(|m| (m.environment.clone(), source.fetch(m).expect("mock never fails")))
        .collect()
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

fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;

    let source = MockSource::new();
    let sets = fetch_sets(&source, &payments_mappings());
    let view = project(&Comparison::build(&sets)); // Comparison is transient — dropped here.

    ui.set_environments(env_models(&view));
    ui.set_rows(to_row_models(&view));

    ui.run()
}
