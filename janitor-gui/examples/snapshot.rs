//! Dev aid (companion to the ADR 0021 geometry tests): render the matrix with
//! the *real* backend and dump it to a raw RGBA buffer, so layout changes can be
//! eyeballed without screen-grabbing the desktop. The window flashes open for a
//! few hundred ms, snapshots its own framebuffer, and quits.
//!
//! No secret material is involved — the fixture below is synthetic (Entry names
//! and masked dots only, never Values).
//!
//! Usage:
//!   cargo run -p janitor-gui --example snapshot
//! It prints the exact `magick …` line to turn the buffer into a PNG, e.g.:
//!   magick -size 1100x560 -depth 8 rgba:/tmp/janitor-matrix.rgba /tmp/janitor-matrix.png

use slint::{ComponentHandle, LogicalSize, ModelRc, SharedString, Timer, VecModel};
use std::rc::Rc;
use std::time::Duration;

slint::include_modules!();

fn envs(names: &[&str]) -> ModelRc<SharedString> {
    let v: Vec<SharedString> = names.iter().map(|n| SharedString::from(*n)).collect();
    ModelRc::from(Rc::new(VecModel::from(v)))
}

fn present(len: &str, hex: &str) -> CellView {
    CellView {
        absent: false,
        dots: SharedString::from("··········"),
        length: SharedString::from(len),
        hex: SharedString::from(hex),
    }
}

fn absent() -> CellView {
    CellView {
        absent: true,
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn row(
    idx: i32,
    prefix: &str,
    leaf: &str,
    badge: &str,
    state: &str,
    glyph: &str,
    zebra: bool,
    cells: Vec<CellView>,
) -> MatrixItemView {
    MatrixItemView {
        is_header: false,
        row_index: idx,
        prefix: SharedString::from(prefix),
        leaf: SharedString::from(leaf),
        badge: SharedString::from(badge),
        state: SharedString::from(state),
        glyph: SharedString::from(glyph),
        zebra,
        cells: ModelRc::from(Rc::new(VecModel::from(cells))),
        ..Default::default()
    }
}

fn header(label: &str, count: i32) -> MatrixItemView {
    MatrixItemView {
        is_header: true,
        label: SharedString::from(label),
        count,
        ..Default::default()
    }
}

/// A representative 3-env matrix: two prefix clusters (dotted + underscore), lone
/// rows, type badges, and Aligned/Drift/Gap states with present + absent cells.
fn sample_matrix() -> ModelRc<MatrixItemView> {
    let p = || {
        vec![
            present("24", "a1b2c3"),
            present("24", "a1b2c3"),
            present("24", "a1b2c3"),
        ]
    };
    let items = vec![
        header("database.*", 2),
        row(
            0,
            "database.primary.",
            "url",
            "STRING",
            "Drift",
            "≠",
            false,
            vec![
                present("31", "9f0e1d"),
                present("28", "44aa11"),
                present("33", "0c0c0c"),
            ],
        ),
        row(
            1,
            "database.primary.",
            "pass",
            "STRING",
            "Aligned",
            "=",
            true,
            p(),
        ),
        header("GITHUB_APP_*", 2),
        row(2, "GITHUB_APP_", "ID", "NUMBER", "Aligned", "=", false, p()),
        row(
            3,
            "GITHUB_APP_",
            "KEY",
            "STRING",
            "Gap",
            "∅",
            true,
            vec![present("40", "ee33aa"), absent(), present("40", "ee33aa")],
        ),
        row(
            4,
            "",
            "STRIPE_KEY",
            "STRING",
            "Gap",
            "∅",
            false,
            vec![present("36", "7711cc"), absent(), absent()],
        ),
        row(5, "", "LOG_LEVEL", "STRING", "Aligned", "=", false, p()),
    ];
    ModelRc::from(Rc::new(VecModel::from(items)))
}

fn main() -> Result<(), slint::PlatformError> {
    let (w, h) = (1100.0_f32, 560.0_f32);
    let ui = MainWindow::new()?;
    ui.set_pane(SharedString::from("matrix"));
    ui.set_dark(true);
    ui.set_grouped(true);
    ui.set_environments(envs(&["prod", "staging", "dev"]));
    ui.set_items(sample_matrix());
    ui.window().set_size(LogicalSize::new(w, h));
    ui.show()?;

    let ui_weak = ui.as_weak();
    // Snapshot after a couple frames have rendered, then quit.
    Timer::single_shot(Duration::from_millis(1200), move || {
        let ui = ui_weak.upgrade().unwrap();
        match ui.window().take_snapshot() {
            Ok(buf) => {
                let (pw, ph) = (buf.width(), buf.height());
                let path = "/tmp/janitor-matrix.rgba";
                std::fs::write(path, buf.as_bytes()).expect("write rgba buffer");
                eprintln!("SNAPSHOT {pw}x{ph} -> {path}");
                eprintln!(
                    "PNG:  magick -size {pw}x{ph} -depth 8 rgba:{path} /tmp/janitor-matrix.png"
                );
            }
            Err(e) => eprintln!("snapshot failed: {e}"),
        }
        slint::quit_event_loop().expect("quit");
    });

    slint::run_event_loop()?;
    Ok(())
}
