//! Spike (tracer bullet): prove the headless Slint testing backend works in
//! this repo, and use it to lock in the ADR 0020 env-band layout fix.
//!
//! What this demonstrates about the harness:
//!   * `i_slint_backend_testing::init_no_event_loop()` lets us create a
//!     `MainWindow`, set its `in` properties, force a window size, and read
//!     **real, non-zero** element geometry — all headlessly, no event loop, no
//!     real window. The `ElementHandle` query API needs the Slint compiler's
//!     element debug info; `build.rs` enables it for debug builds via
//!     `CompilerConfiguration::with_debug_info(true)` (equivalent to
//!     `SLINT_EMIT_DEBUG_INFO=1`), so `cargo test` works with no extra env var.
//!   * Repeated `for` elements are found via `accessible-label`s that encode
//!     ONLY structural / positional info (the column index, or a band name) —
//!     never a Value, the masked dots, or a length (THREAT-MODEL).
//!
//! What it asserts about the UI (ADR 0020):
//!   1. ALIGNMENT: header env column N and body env column N step left-to-right
//!      by exactly `env-w`, packed flush, in lockstep — i.e. column N of the
//!      header sits at the same offset-from-its-band as column N of the body, so
//!      they line up at any window width. (Measured relative to each band's own
//!      origin, which factors out the constant `ScrollView` chrome offset the
//!      headless style adds around the body — see the module note below.)
//!   2. NO-SPREAD / FILLS THE WINDOW: with the `alignment: start` fix present the
//!      env band's max-width stays infinite, so it STRETCHES to fill a window far
//!      wider than the table (band width ≫ table-of-columns width). This is the
//!      exact property `alignment: start` controls; removing it collapses the
//!      band to the columns' intrinsic width and the table stops filling the
//!      window — the RED state.
//!
//! Note on the literal "header.x == body.x" check: the body env region is
//! wrapped in a `std-widgets` `ScrollView`, and the headless testing backend's
//! style reserves a different amount of chrome around it than the real (fluent)
//! renderer, shifting the whole body region right by a constant. So absolute
//! header.x vs body.x is NOT equal headlessly even when the columns are
//! correctly aligned. We therefore assert the renderer-independent invariant:
//! identical per-column step within each band. See the spike report for detail.

#![cfg(test)]

use slint::{ComponentHandle, LogicalSize, ModelRc, SharedString, VecModel};
use std::rc::Rc;

use crate::{CellView, MainWindow, MatrixItemView};
use i_slint_backend_testing::ElementHandle;

const ENV_W: f32 = 200.0; // must match `env-w` in app.slint
const ENV_COUNT: usize = 2;

/// One non-header data row with `env_count` present cells. The cell text is a
/// short structural fixture, never a real Value.
fn data_row(env_count: usize) -> MatrixItemView {
    let cells: Vec<CellView> = (0..env_count)
        .map(|_| CellView {
            absent: false,
            dots: SharedString::from("··"),
            length: SharedString::from("2"),
            hex: SharedString::from("ab"),
        })
        .collect();
    MatrixItemView {
        is_header: false,
        row_index: 0,
        state: SharedString::from("Aligned"),
        glyph: SharedString::from("="),
        cells: ModelRc::from(Rc::new(VecModel::from(cells))),
        ..Default::default()
    }
}

/// Exactly-one ElementHandle for a structural label (labels are unique per
/// column / band in the fixture); fail loudly otherwise.
fn one_by_label(ui: &MainWindow, label: &str) -> ElementHandle {
    let found: Vec<ElementHandle> = ElementHandle::find_by_accessible_label(ui, label).collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one element labelled {label:?}, found {} \
         (is SLINT_EMIT_DEBUG_INFO=1 set at build time?)",
        found.len()
    );
    found.into_iter().next().unwrap()
}

fn header_x(ui: &MainWindow, col: usize) -> f32 {
    one_by_label(ui, &format!("envhead-{col}"))
        .absolute_position()
        .x
}
fn body_x(ui: &MainWindow, col: usize) -> f32 {
    one_by_label(ui, &format!("envcell-{col}"))
        .absolute_position()
        .x
}

/// Build the window, feed it a 2-env / 1-row matrix, and force it WIDE so any
/// column spread / band collapse is geometrically obvious. Returns the window
/// (kept alive by the caller).
fn matrix_window() -> MainWindow {
    let ui = MainWindow::new().expect("create MainWindow");
    ui.set_pane(SharedString::from("matrix"));
    ui.set_environments(ModelRc::from(Rc::new(VecModel::from(vec![
        SharedString::from("prod"),
        SharedString::from("staging"),
    ]))));
    ui.set_items(ModelRc::from(Rc::new(VecModel::from(vec![data_row(
        ENV_COUNT,
    )]))));

    // Table content ≈ entry(300) + state(46) + 2*env(200) = 746px; 1400px
    // leaves ~650px of slack the band must absorb (GREEN) — or spread into (RED).
    ui.window().set_size(LogicalSize::new(1400.0, 700.0));
    // Advance the mock clock once so the layout pass settles and geometry /
    // absolute_position() are populated.
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    ui
}

#[test]
fn env_columns_align_and_band_fills_window() {
    // MUST initialise the backend before creating any window.
    i_slint_backend_testing::init_no_event_loop();

    let ui = matrix_window();

    // --- (1) ALIGNMENT: header col N and body col N share the same per-column
    // step (env-w), measured relative to each band's own column-0 origin. This
    // is the renderer-independent statement of "header column N sits above body
    // column N". ---
    let h0 = header_x(&ui, 0);
    let b0 = body_x(&ui, 0);
    for col in 0..ENV_COUNT {
        let h_off = header_x(&ui, col) - h0;
        let b_off = body_x(&ui, col) - b0;
        let want = col as f32 * ENV_W;
        assert!(
            (h_off - want).abs() <= 1.0,
            "header column {col} offset {h_off} != {want} (env-w step) — header columns spread/misaligned"
        );
        assert!(
            (b_off - want).abs() <= 1.0,
            "body column {col} offset {b_off} != {want} (env-w step) — body columns spread/misaligned"
        );
        assert!(
            (h_off - b_off).abs() <= 1.0,
            "header col {col} (off {h_off}) and body col {col} (off {b_off}) must line up within 1px"
        );
    }

    // --- (2) NO-SPREAD / FILLS WINDOW: with `alignment: start`, the env band's
    // max-width stays infinite, so it stretches to fill the wide window — its
    // width is far greater than the columns' intrinsic width (ENV_COUNT*env-w).
    // Removing `alignment: start` (RED) collapses the band to that intrinsic
    // width and the table no longer fills the window. ---
    let band_w = one_by_label(&ui, "envhead-band").size().width;
    let intrinsic = ENV_COUNT as f32 * ENV_W; // 400px
    eprintln!(
        "env-head band width = {band_w} (intrinsic columns width = {intrinsic}); \
         header col0.x={h0}, body col0.x={b0}"
    );
    assert!(
        band_w > intrinsic + 50.0,
        "env band width {band_w} did not stretch past the columns' intrinsic \
         width {intrinsic} — `alignment: start` missing? The band collapsed and \
         the table stops filling the window (ADR 0020 regression)."
    );
}

// --- Issue #23: Settings + chrome polish (cosmetic layout pass). The settings
// overlay must render as a centered, constrained-width card (not full-bleed); the
// top bar carries a read-only badge + identity + breadcrumb; the bottom status bar
// carries identity, session time, memory-only / manual-refresh notes, and the
// Drift/Aligned/Gap legend WITH COUNTS; the main header carries the Application
// title + Secret ARN subtitle + a snapshot timestamp. All chrome facts are pushed
// from Rust as `in` properties (no Values — identity / ARN / timestamps / counts
// only). Geometry assertions use only size + relative inset (renderer-independent
// per ADR 0021). ---

/// A wide window (1400px) with the settings overlay open, so the card's bounded
/// width and centering are geometrically obvious.
fn settings_window() -> MainWindow {
    let ui = MainWindow::new().expect("create MainWindow");
    ui.set_settings_open(true);
    ui.window().set_size(LogicalSize::new(1400.0, 800.0));
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    ui
}

#[test]
fn settings_renders_as_a_centered_bounded_width_card() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = settings_window();

    // The card is a structural anchor (a Rectangle needs a role to carry a label).
    let card = one_by_label(&ui, "settings-card");
    let card_pos = card.absolute_position();
    let card_w = card.size().width;

    // (1) BOUNDED: in a 1400px window the card stays a constrained card, not a
    // full-bleed panel. The spec calls for ~520–560px; allow generous slack.
    assert!(
        card_w <= 600.0,
        "settings card width {card_w} is not bounded to a card (≤600px) in a 1400px window"
    );

    // (2) CENTERED: the left inset ≈ the right inset. Both are relative facts
    // (size + position within the window), reliable headlessly.
    let win_w = ui.window().size().width as f32; // physical px == logical at scale 1
    let left = card_pos.x;
    let right = win_w - (card_pos.x + card_w);
    assert!(
        (left - right).abs() <= 4.0,
        "settings card is not centered: left inset {left} != right inset {right}"
    );
}

#[test]
fn top_bar_carries_read_only_badge_and_identity_and_breadcrumb() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new().expect("create MainWindow");
    ui.set_identity("ops@acme".into());
    ui.set_app_title("Payments API".into());
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));

    // The read-only badge (v1 ships read-only — ADR 0004) is always present.
    one_by_label(&ui, "topbar-readonly");
    // Identity + breadcrumb anchors are present (their text is fed by properties).
    one_by_label(&ui, "topbar-identity");
    one_by_label(&ui, "topbar-breadcrumb");
}

#[test]
fn bottom_status_bar_carries_session_notes_and_legend_with_counts() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new().expect("create MainWindow");
    ui.set_aligned_count(5);
    ui.set_drift_count(2);
    ui.set_gap_count(1);
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));

    // Session/status bar anchors: identity, session-remaining, the memory-only
    // note, and the manual-refresh / no-background-polling note (ADR 0005).
    one_by_label(&ui, "statusbar-identity");
    one_by_label(&ui, "statusbar-session");
    one_by_label(&ui, "statusbar-memory-note");
    one_by_label(&ui, "statusbar-refresh-note");

    // The legend shows COUNTS. A `Text` carries its content as its implicit
    // accessible-label, so the counted phrases must each match exactly one element.
    assert_eq!(
        ElementHandle::find_by_accessible_label(&ui, "Aligned 5").count(),
        1,
        "legend must show the Aligned count"
    );
    assert_eq!(
        ElementHandle::find_by_accessible_label(&ui, "Drift 2").count(),
        1,
        "legend must show the Drift count"
    );
    assert_eq!(
        ElementHandle::find_by_accessible_label(&ui, "Gap 1").count(),
        1,
        "legend must show the Gap count"
    );
}

#[test]
fn main_header_carries_arn_subtitle_and_snapshot_anchor() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new().expect("create MainWindow");
    // The main header lives above the matrix toolbar; it shows for the matrix pane.
    ui.set_pane("matrix".into());
    ui.set_app_title("Payments API".into());
    ui.set_secret_arn("arn:aws:secretsmanager:us-east-1:111:secret:payments".into());
    ui.set_snapshot_label("Snapshot 14:05 / 2 min ago".into());
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));

    one_by_label(&ui, "header-arn");
    one_by_label(&ui, "header-snapshot");
}
