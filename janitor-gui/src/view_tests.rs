//! Spike (tracer bullet): prove the headless Slint testing backend works in
//! this repo, and use it to lock in the env-band layout — originally the ADR
//! 0020 resize fix, now the ADR 0023 column-sizing model (stretch-to-fill down
//! to a content floor; below the floor, hold the floor and scroll).
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
//! What it asserts about the UI (ADR 0023 column-sizing model):
//!   1. STRETCH-TO-FILL: with few columns and a wide window the Comparison
//!      Columns share the available env width and stretch past the content floor
//!      to fill it (no right-hand gutter).
//!   2. HOLD-FLOOR-AND-SCROLL: with many columns (or a narrow window) the columns
//!      stop shrinking at the floor and the env region's content grows past the
//!      visible band, so it scrolls horizontally.
//!   3. ALIGNMENT: header env column N sits directly above body env column N —
//!      the two bands share the same env-region ORIGIN (column 0 at the same
//!      absolute x) AND the same per-column step (`col-w`), at every window width.
//!      One shared `col-w` drives both bands and the frozen ENTRY/STATE column is
//!      pinned to a fixed width, so neither origin nor step drifts.
//!
//! Note on absolute origin alignment: the body env region is wrapped in a
//! `std-widgets` `ScrollView`, and the frozen ENTRY/STATE column beside it is
//! pinned to `state-w + entry-w` (a bare `VerticalLayout` there defaults to
//! horizontal-stretch 1 and would otherwise balloon to half the viewport, shoving
//! the body env region sideways — the regression `assert_header_body_aligned`
//! guards). With the column pinned, the body env origin equals the header band's,
//! so we assert absolute alignment directly rather than only equal per-column step
//! (a step-only check cancels any constant offset and would miss exactly that drift).

#![cfg(test)]

use slint::{ComponentHandle, LogicalSize, ModelRc, SharedString, VecModel};
use std::rc::Rc;

use crate::{CellView, MainWindow, MatrixItemView};
use i_slint_backend_testing::ElementHandle;

const ENV_FLOOR: f32 = 200.0; // must match `env-floor` in app.slint (the content floor)
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

/// Build the window, feed it an `env_count`-env / 1-row matrix at a forced window
/// size, and settle the layout so geometry is populated. Returns the window (kept
/// alive by the caller). The env names are structural fixtures, never Values.
fn matrix_window_n(env_count: usize, w: f32, h: f32) -> MainWindow {
    let ui = MainWindow::new().expect("create MainWindow");
    ui.set_pane(SharedString::from("matrix"));
    let envs: Vec<SharedString> = (0..env_count)
        .map(|j| SharedString::from(format!("env{j}")))
        .collect();
    ui.set_environments(ModelRc::from(Rc::new(VecModel::from(envs))));
    ui.set_items(ModelRc::from(Rc::new(VecModel::from(vec![data_row(
        env_count,
    )]))));
    ui.window().set_size(LogicalSize::new(w, h));
    // Advance the mock clock once so the layout pass settles and geometry /
    // absolute_position() are populated.
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    ui
}

/// The default fixture: a 2-env / 1-row matrix in a WIDE window, so any column
/// spread / band collapse is geometrically obvious.
fn matrix_window() -> MainWindow {
    matrix_window_n(ENV_COUNT, 1400.0, 700.0)
}

/// The body's per-column width = the absolute-x step between adjacent env cells
/// (chrome offset cancels in the difference). Needs ≥2 env columns.
fn body_col_w(ui: &MainWindow) -> f32 {
    body_x(ui, 1) - body_x(ui, 0)
}

// --- Issue #41 / ADR 0023: the Comparison Columns stretch to fill the available
// env width down to a content floor, and below the floor hold the floor and the
// env region scrolls horizontally. The Environment-name header stays metric-locked
// above its own column at every width. (env-w is gone; the floor is `env-floor`.)

#[test]
fn env_columns_stretch_to_fill_when_few_and_wide() {
    // MUST initialise the backend before creating any window.
    i_slint_backend_testing::init_no_event_loop();

    // Two env columns in a wide (1400px) window: there is far more room than
    // 2*floor, so the columns must STRETCH past the floor and together fill the
    // band — no empty right-hand gutter (AC1). The old fixed-200 layout pinned
    // each column at the floor and left the slack as a gutter (RED).
    let ui = matrix_window();

    let col_w = body_col_w(&ui);
    let band_w = one_by_label(&ui, "envhead-band").size().width;
    eprintln!("stretch: col_w={col_w} band_w={band_w} floor={ENV_FLOOR}");

    // (1) STRETCH: each column is meaningfully wider than the floor (the slack
    // landed in the columns, not in a gutter).
    assert!(
        col_w > ENV_FLOOR + 50.0,
        "env column width {col_w} did not stretch past the floor {ENV_FLOOR} — \
         columns still pinned to the floor, leaving a right-hand gutter (AC1)"
    );

    // (2) FILLS: the N columns together span the whole band (no gutter). With
    // col_w = band/N above the floor, N*col_w == band within rounding.
    let columns_w = col_w * ENV_COUNT as f32;
    assert!(
        (columns_w - band_w).abs() <= 2.0,
        "columns span {columns_w} but the band is {band_w} — a gutter remains (AC1)"
    );
}

#[test]
fn env_columns_hold_floor_and_scroll_when_many() {
    i_slint_backend_testing::init_no_event_loop();

    // Eight env columns in a moderate (1000px) window: there is far LESS room than
    // 8*floor, so the columns must NOT shrink below the floor — they hold it and
    // the env region's content grows past the visible band (it scrolls). (AC2.)
    const MANY: usize = 8;
    let ui = matrix_window_n(MANY, 1000.0, 700.0);

    let col_w = body_col_w(&ui);
    let band_w = one_by_label(&ui, "envhead-band").size().width;
    eprintln!("floor: col_w={col_w} band_w={band_w} floor={ENV_FLOOR}");

    // (1) HOLDS THE FLOOR: each column is exactly the floor, not the squeezed
    // band/N (~48px) it would be if the columns kept shrinking.
    assert!(
        (col_w - ENV_FLOOR).abs() <= 1.0,
        "env column width {col_w} did not hold the floor {ENV_FLOOR} when many columns \
         don't fit — columns shrank below the content floor (AC2)"
    );

    // (2) SCROLLS: the columns' total width exceeds the visible band, so there is
    // a horizontal scroll region (the env viewport is wider than what's shown).
    let columns_w = col_w * MANY as f32;
    assert!(
        columns_w > band_w + 50.0,
        "columns span {columns_w} but the band is only {band_w} — the env region is \
         not wider than the viewport, so it would not scroll horizontally (AC2)"
    );
}

/// Assert the env-name header sits directly above its column's cells: the header
/// band and the body share the SAME env-region origin (column 0 starts at the same
/// absolute x) AND advance by the SAME per-column step. Equal origin + equal step
/// ⇒ header column N lands exactly above body column N for all N (checked at the
/// two always-visible leftmost columns; off-screen `for` columns aren't
/// instantiated by the Flickable). The ORIGIN check is the regression guard: a
/// frozen column that stretches (a VerticalLayout defaults to stretch 1) balloons
/// to half the viewport and shoves the whole body env region sideways while the
/// fixed-width header band stays put — a window-width-dependent drift that an
/// equal-step-only check (which cancels any constant offset) silently passes.
fn assert_header_body_aligned(ui: &MainWindow) {
    let h0 = header_x(ui, 0);
    let b0 = body_x(ui, 0);
    assert!(
        (h0 - b0).abs() <= 1.0,
        "env header column 0 starts at x={h0} but body column 0 at x={b0} — the env \
         region's origin differs between the bands, so every header sits off its own \
         cells (AC3)"
    );
    let h_step = header_x(ui, 1) - header_x(ui, 0);
    let b_step = body_x(ui, 1) - body_x(ui, 0);
    assert!(
        (h_step - b_step).abs() <= 1.0,
        "header per-column step {h_step} != body per-column step {b_step} — the env \
         header drifts across columns (AC3)"
    );
}

#[test]
fn env_header_and_body_columns_stay_aligned() {
    i_slint_backend_testing::init_no_event_loop();

    // AC3: the env-name header stays directly above its own column's cells at
    // every width — columns STRETCH wide (1400) and narrower (1100), and HOLD THE
    // FLOOR and scroll (8 cols / 1000). One `col-w` drives both bands and the
    // frozen column is pinned, so neither the origin nor the step drifts.
    assert_header_body_aligned(&matrix_window());
    assert_header_body_aligned(&matrix_window_n(2, 1100.0, 700.0));
    assert_header_body_aligned(&matrix_window_n(8, 1000.0, 700.0));
}

// --- Issue #38: STATE is the leftmost frozen column (left of ENTRY), and the
// ENTRY cell is one line — the status dot and the secondary state word are gone,
// so the glyph in the STATE column is the row's only state carrier. ---

#[test]
fn state_column_is_frozen_left_of_entry() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = matrix_window();

    // Header band: the STATE header sits left of the ENTRY header. Both live in
    // the same band OUTSIDE the body ScrollView, so absolute x is reliable and
    // directly comparable (no ScrollView chrome offset to factor out).
    let state_hdr = one_by_label(&ui, "statehdr").absolute_position().x;
    let entry_hdr = one_by_label(&ui, "entryhdr").absolute_position().x;
    assert!(
        state_hdr < entry_hdr,
        "STATE header (x={state_hdr}) must be left of ENTRY header (x={entry_hdr})"
    );

    // Body: the frozen STATE glyph cell sits left of the ENTRY cell. Both are in
    // one HorizontalLayout inside the ScrollView, so their relative order holds
    // even though absolute x carries the (shared) ScrollView chrome offset.
    let state_cell = one_by_label(&ui, "state-cell").absolute_position().x;
    let entry_cell = one_by_label(&ui, "entry-cell").absolute_position().x;
    assert!(
        state_cell < entry_cell,
        "STATE cell (x={state_cell}) must be left of ENTRY cell (x={entry_cell})"
    );

    // STATE is the SOLE state carrier: assert the coloured glyph actually renders
    // (= for the Aligned fixture row). A Text exposes its content as its implicit
    // accessible-label, so finding "=" confirms the glyph is present — not just the
    // cell. Without this, a dropped glyph would still pass the position checks.
    assert_eq!(
        ElementHandle::find_by_accessible_label(&ui, "=").count(),
        1,
        "the STATE column's glyph must render as the row's sole state carrier"
    );
}

#[test]
fn entry_cell_is_single_line_with_no_state_word() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = matrix_window();

    // The secondary state word ("Aligned"/"Drift"/"Gap") no longer renders in the
    // ENTRY cell. A `Text` exposes its content as its implicit accessible-label,
    // so the word being absent means zero elements carry it. (The fixture row's
    // state is "Aligned"; the STATE glyph is "=", never the word.)
    let state_word_hits = ElementHandle::find_by_accessible_label(&ui, "Aligned").count();
    assert_eq!(
        state_word_hits, 0,
        "the secondary state word must be gone from the ENTRY cell (found {state_word_hits})"
    );

    // Row height is now single-line (name + symmetric padding ≈ 30px), well below
    // the old two-line height (~49px). The ENTRY cell fills the row, so its height
    // is the row height — `size()` is reliable headlessly (only offsets aren't).
    let h = one_by_label(&ui, "entry-cell").size().height;
    assert!(
        (20.0..40.0).contains(&h),
        "ENTRY cell height {h} is not single-line (expected ~30px; two-line was ~49px)"
    );
}

// --- Issue #40: a grouped/elided ENTRY name is safe because hovering reveals the
// full (un-stripped) name and clicking copies it. ---

/// A one-row matrix whose row carries an explicit `full_name` (and the
/// prefix/leaf it would render when prefix-stripped).
fn one_row_matrix(full_name: &str, prefix: &str, leaf: &str) -> MainWindow {
    let ui = MainWindow::new().expect("create MainWindow");
    ui.set_pane(SharedString::from("matrix"));
    ui.set_environments(ModelRc::from(Rc::new(VecModel::from(vec![
        SharedString::from("prod"),
    ]))));
    let cells = vec![CellView {
        absent: false,
        dots: SharedString::from("··"),
        length: SharedString::from("2"),
        hex: SharedString::from("ab"),
    }];
    let item = MatrixItemView {
        is_header: false,
        row_index: 0,
        prefix: SharedString::from(prefix),
        leaf: SharedString::from(leaf),
        full_name: SharedString::from(full_name),
        state: SharedString::from("Aligned"),
        glyph: SharedString::from("="),
        cells: ModelRc::from(Rc::new(VecModel::from(cells))),
        ..Default::default()
    };
    ui.set_items(ModelRc::from(Rc::new(VecModel::from(vec![item]))));
    ui.window().set_size(LogicalSize::new(1000.0, 400.0));
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    ui
}

#[test]
fn value_cell_press_fires_reveal_cell() {
    i_slint_backend_testing::init_no_event_loop();
    // The value cells live in the env-body (now non-interactive, so the cell
    // TouchAreas own their grab — an interactive Flickable would instead defer the
    // press and synthesise a tap at release, breaking press-and-hold). A press on
    // envcell-0 must fire reveal-cell with (row=0, col=0).
    let ui = matrix_window();

    let pressed = Rc::new(std::cell::RefCell::new(None::<(i32, i32)>));
    {
        let pressed = pressed.clone();
        ui.on_reveal_cell(move |r, c| *pressed.borrow_mut() = Some((r, c)));
    }

    one_by_label(&ui, "envcell-0").mock_single_click(slint::platform::PointerEventButton::Left);

    assert_eq!(
        *pressed.borrow(),
        Some((0, 0)),
        "pressing a value cell must reach its TouchArea and fire reveal-cell — \
         if None, the env-body Flickable is swallowing the press (the regression)"
    );
}

/// The cell centre in logical window coordinates, for raw pointer dispatch.
fn cell_center(ui: &MainWindow, label: &str) -> slint::LogicalPosition {
    let h = one_by_label(ui, label);
    let p = h.absolute_position();
    let s = h.size();
    slint::LogicalPosition::new(p.x + s.width / 2.0, p.y + s.height / 2.0)
}

#[test]
fn value_cell_reveals_while_held_and_hides_on_release() {
    use slint::platform::{PointerEventButton, WindowEvent};
    i_slint_backend_testing::init_no_event_loop();
    // Press-and-hold momentary reveal: while the left button is held over a value
    // cell, the worker-supplied plaintext shows; releasing hides it at once. The
    // worker round-trip is simulated here by setting revealed-* on the press (in
    // the real app the Revealed event does this); the GATE is the live press+hover,
    // so the clear-on-release must hide it.
    let ui = matrix_window();
    let pos = cell_center(&ui, "envcell-0");
    let window = ui.window();

    // Press and hold: move to the cell (→ hover) then press (→ reveal-cell). The
    // worker reply lands as revealed-* for (row 0, col 0).
    window.dispatch_event(WindowEvent::PointerMoved { position: pos });
    window.dispatch_event(WindowEvent::PointerPressed {
        position: pos,
        button: PointerEventButton::Left,
    });
    ui.set_revealed_row(0);
    ui.set_revealed_col(0);
    ui.set_revealed_text("SECRETVAL".into());
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));

    // A Text exposes its content as its implicit accessible-label, so the plaintext
    // renders iff this finds it. While held, it must show.
    assert_eq!(
        ElementHandle::find_by_accessible_label(&ui, "SECRETVAL").count(),
        1,
        "the Value must be revealed while the cell is held"
    );

    // Release: the up handler zeroes revealed-* → the gate closes → plaintext gone.
    window.dispatch_event(WindowEvent::PointerReleased {
        position: pos,
        button: PointerEventButton::Left,
    });
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));

    assert_eq!(
        ElementHandle::find_by_accessible_label(&ui, "SECRETVAL").count(),
        0,
        "releasing the cell must hide the Value immediately"
    );
}

#[test]
fn collapsed_diagnostics_strip_shows_the_latest_log_line() {
    i_slint_backend_testing::init_no_event_loop();
    // The collapsed "Diagnostics" strip is the status area: it shows the newest log
    // line inline (e.g. "NAME[env] copied to clipboard"). A Text exposes its content
    // as its implicit accessible-label, so the line is findable by its text.
    let ui = MainWindow::new().expect("create MainWindow");
    ui.set_log_latest("STRIPE_API_KEY[prod] copied to clipboard".into());

    // Collapsed (default): the latest line shows on the strip.
    ui.set_log_open(false);
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    assert_eq!(
        ElementHandle::find_by_accessible_label(&ui, "STRIPE_API_KEY[prod] copied to clipboard")
            .count(),
        1,
        "the collapsed Diagnostics strip must show the latest log line"
    );

    // Expanded: the inline status line is replaced by the full stream below, so the
    // strip's inline copy is gone.
    ui.set_log_open(true);
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    assert_eq!(
        ElementHandle::find_by_accessible_label(&ui, "STRIPE_API_KEY[prod] copied to clipboard")
            .count(),
        0,
        "expanding the log removes the inline status line (the full stream shows instead)"
    );
}

#[test]
fn entry_hover_reveals_full_name_and_left_click_does_not_copy() {
    i_slint_backend_testing::init_no_event_loop();
    // A grouped row would show only "primary.url"; the un-stripped name is the full one.
    let ui = one_row_matrix("database.primary.url", "primary.", "url");

    let copied = Rc::new(std::cell::RefCell::new(String::new()));
    {
        let copied = copied.clone();
        ui.on_copy_entry(move |name| *copied.borrow_mut() = name.to_string());
    }

    // The full-name overlay is hidden until the cell is hovered.
    assert_eq!(
        ElementHandle::find_by_accessible_label(&ui, "entry-full").count(),
        0,
        "the full-name overlay must stay hidden until the ENTRY cell is hovered"
    );

    // mock_single_click routes through window hit-testing: it moves the pointer to
    // the cell centre (→ hover) before a LEFT press/release.
    one_by_label(&ui, "entry-cell").mock_single_click(slint::platform::PointerEventButton::Left);

    // Hover still reveals the full (un-stripped) name — the elision safety net.
    assert_eq!(
        ElementHandle::find_by_accessible_label(&ui, "entry-full").count(),
        1,
        "hovering the ENTRY cell must reveal the full (un-stripped) Entry name"
    );
    // But a LEFT click no longer copies — copy moved to the right-click menu (the
    // native ContextMenuArea can't render headlessly, so the menu Copy path is
    // verified by running the app, not here).
    assert_eq!(
        *copied.borrow(),
        "",
        "a left click on the ENTRY name must NOT copy (copy is now right-click only)"
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
fn settings_card_keeps_its_controls_after_the_restructure() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = settings_window();

    // A full-block rewrite is exactly where a control silently goes missing, so
    // assert each relocated Preferences control still renders in the new card.
    for label in [
        "settings-card",
        "settings-theme",
        "settings-sort",
        // "settings-reveal" removed: press-and-hold replaced the timed reveal,
        // so the "Reveal seconds" SpinBox no longer exists.
    ] {
        assert_eq!(
            ElementHandle::find_by_accessible_label(&ui, label).count(),
            1,
            "settings control {label:?} did not survive the card restructure"
        );
    }
    // The text-bearing action buttons survive too (found by their caption, the
    // implicit accessible-label of a Button).
    for caption in ["Save accounts", "Add application"] {
        assert!(
            ElementHandle::find_by_accessible_label(&ui, caption).count() >= 1,
            "settings button {caption:?} did not survive the card restructure"
        );
    }

    // And the Dark-theme switch is still WIRED, not merely rendered: a real
    // press/release routed through hit-testing toggles it and fires set-theme.
    let fired = Rc::new(std::cell::RefCell::new(false));
    {
        let fired = fired.clone();
        ui.on_set_theme(move |_| *fired.borrow_mut() = true);
    }
    one_by_label(&ui, "settings-theme")
        .mock_single_click(slint::platform::PointerEventButton::Left);
    assert!(
        *fired.borrow(),
        "toggling the Dark-theme switch must still fire set-theme after the restructure"
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

// --- Issue #42: sticky group headers + a resizable, persisted ENTRY column. ---

// MUST match `entry-min` and `entry-w`'s default in app.slint (the resize floor /
// default), the way ENV_FLOOR mirrors `env-floor`.
const ENTRY_MIN: f32 = 200.0;
const ENTRY_DEFAULT: f32 = 300.0;
// MUST match `header-h` / `row-h` in app.slint (font-size + 2·row-pad): the row
// kinds the sticky-header offset math sums. header-h = 11 + 2·8; row-h = 14 + 2·8.
const HEADER_H: f32 = 27.0;
const ROW_H: f32 = 30.0;

fn label_count(ui: &MainWindow, label: &str) -> usize {
    ElementHandle::find_by_accessible_label(ui, label).count()
}

#[test]
fn entry_column_drag_handle_resizes_and_clamps_to_the_floor_and_persists_on_release() {
    use slint::platform::{PointerEventButton, WindowEvent};
    i_slint_backend_testing::init_no_event_loop();
    // A wide window so there is room to drag the ENTRY column wider without the
    // env columns hitting their floor (the drag is about the frozen column).
    let ui = matrix_window();
    let window = ui.window();

    // Capture the persisted width on release (the real app routes this to
    // Config::set_entry_column_width).
    let committed = Rc::new(std::cell::RefCell::new(None::<f32>));
    {
        let committed = committed.clone();
        ui.on_commit_entry_width(move |w| *committed.borrow_mut() = Some(w));
    }

    let start = ui.get_entry_w();
    assert!(
        (start - ENTRY_DEFAULT).abs() <= 0.5,
        "ENTRY column should start at its layout default {ENTRY_DEFAULT}, got {start}"
    );

    // Grab the handle (its grip carries the structural label).
    let grip = cell_center(&ui, "entry-resize-handle");
    window.dispatch_event(WindowEvent::PointerMoved { position: grip });
    window.dispatch_event(WindowEvent::PointerPressed {
        position: grip,
        button: PointerEventButton::Left,
    });

    // Drag RIGHT by 80px → the column widens by ~80 (the right edge tracks the
    // cursor; no feedback drift from the handle moving with the column).
    let right = slint::LogicalPosition::new(grip.x + 80.0, grip.y);
    window.dispatch_event(WindowEvent::PointerMoved { position: right });
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    let wider = ui.get_entry_w();
    assert!(
        (wider - (start + 80.0)).abs() <= 2.0,
        "dragging the handle right by 80px should widen ENTRY to ~{} (got {wider})",
        start + 80.0
    );

    // Drag far LEFT, past the floor → ENTRY clamps to the 200px floor, never below.
    let far_left = slint::LogicalPosition::new(grip.x - 400.0, grip.y);
    window.dispatch_event(WindowEvent::PointerMoved { position: far_left });
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    let clamped = ui.get_entry_w();
    assert!(
        (clamped - ENTRY_MIN).abs() <= 0.5,
        "ENTRY must not shrink below the {ENTRY_MIN}px floor (got {clamped})"
    );

    // Release → the final (clamped) width is persisted exactly once.
    window.dispatch_event(WindowEvent::PointerReleased {
        position: far_left,
        button: PointerEventButton::Left,
    });
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    let persisted = committed.borrow().expect("release must persist the width");
    assert!(
        (persisted - ENTRY_MIN).abs() <= 0.5,
        "release must persist the final clamped width {ENTRY_MIN} (got {persisted})"
    );
}

#[test]
fn resizing_entry_reflows_the_comparison_columns() {
    i_slint_backend_testing::init_no_event_loop();
    // AC3: a wider ENTRY column leaves less width for the env region, so the
    // Comparison Columns re-stretch (shrink) into what remains. Both widths stay
    // above the env floor here, so the change is genuine reflow, not floor-clamping.
    let ui = matrix_window(); // 2 envs, 1400px wide, ENTRY default 300
    let col_at_default = body_col_w(&ui);

    ui.set_entry_w(ENTRY_DEFAULT + 200.0);
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    let col_when_wide = body_col_w(&ui);

    assert!(
        col_when_wide < col_at_default - 50.0,
        "widening ENTRY by 200px must reflow (shrink) the Comparison Columns: \
         {col_when_wide} vs {col_at_default}"
    );
    assert!(
        col_when_wide > ENV_FLOOR,
        "both column widths should stay above the env floor so this is reflow, \
         not floor-clamping (got {col_when_wide})"
    );
}

/// A pinned-header window: a matrix in the matrix pane whose `items` carry the
/// header/row offsets `rows::item_offsets` would compute. The cell text is a short
/// structural fixture, never a Value.
fn sticky_window(items: Vec<MatrixItemView>) -> MainWindow {
    let ui = MainWindow::new().expect("create MainWindow");
    ui.set_pane(SharedString::from("matrix"));
    ui.set_environments(ModelRc::from(Rc::new(VecModel::from(vec![
        SharedString::from("prod"),
    ]))));
    ui.set_items(ModelRc::from(Rc::new(VecModel::from(items))));
    ui.window().set_size(LogicalSize::new(1000.0, 700.0));
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    ui
}

fn header_item(label: &str, count: i32, headers_before: i32, rows_before: i32) -> MatrixItemView {
    MatrixItemView {
        is_header: true,
        label: SharedString::from(label),
        count,
        headers_before,
        rows_before,
        ..Default::default()
    }
}

fn row_item(headers_before: i32, rows_before: i32) -> MatrixItemView {
    let cells = vec![CellView {
        absent: false,
        dots: SharedString::from("··"),
        length: SharedString::from("2"),
        hex: SharedString::from("ab"),
    }];
    MatrixItemView {
        is_header: false,
        row_index: rows_before,
        state: SharedString::from("Aligned"),
        glyph: SharedString::from("="),
        headers_before,
        rows_before,
        cells: ModelRc::from(Rc::new(VecModel::from(cells))),
        ..Default::default()
    }
}

#[test]
fn sticky_header_pins_the_cluster_owning_the_scroll_top_and_hands_off() {
    i_slint_backend_testing::init_no_event_loop();
    // Two 2-member clusters (offsets as rows::item_offsets would emit them):
    //   db.* span [0, 1·H + 2·R) = [0, 87); gh.* span [87, 2·H + 4·R) = [87, 174).
    let ui = sticky_window(vec![
        header_item("db.*", 2, 0, 0),
        row_item(1, 0),
        row_item(1, 1),
        header_item("gh.*", 2, 1, 2),
        row_item(2, 2),
        row_item(2, 3),
    ]);

    // At the top, the first cluster's header is pinned; the next is not.
    ui.set_scroll_y(0.0);
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    assert_eq!(
        label_count(&ui, "pinned-db.*"),
        1,
        "first cluster pins at the top"
    );
    assert_eq!(label_count(&ui, "pinned-gh.*"), 0);

    // Scrolled within the first cluster's rows, it stays pinned.
    ui.set_scroll_y(50.0);
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    assert_eq!(
        label_count(&ui, "pinned-db.*"),
        1,
        "the first cluster's header stays pinned while its rows occupy the top"
    );
    assert_eq!(label_count(&ui, "pinned-gh.*"), 0);

    // Scrolled into the second cluster, its header takes the next one's place.
    ui.set_scroll_y(100.0);
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    assert_eq!(
        label_count(&ui, "pinned-db.*"),
        0,
        "the next cluster's header replaces the previous when it reaches the top"
    );
    assert_eq!(label_count(&ui, "pinned-gh.*"), 1);
}

#[test]
fn no_sticky_header_pins_over_a_lone_row_with_no_cluster() {
    i_slint_backend_testing::init_no_event_loop();
    // A lone row (no cluster) precedes the first cluster:
    //   lone row span [0, 30); db.* span [1·R, 1·R + 1·H + 2·R) = [30, 117).
    let ui = sticky_window(vec![
        row_item(0, 0),
        header_item("db.*", 2, 0, 1),
        row_item(1, 1),
        row_item(1, 2),
    ]);

    // Over the lone row at the top → nothing pins (it belongs to no cluster).
    ui.set_scroll_y(10.0);
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    assert_eq!(
        label_count(&ui, "pinned-db.*"),
        0,
        "no group context to pin while a lone row occupies the top"
    );

    // Scrolled into the cluster → its header pins.
    ui.set_scroll_y(50.0);
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    assert_eq!(
        label_count(&ui, "pinned-db.*"),
        1,
        "the cluster's header pins once its rows occupy the top"
    );
}

// Heights referenced in the span arithmetic above, asserted so a future font /
// padding change to header-h / row-h fails here loudly instead of silently
// drifting the sticky-header spans.
#[test]
fn sticky_header_height_constants_match_the_view() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = sticky_window(vec![header_item("db.*", 1, 0, 0), row_item(1, 0)]);
    // The frozen ENTRY cell fills the row, so its height is the data-row height.
    let row_h = one_by_label(&ui, "entry-cell").size().height;
    assert!(
        (row_h - ROW_H).abs() <= 1.0,
        "row-h drifted from the {ROW_H}px the sticky-header spans assume (got {row_h})"
    );
    // At the top the first cluster pins; the overlay's height is header-h.
    ui.set_scroll_y(0.0);
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    let header_h = one_by_label(&ui, "pinned-db.*").size().height;
    assert!(
        (header_h - HEADER_H).abs() <= 1.0,
        "header-h drifted from the {HEADER_H}px the sticky-header spans assume (got {header_h})"
    );
}

#[test]
fn entry_column_drag_tracks_the_cursor_under_continuous_motion() {
    use slint::platform::{PointerEventButton, WindowEvent};
    i_slint_backend_testing::init_no_event_loop();
    // Many small steps with NO layout settle between them — exactly the
    // multiple-events-per-frame case where a drag anchored to the *moving* column
    // edge would accumulate error and overshoot. The fixed-left-frame drag measures
    // the pointer from the column's stationary left edge, so the column tracks the
    // cursor exactly: +100px of motion → +100px of width, not more.
    let ui = matrix_window();
    let window = ui.window();
    let start = ui.get_entry_w();
    let grip = cell_center(&ui, "entry-resize-handle");

    window.dispatch_event(WindowEvent::PointerMoved { position: grip });
    window.dispatch_event(WindowEvent::PointerPressed {
        position: grip,
        button: PointerEventButton::Left,
    });
    for k in 1..=20 {
        let p = slint::LogicalPosition::new(grip.x + (k as f32) * 5.0, grip.y);
        window.dispatch_event(WindowEvent::PointerMoved { position: p });
    }
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));

    let w = ui.get_entry_w();
    assert!(
        (w - (start + 100.0)).abs() <= 2.0,
        "continuous drag of +100px should widen ENTRY to ~{} with no overshoot (got {w})",
        start + 100.0
    );
    window.dispatch_event(WindowEvent::PointerReleased {
        position: slint::LogicalPosition::new(grip.x + 100.0, grip.y),
        button: PointerEventButton::Left,
    });
}

#[test]
fn cell_reveal_fires_through_the_sticky_header_overlay() {
    i_slint_backend_testing::init_no_event_loop();
    // Grouped data → the sticky overlay (full-body transparent per-item containers
    // + one pinned header) is active. A press on a value cell must still reach its
    // TouchArea: the overlay elements carry no TouchArea, so they must not swallow
    // input bound for the cells below them.
    let ui = sticky_window(vec![header_item("db.*", 1, 0, 0), row_item(1, 0)]);
    ui.set_scroll_y(0.0); // pin the header → overlay rendered
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    // Sanity: the overlay really is present for this fixture.
    assert_eq!(label_count(&ui, "pinned-db.*"), 1);

    let pressed = Rc::new(std::cell::RefCell::new(None::<(i32, i32)>));
    {
        let pressed = pressed.clone();
        ui.on_reveal_cell(move |r, c| *pressed.borrow_mut() = Some((r, c)));
    }
    one_by_label(&ui, "envcell-0").mock_single_click(slint::platform::PointerEventButton::Left);
    assert_eq!(
        *pressed.borrow(),
        Some((0, 0)),
        "the sticky-header overlay must not intercept the press meant for the value cell"
    );
}

#[test]
fn to_item_models_offsets_drive_sticky_pinning_end_to_end() {
    use janitor_core::compare::{EntryState, RowKey};
    use janitor_core::view::{MatrixRow, MatrixView};
    i_slint_backend_testing::init_no_event_loop();
    // Two clustered names + a lone row, through the REAL assembly path
    // (matrix_items + item_offsets), not hand-built offsets. Grouped:
    //   header(db.*) + db.a + db.b + LONE → db.* span [0, 1·H + 2·R) = [0, 87);
    //   LONE is a lone row [87, 117) that pins nothing.
    let view = MatrixView {
        environments: vec!["prod".into()],
        rows: ["db.a", "db.b", "LONE"]
            .iter()
            .map(|n| MatrixRow {
                key: RowKey::WholeSet,
                name: (*n).into(),
                state: EntryState::Aligned,
                kind: None,
                cells: Vec::new(),
            })
            .collect(),
    };

    // Grouped: scroll within the cluster pins db.*; over the lone row, nothing pins.
    let ui = sticky_from_items(crate::to_item_models(&view, true));
    ui.set_scroll_y(40.0);
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    assert_eq!(
        label_count(&ui, "pinned-db.*"),
        1,
        "to_item_models must emit offsets that pin the real cluster"
    );
    ui.set_scroll_y(100.0);
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    assert_eq!(
        label_count(&ui, "pinned-db.*"),
        0,
        "nothing pins while the trailing lone row occupies the top"
    );

    // Ungrouped: no headers are emitted at all, so nothing ever pins.
    let flat = sticky_from_items(crate::to_item_models(&view, false));
    for y in [0.0_f32, 40.0, 100.0] {
        flat.set_scroll_y(y);
        i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
        assert_eq!(
            label_count(&flat, "pinned-db.*"),
            0,
            "ungrouped mode emits no headers, so no cluster pins (scroll-y={y})"
        );
    }
}

/// A matrix window fed a prebuilt item model (from the real `to_item_models`).
fn sticky_from_items(items: ModelRc<MatrixItemView>) -> MainWindow {
    let ui = MainWindow::new().expect("create MainWindow");
    ui.set_pane(SharedString::from("matrix"));
    ui.set_environments(ModelRc::from(Rc::new(VecModel::from(vec![
        SharedString::from("prod"),
    ]))));
    ui.set_items(items);
    ui.window().set_size(LogicalSize::new(1000.0, 700.0));
    i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
    ui
}
#[test]
fn real_wheel_scroll_mirrors_to_scroll_y_and_repins_the_active_cluster() {
    use slint::platform::WindowEvent;
    i_slint_backend_testing::init_no_event_loop();
    // The view tests above drive `scroll-y` directly; this one exercises the full
    // path — a real wheel scroll → the body ScrollView's viewport-y →
    // `changed viewport-y => scroll-y` → the overlay repins. Two 20-member clusters
    // make the body genuinely taller than its viewport so it scrolls past the first
    // cluster's span [0, 1·H + 20·R) into the second.
    let mut items = vec![header_item("db.*", 20, 0, 0)];
    for r in 0..20 {
        items.push(row_item(1, r));
    }
    items.push(header_item("gh.*", 20, 1, 20));
    for r in 0..20 {
        items.push(row_item(2, 20 + r));
    }
    let ui = sticky_window(items);

    // At the top: scroll-y is zero and the first cluster is pinned.
    assert!(ui.get_scroll_y().abs() < 0.5, "starts unscrolled");
    assert_eq!(label_count(&ui, "pinned-db.*"), 1);

    // Wheel-scroll down until we pass the first cluster's span (or give up).
    let pos = slint::LogicalPosition::new(500.0, 400.0);
    ui.window()
        .dispatch_event(WindowEvent::PointerMoved { position: pos });
    let db_end = HEADER_H + 20.0 * ROW_H; // gh.* begins here
    let mut crossed = false;
    for _ in 0..40 {
        ui.window().dispatch_event(WindowEvent::PointerScrolled {
            position: pos,
            delta_x: 0.0,
            delta_y: -120.0,
        });
        i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(16));
        if ui.get_scroll_y() > db_end + 5.0 {
            crossed = true;
            break;
        }
    }
    assert!(
        crossed,
        "wheel scroll must mirror into scroll-y via `changed viewport-y` and pass the \
         first cluster's span (reached scroll-y={})",
        ui.get_scroll_y()
    );
    // The mirrored offset repinned the overlay to the second cluster.
    assert_eq!(label_count(&ui, "pinned-db.*"), 0);
    assert_eq!(label_count(&ui, "pinned-gh.*"), 1);
}
