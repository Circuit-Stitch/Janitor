# GUI view tests via the Slint testing backend

**Status:** accepted

## Context

`janitor-gui` is a thin Slint view ([ADR 0003](0003-core-gui-split-slint-and-secret-display.md)):
the testable logic — pane selection (`pane.rs`), row assembly (`rows.rs`), log
rendering (`logpane.rs`), the worker's `Command → Event` loop (`worker.rs`) — lives
in pure Rust modules and is unit-tested. Two surfaces stayed untested: the
**declarative bindings and click-routing in `app.slint`**, and **layout/geometry**
(the header/body column drift and window-resize regressions of
[ADR 0020](0020-window-resize-floor-and-uncapped-matrix-width.md)). Pure-`.slint`
changes had "no Rust seam," so the practice was verify-visually-only — which let a
latent layout bug ship and gave view work no red-green loop.

We evaluated switching GUI frameworks for better testability and rejected it:

- **GTK (gtk-rs)** — its automated UI story (AT-SPI / `dogtail`) is flakier and
  weaker than what Slint already offers, and Linux-only; it doesn't solve the pain.
- **egui (`egui_kittest`)** — genuinely the best Rust UI harness, including
  image-diff snapshots, but immediate-mode interleaves view and logic, eroding
  ADR 0003's thin-view split. Full rewrite.
- **Tauri / web** — best-in-class tooling (Playwright), but a webview puts Values
  in a JS heap/DOM and widens exactly the sibling-scrapable surface the threat
  model shrinks ([THREAT-MODEL.md](../THREAT-MODEL.md)). Full rewrite + new stack.

Slint 1.16 already ships a headless test backend, `i-slint-backend-testing`
(transitively in our lockfile). A spike proved it works in this repo: a geometry
test reproduces the ADR 0020 invariant red→green and the full suite stays green.

## Decision

Stand up GUI view tests on `i-slint-backend-testing`, as a **dev-dependency pinned
`=1.16.1`** — it is an *internal* Slint crate with no semver guarantee, so pin it to
the `slint` version and bump the two in lockstep. Conventions:

- **Property-API-first.** Assert state via the generated getters (`get_pane()`,
  `get_revealed_text()`, …) and invoke callbacks directly. Use `ElementHandle`
  *only* for what the property API cannot reach: **click routing** (`single_click`)
  and **geometry** (`absolute_position` / `size`).
- **Tests live in the crate.** `janitor-gui` is a binary, so the
  `slint::include_modules!()` types are visible only to in-crate `#[cfg(test)]`
  modules (`src/view_tests.rs`), never a `tests/` integration crate.
- **Compiler debug info is required for `ElementHandle` queries.** `build.rs` uses
  `compile_with_config(…).with_debug_info(profile != "release")`, so `cargo test`
  works with no env var and release builds stay lean. (Manual equivalent:
  `SLINT_EMIT_DEBUG_INFO=1`.) Without it, queries silently find nothing.
- **Queryable anchors carry structural-only `accessible-label`s**
  (`"envcell-" + j`, env names) — **never** a Value, the masked dots, or the length.
  This adds nothing to the accessibility side-channel beyond what the threat model
  already accepts (env/entry names are Config recon; length is an accepted
  side-channel), and it keeps secret material asserted via the property API, not the
  a11y tree. (A `Rectangle` needs an explicit `accessible-role` to carry a label; a
  `Text` already defaults to one.)
- **Headless geometry is asserted in renderer-independent terms.**
  `init_no_event_loop()` + `window().set_size(…)` + one `mock_elapsed_time(16ms)`
  tick populates geometry. But absolute positions are **not faithful** to the real
  renderer: the body env region sits inside a std-widgets `ScrollView` whose chrome
  the headless style sizes differently, offsetting the whole body region from the
  header by a constant. So assert *relative* invariants — identical per-column step,
  and "the band stretches to fill the window vs collapses to its intrinsic width" —
  never `header.x == body.x`.
- **Pixel / visual fidelity stays manual.** The crate exposes geometry and state,
  not a framebuffer; colours, theme swap, zebra, hover, and badge styling are
  validated by `JANITOR_MOCK=1 cargo run -p janitor-gui`, not headless tests.
- **Prefer extraction over UI tests.** Logic embedded in bindings or
  `MainWindow`-coupled glue — the `is_revealed` reveal gate, the
  `pane_title` / body-copy `?:` ladders, the sidebar drift-badge suppression,
  `banner()` — is extracted into pure functions and unit-tested, continuing the
  ADR 0003 seam; UI tests cover only what is irreducibly view-side.

## Consequences

- There is now a red-green loop for view changes. The first test,
  `view_tests::env_columns_align_and_band_fills_window`, encodes the ADR 0020
  band-stretch invariant (RED ~400px collapse → GREEN ~782px fill) and passes.
- We depend, **in tests only**, on an internal Slint crate with no stability
  guarantee; a `slint` upgrade may break the suite and require porting. Contained to
  CI/dev — never shipped in the binary.
- Headless geometry cannot verify absolute on-screen alignment, so a residual visual
  check on the real renderer remains for layout work. The geometry test is the most
  structure-coupled in the suite —
  [issue #41](https://github.com/Circuit-Stitch/Janitor/issues/41) rewrites the
  matrix env region (self-contained columns) and will re-point or replace it.
- `build.rs` now emits debug info for non-release builds: slightly larger debug
  artifacts, release unaffected.

This stays inside ADR 0003 (no logic moved into the view; the suite asserts the view
from outside) and changes nothing in the threat model — ADR 0003's
accessibility-as-display-side-channel non-goal already covers the a11y surface.
