# Drift-matrix: sticky group headers + a resizable, persisted ENTRY column

**Status:** accepted

## Context

[ADR 0023](0023-drift-matrix-column-sizing-stretch-to-fill.md) settled the
freeze-pane column-sizing model: ENTRY/STATE frozen on the left, the
[Comparison Columns](../../CONTEXT.md) sharing the remaining width
(`col_w = max(floor, available / N)`) and scrolling horizontally beside them. It
explicitly deferred two interactions to issue #42 (and named them in its rejected
alternatives): a **persisted per-column width** ("resizes the *frozen* column and
lets these Comparison Columns reflow into whatever width remains") and, with
[issue #20](../../CONTEXT.md)'s prefix-cluster grouping, the matrix scrolls a long
list of grouped rows where the cluster header scrolls out of view — losing the
group context the prefix-stripped Entry names rely on (#40).

This ADR is that work. Two view-only interactions, no logic leaving `core`
(ADR 0003), no secret material involved:

1. **Sticky group headers** — while any row of a prefix cluster occupies the top
   of the scroll area, that cluster's header pins there.
2. **Resizable, persisted ENTRY column** — a drag handle on the ENTRY column's
   right edge resizes it (floored at 200px); the chosen width survives relaunch.

## Decision

### Sticky group headers — a declarative overlay keyed on a mirrored scroll offset

The pinned header is **not** computed in Rust per scroll frame (a round-trip per
wheel tick) and **not** a manual absolute-positioned scroll viewport (a rewrite of
the proven ADR 0023 body). Instead:

- The body `ScrollView` is wrapped in a `clip: true` container. A pinned-header
  **overlay** is a sibling drawn *over* the scrolled content, so it stays put while
  the content scrolls under it.
- The live scroll offset is **mirrored out** of the widget into a window property:
  `changed viewport-y => { root.scroll-y = -self.viewport-y }`. Making `scroll-y`
  an `in-out` property (rather than a binding to the internal `viewport-y`) also
  lets a [view test](0021-gui-view-tests-via-slint-testing-backend.md) drive the
  pin directly without faking a scroll gesture.
- Each header **self-selects**: the overlay is a `for item in items` whose pinned
  header renders only when `scroll-y` falls in that cluster's vertical span
  `[top, top + header-h + count·row-h)`. No array reduction (Slint has none) and
  no "which header" decision in the view — the spans partition the scroll axis, so
  exactly one header (or none, over a lone row that belongs to no cluster) matches.
  Contiguous clusters hand off seamlessly because this cluster's `end` equals the
  next cluster's `top`. As the next header arrives, the outgoing overlay slides up
  (`y = min(0, end - scroll-y - header-h)`) while the incoming in-flow header rises
  beneath it — the classic "push".
- A header's pixel `top` is `headers-before · header-h + rows-before · row-h`. The
  **counts** (`headers-before`, `rows-before`) are computed and unit-tested in
  `core`-adjacent pure Rust (`rows::item_offsets`); the **heights** stay in the
  view as the single source of truth (ADR 0023). Headers and data rows are summed
  on separate axes because a header row is shorter than a data row.

### Resizable ENTRY column — a stable drag, persisted in Config

- `entry-w` becomes an `in-out` length seeded from Config on launch. A drag handle
  on the ENTRY header's right edge updates it live; the env columns reflow for free
  because `matrix.available` already derives from `entry-w` (ADR 0023).
- **Floor, no cap.** The column never shrinks below `entry-min` (200px, enough for
  a prefix-stripped name + badge). No maximum — consistent with ADR 0020's
  no-max-width-cap constraint.
- **Feedback-free drag math.** The drag is *sensed* by a TouchArea anchored to the
  column's **fixed left edge** (`x: 0`, spanning the header), so `mouse-x` is the
  pointer's distance from a stationary origin — independent of `entry-w`. New width
  is `mouse-x + grab-offset` (the offset captured at press so the edge tracks the
  cursor with no jump), floored at `entry-min`. A handle anchored to the *moving*
  right edge instead would feed back: each `moved` reads an `entry-w` that may be a
  frame ahead of the handle geometry `mouse-x` is measured against, so a burst of
  move events in one frame accumulates and the column overshoots the cursor. The
  fixed-left frame removes the dependency entirely — exact under fast/continuous
  motion, and it recovers cleanly when a drag clamps at the floor then reverses
  (the clamp is applied only to the output, never fed back into the measurement).
  A thin grip at the right edge is the visual affordance; the resize only arms when
  the press lands in that right-edge zone.
- **Persistence.** The width is **view-state, not a Value** — structurally a number
  (`Config::entry_column_width: Option<f64>`), so it cannot hold a secret
  (THREAT-MODEL). It is persisted only on drag *release* (`commit-entry-width`), via
  the existing mock-guarded `maybe_save` (the offline demo's Config is never
  written over a real org's file). The store **clamps to the floor**
  (`set_entry_column_width`) and the read re-floors (`entry_column_width_or`), so a
  stale or hand-edited sub-floor value can never render a broken column. `core` is
  handed the floor/default by the GUI, so it stays ignorant of view px (ADR 0003).
  `None` (never resized) falls back to the layout default — and an older config
  without the field loads as `None` (`#[serde(default)]`).

Rejected alternatives:

- *Compute the pinned header in Rust on every scroll event.* A round-trip per wheel
  tick, and Rust would still need the view's `header-h`/`row-h` to map px → item.
  The declarative overlay updates synchronously with no round-trip.
- *Re-implement the body as a manual absolute-positioned scroll viewport so headers
  can be positioned arbitrarily.* Discards ADR 0023's single-vertical-scroll
  row-lockstep and wheel-anywhere for a fragile hand-rolled scroll. The overlay
  achieves the same pin without touching the proven body.
- *A `ViewState` sub-struct in Config now.* Over-built for one value; a flat
  `Option<f64>` field with a clamp helper is the migration-safe minimum. Future
  view prefs can group later without blocking this.

## Consequences

- Scrolling a long grouped list keeps the current cluster's header pinned at the
  top until the next cluster's header takes its place; over an ungrouped lone row,
  nothing pins (correct — it has no group context).
- The ENTRY column has a drag handle; dragging resizes it, floored at 200px, and
  the Comparison Columns re-stretch into the remaining width.
- The ENTRY width persists in Config (a number, never a Value) and is restored,
  floored, on relaunch; nothing secret is written to disk.
- Verified by [ADR 0021](0021-gui-view-tests-via-slint-testing-backend.md) headless
  tests — drag resize + floor clamp + persist-on-release; **drag tracks the cursor
  under continuous (no-settle) motion** (the overshoot guard); reflow of the
  Comparison Columns; sticky-pin + cluster hand-off; no-pin-over-a-lone-row; the
  full `to_item_models` → pin path for grouped data and the no-headers ungrouped
  case; **a real wheel scroll mirroring through `changed viewport-y` to repin**; a
  press reaching a value cell **through** the overlay; and height-constant guards —
  plus running the GUI on the mock Provider.
