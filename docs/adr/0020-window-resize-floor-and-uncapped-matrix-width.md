# Window resize floor and an uncapped matrix max-width

**Status:** accepted

## Context

The main window opened too narrow to read and, worse, resisted resizing.
The lock turned out to be a finite **max-width** the
[Drift matrix](../../CONTEXT.md) pane imposed on the whole `Window`, and it
traces to two Slint (1.16) layout rules that compose badly with the matrix's
frozen/scroll split ([ADR 0014](0014-drift-matrix-model-n-column-and-comparison-columns.md)):

- A `Flickable` reports `max-width == its viewport-width`, not infinity. The
  header band that labels the Environment columns is
  `ENTRY (300px) + STATE (46px) + a Flickable` whose viewport is `envs-w`
  (`env-w × N`), so the band's max-width is the *exact* table width — finite.
- A `VerticalLayout`'s cross-axis max-width is the **minimum** of its children's
  max-widths. So that one finite header band capped the entire main pane, even
  though the always-present Diagnostics row
  ([ADR 0017](0017-in-app-diagnostic-log-panel-and-zero-terminal-output.md))
  carries an infinite-max stretch spacer. (That the window still capped at the
  table width *despite* the infinite Diagnostics row is what proves the rule is
  min-of-children, not max.)

The user-visible failure modes both follow from this single finite cap:

- With several Environment columns the cap sat just above the readable width
  (measured at 1018px for two Environments), so the window was resizable only in
  a uselessly narrow band.
- With few or zero columns the computed max-width fell *below* the `min-width`
  floor, the constraints became contradictory, and the window manager clamped the
  window to a tiny fixed size (~400px) that refused to resize at all — the state
  the user hit immediately after Sign-in, before an [Application](../../CONTEXT.md)
  with real columns was loaded. The Sign-in / loading panes never capped (their
  text fills any width), which is why the pre-Sign-in window behaved correctly.

Diagnosed by reading the live window's X11 size hints rather than guessing at
Slint's constraint propagation: run forced onto X11
(`env -u WAYLAND_DISPLAY DISPLAY=:0 …`, since the winit window is native Wayland
by default and `xprop` can't see it), then
`xprop -id <id> WM_NORMAL_HINTS`. A "maximum size" line means
fixed/clamped; its absence means freely resizable.

## Decision

- **Floor the window at `min-width: 800px`** on `MainWindow` so it can never open
  or shrink below a readable width. (`preferred-width` stays 1100px.)

- **Give the header band an infinite max-width** by pinning the env-name
  `Flickable` to `width: envs-w` and appending a trailing
  `Rectangle { horizontal-stretch: 1; }` spacer. The spacer's unbounded max-width
  lifts the band — and therefore the whole pane — out of the finite cap,
  *regardless of column count*, so the sub-floor-clamp case disappears too.
  `horizontal-stretch` alone does **not** do this: it is a slack-distribution
  factor and never raises a `Flickable`'s viewport-bound max-width.

- **Keep the env region pinned to `envs-w`** (not stretched to fill) so the header
  labels stay aligned column-for-column with the body cells. Extra window width
  beyond the table lands in the trailing spacer (header) and the body's natural
  left-aligned slack (body) — identical on both, so alignment holds at any width.

Rejected alternatives:

- *Set an explicit large `max-width` on the `Window`.* A magic number, and it
  fights rather than removes the content-derived cap; the spacer expresses
  "this row may be arbitrarily wide" idiomatically and locally.
- *Stretch the Environment columns to fill the extra width.* Deferred — it means
  deriving `env-w` from the available width, a real feature with its own layout
  questions, not a resize fix. For now the matrix simply leaves blank space to the
  right of the last column, the conventional table behaviour.

This stays inside [ADR 0003](0003-core-gui-split-slint-and-secret-display.md): a
pure-view layout change in `app.slint`, no logic moved into the GUI, no secret
material involved.

## Consequences

- The window is freely resizable from the 800px floor upward in both axes;
  `WM_NORMAL_HINTS` now reports no maximum size. Verified against the mock matrix.
- A wide window shows empty space to the right of the last Environment column.
  Acceptable for a table; revisit if/when columns are made to stretch.
- The fix is column-count agnostic, so it covers the 0/1-Environment matrix that
  previously produced the sub-floor clamp.
- Process note: when a Slint window will not resize or clamps unexpectedly,
  read `WM_NORMAL_HINTS` (forced onto X11) before theorising — the min/max hints
  state the contradiction directly.
