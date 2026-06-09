# Drift-matrix column-sizing: stretch-to-fill down to a content floor

**Status:** accepted

## Context

[ADR 0014](0014-drift-matrix-model-n-column-and-comparison-columns.md)
established the N-column [Drift matrix](../../CONTEXT.md): ENTRY/STATE frozen on
the left, the [Comparison Columns](../../CONTEXT.md) scrolling horizontally
beside them. [ADR 0020](0020-window-resize-floor-and-uncapped-matrix-width.md)
then unlocked window resizing by giving the env band an *infinite* max-width,
but it deliberately **deferred stretching**: it pinned the env region to a fixed
`envs-w` (`env-w × N`), so a wide window left an empty gutter to the right of the
last column — "the conventional table behaviour … revisit if/when columns are
made to stretch."

This is that revisit. We want the Comparison Columns to use the available width
instead of leaving a gutter, while staying readable when there are many columns
or the window is narrow — and without giving back the resizability ADR 0020 won.

## Decision

- **Stretch to fill, down to a content floor.** The Comparison Columns share the
  available env width equally and stretch to fill it, down to a per-column
  **content floor** wide enough for a cell's `dot · mask · length · hex`
  (~200px). One mechanism expresses both regimes:

  ```text
  col_w          = max(floor, available / N)
  viewport_width = col_w × N = max(available, N × floor)
  ```

  Above the floor the columns absorb all slack (no gutter); at the floor they
  stop shrinking and the env region's `viewport_width` exceeds the visible
  width, so it **scrolls horizontally**.

- **Freeze-pane structure.** ENTRY and STATE stay frozen on the left. Each
  Comparison Column's **Environment-name header is metric-locked to that
  column** — it shares the one computed `col_w` and the column's horizontal
  scroll origin — so the env label can never size or drift off its own cells,
  and horizontal scroll slides the leftmost Environment *under* the frozen
  ENTRY/STATE columns. Vertical context (which Environment a column is) is
  therefore never lost.

- **Implementation note — header strip vs. per-column unit.** "Header belongs to
  its column" is realized as a single top header strip that shares the body's
  computed `col_w` and is locked to the body's horizontal scroll position
  (`viewport-x`), **not** as N independent header-over-cells vertical units. This
  keeps **one** vertical scroll for the whole body, so the frozen ENTRY/STATE
  cells and the env cells stay row-locked while scrolling and the wheel scrolls
  anywhere in the body. A fully-merged per-column unit would force splitting the
  vertical scroll into two synced flickables — trading the (proven, ADR 0020)
  horizontal lockstep for a fragile vertical one and losing wheel-scroll-anywhere.
  The metric-locked strip gives the same guarantee the model asks for (the header
  cannot drift from its column) without that cost.

- **Supersedes [ADR 0020](0020-window-resize-floor-and-uncapped-matrix-width.md)'s
  "keep the env region pinned to `envs-w` (not stretched)" decision bullet.** The
  rest of ADR 0020 stands. In particular the **no-max-width-cap** constraint is
  binding and must not be reintroduced: the window stays freely resizable from the
  800px floor (`WM_NORMAL_HINTS` reports no maximum size). The infinite-max-width
  mechanism ADR 0020 added (the `horizontal-stretch` band) is retained — `col_w`
  changes *how wide each column is*, never *whether the band caps the window*.

Rejected alternatives:

- *N independent per-column vertical units (the literal "self-contained column").*
  Rejected for the reason in the implementation note: it forces two vertically
  synced flickables and loses single-scroll row-lockstep / wheel-anywhere. The
  metric-locked strip is observationally identical for the user.
- *A configurable / persisted per-column width here.* Out of scope; that is the
  resizable-ENTRY work (issue #42, now
  [ADR 0030](0030-matrix-sticky-group-headers-and-resizable-entry-column.md)),
  which resizes the *frozen* column and lets these Comparison Columns reflow into
  whatever width remains.

This stays inside [ADR 0003](0003-core-gui-split-slint-and-secret-display.md): a
pure-view layout change in `app.slint` (`col_w` is a Slint layout expression), no
logic moved into the GUI, no secret material involved.

## Consequences

- A wide window with few columns fills the env area — a single Comparison Column
  fills the whole area; no empty right-hand gutter.
- Many columns or a narrow window hold the content floor and scroll horizontally;
  widening the window reveals more columns before scrolling resumes.
- The Environment-name header stays directly above its own column's cells at every
  window width and throughout horizontal scroll (no header/cell drift).
- The window remains freely resizable from the 800px floor (no reintroduced
  max-width cap).
- Verified by [ADR 0021](0021-gui-view-tests-via-slint-testing-backend.md)
  headless geometry tests (stretch-to-fill, hold-floor-and-scroll, header/body
  alignment) and by running the GUI on the mock Provider at several widths and
  column counts.
