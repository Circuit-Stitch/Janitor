# Drift-matrix model: an N-column matrix with a frozen overall-state column and view-level Comparison Columns

**Status:** accepted

## Context

The GUI redesign (a richer, table-like drift matrix) forced a decision the
earlier slices had deferred: **what is the shape of the comparison view when an
Application has more than two Environments?**

[ADR 0013](0013-guided-discovery-in-gui-step-machine-and-manage-window.md) shipped
discovery on "the existing N-column matrix" and explicitly **deferred to a later
ADR ("Slice 2")** a different model: a *left/right (git-style) 2-up diff* — pick 2
of N Environments via dropdown column headers, fetch only those two, and show a
**pairwise** `= / ≠ / ø` glyph between them (tracked as issue #12). That framing
treats the matrix as a two-sided diff.

The redesign mockup is read more naturally as a **table of N Environments** than a
two-sided diff, and the domain disagrees with the pairwise framing in a concrete
way: per [CONTEXT.md](../../CONTEXT.md), an Application's Environments routinely
span **more than two** contexts (prod / staging / dev, possibly across accounts and
regions), and the actual job — "is this Entry **Aligned** everywhere, **Drift**
everywhere-but-differing, or a **Gap** missing somewhere" — is an **N-way** verdict
([ADR 0009](0009-comparison-engine-result-model.md)'s `EntryState`), not a property
of a chosen pair. `janitor-core` already projects that: `MatrixView` emits **N
cells per row** plus one whole-row `EntryState`. A pairwise model would need *new*
per-pair comparison logic that partially duplicates `EntryState`, and it would hide
the N-way verdict behind whichever two columns the user happened to pick.

This ADR settles the model and **supersedes ADR 0013's Slice-2 pairwise deferral
and #12's pairwise premise.** The region-picker / cross-region-discovery scope that
was bundled into #12 is unaffected and survives there.

## Decision

- **N-column matrix, horizontal scroll.** Each compared Environment is its own
  column. When the columns overflow the window they **scroll horizontally** — we do
  not collapse to two sides. N=2 is just the common case, not a distinct mode.

- **ENTRY and a single overall-STATE column are frozen on the left** while the env
  columns scroll. The STATE column shows the row's **whole-row** `EntryState` as one
  glyph — `=` Aligned, `≠` Drift, `∅` Gap — computed across **all displayed
  columns**. It reuses `janitor-core`'s `EntryState` verbatim; it is
  **order-independent**, so reordering or hiding columns never churns it, and it
  stays visible no matter how far right the user scrolls. There is **no per-pair
  comparator** — neither a single "between two sides" glyph nor interleaved `N−1`
  ones.

- **Comparison Columns: a view-level, persisted selection over an Application's
  Environments.** The set of Environments *shown as columns* (and their order) is a
  **view selection**, not the same thing as the Environments *configured* on the
  Application. (New term, already in `CONTEXT.md`.)
  - An env column header is a dropdown that **swaps** the column to another
    configured Environment or **takes it out of the comparison** (hides it from the
    view — it stays configured and can be brought back). These are **view**
    operations.
  - Real config **add / remove** of an Environment stays in the non-modal Manage
    window (ADR 0013) — that path is what forgets a Mapping; hiding a column never
    does.
  - The selection + order are **persisted in `Config`** so they survive relaunch.
    Only Environment **identifiers / locations** are written — never Values — so the
    nothing-secret-on-disk invariant ([ADR 0002](0002-identity-center-only-memory-only-auth.md),
    [THREAT-MODEL](../THREAT-MODEL.md)) holds.
  - The matrix **loads and compares the displayed Comparison Columns**, not
    necessarily every configured Environment; the whole-app error rule
    ([ADR 0012](0012-gui-aws-bridge-worker-and-lazy-sign-in.md)) scopes to the
    displayed columns.

This keeps the model on the side of the more general abstraction (columns are a
*selection over* Environments, not an *alias for* them), consistent with the
owner's stated preference for generic-over-coupled implementations (cited in
ADR 0013), and consistent with `core` already being N-column.

## Considered options

- **Left/right 2-of-N pairwise diff (ADR 0013 Slice 2 / #12).** Rejected. The
  comparator glyph and "diff" framing only describe **two** sides, but an
  Application routinely has more, and the per-Entry verdict the tool exists to
  surface (Aligned / Drift / Gap) is **N-way**. A chosen pair hides the other
  Environments' state; it also needs **new core pairwise-comparison logic** that
  duplicates `EntryState`. "How do prod and staging specifically differ" is still
  answerable in the N-column view by reading those two columns' **per-cell hex-tag
  pills** (equal Values share a tag) — the accepted trade-off below.

- **Interleaved `N−1` pairwise comparator columns** (`prod ≠ staging = dev …`).
  Rejected. It is **order-dependent** — but Comparison Columns are reorderable, so
  the comparators would churn on every reorder — doubles the column count, and needs
  the same new pairwise logic. A single frozen whole-row verdict is order-independent
  and reuses existing `core`.

- **Columns are exactly the configured Environments (no view selection).** Rejected.
  A 5–6 Environment Application is unreadable if you cannot hide or reorder columns,
  and the only way to "focus" would be to **mutate config** (delete Environments),
  which forgets Mappings. The view-level Comparison Columns selection is the more
  general abstraction and keeps config and view concerns separate.

- **State as a faint full-row background tint instead of a dedicated column.**
  Out of scope here (a styling choice handled in the table rewrite); the *model*
  decision is that the whole-row verdict is a first-class frozen column, not a
  per-pair value.

## Consequences

- **No `core` rewrite.** `MatrixView` already emits N cells per row plus
  `EntryState`; the frozen STATE column renders that directly and the env columns
  render the existing cells. The pairwise comparison logic that #12 implied is never
  built.

- **`Config` gains a per-Application Comparison Columns selection** (an ordered list
  of Environment identifiers, plus the grouped/sort prefs from the redesign). Locations
  only — the invariant is unchanged. The worker's `load()` is scoped to the
  displayed columns, and the whole-app error rule scopes with it.

- **ADR 0013's "Slice 2" pairwise deferral and #12's pairwise premise are
  superseded.** #12 is retrimmed to the scope that survives — the AWS-console-style
  **region picker** (`config.secret_region`) and **cross-region Discovery** — which
  are orthogonal to this model. The "Ad-hoc compare" idea stays noted-but-unscheduled.

- **Implementation constraint for the GUI:** a horizontally-scrolling region with
  **frozen left columns** (ENTRY + STATE) is the layout primitive the table rewrite
  (#20) must realize in Slint; it is untested view shell per ADR 0010 §5 / ADR 0003.

- **`CONTEXT.md` gained the Comparison Columns term** (already added during the
  design grill).

- **Prefix-cluster grouping is orthogonal** to this model and decided separately —
  group headers cluster rows within whatever Comparison Columns are shown; the
  clustering *algorithm* is its own ADR (#24).
