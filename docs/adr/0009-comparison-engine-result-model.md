# Comparison engine result model

**Status:** accepted

## Context

The comparison engine turns N fetched Secret Sets into the Aligned/Drift/Gap
matrix (job #1). Its result types are **load-bearing**: the GUI renders them,
and the v2 write engine's notion of "the same Value" must agree with what the
viewer calls Aligned. Several modelling choices are hard to reverse once
downstream code depends on them.

CONTEXT.md describes the *happy path* — "every Entry is in exactly one of
Aligned / Drift / Gap", "equality grouping by hash" — but leaves four things
open that the engine must pin down: what happens when an Environment can't be
fetched, how long-lived the in-memory secret handles are, whether equality is
sensitive to JSON type, and what "by hash" means mechanically.

## Decision

- **Complete input; a partial fetch fails the whole comparison.** The engine
  assumes every Environment was fetched. The input type has **no "unavailable
  Environment" variant**, so a partial comparison is unrepresentable; the
  fetch/orchestration layer errors out and never calls the engine. Because a
  matrix is never built from incomplete data, a **Gap is always a real Gap**
  (never a fetch failure in disguise). Trade-off: one unavailable Environment
  blocks the whole Application matrix.

- **Transient borrow of the canonical Value.** `Comparison<'a>` *borrows* the
  fetched snapshot; a present cell holds `&'a Value` and reveal is a cell
  accessor. There is exactly one copy of each Value, owned by the snapshot in
  `core`'s zeroizing buffer (ADR 0003). The GUI keeps the **snapshot** as its
  state (ADR 0005: a point-in-time, manual-refresh snapshot) and rebuilds the
  `Comparison` projection on render/refresh/reveal. The `Comparison` is **not**
  stored beside the Sets it borrows (safe Rust rejects the self-reference); it
  does not need to be.

- **Equality = content bytes AND `LeafKind`.** Two cells are equal only if both
  their exposed content and their JSON leaf type match. "Aligned" therefore
  means *a v2 cross-Environment copy of this Entry would be a no-op*, keeping
  compare-"same" consistent with write-"same" — ADR 0008 preserves `LeafKind`
  precisely so v2 writes round-trip type. JSON type-drift (`5432` vs `"5432"`)
  surfaces as Drift, which a drift tool should catch.

- **Equality is computed directly in memory and surfaced as a row-local opaque
  group id — not a cryptographic hash.** Direct comparison gives **zero
  false-Aligned** (no collisions), is inherently per-comparison, and persists
  nothing, so there is no value fingerprint to leak or salt. This **refines**
  CONTEXT.md / ADR 0003's "equality grouping (by hash)": "by hash" names the
  masked *effect* (equality shown without plaintext); the mechanism is direct
  comparison. The prior ADR text stands unchanged.

- **Shapes map to rows via `RowKey { Entry(EntryName), WholeSet }`.** A JSON Set
  yields one `Entry` row per Entry; a Raw or Binary Set (which has no JSON entry
  names) yields the single `WholeSet` row. A Binary cell carries length + group
  only and is **structurally non-revealable** — the variant holds no `Value`, so
  ADR 0004's "never rendered" is enforced by the type, not a runtime check.

## Consequences

- The pure engine is offline-testable to the `core` ≥80% bar. Partial-fetch,
  retry, and re-auth handling live in the future fetch + GUI layers, not here.
- A GUI needing persistent state holds the fetched snapshot, not the
  `Comparison`. Recorded so the GUI slice does not hit the self-reference wall by
  surprise.
- Compare-"same" and write-"same" stay consistent (kind-sensitive), at the cost
  of reporting pure JSON-type differences as Drift.
- One small foundation addition: a **crate-internal** byte-equality on
  `SecretBytes` (for binary grouping). No public API behaviour changes, and the
  secret type gains no public value-comparison.
- Mixed-shape Environments (e.g. JSON in one, Raw in another) produce a
  non-panicking but rough matrix (entries as Gaps plus a `WholeSet` row).
  Accepted for v1, in the spirit of the renamed-key-drift limitation.

## Reference

Full design, type sketch, and test plan:
[`docs/superpowers/specs/2026-05-30-comparison-engine-design.md`](../superpowers/specs/2026-05-30-comparison-engine-design.md).
