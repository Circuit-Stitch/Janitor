# Comparison engine — design

**Date:** 2026-05-30
**Slice of:** `janitor-core`
**Status:** approved (decisions settled with the maintainer; pending written-spec review)

## Why this slice

Janitor's job #1 is **drift detection**: comparing the same logical Secret Set
across N Environments and labelling each Entry **Aligned**, **Drift**, or **Gap**
(CONTEXT.md). This is the first slice after the offline foundation
(`SecretShape` / `flatten` / `Value` / `Config`) and the natural next step toward
the read-only v1 viewer (ADR 0004):

- It is **pure and fully testable offline** — it consumes already-fetched
  `SecretShape`s and touches no AWS, so it honours the `core` ≥80% coverage
  mandate without an AWS account in the loop.
- It builds directly on the just-landed secret-shape model.
- It nails the matrix semantics that the GUI (what to render) and v2
  write-targeting (what "the same" means) both depend on.

Auth / Secrets Manager I/O is deferred to a later slice; it produces the data
this engine consumes (see [`lib.rs`](../../../janitor-core/src/lib.rs): core
logic depends on an AWS-client trait; the SDK is never wired in directly).

## Scope

**In:** the comparison result model (types), classification into
Aligned/Drift/Gap, masked cells (presence + length + equality group), per-cell
reveal (with binary structurally suppressed), and the `SecretShape` → matrix-row
mapping for all three shapes (Json / Raw / Binary).

**Out (next slice):** prefix clustering (`GITHUB_APP_*`), sorting, and
filtering. These are presentation predicates that operate *on* the finished
matrix; isolating the security-sensitive core (Values + equality + reveal) and
testing it exhaustively before layering presentation on top.

**Out (other slices):** AWS fetch/auth, version-history retrieval (ADR 0006),
the write engine (ADR 0001), and the GUI.

## What it consumes (foundation, already built)

- `SecretShape` — `Json(BTreeMap<EntryName, Value>)` | `Raw(Value)` |
  `Binary(SecretBytes)`.
- `Value` — a zeroizing `SecretString` + `LeafKind`, with a redacted `Debug`
  and a single `expose() -> &str` accessor. **Not `Clone`.**
- `LeafKind` — `String | Number | Bool | Null | Json` (preserved so a v2 write
  round-trips the original JSON type — ADR 0008).
- `EntryName` — dotted-path name, `Clone + Eq + Ord + Hash`; an Entry *name* is
  config metadata, not secret material.
- `SecretBytes` — zeroizing bytes; today exposes only `len()` (see Foundation
  touch below).
- `Config` → `Application { name, environments: Vec<Mapping> }`,
  `Mapping { environment, account_id, region, secret_id, permission_set }`. An
  Environment is identified within an Application by `Mapping.environment`.

## Approved decisions

1. **Complete input / fail-whole-comparison.** The engine assumes every
   Environment was fetched successfully. A partial fetch (Credential lapsed,
   access denied, network error) is handled *upstream* (the fetch/orchestration
   layer errors and never calls the engine). A partial comparison is therefore
   **unrepresentable**, not merely discouraged — there is no "unavailable
   Environment" variant in the engine's input. Consequence: because a matrix is
   never rendered with missing data, a **Gap always means a real Gap**. Accepted
   trade-off: one denied/slow Environment blocks the whole Application matrix.
   (This satisfies the "never report a fake Gap" requirement via a stricter
   precondition instead of a richer model, and keeps the engine exactly on the
   glossary's "every Entry is one of Aligned/Drift/Gap".)

2. **Transient borrow.** `Comparison<'a>` *borrows* the fetched Sets; a present
   cell carries `&'a Value`, and reveal is a method on the cell. The GUI keeps
   the **fetched snapshot** (`Vec<(EnvName, SecretShape)>`) as its source of
   truth (ADR 0005: a point-in-time, manually-refreshed snapshot) and rebuilds
   the `Comparison` projection to render / on refresh / on reveal — microseconds
   at realistic sizes. The `Comparison` cannot be stored *beside* the Sets it
   borrows (Rust rejects self-reference); it needn't be. **There is exactly one
   copy of each Value**, owned by the snapshot in `core`'s zeroizing buffer and
   borrowed by the matrix (ADR 0003).

3. **Equality = content bytes AND `LeafKind`.** Two cells are equal only if both
   their exposed content *and* their JSON leaf type match. So `port:5432`
   (Number) vs `port:"5432"` (String) is **Drift**, not Aligned. This makes
   "Aligned" mean precisely *a v2 cross-Environment copy of this Entry would be a
   no-op*, keeping compare-"same" consistent with write-"same" (ADR 0008
   preserves `LeafKind` exactly so writes round-trip type). Catching type-drift
   is a feature of a drift tool, not noise.

4. **Direct in-memory equality; opaque row-local `GroupId`.** Grouping is
   computed by directly comparing the in-memory Values (bytes + kind) — not a
   cryptographic hash. The token surfaced to the view is a **row-local opaque
   group id** (cells sharing it have equal Values). This realises the docs'
   "equality grouping (by hash)" by its **effect** (equality shown without
   plaintext) with **zero false-Aligned** (no hash collisions), is inherently
   per-comparison, and persists nothing — so there is no value fingerprint to
   leak or salt. (The "by hash" wording is reconciled in ADR 0009 as a
   mechanism refinement; CONTEXT.md / ADR 0003 / ADR 0004 text is left intact.)

5. **Engine core only** (see Scope).

## Result types

```rust
/// A point-in-time comparison of one Application's Set across its Environments.
/// Borrows the fetched Sets; rebuild rather than store (decision 2).
pub struct Comparison<'a> {
    /// Column labels (Environment names), in input order.
    pub environments: Vec<String>,
    /// One row per Entry plus at most one `WholeSet` row; ordered
    /// deterministically — `Entry` rows by name, the `WholeSet` row (if any)
    /// last.
    pub rows: Vec<Row<'a>>,
}

pub struct Row<'a> {
    pub key: RowKey,
    pub state: EntryState,
    /// Column-aligned to `Comparison::environments`.
    pub cells: Vec<Cell<'a>>,
}

/// A JSON Set yields `Entry` rows; a Raw/Binary Set (no JSON entry names) yields
/// the single `WholeSet` row.
pub enum RowKey {
    Entry(EntryName),
    WholeSet,
}

pub enum EntryState { Aligned, Drift, Gap }

pub enum Cell<'a> {
    /// A JSON leaf Entry, or a Raw whole-value. Revealable.
    Text { value: &'a Value, len: usize, group: GroupId },
    /// A `SecretBinary` Set. Length + equality only; NEVER revealable (ADR 0004).
    Binary { len: usize, group: GroupId },
    /// Not present in this Environment.
    Absent,
}

/// Row-local opaque equality token: `Copy + Eq`, comparable only within one
/// `Row` (group ids carry no meaning across rows; the view compares them to
/// colour cells that match).
pub struct GroupId(u32);
```

The exact `build` signature is an implementation detail; the shape is:

```rust
impl<'a> Comparison<'a> {
    /// Compare N successfully-fetched Sets, labelled by Environment name.
    /// `build` is total: N = 0 yields an empty matrix; N = 1 yields one column
    /// in which every present Entry is trivially Aligned. Never panics.
    pub fn build(environments: &'a [(String, SecretShape)]) -> Comparison<'a> { /* … */ }
}
```

## Classification (per row, over its cells)

1. **Gap** ⟺ at least one `Absent` cell **and** at least one present cell
   (present in some Environments, missing in others — the high-signal finding).
   *Gap is checked first and beats Drift:* an Entry that differs in two
   Environments and is absent in a third is a **Gap**, not Drift.
2. Otherwise (all present): **Aligned** if all present cells share one
   `GroupId`; **Drift** if they span ≥2 groups.
3. Every row has ≥1 present cell (a name only enters the row universe because
   some Environment has it), so "all absent" cannot occur.
4. An empty value (`""`) is **Present, `len` 0** — distinct from `Absent`.

Group ids are still computed for present cells inside a Gap row (useful to the
view: "present in prod & staging and they match; absent in dev"); the row state
is Gap regardless.

## `SecretShape` → rows

| Shape          | Contributes                                         |
| -------------- | --------------------------------------------------- |
| `Json(entries)`| one `Entry(name)` row per entry                     |
| `Raw(value)`   | a `Text` cell in the single `WholeSet` row          |
| `Binary(bytes)`| a `Binary` cell in the single `WholeSet` row        |

- **Homogeneous Environments** (the realistic case) are clean: all-Json → Entry
  rows only; all-Raw or all-Binary → exactly one `WholeSet` row.
- **Mixed shapes** (e.g. prod Json, dev Raw) do not panic: the Json entries read
  as Gaps and a `WholeSet` row appears. Documented as a v1 rough edge, in the
  same spirit as the accepted renamed-key-drift limitation (CONTEXT.md).

## Equality & grouping mechanics

- **Text vs Text:** equal ⟺ `a.expose().as_bytes() == b.expose().as_bytes()`
  **and** `a.kind() == b.kind()` (decision 3). (A `Raw` value is `LeafKind::String`,
  so Raw cells compare as String-kind text.)
- **Binary vs Binary:** equal ⟺ the underlying bytes are equal — *not* merely
  equal length (length-only would risk a false-Aligned, unacceptable in a
  security tool). Requires a small foundation touch (below).
- **Text vs Binary** (only possible in a mixed-shape `WholeSet` row): never
  equal — different kinds → different groups.
- Within each row, present cells are assigned group ids in column order
  (first-seen → `GroupId(0)`, next distinct → `GroupId(1)`, …). Group ids carry
  no meaning across rows.

## Reveal & masking

- `Cell::reveal(&self) -> Option<&Value>` → `Some` for `Text`; `None` for
  `Binary` and `Absent`. Binary cannot be revealed because the variant holds no
  `Value` at all — the "never rendered" guarantee (ADR 0004) is **structural,
  not a runtime check**. The caller (GUI) handles the *momentary* aspect
  (auto-hide on timeout/blur — ADR 0003).
- The **masked** representation of a present cell is `presence + len + group` —
  exactly what ADR 0003's masked view renders (length-sized dots + a group
  marker). No plaintext is reachable on the masked path.

## Security / no-leak (invariant #1)

- Manual `Debug` on `Cell` / `Row` / `Comparison` shows only `state` / `len` /
  `group` / `key` — never a `Value` or bytes (mirrors the existing redacted
  `Debug` on `Value` and `SecretBytes`).
- **No `Serialize` / `Deserialize`** on any of these types (Config is the only
  thing that is persisted, and it holds locations, never Values).
- No `Display` that prints a Value; no Value content in any error message.
- A leak test builds a `Comparison` over a known secret and asserts
  `format!("{cmp:?}")` contains neither the plaintext nor the binary bytes.

## Foundation touch

`SecretBytes` exposes only `len()`. To group `Binary` cells by *true* equality,
add a **crate-internal** equality helper (e.g. `pub(crate) fn ct_eq(&self,
other: &SecretBytes) -> bool`, or a `pub(crate)` byte accessor used only by the
compare module) — deliberately *not* a public `impl PartialEq`, to avoid giving
a secret type broad value-comparison semantics. This is the only change to
just-landed code; no behaviour of existing public APIs changes.

## Module layout

- New module `janitor-core/src/compare/` (`pub mod compare;` in `lib.rs`).
  Split into a types module and a build/classify module if it grows; one file is
  fine initially.
- **Synchronous, no new runtime dependencies** (no AWS, no tokio, no hash crate).
- Tests are table-driven and dependency-light, matching the existing foundation
  style (the dev-deps stay as just `tempfile`).

## Testing (`core` ≥80%; table-driven)

- Aligned / Drift / Gap at N = 2 and N ≥ 3.
- Mixed group within a row (prod = staging ≠ dev → Drift, groups `{0,0,1}`).
- **Gap beats Drift:** differs in two Environments, absent in a third → Gap.
- `LeafKind`-sensitive equality: `5432`#Number vs `"5432"`#String → Drift.
- Raw homogeneous → one `WholeSet` row; Aligned and Drift cases.
- Binary homogeneous → one `WholeSet` row; equality by bytes (equal-length but
  different bytes ⇒ Drift, not Aligned); `reveal() == None`.
- Mixed-shape input does not panic and produces a sensible matrix.
- Reveal: `Text → Some`, `Binary → None`, `Absent → None`.
- Empty value vs absent: `""` is Present/len 0, never `Absent`.
- Opaque-Json-leaf entries (arrays / empty objects) compare like any Text.
- `len` correctness (byte length of the exposed value / blob).
- Deterministic ordering: rows by name, columns by input order.
- `build` total for N = 0 (empty matrix) and N = 1 (single column, all Aligned).
- Debug-leak test (above).

## Accompanying docs

- **ADR 0009 — comparison-engine result model** (terse decision record): the
  load-bearing, hard-to-reverse choices — complete-input/snapshot, the
  transient-borrow contract, equality = bytes + kind, direct-equality vs hash,
  `RowKey`/`WholeSet`, binary-never-reveal.
- **CONTEXT.md:** no change. "WholeSet row" is implementation modelling, not
  domain vocabulary; the glossary's "equality grouping (by hash)" stays as the
  conceptual description and ADR 0009 refines the mechanism.

## Risks / open items

- None blocking. The `build` input shape (`&[(String, SecretShape)]` vs a
  dedicated newtype) is a detail to settle during the writing-plans step.
- Mixed-shape comparison is intentionally a rough edge for v1; revisit only if
  real data shows it matters.
