# Comparison Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `janitor-core`'s offline comparison engine — turn N already-fetched `SecretShape`s into a masked Aligned/Drift/Gap matrix that borrows the canonical zeroizing Values it describes.

**Architecture:** A pure, synchronous module `janitor-core/src/compare/`. `Comparison::build` takes a slice of `(EnvironmentName, SecretShape)` (a complete, point-in-time snapshot — partial fetches fail upstream and never reach here) and returns a borrowed `Comparison<'a>`. Equality is by content bytes **and** `LeafKind`, computed directly in memory and surfaced as a row-local opaque `GroupId`. No AWS, no async, no new dependencies. See the spec: [`docs/superpowers/specs/2026-05-30-comparison-engine-design.md`](../specs/2026-05-30-comparison-engine-design.md) and [ADR 0009](../../adr/0009-comparison-engine-result-model.md).

**Tech Stack:** Rust (edition 2021), `secrecy` (zeroizing types, already a dependency), `cargo test` / `cargo clippy` / `cargo llvm-cov`. Work continues on the `feat/comparison-engine` branch.

---

## Background the engineer needs

- **`SecretShape`** (in `crate::secret`, re-exported from `src/secret/shape.rs`) is the parsed form of one Secret Set:
  - `SecretShape::Json(BTreeMap<EntryName, Value>)` — a JSON object flattened to dotted-path Entries.
  - `SecretShape::Raw(Value)` — a non-JSON string: one whole-value Entry.
  - `SecretShape::Binary(SecretBytes)` — opaque bytes; **never rendered**.
- **`Value`** (`crate::secret::Value`) holds a zeroizing `SecretString` + a `LeafKind` (`String`/`Number`/`Bool`/`Null`/`Json`). It is **not `Clone`**. Read content with `value.expose() -> &str`; type with `value.kind() -> LeafKind`. Its `Debug` is already redacted.
- **`EntryName`** (`crate::secret::EntryName`) is a dotted-path name: `Clone + Eq + Ord + Hash`. It is config metadata, not a secret.
- **`SecretBytes`** (`crate::secret::SecretBytes`) holds zeroizing bytes and today exposes only `len()`. Task 1 adds a crate-internal byte equality.
- **All `secret` types are re-exported at `crate::secret::…`** — always import from there (`use crate::secret::{Value, …}`), never from the private submodules (`crate::secret::shape::…` will not compile).
- **Test style:** the foundation puts a `#[cfg(test)] mod tests { use super::*; … }` block at the bottom of each file, with table-driven `assert_eq!`s and no extra dev-dependencies. Follow that. Run a single test with `cargo test -p janitor-core <substring>`.

## File Structure

| File | Responsibility |
| --- | --- |
| `janitor-core/src/secret/shape.rs` *(modify)* | Add `SecretBytes::bytes_eq` (crate-internal) for grouping Binary cells. |
| `janitor-core/src/lib.rs` *(modify)* | Add `pub mod compare;`. |
| `janitor-core/src/compare/mod.rs` *(create)* | Module doc; declare `model`/`engine`; re-export the public result types. |
| `janitor-core/src/compare/model.rs` *(create)* | Result types: `Comparison`, `Row`, `RowKey`, `EntryState`, `Cell`, `GroupId`; their `Debug`; `Cell::reveal`. No comparison logic. |
| `janitor-core/src/compare/engine.rs` *(create)* | `Comparison::build`, classification, the equality/grouping helper, shape→row mapping. Owns the engine tests. |

---

### Task 1: `SecretBytes::bytes_eq` (foundation touch)

Grouping Binary cells by *true* equality (not just equal length) needs a way to compare two `SecretBytes`. Add a **crate-internal** method — deliberately not a public `PartialEq`, so a secret type does not gain broad value comparison.

**Files:**
- Modify: `janitor-core/src/secret/shape.rs` (add a method to `impl SecretBytes`, after `is_empty`, around line 28; add a test in the existing `mod tests`)

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block at the bottom of `janitor-core/src/secret/shape.rs`:

```rust
    #[test]
    fn bytes_eq_compares_contents_not_just_length() {
        let a = SecretBytes::new(vec![1, 2, 3]);
        let b = SecretBytes::new(vec![1, 2, 3]);
        let same_len_diff = SecretBytes::new(vec![1, 2, 4]); // equal length, different bytes
        let diff_len = SecretBytes::new(vec![1, 2]);
        assert!(a.bytes_eq(&b), "identical bytes must be equal");
        assert!(!a.bytes_eq(&same_len_diff), "equal length but different bytes must NOT be equal");
        assert!(!a.bytes_eq(&diff_len), "different length must not be equal");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p janitor-core bytes_eq_compares_contents_not_just_length`
Expected: FAIL to compile — `no method named bytes_eq found for struct SecretBytes`.

- [ ] **Step 3: Add the method**

In `janitor-core/src/secret/shape.rs`, inside `impl SecretBytes`, immediately after the `is_empty` method, add:

```rust
    /// Crate-internal byte equality, used by the comparison engine to group
    /// Binary cells. Deliberately **not** a public `PartialEq`: a secret type
    /// should not gain broad value comparison. Not constant-time — both
    /// operands are in-process secrets the same user owns, so there is no
    /// cross-trust timing channel to defend.
    pub(crate) fn bytes_eq(&self, other: &SecretBytes) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
```

(`expose_secret` is already in scope via the `use secrecy::{ExposeSecret, SecretBox};` at the top of the file.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p janitor-core bytes_eq_compares_contents_not_just_length`
Expected: PASS (1 passed).

- [ ] **Step 5: Commit**

```bash
git add janitor-core/src/secret/shape.rs
git commit -m "feat(core): crate-internal SecretBytes::bytes_eq for comparison grouping"
```

---

### Task 2: `compare` module + result model

Create the module and the result types with their redacted `Debug` and the `reveal` accessor. No comparison logic yet — `Comparison::build` arrives in Task 4. These types are testable on their own by hand-constructing cells.

**Files:**
- Create: `janitor-core/src/compare/mod.rs`
- Create: `janitor-core/src/compare/model.rs`
- Modify: `janitor-core/src/lib.rs` (add `pub mod compare;` after `pub mod config;`)

- [ ] **Step 1: Wire the module into the crate**

In `janitor-core/src/lib.rs`, add a module declaration so the new code compiles. After the line `pub mod config;`, add:

```rust
pub mod compare;
```

Create `janitor-core/src/compare/mod.rs` with:

```rust
//! The comparison engine: turn already-fetched Secret Sets into a masked
//! Aligned/Drift/Gap matrix (ADR 0009). Pure and synchronous — it consumes
//! `SecretShape`s and never touches AWS.

mod engine;
mod model;

pub use model::{Cell, Comparison, EntryState, GroupId, Row, RowKey};
```

(`engine` is declared now so Task 4 can add it; create an empty `janitor-core/src/compare/engine.rs` for the moment so the crate compiles:)

```rust
//! Comparison construction and classification. Populated in Task 4.
```

- [ ] **Step 2: Write the failing tests**

Create `janitor-core/src/compare/model.rs` with **only** the test module first (the types come next), so the test names exist:

```rust
//! The comparison result model: a masked, point-in-time Aligned/Drift/Gap
//! matrix that borrows the canonical zeroizing Values it describes (ADR 0009).

use crate::secret::{EntryName, Value};

// (types are added in Step 3)

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> EntryName {
        EntryName::from_path(&[name.to_string()])
    }

    #[test]
    fn reveal_exposes_text_but_not_binary_or_absent() {
        let v = Value::string("s3cr3t");
        let text = Cell::Text { value: &v, len: 6, group: GroupId(0) };
        let binary = Cell::Binary { len: 4, group: GroupId(0) };
        let absent = Cell::Absent;
        assert_eq!(text.reveal().map(|v| v.expose()), Some("s3cr3t"));
        assert!(binary.reveal().is_none(), "Binary must never reveal");
        assert!(absent.reveal().is_none());
    }

    #[test]
    fn debug_never_leaks_a_value() {
        // Exercise all three Cell Debug arms (Text, Binary, Absent); the Binary
        // arm is the security-relevant one — it carries length, the deliberate
        // side-channel, and must still never print bytes.
        let v = Value::string("hunter2");
        let cmp = Comparison {
            environments: vec!["prod".to_string(), "staging".to_string(), "dev".to_string()],
            rows: vec![Row {
                key: RowKey::Entry(entry("PASSWORD")),
                state: EntryState::Gap,
                cells: vec![
                    Cell::Text { value: &v, len: 7, group: GroupId(0) },
                    Cell::Binary { len: 4, group: GroupId(1) },
                    Cell::Absent,
                ],
            }],
        };
        let rendered = format!("{cmp:?}");
        assert!(!rendered.contains("hunter2"), "Debug leaked the secret: {rendered}");
        assert!(rendered.contains("PASSWORD"), "Entry names are metadata and should show");
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p janitor-core --lib compare::model`
Expected: FAIL to compile — `Cell`, `Comparison`, `Row`, etc. are not defined yet.

- [ ] **Step 4: Add the result types**

In `janitor-core/src/compare/model.rs`, between the `use` line and the `#[cfg(test)]` block, add:

```rust
/// A point-in-time comparison of one Application's Set across its Environments.
/// Borrows the fetched Sets — build it to render, don't store it (ADR 0009).
#[derive(Debug)]
pub struct Comparison<'a> {
    /// Column labels (Environment names), in input order.
    pub environments: Vec<String>,
    /// Entry rows ordered by name, then the `WholeSet` row (if any) last.
    pub rows: Vec<Row<'a>>,
}

/// One Entry (or the whole Raw/Binary Set) compared across the Environments.
#[derive(Debug)]
pub struct Row<'a> {
    pub key: RowKey,
    pub state: EntryState,
    /// Column-aligned to [`Comparison::environments`].
    pub cells: Vec<Cell<'a>>,
}

/// What a row is keyed by. A JSON Set yields `Entry` rows; a Raw or Binary Set
/// (which has no JSON entry names) yields the single `WholeSet` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowKey {
    Entry(EntryName),
    WholeSet,
}

/// The comparison state of a row across all compared Environments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// Present in every Environment with an identical Value (and `LeafKind`).
    Aligned,
    /// Present in every Environment, but Values differ.
    Drift,
    /// Present in some Environments and missing in others — the high-signal finding.
    Gap,
}

/// One Environment's view of a row.
pub enum Cell<'a> {
    /// A JSON leaf Entry or a Raw whole-value — revealable.
    Text { value: &'a Value, len: usize, group: GroupId },
    /// A `SecretBinary` Set — length and equality only; never revealable.
    Binary { len: usize, group: GroupId },
    /// Not present in this Environment.
    Absent,
}

impl Cell<'_> {
    /// Borrow the plaintext Value for a momentary reveal (the GUI handles the
    /// auto-hide timing — ADR 0003). `Some` only for `Text`; `Binary` is never
    /// revealable (ADR 0004) and `Absent` has nothing to show.
    pub fn reveal(&self) -> Option<&Value> {
        match self {
            Cell::Text { value, .. } => Some(value),
            Cell::Binary { .. } | Cell::Absent => None,
        }
    }
}

// Manual Debug so a cell never prints its Value; length is a tolerated
// side-channel (CONTEXT.md). `Comparison`/`Row` derive Debug on top of this.
impl std::fmt::Debug for Cell<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cell::Text { len, group, .. } => f
                .debug_struct("Text")
                .field("len", len)
                .field("group", group)
                .finish_non_exhaustive(),
            Cell::Binary { len, group } => f
                .debug_struct("Binary")
                .field("len", len)
                .field("group", group)
                .finish(),
            Cell::Absent => f.write_str("Absent"),
        }
    }
}

/// Row-local opaque equality token: `Copy + Eq`, comparable only within one
/// `Row` (group ids carry no meaning across rows; the view compares them to
/// colour cells that match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupId(pub(crate) u32);
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p janitor-core --lib compare::model`
Expected: PASS (2 passed). Also run `cargo build -p janitor-core` to confirm the crate compiles with the empty `engine.rs`.

- [ ] **Step 6: Commit**

```bash
git add janitor-core/src/lib.rs janitor-core/src/compare/mod.rs janitor-core/src/compare/model.rs janitor-core/src/compare/engine.rs
git commit -m "feat(core): comparison result model (types, redacted Debug, reveal)"
```

---

### Task 3: Equality + grouping helper

The security-sensitive core: deciding when two cells are "the same Value" and assigning row-local group ids. Isolated as pure internal functions so it can be tested directly.

**Files:**
- Modify: `janitor-core/src/compare/engine.rs`

- [ ] **Step 1: Write the failing tests**

Replace the contents of `janitor-core/src/compare/engine.rs` with the imports, the `Present` type, and a test module (the helpers come next):

```rust
//! Comparison construction and classification.

// NOTE: `BTreeSet`, `EntryName`, `SecretShape`, and the `Cell`/`Comparison`/
// `EntryState`/`Row`/`RowKey` model types are used by `build`/`build_row` in
// Task 4. They are imported now but unused until then — do NOT remove them when
// tidying warnings; Task 4 will not compile without them.
use std::collections::BTreeSet;

use crate::secret::{EntryName, SecretBytes, SecretShape, Value};

use super::model::{Cell, Comparison, EntryState, GroupId, Row, RowKey};

/// The present content of one cell, borrowed for equality grouping. References
/// are `Copy`, so `Present` is too.
#[derive(Clone, Copy)]
enum Present<'a> {
    Text(&'a Value),
    Binary(&'a SecretBytes),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::LeafKind;

    #[test]
    fn group_ids_assign_by_equality_in_column_order() {
        let a = Value::string("x");
        let b = Value::string("x");
        let c = Value::string("y");
        let present = [Present::Text(&a), Present::Text(&b), Present::Text(&c)];
        assert_eq!(group_ids(&present), vec![GroupId(0), GroupId(0), GroupId(1)]);
    }

    #[test]
    fn group_ids_are_leafkind_sensitive() {
        let number = Value::new("5432", LeafKind::Number);
        let string = Value::new("5432", LeafKind::String);
        let present = [Present::Text(&number), Present::Text(&string)];
        // Same bytes, different JSON type => different groups (ADR 0009).
        assert_eq!(group_ids(&present), vec![GroupId(0), GroupId(1)]);
    }

    #[test]
    fn group_ids_never_equate_text_and_binary() {
        let text = Value::string("AAAA");
        let bytes = SecretBytes::new(b"AAAA".to_vec());
        let present = [Present::Text(&text), Present::Binary(&bytes)];
        assert_eq!(group_ids(&present), vec![GroupId(0), GroupId(1)]);
    }

    #[test]
    fn group_ids_compare_binary_by_bytes() {
        let a = SecretBytes::new(vec![1, 2, 3]);
        let b = SecretBytes::new(vec![1, 2, 3]);
        let c = SecretBytes::new(vec![1, 2, 4]);
        let present = [Present::Binary(&a), Present::Binary(&b), Present::Binary(&c)];
        assert_eq!(group_ids(&present), vec![GroupId(0), GroupId(0), GroupId(1)]);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p janitor-core --lib compare::engine`
Expected: FAIL to compile — `group_ids` is not defined. (Imports `EntryName`, `SecretShape`, `Cell`, `Comparison`, `EntryState`, `Row`, `RowKey`, `BTreeSet` are unused for now; that is expected and resolved in Task 4. If a warning is denied as an error locally, proceed — Task 4 uses them.)

- [ ] **Step 3: Add the equality and grouping helpers**

In `janitor-core/src/compare/engine.rs`, immediately after the `Present` enum definition, add:

```rust
/// Are two present cells the same Value? Text matches on content bytes **and**
/// `LeafKind` (ADR 0009: Aligned ⇔ a v2 copy would be a no-op). Binary matches
/// on bytes. Text and Binary are never equal.
fn same_value(a: &Present, b: &Present) -> bool {
    match (a, b) {
        (Present::Text(x), Present::Text(y)) => {
            x.kind() == y.kind() && x.expose().as_bytes() == y.expose().as_bytes()
        }
        (Present::Binary(x), Present::Binary(y)) => x.bytes_eq(y),
        _ => false,
    }
}

/// Assign a row-local [`GroupId`] to each present cell: equal Values share an
/// id, ids issued in first-seen (column) order. O(n²) over the present cells in
/// a row — n is the number of Environments, so this is tiny.
fn group_ids(present: &[Present]) -> Vec<GroupId> {
    let mut ids = Vec::with_capacity(present.len());
    let mut representatives: Vec<usize> = Vec::new(); // index of each group's first cell
    for (i, cell) in present.iter().enumerate() {
        match representatives
            .iter()
            .position(|&r| same_value(&present[r], cell))
        {
            Some(group) => ids.push(GroupId(group as u32)),
            None => {
                ids.push(GroupId(representatives.len() as u32));
                representatives.push(i);
            }
        }
    }
    ids
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p janitor-core --lib compare::engine`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add janitor-core/src/compare/engine.rs
git commit -m "feat(core): value-equality + row-local grouping for the comparison engine"
```

---

### Task 4: `Comparison::build`

Wire shapes into rows, classify each row, and produce the full matrix. The tests cover every spec case: Aligned/Drift/Gap, Gap-beats-Drift, `LeafKind` sensitivity, empty-value-vs-absent, Raw, Binary, mixed shapes, ordering, and N=0/N=1.

**Files:**
- Modify: `janitor-core/src/compare/engine.rs`

- [ ] **Step 1: Write the failing tests**

In `janitor-core/src/compare/engine.rs`, add these tests **inside** the existing `mod tests` block (after the grouping tests). They use small helpers to build inputs and read results:

```rust
    // `SecretShape`, the model types, and `EntryName` are already in scope via
    // the `use super::*;` at the top of this `mod tests` (from Task 3).

    fn env(name: &str, shape: SecretShape) -> (String, SecretShape) {
        (name.to_string(), shape)
    }
    fn json(s: &str) -> SecretShape {
        SecretShape::from_secret_string(s)
    }

    fn row<'a>(cmp: &'a Comparison<'a>, name: &str) -> &'a Row<'a> {
        cmp.rows
            .iter()
            .find(|r| matches!(&r.key, RowKey::Entry(n) if n.as_str() == name))
            .unwrap_or_else(|| panic!("no Entry row named {name}"))
    }
    fn whole_set<'a>(cmp: &'a Comparison<'a>) -> &'a Row<'a> {
        cmp.rows
            .iter()
            .find(|r| r.key == RowKey::WholeSet)
            .expect("no WholeSet row")
    }

    #[test]
    fn aligned_when_present_and_equal_everywhere() {
        let envs = [env("prod", json(r#"{"A":"1"}"#)), env("staging", json(r#"{"A":"1"}"#))];
        let cmp = Comparison::build(&envs);
        assert_eq!(cmp.environments, vec!["prod".to_string(), "staging".to_string()]);
        let r = row(&cmp, "A");
        assert_eq!(r.state, EntryState::Aligned);
        assert!(matches!(r.cells[0], Cell::Text { group: GroupId(0), .. }));
        assert!(matches!(r.cells[1], Cell::Text { group: GroupId(0), .. }));
    }

    #[test]
    fn drift_when_present_everywhere_but_values_differ() {
        let envs = [env("prod", json(r#"{"A":"1"}"#)), env("staging", json(r#"{"A":"2"}"#))];
        let cmp = Comparison::build(&envs);
        let r = row(&cmp, "A");
        assert_eq!(r.state, EntryState::Drift);
        assert!(matches!((&r.cells[0], &r.cells[1]),
            (Cell::Text { group: GroupId(0), .. }, Cell::Text { group: GroupId(1), .. })));
    }

    #[test]
    fn gap_when_present_in_some_and_absent_in_others() {
        let envs = [env("prod", json(r#"{"A":"1"}"#)), env("staging", json(r#"{"B":"1"}"#))];
        let cmp = Comparison::build(&envs);
        assert_eq!(row(&cmp, "A").state, EntryState::Gap);
        assert!(matches!(row(&cmp, "A").cells[1], Cell::Absent));
        assert_eq!(row(&cmp, "B").state, EntryState::Gap);
        assert!(matches!(row(&cmp, "B").cells[0], Cell::Absent));
    }

    #[test]
    fn gap_beats_drift_when_differing_and_also_absent() {
        // Present-but-differing in prod & staging, absent in dev => Gap, not Drift.
        let envs = [
            env("prod", json(r#"{"A":"1"}"#)),
            env("staging", json(r#"{"A":"2"}"#)),
            env("dev", json(r#"{"Z":"9"}"#)),
        ];
        let cmp = Comparison::build(&envs);
        assert_eq!(row(&cmp, "A").state, EntryState::Gap);
    }

    #[test]
    fn leafkind_difference_is_drift() {
        // 5432 (Number) vs "5432" (String): same text, different JSON type.
        let envs = [env("prod", json(r#"{"port":5432}"#)), env("staging", json(r#"{"port":"5432"}"#))];
        let cmp = Comparison::build(&envs);
        assert_eq!(row(&cmp, "port").state, EntryState::Drift);
    }

    #[test]
    fn empty_value_is_present_not_absent() {
        let envs = [env("prod", json(r#"{"A":""}"#)), env("staging", json(r#"{"A":""}"#))];
        let cmp = Comparison::build(&envs);
        let r = row(&cmp, "A");
        assert_eq!(r.state, EntryState::Aligned);
        assert!(matches!(r.cells[0], Cell::Text { len: 0, .. }), "empty value is Present len 0");
    }

    #[test]
    fn raw_sets_compare_as_one_whole_set_row() {
        let envs = [
            env("prod", SecretShape::from_secret_string("token-xyz")),
            env("staging", SecretShape::from_secret_string("token-xyz")),
        ];
        let cmp = Comparison::build(&envs);
        assert_eq!(cmp.rows.len(), 1);
        let r = whole_set(&cmp);
        assert_eq!(r.state, EntryState::Aligned);
        assert!(matches!(r.cells[0], Cell::Text { .. }));
        assert_eq!(r.cells[0].reveal().map(|v| v.expose()), Some("token-xyz"));
    }

    #[test]
    fn binary_sets_are_a_whole_set_row_compared_by_bytes_and_never_revealed() {
        let envs = [
            env("prod", SecretShape::from_secret_binary(vec![1, 2, 3, 4])),
            env("staging", SecretShape::from_secret_binary(vec![1, 2, 3, 4])),
            env("dev", SecretShape::from_secret_binary(vec![1, 2, 3, 9])), // same length, different bytes
        ];
        let cmp = Comparison::build(&envs);
        let r = whole_set(&cmp);
        assert_eq!(r.state, EntryState::Drift, "equal length but different bytes is Drift");
        for cell in &r.cells {
            assert!(matches!(cell, Cell::Binary { len: 4, .. }));
            assert!(cell.reveal().is_none(), "Binary must never reveal");
        }
    }

    #[test]
    fn mixed_shapes_do_not_panic() {
        // prod is JSON, dev is Raw: entries become Gaps and a WholeSet row appears.
        let envs = [env("prod", json(r#"{"A":"1"}"#)), env("dev", SecretShape::from_secret_string("raw"))];
        let cmp = Comparison::build(&envs);
        assert_eq!(row(&cmp, "A").state, EntryState::Gap);
        assert_eq!(whole_set(&cmp).state, EntryState::Gap);
    }

    #[test]
    fn rows_are_sorted_by_name_with_whole_set_last() {
        let envs = [env("prod", json(r#"{"B":"1","A":"1"}"#)), env("staging", SecretShape::from_secret_string("raw"))];
        let cmp = Comparison::build(&envs);
        let keys: Vec<&RowKey> = cmp.rows.iter().map(|r| &r.key).collect();
        assert_eq!(keys[0], &RowKey::Entry(EntryName::from_path(&["A".to_string()])));
        assert_eq!(keys[1], &RowKey::Entry(EntryName::from_path(&["B".to_string()])));
        assert_eq!(keys[2], &RowKey::WholeSet);
    }

    #[test]
    fn build_is_total_for_zero_and_one_environment() {
        let empty: [(String, SecretShape); 0] = [];
        let cmp0 = Comparison::build(&empty);
        assert!(cmp0.environments.is_empty() && cmp0.rows.is_empty());

        let one = [env("prod", json(r#"{"A":"1"}"#))];
        let cmp1 = Comparison::build(&one);
        assert_eq!(row(&cmp1, "A").state, EntryState::Aligned); // single column => trivially Aligned
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p janitor-core --lib compare::engine`
Expected: FAIL to compile — `Comparison::build` is not defined.

- [ ] **Step 3: Implement `build` and `build_row`**

In `janitor-core/src/compare/engine.rs`, add (after `group_ids`, before the `#[cfg(test)]` block):

```rust
impl<'a> Comparison<'a> {
    /// Compare N successfully-fetched Sets, labelled by Environment name, into a
    /// masked Aligned/Drift/Gap matrix (ADR 0009). **Total** — never panics:
    /// N = 0 yields an empty matrix; N = 1 yields one column in which every
    /// present Entry is trivially Aligned. A partial fetch is handled upstream
    /// and never reaches here (the input cannot express an absent Environment).
    pub fn build(environments: &'a [(String, SecretShape)]) -> Comparison<'a> {
        let labels = environments.iter().map(|(name, _)| name.clone()).collect();

        // Row universe: the union of JSON Entry names, plus a single WholeSet row
        // iff any Environment is a Raw or Binary Set (which has no entry names).
        let mut entry_names: BTreeSet<EntryName> = BTreeSet::new();
        let mut has_whole_set = false;
        for (_, shape) in environments {
            match shape {
                SecretShape::Json(entries) => entry_names.extend(entries.keys().cloned()),
                SecretShape::Raw(_) | SecretShape::Binary(_) => has_whole_set = true,
            }
        }

        let mut rows: Vec<Row<'a>> = Vec::with_capacity(entry_names.len() + has_whole_set as usize);
        for name in &entry_names {
            rows.push(build_row(RowKey::Entry(name.clone()), environments, |shape| {
                match shape {
                    SecretShape::Json(entries) => entries.get(name).map(Present::Text),
                    SecretShape::Raw(_) | SecretShape::Binary(_) => None,
                }
            }));
        }
        if has_whole_set {
            rows.push(build_row(RowKey::WholeSet, environments, |shape| match shape {
                SecretShape::Raw(value) => Some(Present::Text(value)),
                SecretShape::Binary(bytes) => Some(Present::Binary(bytes)),
                SecretShape::Json(_) => None,
            }));
        }

        Comparison { environments: labels, rows }
    }
}

/// Build one row: project each Environment's shape to a cell via `cell_of`,
/// group the present cells, classify, and assemble the column-aligned cells.
fn build_row<'a>(
    key: RowKey,
    environments: &'a [(String, SecretShape)],
    cell_of: impl Fn(&'a SecretShape) -> Option<Present<'a>>,
) -> Row<'a> {
    // Per-column present content (None = Absent), in input order.
    let present_by_col: Vec<Option<Present<'a>>> =
        environments.iter().map(|(_, shape)| cell_of(shape)).collect();

    // Group ids over just the present cells, in column order.
    let present: Vec<Present<'a>> = present_by_col.iter().copied().flatten().collect();
    let ids = group_ids(&present);

    // Assemble cells, threading the present-only group ids back onto columns.
    let mut cells: Vec<Cell<'a>> = Vec::with_capacity(present_by_col.len());
    let mut next = 0usize;
    let mut any_absent = false;
    for slot in present_by_col.iter().copied() {
        match slot {
            None => {
                cells.push(Cell::Absent);
                any_absent = true;
            }
            Some(Present::Text(value)) => {
                let group = ids[next];
                next += 1;
                cells.push(Cell::Text { value, len: value.expose().len(), group });
            }
            Some(Present::Binary(bytes)) => {
                let group = ids[next];
                next += 1;
                cells.push(Cell::Binary { len: bytes.len(), group });
            }
        }
    }

    // Every row has ≥1 present cell, so `any_absent` alone means "present in some,
    // missing in others" — Gap, which beats Drift. Otherwise all present: one
    // group ⇒ Aligned, ≥2 groups ⇒ Drift.
    let all_equal = ids.windows(2).all(|w| w[0] == w[1]);
    let state = if any_absent {
        EntryState::Gap
    } else if all_equal {
        EntryState::Aligned
    } else {
        EntryState::Drift
    };

    Row { key, state, cells }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p janitor-core --lib compare::engine`
Expected: PASS (all engine tests green — the 4 grouping tests plus the 11 build tests).

- [ ] **Step 5: Commit**

```bash
git add janitor-core/src/compare/engine.rs
git commit -m "feat(core): Comparison::build — Aligned/Drift/Gap matrix over SecretShapes"
```

---

### Task 5: Quality gate

Confirm the whole crate is clean and the `core` ≥80% coverage bar holds.

**Files:** none (verification only).

- [ ] **Step 1: Format and lint**

Run: `cargo fmt -p janitor-core` then `cargo clippy -p janitor-core --all-targets -- -D warnings`
Expected: no diff from `fmt`; clippy reports no warnings. Fix any clippy findings (e.g. an unused import left over from Task 3) and re-run.

- [ ] **Step 2: Full test run**

Run: `cargo test -p janitor-core`
Expected: PASS — all foundation tests plus the new `compare::model` and `compare::engine` tests.

- [ ] **Step 3: Coverage**

Run: `cargo llvm-cov -p janitor-core`
Expected: `janitor-core` line coverage ≥80%; the new `compare/` files should be near-fully covered. If a branch is uncovered (e.g. the mixed Text-vs-Binary group arm), add the missing case to the engine tests, then re-run from Step 2.

- [ ] **Step 4: Commit any fixes**

```bash
git add -A
git commit -m "test(core): tidy lints and close comparison-engine coverage gaps"
```

(If Steps 1–3 produced no changes, skip this commit.)

---

## Self-review (completed while writing this plan)

**Spec coverage** — every spec section maps to a task:
- Result types (`Comparison`/`Row`/`RowKey`/`EntryState`/`Cell`/`GroupId`) → Task 2.
- Classification (Aligned/Drift/Gap, Gap-beats-Drift, empty-vs-absent) → Task 4 (tests + `build_row`).
- Shape→rows (Json/Raw/Binary/mixed, WholeSet) → Task 4.
- Equality = bytes + `LeafKind`; binary by bytes; Text≠Binary → Task 3.
- Reveal (Text→Some, Binary→None) and binary structural suppression → Task 2 (`Cell::reveal`, no `Value` in `Binary`).
- Masked cell = presence + len + group → Task 2 (`Cell` fields) + Task 4 (`len` set from `expose().len()` / `bytes.len()`).
- No-leak: redacted Debug, no Serialize, leak test → Task 2 (manual `Cell` Debug, derived `Comparison`/`Row` Debug, `debug_never_leaks_a_value`).
- Foundation touch (`SecretBytes` equality) → Task 1.
- Module layout / sync / no new deps → Tasks 2–4 (no `Cargo.toml` change).
- Ordering determinism, N=0/N=1 totality → Task 4 tests.
- `core` ≥80% coverage → Task 5.

**Placeholder scan:** none — every code step shows complete code; every command shows expected output.

**Type consistency:** `Comparison`/`Row`/`RowKey`/`EntryState`/`Cell`/`GroupId`, `Present`, `same_value`, `group_ids`, `build`, `build_row`, and `SecretBytes::bytes_eq` are used with identical names and signatures across all tasks. Imports use the re-exported `crate::secret::…` paths (verified against `src/secret/mod.rs`).

## Out of scope (follow-on slices)

Prefix clustering (`GITHUB_APP_*`), sorting, and filtering operate on the finished matrix and are a separate slice. AWS fetch/auth, version-history retrieval, the write engine, and the GUI are later slices. Mixed-shape comparison is intentionally a v1 rough edge (does not panic; not refined further).
