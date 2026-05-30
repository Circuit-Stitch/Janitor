# GUI Tracer-Bullet Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the end-to-end thread *Slint window → mock `SecretSource` → `Comparison::build` → masked matrix → per-cell reveal*, with sidebar app-switching and a faked (in-memory) settings/preferences surface.

**Architecture:** A new thin `janitor-gui` Slint crate renders state produced entirely by `janitor-core`. A synchronous `SecretSource` trait (the future AWS-adapter seam) is satisfied by an in-memory `MockSource`. Core gains a pure, owned `MatrixView` projection of the borrowed `Comparison`, plus a `reveal_value` lookup — both unit-tested without Slint. The GUI holds only masked tokens; plaintext is re-borrowed from core's zeroizing buffers for a momentary, auto-cleared reveal.

**Tech Stack:** Rust (edition 2021), `janitor-core` (existing), Slint 1.x (`slint` + `slint-build`), `serde_json` (already a core dep).

**Spec:** `docs/superpowers/specs/2026-05-30-gui-tracer-bullet-design.md`

---

## Conventions for this plan

- **Core tasks (Part A)** are full red-green TDD: write the failing test, watch it fail, implement, watch it pass, commit. They keep `janitor-core`'s ≥80 % coverage gate reachable.
- **GUI tasks (Part B)** are *manually verified* — Slint view logic is not unit-tested (ADR 0003). Each has an explicit **Manual verification** step. The wiring logic (models, callbacks, reveal, timer) is fully specified; **`.slint` styling is deliberately rough** (the spec is "rough look first") — exact widget props may be adjusted against the Slint std-widgets docs without changing behavior.
- Run from the workspace root. Single-test runs use `cargo test -p janitor-core <name>`.
- Commit messages follow the repo convention `type(scope): summary`.

---

## File structure

**`janitor-core` (additions)**
- `janitor-core/src/source.rs` — `trait SecretSource` + `FetchError` (the AWS-adapter seam).
- `janitor-core/src/mock.rs` — `MockSource`: seeded Payments fixtures + deterministic fallback. Non-production.
- `janitor-core/src/view.rs` — owned `MatrixView`/`MatrixRow`/`MatrixCell`, `project()`, `reveal_value()`, `sort_rows()`/`SortKey`. Pure, tested.
- `janitor-core/src/lib.rs` — add `pub mod source; pub mod mock; pub mod view;`.

**`janitor-gui` (new crate)**
- `janitor-gui/Cargo.toml`, `janitor-gui/build.rs`
- `janitor-gui/ui/app.slint` — window, header, matrix, sidebar, settings + preferences (built up across Part B).
- `janitor-gui/src/main.rs` — seed in-memory `Config`, wire callbacks, map `MatrixView` → Slint models.

**Workspace**
- `Cargo.toml` — add `janitor-gui` to `members`.

---

# Part B-0: De-risk Slint first

## Task 1: `janitor-gui` skeleton + blank Slint window

The highest integration risk is "does Slint build and open a window on this box," so prove it before any view-model exists.

**Files:**
- Modify: `Cargo.toml` (workspace members)
- Create: `janitor-gui/Cargo.toml`
- Create: `janitor-gui/build.rs`
- Create: `janitor-gui/ui/app.slint`
- Create: `janitor-gui/src/main.rs`

- [ ] **Step 1: Add the crate to the workspace**

Replace `Cargo.toml` contents with:

```toml
[workspace]
resolver = "2"
members = ["janitor-core", "janitor-gui"]
```

- [ ] **Step 2: Create `janitor-gui/Cargo.toml`**

```toml
[package]
name = "janitor-gui"
version = "0.1.0"
edition = "2021"
license = "GPL-3.0-only"
description = "Janitor's thin Slint view over janitor-core (ADR 0003)."
build = "build.rs"

[dependencies]
janitor-core = { path = "../janitor-core" }
slint = "1"

[build-dependencies]
slint-build = "1"
```

- [ ] **Step 3: Create `janitor-gui/build.rs`**

```rust
fn main() {
    slint_build::compile("ui/app.slint").unwrap();
}
```

- [ ] **Step 4: Create `janitor-gui/ui/app.slint`**

```slint
export component MainWindow inherits Window {
    title: "Janitor";
    preferred-width: 1100px;
    preferred-height: 720px;
    background: #14161a;

    Text {
        text: "Janitor — booting…";
        color: #c8ccd4;
    }
}
```

- [ ] **Step 5: Create `janitor-gui/src/main.rs`**

```rust
slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    MainWindow::new()?.run()
}
```

- [ ] **Step 6: Build and run**

Run: `cargo run -p janitor-gui`
Expected: a dark window titled "Janitor" opens showing "Janitor — booting…".
If the window does not open, resolve Slint's Windows prerequisites before continuing (the default backend works on stable Rust with no extra system packages) — this is the de-risk gate.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml janitor-gui
git commit -m "feat(gui): janitor-gui crate skeleton + blank Slint window"
```

---

# Part A: Core data layer (TDD)

## Task 2: `SecretSource` trait + `FetchError`

**Files:**
- Create: `janitor-core/src/source.rs`
- Modify: `janitor-core/src/lib.rs`

- [ ] **Step 1: Declare the module**

In `janitor-core/src/lib.rs`, add after `pub mod config;`:

```rust
pub mod source;
```

- [ ] **Step 2: Write `source.rs` with the trait, error, and a failing test**

```rust
//! The data-source seam: where Secret Sets enter the comparison pipeline.
//!
//! [`SecretSource`] is the boundary the real AWS Secrets Manager adapter will
//! implement (see this crate's `lib.rs`: "core logic must depend on an
//! AWS-client trait"). It is **synchronous on purpose**: the only impl today is
//! an in-memory mock that returns instantly, so async↔GUI threading would be
//! premature.
//!
//! ASYNC SEAM (deferred): the real AWS SDK is async. When it lands, `fetch`
//! becomes async (or returns a boxed future) and every caller threads the
//! await. That change is intentionally out of scope for the tracer-bullet slice.

use crate::config::Mapping;
use crate::secret::SecretShape;

/// Fetches the Secret Set backing one Environment's [`Mapping`].
pub trait SecretSource {
    /// Fetch and parse the Set that `mapping` points at.
    fn fetch(&self, mapping: &Mapping) -> Result<SecretShape, FetchError>;
}

/// Why a [`SecretSource::fetch`] failed.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// No Set is known for this Mapping's `secret_id`.
    #[error("no secret found for {0}")]
    NotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mapping;

    fn mapping(secret_id: &str) -> Mapping {
        Mapping {
            environment: "prod".into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
            secret_id: secret_id.into(),
            permission_set: "ReadOnly".into(),
        }
    }

    /// A stub source proving the trait shape: it knows exactly one secret_id.
    struct OneSecret;
    impl SecretSource for OneSecret {
        fn fetch(&self, m: &Mapping) -> Result<SecretShape, FetchError> {
            if m.secret_id == "known" {
                Ok(SecretShape::from_secret_string(r#"{"A":"1"}"#))
            } else {
                Err(FetchError::NotFound(m.secret_id.clone()))
            }
        }
    }

    #[test]
    fn source_returns_shape_or_not_found() {
        let s = OneSecret;
        assert!(s.fetch(&mapping("known")).is_ok());
        let err = s.fetch(&mapping("missing")).unwrap_err();
        assert!(matches!(err, FetchError::NotFound(id) if id == "missing"));
    }
}
```

- [ ] **Step 3: Run the test (verify it compiles and passes)**

Run: `cargo test -p janitor-core source_returns_shape_or_not_found`
Expected: PASS. (If it fails to compile, the trait/error signatures are wrong — fix before moving on.)

- [ ] **Step 4: Commit**

```bash
git add janitor-core/src/source.rs janitor-core/src/lib.rs
git commit -m "feat(core): SecretSource trait + FetchError (the AWS-adapter seam)"
```

---

## Task 3: `MockSource` — seeded fixtures + deterministic fallback

**Files:**
- Create: `janitor-core/src/mock.rs`
- Modify: `janitor-core/src/lib.rs`

- [ ] **Step 1: Declare the module**

In `janitor-core/src/lib.rs`, add after `pub mod source;`:

```rust
pub mod mock;
```

- [ ] **Step 2: Write the failing tests + implementation in `mock.rs`**

```rust
//! A **non-production** [`SecretSource`] that returns canned Secret Sets so the
//! GUI can be built and demoed before AWS auth + I/O exist. Not for release.

use crate::config::Mapping;
use crate::secret::SecretShape;
use crate::source::{FetchError, SecretSource};

/// In-memory mock source. Knows a few hand-seeded Sets (reproducing the design
/// mockup's Payments API) and deterministically fabricates a plausible Set for
/// anything else.
#[derive(Debug, Default)]
pub struct MockSource;

impl MockSource {
    pub fn new() -> Self {
        MockSource
    }
}

impl SecretSource for MockSource {
    fn fetch(&self, mapping: &Mapping) -> Result<SecretShape, FetchError> {
        Ok(seeded(&mapping.secret_id)
            .unwrap_or_else(|| fallback(&mapping.secret_id, &mapping.environment)))
    }
}

/// Hand-seeded Sets keyed by `secret_id`. `prod` carries `database.replica.url`
/// and `GITHUB_APP_WEBHOOK_SECRET` that `staging` lacks (→ Gap);
/// `GITHUB_APP_ID` is identical (→ Aligned); the rest differ (→ Drift).
fn seeded(secret_id: &str) -> Option<SecretShape> {
    let json = match secret_id {
        "payments/prod" => PAYMENTS_PROD,
        "payments/staging" => PAYMENTS_STAGING,
        _ => return None,
    };
    Some(SecretShape::from_secret_string(json))
}

const PAYMENTS_PROD: &str = r#"{
  "database": {
    "primary": { "url": "postgres://prod-db.internal:5432/payments", "password": "prod-pw-9f04aa" },
    "pool": { "max": 200 },
    "replica": { "url": "postgres://prod-replica.internal:5432/payments" }
  },
  "GITHUB_APP_ID": 123456,
  "GITHUB_APP_PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----prodKEYmaterial-----END RSA PRIVATE KEY-----",
  "GITHUB_APP_WEBHOOK_SECRET": "whsec_prod_44c1aa",
  "STRIPE_API_KEY": "sk_live_prod_b80a0011",
  "STRIPE_WEBHOOK_SECRET": "whsec_live_prod_c019aa"
}"#;

const PAYMENTS_STAGING: &str = r#"{
  "database": {
    "primary": { "url": "postgres://staging-db.internal:5432/payments", "password": "stg-pw-3ae8bb" },
    "pool": { "max": 20 }
  },
  "GITHUB_APP_ID": 123456,
  "GITHUB_APP_PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----stagingKEYmaterial-----END RSA PRIVATE KEY-----",
  "STRIPE_API_KEY": "sk_test_stg_2f6caa",
  "STRIPE_WEBHOOK_SECRET": "whsec_test_stg_7d3ebb"
}"#;

/// Deterministically fabricate a plausible Set for an unseeded `secret_id`.
/// Same `(secret_id, environment)` always yields the same Set (no RNG), so the
/// matrix is stable across refreshes. Produces a mix: `SERVICE_NAME` is derived
/// from the base name only (→ Aligned across envs), `API_KEY`/`DATABASE_URL`
/// depend on `secret_id` which includes the env (→ Drift), and `LEGACY_TOKEN`
/// is prod-only (→ Gap).
fn fallback(secret_id: &str, environment: &str) -> SecretShape {
    let service = secret_id.split('/').next().unwrap_or(secret_id);
    let mut obj = serde_json::json!({
        "SERVICE_NAME": service,
        "API_KEY": fake_hex(&format!("{secret_id}:API_KEY")),
        "DATABASE_URL": format!("postgres://{service}-{}/{service}", fake_hex(secret_id)),
    });
    if environment == "prod" {
        obj["LEGACY_TOKEN"] =
            serde_json::Value::String(fake_hex(&format!("{secret_id}:LEGACY")));
    }
    SecretShape::from_secret_string(&obj.to_string())
}

/// A tiny deterministic non-secret hex tag (FNV-1a, 16 chars) — for fabricated
/// mock values only, never applied to real secret material.
fn fake_hex(seed: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in seed.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::{LeafKind, SecretShape};

    fn map(secret_id: &str, env: &str) -> Mapping {
        Mapping {
            environment: env.into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
            secret_id: secret_id.into(),
            permission_set: "ReadOnly".into(),
        }
    }

    /// Comparable snapshot of a Json shape: `name -> (exposed, kind)`, sorted by
    /// the BTreeMap so it is deterministic. `Value` has no `PartialEq`, so this
    /// is how we assert equality of shapes.
    fn entries(shape: &SecretShape) -> Vec<(String, String, LeafKind)> {
        match shape {
            SecretShape::Json(m) => m
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.expose().to_string(), v.kind()))
                .collect(),
            other => panic!("expected Json, got {other:?}"),
        }
    }

    fn value_of(shape: &SecretShape, name: &str) -> Option<(String, LeafKind)> {
        entries(shape)
            .into_iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, v, k)| (v, k))
    }

    #[test]
    fn seeded_payments_has_the_mockup_entries() {
        let prod = MockSource::new().fetch(&map("payments/prod", "prod")).unwrap();
        let names: Vec<String> = entries(&prod).into_iter().map(|(n, _, _)| n).collect();
        assert!(names.contains(&"database.primary.url".to_string()));
        assert!(names.contains(&"database.replica.url".to_string()));
        assert!(names.contains(&"GITHUB_APP_ID".to_string()));
    }

    #[test]
    fn seeded_github_app_id_aligned_replica_is_gap_stripe_drifts() {
        let prod = MockSource::new().fetch(&map("payments/prod", "prod")).unwrap();
        let stg = MockSource::new().fetch(&map("payments/staging", "staging")).unwrap();
        assert_eq!(
            value_of(&prod, "GITHUB_APP_ID"),
            value_of(&stg, "GITHUB_APP_ID"),
            "identical → Aligned"
        );
        assert_ne!(
            value_of(&prod, "STRIPE_API_KEY"),
            value_of(&stg, "STRIPE_API_KEY"),
            "differ → Drift"
        );
        assert!(
            value_of(&stg, "database.replica.url").is_none(),
            "replica is prod-only → Gap"
        );
    }

    #[test]
    fn fallback_is_deterministic_and_mixes_states() {
        let a = MockSource::new().fetch(&map("auth/prod", "prod")).unwrap();
        let b = MockSource::new().fetch(&map("auth/prod", "prod")).unwrap();
        assert_eq!(entries(&a), entries(&b), "same input → same shape");

        let prod = MockSource::new().fetch(&map("auth/prod", "prod")).unwrap();
        let stg = MockSource::new().fetch(&map("auth/staging", "staging")).unwrap();
        assert_eq!(
            value_of(&prod, "SERVICE_NAME"),
            value_of(&stg, "SERVICE_NAME"),
            "base-derived → Aligned"
        );
        assert_ne!(
            value_of(&prod, "API_KEY"),
            value_of(&stg, "API_KEY"),
            "secret_id includes env → Drift"
        );
        assert!(value_of(&stg, "LEGACY_TOKEN").is_none(), "prod-only → Gap");
    }
}
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p janitor-core mock::`
Expected: 3 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add janitor-core/src/mock.rs janitor-core/src/lib.rs
git commit -m "feat(core): MockSource — seeded Payments fixtures + deterministic fallback"
```

---

## Task 4: `view` module — `MatrixView` DTO + `project()`

**Files:**
- Create: `janitor-core/src/view.rs`
- Modify: `janitor-core/src/lib.rs`

- [ ] **Step 1: Declare the module**

In `janitor-core/src/lib.rs`, add after `pub mod mock;`:

```rust
pub mod view;
```

- [ ] **Step 2: Write `view.rs` with the DTO, `project()`, and failing tests**

```rust
//! Owned, masked projection of a [`Comparison`] for the GUI. Carries no secret
//! Values — only presence, byte length, equality grouping, and a cosmetic tag —
//! so the view may hold it long-lived (ADR 0003). Plaintext reveal goes through
//! [`reveal_value`] against the still-owned Sets, never through this DTO.

use crate::compare::{Cell, Comparison, EntryState, RowKey};

/// An owned, non-secret matrix ready to map onto view models.
#[derive(Debug, Clone, PartialEq)]
pub struct MatrixView {
    pub environments: Vec<String>,
    pub rows: Vec<MatrixRow>,
}

/// One projected row.
#[derive(Debug, Clone, PartialEq)]
pub struct MatrixRow {
    /// The row's identity, kept so [`reveal_value`] can re-index the Sets.
    pub key: RowKey,
    /// Display name (`EntryName` text, or `"(whole set)"`).
    pub name: String,
    pub state: EntryState,
    pub cells: Vec<MatrixCell>,
}

/// One projected cell — masked only.
#[derive(Debug, Clone, PartialEq)]
pub enum MatrixCell {
    /// Present: byte length, row-local equality group, and a cosmetic hex tag.
    Present { len: usize, group: u32, hex: String },
    /// Missing in this Environment.
    Absent,
}

/// Project a freshly-built [`Comparison`] into an owned [`MatrixView`].
pub fn project(comparison: &Comparison) -> MatrixView {
    let rows = comparison
        .rows
        .iter()
        .map(|row| {
            let name = match &row.key {
                RowKey::Entry(n) => n.as_str().to_string(),
                RowKey::WholeSet => "(whole set)".to_string(),
            };
            let cells = row
                .cells
                .iter()
                .map(|cell| match cell {
                    // `group.0` is pub(crate) on GroupId — readable here in-crate.
                    Cell::Text { len, group, .. } => MatrixCell::Present {
                        len: *len,
                        group: group.0,
                        hex: hex_tag(&name, group.0),
                    },
                    Cell::Binary { len, group } => MatrixCell::Present {
                        len: *len,
                        group: group.0,
                        hex: hex_tag(&name, group.0),
                    },
                    Cell::Absent => MatrixCell::Absent,
                })
                .collect();
            MatrixRow {
                key: row.key.clone(),
                name,
                state: row.state,
                cells,
            }
        })
        .collect();
    MatrixView {
        environments: comparison.environments.clone(),
        rows,
    }
}

/// Cosmetic 4-hex-char tag from the Entry name + equality group (**never** the
/// Value). Equal cells in a row share a tag; different Entries differ. Display
/// flavor only — the equality mechanism is the group id.
fn hex_tag(name: &str, group: u32) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes().chain(std::iter::once(b':')).chain(group.to_le_bytes()) {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:04x}", h & 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compare::Comparison;
    use crate::secret::SecretShape;

    fn env(name: &str, json: &str) -> (String, SecretShape) {
        (name.to_string(), SecretShape::from_secret_string(json))
    }
    fn find<'a>(v: &'a MatrixView, name: &str) -> &'a MatrixRow {
        v.rows.iter().find(|r| r.name == name).expect("row exists")
    }

    #[test]
    fn project_preserves_environments_and_row_names() {
        let sets = [env("prod", r#"{"A":"1"}"#), env("staging", r#"{"A":"1"}"#)];
        let view = project(&Comparison::build(&sets));
        assert_eq!(view.environments, vec!["prod", "staging"]);
        assert_eq!(view.rows.len(), 1);
        assert_eq!(view.rows[0].name, "A");
    }

    #[test]
    fn aligned_cells_share_group_and_hex() {
        let sets = [env("prod", r#"{"A":"1"}"#), env("staging", r#"{"A":"1"}"#)];
        let view = project(&Comparison::build(&sets));
        let r = find(&view, "A");
        assert_eq!(r.state, EntryState::Aligned);
        match (&r.cells[0], &r.cells[1]) {
            (
                MatrixCell::Present { group: g0, hex: h0, .. },
                MatrixCell::Present { group: g1, hex: h1, .. },
            ) => {
                assert_eq!(g0, g1, "aligned → same group");
                assert_eq!(h0, h1, "same group in a row → same cosmetic hex");
            }
            _ => panic!("expected two Present cells"),
        }
    }

    #[test]
    fn drift_cells_have_different_groups() {
        let sets = [env("prod", r#"{"A":"1"}"#), env("staging", r#"{"A":"2"}"#)];
        let view = project(&Comparison::build(&sets));
        let r = find(&view, "A");
        assert_eq!(r.state, EntryState::Drift);
        match (&r.cells[0], &r.cells[1]) {
            (MatrixCell::Present { group: g0, .. }, MatrixCell::Present { group: g1, .. }) => {
                assert_ne!(g0, g1)
            }
            _ => panic!("expected Present cells"),
        }
    }

    #[test]
    fn gap_row_has_absent_cell_and_len_is_byte_length() {
        let sets = [env("prod", r#"{"A":"hello"}"#), env("staging", r#"{"B":"x"}"#)];
        let view = project(&Comparison::build(&sets));
        let a = find(&view, "A");
        assert_eq!(a.state, EntryState::Gap);
        assert!(matches!(a.cells[0], MatrixCell::Present { len: 5, .. }));
        assert!(matches!(a.cells[1], MatrixCell::Absent));
    }
}
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p janitor-core view::tests`
Expected: 4 tests PASS. (If `group.0` is a privacy error, confirm `view` is a module *inside* `janitor-core` — `pub(crate)` access requires it.)

- [ ] **Step 4: Commit**

```bash
git add janitor-core/src/view.rs janitor-core/src/lib.rs
git commit -m "feat(core): MatrixView projection of a Comparison (owned, masked)"
```

---

## Task 5: `reveal_value()` — plaintext lookup against the owned Sets

**Files:**
- Modify: `janitor-core/src/view.rs`

- [ ] **Step 1: Add the failing test**

Add to the `tests` module in `view.rs`:

```rust
    use crate::compare::RowKey;
    use crate::secret::EntryName;

    fn entry_key(name: &str) -> RowKey {
        RowKey::Entry(EntryName::from_path(&[name.to_string()]))
    }

    #[test]
    fn reveal_present_json_entry_and_raw_whole_set() {
        let sets = [env("prod", r#"{"A":"secret"}"#)];
        assert_eq!(
            reveal_value(&sets, &entry_key("A"), 0).map(|v| v.expose()),
            Some("secret")
        );
        let raw = [("prod".to_string(), SecretShape::from_secret_string("raw-token"))];
        assert_eq!(
            reveal_value(&raw, &RowKey::WholeSet, 0).map(|v| v.expose()),
            Some("raw-token")
        );
    }

    #[test]
    fn reveal_is_none_for_absent_oob_and_binary() {
        let sets = [
            env("prod", r#"{"A":"x"}"#),
            ("bin".to_string(), SecretShape::from_secret_binary(vec![1, 2, 3])),
        ];
        assert!(reveal_value(&sets, &entry_key("MISSING"), 0).is_none());
        assert!(reveal_value(&sets, &entry_key("A"), 9).is_none(), "col out of range");
        assert!(reveal_value(&sets, &RowKey::WholeSet, 1).is_none(), "binary never reveals");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p janitor-core reveal_present_json_entry_and_raw_whole_set`
Expected: FAIL to compile — `reveal_value` not found.

- [ ] **Step 3: Implement `reveal_value`**

Add to `view.rs` (after `project`), and extend the top `use` line:

```rust
use crate::secret::{SecretShape, Value};
```

```rust
/// Borrow the plaintext Value at `(row key, column)` for a momentary reveal,
/// indexing the still-owned Sets directly (independent of any `Comparison`).
/// `None` when the column is out of range, the Entry is absent there, or the
/// Set is Binary (never revealable, ADR 0004).
pub fn reveal_value<'a>(
    sets: &'a [(String, SecretShape)],
    key: &RowKey,
    col: usize,
) -> Option<&'a Value> {
    let (_, shape) = sets.get(col)?;
    match (key, shape) {
        (RowKey::Entry(name), SecretShape::Json(map)) => map.get(name),
        (RowKey::WholeSet, SecretShape::Raw(value)) => Some(value),
        _ => None,
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p janitor-core reveal`
Expected: both reveal tests PASS.

- [ ] **Step 5: Commit**

```bash
git add janitor-core/src/view.rs
git commit -m "feat(core): reveal_value — plaintext lookup into owned Sets for momentary reveal"
```

---

## Task 6: `sort_rows()` + `SortKey`

**Files:**
- Modify: `janitor-core/src/view.rs`

- [ ] **Step 1: Add the failing test**

Add to the `tests` module in `view.rs`:

```rust
    #[test]
    fn gap_first_sort_is_stable_and_high_signal_first() {
        // aaa: drift, bbb: aligned, ccc: prod-only gap. Engine order: aaa,bbb,ccc.
        let sets = [
            env("prod", r#"{"aaa":"1","bbb":"1","ccc":"1"}"#),
            env("staging", r#"{"aaa":"2","bbb":"1"}"#),
        ];
        let mut view = project(&Comparison::build(&sets));
        sort_rows(&mut view, SortKey::GapFirst);
        let order: Vec<&str> = view.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(order, vec!["ccc", "aaa", "bbb"], "Gap, then Drift, then Aligned");
    }

    #[test]
    fn name_sort_keeps_engine_order() {
        let sets = [
            env("prod", r#"{"bbb":"1","aaa":"1"}"#),
            env("staging", r#"{"bbb":"1","aaa":"1"}"#),
        ];
        let mut view = project(&Comparison::build(&sets));
        sort_rows(&mut view, SortKey::Name);
        let order: Vec<&str> = view.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(order, vec!["aaa", "bbb"], "engine already sorts by name");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p janitor-core gap_first_sort_is_stable_and_high_signal_first`
Expected: FAIL to compile — `sort_rows`/`SortKey` not found.

- [ ] **Step 3: Implement `sort_rows` + `SortKey`**

Add to `view.rs`:

```rust
/// Row ordering for the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    /// The engine's default — Entry name order.
    Name,
    /// High-signal rows on top: Gap, then Drift, then Aligned.
    GapFirst,
}

/// Reorder `view.rows` per `sort`. Stable, so within a rank the engine's name
/// order is preserved. `Name` is a no-op (the engine already name-sorts).
pub fn sort_rows(view: &mut MatrixView, sort: SortKey) {
    if sort == SortKey::GapFirst {
        view.rows.sort_by_key(|r| match r.state {
            EntryState::Gap => 0u8,
            EntryState::Drift => 1,
            EntryState::Aligned => 2,
        });
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p janitor-core sort`
Expected: both sort tests PASS.

- [ ] **Step 5: Run the full core suite + coverage sanity**

Run: `cargo test -p janitor-core`
Expected: all tests PASS (existing + new).

- [ ] **Step 6: Commit**

```bash
git add janitor-core/src/view.rs
git commit -m "feat(core): sort_rows + SortKey (name / gap-first matrix ordering)"
```

---

# Part B: GUI (incremental, manually verified)

> From here the `.slint` file grows. Each task shows the **full current `app.slint`** when it changes substantially, and full Rust functions when modified, so tasks can be read out of order. Styling is rough on purpose.

## Task 7: Render the matrix from mock data

Wire `MockSource → Comparison::build → project → Slint models` for a hardcoded Payments App.

**Files:**
- Modify: `janitor-gui/ui/app.slint`
- Modify: `janitor-gui/src/main.rs`

- [ ] **Step 1: Replace `janitor-gui/ui/app.slint`**

```slint
import { ScrollView } from "std-widgets.slint";

export struct CellView {
    absent: bool,
    dots: string,
    length: string,
    hex: string,
}

export struct RowView {
    name: string,
    state: string,    // "Aligned" / "Drift" / "Gap"
    glyph: string,    // "=" / "≠" / "ø"  (meaningful for 2 envs)
    cells: [CellView],
}

export component MainWindow inherits Window {
    title: "Janitor";
    preferred-width: 1100px;
    preferred-height: 720px;
    background: #14161a;

    in property <[string]> environments;
    in property <[RowView]> rows;

    // Reveal slot (Task 8 sets these). -1 = nothing revealed.
    in property <int> revealed-row: -1;
    in property <int> revealed-col: -1;
    in property <string> revealed-text;

    callback reveal-cell(int, int);

    VerticalLayout {
        padding: 16px;
        spacing: 6px;

        // Column header
        HorizontalLayout {
            spacing: 12px;
            Text { text: "ENTRY"; color: #8a8f98; width: 320px; }
            for env in environments : Text {
                text: env;
                color: #c8ccd4;
                horizontal-stretch: 1;
            }
        }

        ScrollView {
            VerticalLayout {
                spacing: 2px;
                for row[i] in rows : HorizontalLayout {
                    spacing: 12px;
                    // Entry name + state
                    VerticalLayout {
                        width: 320px;
                        Text { text: row.name; color: white; overflow: elide; }
                        Text {
                            text: row.state + "   " + row.glyph;
                            color: row.state == "Gap" ? #6b7280
                                 : row.state == "Drift" ? #e0a356
                                 : #5db07a;
                            font-size: 11px;
                        }
                    }
                    // One cell per environment
                    for cell[j] in row.cells : Rectangle {
                        horizontal-stretch: 1;
                        property <bool> is-revealed:
                            root.revealed-row == i && root.revealed-col == j;
                        background: touch.has-hover ? #1b1e24 : transparent;
                        touch := TouchArea {
                            clicked => { root.reveal-cell(i, j); }
                        }
                        HorizontalLayout {
                            padding: 6px;
                            spacing: 8px;
                            if cell.absent : Text {
                                text: "— absent";
                                color: #4b5563;
                                horizontal-stretch: 1;
                            }
                            if !cell.absent : Text {
                                text: is-revealed ? root.revealed-text : cell.dots;
                                color: is-revealed ? #ffd479 : #6b7280;
                                overflow: elide;
                                horizontal-stretch: 1;
                            }
                            if !cell.absent : Text { text: cell.length; color: #6b7280; }
                            if !cell.absent : Text { text: cell.hex; color: #9aa0aa; }
                        }
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 2: Replace `janitor-gui/src/main.rs`**

```rust
slint::include_modules!();

use std::rc::Rc;

use slint::{ModelRc, SharedString, VecModel};

use janitor_core::compare::{Comparison, EntryState};
use janitor_core::config::Mapping;
use janitor_core::mock::MockSource;
use janitor_core::secret::SecretShape;
use janitor_core::source::SecretSource;
use janitor_core::view::{project, MatrixCell, MatrixRow, MatrixView};

/// Hardcoded Payments App for this task (the sidebar/config arrives in Task 9).
fn payments_mappings() -> Vec<Mapping> {
    vec![
        Mapping {
            environment: "prod".into(),
            account_id: "914xxxxxx021".into(),
            region: "us-east-1".into(),
            secret_id: "payments/prod".into(),
            permission_set: "ReadOnly".into(),
        },
        Mapping {
            environment: "staging".into(),
            account_id: "550xxxxxx118".into(),
            region: "us-west-2".into(),
            secret_id: "payments/staging".into(),
            permission_set: "ReadOnly".into(),
        },
    ]
}

/// Fetch every Environment's Set for a set of mappings.
fn fetch_sets(source: &dyn SecretSource, mappings: &[Mapping]) -> Vec<(String, SecretShape)> {
    mappings
        .iter()
        .map(|m| (m.environment.clone(), source.fetch(m).expect("mock never fails")))
        .collect()
}

/// Masked length-dots, capped so a long Value does not blow out the row.
fn dots(len: usize) -> String {
    "·".repeat(len.min(40))
}

/// The 2-env equality glyph; blank for N != 2.
fn glyph_for(row: &MatrixRow) -> &'static str {
    if row.cells.len() != 2 {
        return "";
    }
    match (&row.cells[0], &row.cells[1]) {
        (MatrixCell::Absent, _) | (_, MatrixCell::Absent) => "ø",
        (MatrixCell::Present { group: a, .. }, MatrixCell::Present { group: b, .. }) => {
            if a == b {
                "="
            } else {
                "≠"
            }
        }
    }
}

/// Map an owned `MatrixView` into Slint row models.
fn to_row_models(view: &MatrixView) -> ModelRc<RowView> {
    let rows: Vec<RowView> = view
        .rows
        .iter()
        .map(|r| {
            let cells: Vec<CellView> = r
                .cells
                .iter()
                .map(|c| match c {
                    MatrixCell::Present { len, hex, .. } => CellView {
                        absent: false,
                        dots: dots(*len).into(),
                        length: len.to_string().into(),
                        hex: hex.clone().into(),
                    },
                    MatrixCell::Absent => CellView {
                        absent: true,
                        dots: SharedString::new(),
                        length: SharedString::new(),
                        hex: SharedString::new(),
                    },
                })
                .collect();
            RowView {
                name: r.name.clone().into(),
                state: state_label(r.state).into(),
                glyph: glyph_for(r).into(),
                cells: ModelRc::from(Rc::new(VecModel::from(cells))),
            }
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(rows)))
}

fn state_label(state: EntryState) -> &'static str {
    match state {
        EntryState::Aligned => "Aligned",
        EntryState::Drift => "Drift",
        EntryState::Gap => "Gap",
    }
}

fn env_models(view: &MatrixView) -> ModelRc<SharedString> {
    let envs: Vec<SharedString> = view.environments.iter().map(|e| e.as_str().into()).collect();
    ModelRc::from(Rc::new(VecModel::from(envs)))
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;

    let source = MockSource::new();
    let sets = fetch_sets(&source, &payments_mappings());
    let view = project(&Comparison::build(&sets)); // Comparison is transient — dropped here.

    ui.set_environments(env_models(&view));
    ui.set_rows(to_row_models(&view));

    ui.run()
}
```

- [ ] **Step 3: Build and run**

Run: `cargo run -p janitor-gui`
Expected: the window shows an `ENTRY` / `prod` / `staging` header and ~9 rows. `database.*`, `GITHUB_APP_*`, `STRIPE_*` rows show dotted masks + byte length + a hex tag; `database.replica.url` and `GITHUB_APP_WEBHOOK_SECRET` show "— absent" in the staging column; `GITHUB_APP_ID` shows the green "Aligned" label.

- [ ] **Step 4: Verify the workspace still builds clean**

Run: `cargo build --workspace`
Expected: success, no warnings about unused `glyph`/`dots` (they are used).

- [ ] **Step 5: Commit**

```bash
git add janitor-gui/ui/app.slint janitor-gui/src/main.rs
git commit -m "feat(gui): render the comparison matrix from mock data"
```

---

## Task 8: Per-cell momentary reveal with auto-clear

Hold `sets` + `view` in shared state; on a cell click, re-borrow the plaintext via `reveal_value`, show it, and **clear** it after the preference timeout (default 5 s). One cell at a time (enforced by the single reveal slot).

**Files:**
- Modify: `janitor-gui/src/main.rs`

- [ ] **Step 1: Add shared state + the reveal callback**

In `main.rs`, extend the imports:

```rust
use std::cell::RefCell;
use std::time::Duration;

use janitor_core::view::reveal_value;
```

Add the app-state struct (above `fn main`):

```rust
/// In-memory state shared across Slint callbacks. Owns the fetched Sets (so a
/// reveal can re-borrow plaintext) and the owned, masked `MatrixView`. It never
/// stores a `Comparison` (which would borrow `sets` — a self-referential trap).
struct AppState {
    sets: Vec<(String, SecretShape)>,
    view: MatrixView,
}
```

Replace the body of `fn main` with:

```rust
fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;

    let source = MockSource::new();
    let sets = fetch_sets(&source, &payments_mappings());
    let view = project(&Comparison::build(&sets));

    ui.set_environments(env_models(&view));
    ui.set_rows(to_row_models(&view));

    let state = Rc::new(RefCell::new(AppState { sets, view }));

    // Reveal: re-borrow plaintext from the owned Sets, show it, auto-clear.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_reveal_cell(move |row, col| {
            let ui = ui_weak.unwrap();
            let st = state.borrow();
            let Some(matrix_row) = st.view.rows.get(row as usize) else {
                return;
            };
            if let Some(value) = reveal_value(&st.sets, &matrix_row.key, col as usize) {
                ui.set_revealed_row(row);
                ui.set_revealed_col(col);
                ui.set_revealed_text(SharedString::from(value.expose()));

                // Clear (not just hide) the plaintext out of the model on timeout.
                let ui_weak = ui.as_weak();
                slint::Timer::single_shot(Duration::from_secs(5), move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_revealed_text(SharedString::new());
                        ui.set_revealed_row(-1);
                        ui.set_revealed_col(-1);
                    }
                });
            }
        });
    }

    ui.run()
}
```

- [ ] **Step 2: Build and run**

Run: `cargo run -p janitor-gui`
Expected behavior to verify manually:
- Clicking a **present** cell replaces its dots with amber plaintext; the byte length + hex stay.
- After ~5 s the plaintext reverts to dots on its own.
- Clicking an **absent** ("— absent") cell does nothing.
- Clicking a second cell reveals it; only one cell shows plaintext at a time.

- [ ] **Step 3: Commit**

```bash
git add janitor-gui/src/main.rs
git commit -m "feat(gui): per-cell momentary reveal with auto-clear (ADR 0003)"
```

> Note (known rough edge, acceptable for the slice): rapidly revealing a second cell before the first timer fires can clear the second early. A generation counter would fix it; deferred.

---

## Task 9: Sidebar + Application switching

Introduce an in-memory `Config` with several seeded Applications. The sidebar lists them with a data-derived drift badge; selecting one re-fetches and rebuilds the matrix.

**Files:**
- Modify: `janitor-gui/ui/app.slint`
- Modify: `janitor-gui/src/main.rs`

- [ ] **Step 1: Add the sidebar to `app.slint`**

Add an `AppItem` struct (next to the other structs):

```slint
export struct AppItem {
    name: string,
    subtitle: string,   // e.g. "2 envs"
    drift: string,      // e.g. "9 drift" or "" when none
    selected: bool,
}
```

Add these to `MainWindow`'s properties/callbacks (next to the existing ones):

```slint
    in property <[AppItem]> apps;
    callback select-app(int);
```

Wrap the existing top-level `VerticalLayout` (the matrix) in a `HorizontalLayout` with a sidebar to its left. The new outer structure of `MainWindow`'s body:

```slint
    HorizontalLayout {
        // Sidebar
        Rectangle {
            width: 240px;
            background: #0f1115;
            VerticalLayout {
                padding: 12px;
                spacing: 4px;
                Text { text: "APPLICATIONS"; color: #6b7280; font-size: 11px; }
                for app[i] in apps : Rectangle {
                    height: 48px;
                    background: app.selected ? #1b2330 : (atouch.has-hover ? #161a20 : transparent);
                    atouch := TouchArea { clicked => { root.select-app(i); } }
                    HorizontalLayout {
                        padding: 8px;
                        VerticalLayout {
                            horizontal-stretch: 1;
                            Text { text: app.name; color: white; }
                            Text { text: app.subtitle; color: #6b7280; font-size: 11px; }
                        }
                        Text { text: app.drift; color: #e0a356; font-size: 11px; }
                    }
                }
            }
        }
        // Main pane (the existing matrix VerticalLayout goes here, unchanged)
        VerticalLayout {
            padding: 16px;
            spacing: 6px;
            // ... existing header + ScrollView matrix from Task 7 ...
        }
    }
```

(Keep the header + `ScrollView` matrix body exactly as in Task 7 inside that main-pane `VerticalLayout`.)

- [ ] **Step 2: Seed an in-memory `Config` and add rebuild logic in `main.rs`**

Extend imports:

```rust
use janitor_core::config::{Application, Config};
```

Add seeding + helpers (above `fn main`):

```rust
/// A few seeded Applications. Payments is hand-seeded in MockSource; the others
/// fall back to deterministic fabrication, and some have >2 Environments to show
/// the matrix generalize.
fn seeded_config() -> Config {
    let app = |name: &str, base: &str, envs: &[(&str, &str, &str)]| Application {
        name: name.into(),
        environments: envs
            .iter()
            .map(|(env, account, region)| Mapping {
                environment: (*env).into(),
                account_id: (*account).into(),
                region: (*region).into(),
                secret_id: format!("{base}/{env}"),
                permission_set: "ReadOnly".into(),
            })
            .collect(),
    };
    Config {
        sso_start_url: "https://acme.awsapps.com/start".into(),
        sso_region: "us-east-1".into(),
        applications: vec![
            app("Payments API", "payments", &[
                ("prod", "914xxxxxx021", "us-east-1"),
                ("staging", "550xxxxxx118", "us-west-2"),
            ]),
            app("Auth Service", "auth", &[
                ("prod", "914xxxxxx021", "us-east-1"),
                ("staging", "550xxxxxx118", "us-west-2"),
                ("dev", "330xxxxxx777", "us-west-2"),
            ]),
            app("Billing Worker", "billing", &[
                ("prod", "914xxxxxx021", "us-east-1"),
                ("staging", "550xxxxxx118", "us-west-2"),
            ]),
            app("Notifications", "notif", &[
                ("prod", "914xxxxxx021", "us-east-1"),
                ("staging", "550xxxxxx118", "us-west-2"),
                ("dev", "330xxxxxx777", "us-west-2"),
                ("qa", "330xxxxxx777", "us-west-2"),
            ]),
        ],
    }
}

/// Build the masked view for one Application from the source.
fn build_app(source: &dyn SecretSource, app: &Application) -> (Vec<(String, SecretShape)>, MatrixView) {
    let sets = fetch_sets(source, &app.environments);
    let view = project(&Comparison::build(&sets));
    (sets, view)
}

fn drift_count(view: &MatrixView) -> usize {
    view.rows.iter().filter(|r| r.state == EntryState::Drift).count()
}

/// Sidebar models, marking `selected`.
fn app_models(source: &dyn SecretSource, config: &Config, selected: usize) -> ModelRc<AppItem> {
    let items: Vec<AppItem> = config
        .applications
        .iter()
        .enumerate()
        .map(|(i, app)| {
            let (_, view) = build_app(source, app);
            let n = drift_count(&view);
            AppItem {
                name: app.name.clone().into(),
                subtitle: format!("{} envs", app.environments.len()).into(),
                drift: if n > 0 { format!("{n} drift").into() } else { SharedString::new() },
                selected: i == selected,
            }
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(items)))
}
```

Extend `AppState` to hold the config + selection + source:

```rust
struct AppState {
    source: MockSource,
    config: Config,
    selected: usize,
    sets: Vec<(String, SecretShape)>,
    view: MatrixView,
}
```

Add a render helper that pushes the current selection to the UI:

```rust
/// Rebuild the matrix for the currently-selected Application and push all models.
fn render(ui: &MainWindow, state: &Rc<RefCell<AppState>>) {
    let mut st = state.borrow_mut();
    let selected = st.selected;
    let app = st.config.applications[selected].clone();
    let (sets, view) = build_app(&st.source, &app);
    st.sets = sets;
    st.view = view;
    ui.set_environments(env_models(&st.view));
    ui.set_rows(to_row_models(&st.view));
    ui.set_apps(app_models(&st.source, &st.config, selected));
}
```

- [ ] **Step 3: Rewrite `fn main` to use the config + sidebar**

```rust
fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;

    let config = seeded_config();
    let state = Rc::new(RefCell::new(AppState {
        source: MockSource::new(),
        config,
        selected: 0,
        sets: Vec::new(),
        view: MatrixView { environments: Vec::new(), rows: Vec::new() },
    }));

    render(&ui, &state);

    // Sidebar selection.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_select_app(move |index| {
            let ui = ui_weak.unwrap();
            state.borrow_mut().selected = index as usize;
            render(&ui, &state);
        });
    }

    // Reveal (unchanged from Task 8, reads state.sets / state.view).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_reveal_cell(move |row, col| {
            let ui = ui_weak.unwrap();
            let st = state.borrow();
            let Some(matrix_row) = st.view.rows.get(row as usize) else { return; };
            if let Some(value) = reveal_value(&st.sets, &matrix_row.key, col as usize) {
                ui.set_revealed_row(row);
                ui.set_revealed_col(col);
                ui.set_revealed_text(SharedString::from(value.expose()));
                let ui_weak = ui.as_weak();
                slint::Timer::single_shot(Duration::from_secs(5), move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_revealed_text(SharedString::new());
                        ui.set_revealed_row(-1);
                        ui.set_revealed_col(-1);
                    }
                });
            }
        });
    }

    ui.run()
}
```

(`payments_mappings` is now unused — delete it.)

- [ ] **Step 4: Build and run**

Run: `cargo run -p janitor-gui`
Expected:
- A left sidebar lists Payments API / Auth Service / Billing Worker / Notifications, each with an "N envs" subtitle and a "K drift" badge derived from the actual matrix.
- Clicking an Application rebuilds the matrix; Auth Service shows 3 columns, Notifications 4 (the glyph blanks for >2 envs).
- Reveal still works on the selected App.

- [ ] **Step 5: Commit**

```bash
git add janitor-gui/ui/app.slint janitor-gui/src/main.rs
git commit -m "feat(gui): sidebar Application switching driven by in-memory Config"
```

---

## Task 10: Settings overlay — edit SSO + add/remove Applications

A settings panel (toggled by a button) edits the Identity Center fields and adds/removes Applications, mutating the in-memory `Config`. Per-mapping field editing is shown read-only here (full mapping CRUD is a later increment); adding an App auto-creates prod/staging mappings, which immediately render via the deterministic fallback.

**Files:**
- Modify: `janitor-gui/ui/app.slint`
- Modify: `janitor-gui/src/main.rs`

- [ ] **Step 1: Add the settings panel to `app.slint`**

Extend imports at the top:

```slint
import { ScrollView, LineEdit, Button } from "std-widgets.slint";
```

Add to `MainWindow` properties/callbacks:

```slint
    in property <bool> settings-open: false;
    in-out property <string> sso-start-url;
    in-out property <string> sso-region;
    in property <[AppItem]> apps;   // (already added in Task 9 — keep one copy)
    callback toggle-settings();
    callback save-sso();
    callback add-app(string);
    callback remove-app(int);
```

Add a gear button in the main pane header row (next to the `ENTRY` header or above it). Inside the main-pane `VerticalLayout`, before the column header:

```slint
        HorizontalLayout {
            Text { text: "Payments matrix"; color: #c8ccd4; horizontal-stretch: 1; }
            Button { text: root.settings-open ? "Close settings" : "Settings"; clicked => { root.toggle-settings(); } }
        }
```

Add the settings panel as an overlay at the end of `MainWindow`'s body (a sibling of the outer `HorizontalLayout`), shown only when open:

```slint
    if settings-open : Rectangle {
        width: 100%;
        height: 100%;
        background: #0b0d11;
        VerticalLayout {
            padding: 24px;
            spacing: 12px;
            Text { text: "Settings"; color: white; font-size: 18px; }

            Text { text: "Identity Center"; color: #8a8f98; }
            HorizontalLayout {
                spacing: 8px;
                Text { text: "Start URL"; color: #c8ccd4; width: 120px; }
                start-url := LineEdit { text <=> root.sso-start-url; horizontal-stretch: 1; }
            }
            HorizontalLayout {
                spacing: 8px;
                Text { text: "Region"; color: #c8ccd4; width: 120px; }
                region := LineEdit { text <=> root.sso-region; horizontal-stretch: 1; }
            }
            Button { text: "Save accounts"; clicked => { root.save-sso(); } }

            Text { text: "Applications"; color: #8a8f98; }
            for app[i] in apps : HorizontalLayout {
                spacing: 8px;
                Text { text: app.name; color: white; horizontal-stretch: 1; }
                Text { text: app.subtitle; color: #6b7280; }
                Button { text: "Remove"; clicked => { root.remove-app(i); } }
            }
            HorizontalLayout {
                spacing: 8px;
                new-app := LineEdit { placeholder-text: "New Application name"; horizontal-stretch: 1; }
                Button { text: "Add"; clicked => { root.add-app(new-app.text); } }
            }
        }
    }
```

> The overlay is the last child of `MainWindow`, so it stacks on top of the matrix; `width`/`height: 100%` make it cover the window.

- [ ] **Step 2: Wire settings callbacks in `main.rs`**

Inside `fn main`, after the reveal block, add:

```rust
    // Initialize the SSO fields from config.
    {
        let st = state.borrow();
        ui.set_sso_start_url(st.config.sso_start_url.as_str().into());
        ui.set_sso_region(st.config.sso_region.as_str().into());
    }

    // Toggle settings.
    {
        let ui_weak = ui.as_weak();
        ui.on_toggle_settings(move || {
            let ui = ui_weak.unwrap();
            ui.set_settings_open(!ui.get_settings_open());
        });
    }

    // Save SSO fields back into the in-memory config.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_save_sso(move || {
            let ui = ui_weak.unwrap();
            let mut st = state.borrow_mut();
            st.config.sso_start_url = ui.get_sso_start_url().to_string();
            st.config.sso_region = ui.get_sso_region().to_string();
        });
    }

    // Add an Application (auto prod/staging mappings derived from a slug).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_add_app(move |name| {
            let name = name.trim().to_string();
            if name.is_empty() {
                return;
            }
            let slug: String = name
                .to_lowercase()
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '-' })
                .collect();
            let new_app = Application {
                name,
                environments: vec![
                    Mapping {
                        environment: "prod".into(),
                        account_id: "000000000000".into(),
                        region: "us-east-1".into(),
                        secret_id: format!("{slug}/prod"),
                        permission_set: "ReadOnly".into(),
                    },
                    Mapping {
                        environment: "staging".into(),
                        account_id: "000000000000".into(),
                        region: "us-west-2".into(),
                        secret_id: format!("{slug}/staging"),
                        permission_set: "ReadOnly".into(),
                    },
                ],
            };
            {
                let mut st = state.borrow_mut();
                st.config.applications.push(new_app);
            }
            let ui = ui_weak.unwrap();
            render(&ui, &state);
        });
    }

    // Remove an Application, clamping the selection.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_remove_app(move |index| {
            let index = index as usize;
            {
                let mut st = state.borrow_mut();
                if index < st.config.applications.len() && st.config.applications.len() > 1 {
                    st.config.applications.remove(index);
                    if st.selected >= st.config.applications.len() {
                        st.selected = st.config.applications.len() - 1;
                    }
                }
            }
            let ui = ui_weak.unwrap();
            render(&ui, &state);
        });
    }
```

- [ ] **Step 3: Build and run**

Run: `cargo run -p janitor-gui`
Expected:
- The "Settings" button opens an overlay; "Close settings" hides it.
- Editing Start URL / Region and clicking "Save accounts" persists into the in-memory config (re-open settings to confirm the values stuck).
- Typing a name + "Add" creates a new Application; it appears in the sidebar and renders a matrix (via fallback) when selected.
- "Remove" deletes an Application from the sidebar (won't remove the last one).

- [ ] **Step 4: Commit**

```bash
git add janitor-gui/ui/app.slint janitor-gui/src/main.rs
git commit -m "feat(gui): in-memory settings — edit SSO + add/remove Applications"
```

---

## Task 11: Preferences — theme, sort, auto-hide

A small preferences panel inside Settings: light/dark theme, matrix sort (Name / Gap-first), and the reveal auto-hide duration. All in-memory; the view reads them.

**Files:**
- Modify: `janitor-gui/ui/app.slint`
- Modify: `janitor-gui/src/main.rs`

- [ ] **Step 1: Add preference controls + theme wiring to `app.slint`**

Extend imports:

```slint
import { ScrollView, LineEdit, Button, ComboBox, Switch, SpinBox } from "std-widgets.slint";
```

Add to `MainWindow` properties/callbacks:

```slint
    in property <bool> dark: true;
    in-out property <int> auto-hide-secs: 5;
    callback set-theme(bool);
    callback set-sort(int);   // 0 = Name, 1 = Gap-first
    callback set-auto-hide(int);
```

Make the window background follow the theme (replace the fixed `background:` line):

```slint
    background: root.dark ? #14161a : #f4f5f7;
```

Add a "Preferences" block inside the settings panel `VerticalLayout` (after the Applications section):

```slint
            Text { text: "Preferences"; color: #8a8f98; }
            HorizontalLayout {
                spacing: 8px;
                Text { text: "Dark theme"; color: #c8ccd4; width: 120px; }
                Switch { checked: root.dark; toggled => { root.set-theme(self.checked); } }
            }
            HorizontalLayout {
                spacing: 8px;
                Text { text: "Sort"; color: #c8ccd4; width: 120px; }
                ComboBox {
                    model: ["Name", "Gap first"];
                    current-index: 0;
                    selected => { root.set-sort(self.current-index); }
                }
            }
            HorizontalLayout {
                spacing: 8px;
                Text { text: "Reveal seconds"; color: #c8ccd4; width: 120px; }
                SpinBox {
                    minimum: 1;
                    maximum: 60;
                    value <=> root.auto-hide-secs;
                    edited => { root.set-auto-hide(self.value); }
                }
            }
```

- [ ] **Step 2: Add `Preferences` to state + wire callbacks in `main.rs`**

Extend imports:

```rust
use janitor_core::view::{sort_rows, SortKey};
```

Add a preferences struct and extend `AppState`:

```rust
struct Preferences {
    sort: SortKey,
    auto_hide_secs: u64,
    dark: bool,
}

// In AppState, add:
//     prefs: Preferences,
```

So `AppState` becomes:

```rust
struct AppState {
    source: MockSource,
    config: Config,
    selected: usize,
    prefs: Preferences,
    sets: Vec<(String, SecretShape)>,
    view: MatrixView,
}
```

Apply the sort preference in `render` (after building `view`, before pushing models):

```rust
fn render(ui: &MainWindow, state: &Rc<RefCell<AppState>>) {
    let mut st = state.borrow_mut();
    let selected = st.selected;
    let app = st.config.applications[selected].clone();
    let (sets, mut view) = build_app(&st.source, &app);
    sort_rows(&mut view, st.prefs.sort);
    st.sets = sets;
    st.view = view;
    ui.set_environments(env_models(&st.view));
    ui.set_rows(to_row_models(&st.view));
    ui.set_apps(app_models(&st.source, &st.config, selected));
}
```

Initialize `prefs` in the `AppState` literal in `fn main`:

```rust
        prefs: Preferences { sort: SortKey::Name, auto_hide_secs: 5, dark: true },
```

The reveal block is finalized in **Step 3** below — it must read `prefs.auto_hide_secs` only *after* dropping the `reveal_value` borrow, so it is rewritten wholesale rather than patched here.

Add the preference callbacks after the settings callbacks:

```rust
    // Theme.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_set_theme(move |dark| {
            state.borrow_mut().prefs.dark = dark;
            ui_weak.unwrap().set_dark(dark);
        });
    }

    // Sort.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_set_sort(move |index| {
            state.borrow_mut().prefs.sort = if index == 1 { SortKey::GapFirst } else { SortKey::Name };
            let ui = ui_weak.unwrap();
            render(&ui, &state);
        });
    }

    // Auto-hide duration.
    {
        let state = state.clone();
        ui.on_set_auto_hide(move |secs| {
            state.borrow_mut().prefs.auto_hide_secs = secs.max(1) as u64;
        });
    }
```

- [ ] **Step 3: Resolve the reveal borrow ordering**

Ensure the reveal callback reads `prefs.auto_hide_secs` only after dropping the `reveal_value` borrow. Final reveal block:

```rust
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_reveal_cell(move |row, col| {
            let ui = ui_weak.unwrap();
            // Re-borrow plaintext, copy it into a SharedString, then drop the borrow.
            let revealed: Option<SharedString> = {
                let st = state.borrow();
                st.view
                    .rows
                    .get(row as usize)
                    .and_then(|r| reveal_value(&st.sets, &r.key, col as usize))
                    .map(|v| SharedString::from(v.expose()))
            };
            let Some(text) = revealed else { return; };

            ui.set_revealed_row(row);
            ui.set_revealed_col(col);
            ui.set_revealed_text(text);

            let secs = state.borrow().prefs.auto_hide_secs;
            let ui_weak = ui.as_weak();
            slint::Timer::single_shot(Duration::from_secs(secs), move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_revealed_text(SharedString::new());
                    ui.set_revealed_row(-1);
                    ui.set_revealed_col(-1);
                }
            });
        });
    }
```

- [ ] **Step 4: Build and run**

Run: `cargo run -p janitor-gui`
Expected:
- The Dark-theme switch flips the window background light/dark.
- The Sort combo "Gap first" reorders the matrix so Gap rows are on top; "Name" restores name order.
- Changing "Reveal seconds" changes how long a revealed cell stays before auto-clearing (e.g. set to 2 and confirm the faster clear).

- [ ] **Step 5: Commit**

```bash
git add janitor-gui/ui/app.slint janitor-gui/src/main.rs
git commit -m "feat(gui): preferences — theme, matrix sort, reveal auto-hide"
```

---

## Task 12: Workspace green + docs

**Files:**
- Modify: `CLAUDE.md` (status note)

- [ ] **Step 1: Format, lint, test the whole workspace**

Run: `cargo fmt`
Run: `cargo clippy --all-targets`
Expected: no warnings. (Fix any clippy findings in the GUI glue.)
Run: `cargo test --workspace`
Expected: all `janitor-core` tests PASS; `janitor-gui` builds.

- [ ] **Step 2: Update the CLAUDE.md status line**

In `CLAUDE.md`, update the status blockquote near the top to note the GUI tracer-bullet slice landed: a thin `janitor-gui` Slint view renders the masked matrix + reveal over a mock `SecretSource`, with in-memory settings/preferences; real auth/AWS I/O and `Config` persistence remain unbuilt. Reference `docs/superpowers/specs/2026-05-30-gui-tracer-bullet-design.md`.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: note the GUI tracer-bullet slice landed"
```

- [ ] **Step 4: Final manual smoke**

Run: `cargo run -p janitor-gui`
Walk the whole thread once: pick each Application, reveal a few cells, open Settings, add/remove an App, flip theme/sort/auto-hide. Confirm nothing panics and the matrix always reflects the selection.

---

## Self-review notes (for the planner; delete before execution if desired)

- **Spec coverage:** matrix render (Task 7), reveal+clear (Task 8), sidebar/switching (Task 9), settings/accounts (Task 10), preferences theme/sort/auto-hide (Task 11), `SecretSource` seam (Task 2), `MockSource` seeded+fallback (Task 3), `project`/`MatrixView` (Task 4), `reveal_value` (Task 5), `sort_rows` (Task 6), Slint-on-Windows de-risk first (Task 1). All spec sections map to a task.
- **No new `Config` fields:** preferences live in the GUI `Preferences` struct (spec invariant) — existing core tests untouched; this plan only *adds* tests.
- **Lifetime crux:** `AppState` never stores a `Comparison`; `render` builds it transiently and projects to the owned `MatrixView`; reveal re-borrows `sets`. No self-referential struct.
- **Reveal clears, not hides:** the timeout overwrites `revealed-text` to empty and resets row/col (Tasks 8, 11).
