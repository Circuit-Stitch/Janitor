# Janitor Foundation Slice — Core, Secret Shapes & Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the `janitor-core` crate, its CI lint/test/coverage lane, the lossless secret-shape model (JSON ↔ dotted-path Entries with literal-dot handling), zeroizing secret types, and Config load/save — the entirely offline bedrock every later slice depends on.

**Architecture:** A Cargo workspace with one library crate, `janitor-core`, holding the security-critical logic (ADR 0003). This slice is **100% offline** — no AWS, no GUI. Secret material lives in zeroizing, Debug-redacted types (`secrecy`); the only thing that ever serializes to disk is `Config`, whose types structurally cannot hold a secret Value. **AWS-client seam (do not violate):** when auth (ADR 0002) and Secrets Manager I/O (ADR 0005) land in later slices, `core` logic must depend on an *AWS-client trait* with the concrete SDK adapter isolated in its own module, so the network stays mockable and the ≥80% coverage gate stays reachable. Lay out modules now so they don't fight that seam (this slice simply has no AWS, which is the easy way to comply).

**Tech Stack:** Rust (edition 2021), Cargo workspace. `serde` + `serde_json` (shape parsing), `toml` + `directories` (config), `secrecy`/`zeroize` (secret-in-memory), `thiserror` (typed errors). CI on GitHub Actions with `cargo fmt` / `cargo clippy -D warnings` / `cargo-llvm-cov` enforcing ≥80% line coverage on `janitor-core` (ADR 0007).

**In scope:** workspace + CI; `Value`/`LeafKind`; `EntryName` escaping; `flatten`/`unflatten`; `SecretShape`/`SecretBytes`; `Config` load/save; ADR 0008 recording the flattening scheme.

**Out of scope (later slices, do NOT build here):** the comparison engine (Aligned/Drift/Gap, hashing, the N-Environment matrix), Identity Center auth, Secrets Manager I/O, version-history viewing, the ADR-0001 write engine, and the Slint GUI. If a task tempts you toward any of these, stop — it belongs to a different plan.

**Conventions for every task below:**
- Each commit message ends with the trailer (per repo policy):
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- "Red" in Rust is usually a **compile error** (the type/fn doesn't exist yet) — that is the expected failing state; do not skip running it.
- After each task: `cargo fmt --all`, then `cargo clippy --all-targets -- -D warnings` must be clean before the commit.

---

## File Structure

```
janitor/
├── Cargo.toml                         # [workspace] — members = ["janitor-core"]
├── Cargo.lock                         # committed (this is ultimately an app)
├── rust-toolchain.toml                # pin stable + rustfmt/clippy
├── .gitignore                         # /target
├── .github/workflows/ci.yml           # fmt + clippy + test + coverage (no GUI deps yet)
├── docs/adr/0008-secret-shape-flattening-scheme.md   # records this slice's key decision
└── janitor-core/
    ├── Cargo.toml                     # lib crate + deps
    └── src/
        ├── lib.rs                     # module decls, crate docs, AWS-seam note
        ├── secret/
        │   ├── mod.rs                 # re-exports; declares submodules
        │   ├── value.rs               # LeafKind, Value (zeroizing, redacted)
        │   ├── name.rs                # EntryName (escaped dotted path) + escaping
        │   ├── flatten.rs             # flatten / unflatten / ShapeError
        │   └── shape.rs               # SecretShape, SecretBytes
        └── config/
            └── mod.rs                 # Config, Application, Mapping, ConfigError, load/save
```

Responsibilities: `value.rs` holds the secret + its JSON leaf type; `name.rs` owns the path↔name bijection; `flatten.rs` walks JSON trees both ways; `shape.rs` decides how a raw Secret Set value is interpreted; `config/mod.rs` is the only thing that touches disk.

---

## Task 1: Workspace, crate, toolchain & CI scaffolding

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `janitor-core/Cargo.toml`
- Create: `janitor-core/src/lib.rs`
- Create: `rust-toolchain.toml`
- Create: `.gitignore`
- Create: `.github/workflows/ci.yml`

This task has no logic to TDD; it is verified by build + lint. The coverage gate becomes meaningful once Task 3+ land (on an empty crate `cargo-llvm-cov` reports 100%, so CI stays green either way).

- [ ] **Step 1: Create the workspace root `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = ["janitor-core"]
# janitor-gui (Slint) joins this list in a later slice.
```

- [ ] **Step 2: Create `janitor-core/Cargo.toml`**

```toml
[package]
name = "janitor-core"
version = "0.1.0"
edition = "2021"
license = "GPL-3.0-only"
description = "Security-critical core for Janitor: secret-shape model, zeroizing types, and config."

[dependencies]
secrecy = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
thiserror = "2"
directories = "5"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 3: Create `janitor-core/src/lib.rs`** (docs only — modules are added by later tasks)

```rust
//! `janitor-core` — the security-critical core of Janitor.
//!
//! Holds everything that matters and is testable without a GUI (ADR 0003):
//! the secret-shape model (parsing AWS Secret Sets into comparable Entries),
//! zeroizing secret types, and Config load/save. **No GUI dependencies.**
//! Targets ≥80% line coverage.
//!
//! ## AWS access (future slices)
//! This foundation slice is entirely offline. When Identity Center auth
//! (ADR 0002) and Secrets Manager I/O (ADR 0005) land, core logic must depend
//! on an **AWS-client trait**, with the concrete AWS SDK adapter isolated in
//! its own module, so the network stays mockable and the coverage gate stays
//! reachable. Do not wire the SDK directly into the modules here.

// Modules are introduced by later tasks:
//   pub mod secret;   (Task 3+)
//   pub mod config;   (Task 8)
```

- [ ] **Step 4: Create `rust-toolchain.toml`**

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

- [ ] **Step 5: Create `.gitignore`**

```gitignore
/target
```

- [ ] **Step 6: Create `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always

jobs:
  check:
    name: fmt + clippy + test + coverage
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust (stable) with rustfmt, clippy, llvm-tools
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy, llvm-tools-preview

      - name: Cache cargo
        uses: Swatinem/rust-cache@v2

      - name: Format check
        run: cargo fmt --all -- --check

      - name: Clippy (deny warnings)
        run: cargo clippy --all-targets --all-features -- -D warnings

      - name: Install cargo-llvm-cov
        uses: taiki-e/install-action@cargo-llvm-cov

      - name: Test with coverage (janitor-core ≥80% lines)
        run: cargo llvm-cov --package janitor-core --all-features --fail-under-lines 80
```

- [ ] **Step 7: Verify the workspace builds and lints clean**

Run: `cargo build`
Expected: `Compiling janitor-core v0.1.0` … `Finished`, no errors.

Run: `cargo fmt --all -- --check`
Expected: no output, exit 0.

Run: `cargo clippy --all-targets -- -D warnings`
Expected: `Finished`, no warnings.

Run: `cargo test`
Expected: `running 0 tests` … `test result: ok. 0 passed`.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock rust-toolchain.toml .gitignore janitor-core/ .github/
git commit -m "chore: initialize cargo workspace, janitor-core crate, and CI

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: ADR 0008 — secret-shape flattening scheme

**Files:**
- Create: `docs/adr/0008-secret-shape-flattening-scheme.md`

Records the hard-to-reverse decision this slice implements (per CLAUDE.md working agreements). It becomes the v2 write round-trip contract, so it earns an ADR rather than living only in code.

- [ ] **Step 1: Write the ADR**

```markdown
# Secret-shape flattening: leaf-type-preserving dotted paths with escaped dots

**Status:** accepted

## Context

ADR 0004 fixes *that* nested JSON is flattened to dotted-path Entry names and
that the flatten/un-flatten round-trip must be lossless, but leaves the concrete
scheme open ("e.g. handling literal dots in keys"). It also leaves open how a
Set whose JSON has non-string leaves (numbers, bools, null, arrays) is modelled.
This ADR pins both, because the scheme is the de-facto interface a v2 write must
round-trip through — changing it later silently corrupts writes.

## Decision

- **Only JSON *objects* flatten.** A non-empty object is descended into; every
  other JSON value is a **leaf** → one Entry. A value that is not a JSON object
  at the top level (non-JSON text, or a top-level array/scalar) is **Raw**: a
  single Entry holding the verbatim original string.
- **Leaf types are preserved.** Each Entry carries a `LeafKind`
  (`String` | `Number` | `Bool` | `Null` | `Json`) so the inverse reproduces the
  original JSON *type* — a numeric Entry serializes back as `5432`, not `"5432"`.
  Arrays and **empty** objects are opaque `Json` leaves kept as verbatim compact
  JSON text. (Chosen over a simpler "strings-only, else Raw" rule so real-world
  secrets with numeric/bool fields still get per-Entry drift detection.)
- **Names escape literal dots.** A key path is rendered to an `EntryName` by
  joining segments with `.`, escaping `\` → `\\` and `.` → `\.` inside each
  segment first. This makes the path↔name mapping a **bijection**, so a single
  key containing a dot (`{"a.b": …}` → `a\.b`) and nesting (`{"a":{"b":…}}` →
  `a.b`) never collide — in the name *or* in cross-Environment comparison.

## Consequences

- **Number/bool tokens are normalized** by serde_json's default parser
  (`1.50` → `1.5`; integers beyond f64 range lose precision). Accepted: v1 is
  read-only, secrets rarely carry exotic numerics, and it keeps serde_json's
  well-tested default behavior. If token-exactness is ever needed, enabling
  `serde_json`'s `arbitrary_precision` (or `RawValue` for leaves) is a localized
  change.
- **Object key ordering is not byte-preserved** (objects re-serialize in sorted
  order). The result is semantically-equal JSON, which is all ADR 0001's
  replay-on-fresh write path needs.
- A path segment is never empty *as a whole path* — every Entry has ≥1 segment,
  so the empty path is not a representable input (an empty *string* key is, and
  round-trips fine).
```

- [ ] **Step 2: Commit**

```bash
git add docs/adr/0008-secret-shape-flattening-scheme.md
git commit -m "docs(adr): 0008 secret-shape flattening scheme

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `Value` and `LeafKind` (zeroizing, Debug-redacted)

**Files:**
- Create: `janitor-core/src/secret/mod.rs`
- Create: `janitor-core/src/secret/value.rs`
- Modify: `janitor-core/src/lib.rs` (add `pub mod secret;`)

`Value` is the secret content of one Entry plus the JSON leaf type it came from. It holds the content in a `secrecy::SecretString` (zeroized on drop, redacted in `Debug`) and exposes it only through one explicit accessor. It deliberately does **not** derive `Clone`/`PartialEq` — nothing in this slice needs them, and avoiding them sidesteps `secrecy`'s gated `Clone` and any secret-comparison footguns.

- [ ] **Step 1: Wire the `secret` module**

In `janitor-core/src/lib.rs`, replace the trailing comment block with:

```rust
pub mod secret;
```

Create `janitor-core/src/secret/mod.rs`:

```rust
//! The secret-shape model: how a Secret Set's stored value is parsed into
//! comparable Entries, and the zeroizing types that hold secret material.

mod value;

pub use value::{LeafKind, Value};
```

- [ ] **Step 2: Write the failing tests** — create `janitor-core/src/secret/value.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_value_exposes_content_and_kind() {
        let v = Value::string("hunter2");
        assert_eq!(v.expose(), "hunter2");
        assert_eq!(v.kind(), LeafKind::String);
    }

    #[test]
    fn number_value_keeps_token_and_kind() {
        let v = Value::new("5432", LeafKind::Number);
        assert_eq!(v.expose(), "5432");
        assert_eq!(v.kind(), LeafKind::Number);
    }

    #[test]
    fn debug_never_leaks_content() {
        let v = Value::string("hunter2");
        let rendered = format!("{v:?}");
        assert!(!rendered.contains("hunter2"), "Debug leaked secret: {rendered}");
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p janitor-core value`
Expected: **compile error** — `cannot find type/function ... Value` / `LeafKind`. This is the expected red.

- [ ] **Step 4: Implement `Value` and `LeafKind`** — prepend above the test module in `janitor-core/src/secret/value.rs`:

```rust
//! The secret Value of an Entry and the JSON leaf type it came from.

use secrecy::{ExposeSecret, SecretString};

/// The JSON type of a leaf, preserved so a v2 write round-trips the original
/// type (a numeric Entry serializes back as `5432`, not `"5432"`). See ADR 0008.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafKind {
    /// A JSON string. `content` is the unescaped string contents.
    String,
    /// A JSON number. `content` is the number token (e.g. `5432`, `1.5`).
    Number,
    /// A JSON boolean. `content` is `"true"` or `"false"`.
    Bool,
    /// JSON `null`. `content` is `"null"`.
    Null,
    /// An opaque JSON subtree kept verbatim: arrays and empty objects.
    /// `content` is the compact JSON text (e.g. `["a","b"]`, `{}`).
    Json,
}

/// One Entry's secret Value: content held in a zeroizing, redacted buffer plus
/// the JSON leaf type. The content is **never** exposed via `Debug`/`Display` —
/// only through the explicit [`Value::expose`] accessor.
pub struct Value {
    content: SecretString,
    kind: LeafKind,
}

impl Value {
    /// Construct a Value of the given kind from already-decoded content.
    pub fn new(content: impl Into<String>, kind: LeafKind) -> Self {
        Self {
            content: SecretString::from(content.into()),
            kind,
        }
    }

    /// A JSON string Value (also used for a Raw, non-JSON Secret Set).
    pub fn string(content: impl Into<String>) -> Self {
        Self::new(content, LeafKind::String)
    }

    /// The leaf's JSON type.
    pub fn kind(&self) -> LeafKind {
        self.kind
    }

    /// Borrow the secret content. Call sites that touch this are the ones that
    /// must respect the reveal/clipboard rules — keep them few.
    pub fn expose(&self) -> &str {
        self.content.expose_secret()
    }
}

// Manual Debug so a Value never prints its content. (`SecretString` already
// redacts; spelled out here so the guarantee is local and obvious.)
impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Value")
            .field("kind", &self.kind)
            .field("content", &"<redacted>")
            .finish()
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p janitor-core value`
Expected: `test result: ok. 3 passed`.

- [ ] **Step 6: Commit** (after `cargo fmt --all` and clippy clean)

```bash
git add janitor-core/src/lib.rs janitor-core/src/secret/
git commit -m "feat(core): zeroizing Value type with JSON leaf kinds

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `EntryName` — escaped dotted path (the literal-dot bijection)

**Files:**
- Create: `janitor-core/src/secret/name.rs`
- Modify: `janitor-core/src/secret/mod.rs` (declare + re-export `name`)

An `EntryName` is nested keys joined by `.`, with `\` and `.` escaped inside each segment so the path↔name mapping is a bijection. An Entry *name* is not secret (it's a config key like `DB_URL`), so it prints normally — unlike a `Value`.

- [ ] **Step 1: Declare the module** — in `janitor-core/src/secret/mod.rs`, add under `mod value;`:

```rust
mod name;
```

and add to the re-export line:

```rust
pub use name::EntryName;
```

- [ ] **Step 2: Write the failing tests** — create `janitor-core/src/secret/name.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn p(segs: &[&str]) -> Vec<String> {
        segs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn joins_simple_path_with_dots() {
        assert_eq!(
            EntryName::from_path(&p(&["db", "primary", "url"])).as_str(),
            "db.primary.url"
        );
    }

    #[test]
    fn escapes_literal_dot_in_key() {
        // A single key containing a dot must NOT look like nesting.
        let dotted = EntryName::from_path(&p(&["a.b"]));
        let nested = EntryName::from_path(&p(&["a", "b"]));
        assert_eq!(dotted.as_str(), "a\\.b");
        assert_eq!(nested.as_str(), "a.b");
        assert_ne!(dotted, nested); // injective: distinct paths → distinct names
    }

    #[test]
    fn escapes_literal_backslash() {
        assert_eq!(EntryName::from_path(&p(&["a\\b"])).as_str(), "a\\\\b");
    }

    #[test]
    fn path_round_trips_through_name() {
        let cases = vec![
            p(&["A"]),
            p(&["db", "url"]),
            p(&["a.b"]),
            p(&["a", "b"]),
            p(&["a\\b"]),
            p(&["a.b", "c"]),
            p(&["weird\\.key", "x"]),
            p(&[""]),       // single empty-string key
            p(&["a", ""]),  // trailing empty segment
        ];
        for path in cases {
            let name = EntryName::from_path(&path);
            assert_eq!(name.segments(), path, "round-trip failed for {path:?} -> {name}");
        }
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p janitor-core name`
Expected: **compile error** — `cannot find ... EntryName`. Expected red.

- [ ] **Step 4: Implement `EntryName` + escaping** — prepend above the test module in `janitor-core/src/secret/name.rs`:

```rust
//! `EntryName`: the dotted-path name of an Entry, with literal dots/backslashes
//! escaped so the path↔name mapping is a bijection (ADR 0008).

/// The name of an Entry: nested JSON keys joined by `.`, with any literal `.`
/// or `\` inside a key escaped (`.` → `\.`, `\` → `\\`). The mapping is
/// reversible, so `{"a.b": …}` and `{"a": {"b": …}}` get distinct names.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryName(String);

impl EntryName {
    /// Build a name from a key path (one element per nesting level).
    pub fn from_path(path: &[String]) -> Self {
        let escaped: Vec<String> = path.iter().map(|seg| escape_segment(seg)).collect();
        EntryName(escaped.join("."))
    }

    /// Recover the original key path. Inverse of [`EntryName::from_path`].
    pub fn segments(&self) -> Vec<String> {
        split_escaped(&self.0)
    }

    /// The rendered name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EntryName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Debug for EntryName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // An Entry *name* is config metadata (e.g. DB_URL), not a secret.
        write!(f, "EntryName({:?})", self.0)
    }
}

fn escape_segment(seg: &str) -> String {
    let mut out = String::with_capacity(seg.len());
    for ch in seg.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '.' => out.push_str("\\."),
            other => out.push(other),
        }
    }
    out
}

/// Split an escaped name on unescaped `.` and unescape each segment.
fn split_escaped(name: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = name.chars();
    loop {
        let Some(ch) = chars.next() else { break };
        match ch {
            '\\' => match chars.next() {
                // The next char is literal (escaped).
                Some(next) => current.push(next),
                // Trailing lone backslash (not produced by our escaper): keep it.
                None => current.push('\\'),
            },
            '.' => segments.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    segments.push(current);
    segments
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p janitor-core name`
Expected: `test result: ok. 4 passed`.

- [ ] **Step 6: Commit** (after fmt + clippy clean)

```bash
git add janitor-core/src/secret/
git commit -m "feat(core): EntryName with reversible dotted-path escaping

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `flatten` — JSON object → dotted-path Entries

**Files:**
- Create: `janitor-core/src/secret/flatten.rs`
- Modify: `janitor-core/src/secret/mod.rs` (declare + re-export `flatten`)

Walks a parsed JSON object, descending into non-empty objects and emitting one Entry per leaf, preserving the leaf's `LeafKind`. (`unflatten` arrives in Task 6 — keep this commit to the forward direction so it compiles green on its own.)

- [ ] **Step 1: Declare the module** — in `janitor-core/src/secret/mod.rs`, add under `mod name;`:

```rust
mod flatten;
```

and add to the re-exports:

```rust
pub use flatten::flatten;
```

- [ ] **Step 2: Write the failing tests** — create `janitor-core/src/secret/flatten.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn parse_obj(json: &str) -> Map<String, Json> {
        match serde_json::from_str(json).unwrap() {
            Json::Object(m) => m,
            _ => panic!("test input must be a JSON object"),
        }
    }

    fn name(segs: &[&str]) -> EntryName {
        EntryName::from_path(&segs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn flattens_flat_string_map() {
        let entries = flatten(&parse_obj(r#"{"A":"1","B":"2"}"#));
        let names: Vec<_> = entries.keys().map(|n| n.as_str().to_string()).collect();
        assert_eq!(names, vec!["A", "B"]);
        assert_eq!(entries[&name(&["A"])].kind(), LeafKind::String);
        assert_eq!(entries[&name(&["A"])].expose(), "1");
    }

    #[test]
    fn flattens_nested_to_dotted_path() {
        let entries = flatten(&parse_obj(r#"{"db":{"primary":{"url":"x"}}}"#));
        let v = &entries[&name(&["db", "primary", "url"])];
        assert_eq!(entries.len(), 1);
        assert_eq!(v.expose(), "x");
        assert_eq!(v.kind(), LeafKind::String);
    }

    #[test]
    fn preserves_non_string_leaf_kinds() {
        let entries = flatten(&parse_obj(r#"{"port":5432,"tls":true,"opt":null}"#));
        assert_eq!(entries[&name(&["port"])].kind(), LeafKind::Number);
        assert_eq!(entries[&name(&["port"])].expose(), "5432");
        assert_eq!(entries[&name(&["tls"])].kind(), LeafKind::Bool);
        assert_eq!(entries[&name(&["tls"])].expose(), "true");
        assert_eq!(entries[&name(&["opt"])].kind(), LeafKind::Null);
    }

    #[test]
    fn array_and_empty_object_are_opaque_json_leaves() {
        let entries = flatten(&parse_obj(r#"{"hosts":["a","b"],"meta":{}}"#));
        assert_eq!(entries[&name(&["hosts"])].kind(), LeafKind::Json);
        assert_eq!(entries[&name(&["hosts"])].expose(), r#"["a","b"]"#);
        assert_eq!(entries[&name(&["meta"])].kind(), LeafKind::Json);
        assert_eq!(entries[&name(&["meta"])].expose(), "{}");
    }

    #[test]
    fn literal_dot_key_is_escaped_not_nested() {
        let entries = flatten(&parse_obj(r#"{"a.b":"flat","a":{"b":"nested"}}"#));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[&name(&["a.b"])].expose(), "flat");
        assert_eq!(entries[&name(&["a", "b"])].expose(), "nested");
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p janitor-core flatten`
Expected: **compile error** — `cannot find function flatten`. Expected red.

- [ ] **Step 4: Implement `flatten`** — prepend above the test module in `janitor-core/src/secret/flatten.rs`:

```rust
//! Flatten a parsed JSON object into dotted-path Entries (and, with Task 6,
//! back again). Only JSON *objects* are descended into; every other value
//! (string, number, bool, null, array, empty object) is a leaf → one Entry,
//! with its [`LeafKind`] preserved. See ADR 0008.

use std::collections::BTreeMap;

use serde_json::{Map, Value as Json};

use super::name::EntryName;
use super::value::{LeafKind, Value};

/// Flatten a JSON object into Entries keyed by dotted-path [`EntryName`].
pub fn flatten(object: &Map<String, Json>) -> BTreeMap<EntryName, Value> {
    let mut out = BTreeMap::new();
    let mut path: Vec<String> = Vec::new();
    flatten_object(object, &mut path, &mut out);
    out
}

fn flatten_object(
    object: &Map<String, Json>,
    path: &mut Vec<String>,
    out: &mut BTreeMap<EntryName, Value>,
) {
    for (key, child) in object {
        path.push(key.clone());
        match child {
            Json::Object(inner) if !inner.is_empty() => flatten_object(inner, path, out),
            leaf => {
                out.insert(EntryName::from_path(path), leaf_to_value(leaf));
            }
        }
        path.pop();
    }
}

fn leaf_to_value(leaf: &Json) -> Value {
    match leaf {
        Json::String(s) => Value::new(s.clone(), LeafKind::String),
        Json::Number(n) => Value::new(n.to_string(), LeafKind::Number),
        Json::Bool(b) => Value::new(b.to_string(), LeafKind::Bool),
        Json::Null => Value::new("null", LeafKind::Null),
        // Arrays and (empty) objects: keep the verbatim compact JSON text.
        Json::Array(_) | Json::Object(_) => Value::new(leaf.to_string(), LeafKind::Json),
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p janitor-core flatten`
Expected: `test result: ok. 5 passed`.

- [ ] **Step 6: Commit** (after fmt + clippy clean)

```bash
git add janitor-core/src/secret/
git commit -m "feat(core): flatten JSON objects into dotted-path Entries

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: `unflatten` + `ShapeError` + lossless round-trip

**Files:**
- Modify: `janitor-core/src/secret/flatten.rs` (add `unflatten`, `ShapeError`)
- Modify: `janitor-core/src/secret/mod.rs` (re-export `unflatten`, `ShapeError`)

The inverse of `flatten`, plus the property test that proves the round-trip is lossless across flat/nested/typed/array/empty-object/literal-dot/empty-key inputs. Round-trip equality is asserted **semantically** (compare reconstructed `serde_json::Value`s), since object key order is intentionally not byte-preserved (ADR 0008).

- [ ] **Step 1: Add the failing tests** — append these to the existing `tests` module in `janitor-core/src/secret/flatten.rs` (reuse `parse_obj`/`name` from Task 5):

```rust
    #[test]
    fn round_trips_through_flatten_unflatten() {
        let inputs = [
            r#"{"A":"1","B":"2"}"#,
            r#"{"db":{"primary":{"url":"postgres://x"}}}"#,
            r#"{"port":5432,"tls":true,"opt":null}"#,
            r#"{"hosts":["a","b"],"meta":{}}"#,
            r#"{"a.b":"flat","a":{"b":"nested"}}"#,
            r#"{"":"empty-key","x":{"":"nested-empty-key"}}"#,
            r#"{"big":1.5e3,"neg":-7}"#,
        ];
        for input in inputs {
            let original: Json = serde_json::from_str(input).unwrap();
            let object = match &original {
                Json::Object(m) => m.clone(),
                _ => unreachable!(),
            };
            let rebuilt = unflatten(&flatten(&object)).unwrap();
            assert_eq!(rebuilt, original, "round-trip changed value for {input}");
        }
    }

    #[test]
    fn unflatten_rejects_malformed_number_leaf() {
        let mut entries = BTreeMap::new();
        entries.insert(name(&["port"]), Value::new("not-a-number", LeafKind::Number));
        let err = unflatten(&entries).unwrap_err();
        assert!(matches!(err, ShapeError::MalformedLeaf { .. }));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p janitor-core flatten`
Expected: **compile error** — `cannot find ... unflatten` / `ShapeError`. Expected red.

- [ ] **Step 3: Implement `unflatten` + `ShapeError`** — add to `janitor-core/src/secret/flatten.rs` (below `leaf_to_value`):

```rust
/// Something went wrong reconstructing JSON from Entries.
#[derive(Debug, thiserror::Error)]
pub enum ShapeError {
    /// A leaf's stored content was not valid for its [`LeafKind`] (e.g. a
    /// `Number` Entry whose content is not a JSON number). Only reachable for
    /// hand-constructed Entries; [`flatten`] never produces such a set.
    #[error("entry {name} has malformed {kind:?} content")]
    MalformedLeaf { name: String, kind: LeafKind },
}

/// Rebuild a JSON object from Entries. Inverse of [`flatten`].
pub fn unflatten(entries: &BTreeMap<EntryName, Value>) -> Result<Json, ShapeError> {
    let mut root = Map::new();
    for (name, value) in entries {
        let leaf = value_to_leaf(name, value)?;
        insert_at_path(&mut root, &name.segments(), leaf);
    }
    Ok(Json::Object(root))
}

fn value_to_leaf(name: &EntryName, value: &Value) -> Result<Json, ShapeError> {
    let malformed = || ShapeError::MalformedLeaf {
        name: name.to_string(),
        kind: value.kind(),
    };
    let content = value.expose();
    let json = match value.kind() {
        LeafKind::String => Json::String(content.to_string()),
        LeafKind::Number => {
            let n: serde_json::Number = serde_json::from_str(content).map_err(|_| malformed())?;
            Json::Number(n)
        }
        LeafKind::Bool => Json::Bool(content.parse().map_err(|_| malformed())?),
        LeafKind::Null => Json::Null,
        LeafKind::Json => serde_json::from_str(content).map_err(|_| malformed())?,
    };
    Ok(json)
}

fn insert_at_path(root: &mut Map<String, Json>, segments: &[String], leaf: Json) {
    // `segments` is always non-empty for Entries produced by `flatten`.
    let Some((first, rest)) = segments.split_first() else {
        return;
    };
    if rest.is_empty() {
        root.insert(first.clone(), leaf);
        return;
    }
    let child = root
        .entry(first.clone())
        .or_insert_with(|| Json::Object(Map::new()));
    if let Json::Object(map) = child {
        insert_at_path(map, rest, leaf);
    }
    // If `child` already exists and isn't an object, the Entry set is internally
    // inconsistent; `flatten` never produces such a set, so we keep the first
    // writer rather than panicking.
}
```

Then in `janitor-core/src/secret/mod.rs`, **replace** the Task 5 line `pub use flatten::flatten;` **with** (do not add a second line — that would be a duplicate `flatten` import, E0252):

```rust
pub use flatten::{flatten, unflatten, ShapeError};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p janitor-core flatten`
Expected: `test result: ok. 7 passed`.

- [ ] **Step 5: Commit** (after fmt + clippy clean)

```bash
git add janitor-core/src/secret/
git commit -m "feat(core): lossless unflatten with round-trip property tests

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: `SecretShape` + `SecretBytes`

**Files:**
- Create: `janitor-core/src/secret/shape.rs`
- Modify: `janitor-core/src/secret/mod.rs` (declare + re-export `shape`)

`SecretShape` is how Janitor interprets a Secret Set's stored value: a JSON object flattens to Entries; anything else (non-JSON text, top-level array/scalar) is `Raw` holding the verbatim string; `SecretBinary` is opaque bytes in a zeroizing buffer, never rendered (ADR 0004). `SecretBytes` exposes only its length (a tolerated side-channel per CONTEXT.md); hashing is a later slice.

- [ ] **Step 1: Declare the module** — in `janitor-core/src/secret/mod.rs`, add under `mod flatten;`:

```rust
mod shape;
```

and add to the re-exports:

```rust
pub use shape::{SecretBytes, SecretShape};
```

- [ ] **Step 2: Write the failing tests** — create `janitor-core/src/secret/shape.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::value::LeafKind;

    #[test]
    fn json_object_becomes_entries() {
        match SecretShape::from_secret_string(r#"{"A":"1"}"#) {
            SecretShape::Json(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries.values().next().unwrap().expose(), "1");
            }
            other => panic!("expected Json, got {other:?}"),
        }
    }

    #[test]
    fn non_json_text_becomes_raw() {
        match SecretShape::from_secret_string("just-a-token") {
            SecretShape::Raw(v) => {
                assert_eq!(v.expose(), "just-a-token");
                assert_eq!(v.kind(), LeafKind::String);
            }
            other => panic!("expected Raw, got {other:?}"),
        }
    }

    #[test]
    fn top_level_array_is_raw_verbatim() {
        match SecretShape::from_secret_string("[1,2,3]") {
            SecretShape::Raw(v) => assert_eq!(v.expose(), "[1,2,3]"),
            other => panic!("expected Raw, got {other:?}"),
        }
    }

    #[test]
    fn binary_reports_length() {
        match SecretShape::from_secret_binary(vec![1, 2, 3, 4]) {
            SecretShape::Binary(b) => {
                assert_eq!(b.len(), 4);
                assert!(!b.is_empty());
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_values_and_bytes() {
        let json = SecretShape::from_secret_string(r#"{"password":"hunter2"}"#);
        assert!(!format!("{json:?}").contains("hunter2"), "leaked value in Debug");

        let bin = SecretShape::from_secret_binary(vec![1, 2, 3, 4]);
        assert!(format!("{bin:?}").contains("len: 4"), "Binary Debug should show length");
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p janitor-core shape`
Expected: **compile error** — `cannot find ... SecretShape`. Expected red.

- [ ] **Step 4: Implement `SecretShape` + `SecretBytes`** — prepend above the test module in `janitor-core/src/secret/shape.rs`:

```rust
//! `SecretShape`: how Janitor interprets a Secret Set's stored value
//! (ADR 0004 / ADR 0008).

use std::collections::BTreeMap;

use secrecy::{ExposeSecret, SecretBox};
use serde_json::Value as Json;

use super::flatten::flatten;
use super::name::EntryName;
use super::value::Value;

/// Opaque bytes of a `SecretBinary`, held in a zeroizing buffer and never
/// rendered (ADR 0004). Compared only by length/hash in a later slice.
pub struct SecretBytes(SecretBox<[u8]>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(SecretBox::from(bytes.into_boxed_slice()))
    }

    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the bytes; length is a tolerated side-channel (CONTEXT.md).
        f.debug_struct("SecretBytes").field("len", &self.len()).finish()
    }
}

/// How Janitor interprets a Secret Set's stored value.
#[derive(Debug)]
pub enum SecretShape {
    /// A JSON object, flattened to dotted-path Entries.
    Json(BTreeMap<EntryName, Value>),
    /// A value that is not a JSON object (non-JSON text, or a top-level JSON
    /// array/scalar): one opaque Entry holding the verbatim text.
    Raw(Value),
    /// `SecretBinary`: opaque bytes, never rendered.
    Binary(SecretBytes),
}

impl SecretShape {
    /// Interpret a `SecretString` value. A JSON *object* flattens to Entries;
    /// anything else is [`SecretShape::Raw`] holding the verbatim string.
    pub fn from_secret_string(secret_string: &str) -> Self {
        match serde_json::from_str::<Json>(secret_string) {
            Ok(Json::Object(object)) => SecretShape::Json(flatten(&object)),
            _ => SecretShape::Raw(Value::string(secret_string)),
        }
    }

    /// Interpret a `SecretBinary` value: always [`SecretShape::Binary`].
    pub fn from_secret_binary(bytes: Vec<u8>) -> Self {
        SecretShape::Binary(SecretBytes::new(bytes))
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p janitor-core shape`
Expected: `test result: ok. 5 passed`.

- [ ] **Step 6: Commit** (after fmt + clippy clean)

```bash
git add janitor-core/src/secret/
git commit -m "feat(core): SecretShape interpretation and zeroizing SecretBytes

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: `Config` — load/save (the only thing that touches disk)

**Files:**
- Create: `janitor-core/src/config/mod.rs`
- Modify: `janitor-core/src/lib.rs` (add `pub mod config;`)

`Config` is the user's saved, non-secret locations: Applications and their per-Environment Mappings, plus Identity Center settings. It is the *only* data Janitor writes to disk and holds **locations, never Values** — the types structurally cannot hold a secret (no `Value`/`SecretString` field), which is the invariant enforced by construction. Load/save take an explicit path so they're unit-testable against a tempdir; thin no-arg wrappers resolve the per-OS path via `directories`.

- [ ] **Step 1: Wire the module** — in `janitor-core/src/lib.rs`, add below `pub mod secret;`:

```rust
pub mod config;
```

- [ ] **Step 2: Write the failing tests** — create `janitor-core/src/config/mod.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        Config {
            sso_start_url: "https://acme.awsapps.com/start".into(),
            sso_region: "us-east-1".into(),
            applications: vec![Application {
                name: "myapp".into(),
                environments: vec![
                    Mapping {
                        environment: "prod".into(),
                        account_id: "111111111111".into(),
                        region: "us-east-1".into(),
                        secret_id: "myapp/prod".into(),
                        permission_set: "ReadOnly".into(),
                    },
                    Mapping {
                        environment: "staging".into(),
                        account_id: "222222222222".into(),
                        region: "us-west-2".into(),
                        secret_id: "myapp/staging".into(),
                        permission_set: "ReadOnly".into(),
                    },
                ],
            }],
        }
    }

    #[test]
    fn default_config_is_empty() {
        let c = Config::default();
        assert!(c.sso_start_url.is_empty());
        assert!(c.applications.is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = sample();
        original.save_to(&path).unwrap();
        assert_eq!(Config::load_from(&path).unwrap(), original);
    }

    #[test]
    fn missing_file_loads_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        assert_eq!(Config::load_from(&path).unwrap(), Config::default());
    }

    #[test]
    fn invalid_toml_is_a_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "this is = = not toml").unwrap();
        assert!(matches!(Config::load_from(&path).unwrap_err(), ConfigError::Parse(_)));
    }

    #[test]
    fn save_creates_missing_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("sub").join("config.toml");
        sample().save_to(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn default_config_path_ends_with_config_toml() {
        // Relies on a resolvable home/config dir (true on dev machines & CI runners).
        let path = Config::config_path().unwrap();
        assert_eq!(path.file_name().unwrap(), "config.toml");
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p janitor-core config`
Expected: **compile error** — `cannot find ... Config`. Expected red.

- [ ] **Step 4: Implement `Config`** — prepend above the test module in `janitor-core/src/config/mod.rs`:

```rust
//! Config: the user's saved, non-secret locations (Applications and their
//! per-Environment Mappings) plus Identity Center settings. This is the *only*
//! data Janitor writes to disk, and it holds **locations, never Values**
//! (THREAT-MODEL.md): the types below cannot structurally hold a secret.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Everything Janitor persists. Plain, non-secret data.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// IAM Identity Center start URL (e.g. `https://my-org.awsapps.com/start`).
    pub sso_start_url: String,
    /// AWS region hosting Identity Center (where SSO-OIDC calls go).
    pub sso_region: String,
    /// Saved Applications, each tying a logical Entry set to a Set per Environment.
    pub applications: Vec<Application>,
}

/// A named grouping of one logical Entry set across Environments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Application {
    /// User-facing Application name (e.g. `myapp`).
    pub name: String,
    /// One Mapping per Environment compared in this Application's matrix.
    pub environments: Vec<Mapping>,
}

/// Which concrete AWS Secret Set backs one Environment of an Application.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mapping {
    /// Environment name (e.g. `prod`, `staging`).
    pub environment: String,
    /// AWS account id that owns the Set.
    pub account_id: String,
    /// AWS region the Set lives in.
    pub region: String,
    /// Secret name or ARN of the Set.
    pub secret_id: String,
    /// IAM Identity Center permission set used to reach this account.
    pub permission_set: String,
}

/// Errors loading or saving [`Config`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The per-OS config directory could not be determined.
    #[error("could not determine the OS config directory")]
    NoConfigDir,
    /// Reading or writing the config file failed.
    #[error("config file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The config file was not valid TOML.
    #[error("config file is not valid TOML: {0}")]
    Parse(#[from] toml::de::Error),
    /// The config could not be serialized to TOML.
    #[error("could not serialize config to TOML: {0}")]
    Serialize(#[from] toml::ser::Error),
}

impl Config {
    /// The default config file path: `<OS config dir>/config.toml`.
    pub fn config_path() -> Result<PathBuf, ConfigError> {
        let dirs = directories::ProjectDirs::from("com", "Janitor", "Janitor")
            .ok_or(ConfigError::NoConfigDir)?;
        Ok(dirs.config_dir().join("config.toml"))
    }

    /// Load config from the default path (missing file → [`Config::default`]).
    pub fn load() -> Result<Config, ConfigError> {
        Self::load_from(&Self::config_path()?)
    }

    /// Save config to the default path, creating the directory if needed.
    pub fn save(&self) -> Result<(), ConfigError> {
        self.save_to(&Self::config_path()?)
    }

    /// Load config from an explicit path. Missing file → [`Config::default`].
    pub fn load_from(path: &Path) -> Result<Config, ConfigError> {
        match fs::read_to_string(path) {
            Ok(text) => Ok(toml::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(ConfigError::Io(e)),
        }
    }

    /// Save config to an explicit path, atomically (write a sibling temp file,
    /// then rename over the target so a crash never leaves a half-written file).
    pub fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, text)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p janitor-core config`
Expected: `test result: ok. 6 passed`.

- [ ] **Step 6: Commit** (after fmt + clippy clean)

```bash
git add janitor-core/src/lib.rs janitor-core/src/config/
git commit -m "feat(core): non-secret Config with atomic TOML load/save

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Full-suite verification & honest doc update

**Files:**
- Modify: `CLAUDE.md` (status + commands now that real code exists)

Close the slice: prove the whole lane is green including the coverage gate, then bring `CLAUDE.md` in line with reality (it currently says "no source code or Cargo.toml exists yet" and lists `cargo run -p janitor-gui`, which is not yet a real command).

- [ ] **Step 1: Run the full workspace suite**

Run: `cargo test`
Expected: `test result: ok. 25 passed; 0 failed` (25 at time of writing — `value` 3, `name` 4, `flatten` 7, `shape` 5, `config` 6).

- [ ] **Step 2: Run fmt + clippy**

Run: `cargo fmt --all -- --check`
Expected: no output, exit 0.

Run: `cargo clippy --all-targets -- -D warnings`
Expected: `Finished`, no warnings.

- [ ] **Step 3: Run the coverage gate locally** (matches CI)

Run: `cargo llvm-cov --package janitor-core --fail-under-lines 80`
Expected: a coverage table, total line coverage ≥ 80%, exit 0. If under 80%, add tests for the uncovered lines (do **not** lower the threshold) and surface what was uncovered.

- [ ] **Step 4: Update `CLAUDE.md` status** — replace this exact block:

```markdown
> **Status: design phase.** No source code or `Cargo.toml` exists yet. The design
> is fully specified in [`CONTEXT.md`](CONTEXT.md) (domain glossary),
> [`docs/adr/`](docs/adr/) (decisions 0001–0007), and
> [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) (security posture). **Read those
> first** — this file only summarizes. Replace the placeholder command/architecture
> notes below with verified specifics as real code lands.
```

with:

```markdown
> **Status: foundation landed.** The Cargo workspace and `janitor-core`'s offline
> bedrock exist — secret-shape model (parse/flatten/unflatten), zeroizing `Value`,
> and `Config` load/save — under a CI lint/test/coverage lane. No AWS, GUI, or
> write path yet. The design is specified in [`CONTEXT.md`](CONTEXT.md) (domain
> glossary), [`docs/adr/`](docs/adr/) (decisions 0001–0008), and
> [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) (security posture). **Read those
> first** — this file only summarizes.
```

- [ ] **Step 5: Update `CLAUDE.md` commands** — replace this exact line:

```
cargo run -p janitor-gui          # run the app
```

with:

```
cargo llvm-cov -p janitor-core    # coverage (≥80% gate)
# cargo run -p janitor-gui        # (not yet — GUI lands in a later slice)
```

- [ ] **Step 6: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: mark foundation slice landed; align commands with real workspace

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Author's Self-Review

Checked against the chosen scope (workspace + CI; secret-shape model with lossless flatten/un-flatten incl. literal-dot handling; zeroizing `Value`; Config load/save) and ADR 0008:

- **Scope coverage:** workspace/CI → Task 1; flattening-scheme decision → Task 2; `Value`/`LeafKind` → Task 3; `EntryName` escaping → Task 4; `flatten` → Task 5; `unflatten` + round-trip → Task 6; `SecretShape`/`SecretBytes` → Task 7; `Config` → Task 8; verification/docs → Task 9. No scope gaps; comparison engine / auth / I/O / write engine / GUI explicitly deferred.
- **Compiles green at every commit:** modules are wired incrementally — Task 5 re-exports only `flatten`; `unflatten`/`ShapeError` are added in Task 6 — so no commit references an undefined item.
- **Type/name consistency:** `Value::new`/`Value::string`/`expose`/`kind`; `EntryName::from_path`/`segments`/`as_str`; `flatten`/`unflatten`/`ShapeError::MalformedLeaf`; `SecretShape::{Json,Raw,Binary}`/`from_secret_string`/`from_secret_binary`; `SecretBytes::{new,len,is_empty}`; `Config::{load,save,load_from,save_to,config_path}`/`ConfigError` — all referenced consistently across tasks.
- **No placeholders:** every code/test step carries complete code; every run step has an exact command and expected output.
- **Invariants honored:** `Value`/`SecretBytes` are Debug-redacted and zeroizing; `Value` deliberately omits `Clone`/`PartialEq`; `Config` types cannot hold a secret; nothing in this slice can make a network or mutating call.
- **Known risk flagged for the executor:** ADR 0008 records that number/bool tokens are normalized by serde_json's default parser — the round-trip test asserts *semantic* (value) equality, not byte-exact tokens. If true token-exactness is ever required, that's an additive `arbitrary_precision`/`RawValue` change, not a redesign.
