# GUI tracer-bullet slice: mock-driven matrix + reveal + faked settings

**Status:** approved (brainstorm) — ready for planning
**Date:** 2026-05-30
**Related:** ADR 0001 (non-stomping writes), ADR 0002 (auth), ADR 0003 (core/GUI split, Slint, secret display), ADR 0004 (read-only v1, secret shapes), ADR 0005 (clipboard/read model), ADR 0006 (history), ADR 0009 (Comparison borrows Values); `CONTEXT.md`; `docs/THREAT-MODEL.md`.

## Why

Rather than build the AWS auth (ADR 0002) or Secrets Manager I/O (ADR 0005) layers
horizontally in isolation, this slice drives a **vertical tracer bullet** to prove the
end-to-end wiring early. Mock data stands in for the two unbuilt layers. The deliverable
is a *runnable* thread through the real architecture — not visual polish.

The thread:

```
Slint window
  └─ select Application (in-memory mock Config)
       └─ MockSource.fetch(&Mapping)  →  SecretShape per Environment      [the mock seam]
            └─ Comparison::build(&[(env, SecretShape)])                    [real core engine]
                 └─ project() → owned MatrixView (masked, non-secret)      [pure, tested]
                      └─ Slint matrix renders
                           └─ click cell → reveal_value() → momentary plaintext → auto-clear
```

The only mocked element is the fetch. Auth, the AWS SDK, real `Config` persistence, and the
write path are explicitly out.

## Goal / non-goals

**In scope**
- New `janitor-gui` crate (Slint), thin view only (ADR 0003).
- Matrix view of one Application across its Environments: row state (Aligned/Drift/Gap),
  masked length-dots, byte count, equality glyph, cosmetic hex token.
- Per-cell momentary reveal with auto-clear.
- Sidebar selecting among several seeded mock Applications.
- In-memory Settings (edit SSO fields + Applications/Mappings) and Preferences
  (auto-hide duration, default sort, light/dark theme).
- A synchronous `SecretSource` trait in core + a `MockSource` reference impl, unit-tested.
- Pure `project()` and `reveal_value()` helpers in core, unit-tested.

**Out of scope (deferred)**
- Real AWS / Identity Center auth; the AWS SDK adapter.
- Real `Config` disk persistence (settings are faked in-memory; `Config` gains no new fields).
- Async fetch + async↔Slint threading.
- The write / mutation path (ADR 0001).
- History / version restore (ADR 0006).
- Filters (All/Drift/Aligned/Gap) and prefix clustering — view sugar, later slice.
- Functional read-only lock, session timer, clipboard model (ADR 0005).
- Visual polish, theming beyond a light/dark toggle, accessibility.

## Build order (each step runnable before the next)

The slice is **one ordered thread**, not five co-equal regions. Budget goes to the spine;
the settings forms come last and shallow ("fake settings is fine").

0. **Slint-on-Windows smoke test.** A blank Slint window opens via `build.rs` + the `.slint`
   compiler on this toolchain. Proven *first* — it is the highest integration risk, and a
   tracer bullet exists to flush integration risk early.
1. **Matrix from one hardcoded mock Application.** `MockSource` → `SecretShape` per env →
   `Comparison::build` → `project()` → owned `MatrixView` → Slint rows. Renders row state
   color, masked length-dots, byte count, equality glyph, cosmetic hex.
2. **Reveal.** Click a cell → `reveal_value()` → momentary plaintext `SharedString` →
   auto-**clear** after the configured duration. One cell at a time.
3. **Sidebar.** List the seeded Applications from in-memory config; selecting one re-fetches
   (MockSource) and rebuilds the matrix.
4. **Settings.** Edit `sso_start_url` / `sso_region` and add/edit/remove `Application`s and
   their `Mapping`s — mutating in-memory state built from real `Config` types.
5. **Preferences.** In-memory `Preferences { auto_hide, sort, theme }` the view reads;
   editable in Settings. `auto_hide` is the reveal clear-timeout; `theme` is a light/dark
   toggle; `sort` selects the matrix row order — **name** (the engine's default) or
   **Gap-first** (high-signal rows on top) — applied when ordering `MatrixView` rows.

## The mock seam — `SecretSource`

A **synchronous** trait in `janitor-core`. It realizes the "AWS-client trait" already
anticipated in `lib.rs` ("core logic must depend on an AWS-client trait, with the concrete
AWS SDK adapter isolated").

```rust
pub trait SecretSource {
    fn fetch(&self, mapping: &Mapping) -> Result<SecretShape, FetchError>;
}
```

- **Sync is a conscious choice.** The mock returns canned data instantly; building
  async↔Slint threading for a mock is over-build. The real AWS SDK is async (tokio); a
  one-line doc note marks where the trait flips to async and that the change ripples through
  callers. A future ADR may formalize the seam when the AWS adapter lands.
- **`MockSource`** returns canned `SecretShape`s seeded to reproduce the mockup — Payments
  API → `database.*`, `GITHUB_APP_*`, `STRIPE_*` with a realistic Aligned/Drift/Gap mix —
  keyed by `Mapping.secret_id` (+ environment). A **deterministic fallback** generates a
  plausible shape for any unseeded `secret_id`, so every configured Application yields a
  matrix.
- **Location:** `janitor-core` — a testable reference impl of the real seam, not in `gui`.
  Keeps fake data out of the view and lets the seam be exercised by core's test suite.
  Clearly marked non-production.

## Core ↔ Slint adapter — the lifetime handling

`Comparison<'a>` **borrows** the fetched Sets (ADR 0009: "build it to render, don't store
it"); Slint models need **owned** data. Holding both the Sets and a `Comparison` that
borrows them in one app-state struct is **self-referential and rejected by the borrow
checker** — so we do not store a `Comparison` at all.

Flow per matrix render:

1. App state owns `sets: Vec<(String, SecretShape)>` for the selected Application (the result
   of fetching each `Mapping`).
2. Build a `Comparison` **transiently** borrowing `sets`.
3. `project(&Comparison) -> MatrixView` copies out an **owned, non-secret** DTO; the
   `Comparison` is then dropped.
4. The gui maps `MatrixView` → Slint structs/models.

```
MatrixView { environments: Vec<String>, rows: Vec<MatrixRow> }
MatrixRow  { key: RowKeyView, state: EntryState, cells: Vec<MatrixCell> }
MatrixCell { Present { len, group, hex } | Absent }   // no Value — masked only
```

**Reveal** is independent of `Comparison`. A pure helper indexes the still-owned Sets
directly:

```rust
fn reveal_value<'a>(
    sets: &'a [(String, SecretShape)],
    key: &RowKey,
    col: usize,
) -> Option<&'a Value>;
//   Json(map) → map.get(name) ;  Raw(v) → v ;  Binary → None (never revealable, ADR 0004)
```

`project()` and `reveal_value()` are **pure and unit-tested in core without Slint** — the
masking and classification stay in core; the gui stays thin (ADR 0003).

## Reveal discipline (security)

- Reveal **clears, not hides.** When the auto-hide timer fires (or the cell blurs/closes),
  the revealed `SharedString` is **overwritten out of the Slint model** — not merely made
  invisible. A visibility flag would leave plaintext lingering in widget state, violating
  ADR 0003's "reveal/edit buffers cleared on blur/close."
- **At most one cell revealed at a time.**
- Plaintext otherwise lives only in core's zeroizing buffers; the gui holds masked tokens.
  Revealed plaintext is the accepted transient exposure inherent to displaying a secret
  (ADR 0003), bounded by the clear-on-timeout window.

## Glyph & hex semantics

- Row dot color and the `=` / `≠` / `ø` column derive from `EntryState` and **row-local
  `GroupId` equality** — `=` when the compared cells share a `GroupId`, `≠` when groups
  differ, `ø` when a cell is `Absent`. There is **no hash** in the model.
- For the 2-Environment mock Applications the glyph compares column 0 vs column 1; the rule
  generalizes (per-cell vs a reference column) when N > 2.
- The `a17c` / `6b22` hex tokens are **cosmetic display flavor**, computed from a stable,
  non-secret hash of the Entry name + `GroupId` (**never** from the `Value`). This makes
  equal cells within a row share a token while different Entries differ — matching the
  mockup, where Aligned `GITHUB_APP_ID` shows `5c9d` in both columns. It is a *display*
  token: the equality mechanism is `GroupId` (the model has no hash), and this token is not
  a digest of any secret.

## Module layout

**`janitor-core`** (additions)
- `source` — `trait SecretSource`, `FetchError`.
- `mock` — `MockSource` + seeded fixtures + deterministic fallback.
- projection helpers (`compare::view` or a new `view` module) — `MatrixView` / `MatrixRow` /
  `MatrixCell`, `project()`, `reveal_value()`.

**`janitor-gui`** (new crate; joins the workspace `members`)
- `Cargo.toml` — depends on `janitor-core` + `slint`; `build.rs` compiles `.slint`.
  GPL-3.0-only (consistent with ADR 0003).
- `main.rs` — seed in-memory mock `Config`, build the Slint app, wire callbacks
  (select Application, reveal, edit settings/preferences).
- `ui/app.slint` — window, sidebar, matrix, settings + preferences forms (rough).
- adapter glue — `MatrixView` → Slint models; the reveal timer; the in-memory `Preferences`.

## Testing

- **Core (unit, no Slint):** `MockSource` produces the expected seeded shapes and a
  deterministic fallback; `project()` maps a `Comparison` to the correct `MatrixView`
  (states, lengths, group ids); `reveal_value()` returns plaintext for `Json` / `Raw` and
  `None` for `Binary` / `Absent` / out-of-range column. Keeps core's ≥80% gate reachable.
- **GUI:** thin Slint logic; at most a build/smoke check. Not coverage-gated (ADR 0003).
- **No regressions:** existing tests are untouched. `Config` gains no fields (preferences
  are in-memory), so its round-trip tests are unaffected; this slice only *adds* tests.

## Future seams (noted, not built)

- `SecretSource` flips to async when the real AWS adapter lands; callers thread it then.
- Settings gains real `Config::save` / `load` (the types are already used, so this is wiring,
  not a remodel) and possibly a real `preferences` field with `#[serde(default)]`.
- Filters + prefix clustering project over `MatrixView` (pure, testable) in a later slice.
