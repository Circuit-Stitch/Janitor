# Read-only v1 scope, and how non-flat secret shapes are handled

**Status:** accepted

## Context

Janitor's value is split between *reading* (drift detection across Environments)
and *writing* (safe, non-stomping edits). Writing is the high-risk half; the
safe-write engine (ADR 0001) is the hard part to get right. We also have to
decide what Janitor does with secrets that are not flat `string → string` JSON,
since real AWS secrets include nested JSON, raw strings, and `SecretBinary`.

## Decision

**Phased scope.**

- **v1 is read-only.** Ships the drift-detection viewer: Aligned / Drift / Gap
  comparison across N Environments, masked matrix (presence, length, hash-group),
  sort and filter by Entry name (incl. prefix clusters like `GITHUB_APP_*`),
  per-cell reveal, both saved Applications and ad-hoc compares, and **viewing**
  version history (ADR 0006). **No mutating AWS call is reachable.** The ADR-0001
  write engine is built and unit-tested but wired to no UI action.
- **v2 enables writes**, all behind the read-only-by-default lock and routed
  through the ADR-0001 safe engine: edit / add / delete Entry, copy an Entry
  across Environments (the drift payoff — fill a Gap from another Environment),
  and **restore** a prior version (ADR 0006).
- **Out of scope (both versions): creating or deleting an entire Secret Set**
  (`CreateSecret` / `DeleteSecret`). Janitor's thesis is surgical safety within
  existing Sets, not Set lifecycle management.

**Secret shapes.**

- **Flat `string → string` JSON** — the native case; full compare and (v2) edit.
- **Nested JSON** — flattened to **dotted-path Entry names** (`database.primary.url`
  is one Entry). The matrix stays 2-dimensional; nesting is only naming. Leaves
  compare and (v2) edit like any Entry.
- **Raw (non-JSON) string** — the whole value is treated as a single Entry.
- **`SecretBinary`** — compared by length/hash only, **never rendered**. v1: read
  only. v2: may be **replaced whole, from a file**, through the ADR-0001 engine
  ("replace entire binary value", explicitly not an Entry edit). The non-stomping
  per-Entry guarantee does not apply — a binary blob has no Entries to protect.

## Consequences

- v1 carries no write risk and can ship while the safe-write engine earns trust
  through tests; turning on v2 writes is a deliberate later step.
- Dotted-path flattening keeps one comparison/diff engine for flat and nested
  alike; the round-trip (flatten on read, un-flatten on write in v2) must be
  lossless, which constrains the flattening scheme (e.g. handling literal dots in
  keys).
