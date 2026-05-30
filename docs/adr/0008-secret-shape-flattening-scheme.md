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
