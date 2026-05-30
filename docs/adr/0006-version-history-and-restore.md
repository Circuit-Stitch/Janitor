# Version history and restore as a first-class feature

**Status:** accepted

## Context

AWS Secrets Manager versions every write (`AWSPREVIOUS` + up to ~100 retained
versions). That is a built-in undo/audit trail Janitor gets for free. The
question was whether surfacing it makes the heavy ADR-0001 safe-write engine
redundant.

## Decision

**Surface version history, and keep the full ADR-0001 engine — they defend
different things.**

- **Version history / restore is recovery** *after* a bad write: browse prior
  versions of a Secret Set (via `ListSecretVersionIds` + `GetSecretValue` at a
  `VersionId`), diff a prior version against current, and **restore** it.
- **The ADR-0001 CAS engine is prevention** of the *silent concurrent clobber* —
  the case the user would never know to restore from, because they never saw the
  loss. Restore cannot recover a loss you don't notice, so the engine still earns
  its place.

**Restore is a write on the ADR-0001 rail.** Mechanically, restore moves
`AWSCURRENT` to an older `VersionId` via `UpdateSecretVersionStage` with
`RemoveFromVersionId=<current>` — the same atomic compare-and-swap, so it cannot
stomp a concurrent change either. (AWS keeps the value immutable per version, so
restore re-points the label rather than re-uploading; confirm whether restoring a
version aged out of the 24h/100 window requires a fresh `PutSecretValue` of its
recovered value instead.)

**Phasing.** v1: **view** version history (timestamps, who/which version is
current) for awareness — read-only. v2: **restore** and version-to-version diff
(writes), behind the read-only-by-default lock.

## Consequences

- Janitor presents AWS's versioning as a visible undo + lightweight audit view,
  not just an invisible backstop.
- Restore reuses the ADR-0001 commit path; no new write primitive.
- Diffing an old version against current pulls that old version's **plaintext**
  into memory — same masked-by-default / momentary-reveal rules apply.
