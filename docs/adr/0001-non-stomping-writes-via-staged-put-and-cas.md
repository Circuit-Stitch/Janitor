# Non-stomping writes via staged PutSecretValue + atomic stage CAS

**Status:** accepted

## Context

The reason Janitor exists is to make it *impossible* to accidentally overwrite an
entire AWS Secrets Manager Secret Set while changing only an Entry or two.
Secrets Manager has no per-Entry update — the value is one JSON blob, and
`PutSecretValue` replaces the whole thing as a new version. The naive
implementation (serialize what's on screen, `PutSecretValue`) loses any Entry
not in the in-memory view and silently clobbers concurrent edits by others
(last-write-wins).

## Decision

Janitor never writes the in-memory blob. It records the user's changes as
**Entry-level operations** (`add` / `update` / `remove`) and commits them with a
write sequence that is atomic against concurrent change:

1. **Load:** `GetSecretValue` and record the `AWSCURRENT` `VersionId` as `base`.
2. **Re-fetch on save:** `GetSecretValue` again → `current`. Replay the ops onto
   `current`, so Entries the user never touched (including ones a teammate added
   since `base`) are preserved. If an op targets an Entry that changed between
   `base` and `current`, **stop and surface the conflict** — never auto-merge.
3. **Stage:** `PutSecretValue(SecretString=merged, ClientRequestToken=<fresh
   uuid>, VersionStages=["janitor-pending-<uuid>"])`. Passing an explicit
   `VersionStages` means `AWSCURRENT` is **not** moved, so this step cannot affect
   what anyone else reads. The `ClientRequestToken` becomes the new `VersionId`.
4. **Atomic commit:** `UpdateSecretVersionStage(VersionStage=AWSCURRENT,
   MoveToVersionId=<new>, RemoveFromVersionId=<current>)`. AWS fails this call if
   `AWSCURRENT` is no longer on `current` ("the version ID does not match, then
   the operation fails"). On success → step 5. On failure → step 6 (cleanup),
   then re-fetch and retry from step 2.
5. **Settle:** remove the temporary `janitor-pending-<uuid>` label from the
   now-current version (`UpdateSecretVersionStage` with only `RemoveFromVersionId`)
   so committed versions don't accumulate stray labels.
6. **Cleanup on failure (mandatory, not optional):** the version staged in step 3
   is now orphaned (has the pending label, holds neither `AWSCURRENT` nor
   `AWSPREVIOUS`). Janitor must remove its `janitor-pending-*` label so AWS can
   deprecate/reclaim it. Leaving it is the failure this tool exists to prevent:
   under contention, uncleaned retries manufacture versions rapidly and blow the
   24h version quota.

**Token & retry rule.** Each retry that produces a *different* merged value MUST
use a **new** `ClientRequestToken` — AWS rejects a reused token paired with
different data. A retry whose re-merge is byte-identical may reuse the prior
token (idempotent no-op). Janitor caps retries and surfaces a hard error rather
than looping (each loop is a potential version + a quota cost).

Every destructive write is preceded by a confirm-diff preview ("will add D,
change B, remove nothing"). v1 is **surgical-only**: there is no "overwrite the
whole Set" action, and conflicts **stop for human re-review** rather than
offering an auto-merge UI.

**Read-only by default; deliberate unlock to write.** Janitor opens in a
read-only mode in which no mutating AWS call is reachable. Writing requires the
user to explicitly switch into read-write mode, and that mode can be **locked**
to prevent accidental modification. This makes the safe state the default state:
drift-detection and browsing never risk a write, and editing is always an act of
intent. The op-based engine above governs every write once in read-write mode.

**Write-rate / version-quota guard (enforced, not advisory).** Because AWS keeps
all versions from the last 24h and advises against `PutSecretValue` faster than
~once / 10 min sustained, Janitor tracks write cadence per Secret Set and
*enforces* a safe rate: it discourages rapid re-saves, batches a session's edits
into a single deliberate commit, and before committing may call
`ListSecretVersionIds` to see how many versions already exist in the last 24h and
warn (or block) when approaching limits. Saves are deliberate user actions that
Janitor may suggest, gate, or refuse — never automatic.

## Considered options

- **Re-fetch, compare `VersionId`, then `PutSecretValue` with default
  `AWSCURRENT`.** Rejected: a TOCTOU race remains between the check and the put,
  through which a concurrent write can still be stomped.
- **Offer a three-way auto-merge UI on conflict.** Deferred past v1: "certainty"
  argues against ever auto-resolving, and it is significant extra work.

## To verify against the live API before implementing

- **AWSPREVIOUS interaction.** Moving `AWSCURRENT` via `UpdateSecretVersionStage`
  (step 4) auto-moves `AWSPREVIOUS`. Confirm the settle/cleanup in steps 5–6
  strips only the `janitor-pending-*` label and never `AWSPREVIOUS`. Needs a
  scenario test.
- **Do label-stripped versions still count toward the 24h "keeps all versions"
  rule?** If a cleaned-up (label-less) version isn't reclaimed promptly, a
  contention storm still burns the version quota despite cleanup — which would
  make the retry cap load-bearing, not just defensive. Verify before relying on
  cleanup alone.

## Consequences

- The atomic-commit step (4) is the only thing that moves `AWSCURRENT`, and it is
  a true compare-and-swap, so Janitor structurally cannot overwrite an unexpected
  version.
- Each successful save creates a new version (free history → "compare to previous
  version" is a natural feature). But AWS keeps *all* versions from the last 24h
  and advises against `PutSecretValue` faster than ~once / 10 min sustained, so
  Janitor must not auto-save on every keystroke; saves are deliberate, batched
  user actions.
- Janitor may leave a temporary `janitor-pending-*` staging label on committed
  versions; it should clean these up (or accept the harmless clutter).
