# Non-stomping writes via staged PutSecretValue + atomic stage CAS

**Status:** accepted; **Secrets Manager write v1 scoped 2026-06-25** (see
*Amendment 2026-06-25* — engine + live-verify against Deferno Staging; flat-JSON only,
write-time base, quota guard deferred; the GUI cell-edit affordance is a later phase).

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

## Amendment (2026-06-25): the v1 Secrets Manager write — scope, the base, and the deferred guard

The remote-`.env`-over-SSM writer (ADR 0029) already implements this ADR's *spirit*
(replay-on-fresh + a CAS) for a flat text file. The **Secrets Manager** write — the
mechanism this ADR was written for (staged `PutSecretValue` + `UpdateSecretVersionStage`
version CAS) — was deferred twice ([ADR 0032](0032-wire-write-seam-to-provider-port-and-read-write-lock.md)
Decision 8) as unverifiable without a live org. That blocker is gone: there is now a
live org to verify against (Deferno Staging). This amendment records the v1 scope and
the three places it deliberately narrows the original Decision. It does **not** change
the load-bearing invariant — step 4's atomic `UpdateSecretVersionStage` CAS is still
the only thing that moves `AWSCURRENT`, so Janitor structurally cannot stomp the Set.

1. **Phase scope: the engine + live-verify only; the GUI cell-edit affordance is a
   later phase.** This phase builds the `SecretsApi` wire-seam additions
   (`put_secret_value` with `ClientRequestToken` + `VersionStages`,
   `update_secret_version_stage`, and surfacing the read `VersionId`), the write
   *engine* (`write_secret`), wires it into `SecretsManagerMethod::write` (replacing the
   `Unsupported` stub), and adds a human-gated `live-verify-sm-write` binary that drives
   a standalone `SecretsManagerWriter` — **mirroring the SSM precedent exactly**
   (`SsmDotenvMethod::write` → `write_dotenv`; `live-verify-ssm-write` → `SsmWriter`,
   ADR 0029). The engine is reachable in v1 *only* through that binary: the GUI stays
   read-only by default and has no edit affordance, so the worker `ApplyEdits` rail
   (built in ADR 0032) is wired but unproduced. The in-matrix edit affordance +
   confirm-diff dialog + refresh-on-`WriteApplied` — including the confirm dialog's
   "add D / change B" split, which needs the current Set to tell add from change — are
   the **next** phase.

2. **Flat-JSON Sets only.** v1 writes a Set whose payload is a flat JSON object of
   `string → string` (the common app-config shape, and the Deferno Staging target). The
   merge is a plain `serde_json` object edit: parse `current`, replace/insert/remove the
   edited top-level keys, re-serialize; **untouched keys are preserved verbatim**,
   including any non-`string` scalar values (we never re-type a key we did not edit).
   A Set that is **not** a flat JSON object — nested JSON (ADR 0008 dotted-path Names),
   a bare non-JSON string, a JSON array, or `secret_binary` — is **not editable**: the
   write returns a masked `Unsupported` rather than guessing how to un-flatten. The
   un-flatten ambiguity (is a `.` in a key a nesting level or a literal dot?) is real
   and corruption-prone; the seam is ready to add nested writes later. Because the edit
   unit is already flat (`EnvEdit::Set`/`Remove`, keyed by a literal key, ADR 0032), no
   new edit type is needed.

3. **The CAS base is the write's own first read, not the matrix-load version.** The
   original Decision records `base` at *load* (step 1) and stops on any op whose Entry
   changed `base`→`current` (step 2). v1 narrows this: **`base` = the `GetSecretValue`
   that opens the write attempt.** Each attempt re-reads → merges our ops onto the fresh
   `current` (replay-on-fresh, so a teammate's untouched keys survive) → stages → runs
   the atomic CAS commit. On a CAS race (the commit fails because `AWSCURRENT` moved),
   we re-read and apply the **per-Entry conflict-stop**: if a key **we are editing**
   changed value since our last read → **stop** and surface `WriteOutcome::Conflict`
   (human re-review, never auto-merge — this ADR's promise); if only **other** keys
   changed → replay onto fresh and retry, bounded by `MAX_ATTEMPTS` (mirroring the SSM
   writer). The protection window is "from the moment the write starts," not "from when
   the matrix was loaded"; threading the load-time `VersionId` through
   load→GUI→worker→write was judged real plumbing for marginal gain (cells are masked
   anyway). This is the one place v1 is materially weaker than the literal Decision, and
   it is a conscious trade.

4. **The active version-quota guard is deferred.** The original Decision mandates an
   "enforced, not advisory" write-rate guard (`ListSecretVersionIds` + cadence tracking
   + warn/block near the 24h limit). v1 does **not** build it. The version-storm hazard
   it defends against is rapid `PutSecretValue`; v1 writes are deliberate human acts,
   each confirmed batch is one `ApplyEdits` → one `PutSecretValue`, and the
   contention-storm case is already bounded by `MAX_ATTEMPTS` + the **mandatory**
   pending-label cleanup (steps 5–6, which v1 *does* build). One of this ADR's two open
   live-API items — *"do label-stripped versions still count toward the 24h quota?"* —
   directly informs whether the guard is ever needed; the live run against Deferno
   Staging resolves it before we write a guard against a hazard that may not exist.

**Unchanged and still in force:** the staged-put + atomic version CAS (steps 3–4), the
fresh-`ClientRequestToken`-per-distinct-payload rule (v1 uses `uuid` v4), the mandatory
pending-label settle/cleanup (steps 5–6), the bounded retry cap, read-only-by-default
with a deliberate unlock, and the THREAT-MODEL constraints (the merged blob and every
Value are held zeroizing and reach only the writer; `ClientRequestToken`/`VersionId`
are non-secret opaque ids, OK to log; no Value, no SDK text in any `Failure`/`Event`/
log). The two **"verify against the live API"** items remain open and are resolved by
the live run, not stubbed away. Coverage holds via fakes + `StaticReplayClient` replay
tests ([ADR 0027](0027-covering-the-shared-auth-shell-with-replay-and-live-tests.md)),
with only the SDK socket untested-by-design.
