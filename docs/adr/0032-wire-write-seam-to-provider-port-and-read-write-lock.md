# Wire the write seam to the Provider port, with the read-write-mode lock in the worker

**Status:** accepted (implemented — #80, backend + lock slice)

**Related:** [ADR 0031](0031-unify-aws-family-providers-behind-swappable-resource-method.md)
(the `ResourceMethod::write` seam this rides, and the `AwsFamilyProvider` shell that
dispatches it), [ADR 0029](0029-remote-dotenv-write-via-interactive-pty-data-channel-stream.md)
/ [#70](https://github.com/Circuit-Stitch/Janitor/issues/70) /
[#72](https://github.com/Circuit-Stitch/Janitor/issues/72) (the SSM write engine —
built + unit-tested), [ADR 0001](0001-non-stomping-writes-via-staged-put-and-cas.md)
(the non-stomping staged-put + replay-on-fresh CAS engine), [ADR 0004](0004-read-only-v1-scope-and-secret-shapes.md)
(read-only v1 + the read-write unlock), [ADR 0013](0013-guided-discovery-in-gui-step-machine-and-manage-window.md)
(the GUI step-machine + Manage window the edit affordance will ride on),
[ADR 0019](0019-provider-port-in-core-and-janitor-mock-crate.md) (the `Provider` port
this extends), [ADR 0003](0003-core-gui-split-slint-and-secret-display.md) (real logic
in tested crates, not the GUI shell), [ADR 0016](0016-per-crate-coverage-badges-and-aws-gate.md)
(per-crate ≥80% gate), [ADR 0017](0017-error-taxonomy-and-diagnostic-log.md) (the
masked Diagnostic Log), [THREAT-MODEL](../THREAT-MODEL.md),
[#80](https://github.com/Circuit-Stitch/Janitor/issues/80).

## Context

After [ADR 0031](0031-unify-aws-family-providers-behind-swappable-resource-method.md)
(#78) the `ResourceMethod::write` seam exists, and the SSM write **engine**
(`write_dotenv`/`SsmWriter`, ADR 0029, #70 → #72) is built and unit-tested. But the
write path was reachable only from the human-gated `live-verify-ssm-write` binary:
the GUI-facing boundary — the `Provider` port, the worker, and the read-only lock —
still had no write at all. ADR 0031's Consequences named exactly this as the
separately-tracked **B5** work: "the actual `Provider::write` port method, the worker
`ApplyEdits` command, and the lockable read-write-mode unlock UX … remain the
separately-tracked B5 work — v1 still ships read-only."

"Safe mutation" is the reason the tool exists ([ADR 0001](0001-non-stomping-writes-via-staged-put-and-cas.md))
— change a few Entries without ever stomping the whole Set. The seam is in place; this
wires it to the user, **without** giving up the spine invariant that v1 is read-only
by default and a mutating AWS call is unreachable until the user deliberately unlocks
([ADR 0004](0004-read-only-v1-scope-and-secret-shapes.md)).

The GUI today is a **read-only viewer**: a masked matrix + momentary per-cell reveal,
plus a Manage window for Environment discovery/rename/remove. There is **no
cell-edit affordance** — no way yet to enter a new Value for an Entry. So the full
"edit a cell → confirm the diff → write" flow is a sizable net-new build whose riskiest,
least-testable part (the Slint affordance + dialog) is distinct from the cleanly
testable backend. The project owner chose to scope #80 to **the backend + the lock**,
with the in-matrix edit affordance + confirm-diff dialog as the next slice.

## Decision

Wire the write seam through the `Provider` port and the worker, gated by a
worker-authoritative read-write lock. Build the backend end to end; defer the
in-matrix edit UI and the Secrets Manager write.

1. **`Provider::write` is the port's method-agnostic write** (`core::provider`):

   ```rust
   async fn write(&mut self, mapping: &Mapping, edits: &[EnvEdit])
       -> Result<WriteOutcome, Failure>;
   ```

   It takes the target `Mapping` (the same unit `fetch`/`load` already work with — it
   carries the `method` tag for dispatch and the GUI has it from Config) plus the
   surgical `edits`. The masked `WriteOutcome` distinguishes the CAS `Applied` from a
   `Conflict` (the remote Set changed under us — re-read and retry, never an error);
   any real failure is masked into the **existing** `Failure { environment, reason,
   detail }` the read side already uses (same `FetchFailReason` taxonomy, never a
   Value/Credential/SDK text). It is **defaulted** to a masked
   `FetchFailReason::Unsupported` `Failure` (mirroring `take_advisories`'s default),
   so a presence-only / read-only Provider degrades gracefully without overriding it.

2. **The write-seam types move to `core::write`.** `EnvEdit`, `WriteOutcome`, and
   `EnvWriteError` were in `janitor-aws-auth::write`, but the `core` port now speaks
   them and `core` cannot depend on any AWS crate, so they live in `core`.
   `janitor-aws-auth::write` **re-exports** them, so every AWS-family caller
   (`ResourceMethod::write`, `janitor-aws`, `janitor-ssm`) keeps its existing
   `janitor_aws_auth::write::…` paths — one set of types, nothing converted at the
   boundary. `core` gains a small `zeroize` dependency (a `Set` edit's new Value is
   held in a zeroize-on-drop buffer; it was already in the dependency tree via
   `secrecy` and the AWS-family crates).

3. **`AwsFamilyProvider::write` dispatches per Mapping through the same broker +
   ladder as `fetch`.** It ensures signed in, looks up `methods[mapping.method]`, mints
   a Credential via the shell broker, and runs a **write ladder** that mirrors the
   fetch ladder: force-refresh the Credential **once** on `AccessDenied` (a stale
   cached Credential AWS now rejects), and re-Sign-in **once** on `ReauthRequired` (a
   dead token), rebuilding the broker on the fresh token. It then masks the
   `MethodError` into a `Failure`. Because the method seam already carries `write`
   (ADR 0031), the SSM writer maps straight onto it and a future SM write fits the same
   shape.

   **Write does *not* run ADR 0018 stale-role recovery.** Recovery rewrites a
   Mapping's `permission_set` and persists the correction through `Loaded.corrected`
   on **load** — that is load-time Config state, and a write is not a load. A
   `RoleNotEntitled` on a write masks straight to `AccessDenied`; a write follows a
   successful load (which already auto-corrected the role), so this is the
   conservative, correct choice. The auth-resilience ladder (force-refresh +
   re-Sign-in) *does* apply, so a stale Credential or dead token still self-heals.

4. **`MockProvider::write` is an offline stub** that reports `Applied` without
   touching anything — enough for the offline demo to exercise the gate + the outcome
   relay end to end.

5. **The worker is the authoritative read-write lock.** The worker — the only side
   that holds the Provider and can issue a mutating AWS call — owns a `read_write:
   bool`, **off every launch** and never persisted. `Command::SetReadWrite(bool)` flips
   it; `Command::ApplyEdits { mapping, edits }` is **honored only when unlocked** and
   refused otherwise (`Event::WriteRefused`, **no** Provider/AWS call). Making the gate
   a worker invariant — not just a GUI affordance — is what makes "mutating calls are
   unreachable until unlocked" (ADR 0004) a *tested* property, with the GUI toggle as
   the deliberate-unlock control and a second layer of defence. Outcomes relay as
   `Event::{WriteApplied, WriteConflict, WriteFailed, ReadWriteModeChanged}`; the GUI
   surfaces each to the Diagnostic Log (ADR 0017) — the visible result surface for
   this slice. The edits never cross a log line; only the env name + a count.

6. **The GUI lock control is a Settings "Read-write mode" toggle** (a "Danger zone"),
   off by default, that sends `SetReadWrite` and is kept in sync by the worker's
   `ReadWriteModeChanged` ack. This is the deliberate switch ADR 0004 requires.

7. **A pure, tested confirm-diff seam lives in `core::write`.** `summarize_edits`
   reduces `&[EnvEdit]` to masked `EditSummary` lines — the non-secret key + the
   action + (for a `Set`) the new Value's **length only**, never its plaintext
   (exactly as the matrix masks a present cell as length-dots). Putting this masking
   in tested `core` (ADR 0003) means the eventual confirm dialog renders an
   already-masked list rather than an inline `.slint` predicate.

8. **Secrets Manager write is deferred and documented.** `SecretsManagerMethod::write`
   stays the masked `Unsupported` stub. The ADR 0001 staged-put + replay-on-fresh CAS
   write for Secrets Manager is still unbuilt and has open "verify against the live
   API" items, so building it without a live org would be unverifiable. It slots into
   the same `ResourceMethod::write` seam when built.

## Considered options

- **Put the lock in the GUI/`AppState` only.** Rejected: the GUI affordance can be
  bypassed by any stray `Command`, and "unreachable" should be a worker invariant, not
  a UI convention. The worker holds the Provider, so the gate belongs there; the GUI
  toggle is the user-facing control + a second layer.

- **Define a parallel `core` edit type and convert at the `ResourceMethod` boundary.**
  Rejected in favour of moving the types to `core` and re-exporting: one set of types,
  no per-call conversion, and the port + the method seam + the SSM engine all speak
  identical `EnvEdit`/`WriteOutcome`.

- **Run ADR 0018 stale-role recovery on writes too.** Rejected for this slice:
  recovery mutates + persists Config (`permission_set`), which is load-time state; a
  write follows a load that already corrected it. The auth-resilience ladder still
  applies, so a stale Credential/dead token self-heals — only the role *rewrite* is
  withheld.

- **Build the full edit→confirm→write GUI flow now.** Deferred (the owner's choice):
  there is no cell-edit affordance today, so the flow is mostly untested-by-design
  Slint/relay shell, distinct from the cleanly testable backend. Shipping the backend
  + lock first keeps this slice reviewable and behaviour-preserving (still read-only by
  default), with the affordance + dialog — the only producer of `Command::ApplyEdits`
  — as the next slice.

- **Build the Secrets Manager write here.** Deferred (see Decision 8): unverifiable
  without a live org; the seam is ready when it is built.

## Consequences

- **#80's backend + lock criteria are met.** `Provider::write` exists and
  `AwsFamilyProvider` dispatches per Mapping through the fetch ladder; `MockProvider`
  stubs it; the worker has `ApplyEdits` + the masked outcome events + the GUI relay;
  the lockable read-write gate makes mutating calls unreachable until unlocked. SM
  write is explicitly scoped out and documented (Decision 8).

- **THREAT-MODEL holds; v1 stays read-only by default.** The lock is off every launch
  and never persisted; a write while locked makes no AWS call. Edit Values are held
  zeroizing, reach only the Provider, and never touch a log line, an `Event`, the
  confirm summary, or `Debug` output. Outcomes are masked (`Failure`'s error-safe
  detail; env names + counts). No new persisted state (the lock and the mode are
  session-only). Plaintext still crosses only on `reveal`/`write` (ADR 0003).

- **The SSM method gains the write path through the port for free**, with the same
  auth-resilience ladder the read path has (Decision 3). No tail-depends-on-tail
  coupling is introduced (the types live in `core`, not in a sibling tail).

- **The port changes shape once** (`Provider::write`, defaulted), rippling to the two
  overriding impls (`AwsFamilyProvider`, `MockProvider`) and the worker. Additive and
  small; read-only Providers and worker test fakes inherit the graceful default.

- **Still pending (the next #80 slice):** the in-matrix cell-edit affordance + the
  confirm-diff dialog (the only producer of `Command::ApplyEdits`, which ships here as
  the enabling rail), a matrix refresh on `WriteApplied`, and live verification of the
  end-to-end GUI write against a real box. Separately pending: the Secrets Manager
  staged-put/CAS write (ADR 0001).

- **Coverage holds** (≥80% per crate, ADR 0016): core 93.6%, mock 98.9%, aws-auth
  90.0%, ssm 95.6%, aws 94.9% lines. The write ladder, the mock stub, the port
  default, the `summarize_edits` masking, and the worker gate/relay are all unit-tested
  against the existing fakes; the new Slint toggle is untested-by-design shell
  (ADR 0010 §5).
