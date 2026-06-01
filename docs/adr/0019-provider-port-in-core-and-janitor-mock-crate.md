# Provider port in `core`, `janitor-mock` crate, and a single async path

**Status:** accepted

## Context

The GUI grew two unrelated execution models for the same job. The **real**
backend forwards UI `Command`s to a worker thread that drives a
`janitor_aws::Session` (lazy browser Sign-in, per-Application fetch, masked
matrix) and marshals `Event`s back ([ADR 0012](0012-gui-aws-bridge-worker-and-lazy-sign-in.md)).
The **mock** backend (`JANITOR_MOCK=1`) instead ran *synchronously on the UI
thread* and **reimplemented `Session`'s orchestration inline** in `main.rs`: it
fetched from `janitor_core::mock::MockSource` (the pre-`Session` sync
`SecretSource` seam), called `project` itself, fabricated a two-account org, and
hand-rolled a discovery state machine (`MockWalk`) duplicating
`janitor_aws::Discovery`. The result was ~200 lines of mock plumbing —
`seeded_config`, the `Backend::Mock` arm, the fabricated org, the `is_mock`
branch of `dispatch` — interleaved with the genuine UI wiring, so "what the UI
actually does" was buried. Meanwhile two parallel mock systems had drifted apart:
the orphaned sync `SecretSource`/`MockSource` in `core`, and the `#[cfg(test)]`
scripted `wire::fakes` in `aws` that the real path uses.

The project owner's framing reset the goal: isolate the `core`↔`aws` boundary
enough that a **`janitor-mock`** crate can be substituted for `janitor-aws`
wholesale, with an eye toward eventual non-AWS [Providers](../../CONTEXT.md)
(another cloud's secret store, or a Terraform / docker-compose file checked for
Entry presence). The mock should *be* such a Provider, not a special case the GUI
knows about.

## Decision

- **A `Provider` port in a new `janitor_core::provider` module** — the single
  boundary the GUI depends on. It is the high-level, `Session`-shaped surface
  (`sign_in` / `load` / `reveal` / `begin_discovery` / `advance_discovery`), not a
  low-level per-Mapping `fetch`. Rejected the low-level cut (basically reviving
  `SecretSource`): the AWS-specific machinery — browser Sign-in, account/role
  Discovery, stale-role recovery ([ADR 0018](0018-stale-role-auto-recovery-on-load.md))
  — has no clean home behind a `fetch` hole, and a file-based Provider (no auth,
  no discovery, no recovery) would have to satisfy assumptions it does not share.
  At the high level each Provider owns its whole pipeline and *calls* `core`
  (`Comparison::build`, `project`) for the generic parts; AWS keeps all of its
  account/role/SSO vocabulary **inside** its impl.

- **The cross-boundary DTOs move from `aws` into `core::provider` verbatim** —
  `Loaded`, `AppError`, `Failure`, `FetchFailReason`, `Step`, `What` — because
  they are already provider-agnostic in shape. `SessionError` (the per-fetch AWS
  taxonomy) **stays in `aws`**; it never crosses the port — `Failure` /
  `FetchFailReason` already mask it.

- **The port's Sign-in error is agnostic.** `SignInError`'s variants
  (`BrowserLaunch`, `NoLoopbackPort`, `StateMismatch`, `TokenEndpoint`…) are
  browser-OAuth-loopback *mechanism* vocabulary a file Provider would never
  produce. Nothing outside `aws` inspects those variants (the worker uses only the
  error-safe `Display` string, or maps any failure to "sign in again"), so the
  port exposes an opaque, error-safe `core` error and `janitor_aws::Session` maps
  its rich internal `SignInError` into it at the boundary — the same masking
  pattern it already uses for `SessionError → FetchFailReason`.

- **Retire the sync seam.** Delete `janitor_core::source` (`SecretSource`,
  `FetchError`) and `janitor_core::mock` (`MockSource`). They were a tracer-bullet
  abstraction the real path abandoned; `core::provider` is their replacement. The
  `SecretShape` model, `Comparison`, and `project` they fed **stay** in `core` —
  those are the genuinely reusable domain pieces every Provider calls.

- **A new `janitor-mock` crate**, peer to `janitor-aws`, implementing `Provider`.
  It depends on **`janitor-core` only — never `janitor-aws`**; that independence
  is the substitutability proof. All mock data lives here: the canned Payments
  shapes, the deterministic FNV fabrication, the seeded demo `Config`, and a
  trivial fabricated org for the Discovery picker — relocated unchanged from
  `core` and the GUI. Held to the same **≥80%** coverage gate as `core`/`aws`
  ([ADR 0016](0016-per-crate-coverage-badges-and-aws-gate.md)); it ships in the
  binary (it *is* offline mode), and the relocated `MockSource` tests transfer.

- **One async path in the GUI.** Delete the `Backend` enum and the entire
  `is_mock` branch of `dispatch` (which collapses to `tx.send(cmd)`). The worker
  always spawns; a `build_provider(kind, &Config) -> Box<dyn Provider>` builds the
  chosen adapter **inside the worker runtime** (AWS adapter construction is async,
  so it must happen there; the mock builds trivially), and `run_loop` drives
  `&mut dyn Provider` instead of a concrete `Session`. `main` only chooses `kind`
  from `JANITOR_MOCK`/`--mock` — the composition root's one job. The mock now runs
  on the worker thread under Tokio, exactly like AWS; its "opens already signed
  in" demo feel is preserved by `main` auto-sending `SignIn` at startup in mock
  mode (the mock's `sign_in` returns instantly). `core` gains an `async-trait`
  dependency for the object-safe async trait; it pulls in no runtime.

- **Hoist `select::{plan_selection, Selectable}` into `core`** — the pure 0/1/many
  + remembered-default resolver, already shared by AWS Discovery, role recovery,
  and `live-verify`. It is the one discovery primitive proven generic by existing
  use; its consumers are repointed to the `core` path.

## Considered options

- **Move mock data to `core` instead of a new crate** (the owner's first
  instinct, when the only choice was UI-vs-`core`). Rejected once a dedicated
  `janitor-mock` crate was on the table: `core` is the *real* domain (comparison
  engine, secret-shape model, Config); hand-seeded Payments JSON and a fake org
  are demo fixtures, not domain logic. A peer crate keeps the `aws`/`mock`
  symmetry and keeps non-production data out of `core`.

- **Keep the mock inline on the UI thread** by `block_on`-ing its ready futures.
  Rejected: it avoids one worker thread but reintroduces the second code path,
  which is the exact thing that made the UI illegible.

## Consequences

- The GUI depends on `janitor-aws` and `janitor-mock` **only at the composition
  root** (`build_provider`'s `match`); everywhere else it speaks `core::provider`.
  Adding a future Provider is a new crate + one match arm.

- **Security posture unchanged.** The port surface is masked DTOs; plaintext stays
  Provider-side in the worker; `reveal` remains the one explicit, on-demand
  plaintext crossing (ADR 0003 / THREAT-MODEL). The mock holds no real secret
  material.

- **Deferred — shared Discovery orchestrator (the owner wants this; it is *not*
  dropped).** `janitor-mock`'s Discovery is a trivial local stub for now; AWS's
  `account → role → mint credential → secret` walk stays in `aws`. A
  provider-agnostic orchestrator should be **extracted from ≥2 real Discovery
  shapes, not guessed from one** — extracting it today, against AWS as the only
  real example, would bake AWS's cadence and mid-walk credential mint into the
  "generic" seam, producing the coupling the abstraction is meant to avoid. The
  honest moment is when a second real Provider (e.g. GitHub's `org → repo → env →
  secret`) shows where Discovery actually varies. Tracked as a follow-up.

- Supersedes [ADR 0010](0010-aws-adapter-crate-and-auth-object-model.md)'s
  position that the sync `SecretSource` seam "stays untouched until the GUI
  integration slice" (it is now retired), and generalizes
  [ADR 0012](0012-gui-aws-bridge-worker-and-lazy-sign-in.md): the worker drives a
  `Provider`, of which `janitor_aws::Session` is the first implementation.
