# A shared `janitor-aws-auth` base crate for Identity Center auth + account/role + credential brokering

**Status:** accepted (not yet implemented)

**Related:** [ADR 0019](0019-provider-port-in-core-and-janitor-mock-crate.md)
(Provider port; AWS vocabulary stays out of `core`; deferred the shared Discovery
orchestrator until a second *real* Provider exists), [ADR 0010](0010-aws-adapter-crate-and-auth-object-model.md)
(the AWS adapter + auth object model being split here), [ADR 0013](0013-guided-discovery-in-gui-step-machine-and-manage-window.md)
(the `Discovery` step-machine), [ADR 0011](0011-guided-sign-in-and-discovery.md)
(`select::plan_selection`), [ADR 0016](0016-per-crate-coverage-badges-and-aws-gate.md)
(per-crate ≥80% gate), [#33](https://github.com/Circuit-Stitch/Janitor/issues/33).
Design detail:
[`docs/superpowers/specs/2026-06-06-second-provider-ssm-dotenv-and-shared-auth-base-design.md`](../superpowers/specs/2026-06-06-second-provider-ssm-dotenv-and-shared-auth-base-design.md).

## Context

The owner chose to satisfy #33's "a second *real* Provider must exist before
extracting the shared Discovery orchestrator" gate by **building** one: a remote
`.env`-over-SSM Provider ([ADR 0025](0025-remote-dotenv-over-ssm-provider.md)).
That Provider is AWS-family — it Signs in to Identity Center, picks an account,
picks a role, and **mints a role Credential** exactly like Secrets Manager does;
it diverges only at the *tail* (read a file off an EC2 instance over SSM instead
of `GetSecretValue`).

So the front half of `janitor-aws` — Sign-in (browser Auth Code + PKCE),
`AccountCatalog`, `RoleCredentialClient`, `CredentialBroker`, the zeroizing
`SsoToken`/`Credential` types, and the AWS error taxonomy — is shared by **two
real Providers**, while the `secrets.rs`/`SecretsApi`/`AuthenticatedSource`/
`Session` tail is Secrets-Manager-specific. Today all of it lives in one
`janitor-aws` crate; `janitor-ssm` would otherwise have to depend on
`janitor-aws` (a sibling depending on a sibling, dragging in Secrets-Manager code
it never uses) or duplicate the auth front half.

This also surfaces the real #33 seam early: it is **not** "AWS vs non-AWS." It is
a **shared `account → role → mint` front half + a provider-owned resource tail.**
Extracting that front half into its own crate is the first, largest, behavior-
preserving chunk of #33, done before the risky generalization.

## Decision

- **Create `janitor-aws-auth`** — a new crate, peer to `janitor-aws` /
  `janitor-ssm` / `janitor-mock`, depending on `janitor-core` only. It holds the
  shared AWS Identity Center access layer; both AWS-family Provider crates depend
  on it. The name is broader than "auth" (it also lists accounts/roles);
  `janitor-aws-identity` was the runner-up — `janitor-aws-auth` chosen for brevity.

- **Move into the base, verbatim with tests:** `pkce`, `state` (CSRF nonce),
  `types` (`SsoToken`, `Credential`, `Clock`, `SystemClock`), `broker`
  (`CredentialBroker`, `REFRESH_SKEW`), `error` (`SignInError`, `SessionError` —
  the generic AWS error taxonomy both tails produce), the shared `wire` seams
  (`RoleCredentialClient`, `AccountCatalog`; the `AccountSummary`/`RoleSummary`
  `Selectable` summaries; `RawSecret`; the `Reauth` trait, relocated from
  `source.rs`) **and `wire::fakes`** (so `broker`/`source` tests transfer
  unchanged), plus the untested Sign-in shell (`loopback`, `authenticator`).

- **Keep in `janitor-aws` (the Secrets Manager tail):** `secrets` (`SecretsClient`),
  the `SecretsApi` trait + `SecretSummary`, `source` (`AuthenticatedSource`'s
  at-most-once force-refresh + re-Sign-in fetch ladder), `session` (`Session`,
  the `Provider` impl), the SM `discovery` walk, `presenter`, and the `bin/*`. Its
  modules' `use crate::{broker,types,error,wire}` become `use janitor_aws_auth::…`.

- **This is a pure move + re-point refactor — no behavior change.** The relocated
  tests are the proof. Per the project rule, **no existing assertion changes**; if
  any covered behavior *would* change, stop and surface it before editing.

- **`janitor-aws-auth` holds the same ≥80% coverage gate** ([ADR 0016](0016-per-crate-coverage-badges-and-aws-gate.md),
  `--ignore-filename-regex 'src/bin/'`). The bulk of today's tested `janitor-aws`
  lines *are* the base, so the gate is met by the relocated tests; `janitor-aws`
  stays at/above its bar with the SM-tail tests that remain.

- **Do not extract the `account → role → mint` *walk sequencing* here.** The base
  exposes the auth **primitives** (Sign-in, `AccountCatalog`,
  `RoleCredentialClient`, `CredentialBroker`) and reuses `core`'s
  `select::plan_selection`. Each Provider's `Discovery` drives the front-half
  sequence itself; that duplication across two **real** shapes is the deliberate
  input to #33 ([ADR 0026, pending]) — extracting the walk now would be designing
  the #33 engine prematurely, which is exactly what we sequenced *after* the second
  Provider.

## Considered options

- **`janitor-ssm` depends on `janitor-aws`.** Rejected: a sibling depending on a
  sibling, pulling Secrets-Manager code (`secrets`, `Session`) into a crate that
  never uses it, and entrenching `janitor-aws` as a de-facto base we would untangle
  during #33 anyway.

- **Put the shared base in `janitor-core`.** Rejected: it carries AWS Identity
  Center vocabulary (accounts, roles, SSO token, `GetRoleCredentials`), and
  ADR 0019's spine is that such vocabulary stays *out* of `core`. The generic
  orchestrator (#33) goes *in* `core`; the AWS auth machinery does not.

- **A module inside `janitor-aws` that `janitor-ssm` reaches into.** Rejected:
  module-private boundaries do not survive a crate split, and Cargo cannot express
  "depend on only these modules." A crate is the unit of reuse.

- **Extract the front-half walk orchestrator now too.** Rejected: that is #33's
  job, to be done from two real walks, not anticipated from one-and-a-half. Keeping
  it out makes this a reviewable, behavior-preserving move.

## Consequences

- The workspace gains `janitor-aws-auth`; `Cargo.toml` `members` grows by one.
  `janitor-aws`, `janitor-ssm` (ADR 0025), and any future AWS-family Provider
  depend on it; `janitor-mock` stays `core`-only (its substitutability proof).

- **Security posture unchanged.** Nothing new is persisted; `SsoToken`/`Credential`
  stay zeroizing and memory-only; the Sign-in shell is unchanged, just relocated
  (ADR 0002 / 0010 / THREAT-MODEL).

- **Sets up #33.** With the auth primitives shared and two Providers each driving
  their own `account → role → mint → …` walk, the duplication that ADR 0026 will
  collapse into a `core` Discovery orchestrator is now concrete and visible.

- Generalizes [ADR 0010](0010-aws-adapter-crate-and-auth-object-model.md): its
  "one `janitor-aws` adapter crate" becomes a base auth crate + per-Provider tail
  crates; the auth object model (broker, facade ladder, stale-role recovery) is
  unchanged, only relocated.

## Implementation notes (2026-06-06, issue #61)

Three things the mechanical move *forced* that this ADR did not spell out, plus
one prediction that did not hold:

1. **The error→port masking `From` impls relocated to the base.**
   `impl From<&SessionError> for FetchFailReason` and `impl From<SignInError> for
   SignInFailed` lived in `session.rs`. Once `SessionError`/`SignInError` moved to
   `janitor-aws-auth`, the orphan rule forbade a tail crate (owning neither the
   `From` trait nor the `janitor_core::provider` target) from writing them, so
   both impls + their three tests moved into `janitor-aws-auth/src/error.rs`. This
   is *better* placement, not a workaround: both AWS-family tails produce these
   errors and mask them identically (the `session.rs` doc comment already said the
   impl "lives in `aws` because `SessionError` does").

2. **Cross-crate test fakes need a `test-support` feature, not `cfg(test)`.**
   `cfg(test)` does not propagate across a crate boundary, so the relocated
   `wire::fakes` (which the tail's `secrets`/`source`/`session`/`discovery`/
   `presenter` tests reuse) are gated `#[cfg(any(test, feature = "test-support"))]`
   and `janitor-aws` enables `test-support` as a **dev-dependency** only. Fakes are
   never compiled into a normal build.

3. **`RawSecret` zeroize-on-drop rippled into `secrets.rs`.** `#[derive(ZeroizeOnDrop)]`
   makes `RawSecret` a `Drop` type, so `SecretsClient::fetch` could no longer move
   its fields out by value; it now `.take()`s them, leaving the emptied buffer to
   wipe on drop (a strict improvement). No assertion changed.

4. **Coverage: the prediction "the gate is met by the relocated tests" did NOT
   hold.** The base lands at **76.3% lines** (the SM tail stays at ~97%). The
   entire shortfall is the ADR 0010 §5 "untested by design" SDK/browser shell
   (`authenticator`, `aws_impl` front-half, `loopback` — 157 lines); the base's
   *logic* is ~93% covered. The shell used to be diluted below the gate by the
   large well-tested Secrets-Manager tail (`session`/`discovery`/…); the split
   concentrated it. **Owner decision (2026-06-06): keep the 80% gate — do not
   weaken it or exclude the shell** ([ADR 0016](0016-per-crate-coverage-badges-and-aws-gate.md)
   stands; its "intended pressure" consequence is now realized). Issue #61 is
   therefore **blocked on a follow-up effort to cover the shared auth shell with
   live-AWS integration tests** (the long-term direction ADR 0016 already named);
   the `janitor-aws-auth` coverage CI step is wired at ≥80% and is RED until then.

   **Resolved by [ADR 0027](0027-covering-the-shared-auth-shell-with-replay-and-live-tests.md):**
   the shell is now covered in CI by replay-transport (`StaticReplayClient`) +
   local-socket tests, with an env-gated live-AWS suite confirming the canned
   shapes against a real org. The crate is at **~89% lines**, the CI step is
   GREEN, and #61's coverage blocker is closed.
