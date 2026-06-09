# Unify the AWS-family Providers behind one swappable resource method

**Status:** accepted (implemented — #78)

**Related:** [ADR 0026](0026-shared-discovery-orchestrator-in-core.md) (the
dual-layer Discovery `Orchestrator`/`Steps` split this generalizes from Discovery
to the whole resource tail — its Considered options names this unification as
"deferred, not rejected"), [ADR 0024](0024-shared-aws-auth-base-crate.md) (the
shared `janitor-aws-auth` base + `authwalk::front_half` the method composes with),
[ADR 0019](0019-provider-port-in-core-and-janitor-mock-crate.md) (the `Provider`
port being refactored under — `sign_in`/`load`/`reveal`/`begin_discovery`),
[ADR 0018](0018-stale-role-auto-recovery-on-load.md) (stale-role recovery, today
AWS-only, that this lifts into the shared shell), [ADR 0025](0025-remote-dotenv-over-ssm-provider.md)
/ [ADR 0029](0029-remote-dotenv-write-via-interactive-pty-data-channel-stream.md)
(the SSM read/write tail that becomes one method), [ADR 0001](0001-non-stomping-writes-via-staged-put-and-cas.md)
(the non-stomping write the method's `write` carries), [ADR 0004](0004-read-only-v1-scope-and-secret-shapes.md)
/ [ADR 0013](0013-guided-discovery-in-gui-step-machine-and-manage-window.md) (the
read-write-mode unlock + Manage window the GUI picker rides on),
[ADR 0016](0016-per-crate-coverage-badges-and-aws-gate.md) (per-crate ≥80% gate),
[THREAT-MODEL](../THREAT-MODEL.md), [#78](https://github.com/Circuit-Stitch/Janitor/issues/78)
(blocked by [#33](https://github.com/Circuit-Stitch/Janitor/issues/33), done).

## Context

[ADR 0026](0026-shared-discovery-orchestrator-in-core.md) split Discovery into a
provider-agnostic `core` `Orchestrator<S: Steps>` (all the walk *sequencing*) plus
a per-Provider `Steps` *method* (the divergent list/input sequence and the I/O
between), with the shared `account → role → mint` front half factored into
`janitor-aws-auth::authwalk::front_half`. It deliberately scoped #33 to **Discovery
only** and kept `janitor-aws::Session` and `janitor-ssm::SsmProvider` as two
parallel `Provider` impls. Its Considered options recorded the rest — "one AWS
Provider, swappable method, incl. per-Mapping method selection" — as **deferred,
not rejected**, because it also varies `load`/`reveal`/`write`, not just Discovery.
This ADR designs that unification. #78's gate (#33) is met.

**The duplication is now concrete, and it is large.** Comparing the two `Provider`
impls side by side, everything *except the per-Environment resource read* is the
same code:

- **State.** Both hold `reauth`, `role_client`, `catalog`, `clock`,
  `token: Option<Arc<SsoToken>>`, an in-progress `discovery`, and
  `cached: Vec<(String, SecretShape)>`. (`Session` adds `secrets_api` + the
  `AuthenticatedSource` facade; `SsmProvider` adds `instances`/`reader`/`logging`
  + advisory queues.)
- **`sign_in`.** Byte-for-byte the same idempotent shape: a fresh `SsoToken`, a
  `CredentialBroker`, then build a per-method "source" (`AuthenticatedSource` vs
  `SsmSource`).
- **`load`.** The same loop: ensure signed in, fetch every Environment, collect
  `Failure`s or `project(&Comparison::build(&sets))` + cache. They diverge only in
  the per-Environment call (`facade.fetch` vs `source.fetch`) and in two add-ons:
  `Session` runs stale-role recovery (ADR 0018); `SsmProvider` probes the
  session-logging advisory (ADR 0025).
- **`reveal`.** **Identical**: `reveal_value(&self.cached, key, col).map(|v| v.expose().to_string())`.
- **`begin_discovery`/`advance_discovery`/`provide_input`.** The same thin handle
  over an `Orchestrator<…Steps>`, sharing the session token and resetting on
  `Step::Reauth` (`SsmProvider` additionally drains a mid-walk advisory).

The genuine divergence is exactly one thing: **how a minted Credential turns a
`Mapping` into a `SecretShape`** — `GetSecretValue` + shape for Secrets Manager,
read-`.env`-over-MGS + parse for SSM — plus the Discovery *tail* that picks the
location (a Secrets Manager secret vs an Instance + `.env` path). That is the same
"only the tail varies" finding ADR 0026 made for Discovery, now seen across the
whole `Provider`.

Tellingly, `SsmSource`'s own doc comment already names the omission this repays:
it skips the at-most-once force-refresh + re-Sign-in ladder and stale-role recovery
because that resilience is "the kind of resilience #33/ADR 0026 will unify across
both Providers, not re-duplicate." Today the SSM Provider is *less* resilient than
the SM one by deliberate deferral; the unification closes that gap.

The high-value capability this unlocks is **per-Mapping method selection**: today a
Provider is chosen per session (the GUI `--ssm` flag), so a matrix is all–Secrets
Manager or all–SSM. With a method chosen per Mapping, one Application could compare
`prod` in Secrets Manager against `staging` as a remote `.env` in one masked matrix
— precisely the cross-store drift the tool exists to surface.

## Decision

Apply ADR 0026's dual-layer pattern to the entire resource tail: a generic
AWS-family **Provider shell** + a per-tail **`ResourceMethod`** seam.

1. **A generic `AwsFamilyProvider` in `janitor-aws-auth`** that implements
   `core::provider::Provider` and owns everything provider-agnostic: the
   `Arc<SsoToken>`, the idempotent `sign_in` (token → `CredentialBroker`), the
   per-Environment `load` loop + `project`/cache, `reveal` (the cache lookup), the
   Discovery handle (`Orchestrator<Box<dyn Steps>>`) + `reset_if_reauth` + advisory
   drain, and the future `write` dispatch. It speaks only
   `Mapping`/`SecretShape`/`Step`/`Failure`/`Credential` — no Secrets-Manager or
   SSM vocabulary. It lives in `aws-auth` (not `core`) for the same reason
   `front_half` does (ADR 0026 Decision 4): it brokers an AWS `Credential` and uses
   `AccountCatalog`/`RoleCredentialClient`; a non-AWS Provider would not share it.
   `janitor-mock` stays a standalone `core`-only `Provider` (the substitutability
   proof) — it is *not* an AWS-family method.

2. **The `ResourceMethod` trait is the "method" seam** (the `load`/`reveal`/`write`
   analogue of ADR 0026's `Steps`). Object-safe; lives in `aws-auth`. A method
   receives a *freshly-minted* `Credential` from the shell and supplies only the
   divergent tail:

   ```rust
   #[async_trait]
   pub trait ResourceMethod: Send + Sync {
       fn kind(&self) -> Method;                                   // the Mapping tag it backs
       async fn fetch(&self, cred: &Credential, m: &Mapping)       // read + shape one Set
           -> Result<SecretShape, MethodError>;
       async fn write(&self, cred: &Credential, m: &Mapping,       // (B5) non-stomping CAS write
           edits: &[EnvEdit]) -> Result<WriteOutcome, MethodError>;
       async fn advisory(&self, cred: &Credential, m: &Mapping)    // operator advisory probe
           -> Option<String> { None }                              // (SSM session logging; None default)
       fn discovery_steps(&self, env: String, region: String,      // the Discovery tail (a Steps method)
           token: Arc<SsoToken>, remembered: Option<Mapping>) -> Box<dyn Steps>;
   }
   ```

   `MethodError` generalizes today's `DotenvFetchError`: `Session(SessionError)`
   (the shell may run the recovery ladder on it) vs `Content { detail }` (the read
   succeeded but the payload is unusable — a malformed `.env`, a binary secret —
   masked to `Unsupported`, **not** subject to recovery, preserving the precise
   `"malformed .env line N"` detail). The method maps its own errors into it at the
   seam, exactly as `DotenvFetchError`/`SessionError` are masked today.

3. **The AWS-family resilience ladder moves into the shell** (repaying the SSM
   omission above). The shell owns the broker, the at-most-once force-refresh +
   re-Sign-in fetch ladder (today in `janitor-aws::AuthenticatedSource`), and
   stale-role recovery (ADR 0018): on `MethodError::Session(RoleNotEntitled)` it
   re-lists the account's roles via the shared `catalog`, and on the unambiguous
   single-different-role case rewrites `permission_set` and retries the method's
   `fetch` once. All of it operates on `Mapping` + `SessionError` + the shared
   `catalog`/`broker` — method-agnostic — so **both** methods get it. `fetch`
   itself stays the pure "given this `Credential`, read+shape" call.

4. **Per-Mapping method selection: the shell holds a registry, `load` dispatches
   per Mapping.** `AwsFamilyProvider` holds `methods: BTreeMap<Method, Box<dyn
   ResourceMethod>>`. `load` looks up `methods[m.method]` for each Environment,
   mints its `Credential` (one shell broker, one shared token), and calls that
   method's `fetch`. Because the cache is just `(env_name, SecretShape)` and
   `reveal` is method-agnostic, **a mixed-method matrix and its reveals fall out for
   free** — the headline capability needs no special case in `load`/`reveal`. The
   load-time `advisory` is probed once per *distinct* method present in the
   Application.

5. **Discovery dispatches on a method chosen *outside* the walk** (the per-row
   picker, Decision 7). The `Provider::begin_discovery` port gains a `method:
   Method` parameter; the shell calls `methods[method].discovery_steps(…)`, wraps
   the returned `Box<dyn Steps>` in an `Orchestrator`, drives it, and stamps the
   chosen `method` onto the `Done` Mapping. **No `What::Method` step is added to
   `core`** — the method is already known before the walk starts, so the `core`
   Discovery `Step`/`What` surface is untouched. The mid-walk advisory (ADR 0025)
   is generalized: `core::discovery::Steps` gains an optional
   `fn take_advisory(&mut self) -> Option<String> { None }` (mirroring
   `Provider::take_advisories`), so the shell drains it uniformly via
   `Orchestrator::steps_mut()` and AWS/mock simply return `None`.

6. **`Mapping` gains an explicit `method: Method` tag** (`core::config`), not an
   inference from `secret_id`'s shape. `Method` is a small closed enum
   (`SecretsManager` | `SsmDotenv`) with `Default = SecretsManager`; the field is
   `#[serde(default)]`, so every existing `config.toml` (no `method` key) loads as
   `SecretsManager` — exactly today's behavior. `secret_id` keeps overloading the
   ARN (SM) vs `<instance-id>:<path>` (SSM); the tag now *disambiguates the method*
   so nothing parses the string to guess the backend. `Method` lives in `core`
   (where `Mapping` serializes and the registry key must be provider-agnostic); it
   is method *identity*, the same granularity `What::{Secrets,Instances,FilePath}`
   already carries in `core::provider` — not the AWS auth vocabulary ADR 0019 keeps
   out of `core`.

7. **The GUI selects the method per Environment row in the Manage window.** The
   session-global `--ssm`/`JANITOR_SSM` switch is retired as a Provider toggle; the
   GUI always runs `AwsFamilyProvider` (real) or `MockProvider` (mock). Each
   Environment row in the Manage window carries a method dropdown
   (Secrets Manager / Remote `.env` over SSM), defaulting to `SecretsManager` (or
   the remembered last-pick's method). The chosen `Method` rides on
   `Command::BeginDiscovery` into `begin_discovery`, so the walk runs that method's
   tail directly. The composition root (`build_provider`) is the **only** place both
   tail crates are named together — it builds the registry
   `{ SecretsManager: janitor_aws::method(), SsmDotenv: janitor_ssm::method() }`,
   one entry per method, mirroring ADR 0019's "one match arm per Provider."

8. **Crate topology preserves the no-tail-depends-on-tail invariant.**
   `janitor-aws-auth` gains `ResourceMethod`, `AwsFamilyProvider`, `MethodError`,
   and the resilience ladder. `janitor-aws` provides `SecretsManagerMethod:
   ResourceMethod` (its `SecretsClient`/`SecretsApi` + the SM discovery tail);
   `janitor-ssm` provides `SsmDotenvMethod` (its reader/writer/instances/logging +
   the SSM discovery tail). **Neither tail depends on the other**; both depend only
   on `aws-auth`, which depends only on `core`. `janitor-aws::Session` and
   `janitor-ssm::SsmProvider` (the `Provider` impls) collapse into thin
   method-construction helpers, or are deleted in favor of the registry.

## Considered options

- **Keep two `Provider` impls; extract only a shared `AwsFamilyProviderCore`
  helper they each delegate to.** Rejected: it de-duplicates the boilerplate but
  leaves two top-level Providers, so a session is still one-method-only — it cannot
  satisfy the per-Mapping mixing criterion (one Application comparing SM against SSM
  in one matrix), which is the entire point of #78.

- **Infer the method from `secret_id`'s shape** (ARN vs `i-…:/path`). Rejected (and
  the user chose against it): fragile string heuristics, exactly the coupling #78
  flags; an explicit tag is total and future-proof.

- **An open `String` method tag** resolved against the registry. Rejected: loses
  exhaustive matching and type safety for a flexibility (out-of-tree methods) v1
  does not need; a closed enum is the right granularity now.

- **Put `AwsFamilyProvider`/`ResourceMethod` in `core`.** Rejected for the same
  reason ADR 0026 kept `front_half` out of `core`: the shell brokers an AWS
  `Credential` and uses `AccountCatalog`/`RoleCredentialClient`. The generic
  *Discovery* engine belongs in `core`; the AWS-family resource machinery belongs
  in `aws-auth`. Only the `Method` *tag* (provider-agnostic identity) enters `core`,
  alongside the existing `What`.

- **Make `AwsFamilyProvider<M: ResourceMethod>` monomorphic over one method.**
  Rejected: per-Mapping selection needs *several* methods live at once and dispatch
  per Environment, so the shell holds `Box<dyn ResourceMethod>` keyed by `Method`,
  not a single type parameter.

- **Add a leading `What::Method` Discovery step** (the alternative UX). Rejected in
  favor of the per-row Manage-window picker (Decision 7): choosing the method
  *before* the walk keeps `core`'s `Step`/`What` surface untouched and makes the
  method visible/editable on the Environment row independently of running Discovery.

## Consequences

- **#78's acceptance criteria are met by the design.** One AWS-family `Provider`
  drives a swappable method; SM and SSM are two `ResourceMethod`s, not two
  `Provider` impls; per-Mapping selection is structural (the registry + the cache's
  method-agnostic shape); `Config` records the method explicitly; the GUI surfaces
  it per row.

- **THREAT-MODEL holds.** Nothing new is persisted (`Method` is a tag, structurally
  not a Value). Plaintext still lives only in the shell's `cached` and crosses only
  on `reveal`/`write` (ADR 0003). No tail-depends-on-tail coupling is introduced
  (Decision 8). The masked-error boundary is unchanged — `MethodError` is the same
  masking `DotenvFetchError` already performs, generalized.

- **The SSM Provider gains resilience it currently lacks** (Decision 3): the
  force-refresh + re-Sign-in ladder and ADR 0018 stale-role recovery now apply to
  every method. This is a behavior change for `janitor-ssm` (a strict improvement),
  so it is **not** purely behavior-preserving — unlike ADR 0024's move, the
  unification deliberately extends SSM's behavior, and the slice that does it must
  add tests pinning recovery on the SSM method.

- **The `Provider` port changes shape once** (`begin_discovery` gains `method`),
  rippling to all three impls (`AwsFamilyProvider`, `MockProvider`, the GUI worker's
  `Command::BeginDiscovery`). `core::discovery::Steps` gains a defaulted
  `take_advisory`. These are additive and small.

- **Write is *designed in*, not delivered here.** `ResourceMethod::write` shapes the
  seam so the non-stomping CAS write fits (SSM's `SsmWriter::write` maps directly;
  the SM staged-put/CAS write of ADR 0001 is still unbuilt). The actual
  `Provider::write` port method, the worker `ApplyEdits` command, and the lockable
  read-write-mode unlock UX (ADR 0004/0013) remain the separately-tracked B5 work —
  v1 still ships read-only. This ADR ensures that work slots into the method seam
  rather than a third parallel write path.

- **Coverage holds** (≥80% per crate, ADR 0016). The shell + each `ResourceMethod`
  are pure logic, fully testable against the per-crate fakes that already exist
  (`FakeSecretsApi`, `FakeRemoteFileReader`, the `aws-auth` `wire::fakes`). The
  resilience-ladder tests currently in `janitor-aws::session` move into `aws-auth`
  with the ladder (as the `From`-impl tests did in ADR 0024), carrying their
  coverage; new tests pin the registry dispatch and the SSM method's recovery.

- **A third method/Provider stays cheap.** An AWS-family backend (e.g. SSM
  Parameter Store, or S3-object `.env`) is a new `ResourceMethod` + one registry
  entry; a non-AWS Provider (GitHub `org → repo → env`) is still a fresh `Provider`
  impl with its own `Steps` (ADR 0026), unaffected by this AWS-family shell.

- **Implementation is a sequence of vertical slices**, each independently
  reviewable and behavior-checked against the existing suites: (a) the `Method` tag
  + `#[serde(default)]` back-compat; (b) `ResourceMethod` + `AwsFamilyProvider` +
  the ladder in `aws-auth`, tested against fakes; (c) repoint `janitor-aws` to a
  `SecretsManagerMethod`, deleting `Session`; (d) repoint `janitor-ssm` to an
  `SsmDotenvMethod`, deleting `SsmProvider` and gaining recovery; (e) the registry
  in `build_provider` + the `begin_discovery(method)` port ripple; (f) the
  Manage-window per-row picker. (b)–(d) preserve each method's existing fetch/reveal
  behavior; (c)/(d)'s old Provider suites become the method suites.
