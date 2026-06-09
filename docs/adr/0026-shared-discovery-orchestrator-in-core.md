# A shared, provider-agnostic Discovery orchestrator in `core`

**Status:** accepted (implemented)

**Related:** [ADR 0019](0019-provider-port-in-core-and-janitor-mock-crate.md)
(Provider port; deferred the shared Discovery orchestrator until a second *real*
Provider exists — this ADR repays that), [ADR 0024](0024-shared-aws-auth-base-crate.md)
(the shared `janitor-aws-auth` base; Decision 6 deliberately left the
`account → role → mint` walk sequencing duplicated as the input to #33),
[ADR 0025](0025-remote-dotenv-over-ssm-provider.md) (the second real Provider —
the `Input` step, the `Instances`/`FilePath` `What` labels, the mid-walk advisory),
[ADR 0013](0013-guided-discovery-in-gui-step-machine-and-manage-window.md) (the
presenter-agnostic `Step` step-machine being generalized), [ADR 0011](0011-guided-sign-in-and-discovery.md)
(`select::plan_selection` — the one Discovery primitive already in `core`),
[ADR 0016](0016-per-crate-coverage-badges-and-aws-gate.md) (per-crate ≥80% gate),
[#33](https://github.com/Circuit-Stitch/Janitor/issues/33).

## Context

With [ADR 0025](0025-remote-dotenv-over-ssm-provider.md) live-verified, Janitor has
**two real Discovery walks**: `janitor-aws::Discovery`
(`account → role → mint → secret`) and `janitor-ssm::SsmDiscovery`
(`account → role → mint → instance → .env path → read`). [ADR 0019](0019-provider-port-in-core-and-janitor-mock-crate.md)
and [ADR 0024](0024-shared-aws-auth-base-crate.md) deliberately left their
sequencing duplicated — extracting a "generic" engine from AWS alone would have
baked AWS's cadence and mid-walk credential mint into the seam. Now that a second
real shape exists to show where Discovery actually varies, #33's gate is met and the
orchestrator can be extracted **from evidence**.

Comparing the two `resume()` methods, the duplication was stark: the account block,
the role block, and the credential-mint block were **byte-for-byte identical**
(modulo SSM's post-mint logging probe), as were the `ask()`/`terminal_for()`/`pick()`
helpers. They diverged only at the *tail*. The two real shapes also surfaced two
axes of genuine variation: list-pick steps vs. a free-text `Input` step (the `.env`
path), and provider-specific `What` labels (`Secrets` vs. `Instances`/`FilePath`).

The naive "generic engine" is hard in Rust because each walk stored *heterogeneous
typed picks* (`Option<AccountSummary>`, `Option<RoleSummary>`, `Option<SecretSummary>`,
`Option<InstanceSummary>`) and a typed `Awaiting` enum to map a chosen index back to
the item. The unlock: **every Provider only ever needs each pick's
`Selectable::key` downstream** — `account.id`, `role.name`, `secret.arn`,
`instance.id` are each *exactly* the key, and the typed item's `label` is consumed
only into the `Ask`. Nothing typed survives the pick. So a generic engine can work
entirely in type-erased `Choice { key, label }` terms and hand back the chosen
**key** as a `String`; the heterogeneous picks and per-step `Awaiting` enums collapse
into one `chosen: Vec<String>`.

This is the **dual-layer interface** the seam actually wants (and is "option B" from
the [ADR 0019](0019-provider-port-in-core-and-janitor-mock-crate.md) grilling): a
provider-agnostic outer **orchestrator** driving an inner **method** trait, where an
AWS-family method composes a shared `account → role → mint` front half with its own
resource tail. The "method" is exactly what lets one Provider swap between resource
backends (Secrets Manager, SSM `.env`) behind one shared auth layer.

## Decision

1. **A provider-agnostic orchestrator in `janitor_core::discovery`.** A single
   `Orchestrator<S: Steps>` owns all the walk *sequencing* the two walks each
   re-implemented: auto-collapse singletons, stop at the first `Ask`/`Input`, resume
   on the user's pick, clamp out-of-range indices, and accumulate the chosen keys.
   `start`/`advance`/`provide_input` return the same `Step` as before. It reuses the
   pure `select::plan_selection` and knows **nothing** of accounts, roles, secrets,
   instances, or AWS.

2. **The `Steps` trait is the "method" seam.** `async fn next(&mut self, chosen: &[String]) -> StepPlan`
   is how a Provider supplies the divergent sequence. The orchestrator owns the
   pending/resume state, so a `Steps` impl keeps **no** pending state of its own — it
   inspects `chosen` to decide which stage it is at, does its own I/O and side effects
   (credential mint, advisory probe), and returns one `StepPlan` (`List` / `Input` /
   `Done` / `Terminal`). `next` is therefore re-entrant and must guard one-shot side
   effects on its own cached state (e.g. a minted credential).

3. **Type-erase to keys.** Lists cross as `Choice { key, label }` (projected from any
   `Selectable` via `Choice::project`); the orchestrator hands the chosen *key* back
   by appending it to `chosen`. The provider's typed summaries never leave its
   crate, and the per-provider `Awaiting` enums and `Option<Typed>` pick fields are
   deleted.

4. **The shared `account → role → mint` front half moves to `janitor-aws-auth`**
   (`authwalk::front_half`), repaying [ADR 0024](0024-shared-aws-auth-base-crate.md)
   Decision 6. It is expressed as the first stages of a `Steps` method: `chosen`
   empty → list accounts; one key → list the chosen account's roles; two keys → mint
   a Credential and return `FrontHalf::Ready`. Both AWS-family methods call it (gated
   on "not yet minted"); each then runs its own tail. `terminal_for` (the
   `SessionError → Step` masking) moves here too, deduplicated. It lives in
   `aws-auth`, **not `core`** — it needs `AccountCatalog`/`RoleCredentialClient`/
   `Credential`, and a future non-AWS Provider (GitHub's `org → repo → env`) would
   not have this front half.

5. **Provider crates and the `Provider` port are unchanged.** `janitor-aws` and
   `janitor-ssm` stay separate crates (janitor-ssm still never depends on
   janitor-aws); `Discovery`/`SsmDiscovery` keep their exact public
   `new`/`start`/`advance`/`provide_input`/`take_advisory` surface (now thin handles
   over `Orchestrator<…Steps>`), so the worker/presenter layers are untouched. The
   mid-walk advisory ([ADR 0025](0025-remote-dotenv-over-ssm-provider.md)) is the
   method's own state, drained via `Orchestrator::steps_mut()`; the engine never sees
   it.

## Considered options

- **A thin `Stepper` helper (per-step mechanics only), keeping each provider's
  `resume()` ladder.** Rejected: it shares the boilerplate but not the
  orchestration, so the sequencing stays duplicated — closer to a toolkit than the
  orchestrator #33 asks for, and it does not give the "method" interface that lets a
  Provider swap resource backends.

- **A continuation/coroutine engine** where each list step carries a boxed
  `FnOnce(index) -> next stage`. Rejected: nested boxed async closures fight Rust's
  borrow/`Send` rules and read far worse than the flat `next(chosen)` ladder, for no
  added capability.

- **Keep heterogeneous typed picks behind `Box<dyn Any>` in the engine.** Rejected:
  unnecessary once we saw downstream code only ever needs the key — type-erasing to
  `String` keys is simpler and total.

- **Extract the front half into `core` too.** Rejected: it is AWS-family-specific
  (it mints an AWS `Credential` via aws-auth seams). `core` stays free of AWS
  vocabulary ([ADR 0019](0019-provider-port-in-core-and-janitor-mock-crate.md)); the
  front half belongs in `aws-auth`.

- **Merge `janitor-aws` + `janitor-ssm` into one AWS Provider that swaps methods at
  runtime (incl. per-Mapping method selection).** Deferred, not rejected: the
  dual-layer design *enables* it, but it also varies `load`/`reveal`/`write`, not
  just Discovery — a larger follow-on beyond #33's scope.

## Consequences

- **#33's acceptance criteria are met.** A provider-agnostic orchestrator exists and
  both real Providers drive it; no AWS vocabulary leaks into the `core` engine
  (it speaks only `Choice`/`Step`/`What`); the deliberately-duplicated front half is
  repaid into `janitor-aws-auth`. Existing behavior is preserved — the two crates'
  full discovery + session test suites are the behavior-preservation guard and pass
  unchanged.

- **A third Provider is now cheap.** A non-AWS Provider (GitHub `org → repo → env`)
  implements `Steps` directly with its own front half; an AWS-family one reuses
  `front_half`. The `Input` rail and key-erasure already cover free-text and
  list-pick stages.

- **The `chosen: Vec<String>` convention is positional.** A method indexes
  `chosen[0]`/`chosen[1]`/… by stage; the cost of dropping named typed fields is
  that the stage order must match the `next` ladder. This is contained to each small
  `Steps` impl and documented there.

- **Coverage holds** (≥80% per crate, [ADR 0016](0016-per-crate-coverage-badges-and-aws-gate.md)):
  post-extraction line coverage is `core` 94.5% (new `discovery.rs` 93.1%),
  `janitor-aws-auth` 94.0% (`authwalk.rs` 96.1%), `janitor-aws` 96.8%
  (`discovery.rs` 97.3%), `janitor-ssm` 95.5% (`discovery.rs` 98.1%). The orchestrator
  is unit-tested against a scripted `Steps` fake; `front_half` against the front-half
  `wire::fakes`.

- **Still deferred:** the runtime "one AWS Provider, swappable method" unification
  (and per-Mapping method selection) above; and `core`'s `janitor-mock` Discovery
  stub could be re-expressed as a trivial `Steps` method, but is left as-is (it is a
  test double, not a real walk).
