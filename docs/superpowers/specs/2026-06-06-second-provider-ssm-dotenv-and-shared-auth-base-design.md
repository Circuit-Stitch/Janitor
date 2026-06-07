# A second real Provider (remote `.env` over SSM) + a shared AWS-auth base, en route to the shared Discovery orchestrator (#33)

**Status:** design — under review (not yet ratified; ADRs 0024/0025 to follow)

**Related:** [#33](https://github.com/Circuit-Stitch/Janitor/issues/33) (the shared
Discovery orchestrator this unblocks), ADR 0019 (Provider port + `janitor-mock`;
deferred the orchestrator until a *second real* Provider exists), ADR 0013 (the
`Discovery` step-machine + `Step` enum), ADR 0011 (`select::plan_selection` /
guided sign-in), ADR 0010 (the AWS adapter crate + auth object model + the §5
"SDK/browser shell is untested by design" rule), ADR 0012 (the GUI worker
bridge), ADR 0018 (stale-role recovery), ADR 0002 (memory-only auth), ADR 0003
(core holds the logic; GUI is a thin view), ADR 0004 (read-only v1),
ADR 0008 (secret-shape flattening), [THREAT-MODEL.md](../../THREAT-MODEL.md),
[CONTEXT.md](../../../CONTEXT.md).

**Audience:** the next implementer. Assumes the ADRs above are read, plus
`janitor-aws/src/{discovery,session,source,broker,wire}.rs` and
`janitor-core/src/{provider,select}.rs`.

## Why this exists

#33 wants the "stepwise picker" engine (auto-collapse singletons, stop at the
first `Ask`, resume on advance, `select::plan_selection` for 0/1/many +
remembered default) extracted into `core` so every Provider drives **one** shared
machine. ADR 0019 deferred it on a single, honest argument: there is exactly
**one real Discovery shape** today — AWS Secrets Manager's `account → role → mint
credential → secret`. `janitor-mock`'s walk is a fake. Extracting a "generic"
engine against one real example bakes that example's cadence into the seam — the
exact coupling the abstraction is meant to remove.

The project owner's call (2026-06-06): **build a second *real* Provider first**,
then extract. The chosen second shape is **a `.env` file living on a remote EC2
instance's filesystem, read over AWS Systems Manager (SSM) Session Manager.** This
spec is the design for that build, and for the **shared AWS-auth base** the owner
chose to extract up front (the first and largest chunk of #33's eventual work).

### Why this second shape is the *right* evidence for the seam

A remote-`.env`-over-SSM Provider shares AWS's **entire front half** — Identity
Center Sign-in → pick account → pick role → mint credential — and **diverges only
at the tail**: instead of `list_secrets → GetSecretValue`, it is `list
SSM-managed instances → pick instance → choose .env path → read the file over a
Session Manager session → parse `KEY=VALUE``. That contrast is sharper than
GitHub or Azure would have been, because it isolates the variable from the shared:

1. **The mid-walk credential mint is *shared*, not Secrets-Manager-specific.**
   ADR 0019 worried the orchestrator would "bake AWS's mid-walk credential mint
   in." Two AWS-family Providers both mint mid-walk, so the seam is not "AWS vs
   not-AWS" — it is **shared `account → role → mint` stages + a pluggable
   resource-selection tail.** That is a much cleaner thing to extract, and the
   shared-auth-base extraction below *is* that front half made reusable.

2. **Discovery is not always "pick one of N."** The `.env path` step is
   **free-text entry**, not a list pick. Today `Step::Ask { choices, default }`
   only models a list. The second Provider forces the orchestrator's step model
   to grow an **`Input`** shape — a variation we could only have guessed at from
   AWS alone. (See §"What the second Provider teaches the #33 seam.")

3. **`What { Accounts, Roles, Secrets }` is AWS vocabulary in `core`.** The SSM
   tail needs `Instances` and a file-path notion, exposing that `What` is a leak
   #33's acceptance criteria explicitly forbid. The second Provider makes the leak
   concrete instead of theoretical.

## Scope

**In (this spec, built in two ADR-tracked phases).**

- **Phase A — extract a shared AWS-auth base crate** (`janitor-aws-auth`,
  name TBD — see Decision 1): Identity Center Sign-in, the account/role catalog,
  the credential broker, the zeroizing `SsoToken`/`Credential` types, the shared
  AWS error taxonomy, and the shared `wire` seams + fakes. `janitor-aws` (Secrets
  Manager) is repointed onto it and stays green. **No behavior change** — this is
  a move + re-export refactor proven by the existing tests.
- **Phase B — a new `janitor-ssm` Provider crate**: the real second Provider.
  Discovery tail `instance → .env path`; read over Session Manager
  (`StartSession`, transport spiked then chosen — Decision 3); a pure tested
  `.env → SecretShape` parser; a human-gated `live-verify-ssm` binary
  (Milestone B). Read-only (ADR 0004).

**Out (deferred).**

- **The #33 orchestrator extraction itself.** Phases A+B deliberately leave the
  `account → role → mint` *walk sequencing* duplicated between
  `janitor-aws::Discovery` and `janitor-ssm::Discovery` (Decision 6). That
  duplication, across two *real* shapes, is the evidence #33 then extracts into a
  `core` engine. A separate ADR 0026 + spec covers it once Phases A+B land.
- **Any mutation** — read-only v1 (ADR 0004). Writing a `.env` back over SSM (a
  non-stomping remote-file write, ADR 0001) is a future, separate effort.
- **`.env` candidate-path *discovery*** (running a bounded `find` on the box to
  offer a list of `.env` files). v1 takes the path as free-text input with a
  remembered default (Decision 5).
- **Non-EC2 SSM targets** (on-prem hybrid-activation managed instances). The walk
  lists whatever `DescribeInstanceInformation` returns; we do not special-case
  non-EC2, but we verify against EC2 only in Milestone B.

## Decisions

### 1. A shared AWS-auth base **crate**, not a `core` module

The shared front half (Sign-in + account/role + mint) is **AWS Identity Center
vocabulary**. ADR 0019's spine is that AWS vocabulary stays *out* of `core`; the
generic orchestrator (#33) goes *in* `core` knowing nothing of accounts/roles.
Therefore the shared base is a new crate, peer to `janitor-aws`/`janitor-mock`,
that both AWS-family Providers depend on:

```
janitor-core         (domain: SecretShape, Comparison, project, Provider port,
                       select::plan_selection, the Step/What/Discovery model)
   ▲        ▲
   │        │
janitor-aws-auth     (AWS Identity Center: Sign-in, AccountCatalog,
   ▲        ▲         RoleCredentialClient, CredentialBroker, SsoToken,
   │        │         Credential, Clock, SignInError, SessionError, wire+fakes)
   │        │
janitor-aws        janitor-ssm
(Secrets Mgr tail) (remote .env / SSM tail)     janitor-mock (core only)
   ▲        ▲        ▲
   └────────┴────────┘
        janitor-gui  (composition root: build_provider match arm per Provider)
```

**Proposed name: `janitor-aws-auth`.** It is slightly broader than "auth" (it
also lists accounts/roles), so `janitor-aws-identity` is the runner-up. Owner's
call (Decision flagged for confirmation).

**What moves out of `janitor-aws` into the base (verbatim, tests included):**

| Module | Contents | Why shared |
|---|---|---|
| `pkce.rs` | PKCE verifier/challenge | Sign-in mechanism |
| `state.rs` | CSRF `state` nonce | Sign-in mechanism |
| `types.rs` | `SsoToken`, `Credential`, `Clock`, `SystemClock` | Both tails mint+use creds |
| `broker.rs` | `CredentialBroker` (+ `REFRESH_SKEW`) | Both tails mint per-Mapping creds |
| `error.rs` | `SignInError`, `SessionError` | Generic AWS error taxonomy both produce |
| `wire.rs` (part) | `RoleCredentialClient`, `AccountCatalog` traits; `AccountSummary`, `RoleSummary` (`Selectable`); `RawSecret`; the `Reauth` trait (today in `source.rs`); `fakes` | Front-half seams + shared fakes |
| `loopback.rs`, `authenticator.rs` | browser/loopback Sign-in shell | Untested shell (ADR 0010 §5), still shared |

**What stays in `janitor-aws` (the Secrets Manager tail):**

| Module | Contents |
|---|---|
| `secrets.rs` | `SecretsClient` (`GetSecretValue` → `SecretShape`) |
| `wire.rs` (part) | `SecretsApi` trait + `SecretSummary` |
| `source.rs` | `AuthenticatedSource` (the at-most-once force-refresh + re-Sign-in fetch ladder) — composes base `CredentialBroker` + local `SecretsClient` |
| `session.rs` | `Session` (`Provider` impl for SM) |
| `discovery.rs` | the SM `account → role → mint → secret` walk |
| `presenter.rs`, `bin/*` | stdin presenter + `live-verify` / `loopback-spike` |

The split is mechanical: `janitor-aws`'s modules already `use crate::{broker,
types, error, wire}`; those `use` paths become `use janitor_aws_auth::…`. The
`wire::fakes` move with the traits they fake, so `broker`/`source` tests transfer
unchanged. Coverage: `janitor-aws-auth` holds to the same **≥80%** gate (ADR
0016); the bulk of today's tested `janitor-aws` lines *are* the base, so the gate
is met by the relocated tests.

### 2. `janitor-ssm` Discovery tail: `instance → .env path`

After the shared `account → role → mint credential` front half, the SSM Provider
walks:

- **`instance`** — `DescribeInstanceInformation` (SSM) lists managed instances the
  minted credential can reach in the region. New summary `InstanceSummary { id,
  name }` (`name` from the `Name` tag or `ComputerName`, falling back to `id`),
  `Selectable` by `id`. Auto-collapse/Ask/Empty via `select::plan_selection`,
  exactly like accounts/roles.
- **`.env path`** — **free-text input**, not a list pick (Decision 5). Yields the
  absolute path to read (default `/app/.env`, or the remembered path for this
  Environment).
- **read + parse** — read the file over Session Manager (Decision 3), parse to
  `SecretShape` (Decision 4). On success the walk is `Done(Mapping)`; the read
  itself happens here so a path that cannot be read fails *in the wizard*
  (masked), not later at load.

The resulting `Mapping` reuses the existing fields without schema change:
`account_id`, `region`, `permission_set` from the front half; `secret_id` carries
**`<instance-id>:<path>`** (the SSM Provider's "where the Set lives"); `environment`
from the wizard. (`Mapping`'s field *names* lean AWS — `account_id`,
`permission_set` — which #33/ADR 0026 may generalize; for Phases A+B we reuse them
as-is and document the SSM interpretation. Flagged for confirmation.)

### 3. Read over **Session Manager `StartSession`**; transport **spiked, then chosen in ADR 0025**

The owner chose Session Manager streaming over `SendCommand` for the disk
invariant (see §"Security"). There is **no Rust crate that speaks the Session
Manager data-channel (MGS) WebSocket protocol** — the SDK's `start_session` only
returns `StreamUrl` + `TokenValue` + `SessionId`; the protocol the open-source
`session-manager-plugin` implements is ours to drive. Two transports, **spiked
against a real box, then committed in ADR 0025**:

- **(a) Shell out to `session-manager-plugin`** with the **`AWS-StartNonInteractiveCommand`**
  session document (runs `cat <path>`, streams stdout, ends the session — no
  interactive PTY, no `SendCommand` S3 archival). Pragmatic; lands wholly in the
  untested SDK/shell layer (ADR 0010 §5). Cost: a runtime dependency on the plugin
  binary being installed (packaging impact, ADR 0022).
- **(b) Implement the MGS protocol in Rust** over the `StreamUrl`/`TokenValue`
  WebSocket. Pure-Rust, no external binary; the data-channel handling is fakeable
  and testable. Cost: most build effort, highest correctness risk.

Either way the **wire seam is the same** and is the unit under test:

```rust
#[async_trait]
pub trait RemoteFileReader: Send + Sync {
    /// Read a file's bytes from `instance_id` over SSM, using `cred` in `region`.
    /// Returns RawSecret (zeroizing) on success; SessionError on failure.
    async fn read_file(
        &self, cred: &Credential, instance_id: &str, region: &str, path: &str,
    ) -> Result<RawSecret, SessionError>;
}
```

The orchestration, parsing, and error mapping are tested against a
`FakeRemoteFileReader`; only the concrete (a) or (b) impl is the untested shell.

### 4. `.env → SecretShape`: a pure, tested parser in `janitor-ssm`

A `.env` is a flat `KEY=VALUE` text file — it maps onto the *same* flat
representation a flat JSON Secret Set produces, so it slots into the existing
`SecretShape`/comparison model with **zero** change to `core`. A new pure
`parse_dotenv(raw: &str) -> Result<SecretShape, SessionError::Unsupported>` (in
`janitor-ssm`, reusing `core`'s shape/flatten) handles:

- `# comment` lines and blank lines → ignored.
- optional leading `export ` → stripped.
- `KEY=VALUE`; `KEY="..."` / `KEY='...'` → quotes stripped, single-quote literal,
  double-quote allows `\n`/`\"` unescaping (standard dotenv rules — pin the exact
  rules in the ADR/tests).
- trailing inline `# comment` after an unquoted value → trimmed; inside quotes →
  literal.
- duplicate keys → last wins (document); malformed line (no `=`) → `Unsupported`.

The Value goes straight into the zeroizing `Value` type; the raw file bytes live
in `RawSecret` and are dropped/zeroized after parse. Each Entry is one `KEY` →
`Value`; comparison/Aligned/Drift/Gap then works identically to a JSON Set.

### 5. The `.env path` step is **free-text `Input`**, generalizing the Step model

The path is not selected from a list, so it does not fit `Step::Ask`. v1 takes it
as free-text with a remembered default. This requires a **new step shape**, added
additively to `core::provider`:

```rust
pub enum Step {
    Ask   { what: What, choices: Vec<String>, default: Option<usize> },
    Input { what: What, prompt: String, default: Option<String> }, // NEW
    Done(Mapping),
    Empty(What),
    Failed(FetchFailReason),
    Reauth,
}
```

and a matching GUI relay: a `Command::ProvideInput(String)` (alongside
`AdvanceDiscovery { choice }`), an `Event::DiscoveryInput { what, prompt, default }`,
and a text-field presenter in the Manage window (instead of a list). The stdin
presenter (`presenter::drive_discovery`) gains an `Input` arm that reads a line.
`What` grows `Instances` (and a `FilePath` label for the Input prompt). This is
the smallest honest generalization; **candidate-path discovery** (a bounded remote
`find` to make path a list pick, keeping the Ask-only model) is the considered
alternative — rejected for v1 as an extra remote-exec round-trip for little gain,
noted as a future enhancement. (Flagged for confirmation: add `Input` now vs.
discover candidates.)

> **Note for #33:** adding `Input` and `Instances` to `core::provider` *now*
> (Phase B, before the orchestrator extraction) is deliberate — it is the second
> Provider doing exactly its job: showing where the shared step model must flex.
> ADR 0026 then decides whether `What` becomes a provider-supplied label (killing
> the AWS-vocabulary leak) and whether `Input`/`Ask` unify.

### 6. Leave the `account → role → mint` walk **duplicated** between the two Providers — on purpose

Phase A extracts the auth *primitives* (Sign-in, `AccountCatalog`,
`RoleCredentialClient`, `CredentialBroker`, `select::plan_selection`). It does
**not** extract the *walk sequencing* — `janitor-aws::Discovery` and the new
`janitor-ssm::Discovery` will each drive `account → role → mint` themselves before
their own tails. That duplication is intentional, time-boxed, and is the literal
input #33 consumes: "extract from ≥2 *real* shapes, not guessed from one"
(ADR 0019). Designing a `janitor-aws-auth` "front-half mini-orchestrator" now
would be designing the #33 engine prematurely — the thing we are explicitly
sequencing *after* the second Provider. The duplication is tracked by #33 and
repaid by ADR 0026. (Considered: extract the orchestrator *during* Phase B to
avoid ever duplicating — rejected; it collapses "second Provider first" back into
"guess the engine from ~1.5 shapes" and makes Phase B reviewable only as a giant
change.)

### 7. `Provider` trait additions are **additive**; the GUI worker grows two arms

`begin_discovery`/`advance_discovery` stay; `provide_input(&mut self, text:
String) -> Option<Step>` is added for the `Input` step. The worker's `run_loop`
gains a `Command::ProvideInput` arm mirroring `AdvanceDiscovery`. `janitor-mock`
and `janitor-aws` implement `provide_input` as `None`/unreachable (they emit no
`Input` step). `build_provider` gains a `ProviderKind::SsmDotenv` arm. No existing
Provider behavior changes (per the project rule: if an existing test would change,
stop and surface it).

## What the second Provider teaches the #33 seam (the payoff)

Recorded here so ADR 0026 inherits concrete evidence rather than a guess:

1. **Seam line:** shared `[sign_in, account, role, mint]` front half + a
   provider-owned tail. Not "AWS vs not."
2. **Step model must include `Input`** (free-text), not just `Ask` (list). Likely
   future variations a third Provider would add: confirmation steps, multi-select.
3. **`What` must be provider-supplied**, not a fixed `Accounts|Roles|Secrets`
   enum — that is the AWS-vocabulary leak #33 forbids.
4. **A `Stage` abstraction** suggests itself: `produce candidates | request input
   → on selection, optional side-effect (e.g. mint) → next stage`, with the engine
   owning auto-collapse/stop-at-Ask/resume and `plan_selection`. Two real stage
   lists (`[acct, role(+mint), secret]` and `[acct, role(+mint), instance, path,
   read]`) now exist to validate that shape.
5. **`Mapping` field names** (`account_id`, `permission_set`) are AWS-leaning; a
   provider-agnostic `location` shape may be warranted — deferred, flagged.

## Architecture (Phase B data flow)

```
[GUI worker thread]                         janitor-ssm::SsmProvider : Provider
  Command::BeginDiscovery ───────────────▶  begin_discovery → SsmDiscovery::start
  Command::AdvanceDiscovery{choice} ─────▶  advance(choice)  ── account/role/instance picks
  Command::ProvideInput(path) ───────────▶  provide_input(path) ── .env path
        ▲                                        │
        │ Event::DiscoveryChoice / *Input        │ uses janitor-aws-auth:
        │ Event::EnvDiscovered(Mapping)          │  Reauth.sign_in, AccountCatalog,
        │ Event::DiscoveryFailed / Reauth        │  RoleCredentialClient, CredentialBroker
        └────────────────────────────────────────┤
                                                  │ tail: InstanceCatalog.describe_instances,
                                                  │       RemoteFileReader.read_file (SSM),
                                                  │       parse_dotenv → SecretShape
        Command::LoadApp(app) ─────────────▶ load: for each Mapping → read_file → parse →
        Event::AppLoaded(MatrixView) ◀────────────  Comparison::build + project (core)
        Command::Reveal ───────────────────▶ reveal from worker-resident cache (round-trip)
```

`load` mirrors `janitor-aws::Session::load`: read every Environment's `.env`,
any failure → whole-app `AppError` naming the env (ADR 0012, Decision 8 there);
all succeed → masked `MatrixView` via core. Plaintext stays worker-side; `reveal`
is the one on-demand crossing.

## Security (THREAT-MODEL additions — the sharp edge of this Provider)

Reading a `.env` over SSM is the first Janitor path that pulls plaintext off a
**remote** machine, and the read mechanism can cause secrets to be written to
disk **on the AWS side**, via org config we do not control. New entries for
THREAT-MODEL.md:

- **Asset extension.** A remote `.env`'s contents are Values (highest-value
  asset). They cross the wire from the instance to the worker, live only in
  `RawSecret`/`Value` zeroizing buffers, and are never persisted, logged, or put
  in an `Event` except the single user-requested `Revealed{text}`.
- **Residual risk we accept and surface: Session Manager session logging.**
  Session Manager can be configured **account-wide** (Session Manager preferences)
  to log session data — including the streamed file contents — to **S3 and/or
  CloudWatch Logs**. Janitor cannot disable this. Mitigation: before/at first read
  Janitor **detects** the setting (`GetServiceSetting` / the session preferences
  document) and **warns** in the Diagnostic Log + wizard ("this org logs SSM
  sessions; the file contents will be written to its S3/CloudWatch"). Documented
  as an accepted residual risk, sibling to the AWS-24h-version-retention note —
  the secret already lives in the customer's AWS account; we surface, not prevent.
  (Why not `SendCommand`: its inline output truncates at ~2500 chars *and* routing
  full output anywhere means S3 — a disk write to read large files; Session
  Manager streams arbitrarily large files with archival being opt-in/detectable.)
- **No SDK/SSM text leaks.** SSM/SSO errors map through the existing
  `SessionError → FetchFailReason` masking; no raw protocol text reaches a Value,
  an `Event`, or the Diagnostic Log (CONTEXT: Diagnostic Log holds error-safe
  signal only).
- **Read-only.** Only `cat`-class reads; no remote mutation reachable (ADR 0004).
- **IAM (least privilege, docs/iam_setup.md update).** The SSM read path needs
  `ssm:DescribeInstanceInformation`, `ssm:StartSession` (scoped to the target
  instances + the `AWS-StartNonInteractiveCommand` document),
  `ssm:TerminateSession`/`ssm:ResumeSession`, plus the existing Identity Center +
  `GetRoleCredentials`. The instance needs the SSM agent + an instance profile.
  The transport (a) also needs the `session-manager-plugin` installed locally.

## Testing

- **`janitor-aws-auth`** — the relocated `broker`/`source`-fed tests +
  `wire::fakes` transfer unchanged; ≥80% gate met by the move. No new behavior.
- **`janitor-aws`** — unchanged behavior; tests pass after the `use` repointing.
  Per the project rule, **no existing assertion changes**; if one *would*, stop and
  surface it.
- **`janitor-ssm`** (new logic, fakes): `SsmDiscovery` against
  `FakeAccountCatalog`/`FakeRoleClient` (reused from the base) +
  `FakeInstanceCatalog` + `FakeRemoteFileReader`: auto-pick singletons; Ask on
  many with remembered default; `Input` for path with remembered default; `Empty`
  per step; `Reauth` routing; `Done` builds the `<instance>:<path>` Mapping; read
  failure surfaces masked in the wizard; `load` whole-app error on one failing
  env. `parse_dotenv` table-tests (comments, `export`, quotes, inline comments,
  duplicates, malformed). ≥80% gate (ADR 0016), `--ignore-filename-regex 'src/bin/'`.
- **`janitor-gui`** — additive `Input` plumbing (untested shell, ADR 0010 §5);
  the existing view tests (ADR 0021) stay green.
- **Human-gated (Milestone B):** `live-verify-ssm` against a real EC2+SSM box
  resolves the transport spike (Decision 3) and the session-logging detection.

## Risks & verify-at-implementation

- **MGS protocol cost (transport b)** — unknown until the spike; (a) is the
  fallback. The `RemoteFileReader` seam means the choice does not leak upward.
- **`AWS-StartNonInteractiveCommand` availability/semantics** — confirm the
  document name and that it streams full stdout cleanly in the spike (my recall,
  not verified).
- **Session-logging detection API** — confirm `GetServiceSetting`
  (`/ssm/session-manager/...`) actually reveals the org's logging config under the
  minted role's permissions; if not, fall back to an always-on warning.
- **`Send` of `RawSecret`/`Value` across the worker** — already relied on by
  `janitor-aws`; reconfirm for the SSM path.
- **Phase A is a big mechanical move** — do it as its own reviewable change with
  the test suite green before any byte of Phase B.

## Suggested slicing (tracer-bullet vertical slices → issues)

1. **A:** create `janitor-aws-auth`, move the shared modules + fakes, repoint
   `janitor-aws`, workspace green. (No behavior change.)
2. **B1:** `core::provider` gains `Input`/`Instances` (+ `provide_input`),
   `janitor-mock`/`janitor-aws` no-op them, GUI relays them. (No behavior change.)
3. **B2:** `parse_dotenv` (pure, fully tested) in a skeleton `janitor-ssm`.
4. **B3:** `SsmDiscovery` + `InstanceCatalog`/`RemoteFileReader` seams + fakes;
   `SsmProvider: Provider`; `build_provider` arm; GUI offline-runnable on a fake.
5. **B4:** the real SSM transport shell (spike → choose (a)/(b)) +
   `live-verify-ssm` + session-logging detection + `docs/iam_setup.md`.
6. **(#33 / ADR 0026, after A+B):** extract the `core` Discovery orchestrator from
   the two real walks; both Providers drive it; kill the `account→role→mint`
   duplication and the `What` AWS-vocabulary leak.
