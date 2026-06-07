# A remote `.env`-over-SSM Provider (`janitor-ssm`): the second real Provider

**Status:** accepted (not yet implemented)

**Related:** [#33](https://github.com/Circuit-Stitch/Janitor/issues/33) (the
shared Discovery orchestrator this unblocks), [ADR 0024](0024-shared-aws-auth-base-crate.md)
(the `janitor-aws-auth` base this consumes), [ADR 0019](0019-provider-port-in-core-and-janitor-mock-crate.md)
(Provider port; "extract from ≥2 real shapes"), [ADR 0013](0013-guided-discovery-in-gui-step-machine-and-manage-window.md)
(`Discovery`/`Step`), [ADR 0010](0010-aws-adapter-crate-and-auth-object-model.md)
(§5 untested SDK/shell), [ADR 0012](0012-gui-aws-bridge-worker-and-lazy-sign-in.md)
(worker bridge; whole-app fetch error), [ADR 0008](0008-secret-shape-flattening-scheme.md)
(secret-shape flattening), [ADR 0004](0004-read-only-v1-scope-and-secret-shapes.md)
(read-only v1), [ADR 0016](0016-per-crate-coverage-badges-and-aws-gate.md),
[ADR 0022](0022-packaging-cargo-packager-and-windows-signing.md) (packaging),
[THREAT-MODEL.md](../THREAT-MODEL.md), [CONTEXT.md](../../CONTEXT.md). Design
detail:
[`docs/superpowers/specs/2026-06-06-second-provider-ssm-dotenv-and-shared-auth-base-design.md`](../superpowers/specs/2026-06-06-second-provider-ssm-dotenv-and-shared-auth-base-design.md).

## Context

#33 needs a **second real Provider** before the shared Discovery orchestrator can
be extracted from evidence rather than guessed from AWS alone (ADR 0019). The
owner chose to build one whose Discovery shape deliberately *shares AWS's front
half and varies only at the tail*: a `.env` file on a remote EC2 instance's
filesystem, read over AWS Systems Manager (SSM) Session Manager. It Signs in to
Identity Center, picks account → role → mints a Credential (all via
[`janitor-aws-auth`](0024-shared-aws-auth-base-crate.md)), then walks its own
tail: list SSM-managed instances → pick instance → choose the `.env` path → read
the file over a Session Manager session → parse `KEY=VALUE`.

Two facts make the design non-trivial. **(1) Discovery is not always "pick one of
N":** the `.env` path is free-text, which the current `Step::Ask { choices }`
cannot express. **(2) Reading the file can write secrets to disk on the AWS side:**
Session Manager session logging can be enabled account-wide to S3/CloudWatch, and
`SendCommand`'s inline output truncates at ~2500 chars (forcing S3 for larger
files). The read mechanism is therefore a security decision, not an ergonomic one.

## Decision

- **A new `janitor-ssm` crate** implementing `core::provider::Provider`, depending
  on `janitor-core` + `janitor-aws-auth` (never `janitor-aws`). Read-only (ADR 0004).

- **Discovery tail: `instance → .env path`.** `instance` lists SSM-managed
  instances via `DescribeInstanceInformation` (new `InstanceSummary { id, name }`,
  `Selectable` by `id`, `name` from the `Name` tag/`ComputerName` else `id`),
  auto-collapsed/Asked via `select::plan_selection` like accounts/roles. `.env
  path` is **free-text input** with a remembered default. The read happens at the
  end of the walk so an unreadable path fails *in the wizard* (masked), not later.

- **Read over Session Manager `StartSession`, not `SendCommand`** — chosen for the
  disk invariant (below). The concrete transport is **spiked against a real box in
  Milestone B, then committed by amending this ADR** between:
  **(a)** shell out to `session-manager-plugin` with the
  `AWS-StartNonInteractiveCommand` document (`cat <path>`, streamed, no PTY, no
  `SendCommand` S3 archival) — pragmatic, an untested shell (ADR 0010 §5), adds a
  runtime dependency on the plugin (ADR 0022); or **(b)** implement the SSM
  data-channel (MGS) WebSocket protocol in Rust — pure-Rust, no external binary,
  fakeable channel, most build effort. Either way the **`RemoteFileReader` wire
  seam is identical**, so the orchestration/parse/error-mapping is tested against a
  `FakeRemoteFileReader` and only the concrete impl is the untested shell.

- **The `Step` model grows an `Input` variant** in `core::provider` (additive):
  `Step::Input { what, prompt, default: Option<String> }`, with a
  `Provider::provide_input(text) -> Option<Step>` method, a worker
  `Command::ProvideInput` / `Event::DiscoveryInput`, a GUI text-field presenter,
  and a stdin-presenter `Input` arm. `What` grows `Instances` (and a `FilePath`
  label). `janitor-mock`/`janitor-aws` implement `provide_input` as `None` (they
  emit no `Input`). No existing Provider behavior changes.

- **`.env → SecretShape` via a pure, tested `parse_dotenv` in `janitor-ssm`.** A
  `.env` is flat `KEY=VALUE`, mapping onto the same flat representation a flat JSON
  Set produces — so it slots into the existing comparison model with **no `core`
  change** (ADR 0008). Rules (pinned by table-tests): ignore `#`/blank lines; strip
  leading `export `; `"…"`/`'…'` quoting (single literal, double unescapes
  `\n`/`\"`); trailing inline `#` comment trimmed only outside quotes; duplicate
  key = last wins; a line without `=` → `SessionError::Unsupported`. Raw bytes live
  in zeroizing `RawSecret`; each Entry's Value is a zeroizing `Value`.

- **`Mapping` fields are reused as-is** (no schema/Config change): `secret_id`
  carries **`<instance-id>:<path>`**; `account_id`/`region`/`permission_set` keep
  their front-half meaning; `environment` from the wizard. Whether `Mapping`'s
  AWS-leaning field *names* become a provider-agnostic location is deferred to
  #33/ADR 0026.

- **`load` mirrors `janitor-aws::Session::load`:** read every Environment's `.env`,
  any failure → whole-app `AppError` naming the env (ADR 0012); all succeed → masked
  `MatrixView` via `Comparison::build` + `project`. Plaintext stays worker-side;
  `reveal` is the one on-demand crossing.

- **A human-gated `live-verify-ssm` binary** (Milestone B, like `live-verify`)
  verifies the end-to-end path against a real EC2+SSM org and resolves the
  transport spike and the session-logging detection.

## Considered options

- **`SendCommand` + inline `GetCommandInvocation`.** Rejected: ~2500-char output
  truncation means large `.env`s force output to S3 — a disk write to *read* a
  secret. Session Manager streams arbitrary sizes with archival opt-in/detectable.

- **Discover candidate `.env` paths** (a bounded remote `find`, presented as an
  `Ask` list). Rejected for v1: an extra remote-exec round-trip (itself an SSM read
  to handle) to avoid one free-text field. Free-text `Input` is the smaller, more
  honest change and the better #33 evidence; candidate discovery is a noted future
  enhancement.

- **Interactive Session Manager shell (PTY) and scrape stdout.** Rejected in favor
  of `AWS-StartNonInteractiveCommand`: a one-shot command with clean streamed
  output, no prompt/echo parsing.

- **Generalize the `Mapping`/location model now.** Deferred: pulls #33's
  generalization forward and touches Config + every Provider; reuse keeps Phase B
  small (ADR 0024's "duplication is the evidence" stance).

## Consequences

- The workspace gains `janitor-ssm` (≥80% gate, ADR 0016, `--ignore-filename-regex
  'src/bin/'`); `build_provider` gains a `ProviderKind::SsmDotenv` arm; the GUI
  gains the additive `Input` plumbing (untested shell, ADR 0010 §5). The existing
  view tests (ADR 0021) stay green.

- **THREAT-MODEL gains the remote-read posture** (see THREAT-MODEL.md): remote
  `.env` contents are Values (zeroizing, memory-only, never persisted/logged, only
  the user-requested `Revealed{text}` crosses); **accepted residual risk** —
  account-wide Session Manager logging to S3/CloudWatch, which Janitor cannot
  disable, is **detected and warned** (Diagnostic Log + wizard) and documented like
  the AWS 24h version-retention note; no SSM/SDK text leaks (masked via
  `SessionError → FetchFailReason`); read-only only.

- **`docs/iam_setup.md` gains the SSM least-privilege policy:**
  `ssm:DescribeInstanceInformation`, `ssm:StartSession` (scoped to the target
  instances + `AWS-StartNonInteractiveCommand`),
  `ssm:TerminateSession`/`ssm:ResumeSession`, plus existing Identity Center +
  `GetRoleCredentials`; the instance needs the SSM agent + an instance profile;
  transport (a) needs `session-manager-plugin` installed locally.

- **Delivers #33's gate.** With two real Discovery shapes — `[account, role(+mint),
  secret]` and `[account, role(+mint), instance, path, read]` — and concrete
  evidence (shared front half; `Input` vs `Ask`; the `What` AWS-vocabulary leak;
  the suggested `Stage` shape), ADR 0026 can extract the `core` orchestrator from
  evidence, satisfying #33's acceptance criteria.

- **CONTEXT.md gains terms** (Instance, Remote `.env` Provider; see CONTEXT.md).
