# A remote `.env`-over-SSM Provider (`janitor-ssm`): the second real Provider

**Status:** accepted; B3 implemented (#64); **B4 implemented + LIVE-VERIFIED (#65,
2026-06-07)** — transport (b) chosen, the read is `sudo`+`base64`, see [the B4
implementation note](#b4-implementation-note-2026-06-07) and [Live verification](#live-verification-2026-06-07--milestone-b-done)
below. The **write** path is designed in [ADR 0028](0028-remote-dotenv-write-over-ssm-command-channel.md).

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

## B4 implementation note (2026-06-07)

B4 (#65) implemented the concrete SSM tail. Two decisions are recorded here as the
ADR's Decision says to "commit by amending this ADR."

- **Transport: (b), the pure-Rust MGS data channel — chosen over (a).** Janitor
  reimplements the Session Manager agent message protocol
  (`AWS-StartNonInteractiveCommand` → `StartSession` → the `StreamUrl` WebSocket)
  directly in Rust (`janitor-ssm/src/mgs/`), so reading a remote `.env` needs **no**
  `session-manager-plugin` binary (no packaging/runtime dependency; ADR 0022
  unaffected). The byte framing (`mgs::frame`, reproduced from the `amazon-ssm-agent`
  contract) and the session state machine + driver (`mgs::protocol`) are **pure,
  unit-tested logic**; only the `wss` socket adapter (`mgs::channel`, ~30 lines) and
  the `StartSession`→socket glue are the untested shell (ADR 0010 §5). The SDK calls
  (`DescribeInstanceInformation`, `StartSession`, `GetDocument`) are replay-tested
  against `StaticReplayClient` (ADR 0027), so `janitor-ssm` holds its ≥80% gate with
  the shell in the number (~95% lines). The read command is **`sudo -n sh -c 'base64
  -- '\''<path>'\'''`** with a non-sudo `||` fallback — `sudo` because the session
  runs as the unprivileged `ssm-user` which cannot read a root-owned `600` secrets
  file, and `base64` because the session's `sudo`/PAM/PTY path can fold banner/relay
  bytes into the stream (it is decoded back on our side, the non-alphabet noise
  dropped). This superseded an initial `cat -- '<path>'` during live bring-up — see
  *Live verification* below.

- **Session-logging detection: `GetDocument`, not `GetServiceSetting`.** The spec
  recalled this as `GetServiceSetting`; that was wrong — there is no service setting
  for session logging. The org's preference lives in the `SSM-SessionManagerRunShell`
  SSM **document** (`ssm:GetDocument`); its `inputs.s3BucketName` /
  `cloudWatchLogGroupName` drive the advisory, and `inputs.kmsKeyId` flags KMS data-
  channel encryption. A new `LoggingPreference`/`LoggingState` seam + fake + the pure
  `session_logging_advisory` decision are **covered**; only the live `GetDocument`
  call is shell. The on/off → warn decision (with "doc absent (`ResourceNotFound`) =
  Session Manager default = no logging" and "unreachable probe = always-on fallback
  warning") is unit-tested. The advisory surfaces through a new, provider-agnostic
  `Provider::take_advisories` port method (default empty) to **both** the Diagnostic
  Log and the Discovery wizard; it is raised at the credential mint (while the wizard
  is still open) and once per load.

- **KMS-encrypted sessions are unsupported (v1).** If the org enables session-data
  KMS encryption, the data channel's handshake requests `KMSEncryption`; the pure
  transport does not implement the KMS data-key exchange, so it responds `Unsupported`
  and the read fails fast and **masked** (`SessionError::Unsupported`) rather than
  hanging. The `GetDocument` probe's `kmsKeyId` flag detects this. Implementing KMS
  is a noted future enhancement.

### Live verification (2026-06-07 — Milestone B, done)

`live-verify-ssm` was run against a real Identity Center org + EC2/SSM box
(`/opt/deferno/.env`, a 62-line / 3,579-byte root-owned `600` file). It read the file
end-to-end and printed the masked 49-entry matrix — **no `session-manager-plugin`, no
Value leaked.** Four things had to be fixed/learned during bring-up; each is now in the
code + tests:

1. **AgentMessage `MessageId` is half-swapped on the wire.** The `amazon-ssm-agent` /
   `session-manager-plugin` marshal the 16-byte id as two byte-swapped 8-byte longs
   (`getUuid`/`putUuid`: least-significant half first). Reading it verbatim made every
   `AcknowledgedMessageId` we echoed unrecognized, so the agent retransmitted its
   `handshake_request` forever and its send window stalled — the file truncated to its
   first frame. `mgs::frame` now transposes the halves on encode + decode.
2. **The session runs as `ssm-user`; the file is root-owned `600`.** A plain `cat`
   returned `cat: …: Permission denied` (exactly 42 bytes). The read now uses
   `sudo -n` (the SSM agent grants `ssm-user` NOPASSWD sudo by default), `||`-falling
   back to a non-sudo read.
3. **The `sudo`/PAM/PTY path can fold a large binary banner block into the stream**
   (a 3.5 KB file came back as ~44 KB of mixed text+binary). The read is therefore
   `base64` — its alphabet excludes the control/high-bit noise, which `decode_base64
   _output` filters before a strict decode (a corrupt/aborted read → masked `Err`,
   never a mis-parsed `.env`). This replaced both the raw `cat` and an interim
   sentinel-bracketing approach.
4. **`AWS-StartNonInteractiveCommand` ends with `channel_closed` and no `EXIT_CODE`.**
   The completion signal is a clean `channel_closed` (return the accumulated output);
   only an abrupt socket drop (recv `None` with no close) is `ClosedEarly`.

Checklist resolution:

- [x] `StartSession` accepts the `AWS-StartNonInteractiveCommand` document name.
- [x] stdout streams cleanly and whole — the 49 masked Entries matched the file's
      `KEY=VALUE` lines (50 lines, `POSTGRES_PASSWORD` duplicated → 49 unique).
- [x] completion signal resolved (clean `channel_closed`, no `EXIT_CODE` — item 4
      above). A non-zero `cat`/command still maps to masked `NotFound`; a bad-path
      run is the one remaining easy manual check.
- [~] `ssm:GetDocument` on `SSM-SessionManagerRunShell` — the test role lacked the
      permission, so the **always-on fallback advisory fired** (the intended
      degraded behaviour); the on/off toggle still wants a role that *has* the
      permission against an org with logging configured.
- [ ] a KMS-encrypted org fails masked (`Unsupported`) — untested (org has no
      session KMS); the handshake path is unit-tested.

The **write** path (read+modify+write a few Entries) is designed in **ADR 0028**,
which also records the command-channel-vs-SFTP foundation decision this read settled.
