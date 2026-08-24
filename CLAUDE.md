# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Latest: the Slint shell moved out to `Circuit-Stitch/Janitor-slint`
> (#106, ADR 0036 Amendment 2026-08-24).** `janitor-gui` is gone from this
> workspace. `git subtree split` rooted its 72 commits at the new repository's
> root, so the shell kept its real history and is that repository's **root
> package**, not a member of a workspace. It takes `janitor-core`, `janitor-app`,
> and `janitor-mock` by **Cargo path to a sibling checkout** — Gonger's pattern.
> Cargo cannot fetch a binary over plain HTTPS, so the depot is unreachable from
> Rust, and a path keeps "nothing to publish, nothing to bump" for the shell that
> moves with the core. Its CI checks this repository out beside it through
> `.github/actions/checkout-core`, the `checkout-wire` shape. **The whole desktop
> release lane moved** — `release.yml` (rpm, deb, AppImage, dmg, signed MSIX),
> `setup`, `verify-version`, `oidc-smoke.yml`, `.github/release-body.md`, the
> Azure signing variables, and `docs/RELEASING.md`. **The version authority moved
> with it:** `vX.Y.Z` now reads `Janitor-slint/Cargo.toml` and stops describing
> the core. This repository keeps test, clippy, and the five coverage gates, plus
> `publish.yml`'s `kit-vX.Y.Z` lane, and its `docs/RELEASING.md` is now about that
> lane only. **The macOS `.dmg` stays** in `Janitor-slint`, by owner decision: a
> Mac user who wants the Slint build rather than the SwiftUI one has somewhere to
> get it. Two paths changed because the crate is no longer a workspace member —
> the rpm `source` entries lost their `janitor-gui/` prefix, and the MSIX update
> URL points at the new repository. That last one **breaks "Check for updates" for
> anyone on 0.1.4**, who needs a one-time manual reinstall; `Janitor-slint`'s
> `docs/RELEASING.md` carries it, the same shape as the earlier NSIS → MSIX gap.
> **Still pending:** the Azure federated credential names
> `repo:Circuit-Stitch/Janitor:environment:release`, so a credential for
> `repo:Circuit-Stitch/Janitor-slint:environment:release` has to be added in the
> Entra app registration before a Windows release can sign; `oidc-smoke.yml`
> confirms it in ~30s. The 47 view tests pass unchanged; workspace tests 583 →
> 536. Design:
> [`docs/adr/0036-three-repos-core-slint-shell-macos-shell.md`](docs/adr/0036-three-repos-core-slint-shell-macos-shell.md)
> (Amendment 2026-08-24).
>
> **JanitorKit is published, and the SwiftUI shell drives the real core
> (#105/#104/#97, ADR 0035 Amendment 2026-08-24).**
> `scripts/build-xcframework.sh` builds `JanitorKit.xcframework` — one
> `macos-arm64_x86_64` slice carrying the Rust archive and the UniFFI-generated
> Swift compiled over it — and `.github/workflows/publish.yml` publishes it to the
> depot on a `kit-vX.Y.Z` tag (its own lane: `Janitor-slint`'s `vX.Y.Z` versions
> `janitor-gui`, this one versions `janitor-app`). **The framework is one
> mixed-language module, not two.** UniFFI emits 48 public
> `FfiConverterType*_lift`/`_lower` functions taking a `RustBuffer`, so the C module
> cannot be hidden the way Gonger hides `CWotSound`; the C header is the framework's
> own clang module, the Swift is compiled `-import-underlying-module`, and both are
> `JanitorKit`. The modulemap carries **autolink directives** for the twelve system
> frameworks `--print native-static-libs` names (AppKit and AuthenticationServices
> among them, from the `ASWebAuthenticationSession` sign-in), and the script's last
> step **links and runs a consumer** against the finished slice, so a stale list
> fails there rather than in somebody's app. **`Config` now crosses**, resolving
> ADR 0035's open item: a `ConfigStore` UniFFI object holds the one copy and every
> edit runs the core's own rule before saving, `ConfigError` crosses as a thrown
> `ConfigFailure`, and an **in-memory constructor** means `JANITOR_MOCK=1` and the
> test suite cannot touch a real `config.toml`. The boundary also gained the pure
> rules (`matrix_items`, `display_name_parts`, `badge_label`, `state_glyph`,
> `error_banner`, `pane_title`/`pane_body`, `choice_prompt`, `method_*`,
> `summarize_edits`) and `apply_corrected_roles`. **Four rules left `janitor-gui`**
> for core, where both shells reach them: `Method::{label,full_name,from_index}` and
> `What::prompt`, plus a typed `pane::LoadStatus`. **In `Janitor-macos`,
> `Protocol.swift` is deleted** — the generated types are what the views use, three
> names are aliased (`Method` shadows the Objective-C runtime's), and `StubCore`
> lost its ~250 lines of rule copies to become a scripted fixture over an in-memory
> `ConfigStore`; its tests kept their assertions and now pin the real rules. 83
> Swift tests pass, three of them driving the Rust worker end to end over the FFI.
> Rust 572 → 583; core coverage 95.93% → 96.03%. **The rail is live end to end:** the
> depot tenant is applied (role `depot-publisher-janitor`, prefix `open/swift/janitor`),
> tag `kit-v0.1.0` published `JanitorKit.xcframework.zip`, and
> `JanitorKit/Package.swift` pins the checksum that run printed. The 83 Swift tests pass
> against the fetched slice with `JANITORKIT_LOCAL` unset, so the default route is the
> depot. **Still pending:** the UI test lane has only run against a local build, and a
> version publishes once — a Rust change needs a new `kit-vX.Y.Z` and a checksum bump.
> **Next:** #106, the `Janitor-slint` split. Design:
> [`docs/adr/0035-swiftui-macos-shell-over-uniffi.md`](docs/adr/0035-swiftui-macos-shell-over-uniffi.md)
> (Amendment 2026-08-24).
>
> **The UniFFI boundary landed in `janitor-app` (#95, ADR 0035 Amendment
> 2026-08-21).** Swift drives the worker protocol directly: `Command` (10 in) and
> `Event` (21 out) are exported, plus an `EventSink` foreign trait, a `Worker`
> object (`start` + `send`), and `is_revealed` — so the un-mask-exactly-one rule
> stays tested Rust instead of being reimplemented in Swift. **Zero `async fn`
> crosses** (Swift gets a fire-and-forget call plus a stream, which also dodges the
> `@MainActor` inheritance under Xcode 26). **UniFFI is a Cargo feature**
> (`janitor-app/uniffi`), so a Slint build compiles none of it, and **`janitor-core`
> gains no UniFFI dependency**: the fifteen core types the protocol carries cross as
> `#[uniffi::remote]` mirrors declared in `janitor-app::ffi`. The generated code
> destructures the real type, so a field renamed/retyped/added in core fails to
> compile at the boundary. `usize` is not a UniFFI primitive — it crosses as `u64`
> behind a custom type (`typealias Usize = UInt64` in Swift). **The single plaintext
> crossing is the new `janitor_core::secret::Plaintext`** — a zeroizing newtype whose
> only readers are `expose`/`expose_owned`. It replaced the bare `String` in
> `Event::Revealed`/`CopyValue` **and** the `Zeroizing<String>` in `EnvEdit::Set`, and
> `Provider::reveal` returns it now too: one greppable symbol covering both
> directions, closing the gap where a revealed Value travelled the port unzeroed.
> Verified against the real toolchain by `scripts/generate-swift-bindings.sh` — it
> builds the staticlib, generates the Swift, and compiles it as module `JanitorKit`
> under Swift 6 + `nonisolated` default actor isolation + library evolution, with the
> emitted `.swiftinterface` **verified** (the module-vs-type name check ADR 0035 asks
> for) and a guard that fails on any exported `async`. The generator is its own
> package outside the workspace (`tools/uniffi-bindgen-swift`, `uniffi` pinned
> `=0.32.0`) so a workspace `--all-features` never compiles `uniffi_bindgen`; the
> script fails if that pin and `janitor-app`'s resolved version disagree. Core
> coverage rose (95.78% → 95.93%); tests 555 → 572. CI's workspace test now runs
> `--all-features`, so the boundary's round-trip tests are in the gate. **Still
> pending:** `Config::load`/`save` do not cross yet — #97 needs them, and will settle
> whether `ConfigError` should cross as a thrown error. **Next:** #105/#104 (depot
> tenant + xcframework publish, built from `janitor-app`), then #106 (the
> `Janitor-slint` split), then #97 (the SwiftUI tracer bullet). Design:
> [`docs/adr/0035-swiftui-macos-shell-over-uniffi.md`](docs/adr/0035-swiftui-macos-shell-over-uniffi.md)
> (Amendment 2026-08-21 — *the boundary as built*).
>
> **Latest: the shells are being split apart (#96, ADR 0035 Amendment 2026-08-21).**
> The first two slices of the macOS epic (#94) landed, both behavior-preserving.
> **The six shared presentation seams moved to `janitor-core`** — `errors`,
> `logpane`, `pane`, `reveal`, `rows`, `sidebar`. They were bin-local `mod`s in
> `janitor-gui`, which has no `lib.rs`, so nothing outside that binary could reach
> them; both shells drive all six. Their 38 tests moved and pass unchanged (core
> 133 → 171 tests, 95.8% lines). Core gained `tracing` + `tracing-subscriber`,
> because `logpane` is both the layer and the ring buffer it feeds.
> **The worker moved to a new `janitor-app` crate**, not to `janitor-core` as
> ADR 0035 said. That was a **Cargo cycle**: `worker.rs` names `janitor-aws`,
> `janitor-aws-auth`, and `janitor-ssm`, and all three depend on `janitor-core`
> (verified — `error: cyclic package dependency`). The composition root
> (`build_family`) is the forcing constraint: it is the only place both AWS-family
> tails are named together, so it must sit **above** every adapter crate.
> `janitor-app` depends on core + all four adapters and holds `Command`, `Event`,
> `run_loop`, `discovery_event`, `write_event`, `surface_advisories`,
> `ProviderKind`, `spawn`, `build_provider`, `build_family` — and later the UniFFI
> boundary (#95), so **`JanitorKit.xcframework` is built from `janitor-app`**, not
> from `janitor-core`. This is **not** the rejected `janitor-ffi`: `janitor-app` is
> not Apple-only, it is the application layer both shells drive, and UniFFI stays
> optional there. Core keeps its name, its meaning, and its ≥80% gate over pure
> logic; `janitor-app` carries **no** gate (I/O loop + composition root, 80.2%).
> **The Windows MSIX update rail left the shared protocol** (ADR 0034): its four
> `Command`/`Event` variants carried `janitor-gui` types that UniFFI cannot export,
> and only the Slint shell ships an MSIX, so `janitor-gui` now owns its own update
> thread + runtime + two-command loop. Manual-only, off the UI thread, zero
> background egress — unchanged. `janitor-gui` now depends on `janitor-core` +
> `janitor-app` + `janitor-mock` only, and names **no** adapter crate — which is
> what #106 needs to lift it into `Janitor-slint`. Test totals are conserved
> exactly (235 → core 171 + app 16 + gui 48). **#95 followed it** — see the block
> above. Design:
> [`docs/adr/0035-swiftui-macos-shell-over-uniffi.md`](docs/adr/0035-swiftui-macos-shell-over-uniffi.md)
> (Amendment 2026-08-21) and
> [`docs/adr/0036-three-repos-core-slint-shell-macos-shell.md`](docs/adr/0036-three-repos-core-slint-shell-macos-shell.md).
>
> **Latest: the Secrets Manager staged-put/CAS write engine landed (ADR 0001 +
> Amendment 2026-06-25, #89) — built behind fakes + replay, shipped read-only.**
> `SecretsManagerMethod::write` is no longer the masked `Unsupported` stub (ADR 0032
> Decision 8's deferral is resolved): it dispatches to a new pure
> `janitor-aws::secret_write::write_secret` engine that does the **flat-JSON merge**
> (parse the current blob, replace/insert/remove the edited **top-level** keys via
> `serde_json`, preserve every untouched key — incl. non-string scalars — verbatim;
> nested/array/bare-string/`secret_binary` → masked `NotFlat`/`Unsupported`, never an
> un-flatten guess) then the ADR 0001 staged-put → atomic-CAS → mandatory-cleanup
> sequence under **conflict model B** (base = the write's *own* first read; a key
> *we* edited changing across a re-read → stop with `Conflict`, never auto-merge;
> only other keys changed → replay-on-fresh + bounded `MAX_ATTEMPTS` retry; a no-op
> merge writes nothing). The `SecretsApi` seam gained `put_secret_value` (returns the
> new `VersionId`, stages under a `janitor-pending-<uuid>` label so `AWSCURRENT` is
> not moved), `update_secret_version_stage` (a `CasOutcome::{Committed,Mismatch}`
> CAS), and a `VersionId` on the read; the three new SDK methods are **replay-tested**
> (`StaticReplayClient`, ADR 0027) so the shell stays in the coverage number (aws
> 94.8%, gate held). A standalone `SecretsManagerWriter` (broker + `SecretsApi`) backs
> a human-gated `live-verify-sm-write` binary (guided sign-in → Discovery → edit →
> masked outcome → masked re-read). The merged blob + Values are `Zeroizing` and reach
> only the writer; `ClientRequestToken`/`VersionId` are non-secret opaque ids — no
> Value or SDK text crosses a `Failure`/`Event`/log/`Debug` (THREAT-MODEL); v1 stays
> read-only (engine reachable only via the binary). **Still pending:** the live run
> itself (ADR 0001's AWSCURRENT/AWSPREVIOUS + label-reclamation + exact CAS-mismatch
> error-code checks; the shell errs to the safe side until then), the version-quota
> cadence guard (deferred — `MAX_ATTEMPTS` is the only quota defence for now), and the
> GUI cell-edit + confirm-diff UI (out of scope, #80 follow-up). Design:
> [`docs/adr/0001-non-stomping-writes-via-staged-put-and-cas.md`](docs/adr/0001-non-stomping-writes-via-staged-put-and-cas.md)
> (Amendment 2026-06-25).
>
> **Latest: the Discovery browse-region picker + cross-region Discovery landed
> (ADR 0015, #12).** Discovery's browse region is now a **console-style picker
> (never free text)** wired in **two surfaces over one sticky value**: Global
> Settings and at-hand beside `+ Add env` in the Manage window. The testable core
> is a new pure `core::region` module (100% covered): `region_choices(&Config)` —
> the static `KNOWN_REGIONS` commercial list **unioned with** the user's own
> regions (`sso_region`, every saved `Mapping.region`, `last_pick`), deduped,
> known-first, so a gov/opt-in region always appears; and `browse_region(&Config)`
> — the `secret_region`-else-`sso_region` resolve rule, **extracted from the GUI's
> inline copy** so it's finally tested. The GUI (untested shell, ADR 0003/0010 §5)
> binds both `ComboBox`es to the same `config.secret_region`: a shared
> `set_browse_region` persists the pick and `publish_browse_region` re-pushes
> choices + selection to **both** windows, so the two pickers are one value that
> never drifts; `begin_discovery` now reads `region::browse_region` instead of the
> deleted inline computation. **No `Config` schema change** (the `secret_region`
> field + its documented fallback already existed) and **no engine change** —
> cross-region "falls out for free" because the walk already takes one browse
> region per `start()` and stamps `Mapping.region`; a `janitor-aws` guard test
> (`two_walks_with_different_browse_regions_yield_cross_region_mappings`) proves an
> Application can span regions. Region is a location, never a Value (THREAT-MODEL).
> Coverage holds (core 97.5%, aws 95.0%). **Out of scope (unchanged):** region as a
> compare/display axis (rejected, ADR 0013/0015 — Environment stays the compare
> axis, region stays passive `Mapping` metadata) and the unscheduled "Ad-hoc
> compare". Design:
> [`docs/adr/0015-region-picker-and-cross-region-discovery.md`](docs/adr/0015-region-picker-and-cross-region-discovery.md).
>
> **Latest: the write seam is wired to the `Provider` port behind a worker-held
> read-write lock (ADR 0032, B5 / #80) — backend + lock slice.** `core::provider::Provider`
> gains a method-agnostic `write(&mut self, mapping, edits) -> Result<WriteOutcome,
> Failure>` (defaulted to a masked `Unsupported` so a read-only Provider degrades for
> free); `AwsFamilyProvider::write` dispatches per `Mapping` to `methods[m.method].write`
> through the **same broker + force-refresh/re-Sign-in ladder** as `fetch` (but **not**
> ADR 0018 stale-role recovery — that rewrites/persists Config on *load*, not write);
> `MockProvider::write` stubs `Applied`. The write-seam types (`EnvEdit`/`WriteOutcome`/
> `EnvWriteError`) **moved to `core::write`** so the port can speak them (`core` can't
> depend on an AWS crate); `janitor-aws-auth::write` re-exports them, so every
> AWS-family `janitor_aws_auth::write::…` path is unchanged. The **worker is the
> authoritative lock**: `read_write` starts off every launch (never persisted),
> `Command::SetReadWrite` flips it, and `Command::ApplyEdits` is **refused without any
> AWS call** while locked (`Event::WriteRefused`) — so "mutating calls are unreachable
> until unlocked" (ADR 0004) is a *tested* worker invariant, not just a GUI affordance;
> a Settings "Read-write mode" toggle is the deliberate-unlock control, outcomes relay
> to the Diagnostic Log. A pure tested `core::write::summarize_edits` masks pending
> edits to key + **length only** (never the new Value) for the eventual confirm dialog.
> Edit Values are zeroizing, reach only the Provider, and never touch a log/`Event`/
> `Debug` (THREAT-MODEL); v1 still ships read-only by default. Coverage holds (core
> 93.6%, aws-auth 90.0%, ssm 95.6%, aws 94.9%, mock 98.9%). **Still pending (next #80
> slice):** the in-matrix cell-edit affordance + confirm-diff dialog (the only producer
> of `ApplyEdits`, shipped here as the enabling rail) + a refresh on `WriteApplied`;
> separately, the **Secrets Manager** staged-put/CAS write (ADR 0001 — still the masked
> `Unsupported` stub, deferred as unverifiable without a live org). Design:
> [`docs/adr/0032-wire-write-seam-to-provider-port-and-read-write-lock.md`](docs/adr/0032-wire-write-seam-to-provider-port-and-read-write-lock.md).
>
> **Latest: the shared provider-agnostic Discovery orchestrator landed (ADR 0026, #33).**
> With two *real* Discovery walks to learn from, the engine was extracted **from
> evidence** as a **dual-layer interface**: a `core` `Orchestrator<S: Steps>` owns all
> the walk *sequencing* (auto-collapse singletons, stop at the first `Ask`/`Input`,
> resume, clamp) and speaks only `Choice`/`Step`/`What` — **zero AWS vocabulary**;
> each Provider supplies its *method* as a `Steps::next(chosen: &[String]) -> StepPlan`
> impl (the inner seam that lets one auth layer swap resource backends). The unlock:
> every Provider only ever needs each pick's `Selectable::key` downstream, so the
> engine type-erases to `Choice { key, label }` and accumulates chosen **keys** in one
> `chosen: Vec<String>` — the heterogeneous typed picks and per-step `Awaiting` enums
> the two walks each carried are **deleted**. The shared `account → role → mint` front
> half moved to `janitor-aws-auth::authwalk::front_half` (repaying ADR 0024 Decision 6;
> `terminal_for` deduped there too); both AWS-family methods compose it with their own
> tail. `Discovery`/`SsmDiscovery` are now thin handles over `Orchestrator<…Steps>`
> with **unchanged** public surface, so the `Provider` port, worker, and presenter are
> untouched; the mid-walk advisory (ADR 0025) stays the method's state, drained via
> `Orchestrator::steps_mut()`. Behaviour-preserving: both crates' full discovery+session
> suites pass unchanged; coverage holds (core 94.5%, aws-auth 94%, aws 96.8%, ssm 95.5%).
> The two Provider crates stay separate (janitor-ssm still never depends on
> janitor-aws). **Still deferred:** a runtime "one AWS Provider, swappable method" (incl.
> per-Mapping method selection) unification — the dual layer *enables* it but it also
> varies `load`/`reveal`/`write`, beyond #33. Design:
> [`docs/adr/0026-shared-discovery-orchestrator-in-core.md`](docs/adr/0026-shared-discovery-orchestrator-in-core.md).
>
> **Latest: the remote-`.env` WRITE engine + transport landed (ADR 0029, B5 / #70).**
> Research against the `amazon-ssm-agent` source overturned ADR 0028's central
> assumption: **`AWS-StartNonInteractiveCommand` never connects stdin to the command**
> (its `InputStreamMessageHandler` discards all but `Ctrl-C`/`Ctrl-\`), so "base64
> over stdin" was mechanically impossible. **ADR 0029 supersedes that transport**:
> the write runs over **`AWS-StartInteractiveCommand`** (pty), streaming the base64
> content as `input_stream_data` over the data channel (off the CloudTrail-logged
> `Parameters`), tames the pty with `stty raw -echo`, and reads exactly `head -c N`
> bytes (a non-secret length prefix) so completion is deterministic — no fragile
> tty-EOF. It keeps ADR 0028's semantics: the `sha256` **CAS guard** (ADR 0001),
> the atomic `mktemp`/`--reference`(+`stat` fallback)/`mv` replace, and the
> `JANITOR_OK`/`JANITOR_CONFLICT` tokens. New code (all pure + unit-tested except the
> live `wss` socket): `dotenv_edit` (a **total** value encoder + the non-stomping
> textual `apply_edits`; this required an **ADR 0025 amendment** adding `\\` to the
> double-quoted grammar so every Value round-trips), the `WriteSession` MGS state
> machine + `write_command_output` driver (chunked `input_stream_data` + `FLAG_FIN`),
> `build_write_command`/`sha256_hex`/base64 encode + the `SsmFileWriter` shell, the
> `RemoteFileWriter` seam + fake, `source::write_dotenv`/`SsmWriter` (read→hash→apply
> →write with bounded **replay-on-fresh** conflict retry), and a human-gated
> `live-verify-ssm-write` binary. **Still pending:** live verification against a real
> box (the ADR 0029 checklist — pty readiness, `head -c N` byte-count, CAS conflict,
> `--reference` portability); the `Provider::apply_edits` port method + worker
> `ApplyEdits` command; and the lockable **read-write-mode unlock UX** (ADR 0004/0013)
> — v1 still ships read-only, the write path reachable only via the live-verify binary.
>
> **Latest: the second real Provider is LIVE-VERIFIED (ADR 0025, B4 / #65).** On
> 2026-06-07 `live-verify-ssm` read a real root-owned `600` `/opt/deferno/.env` off a
> real EC2 box end-to-end and printed the masked 49-entry matrix — **no
> `session-manager-plugin`, no Value leaked.** Bring-up surfaced four real fixes, all
> now in code+tests (ADR 0025 *Live verification*): (1) the AgentMessage **`MessageId`
> is half-swapped on the wire** (`mgs::frame` transposes the two 8-byte halves —
> reading it verbatim made every ack unrecognized → handshake-retransmit stall →
> truncation); (2) the session runs as **`ssm-user`** so the read uses **`sudo -n`**
> (the file is root-owned `600`); (3) the `sudo`/PAM/PTY path can fold a binary banner
> into the stream, so the read is **`base64`** (decoded + noise-filtered on our side,
> not a raw `cat`); (4) `AWS-StartNonInteractiveCommand` ends with **`channel_closed`
> and no `EXIT_CODE`** — a clean close is the completion signal. The **write** path
> (read-modify-write a few Entries, non-stomp) is designed in **ADR 0028** (command
> channel chosen over SFTP-over-SSM; SFTP can't `sudo` a root-owned file). The
> `janitor-ssm` remote-`.env`-over-SSM Provider reads a real file off a real
> EC2 instance over a **pure-Rust Session Manager (MGS) data channel** — no
> `session-manager-plugin` binary. The AgentMessage byte codec (`mgs::frame`) and
> the session state machine + driver (`mgs::protocol`) are pure, unit-tested logic;
> the `DescribeInstanceInformation`/`StartSession`/`GetDocument` SDK calls are
> replay-tested (ADR 0027); only the `wss` socket (`mgs::channel`) is the untested
> shell (`janitor-ssm` holds ~96% coverage). B4 also added **session-logging
> detection** (a `GetDocument`-backed `LoggingPreference` seam + the pure
> `session_logging_advisory` decision) that warns — via a new provider-agnostic
> `Provider::take_advisories` port method — in the Diagnostic Log and the Discovery
> wizard when a read would be archived to S3/CloudWatch; a `live-verify-ssm` binary
> and the GUI `--ssm` selector; and `docs/iam_setup.md`'s SSM least-privilege policy.
> **Still pending:** the **write** path (ADR 0028 — non-stomp, base64-over-stdin,
> hash-guarded, gated behind read-write mode; the one new capability is streaming
> stdin over MGS); and two minor live checks (the `GetDocument` on/off toggle under a
> role that *has* the permission, and KMS-on masked-failure). **#33/ADR 0026** can now
> extract the shared `core` Discovery orchestrator from the two real Provider shapes.
> KMS-encrypted SSM sessions are unsupported in v1 (the read fails masked).
> Design/decisions:
> [`docs/adr/0025-remote-dotenv-over-ssm-provider.md`](docs/adr/0025-remote-dotenv-over-ssm-provider.md).
>
> **Status: GUI↔AWS bridge landed (ADR 0012) — the matrix now reads real AWS.** The Cargo
> workspace now holds three crates under a CI lint/test/coverage lane:
> `janitor-core`'s offline bedrock (secret-shape model, zeroizing `Value`,
> `Config` load/save, comparison engine); a thin `janitor-gui` (Slint)
> tracer-bullet rendering the masked Aligned/Drift/Gap matrix (per-cell momentary
> reveal, sidebar Application switching, in-memory settings) from a mock
> `SecretSource`; and a new async `janitor-aws` crate implementing real Identity
> Center Sign-in (browser Auth Code + PKCE → in-memory SSO token →
> `GetRoleCredentials` → `GetSecretValue` → `SecretShape`) behind a tested
> `AuthenticatedSource` facade. All of `janitor-aws`'s brokering / orchestration /
> error logic is unit-tested against fakes; only the browser/loopback/SDK shell is
> untested by design (ADR 0010 §5). The `live-verify` binary is now a **guided
> sign-in**: browser → log in → auto-discovered account/role/secret (via
> `ListAccounts`/`ListAccountRoles`/`ListSecrets`, with a pure tested
> 0/1/many+remembered-default `select::resolve`), with the org + last pick
> remembered in `Config` (ADR 0011). The `--authorize-endpoint` flag is gone —
> the endpoint is read from `RegisterClient`'s response and `issuerUrl` is passed.
> **GUI↔AWS bridge landed (ADR 0012):** the GUI now feeds the masked matrix from
> **real** AWS via a worker-threaded `janitor-aws::Session` (lazy browser sign-in
> off the UI thread, one Application at a time; secrets resident only in the
> worker; reveal is an on-demand round-trip; whole-app error on any env failure);
> `JANITOR_MOCK=1` runs it offline on `MockSource`. **Still deferred:**
> discovery-driven column assembly, per-column error rendering, the typed
> `GetSecretValue` error mapping, and live re-verification (browser + real org)
> pending **Milestone B** — running `live-verify` against a real org to resolve
> the ADR 0010/0011 verify lists (incl. whether the start URL is accepted as
> `issuerUrl`). Design and plan:
> [`docs/adr/0012-gui-aws-bridge-worker-and-lazy-sign-in.md`](docs/adr/0012-gui-aws-bridge-worker-and-lazy-sign-in.md),
> [`docs/superpowers/specs/2026-05-31-gui-aws-bridge-design.md`](docs/superpowers/specs/2026-05-31-gui-aws-bridge-design.md),
> and [`docs/superpowers/plans/2026-05-31-gui-aws-bridge.md`](docs/superpowers/plans/2026-05-31-gui-aws-bridge.md).
> Domain glossary: [`CONTEXT.md`](CONTEXT.md); decisions: [`docs/adr/`](docs/adr/)
> (0001–0031); security posture: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).
> **Read those first** — this file only summarizes.

## What this is

**Janitor** is a cross-platform desktop application that is an **ephemeral client
onto AWS Secrets Manager**. It stores no secrets and no credentials of its own —
it borrows them on demand and forgets them. The name is the thesis: the janitor
holds the most keys, but Janitor itself keeps none.

Two core jobs:
1. **Drift detection** — compare the same logical Secret Set across N Environments
   (prod/staging/dev, possibly different AWS accounts and regions) in a masked
   matrix. Each Entry is **Aligned** (same everywhere), **Drift** (present
   everywhere, values differ), or **Gap** (missing in some) — Gap being the
   high-signal "Terraform/compose hole" finding.
2. **Safe mutation** — change a few Entries without ever accidentally overwriting
   the whole Set. This is the reason the tool exists (see ADR 0001).

## Non-negotiable invariants

These are the spine of the project. Violating one is never a "small" change —
surface it loudly (see [THREAT-MODEL.md](docs/THREAT-MODEL.md)):

- **Nothing secret touches disk.** No Values, no Credentials, no SSO-token cache.
  Config (locations only, never Values) is the *only* thing persisted. Hold
  secret material in zeroizing types (`zeroize`/`secrecy`); keep it out of
  `Debug`/`Display`/logs/errors.
- **Never stomp a Secret Set.** All writes go through the op-based, replay-on-fresh,
  atomic compare-and-swap engine in **ADR 0001** — never a naive `PutSecretValue`
  of the in-memory blob.
- **Read-only by default.** Mutating AWS calls are unreachable until the user
  deliberately switches into (lockable) read-write mode. v1 ships read-only.
- **Auth is Identity Center only, memory-only.** Browser Sign-in each launch; no
  static keys; role Credentials refreshed silently from the SSO token (ADR 0002).
- **`core` holds the secrets logic; a shell is a thin, softer-trust view.** Don't
  push auth/AWS/compare/write logic into either shell (ADR 0003). Both shells
  live in their own repositories (ADR 0036).

## Architecture (target)

- **`janitor-core`** — no GUI deps. Identity Center auth + per-Environment
  Credential model, Secrets Manager I/O, the non-stomping write engine, the
  comparison engine, Config load/save, secret-in-memory handling, and the shared
  presentation seams (`errors`, `logpane`, `pane`, `reveal`, `rows`, `sidebar`).
  **Target ≥80% test coverage** — this is where correctness is proven.
- **`janitor-app`** — the worker thread, the `Command`/`Event` protocol every
  shell speaks, the AWS composition root, and the UniFFI boundary (`ffi`, behind
  the optional `uniffi` feature). It sits above the adapter crates because it
  names them all, which `janitor-core` cannot do (ADR 0035, Amendment
  2026-08-21). No coverage gate: it is the I/O loop and the composition root.
  `JanitorKit.xcframework` is built from this crate.
- **`Janitor-macos`** — the SwiftUI shell, in its own repository. It resolves
  `JanitorKit` as a checksum-pinned SwiftPM binary target and never compiles
  Rust. Set `JANITORKIT_LOCAL=1` to build it against this repository's
  `build/apple/JanitorKit.xcframework` instead of the published zip.
- **`Janitor-slint`** — the thin Slint view, in its own repository. It links
  Slint, so it is the one GPL-3.0-only component; everything else is Apache-2.0.
  It holds the
  comparison matrix (sortable, filterable by Entry name incl. prefix clusters),
  masked cells with momentary per-cell reveal, confirm-diff dialogs, browser
  launch. No secret logic. It names no adapter crate; it drives `janitor-app`. It
  takes the core by Cargo path from a checkout beside this one, so it does not
  build from a clean clone alone. It also owns the desktop release lane and the
  `vX.Y.Z` version authority.

## Commands

> Standard Cargo, valid once the workspace is initialized. Verify against the real
> `Cargo.toml` / workspace layout once it exists.

```bash
cargo build                       # build the workspace
cargo test --workspace            # all crates (core + app + janitor-aws fakes)
cargo test --workspace --all-features   # + janitor-app's UniFFI boundary tests (what CI runs)
cargo test -p janitor-core <name> # a single core test (substring match)
cargo test -- --nocapture         # show test stdout/stderr
cargo clippy --all-targets        # lint
cargo fmt                         # format
cargo llvm-cov -p janitor-core    # core coverage (≥80% gate)
cargo llvm-cov -p janitor-aws --ignore-filename-regex 'src/bin/'  # aws lib coverage (≥80% gate, ADR 0016)

# Running a shell (#106): both live in their own repositories, checked out beside
# this one. The Slint one takes the core by Cargo path.
cd ../Janitor-slint && cargo run          # real AWS via the worker bridge (browser sign-in)
JANITOR_MOCK=1 cargo run                  # offline mock — bash
$env:JANITOR_MOCK=1; cargo run            # offline mock — Windows PowerShell

# Swift bindings for the UniFFI boundary (ADR 0035 / #95). On macOS it also
# compiles the generated Swift as module JanitorKit and verifies the interface.
./scripts/generate-swift-bindings.sh

# The Apple artifact (ADR 0035 / #104): JanitorKit.xcframework and its zip, into
# build/apple. Needs full Xcode and both Darwin targets. It verifies the emitted
# interfaces, then links and runs a consumer against the finished slice.
rustup target add x86_64-apple-darwin      # aarch64-apple-darwin comes with the Mac
./scripts/build-xcframework.sh

# Publishing it: tag kit-vX.Y.Z, which must equal janitor-app's crate version.
# That is a different lane from Janitor-slint's vX.Y.Z, which versions that
# repository's desktop packages. Needs the depot publisher role (#105).
git tag kit-v0.1.0 && git push origin kit-v0.1.0

# janitor-aws human-gated binaries (ADR 0010 Milestone B — need a browser):
# Identity Center org + permission-set setup for these: docs/iam_setup.md
cargo run -p janitor-aws --bin loopback-spike   # browser↔loopback shell, no AWS
cargo run -p janitor-aws --bin live-verify -- … # live Identity Center round-trip
```

## Working agreements

- **Decisions get ADRs.** When you make a hard-to-reverse, non-obvious,
  real-trade-off choice, add `docs/adr/NNNN-slug.md` (see existing ones for
  format) rather than burying it in a diff.
- **New domain terms go in `CONTEXT.md`**, and only there — it is a glossary, not
  a spec or scratchpad. Keep implementation detail out of it.
- **ADR 0001 has open API-behavior items** ("verify against the live API")—
  resolve those with real AWS calls before relying on the write path.

## Agent skills

### Issue tracker

Issues and PRDs are tracked as GitHub issues (`Circuit-Stitch/Janitor`) via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary — `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context — `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
