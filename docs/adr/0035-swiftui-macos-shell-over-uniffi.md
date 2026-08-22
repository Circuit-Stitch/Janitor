# SwiftUI macOS shell over the Rust core via UniFFI

**Status:** accepted, 2026-08-20

Supersedes [ADR 0003](0003-core-gui-split-slint-and-secret-display.md)'s toolkit
choice on macOS only. ADR 0003's core/GUI split and its secret-display stance
both stand unchanged. Research:
[`docs/superpowers/specs/2026-08-20-swiftui-shell-research.md`](../superpowers/specs/2026-08-20-swiftui-shell-research.md).

## Context

Janitor ships to Linux and Windows and has no macOS distribution channel. The
macOS artifact is an unsigned `.dmg`. Gatekeeper warns on first open.

The Mac App Store is the wanted channel. Three things blocked it.

Slint is used under its GPLv3 option, so Janitor is GPL-3.0-only. GPLv3 section
10 forbids imposing further restrictions on the rights it grants. The App Store
terms impose them. Apple has removed GPL apps over this.

Janitor has no Xcode project. The sibling repos upload to App Store Connect with
`xcodebuild -exportArchive`, which needs one. That command is also what makes
cloud signing available, and cloud signing is why those repos store no
certificate and no provisioning profile anywhere.

The Mac App Store requires App Sandbox. The sandbox breaks the loopback OAuth
listener and the configurable browser command.

A native macOS shell answers all three at once. Slint is confined to
`janitor-gui`, so a second shell that does not link it produces a macOS binary
with no GPL obligation from Slint. A SwiftUI app is an Xcode project by
construction. The sandbox questions become answerable rather than hypothetical.

## Decision

**Add a SwiftUI shell for macOS. Keep `janitor-gui`.** The Slint crate remains
the Linux and Windows shell. It keeps the Fedora rpm, the deb, the AppImage, and
the MSIX with App Installer updates ([ADR 0034](0034-windows-auto-update-via-msix-and-app-installer.md)).
This is a second shell, not a replacement.

> **Amended by [ADR 0036](0036-three-repos-core-slint-shell-macos-shell.md).** The
> two shells live in their own repositories, `Janitor-slint` and `Janitor-macos`.
> This repository keeps the core and publishes to both. Every decision below still
> holds; only where the shells live has changed.

**The FFI is UniFFI, and the boundary is the worker's `Command`/`Event`
protocol.** Twelve commands go in. Twenty-three events come out. No `async fn`
is exported. Swift gets a fire-and-forget call plus an `AsyncStream` of events,
never `try await`.

**UniFFI is chosen because it has no Rust-to-foreign borrow type.** `&[u8]`
flows foreign-to-Rust only. Foreign trait methods cannot take references, so
every event payload crosses by value. "Copy the secret out, never lend a pointer
into a zeroizing buffer" becomes a compiler rule rather than a review rule. That
is the one genuinely new risk a foreign shell introduces, and this choice
removes it structurally.

**`janitor-core` holds the boundary.** No new crate. The FFI boundary is core's
public API expressed for a foreign caller, not view logic, so it sits inside
ADR 0003's line rather than across it.

> **Amended 2026-08-21 by the Amendment below.** The boundary and the worker moved
> to a new `janitor-app` crate instead, because a Cargo cycle makes this
> impossible. Everything else in this section stands.

Core absorbs today's bin-local `worker.rs` wholesale — `Command`, `Event`,
`run_loop`, `build_provider`, `build_family`, `discovery_event`, `write_event`,
`surface_advisories` — plus the shared seams `reveal.rs`, `rows.rs`,
`sidebar.rs`, `pane.rs`, `errors.rs`, and `logpane.rs`. All of it is driven by
**both** shells today, which is why none of it can live in an Apple-only crate.

Core declares no `staticlib` crate type. The Apple build produces one on demand
with `cargo rustc --lib --crate-type staticlib`, so Linux and Windows builds
never link an unused archive. The cost is that `uniffi` and `uniffi_macros`
compile into every build, and `setup_scaffolding!()` emits `#[no_mangle]` shims
that go unused off macOS. Both are accepted.

**Swift receives a revealed Value as an ordinary `String`.** This matches what
Slint's `SharedString` already does. ADR 0003 reasoned it through: to be
human-legible the glyphs are already in the framebuffer, so the heap-string
lifetime sits below the floor the display surface sets. The single plaintext
crossing is declared as a UniFFI custom type with an explicit `lower` closure,
so it is one greppable symbol.

**Revealed Values are not hidden from VoiceOver.** macOS gates third-party
accessibility access behind an explicit TCC grant, and screen recording behind a
separate one. Both channels are gated the same way, so hiding one while the
other stays open is the asymmetry ADR 0003 already rejected. The stronger reason
is that `.accessibilityHidden(true)` on a reveal cell would make the feature
unusable for a blind operator. That is exclusion, not hardening. **This decision
is macOS-only.** Windows UI Automation has no equivalent permission gate, so
`janitor-gui` inherits nothing from it.

**The app ships with three entitlements.** `com.apple.security.app-sandbox`,
`com.apple.security.network.client`, and `com.apple.security.network.server`.
Nothing else. No keychain group, no file exceptions, no hardened-runtime
exceptions.

**`CommandBrowser` is compiled out on macOS.** A sandboxed child inherits the
container, so a spawned browser loses its profile, its cookies, and its
network-server rights. The spawn succeeds, so the failure is silent. On macOS a
non-`@native` `browser_command` maps to `WebAuthSession`, never to `Default`, so
session isolation is never silently downgraded.

**Xcode Cloud builds and uploads, not GitHub Actions.** This matches AnimalSpin.
Xcode Cloud owns signing, the `.pkg`, and the App Store Connect upload, so the
repository holds no certificate, no provisioning profile, and no App Store
Connect API key. The unproven Mac Installer Distribution certificate and the
unreachable organization secrets both stop being problems, because neither is
needed.

**The Xcode project is generated and gitignored.** `apple/project.yml` is the
source. `ci_scripts/ci_post_clone.sh` installs XcodeGen and regenerates the
project, the way AnimalSpin's does. Xcode Cloud fails without it: a fresh clone
has no project to build.

**Xcode Cloud never runs cargo.** The Rust reaches it as a prebuilt
`JanitorKit.xcframework`, built from `janitor-core`, published to `depot.circuitstitch.com`, and consumed by
a SwiftPM `binaryTarget` pinned by URL and checksum. This is the Gonger pattern.
Xcode Cloud has no cargo cache, and Janitor's tree includes `aws-lc-sys`, so
building the core on every Xcode Cloud run would compile the AWS SDK and a large
C library from cold every time.

**The xcframework carries the Swift.** One static framework per slice holds the
UniFFI-generated Swift compiled over the Rust archive, folded together with
`libtool` so the framework contains the core rather than pointing at it. It is
built with `-enable-library-evolution` so a `.swiftinterface` is emitted and any
Xcode can consume it. macOS-only means one slice, `macos-arm64_x86_64`, where
Gonger needs three.

**GitHub Actions keeps Linux and Windows and gains the publish job.** `setup`,
`verify-version`, `linux-rpm`, `linux-portable`, `macos`, and `windows` are
unchanged. A new job builds and publishes the xcframework on a tag. The existing
unsigned `.dmg` job stays while `janitor-gui` is still the Linux and Windows
binary.

## Considered options

- **Ship to App Store Connect from the Slint app.** Rejected: no Xcode project,
  so no cloud signing, and Slint's GPL still reaches the binary.
- **Relicense and keep Slint.** Rejected: Slint's royalty-free option would
  answer the license, but the Xcode-project and sandbox problems remain.
- **Delete `janitor-gui`.** Rejected: it would drop the Windows MSIX and the
  Fedora rpm, which ADR 0022 calls the priority install target.
- **swift-bridge.** Rejected on the borrow constraint. Its `&str` maps to
  `RustStr`, a pointer plus length. Its own safety chapter demonstrates a
  use-after-free it states it cannot mitigate. Handing Swift a `RustStr` into a
  buffer Rust later zeroes would be one keyword away in every signature. It has
  also been dormant since January 2026.
- **cxx or Swift C++ interop.** Rejected: Swift does not import C++ class
  templates, and `Slice<T>`, `Box<T>`, and `Vec<T>` are exactly that.
- **cbindgen with a hand-rolled C ABI.** Recorded as Plan B. It emits headers
  and no marshalling, so twelve commands and twenty-three events become hundreds
  of lines of hand-written unsafe, and the borrow rule degrades to a review rule.
- **A separate `janitor-ffi` crate for the boundary.** Rejected. The worker is
  driven by both shells, so an Apple-only crate holding it would force
  `Janitor-slint` to depend on that crate structurally — dragging UniFFI along by
  requirement rather than by accident.
- **A `janitor-view` crate for the shared presentation seams.** Rejected for the
  same reason: once the worker is in core, those seams have no separate consumer
  set to justify a crate of their own.
- **The Device Authorization grant instead of the loopback listener.** It would
  delete `network.server` and the listener entirely. Deferred: it costs a new
  `OidcClient` method, a new wizard step, and worse sign-in. Hold it as insurance
  against App Review refusing `network.server`.
- **GitHub Actions for the App Store upload.** Rejected in favor of Xcode Cloud,
  which is the house pattern and which removes the certificate and secret
  problems rather than solving them. The full GitHub Actions job was designed
  before this and is recorded in the research spec.
- **Building the Rust on Xcode Cloud.** Rejected on build cost. Janitor is a
  public single repository, so Gonger's credential argument for the depot does
  not apply here — Xcode Cloud could clone and build it. It would recompile the
  AWS SDK and `aws-lc-sys` from cold on every run, with no cargo cache.
- **Republishing the xcframework on every push to main.** Rejected for now. It
  would remove the manual version-and-checksum step at the cost of a bot commit
  per Rust change.

## Consequences

- **Trust boundary 2 is reworded for Swift.** `THREAT-MODEL.md` names Slint
  widget state; on macOS the plaintext lives in SwiftUI `@State` instead. The
  boundary itself does not move.
- **SwiftUI retains `@State` longer than Slint retains a property.** Clear on
  blur and timeout is easier to call than to guarantee. Keep the reveal in a
  short-lived view with a stable identity and no animation.
- **`ITSAppUsesNonExemptEncryption` must be determined, not guessed.** Janitor
  bundles `aws-lc-rs`, `aws-lc-sys`, `ring`, and `rustls`. The sibling repos'
  reasoning that every primitive comes from the operating system does not carry
  over. This is a legal statement.
- **The App Store Connect app record and the App ID must exist before the first
  run.** Xcode Cloud mints certificates and profiles. It does not create app
  records.
- **Janitor needs a depot tenant.** Add a `"janitor"` entry to the tenants map in
  the depot repository's `infra/terraform/serve/main.tf` and apply it. The
  immutable form GitHub puts in the OIDC subject is
  `Circuit-Stitch@222346232/Janitor@1254222001`. Circuit-Stitch applications live
  under `com.circuitstitch.apps`, so set `maven_prefix` deliberately rather than
  taking the default, even though Janitor publishes no Maven artifact.
- **Every Rust change needs a tag, a publish, and a checksum bump.** Publishing
  is what produces the checksum, so it cannot be written in `Package.swift`
  first. The depot writes a version once and never overwrites it, so the URL and
  the checksum describe one sequence of bytes forever. This is real friction, and
  it is heavier here than in Gonger: the sound engine is a separate slow-moving
  component, while Janitor's Rust is the application.
- **The module name cannot equal a public type name.** Library evolution prints
  types fully qualified in the `.swiftinterface`, so a module and a public type
  sharing a name make the interface fail to verify. Check the UniFFI-generated
  type names against `JanitorKit` before publishing.
- **Config relocates into the sandbox container.** `$HOME` is redirected, so
  `directories` resolves inside it and the old file is unreadable. Existing
  Developer ID users lose their saved Applications and Mappings unless a
  migration is written. `getpwuid` is *not* redirected, so `dirs-sys` can fall
  back to a path outside the container; `load_from` must treat `PermissionDenied`
  as "no config" the way it already treats `NotFound`.
- **The bundle identifier conflict has to be settled.** Packaging declares
  `com.circuitstitch.apps.janitor`. `ProjectDirs` builds `com.Janitor.Janitor`.
  Under sandbox they nest. The stable-path contract breaks once either way.
- **`GPL-3.0-only` is still declared on all six crates.** Dropping Slint from the
  macOS build removes the cause of the GPL, not the license. Relicensing is a
  separate decision and is feasible: one copyright holder across 232 commits.
- **The macOS build is universal by default.** A macOS Release archive carries
  `arm64` and `x86_64`, and the `macos-arm64_x86_64` xcframework slice must carry
  both to match. Today's `.dmg` is Apple Silicon only. Decide this once and set it
  in both places.
- **Twenty-six Slint view tests ([ADR 0021](0021-gui-view-tests-via-slint-testing-backend.md))
  do not port.** They keep covering `janitor-gui`. The SwiftUI shell needs its
  own answer, and about 850 lines of pure GUI seams need a home that keeps them
  tested.
- **The generated Swift must compile with `nonisolated` default actor
  isolation.** Under Xcode 26's `SWIFT_DEFAULT_ACTOR_ISOLATION=MainActor` the
  UniFFI bindings inherit `@MainActor` and fail to build. Exporting no `async fn`
  buys out of the second known issue as well.
- **No repository here has run a macOS App Store upload before.** The sibling
  pattern is proven for iOS only. The first armed run is the experiment.

## Amendment 2026-08-21 — the boundary lives in `janitor-app`, not `janitor-core`

The decision above put the worker and the FFI boundary in `janitor-core`. Cargo
rejects that. `worker.rs` names `janitor-aws`, `janitor-aws-auth`, and
`janitor-ssm`, and all three depend on `janitor-core`, so moving the worker into
core makes the package graph cyclic. Verified against the real workspace:

```
error: cyclic package dependency: package `janitor-aws` depends on itself
```

The composition root is what forces it. `build_family` is the only place both
AWS-family method tails are named together, so it has to sit above every adapter
crate. Nothing above them exists today except the shell.

**A new `janitor-app` crate holds the worker and the composition root.** It
depends on `janitor-core` and on all four adapter crates. `Command`, `Event`,
`run_loop`, `discovery_event`, `write_event`, `surface_advisories`,
`ProviderKind`, `spawn`, `build_provider`, and `build_family` live there. The
UniFFI boundary goes there too, and `JanitorKit.xcframework` is built from
`janitor-app` rather than from `janitor-core`.

**The six presentation seams still go to `janitor-core`.** `errors`, `logpane`,
`pane`, `reveal`, `rows`, and `sidebar` name no adapter crate, so they cross no
cycle. They landed in core as originally decided, and core's coverage rose to
95.8%.

**This is not the rejected `janitor-ffi`.** That option was rejected because an
Apple-only crate holding the worker would force `Janitor-slint` to depend on it
and drag UniFFI along by requirement. `janitor-app` is not Apple-only. It is the
application layer both shells drive, and the Slint shell depends on it because
that is where the worker it already used now lives. UniFFI stays optional there,
so a Slint build need not compile it.

**Core keeps its name and its meaning.** It is still the security-critical
domain, still free of AWS, and still gated at ≥80% lines over pure logic. The
alternative — renaming core to `janitor-model` and rebuilding `janitor-core` on
top — was rejected: it rewrites 108 references across 27 files in four crates,
relocates about 4,200 lines, and leaves the surviving core gate measuring the
untested worker shell.

**`janitor-app` carries no coverage gate.** It holds the worker's I/O loop and
the composition root, both untested by design. It sat inside the ungated
`janitor-gui` until now, and it measures 80.2%, which is too thin a margin to
gate on.

**The update events leave the shared protocol.** `Command::CheckForUpdates`,
`Command::InstallUpdate`, `Event::UpdateChecked`, and `Event::UpdateInstalled`
carried Windows MSIX types from `janitor-gui` (ADR 0034), and UniFFI cannot
export a type from a shell crate. Only the Slint shell ships an MSIX, so the rail
is shell-local: `janitor-gui` owns its own thread, its own current-thread runtime,
and its own two-command loop. The ADR 0034 guarantees are unchanged — manual-only,
off the UI thread, no network egress until the user clicks. The macOS shell needs
no equivalent, because the Mac App Store updates the app.

Consequence: ADR 0036's repository table gains a sixth crate in `Janitor`, and
`Janitor-slint` takes `janitor-app` by Cargo path alongside `janitor-core`.

## Amendment 2026-08-21 — the boundary as built (#95)

The Amendment above put the boundary in `janitor-app`. Building it settled four
things the decision left open.

**UniFFI is a Cargo feature, not a dependency.** `janitor-app` declares
`uniffi = ["dep:uniffi"]`, and `setup_scaffolding!()` plus the `ffi` module are
both behind it. A Slint build compiles none of it, which is what "UniFFI stays
optional there" has to mean in practice.

**The `janitor-core` types cross as `#[uniffi::remote]` mirrors.** The protocol
carries fifteen types that belong to `janitor-core` — `Config`, `Application`,
`Mapping`, `MatrixView`, `RowKey`, `AppError`, and the rest. The alternative was
to derive UniFFI on them in core, which would push `uniffi` and `uniffi_macros`
into all four adapter crates and both shells, and would put a foreign-bindings
concern inside the crate ADR 0003 keeps narrow. A mirror is a redeclaration of
the type's shape in `ffi.rs`, and the generated code destructures the real type,
so a field renamed, retyped, or added in core fails to compile at the boundary.
The cost is that the mirrors must be kept in step; the compiler is what enforces
it.

**`usize` is not one of UniFFI's primitives.** The protocol uses it for matrix
coordinates, choice indexes, and byte lengths. It crosses as `u64` through a
custom type, so the Rust signatures keep saying `usize` and Swift sees
`typealias Usize = UInt64`.

**The plaintext crossing is `janitor_core::secret::Plaintext`.** ADR 0035 asked
for one custom type with one `lower` closure. That needs a named type in the
protocol, and there were two bare ones: `Event::Revealed`/`Event::CopyValue`
carried a `String`, and `EnvEdit::Set` carried a `Zeroizing<String>`. Both are now
`Plaintext`, a zeroizing newtype in core whose only readers are `expose` and
`expose_owned`. So one symbol covers both directions: a revealed Value out, an
edit's new Value in. `Provider::reveal` returns it too, which closes the gap where
a revealed Value travelled the port as an unzeroed `String`.

**Verified against the real Swift toolchain.** `scripts/generate-swift-bindings.sh`
builds the staticlib, generates the Swift, and compiles it as module `JanitorKit`
under Swift 6, `nonisolated` default actor isolation, and library evolution. The
emitted `.swiftinterface` verifies, which is the check that would catch a module
and a public type sharing a name. The script fails if any exported function is
`async`. Swift gets `Command` with ten cases, `Event` with twenty-one, an
`EventSink` protocol, a `Worker` class with `start` and `send`, and `isRevealed`.

**The generator is its own package, outside the workspace.** `uniffi_bindgen`
pulls a template engine and a CLI parser, and a workspace-wide `--all-features`
lint or test run would compile all of it. `tools/uniffi-bindgen-swift` pins
`uniffi` exactly, and the script fails if that pin and `janitor-app`'s resolved
version disagree — a generator that does not match the scaffolding it reads emits
bindings that link and then misbehave.

Still open for #97: `Config` crosses as a record, but nothing exports
`Config::load` or `Config::save`. The tracer bullet is what needs them, and it is
what will show whether `ConfigError` should cross as a thrown error.
