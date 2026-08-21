# Three repositories: the core, the Slint shell, and the macOS shell

**Status:** accepted, 2026-08-20

Follows [ADR 0035](0035-swiftui-macos-shell-over-uniffi.md), which adds a second
shell. Supersedes ADR 0035's assumption that both shells live in one repository.

## Context

ADR 0035 adds a SwiftUI macOS shell beside the Slint one. The core then has two
consumers on two toolchains, where it has always had one.

Circuit Stitch already has a shape for this, and a shape for the opposite case.

`WirelessOrderTelegraph-sound` is a component shared by Gonger, an Android app,
and `WirelessOrderTelegraph-kmp`. It has its own repository and publishes
artifacts to `depot.circuitstitch.com`.

Gonger holds its own Rust in `src/` and its own SwiftUI app in `apple/`, in one
repository. It never split them. What it takes from the depot is the shared
engine, and its own Rust takes that engine by Cargo path to a sibling checkout
rather than by version, so a change is heard on the next build with nothing to
publish and nothing to bump.

So the rule is not "Rust and Swift live apart." It is that a component with
several consumers gets its own repository, and a product's own core stays with
its app. A second shell moves Janitor from the second case into the first.

**The core does not move.** `Janitor` already holds 21,066 lines across five
crates, 36 ADRs, `CONTEXT.md`, `THREAT-MODEL.md`, and the per-crate coverage
gates. `janitor-gui` is 7,403 lines and is a leaf — nothing in the workspace
depends on it. Extracting the core would relocate everything expensive and leave
the project's name on a Slint app. Extracting the shells moves one leaf.

## Decision

**Three repositories.**

| Repository | Holds | Produces |
|---|---|---|
| `Janitor` | `janitor-core`, `-aws`, `-aws-auth`, `-ssm`, `-mock`. Every ADR, `CONTEXT.md`, `THREAT-MODEL.md`. | `JanitorKit.xcframework` on the depot. The Cargo crates. |
| `Janitor-slint` | `janitor-gui`. | rpm, deb, AppImage, MSIX. |
| `Janitor-macos` | The SwiftUI app and its Xcode project. | The Mac App Store build. |

**The name is `Janitor-macos`.** The shell is macOS only. `-ios` would name a
platform it does not target.

**`Janitor` keeps its name and its history.** It is the core and the producer.

**`Janitor-slint` takes the core by Cargo path to a sibling checkout.** This is
what Gonger does. Cargo cannot fetch a binary over plain HTTPS, so the depot is
not reachable from Rust, and a path keeps the "nothing to publish, nothing to
bump" property for the shell that changes with the core. CI checks out `Janitor`
beside it, the way `WirelessOrderTelegraph-kmp` checks out its wire.

**`Janitor-macos` takes the core as the published xcframework**, pinned by URL
and checksum, and by a local SwiftPM path during development. A binary target is
the only way an Xcode project can take Rust, and the local path keeps iteration
free while the UniFFI boundary is still moving.

**Every existing ADR stays in `Janitor`.** That includes the shell decisions —
0003, 0020, 0021, 0023, 0030. Splitting a decision log fragments it. New
shell-specific decisions go in the shell's own repository and link back.

**`THREAT-MODEL.md` stays in `Janitor`.** The security posture is a property of
the whole product. Both shells link to it rather than copying it.

**Each repository versions itself.** The core's version is what the shells pin.
Each shell versions for its own store. There is no single "Janitor 0.2.0" across
three repositories, the same way `wot-sound` is 0.3.0 while Gonger is 0.1.0.

**The order is fixed by one dependency.** Move the worker and the shared seams
into `janitor-core` first, then move the Slint shell out, then build the macOS
shell in its own repository from the first line.

## Considered options

- **Extract the core into a new repository.** The literal form of the request.
  Rejected: it moves 21,066 lines, 36 ADRs, and the threat model, and leaves the
  project's name on the Slint app. Moving the leaf reaches the same three-repository
  end state and moves one seventh as much.
- **Keep one repository.** What Gonger does. Rejected once there are two shells:
  that is the condition that earned `wot-sound` its own repository. It would also
  leave a checksum-pinned artifact sitting beside the source it was built from,
  which can drift silently.
- **`Janitor-slint` takes the core by git tag.** Reproducible, and it builds from
  a clean clone with no sibling. Rejected: it puts a publish-and-bump step between
  every core change and the shell that consumes it, which is the cost Gonger's
  Cargo path exists to avoid. Revisit if a second person works on the shell alone.
- **Publish the core to crates.io.** Rejected: it makes an internal interface
  public and adds a release gate, for a consumer set of two that we own.
- **Build the macOS shell in `Janitor` first, then move it.** Rejected: the shell
  is zero lines today, so this is the cheapest moment it will ever be to place it
  correctly.

## Consequences

- **Moving the shared logic into `janitor-core` becomes a hard prerequisite.**
  About 2,370 lines — `worker.rs` plus `rows.rs`, `logpane.rs`, `sidebar.rs`,
  `pane.rs`, `reveal.rs`, and `errors.rs` — are bin-local modules in
  `janitor-gui`, which has no `lib.rs`. Both shells drive them, so they must reach
  the core before the Slint shell moves out. What is left behind is `main.rs`,
  `view_tests.rs`, `scrollbar.rs`, and `update.rs` — Slint and Windows only.
- **`Janitor-slint` does not build from a clean clone alone.** It needs `Janitor`
  beside it. CI needs a checkout action, and the README needs to say so.
- **The version authority moves.** `janitor-gui/Cargo.toml` is what
  `verify-version`, the bump job, and the release tag all read today. That whole
  chain moves to `Janitor-slint` and stops describing the core.
- **The release workflow splits three ways.** `Janitor` keeps the workspace
  test, clippy, and coverage lanes and gains the xcframework publish job.
  `Janitor-slint` takes the rpm, deb, AppImage, and MSIX lanes. `Janitor-macos`
  has no GitHub Actions release at all, because Xcode Cloud builds it.
- **The unsigned macOS `.dmg` job has no home.** It builds a Slint binary for a
  platform that now has a native shell. Drop it, or keep it in `Janitor-slint`
  until the macOS shell ships.
- **The issue tracker fragments.** The epic and the core slices stay in
  `Janitor`. Shell issues move when their repository exists.
- **The license question is unchanged.** `JanitorKit.xcframework` is compiled
  from GPL-3.0-only crates, so the obligation follows the artifact into whichever
  repository consumes it. Splitting repositories does not answer it.
- **Three repositories need three sets of branch protection, labels, and CI
  secrets.** The Azure signing variables follow the MSIX to `Janitor-slint`. The
  depot publisher role stays with `Janitor`.
- **Git history splits.** Moving `janitor-gui` with `git subtree split` or
  `git filter-repo` preserves its history in the new repository. Doing it with a
  plain copy does not, and the Slint shell carries real history worth keeping.
