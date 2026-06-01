# Packaging with cargo-packager, a Fedora-native rpm, and signed-only Windows

**Status:** accepted

## Context

Janitor had no packaging story: no app icon, no bundles, no installers, and a
single test-only CI lane (`ci.yml`, ubuntu-only). The project's thesis is
cross-platform desktop, but the maintainer's actual daily drivers are **Fedora**
(this dev VM) and **Windows 11**; macOS is wanted *later*. A throwaway placeholder
icon (an Inkscape SVG) was the trigger, but "give it an icon" expanded into
"stand up real distributable packaging," so the irreversible choices are recorded
here rather than buried in build config.

The requested artifacts are **`.rpm` + `.deb` + AppImage** on Linux and a
**signed** Windows installer, with Apple deferred. Two facts shaped the design:

- **An Ubuntu-built rpm is wrong on Fedora.** rpm/deb/AppImage bake in the build
  host's glibc, and an rpm built in the Debian world declares Debian package names
  (`libfontconfig1`) that don't exist on Fedora (`fontconfig`). Since Fedora is an
  install target, the rpm must be built **natively**. AppImage wants the *opposite*
  (oldest glibc for portability), so the two can't share one Linux environment.
- **Windows code signing has external lead time.** Azure Trusted Signing requires
  identity validation that takes days. We refuse to ship unsigned Windows binaries
  (SmartScreen hostility, and it sets a bad precedent for a security tool), so the
  Windows release path must stay *closed* until signing is real — without holding
  Linux releases hostage to Azure's queue.

Bundler options evaluated:

- **`cargo-packager`** (CrabNebula; the de-Tauri'd general bundler) — one config
  emits deb, AppImage, NSIS, and MSI/WiX for a plain Rust binary, with
  first-class Windows + macOS signing hooks. **It has no rpm format** (its
  Linux outputs are deb, AppImage, and pacman) — the gap that forces the hybrid
  below.
- **Native combo** (`cargo-deb` + `cargo-generate-rpm` + appimage tooling +
  `cargo-wix` + `winresource`) — maximum control, but ~5 tools and 5 configs to
  keep in sync.
- **`cargo-dist`** — excellent CI ergonomics, but its output shapes are archives +
  curl/MSI installers, not native deb/rpm/AppImage.
- **`cargo-bundle`** — no rpm, no AppImage, effectively unmaintained.

## Decision

**Bundler (hybrid).** cargo-packager has no rpm format, and rpm is the priority
target — so a single bundler is impossible. Split ownership:

- **`cargo-packager`** (`[package.metadata.packager]`) owns **deb + AppImage +
  signed Windows** (NSIS/WiX) — its real strengths, including the Windows /
  Apple-later signing hooks.
- **`cargo-generate-rpm`** (`[package.metadata.generate-rpm]`) owns the
  **Fedora-native rpm**. It is pure-Rust (no `rpmbuild`), auto-extracts ELF
  soname dependencies, and lets us declare Fedora package `Requires` explicitly —
  exactly the native-deps control rpm needs. (Renderer libs `libxkbcommon` /
  `mesa-libGL` are `dlopen`'d, not in the ELF `NEEDED`, so the explicit `Requires`
  are load-bearing, not redundant with the soname auto-detection.)

The full native-combo remains the documented fallback if cargo-packager ever
fights us on deb/AppImage/Windows. The `.exe`'s *embedded* icon (what
Explorer/taskbar show for the raw binary) is neither tool's job — `winresource`
(a `cfg(windows)` build-dependency) handles it regardless.

**Identifier.** `com.circuitstitch.apps.janitor` — reverse-DNS off a domain the
maintainer owns (`circuitstitch.com`); one identifier across the Linux `.desktop`
app-id, Windows upgrade identity, and the eventual macOS `CFBundleIdentifier`.

**Icon.** The source SVG embedded a 1254×1254 PNG *plus* 195 vector paths; the
PNG is dropped, leaving a true-vector (but dense, ~1.75 MiB auto-traced) SVG. That
cleaned **`janitor-gui/assets/icon.svg` is the committed source of truth**. The
derived raster set — hicolor PNGs (16→512) and a multi-res Windows `.ico` — is
**generated *and committed*** (`janitor-gui/assets/icons/`) by a committed regen
script (`gen-icons.sh`: `resvg` for SVG→PNG, ImageMagick to pack the `.ico`). Both
CI and a local `cargo packager` then need **no rasterizer installed**, and builds
are byte-reproducible; the cost is generated blobs in git, regenerated on art
change. The **runtime window icon** is set declaratively on both `MainWindow` and
`ManageWindow` via Slint's `Window.icon: @image-url(...)`, pointed at a **generated
PNG** — *not* the SVG: embedding the dense 1.75 MiB SVG and rasterizing 195 paths
at every startup is wasteful, so the window icon is just another consumer of the
generated set. (Visual fidelity of the rendered icon stays a manual check —
consistent with ADR 0021's "pixels are verified by running.")

**Linux build topology.** Two environments, by necessity:

- **rpm (cargo-generate-rpm) → a `fedora:latest` container** (native deps:
  `fontconfig`, `libxkbcommon`, `mesa-libGL`, `libxcb`…). First-class — it's an
  install target.
- **deb + AppImage (cargo-packager) → `ubuntu-22.04`** (old glibc floor for
  portability). Best-effort tier.

**Releases.** A net-new workflow triggers on a pushed tag `v*` (plus
`workflow_dispatch` for dry-runs), builds the matrix, and uploads to a **draft**
GitHub Release for human review. The release version is `janitor-gui`'s crate
`version`; CI asserts the tag matches it. PRs / `main` pushes stay on the existing
test-only CI — bundling only on tags.

**Windows signing.** **Azure Trusted Signing**, authenticated from CI via **GitHub
OIDC federation** (`azure/login` federated credential) so **no long-lived Azure
secret is stored in GitHub** — consistent with the project's memory-only,
nothing-secret-at-rest posture (ADR 0002, THREAT-MODEL). **Hard policy: no
unsigned Windows artifact is ever published.** Enforced *by construction* — the
Windows job is **skip-gated** on a repo flag/secret (`WINDOWS_SIGNING_ENABLED` +
Trusted-Signing config); while absent the job is **skipped** (not failed), so a
tagged release simply ships Linux artifacts with a green build. When Azure identity
validation clears, the flag flips and signed Windows artifacts flow with no
workflow rewrite. SignPath Foundation (free for OSS) was considered and kept as a
fallback; Azure won on self-serve control + Microsoft-rooted SmartScreen
reputation.

**macOS** is deferred: a commented packager slot only — no job, no `.icns`, no
signing/notarization — until there is a Mac to build and sign on.

## Consequences

- The icon is an explicit **placeholder**; the committed SVG will be replaced, and
  `gen-icons.sh` makes regenerating the whole set a one-liner.
- Generated icon blobs live in git and must be regenerated when the art changes
  (the script is the contract; drift is the risk).
- The Linux release needs **two** build environments (a Fedora container + an
  Ubuntu runner); a single-runner shortcut would reintroduce the wrong-deps rpm.
- **Windows releases are blocked until Azure validation completes**, by design;
  Linux releases are unaffected, and no path through the workflow can emit an
  unsigned `.exe`/`.msi`.
- This ADR records the design; only the **local slice** (cleaned SVG + committed
  icon set + regen script + window icon + `cargo-packager` config + a verified
  local Fedora rpm) lands with it. The **CI release workflow** and **Azure Trusted
  Signing enablement** can only be proven on a real tag push / once Azure clears,
  so they are tracked as GitHub issues rather than shipped unverified.
- Packaging touches **no secret material** — it is outside the threat model, and
  the window icon is pure Slint markup, so it stays within ADR 0003's thin-view
  split (no logic moved into the GUI).
