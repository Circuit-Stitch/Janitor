# CI and distribution: cargo-packager bundles, Windows signed, macOS notarization deferred

**Status:** accepted

## Context

Janitor is distributed as a downloadable desktop application. We want automated
CI (lint/test on every change) and automated, tagged release artifacts users can
download. Code signing matters more than usual for a *secrets* tool — an
"unidentified developer" / SmartScreen scare screen on a credential manager
corrodes trust. Signing is per-OS, with very different cost and severity:

- **macOS** *hard-blocks* unsigned/un-notarized GUI apps downloaded from the
  internet (Gatekeeper), and notarization requires the Apple Developer Program
  ($99/yr).
- **Windows** only *warns* (SmartScreen, dismissible); Authenticode via Azure
  Artifact Signing (~$10/mo, now open to self-employed individuals) removes it.
- **Linux** has no signing gatekeeping.

An installer is **not** required for config storage: the app creates its per-OS
config directory at runtime on first launch (via the `directories` crate →
`%APPDATA%`, `~/Library/Application Support`, `~/.config`) regardless of how it
was delivered. Installer/signing is a *trust & UX* decision, independent of
config storage.

## Decision

**`cargo-packager` builds real native bundles for all four targets on tag.
Windows is Authenticode-signed in v1; macOS ships unsigned (with bypass docs) and
notarization is deferred; signing is gated to release-only CI.**

- **Tooling: `cargo-packager` from the start.** Chosen over `dist` because
  Janitor is a Slint GUI app, not a CLI: `cargo-packager` produces real windowed
  bundles (macOS `.app`/`.dmg`, Windows `.msi`/NSIS `.exe`, Linux AppImage/`.deb`)
  and has built-in signing + notarization hooks. `dist`'s sweet spot (tarball +
  shell/PowerShell installer) suits CLI tools and does not cleanly emit a `.app`.
- **Targets (v1):** `aarch64-apple-darwin` (Apple Silicon),
  `x86_64-apple-darwin` (Intel macOS), `x86_64-pc-windows-msvc`,
  `x86_64-unknown-linux-gnu`.
- **CI (every push / PR):** `cargo fmt --check`, `cargo clippy --all-targets`,
  `cargo test` — with `janitor-core`'s ≥80% coverage gate (ADR 0003). No signing
  secrets are reachable from this lane (so fork PRs are safe).
- **Release (on `vX.Y.Z` tag):** GitHub Actions runs `cargo-packager` per target
  and publishes a GitHub Release with the per-OS bundles attached. Tag-driven, so
  cutting a release is `git tag` + push.

**Signing in v1:**
- **Windows: Authenticode-signed** via **Azure Artifact Signing** (~$10/mo).
- **macOS: unsigned**, shipped with documented Gatekeeper bypass (right-click →
  Open, or `xattr -dr com.apple.quarantine Janitor.app`). Acceptable because the
  audience is the author + a small known group; for personal use, building on
  one's own Mac avoids quarantine entirely.
- **Linux: unsigned** (no gatekeeping).

**Signing is gated (release-only, protected environment):**
- Signing runs **only** in tag-triggered release jobs, inside a **protected
  GitHub Environment with manual approval**. CI on pushes/PRs never sees signing
  creds; fork PRs cannot reach them.
- Secrets live as GitHub **Environment secrets**, preferring **OIDC federation to
  Azure** (no long-lived secret stored) where `cargo-packager` / the Azure action
  supports it.

## Considered options

- **`dist` (cargo-dist)** — rejected as primary: great for CLI release CI but
  doesn't produce a true macOS `.app` bundle, which a GUI app needs.
- **macOS Developer ID notarization in v1 ($99/yr)** — deferred: the small known
  audience can bypass Gatekeeper, so the $99/yr isn't yet justified. It's a
  config + secrets change in the existing `cargo-packager` macOS step when wanted.
- **macOS TestFlight for the small user set** — rejected: still requires the
  $99/yr Apple Developer Program, *and* mandates App Store Connect + App Sandbox.
  The sandbox fights Janitor's needs (launch a browser, bind a localhost port for
  the PKCE redirect, write an arbitrary config dir, drive the clipboard). It costs
  the same as Developer ID while adding constraints — Developer ID is the better
  upgrade path if/when macOS signing is wanted.
- **Raw binaries (no bundles)** — rejected: a bare Mach-O / `.exe` is a poor,
  trust-eroding experience for a desktop secrets tool; `cargo-packager` gives real
  bundles for the same CI effort.

## Consequences

- **Windows installs cleanly; macOS users must bypass Gatekeeper** until
  notarization lands — documented in release notes / README, not a surprise.
- **Four targets means four runners**; Intel macOS doubles the macOS build matrix
  vs Apple-Silicon-only, accepted to support older Macs.
- **Building a Slint GUI in CI is not dependency-free**: the Linux runner must
  install GUI/system dev libraries (xcb/wayland/font dev packages, per Slint's
  backend requirements) before `cargo build`; macOS/Windows runners need their
  platform toolchains. The release workflow must document and pin these.
- **Azure Artifact Signing requires identity validation with periodic renewal**;
  if it lapses, Windows releases revert to unsigned. The release job must fail
  loudly (not silently ship unsigned) if signing credentials are unavailable.
- Bundle/artifact naming and the tag→release contract become a de-facto interface
  (docs, future auto-update, user muscle memory); changing them later is a
  breaking change — hence this ADR.
- The macOS notarization gap is a **known, documented trust limitation** tracked
  in [THREAT-MODEL.md](../THREAT-MODEL.md), not an oversight.
