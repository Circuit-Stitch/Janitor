# CI and distribution: tagged cross-platform binaries, signing deferred

**Status:** accepted

## Context

Janitor is distributed as a downloadable desktop binary. We want automated CI
(lint/test on every change) and automated, tagged release artifacts users can
download. Code signing matters more than usual for a *secrets* tool — an
"unidentified developer" / SmartScreen scare screen on a credential manager
corrodes trust — but signing carries recurring cost and identity setup that
isn't warranted before the app is near release.

An installer is **not** required for config storage: the app creates its
per-OS config directory at runtime on first launch (via the `directories` crate
→ `%APPDATA%`, `~/Library/Application Support`, `~/.config`) regardless of how
it was delivered. Installer/signing is a *trust & UX* decision, independent of
config storage.

## Decision

**v1 ships unsigned native bundles built by `cargo-packager` on tag; code
signing + notarization are deferred to a pre-release milestone.**

- **Tooling: `cargo-packager` from the start.** Chosen over `dist` because
  Janitor is a Slint GUI app, not a CLI: `cargo-packager` produces real windowed
  bundles (macOS `.app`/`.dmg`, Windows `.msi`/NSIS `.exe`, Linux AppImage/`.deb`)
  and has built-in signing + notarization hooks to switch on later. `dist`'s
  sweet spot (tarball + shell/PowerShell installer) suits CLI tools and does not
  cleanly emit a macOS `.app`.
- **Targets (v1):** `aarch64-apple-darwin` (Apple Silicon),
  `x86_64-apple-darwin` (Intel macOS), `x86_64-pc-windows-msvc`,
  `x86_64-unknown-linux-gnu`.
- **CI (every push / PR):** `cargo fmt --check`, `cargo clippy --all-targets`,
  `cargo test` — with `janitor-core`'s ≥80% coverage gate (ADR 0003).
- **Release (on `vX.Y.Z` tag):** GitHub Actions runs `cargo-packager` on each
  target's runner and publishes a GitHub Release with the per-OS bundles
  attached. Tag-driven, so cutting a release is `git tag` + push.
- **No signing in v1.** The bundles are real but **unsigned**, so Gatekeeper
  (macOS) and SmartScreen (Windows) friction remains; this is accepted and
  **documented in release notes / README** so users of a secrets tool aren't
  blindsided by a scary prompt.

**Deferred to a pre-release milestone (not v1):**
- macOS notarization + Developer ID signing — requires Apple Developer Program
  ($99/yr). Wired into the existing `cargo-packager` macOS step.
- Windows Authenticode signing — Azure Artifact Signing (~$10/mo; now open to
  self-employed individuals). Wired into the `cargo-packager` Windows step.
- Auto-update channel (if desired later).

## Considered options

- **`dist` (cargo-dist)** — rejected as primary: excellent for CLI release CI but
  doesn't produce a true macOS `.app` bundle, which a GUI app needs.
- **Signed bundles from the start** — rejected for v1: needs Apple + Azure
  identity and CI secrets in place before anything ships; premature pre-release.
  The chosen tool makes turning signing on a config + secrets change, not a
  re-architecture.
- **Raw binaries (no bundles)** — rejected: a bare Mach-O / `.exe` is a poor and
  trust-eroding experience for a desktop secrets tool; `cargo-packager` gives real
  bundles for the same CI effort.

## Consequences

- Releasing is trivial (tag push) but users must manually clear OS security
  prompts until signing lands; this is a temporary, documented state.
- **Four targets means four runners**; Intel macOS doubles the macOS build/sign
  matrix versus Apple-Silicon-only, accepted to support older Macs.
- **Building a Slint GUI in CI is not dependency-free**: the Linux runner must
  install GUI/system dev libraries (e.g. xcb/wayland/font dev packages, per
  Slint's backend requirements) before `cargo build`; macOS/Windows runners need
  their platform toolchains. The release workflow must document and pin these.
- Artifact naming and the tag→release contract become a de-facto interface
  (docs, future installers, user muscle memory) — changing them later is a
  breaking change, which is why this is recorded as an ADR.
- Signing being deferred is a **known trust gap** tracked in
  [THREAT-MODEL.md](../THREAT-MODEL.md), not an oversight.
