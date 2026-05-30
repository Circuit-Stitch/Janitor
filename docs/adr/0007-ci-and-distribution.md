# CI and distribution: cargo-packager bundles, signed on macOS and Windows

**Status:** accepted

## Context

Janitor is distributed as a downloadable desktop application. We want automated
CI (lint/test on every change) and automated, tagged release artifacts users can
download. Code signing matters more than usual for a *secrets* tool — an
"unidentified developer" / SmartScreen scare screen on a credential manager
corrodes trust. Signing is per-OS, with different cost and severity:

- **macOS** *hard-blocks* unsigned/un-notarized GUI apps downloaded from the
  internet (Gatekeeper); clean install requires Developer ID signing +
  notarization via the Apple Developer Program ($99/yr).
- **Windows** *warns* (SmartScreen, dismissible); Authenticode via Azure Artifact
  Signing (~$10/mo, now open to self-employed individuals) removes it.
- **Linux** has no signing gatekeeping.

An installer is **not** required for config storage: the app creates its per-OS
config directory at runtime on first launch (via the `directories` crate →
`%APPDATA%`, `~/Library/Application Support`, `~/.config`) regardless of how it
was delivered. Installer/signing is a *trust & UX* decision, independent of
config storage.

## Decision

**`cargo-packager` builds real native bundles for all four targets on tag, and
both macOS and Windows artifacts are signed in v1.**

- **Tooling: `cargo-packager` from the start.** Chosen over `dist` because
  Janitor is a Slint GUI app, not a CLI: `cargo-packager` produces real windowed
  bundles (macOS `.app`/`.dmg`, Windows `.msi`/NSIS `.exe`, Linux AppImage/`.deb`)
  and has built-in signing + notarization hooks. `dist`'s sweet spot (tarball +
  shell/PowerShell installer) suits CLI tools and does not cleanly emit a `.app`.
- **Targets (v1):** `aarch64-apple-darwin` (Apple Silicon),
  `x86_64-apple-darwin` (Intel macOS), `x86_64-pc-windows-msvc`,
  `x86_64-unknown-linux-gnu`.
- **CI (every push / PR):** `cargo fmt --check`, `cargo clippy --all-targets`,
  `cargo test` — with `janitor-core`'s ≥80% coverage gate (ADR 0003). This lane
  is build/test only; it does not sign and does not need signing secrets, so
  fork PRs are safe.
- **Release (on `vX.Y.Z` tag):** GitHub Actions runs `cargo-packager` per target,
  **signs** the macOS and Windows artifacts, and publishes a GitHub Release with
  the per-OS bundles attached. Tag-driven, so cutting a release is `git tag` +
  push.

**Signing (both, in v1):**
- **macOS: Developer ID signing + notarization** via the Apple Developer Program
  ($99/yr). Bundles install cleanly past Gatekeeper.
- **Windows: Authenticode** via Azure Artifact Signing (~$10/mo). Removes the
  SmartScreen warning.
- **Linux: unsigned** (no gatekeeping).

**Signing-secret handling: GitHub Actions secrets + OIDC.**
- Signing runs in the **tag-triggered release jobs**, which read credentials from
  GitHub Actions **(environment) secrets**.
- **Prefer OIDC federation to Azure** (short-lived, no long-lived secret stored in
  the repo) where `cargo-packager` / the Azure signing action supports it; Apple
  notarization credentials (API key / app-specific password) are stored as
  encrypted Actions secrets.
- Keys never live in the repo; the build/test lane never references them.

## Considered options

- **`dist` (cargo-dist)** — rejected as primary: great for CLI release CI but
  doesn't produce a true macOS `.app` bundle, which a GUI app needs.
- **Ship unsigned / defer signing** — rejected: this is a secrets tool; an
  "unidentified developer" prompt (or a macOS hard-block) is corrosive to trust,
  and the recurring cost (~$219/yr combined) is accepted to avoid it.
- **macOS TestFlight instead of Developer ID** — rejected: still requires the
  $99/yr program, *and* mandates App Store Connect + the App Sandbox, which fights
  Janitor's needs (launch a browser, bind a localhost port for the PKCE redirect,
  write an arbitrary config dir, drive the clipboard). Developer ID signing +
  notarization gives clean installs without the sandbox.
- **Raw binaries (no bundles)** — rejected: a bare Mach-O / `.exe` is a poor,
  trust-eroding experience for a desktop secrets tool; `cargo-packager` gives real
  bundles for the same CI effort.

## Consequences

- Both macOS and Windows install cleanly; recurring cost ~$219/yr (Apple $99 +
  Azure ~$120). Linux unsigned (no gatekeeping needed).
- **Identity validation renews periodically** for both Apple and Azure. If either
  lapses, the release job must **fail loudly** rather than silently shipping an
  unsigned artifact — silent un-signing is a regression a secrets tool must not
  hide.
- **Four targets means four runners**; Intel macOS doubles the macOS build/sign
  matrix vs Apple-Silicon-only, accepted to support older Macs.
- **Building a Slint GUI in CI is not dependency-free**: the Linux runner must
  install GUI/system dev libraries (xcb/wayland/font dev packages, per Slint's
  backend requirements) before `cargo build`; macOS/Windows runners need their
  platform toolchains. The release workflow must document and pin these.
- Bundle/artifact naming and the tag→release contract become a de-facto interface
  (docs, future auto-update, user muscle memory); changing them later is a
  breaking change — hence this ADR.
- **macOS notarization sends the app bundle to Apple** as part of release. That is
  the compiled binary only (no secrets, no user data) — an accepted, standard
  step, noted because a secrets tool should be explicit about what leaves the
  build machine.
