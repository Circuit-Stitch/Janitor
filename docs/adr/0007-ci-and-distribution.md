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

**v1 ships raw, unsigned, per-OS binaries on tag; signing and native installers
are deferred to a pre-release milestone.**

- **Targets (v1):** `aarch64-apple-darwin` (Apple Silicon), `x86_64-pc-windows-msvc`,
  `x86_64-unknown-linux-gnu`. No Intel macOS.
- **CI (every push / PR):** `cargo fmt --check`, `cargo clippy --all-targets`,
  `cargo test` — with `janitor-core`'s ≥80% coverage gate (ADR 0003).
- **Release (on `vX.Y.Z` tag):** GitHub Actions builds all three targets and
  publishes a GitHub Release with one archive per OS (`.tar.gz` / `.zip`)
  containing the raw binary. Tag-driven, so cutting a release is `git tag` + push.
- **No signing in v1.** Gatekeeper (macOS) and SmartScreen (Windows) friction is
  accepted and **documented in release notes / README** so users of a secrets
  tool aren't blindsided by a scary prompt.

**Deferred to a pre-release milestone (not v1):**
- Notarized macOS `.app` / `.dmg` — requires Apple Developer Program ($99/yr).
- Signed Windows `.msi` / setup `.exe` — Azure Artifact Signing (~$10/mo;
  now open to self-employed individuals).
- Linux packaging niceties (AppImage / `.deb`).
- **Bundler tool choice** (`dist` aka cargo-dist, vs `cargo-packager`) — decided
  once there's a real binary to evaluate. `dist` is strongest for CLI-shaped
  artifacts (tarball/msi/shell installer); a GUI app wanting a true macOS `.app`
  bundle leans toward `cargo-packager`. Not committing now.

## Considered options

- **Signed native installers from the start** — rejected for v1: needs Apple +
  Azure identity/secrets wired into CI before anything ships; premature pre-release.
- **Commit to `dist` now** — deferred: its CLI-tool sweet spot doesn't cleanly
  produce a macOS `.app` bundle, and the GUI bundling need is a later concern.

## Consequences

- Releasing is trivial (tag push) but users must manually clear OS security
  prompts until signing lands; this is a temporary, documented state.
- **Building a Slint GUI in CI is not dependency-free**: the Linux runner must
  install GUI/system dev libraries (e.g. xcb/wayland/font dev packages, per
  Slint's backend requirements) before `cargo build`; macOS/Windows runners need
  their platform toolchains. The release workflow must document and pin these.
- Artifact naming and the tag→release contract become a de-facto interface
  (docs, future installers, user muscle memory) — changing them later is a
  breaking change, which is why this is recorded as an ADR.
- Signing being deferred is a **known trust gap** tracked in
  [THREAT-MODEL.md](../THREAT-MODEL.md), not an oversight.
