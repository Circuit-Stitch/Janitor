# Releasing Janitor

Janitor ships installable desktop packages built by the tag-triggered
[`release.yml`](../.github/workflows/release.yml) workflow (ADR 0022, #55). This
doc is the operator's checklist; the workflow file is the source of truth for
exact build steps.

## What a release produces

A pushed `vX.Y.Z` tag builds, on native per-OS runners, and attaches to a
**draft** GitHub Release for review:

| Platform | Artifact | Tool | Notes |
| --- | --- | --- | --- |
| Fedora / RHEL | `.rpm` | `cargo-generate-rpm` | Native `Requires`; priority target |
| Debian / Ubuntu | `.deb` | `cargo-packager` | Built on `ubuntu-22.04` (old-glibc floor) |
| Linux portable | `.AppImage` | `cargo-packager` | Distro-independent |
| macOS (Apple Silicon) | `.dmg` | `cargo-packager` | **Unsigned** — Gatekeeper warns (see below) |
| Windows | `.msix` + `.appinstaller` | `makeappx` + Trusted Signing | Auto-updating (ADR 0034); **skip-gated** on signing (see below) |

The Release is left as a **draft** — nothing is published until a human reviews
the artifacts and clicks publish.

## Cutting a release

The version is the single source of truth and **must equal janitor-gui's crate
version**. Both paths below keep them equal; either ends at a **draft** you
review and publish.

### One-click (preferred)

1. **Actions → Release → "Run workflow"**, type the version (e.g. `0.2.0`, no
   leading `v`), Run. The `setup` job bumps
   [`janitor-gui/Cargo.toml`](../janitor-gui/Cargo.toml) to that version, commits
   it to `main`, and the same run builds every artifact and drafts the Release.
2. Smoke-test the artifacts, edit the release notes, and **publish** the draft.
   Publishing creates the `v0.2.0` git tag (at the bump commit) — a failed build
   never leaves a dangling tag.

> The bump commit is pushed with `GITHUB_TOKEN`, which by design does **not**
> trigger another workflow, so the whole release is this one run (the version-bump
> commit lands on `main` un-CI'd — acceptable for a one-line version change).

### Manual (tag push)

1. Bump `version` in `janitor-gui/Cargo.toml` and merge it to `main`.
2. Tag and push the matching `v`-prefixed tag (`verify-version` fails the run if
   the tag and crate version disagree):
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```
3. Smoke-test the resulting draft, edit the notes, and **publish**.

### Dry run (no Release)

Run the workflow (`workflow_dispatch`) with the version field **left empty** to
build + upload all artifacts **without** any bump, tag, or Release — useful for
validating a packaging change before cutting a release.

## Platform signing status

### Windows — MSIX, auto-updating, signed-only, gated (ADR 0034)

Windows ships an **MSIX** that auto-updates via Windows' built-in **App
Installer** engine (ADR 0034, superseding the NSIS `.exe` of ADR 0022). The
release job assembles the package with `makeappx` from
[`janitor-gui/msix/AppxManifest.xml`](../janitor-gui/msix/AppxManifest.xml) + the
built `janitor-gui.exe` + the committed icons, signs the `.msix` with Trusted
Signing, and uploads it alongside a companion
[`Janitor.appinstaller`](../janitor-gui/msix/Janitor.appinstaller).

**Update model — manual only, zero background egress.** The `.appinstaller`
carries **no `UpdateSettings`**, so App Installer never background-checks. The
**sole** update trigger is the in-app **"Check for updates"** button (in
**Settings**), which reads the `.appinstaller` URL only on click. The button
reaches the linked URL via `…/releases/latest/download/Janitor.appinstaller` — so
a **draft** release (not "latest") never advertises an update: the draft → review
→ publish flow is the release gate. An available update installs on confirm; it is
**intended** to apply the next time the user closes Janitor (no forced shutdown) —
**to be confirmed in live verification** (the `None` install option may instead
require a forced shutdown to replace the running package; ADR 0034 checklist (f)).
On a non-MSIX build (e.g. dev `cargo run`) the button reports "unavailable in this build".

> ⚠️ **Bootstrap gap — 0.1.3 NSIS users are NOT auto-updated.** Auto-update only
> begins **once a user is on an MSIX build**. Moving from the shipped NSIS `0.1.3`
> to the first MSIX build (e.g. `0.1.4`) is a **one-time manual reinstall of a
> different package type**: download `Janitor.appinstaller` and **open it** — App
> Installer installs the `.msix` **and** records the update URL, so future "Check
> for updates" works. Installing the bare `.msix` directly does **not** wire up
> updates (no recorded App Installer URI), so call out *open the `.appinstaller`*
> specifically in the first MSIX release's notes. Also: under MSIX,
> `%APPDATA%\Janitor` writes are virtualized into the package store, so the
> existing NSIS install's `config.toml` (start URL, last pick) does **not** carry
> over — a one-time re-enter (no secret implication; Config holds locations only).

**No unsigned Windows artifact is ever produced or published** (ADR 0022 hard
policy). The Windows job is *skipped* unless the `WINDOWS_SIGNING_ENABLED` repo
variable is `true`; while skipped a release simply ships the Linux + macOS
artifacts and stays green.

Signing uses **Azure Trusted Signing** over **OIDC federation** (no stored
secret — `azure/login` mints a token, `azure/trusted-signing-action` consumes it
to sign the `.msix` directly). **Load-bearing:** the `AppxManifest.xml`
`Publisher` (and the `.appinstaller` `Publisher`) **must exactly equal the Subject
(`CN=…`) of the Trusted Signing certificate profile** or signing rejects the
package. To turn signing on, set these repo **Variables** (Settings → Secrets and
variables → Actions → Variables):

| Variable | Value |
| --- | --- |
| `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_SUBSCRIPTION_ID` | the federated app registration's IDs |
| `AZURE_SIGNING_ENDPOINT` | region endpoint, e.g. `https://eus.codesigning.azure.net/` |
| `AZURE_SIGNING_ACCOUNT` | Trusted Signing account name |
| `AZURE_SIGNING_PROFILE` | certificate profile name |
| `WINDOWS_SIGNING_ENABLED` | `true` |

Azure-side prerequisites (one-time): a Trusted Signing account + certificate
profile; an Entra app registration with a **federated credential** for this repo
(subject `repo:Circuit-Stitch/Janitor:ref:refs/tags/v*`); and the **Trusted
Signing Certificate Profile Signer** role granted to that app on the signing
account. Tracked in **#56**.

### macOS — unsigned for now (#57)

The `.dmg` is **not signed or notarized yet** (ADR 0022 amendment, 2026-06-09). On
first open macOS Gatekeeper will say the app "cannot be opened because the
developer cannot be verified." Until **#57** lands Developer ID signing +
notarization, open it via **right-click → Open** (or
`System Settings → Privacy & Security → Open Anyway`). The build is Apple-Silicon
only for now; an Intel/universal build is a follow-up.

## Maintaining the workflow

- **Linux build deps** are duplicated from `ci.yml` (Slint links system libs at
  build time). Keep the two lists in sync when the GUI's native deps change.
- **rpm `Requires` vs deb `depends`** use different package names per distro and
  live in `[package.metadata.generate-rpm.requires]` / `[package.metadata.packager.deb]`
  in `janitor-gui/Cargo.toml`.
- **Icons** are generated + committed (`janitor-gui/assets/gen-icons.sh`); the
  packagers consume the committed PNG/`.ico` set, so no rasterizer is needed in CI.
