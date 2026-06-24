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
| Windows | `.exe` (NSIS) | `cargo-packager` | **Skip-gated** on signing (see below) |

The Release is left as a **draft** — nothing is published until a human reviews
the artifacts and clicks publish.

## Cutting a release

The tag version is the single source of truth and **must equal janitor-gui's
crate version** — the `verify-version` job fails the run otherwise.

1. Bump `version` in [`janitor-gui/Cargo.toml`](../janitor-gui/Cargo.toml) (e.g.
   to `0.2.0`) and merge it to `main`.
2. Tag and push the matching `v`-prefixed tag:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```
3. Watch the run in the Actions tab. On success a **draft Release** named `v0.2.0`
   appears with the `.rpm` / `.deb` / `.AppImage` / `.dmg` attached.
4. Smoke-test the artifacts, edit the release notes, and **publish** the draft.

### Dry run (no Release)

Trigger the workflow manually (`workflow_dispatch`, "Run workflow") to build and
upload all artifacts **without** publishing a Release — useful for validating a
packaging change before tagging.

## Platform signing status

### Windows — signed-only, gated (#56)

**No unsigned Windows artifact is ever produced or published** (ADR 0022 hard
policy). The Windows job is *skipped* unless the `WINDOWS_SIGNING_ENABLED` repo
variable is `true`; while skipped a release simply ships the Linux + macOS
artifacts and stays green.

Signing uses **Azure Trusted Signing** over **OIDC federation** (no stored
secret — `azure/login` mints a token, `azure/trusted-signing-action` consumes it
to sign the NSIS installer). To turn it on, set these repo **Variables**
(Settings → Secrets and variables → Actions → Variables):

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
