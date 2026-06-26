# Windows auto-update via MSIX + App Installer, signed by Trusted Signing

**Status:** accepted (design only — no code lands with this ADR; implementation handed
off)

**Related:** [ADR 0022](0022-packaging-cargo-packager-and-windows-signing.md) (the
packaging + Windows-signing decision this **amends**: it pivots the Windows artifact
from cargo-packager NSIS `.exe` to MSIX, and reuses 0022's Azure Trusted Signing /
OIDC wiring), [ADR 0007](0007-ci-and-distribution.md) (CI + distribution),
[ADR 0002](0002-identity-center-only-memory-only-auth.md) (memory-only, nothing-secret-
at-rest — the "no long-lived signing secret in CI" posture this preserves),
[ADR 0017](0017-in-app-diagnostic-log-panel-and-zero-terminal-output.md) (the masked
Diagnostic Log any in-app update surface logs to),
[THREAT-MODEL](../THREAT-MODEL.md) (this introduces the project's **first** network
update channel + a remote-code-install surface — recorded there).

## Context

A user running the shipped Janitor **0.1.3** (an NSIS `.exe` install, ADR 0022) has
**no way to discover or get a newer version** — updating means manually re-downloading
the installer from the GitHub Releases page and re-running it. The ask: give Janitor an
update story, using **the Microsoft-recommended path**, and **reusing the maintainer's
existing Authenticode signing key** (the Azure Trusted Signing cert already wired into
the release workflow per ADR 0022 / #56).

Two approaches were evaluated end to end (see *Alternatives*):

- A **custom in-app updater** (`cargo-packager-updater`, the companion to the
  cargo-packager we already use). It works, but it authenticates updates with its **own
  minisign keypair** — a *second* signing key whose private half becomes a new
  crown-jewel secret (compromise ⇒ push arbitrary code to every client), with **no
  remote rotation** (the public key is baked into the binary at compile time, so a leak
  is only recoverable by shipping a new *manually-installed* build). It also does **not**
  use the Authenticode cert as the update trust anchor. Its only real advantage was
  keeping the NSIS installer — which the maintainer explicitly declined.

- **MSIX + a companion `.appinstaller` file** — **Microsoft's recommended mechanism for
  auto-updating apps distributed *outside* the Store.** Windows' built-in **App
  Installer** engine performs the update check / download / install itself; the update
  policy (when to check, whether to prompt) lives in the `.appinstaller` XML. The trust
  anchor is **Authenticode**: the `.msix` is signed with the maintainer's cert. **Azure
  Trusted Signing signs MSIX directly** (the same `azure/trusted-signing-action` already
  in `release.yml`), and because Trusted Signing is **CA-trusted**, Windows trusts the
  package with no per-machine sideload-trust configuration.

  Sources: Microsoft Learn — [Auto-update and repair apps (App Installer)](https://learn.microsoft.com/en-us/windows/msix/app-installer/auto-update-and-repair--overview),
  [App Installer file update settings](https://learn.microsoft.com/en-us/windows/msix/app-installer/update-settings),
  [Update non-Store apps from your code](https://learn.microsoft.com/en-us/windows/msix/non-store-developer-updates),
  [Sign an MSIX package](https://learn.microsoft.com/en-us/windows/msix/package/signing-package-overview),
  and [Signing MSIX with Azure Trusted Signing](https://techcommunity.microsoft.com/discussions/msix-discussions/signing-msix-packages-with-azure-trusted-signing-accounts/4372740).

MSIX is strictly better on the two stated requirements: it **is** the Microsoft path,
and **the existing Authenticode signature is the update trust anchor** — so there is
**no second key**, killing the crown-jewel-secret and no-rotation problems of the custom
updater outright.

The one hard constraint: **cargo-packager (ADR 0022's Windows bundler) cannot produce
MSIX.** Its Windows outputs are NSIS (`.exe`) and WiX (`.msi`) only. So adopting MSIX is
a **packaging-toolchain change** for Windows — not a config tweak.

## Decision

**Pivot the Windows artifact to MSIX-only, auto-updating via App Installer, signed by
Azure Trusted Signing.** Linux (rpm/deb/AppImage) and macOS (`.dmg`) are **unchanged** —
ADR 0022 still governs them; this ADR touches **only** the Windows path.

1. **MSIX replaces NSIS on Windows (MSIX-only).** No NSIS `.exe` and no WiX `.msi` are
   built or published for Windows going forward. (The recent `installMode = "both"` NSIS
   work is thereby **superseded on Windows** — MSIX has its own install model; the commit
   stays in history, the config block is removed when the Windows packaging is rewritten.)

2. **Build the MSIX with the Windows SDK `makeappx`.** cargo-packager is dropped from the
   Windows job. The package is assembled from an authored **`AppxManifest.xml`** plus the
   built `janitor-gui.exe` + the committed icon/asset set, then packed with `makeappx
   pack`. (No mature pure-Rust MSIX bundler exists; `makeappx` ships in the Windows SDK on
   the `windows-latest` runner. Re-evaluate community tooling at implementation time, but
   `makeappx` is the assumed path.)

3. **Update via a hosted `.appinstaller`, with NO automatic checks.** CI authors a
   `Janitor.appinstaller` that points at the signed `.msix` for the release, and uploads
   both to the GitHub Release. Crucially the manifest **omits any automatic `UpdateSettings`**
   (no `OnLaunch`, no `HoursBetweenUpdateChecks`), so **App Installer never performs a
   background check** — the linked URL is consulted *only* when the app's manual check runs
   (Decision 6). The manifest is hosted via the GitHub Release's stable
   `…/releases/latest/download/Janitor.appinstaller` URL, so the **existing
   draft → human-review → publish flow is the release gate**: a *draft* release is not
   "latest", so a draft never advertises an update even to the manual check.

4. **Sign the `.msix` with Azure Trusted Signing — posture preserved.** Same
   `azure/trusted-signing-action`, same **GitHub OIDC federation** (no long-lived Azure
   secret stored in CI, ADR 0002 / THREAT-MODEL). The existing **`WINDOWS_SIGNING_ENABLED`
   skip-gate stays** — *no unsigned MSIX is ever published* (ADR 0022's hard policy,
   unchanged). **Load-bearing gotcha:** the `AppxManifest.xml` **`Publisher` must exactly
   equal the Subject (`CN=…`) of the Trusted Signing certificate profile** or the package
   is rejected — this string is dictated by the verified Trusted Signing identity, not
   freely chosen.

5. **Identity.** Keep the reverse-DNS `com.circuitstitch.apps.janitor` as the MSIX
   package `Identity Name` family (consistent with ADR 0022's cross-platform identifier),
   subject to the Publisher-match constraint in (4).

6. **Update *trigger* — manual only, zero background egress (DECIDED).** The maintainer
   requires **no phone-home of any kind**: Janitor performs **zero automatic or background
   network activity** for updates. The `.appinstaller` carries no automatic `UpdateSettings`
   (Decision 3), and the **sole** trigger is an in-app **"Check for updates"** control that
   runs **only on explicit user click**, built on the WinRT App Installer update APIs and
   called from Rust via the `windows` crate (`#[cfg(windows)]`):
   - **Check:** `Windows.ApplicationModel.Package.Current.CheckUpdateAvailabilityAsync()` →
     `PackageUpdateAvailabilityResult.Availability` (`Available` / `Required` / `NoUpdates` /
     `Error`). Consults the linked `.appinstaller` URL **only when called**.
   - **Install (on user confirm):** `PackageManager.AddPackageByAppInstallerFileAsync`.
     **Correction (slice-2 implementation, 2026-06-25):** the API **requires the
     `.appinstaller` URI passed explicitly** — it is *not* inferred from the running
     package (verified against Microsoft's own [non-Store update sample](https://learn.microsoft.com/en-us/windows/msix/non-store-developer-updates),
     which passes `new Uri(".../App.appinstaller")`). Janitor hardcodes the stable
     `…/releases/latest/download/Janitor.appinstaller` URL (the same one the
     `.appinstaller` self-references). The install is requested with
     `AddPackageByAppInstallerOptions::None` (no force-shutdown flag) — the **intent**
     being that the staged update applies on the next app close rather than force-killing
     the running session. **Unverified:** whether `None` defers on the App-Installer path
     or instead requires `ForceApplicationShutdown` to replace the in-use package is a
     live-verification item (Consequences (f)); the MS sample used `ForceApplicationShutdown`.
     A `RegisterApplicationRestart` + force-restart one-click variant was skipped for v1.
     The WinRT op is
     `.await`ed on the worker runtime (the `windows` 0.62 crate removed the blocking
     `.get()`; `windows-future` makes the `IAsyncOperation` awaitable).
   - **No `packageManagement` capability:** that restricted capability is only for
     *cross-publisher* updates; an app updating **itself** (same publisher) does not declare
     it ([update from code](https://learn.microsoft.com/en-us/windows/msix/non-store-developer-updates),
     [App Installer APIs](https://learn.microsoft.com/en-us/windows/msix/app-installer/update-settings)).

   This is more code than a manifest-policy auto-check — **accepted deliberately** to
   guarantee zero background egress. It is the GUI thin-shell + untested-shell pattern
   (ADR 0003 / ADR 0010 §5): a small `#[cfg(windows)]` Rust wrapper over the WinRT calls, a
   button + confirm in the view, surface (not Values) logged to the Diagnostic Log (ADR 0017).

## Consequences

- **Security posture — better than the rejected updater, recorded in THREAT-MODEL.**
  Janitor gains a **remote-code-install** surface, but **no background network channel**:
  egress is **manual-only** — zero automatic/background calls, the sole update-related
  network access happening on an explicit "Check for updates" click (Decision 6). The trust
  anchor is **Authenticode via Trusted Signing** — CA-trusted, OS-verified before install —
  so there is **no second/minisign key**, hence **no new crown-jewel secret and no
  baked-in-pubkey rotation gap** (rotation is the CA-managed cert lifecycle, not a
  recompile). The update payload is OS-verified before it runs. Both the manual-only trigger
  and the no-second-key trust model are why MSIX was chosen over the custom updater.

- **Bootstrap gap (does NOT help current 0.1.3 users automatically).** Auto-update only
  begins **once a user is on an MSIX build**. Getting from today's NSIS 0.1.3 to the first
  MSIX build (e.g. 0.1.4) is a **one-time manual reinstall** of a *different package type*.
  Must be called out in `docs/RELEASING.md` and the 0.1.4 release notes.

- **Config does not auto-migrate (MSIX virtualization).** Under MSIX, per-user writes to
  `%APPDATA%\Janitor` are redirected into the package's storage, so a user moving from the
  NSIS install to MSIX will **not** carry over their existing `config.toml` (start URL,
  last pick) — a one-time re-enter. Janitor's Config holds **locations only, never Values**
  (THREAT-MODEL), so there is **no secret implication**, only a small UX wrinkle to
  document. Verify the running app reads/writes config correctly under virtualization.

- **CI rework (the real cost) — scoped to the Windows job.** `release.yml`'s `windows`
  job changes from `cargo packager … nsis` to: build the release binary → author
  `AppxManifest.xml` + `Janitor.appinstaller` → `makeappx pack` → Trusted-Signing the
  `.msix` → upload `.msix` + `.appinstaller`. The `verify-version` gate, the draft-Release
  step, and every Linux/macOS job are **untouched**. The `workflow_dispatch` dry-run
  already in `release.yml` can prove the MSIX build + signing **without publishing**.

- **Verification reality — "it builds" ≠ "it updates".** End-to-end auto-update is only
  provable by **publishing two real MSIX releases and upgrading on a real Windows box**.
  Open items to confirm on that first live run: (a) Trusted Signing **Publisher-match**
  succeeds; (b) installing from the `.appinstaller` URL then publishing a higher version
  triggers an **in-place update**; (c) **config virtualization** behaves; (d) the CA-trust
  chain installs with **no sideload-trust prompt**; (e) the manual check/install path
  (Decision 6 — `CheckUpdateAvailabilityAsync` + `AddPackageByAppInstallerFileAsync`) works
  from a packaged build, and that **no background check fires** with `UpdateSettings` omitted;
  (f) **whether `AddPackageByAppInstallerOptions::None` defers** the install to the next app
  close (the slice-2 intent) **or instead errors / requires `ForceApplicationShutdown`** to
  replace the in-use running package — the MS sample used `ForceApplicationShutdown`, so this
  is unconfirmed; if `None` errors, the install button's outcome will be `Failed` until the
  flag is changed.

- **Distribution follow-ons (out of scope here).** A **winget** manifest can later point at
  the MSIX (Microsoft-native CLI channel, `winget upgrade`); the **Microsoft Store** remains
  a heavier future option. Neither is built here.

- **No `core` change, GUI stays thin.** Packaging and the App Installer engine are outside
  the crates; an optional in-app update *button* (Decision 6 follow-up) would be GUI shell
  (ADR 0003 / ADR 0010 §5), logging its surface to the Diagnostic Log (ADR 0017), touching
  no secret logic.

## Alternatives considered

- **Custom in-app updater (`cargo-packager-updater` + minisign), keep NSIS** — rejected:
  introduces a **second signing key** (new crown-jewel secret, **no remote rotation**), and
  does **not** use the Authenticode cert as the update anchor; its only upside (keep NSIS)
  was declined. Strictly weaker trust story than MSIX for this tool.

- **Keep NSIS *and* add MSIX (ship both)** — rejected by the maintainer (**MSIX only**) to
  avoid 2× Windows packaging maintenance and a split install base.

- **WiX MSI auto-update** — rejected: `.msi` has no native managed auto-update channel
  comparable to App Installer; it would still need a bolted-on custom updater.

- **Microsoft Store** — deferred: fully managed updates, but Store onboarding + per-release
  review overhead and less control than self-hosted App Installer. Remains a future channel
  alongside winget.

- **Authenticode-only "download + run the signed `.exe`" (no app-side pre-exec verify)** —
  rejected: trusts the download URL; the OS only refuses to run an *unsigned* binary, it
  does not bind the update to *our* identity before execution. MSIX + App Installer gives
  OS-level identity-bound install for free.
