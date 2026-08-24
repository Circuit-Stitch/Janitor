# Flathub distribution: Flatpak manifest with vendored offline build

**Status:** accepted (manifest + metainfo drafted; live `flatpak-builder` run and
the flathub/flathub submission are the remaining steps)

**Related:** [ADR 0022](0022-packaging-cargo-packager-and-windows-signing.md) (the
rpm/deb/AppImage/exe packaging this sits *beside*, reusing the same app ID, desktop
file, and icon set), [ADR 0007](0007-ci-and-distribution.md) (tag-driven release
artifacts), [ADR 0033](0033-pluggable-sign-in-browser-and-portal-cookie-isolation.md)
(the browser openers, one of which the sandbox constrains),
[ADR 0002](0002-identity-center-only-memory-only-auth.md) /
[THREAT-MODEL](../THREAT-MODEL.md) (nothing-secret-on-disk — why the sandbox is a
tight fit and needs no `--filesystem`).

## Context

Janitor already produces native bundles (rpm/deb/AppImage/dmg/exe) via ADR 0022's
tag-triggered `release.yml`. Flathub is a *fifth* Linux channel with its own
build-and-host model — it builds from a manifest in `flathub/flathub`, not from our
CI — so it neither replaces nor touches the existing pipeline. The groundwork was
mostly already there: a D-Bus-legal reverse-DNS app ID (`com.circuitstitch.apps.janitor`,
no hyphens), a `.desktop` file, and a full hicolor icon set (ADR 0022).

Three facts shaped the manifest:

- **Flathub builds offline.** No network during the build, so all 769 crates must be
  vendored. Every dependency is a crates.io registry crate (no git sources), so
  `flatpak-cargo-generator.py` reads checksums straight from `Cargo.lock` and the
  vendoring is deterministic and network-free to *generate* as well.
- **The OAuth loopback survives the sandbox.** Sign-in opens the host browser, which
  redirects to `http://127.0.0.1:5369x/oauth/callback` caught by an in-app listener
  (ADR 0033). `--share=network` shares the *host* network namespace, so the host
  browser and the sandboxed listener see the same `127.0.0.1` — the redirect lands.
  Browser launch itself goes through the OpenURI portal (`open::that` → the xdg-open
  shim), which is automatic.
- **The threat model makes the sandbox tight for free.** Nothing secret touches disk
  and config lives in the per-app dir, so the manifest needs **no `--filesystem`** and
  no extra portal talk-names — only network + the GUI sockets. Least privilege is the
  default, not extra work.

## Decision

**Ship a Flatpak manifest that vendors all crates and builds offline against the
freedesktop runtime + `rust-stable` SDK extension, reusing the ADR 0022 assets.**

- **App ID unchanged:** `com.circuitstitch.apps.janitor`. Kept (not renamed to an
  `io.github.*` fallback) because the maintainer controls `circuitstitch.com`, which
  Flathub requires for a `com.*` namespace. Reusing the ID means the desktop file,
  icons, and packager `identifier` are shared verbatim across every channel.
- **Offline build:** `flatpak/cargo-sources.json` (generated) vendors the 769 crates;
  `CARGO_HOME=/run/build/janitor/cargo` points cargo at the generated config + vendor
  dir; the build is `cargo --offline build --release -p janitor-gui`. The `stable`
  toolchain (`rust-toolchain.toml`) is satisfied by the runtime's `rust-stable`
  extension. Regeneration is a committed wrapper (`flatpak/gen-cargo-sources.sh`); it
  must rerun on any `Cargo.lock` change.
- **AppStream metainfo** (`janitor-gui/assets/com.circuitstitch.apps.janitor.metainfo.xml`)
  is added — mandatory for Flathub, and good practice everywhere — and is **also
  installed by the rpm** (`/usr/share/metainfo`). It is not Flatpak-specific, so it
  lives with the app, not in `flatpak/`.
- **Sandbox:** `--share=network` (AWS + the loopback redirect + the SSM wss channel),
  `--socket=wayland` / `--socket=fallback-x11` / `--share=ipc` / `--device=dri` (Slint).
  No `--filesystem`, no `--talk-name` — see Context.

## Consequences

- **Drafted, not yet submitted.** `flatpak/com.circuitstitch.apps.janitor.yml` +
  `cargo-sources.json` + the metainfo exist and pass static validation
  (`appstreamcli`, `desktop-file-validate`); the live `flatpak-builder` run and the
  `flathub/flathub` PR are the remaining steps. Submission still needs a real
  **screenshot** (the metainfo points at a `docs/screenshots/matrix.png` URL that must
  be committed) and the manifest's git source pinned to a release `tag` + `commit`.
- **`CommandBrowser` (ADR 0033) does not work under Flatpak.** The incognito-isolation
  escape hatch spawns a host browser binary the sandbox can't see (`flatpak-spawn
  --host` would be required, and is deliberately *not* granted). `DefaultBrowser` (via
  the portal) is the only working opener inside the Flatpak; the cookie-jar isolation
  feature is a non-Flatpak affordance until a per-OS in-app strategy (ADR 0033's
  deferred WebKitGTK option) lands. Noted here rather than silently degraded.
- **Two vendoring artifacts to keep in sync with `Cargo.lock`** (this and ADR 0022's
  packagers consume the same lock; only Flathub needs the explicit vendor JSON). The
  regen wrapper makes the refresh one command, but it is a new maintenance edge.
- **`runtime-version` will drift.** Pinned to `24.08`; bump to the current freedesktop
  runtime at submission and on each Flathub runtime EOL.

## Alternatives considered

- **`io.github.Circuit-Stitch.*` app ID** — rejected: the maintainer controls the
  `circuitstitch.com` domain, so the existing `com.*` ID is accepted; and the literal
  GitHub org name carries a hyphen, which is illegal in a D-Bus name (would force an
  underscored variant). Reusing one ID across all channels is simpler and avoids
  renaming the desktop file, icons, and packager identifier.
- **Hand-write or commit a full vendor tree** instead of `cargo-sources.json` —
  rejected: 769 crates is infeasible by hand, and a committed vendor dir bloats the
  repo and the diff on every bump. The generator is the standard Flathub-Rust path.
- **Drive the Flathub build from our own CI** — rejected: Flathub builds and hosts
  from its own infra off the `flathub/flathub` manifest; our `release.yml` stays the
  source of the other four channels and is left untouched.
- **Wider sandbox holes** (`--filesystem=home`, `--talk-name` for the browser) —
  rejected: unnecessary. Config is per-app, no secret hits disk, and the portal
  handles URL opening, so the minimal network + GUI permission set suffices.
