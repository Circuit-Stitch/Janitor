# Flatpak / Flathub

Janitor's Flatpak manifest (ADR 0034). Flathub builds and hosts from these files;
your existing `release.yml` (rpm/deb/AppImage/dmg/exe) is untouched.

## Files

| File | Purpose |
| --- | --- |
| `com.circuitstitch.apps.janitor.yml` | The Flatpak manifest. |
| `cargo-sources.json` | All 769 crates vendored for the offline build. **Generated** — regenerate after any `Cargo.lock` change with `./gen-cargo-sources.sh`. |
| `gen-cargo-sources.sh` | Regenerator wrapper. |

The AppStream metainfo lives with the app, not here:
[`../janitor-gui/assets/com.circuitstitch.apps.janitor.metainfo.xml`](../janitor-gui/assets/com.circuitstitch.apps.janitor.metainfo.xml)
(also installed by the rpm).

## Build & run locally

```bash
flatpak install -y flathub org.freedesktop.Platform//24.08 org.freedesktop.Sdk//24.08 \
  org.freedesktop.Sdk.Extension.rust-stable//24.08
flatpak-builder --user --install --force-clean build-dir flatpak/com.circuitstitch.apps.janitor.yml
flatpak run com.circuitstitch.apps.janitor
```

For fast iteration on the working tree, temporarily swap the `git` source in the
manifest for `{ type: dir, path: .. }`.

## Submitting to Flathub

1. Add a real screenshot at the URL the metainfo points to (or change the URL).
2. Pin the manifest's git source to the release `tag` **and** its `commit` sha.
3. Open a PR adding the manifest to
   [`flathub/flathub`](https://github.com/flathub/flathub) (the `new-pr` branch).
4. The bot validates the build and AppStream; reviewers confirm domain control of
   `circuitstitch.com` for the `com.circuitstitch.*` app ID.

Bump `runtime-version` to whatever freedesktop runtime is current at submission.
