<!-- Release notes template (wired into release.yml via softprops body_path).
     Edit the highlights below in the draft before you click Publish. -->

_Add release highlights here before publishing._

## Install

**Windows** — download **`Janitor.appinstaller`** below and **open it**. Windows'
App Installer fetches and installs the signed package and enables the in-app
**Check for updates** button for future releases. (Opening the bare
`Janitor.msix` installs the app but does **not** wire up updates.)

**Linux**
- Fedora / RHEL — `*.rpm`
- Debian / Ubuntu — `*.deb`
- Any distro — `*.AppImage`: `chmod +x Janitor*.AppImage`, then run it.

**macOS** — open the `*.dmg`. It is unsigned for now, so on first launch
right-click the app → **Open** (or **System Settings → Privacy & Security →
Open Anyway**).
