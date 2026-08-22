//! Windows MSIX self-update (ADR 0034, slice 2 of 2). The in-app "Check for
//! updates" button is Janitor's **sole, manual-only** update trigger — there is
//! zero background egress; the network is touched only when the user clicks
//! (ADR 0034 Decisions 3 + 6).
//!
//! A thin `#[cfg(windows)]` wrapper over the App Installer WinRT APIs (`Package`
//! / `PackageManager`), with a stub everywhere else so the crate stays
//! cross-platform. The WinRT/IO surface is untested shell (ADR 0010 §5); the pure
//! outcome → presentation mapping below is tested.
//!
//! **Identity landmine:** the App Installer APIs require the running process to
//! have MSIX package identity. A plain `cargo run` / unpackaged dev build has
//! none, so `Package::Current()` fails — we map that to [`UpdateCheck::Unsupported`]
//! and surface a calm "unavailable in this build", never a panic.

use std::sync::mpsc::{Receiver, Sender};

/// The masked outcome of a manual update check. No secret material — just which
/// branch the App Installer engine reported. `Send` so it rides the worker
/// `Event` across the thread boundary.
//
// `Available`/`UpToDate`/`Failed` are constructed only in the `#[cfg(windows)]`
// App Installer path; off Windows the stub only ever yields `Unsupported`. Since
// this is a `bin` crate (no external consumers), suppress the platform-conditional,
// intentional dead-code lint off Windows — it stays enforced on the Windows build.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCheck {
    /// A newer (or required) version is available — offer to install.
    Available,
    /// Already on the latest version.
    UpToDate,
    /// Not an installed MSIX build (dev `cargo run`, non-Windows, or no linked
    /// App Installer): the engine has no package identity to check. The calm
    /// "can't check here" — not an error.
    Unsupported,
    /// The check ran but errored (network, etc.). Masked, error-safe reason only.
    Failed(String),
}

/// The masked outcome of kicking off an install.
//
// `Started`/`Failed` are constructed only on Windows (see `UpdateCheck` above for
// why the off-Windows dead-code lint is suppressed).
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateInstall {
    /// Queued: App Installer staged the new package; it applies the next time the
    /// app closes (no forced shutdown — ADR 0034 slice 2).
    Started,
    /// Same identity gap as [`UpdateCheck::Unsupported`].
    Unsupported,
    /// The install could not be started. Masked reason only.
    Failed(String),
}

/// The committed `.appinstaller` URL (ADR 0034). `AddPackageByAppInstallerFileAsync`
/// requires this URI explicitly — it is NOT inferred from the running package
/// (corrected from ADR 0034 Decision 6's original wording). The stable
/// `…/releases/latest/download/…` form always resolves to the latest *published*
/// (non-draft) release, so a draft never advertises an update.
//
// Referenced by the `#[cfg(windows)]` install path (and tests); not used in the
// non-Windows stub build, so suppress the off-Windows dead-code lint there.
#[cfg_attr(not(windows), allow(dead_code))]
pub const APPINSTALLER_URL: &str =
    "https://github.com/Circuit-Stitch/Janitor/releases/latest/download/Janitor.appinstaller";

/// How a check should render: the masked status line and whether to offer Install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckView {
    pub status: String,
    pub available: bool,
}

/// Pure: map a check outcome to its masked status line + Install-button gate. The
/// human phrasing lives here (tested), not in the UI shell.
pub fn describe_check(c: &UpdateCheck) -> CheckView {
    match c {
        UpdateCheck::Available => CheckView {
            status: "An update is available.".to_string(),
            available: true,
        },
        UpdateCheck::UpToDate => CheckView {
            status: "Janitor is up to date.".to_string(),
            available: false,
        },
        UpdateCheck::Unsupported => CheckView {
            status: "Automatic updates are unavailable in this build (install the \
                     packaged app to enable them)."
                .to_string(),
            available: false,
        },
        UpdateCheck::Failed(reason) => CheckView {
            status: format!("Update check failed: {reason}"),
            available: false,
        },
    }
}

/// Pure: map an install outcome to its masked status line.
pub fn describe_install(i: &UpdateInstall) -> String {
    match i {
        UpdateInstall::Started => {
            "Update queued — it applies the next time you close Janitor.".to_string()
        }
        UpdateInstall::Unsupported => {
            "Automatic updates are unavailable in this build.".to_string()
        }
        UpdateInstall::Failed(reason) => format!("Update could not be started: {reason}"),
    }
}

// ── The update rail ─────────────────────────────────────────────────────────
// This rail is shell-local and stays that way. Only the Slint shell ships an MSIX,
// so `janitor-app`'s Command/Event protocol — the one both shells speak, and the
// one UniFFI exports (ADR 0035) — carries no update variant. The rail keeps the
// ADR 0034 guarantees it always had: manual-only, off the UI thread, and no network
// egress until the user clicks.

/// UI → the update thread.
pub enum UpdateCommand {
    Check,
    Install,
    Shutdown,
}

/// The update thread → UI. Masked outcomes only, never a Value (THREAT-MODEL).
pub enum UpdateEvent {
    Checked(UpdateCheck),
    Installed(UpdateInstall),
}

/// Spawn the update thread and return its command Sender.
///
/// It owns a current-thread Tokio runtime, so the WinRT `IAsyncOperation` is awaited
/// off the UI thread — the same guarantee the AWS worker gave this rail before it
/// moved out. `on_event` is invoked for each outcome, and the caller marshals it back
/// onto the UI loop. The thread touches the network only inside `check`/`install`,
/// and only because a command arrived.
pub fn spawn(on_event: impl Fn(UpdateEvent) + Send + 'static) -> Sender<UpdateCommand> {
    let (tx, rx) = std::sync::mpsc::channel::<UpdateCommand>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build update runtime");
        rt.block_on(async move { run_loop(rx, &on_event).await });
    });
    tx
}

/// Drain the update commands. Off Windows, and in an unpackaged build, both arms
/// resolve to a masked `Unsupported` without touching the network.
async fn run_loop(rx: Receiver<UpdateCommand>, on_event: &impl Fn(UpdateEvent)) {
    while let Ok(cmd) = rx.recv() {
        match cmd {
            UpdateCommand::Shutdown => break,
            UpdateCommand::Check => {
                tracing::info!(target: "janitor::gui", "Checking for updates");
                on_event(UpdateEvent::Checked(check().await));
            }
            UpdateCommand::Install => {
                tracing::info!(target: "janitor::gui", "Installing update");
                on_event(UpdateEvent::Installed(install().await));
            }
        }
    }
}

/// Check for an update against the linked `.appinstaller`. `async` — the WinRT
/// `IAsyncOperation` is awaited on the worker's runtime (off the UI thread).
/// Network access happens only here, only on an explicit click.
#[cfg(windows)]
pub async fn check() -> UpdateCheck {
    win::check().await
}

/// Kick off the install of the available update. Queues the staged package to
/// apply on next app close (no forced shutdown).
#[cfg(windows)]
pub async fn install() -> UpdateInstall {
    win::install().await
}

#[cfg(not(windows))]
pub async fn check() -> UpdateCheck {
    UpdateCheck::Unsupported
}

#[cfg(not(windows))]
pub async fn install() -> UpdateInstall {
    UpdateInstall::Unsupported
}

#[cfg(windows)]
mod win {
    use super::{UpdateCheck, UpdateInstall, APPINSTALLER_URL};
    use windows::core::HSTRING;
    use windows::ApplicationModel::{Package, PackageUpdateAvailability};
    use windows::Foundation::Uri;
    use windows::Management::Deployment::{
        AddPackageByAppInstallerOptions, PackageManager, PackageVolume,
    };
    use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};

    /// `APPMODEL_ERROR_NO_PACKAGE` — `Package::Current()` returns this when the
    /// process has no MSIX identity (unpackaged dev build). The one error we treat
    /// as "Unsupported" rather than "Failed".
    const APPMODEL_ERROR_NO_PACKAGE: i32 = 0x8007_3D54u32 as i32;

    /// MTA init so the blocking `IAsyncOperation` completes without a message pump.
    /// Idempotent on the calling (blocking-pool) thread; we never uninitialize.
    fn ensure_com() {
        // SAFETY: RoInitialize is safe to call repeatedly; a benign HRESULT
        // (S_FALSE / already-initialized) is ignored. Never panics.
        unsafe {
            let _ = RoInitialize(RO_INIT_MULTITHREADED);
        }
    }

    /// Map a WinRT error: the no-package case → Unsupported (dev build); anything
    /// else → a masked Failed (never leaks SDK internals beyond a static phrase).
    fn classify(e: windows::core::Error) -> UpdateCheck {
        if e.code().0 == APPMODEL_ERROR_NO_PACKAGE {
            UpdateCheck::Unsupported
        } else {
            UpdateCheck::Failed("the update check could not complete".to_string())
        }
    }

    pub(super) async fn check() -> UpdateCheck {
        ensure_com();
        match try_check().await {
            Ok(c) => c,
            Err(e) => classify(e),
        }
    }

    async fn try_check() -> windows::core::Result<UpdateCheck> {
        let package = Package::Current()?;
        let result = package.CheckUpdateAvailabilityAsync()?.await?;
        Ok(match result.Availability()? {
            PackageUpdateAvailability::Available | PackageUpdateAvailability::Required => {
                UpdateCheck::Available
            }
            PackageUpdateAvailability::NoUpdates => UpdateCheck::UpToDate,
            // Unknown / Error: no update info associated (commonly an unpackaged or
            // unlinked build). Calm "unsupported", not a scary failure.
            _ => UpdateCheck::Unsupported,
        })
    }

    pub(super) async fn install() -> UpdateInstall {
        ensure_com();
        match try_install().await {
            Ok(()) => UpdateInstall::Started,
            Err(e) => match classify(e) {
                UpdateCheck::Unsupported => UpdateInstall::Unsupported,
                UpdateCheck::Failed(m) => UpdateInstall::Failed(m),
                _ => UpdateInstall::Failed("the update could not be started".to_string()),
            },
        }
    }

    async fn try_install() -> windows::core::Result<()> {
        let pm = PackageManager::new()?;
        let uri = Uri::CreateUri(&HSTRING::from(APPINSTALLER_URL))?;
        // No target volume → the default volume.
        let volume: Option<&PackageVolume> = None;
        // `None` (no force-shutdown): the *intent* is the staged update applies on
        // next app close rather than force-killing the session. UNVERIFIED — `None`
        // may instead require `ForceApplicationShutdown` to replace the in-use
        // package (live-verification item, ADR 0034 Consequences (f)).
        pm.AddPackageByAppInstallerFileAsync(&uri, AddPackageByAppInstallerOptions::None, volume)?
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn describe_check_available_offers_install() {
        let v = describe_check(&UpdateCheck::Available);
        assert!(v.available, "an available update must offer Install");
        assert!(v.status.to_lowercase().contains("available"));
    }

    #[test]
    fn describe_check_up_to_date_hides_install() {
        let v = describe_check(&UpdateCheck::UpToDate);
        assert!(!v.available);
        assert!(v.status.contains("up to date"));
    }

    #[test]
    fn describe_check_unsupported_is_calm_not_an_error() {
        let v = describe_check(&UpdateCheck::Unsupported);
        assert!(!v.available);
        // Not phrased as a failure — it is the expected dev/non-MSIX path.
        assert!(!v.status.to_lowercase().contains("failed"));
        assert!(v.status.to_lowercase().contains("unavailable"));
    }

    #[test]
    fn describe_check_failed_carries_the_masked_reason() {
        let v = describe_check(&UpdateCheck::Failed("network down".to_string()));
        assert!(!v.available);
        assert!(v.status.contains("network down"));
    }

    #[test]
    fn describe_install_started_explains_apply_on_close() {
        let s = describe_install(&UpdateInstall::Started);
        assert!(s.to_lowercase().contains("close"));
    }

    #[test]
    fn describe_install_failed_carries_the_masked_reason() {
        let s = describe_install(&UpdateInstall::Failed("denied".to_string()));
        assert!(s.contains("denied"));
    }

    #[test]
    fn appinstaller_url_is_the_stable_latest_download() {
        // The URI is hardcoded (ADR 0034 correction) and must be the stable
        // latest-download form so a future check always sees the newest release.
        assert!(APPINSTALLER_URL.contains("releases/latest/download/Janitor.appinstaller"));
    }

    // Off Windows the whole capability degrades to Unsupported (the stub), proving
    // the cross-platform contract without touching the network. On Windows `check`
    // / `install` reach the real App Installer engine, so this is not run there.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn off_windows_check_and_install_are_unsupported() {
        assert_eq!(check().await, UpdateCheck::Unsupported);
        assert_eq!(install().await, UpdateInstall::Unsupported);
    }

    #[tokio::test]
    async fn check_reports_unsupported_through_the_update_rail() {
        // The whole rail end to end: UpdateCommand::Check -> check().await ->
        // UpdateEvent::Checked. A `cargo test` binary has NO MSIX package identity,
        // so on Windows `Package::Current()` fails fast — no network — and degrades
        // to Unsupported; off Windows the stub returns Unsupported directly. Either
        // way: a calm, non-panicking Unsupported, proving the rail (and the await) is
        // wired without touching the network. (Install is deliberately NOT exercised
        // here — on Windows it would reach the real
        // PackageManager::AddPackageByAppInstallerFileAsync and hit the network.)
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(UpdateCommand::Check).unwrap();
        tx.send(UpdateCommand::Shutdown).unwrap();

        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        run_loop(rx, &move |ev| sink.lock().unwrap().push(ev)).await;

        let events = events.lock().unwrap();
        assert!(
            matches!(
                events.as_slice(),
                [UpdateEvent::Checked(UpdateCheck::Unsupported)]
            ),
            "an unpackaged build reports Unsupported through the update rail — not a panic, not a real network check"
        );
    }
}
