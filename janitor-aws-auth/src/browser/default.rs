//! The default Sign-in browser: hand the authorize URL to the OS default handler
//! (ADR 0033). Shares the system browser's cookie jar — fine for most, but the
//! Identity Center portal session is then shared with other browser-based AWS
//! tools (the CLI). Untested shell: it launches a real browser.

use crate::browser::BrowserOpener;
use crate::error::SignInError;
use crate::loopback::open_browser;

/// Opens the OS default browser via `open::that`. The redirect returns through the
/// loopback listener like any browser.
pub struct DefaultBrowser;

impl BrowserOpener for DefaultBrowser {
    fn open(&self, url: &str) -> Result<(), SignInError> {
        // Surface only (no URL — it carries the client_id + PKCE challenge).
        tracing::info!(target: "janitor::aws", surface = "os-default", "Opening Sign-in browser");
        open_browser(url)
    }
}
