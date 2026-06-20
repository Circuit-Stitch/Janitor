//! The pluggable **Sign-in browser** component (ADR 0033).
//!
//! [`BrowserOpener`] is the port: "render the authorize URL in some cookie
//! context". The loopback listener stays the universal redirect catcher, so every
//! opener is *fire-and-forget* — it returns as soon as the surface is launched and
//! the code comes back out-of-band. [`select`] is the single swap point: it maps
//! Config to a concrete opener, so adding a new strategy (e.g. macOS
//! `ASWebAuthenticationSession`) is one match arm + one file, swappable and
//! auditable in isolation.
//!
//! Impls:
//! - [`DefaultBrowser`] — the OS default browser (shared cookie jar).
//! - [`CommandBrowser`] — a user-configured launch command (`{url}` substituted),
//!   letting a private/incognito window isolate the Identity Center portal cookie
//!   from other browser-based AWS tools like the CLI.
//!
//! Only the actual `open`/process spawn is untested shell; the decision
//! ([`choose`]) and the command parse ([`command::build_browser_command`]) are
//! pure and unit-tested.

use std::sync::Arc;

use crate::error::SignInError;

mod command;
mod default;

pub use command::CommandBrowser;
pub use default::DefaultBrowser;

/// The port: open the authorize `url` so the user can complete Sign-in. The
/// redirect is caught out-of-band by the loopback listener, so this is
/// fire-and-forget — it returns once the browser/surface is launched.
///
/// Behind a trait (ADR 0027/0033) so `sign_in_once` runs end-to-end in tests with
/// a fake browser, and so the Sign-in surface can be swapped and audited on its own.
pub trait BrowserOpener: Send + Sync {
    fn open(&self, url: &str) -> Result<(), SignInError>;
}

/// Which Sign-in surface a Config selects. Pure decision, split from construction
/// so it is unit-testable; also the natural extension point for a future native
/// opener (e.g. a `NativeWebAuth` variant).
#[derive(Debug, PartialEq, Eq)]
enum Strategy {
    /// The OS default browser (shared cookie jar).
    Default,
    /// A user-configured launch command (`{url}` substituted).
    Command(String),
}

/// Decide the strategy from a configured `browser_command`. `None` or a
/// blank/whitespace-only command means the OS default — a blank command is never
/// an error at Sign-in time.
fn choose(command: Option<&str>) -> Strategy {
    match command {
        Some(cmd) if !cmd.trim().is_empty() => Strategy::Command(cmd.to_string()),
        _ => Strategy::Default,
    }
}

/// The swap point: build the Sign-in browser from Config. `None` → the OS default
/// browser (today's behaviour, shared cookie jar); `Some(cmd)` → a
/// [`CommandBrowser`] running `cmd` with `{url}` substituted.
pub fn select(command: Option<&str>) -> Arc<dyn BrowserOpener> {
    match choose(command) {
        Strategy::Default => Arc::new(DefaultBrowser),
        Strategy::Command(cmd) => Arc::new(CommandBrowser::new(cmd)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_chooses_the_default_browser() {
        assert_eq!(choose(None), Strategy::Default);
    }

    #[test]
    fn blank_or_whitespace_command_falls_back_to_default() {
        // A hand-edited or empty setting must degrade to the default, never fail.
        assert_eq!(choose(Some("")), Strategy::Default);
        assert_eq!(choose(Some("   ")), Strategy::Default);
    }

    #[test]
    fn a_real_command_chooses_the_command_browser() {
        assert_eq!(
            choose(Some("firefox -private-window {url}")),
            Strategy::Command("firefox -private-window {url}".to_string())
        );
    }
}
