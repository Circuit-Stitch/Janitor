//! The pluggable **Sign-in browser** component (ADR 0033).
//!
//! [`BrowserOpener`] is the port: "render the authorize URL in some cookie
//! context". The loopback listener stays the universal redirect catcher, so every
//! opener is *fire-and-forget* — it returns as soon as the surface is launched and
//! the code comes back out-of-band. [`select`] is the single swap point: it maps
//! Config to a concrete opener, so adding a new strategy (e.g. a Linux in-app
//! WebView) is one match arm + one file, swappable and auditable in isolation.
//!
//! Impls:
//! - [`DefaultBrowser`] — the OS default browser (shared cookie jar).
//! - [`CommandBrowser`] — a user-configured launch command (`{url}` substituted),
//!   letting a private/incognito window isolate the Identity Center portal cookie
//!   from other browser-based AWS tools like the CLI.
//! - `WebAuthSessionBrowser` (macOS only) — the native ephemeral
//!   `ASWebAuthenticationSession`: an isolated cookie jar with no separate browser
//!   app, selected by the [`NATIVE_SENTINEL`] value of `browser_command`.
//!
//! Only the actual `open`/process spawn is untested shell; the decision
//! ([`choose`]) and the command parse ([`command::build_browser_command`]) are
//! pure and unit-tested.

use std::sync::Arc;

use crate::error::SignInError;

mod command;
mod default;
#[cfg(target_os = "macos")]
mod web_auth_session;

pub use command::CommandBrowser;
pub use default::DefaultBrowser;
#[cfg(target_os = "macos")]
pub use web_auth_session::WebAuthSessionBrowser;

/// The reserved `browser_command` value that selects the macOS native ephemeral
/// `ASWebAuthenticationSession` opener (ADR 0033). It is *not* a launch command —
/// `choose` intercepts it before the command path; on non-macOS it degrades to
/// the OS default (so a Config synced from a Mac never breaks). The Settings
/// presets dropdown writes this for the "macOS native" choice.
pub const NATIVE_SENTINEL: &str = "@native";

/// A live Sign-in surface, returned by [`BrowserOpener::open`] and held by the
/// caller until the loopback catches the redirect. **Dropping it dismisses the
/// surface** — e.g. cancels a macOS `ASWebAuthenticationSession`, closing its
/// window the moment the code arrives. Most surfaces are fire-and-forget and need
/// no teardown, so `()` is the no-op guard. `Send` because the caller holds it
/// across the `wait_for_redirect` await in `Reauth::sign_in`'s boxed future.
pub trait SignInSurface: Send {}

/// The no-op surface for openers that launch an external browser and need no
/// teardown (the user closes the tab) — [`DefaultBrowser`], [`CommandBrowser`].
impl SignInSurface for () {}

/// The port: open the authorize `url` so the user can complete Sign-in. The
/// redirect is caught out-of-band by the loopback listener, so this is
/// fire-and-forget for the *code* — but it returns a [`SignInSurface`] guard the
/// caller holds until the redirect arrives, then drops to dismiss the surface
/// (cancel-on-code; ADR 0033).
///
/// Behind a trait (ADR 0027/0033) so `sign_in_once` runs end-to-end in tests with
/// a fake browser, and so the Sign-in surface can be swapped and audited on its own.
pub trait BrowserOpener: Send + Sync {
    fn open(&self, url: &str) -> Result<Box<dyn SignInSurface>, SignInError>;
}

/// Which Sign-in surface a Config selects. Pure decision, split from construction
/// so it is unit-testable; also the extension point for new openers.
#[derive(Debug, PartialEq, Eq)]
enum Strategy {
    /// The OS default browser (shared cookie jar).
    Default,
    /// A user-configured launch command (`{url}` substituted).
    Command(String),
    /// The macOS native ephemeral `ASWebAuthenticationSession` (ADR 0033).
    #[cfg(target_os = "macos")]
    WebAuthSession,
}

/// Decide the strategy from a configured `browser_command`. The [`NATIVE_SENTINEL`]
/// selects the macOS native opener; `None` or a blank/whitespace-only command means
/// the OS default — a blank command is never an error at Sign-in time.
fn choose(command: Option<&str>) -> Strategy {
    match command.map(str::trim) {
        Some(cmd) if cmd == NATIVE_SENTINEL => native_or_default(),
        Some(cmd) if !cmd.is_empty() => Strategy::Command(cmd.to_string()),
        _ => Strategy::Default,
    }
}

/// The native opener exists only on macOS; elsewhere the sentinel degrades to the
/// OS default so a Config synced from a Mac never breaks.
fn native_or_default() -> Strategy {
    #[cfg(target_os = "macos")]
    {
        Strategy::WebAuthSession
    }
    #[cfg(not(target_os = "macos"))]
    {
        Strategy::Default
    }
}

/// The swap point: build the Sign-in browser from Config. `None` → the OS default
/// browser (today's behaviour, shared cookie jar); [`NATIVE_SENTINEL`] → the macOS
/// ephemeral session; any other `Some(cmd)` → a [`CommandBrowser`] running `cmd`
/// with `{url}` substituted.
pub fn select(command: Option<&str>) -> Arc<dyn BrowserOpener> {
    match choose(command) {
        Strategy::Default => Arc::new(DefaultBrowser),
        Strategy::Command(cmd) => Arc::new(CommandBrowser::new(cmd)),
        #[cfg(target_os = "macos")]
        Strategy::WebAuthSession => Arc::new(WebAuthSessionBrowser),
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

    #[test]
    fn native_sentinel_selects_native_on_macos_else_default() {
        let s = choose(Some(NATIVE_SENTINEL));
        #[cfg(target_os = "macos")]
        assert_eq!(s, Strategy::WebAuthSession);
        #[cfg(not(target_os = "macos"))]
        assert_eq!(s, Strategy::Default);
    }

    #[test]
    fn native_sentinel_tolerates_surrounding_whitespace() {
        // A hand-edited Config with stray spaces still resolves the sentinel
        // (and is never mistaken for a launch command).
        let s = choose(Some("  @native  "));
        #[cfg(target_os = "macos")]
        assert_eq!(s, Strategy::WebAuthSession);
        #[cfg(not(target_os = "macos"))]
        assert_eq!(s, Strategy::Default);
    }
}
