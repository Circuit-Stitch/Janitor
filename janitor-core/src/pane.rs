//! What the main pane should render. Deciding it in core keeps the empty and
//! blank-state choices testable without driving a GUI, and gives every shell the
//! same answer (ADR 0003 keeps this logic out of the view).

/// The content the main pane shows, derived from the auth/load `status` string
/// and whether any Applications exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainPane {
    /// Not signed in — prompt to sign in.
    SignIn,
    /// Browser sign-in in flight.
    Signing,
    /// Fetching the selected Application's secrets.
    Loading,
    /// Signed in but zero Applications — point the user at the sidebar `+`
    /// instead of a blank matrix (issue #10).
    EmptyApps,
    /// Loaded with at least one Application — show the matrix.
    Matrix,
    /// A load failed.
    Error,
}

/// Where the selected Application's load has got to.
///
/// [`main_pane`] has always taken this as a string, because the Slint shell keeps
/// one in a property and pushes it. A shell that can hold a typed value should,
/// so [`LoadStatus::as_token`] produces the same strings and
/// [`main_pane_of`] takes the enum. Both routes reach the one decision below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadStatus {
    /// Nothing has been asked for yet.
    Idle,
    /// Browser sign-in in flight.
    SigningIn,
    /// Fetching the selected Application's secrets.
    Loading,
    /// The matrix is current.
    Loaded,
    /// The load failed.
    Failed,
}

impl LoadStatus {
    /// The string form [`main_pane`] and [`crate::sidebar::sidebar_apps`] match on.
    pub fn as_token(self) -> &'static str {
        match self {
            LoadStatus::Idle => "idle",
            LoadStatus::SigningIn => "signing",
            LoadStatus::Loading => "loading",
            LoadStatus::Loaded => "loaded",
            LoadStatus::Failed => "error",
        }
    }
}

/// Decide the main pane from a typed status. The same decision as [`main_pane`].
pub fn main_pane_of(status: LoadStatus, has_apps: bool) -> MainPane {
    main_pane(status.as_token(), has_apps)
}

/// Decide the main pane. `has_apps` is `!Config.applications.is_empty()`.
pub fn main_pane(status: &str, has_apps: bool) -> MainPane {
    match status {
        "loaded" if has_apps => MainPane::Matrix,
        "loaded" => MainPane::EmptyApps,
        "signing" => MainPane::Signing,
        "loading" => MainPane::Loading,
        "error" => MainPane::Error,
        _ => MainPane::SignIn,
    }
}

impl MainPane {
    /// The stable string a shell switches its pane on. The Slint view keeps its
    /// `if root.pane == …` arms in lockstep with these tokens.
    pub fn as_token(self) -> &'static str {
        match self {
            MainPane::SignIn => "signin",
            MainPane::Signing => "signing",
            MainPane::Loading => "loading",
            MainPane::EmptyApps => "empty-apps",
            MainPane::Matrix => "matrix",
            MainPane::Error => "error",
        }
    }

    /// The top-bar pane title (issue #47). Rust is the one place that maps a pane
    /// to its title; a shell binds the pushed title. SignIn and Error share "Not
    /// signed in" — the top bar shows the banner separately, and Error routes the
    /// user back to Sign-in.
    pub fn title(self) -> &'static str {
        match self {
            MainPane::Matrix => "Drift matrix",
            MainPane::EmptyApps => "No Applications",
            MainPane::Loading => "Loading…",
            MainPane::Signing => "Signing in…",
            MainPane::SignIn | MainPane::Error => "Not signed in",
        }
    }

    /// The centered body copy for a non-matrix / non-empty pane (issue #47). Only
    /// the SignIn / Signing / Loading / Error panes render it; the matrix and
    /// empty-apps panes have their own content, so they route through the error
    /// catch-all and their value is never displayed. On an error the
    /// `status_message` carries the real, error-safe reason (ADR 0017) — shown when
    /// present, else a retry hint.
    pub fn body_copy(self, status_message: &str) -> String {
        match self {
            MainPane::SignIn => "Sign in to load this Application's secrets.".to_string(),
            MainPane::Signing => "A browser tab has opened — complete sign-in there.".to_string(),
            MainPane::Loading => "Fetching secrets…".to_string(),
            MainPane::Error | MainPane::Matrix | MainPane::EmptyApps => {
                if status_message.is_empty() {
                    "Could not load. See the message above, then Sign in to retry.".to_string()
                } else {
                    format!("Could not load — {status_message}")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_typed_status_reaches_the_same_pane_as_its_token() {
        // The enum is a second door onto one decision, not a second decision. A
        // status whose token stopped matching would route a shell to SignIn while
        // the other shell showed the matrix.
        for status in [
            LoadStatus::Idle,
            LoadStatus::SigningIn,
            LoadStatus::Loading,
            LoadStatus::Loaded,
            LoadStatus::Failed,
        ] {
            for has_apps in [false, true] {
                assert_eq!(
                    main_pane_of(status, has_apps),
                    main_pane(status.as_token(), has_apps),
                    "{status:?} with has_apps={has_apps}"
                );
            }
        }
        assert_eq!(main_pane_of(LoadStatus::Loaded, true), MainPane::Matrix);
        assert_eq!(main_pane_of(LoadStatus::Loaded, false), MainPane::EmptyApps);
        assert_eq!(main_pane_of(LoadStatus::Failed, true), MainPane::Error);
    }

    #[test]
    fn pane_tokens_match_the_slint_arms() {
        // The Slint shell's app.slint reads `root.pane` against these exact tokens.
        assert_eq!(MainPane::EmptyApps.as_token(), "empty-apps");
        assert_eq!(MainPane::Matrix.as_token(), "matrix");
        assert_eq!(MainPane::SignIn.as_token(), "signin");
        assert_eq!(MainPane::Signing.as_token(), "signing");
        assert_eq!(MainPane::Loading.as_token(), "loading");
        assert_eq!(MainPane::Error.as_token(), "error");
    }

    #[test]
    fn signed_in_with_no_applications_shows_the_empty_state() {
        // The issue #10 bug: status reaches "loaded" with zero Applications and
        // the matrix branch renders a blank pane. It must be EmptyApps instead.
        assert_eq!(main_pane("loaded", false), MainPane::EmptyApps);
    }

    #[test]
    fn loaded_with_applications_shows_the_matrix() {
        assert_eq!(main_pane("loaded", true), MainPane::Matrix);
    }

    #[test]
    fn transient_and_error_statuses_keep_their_own_panes() {
        // These drive distinct progress/error copy; the empty-state refactor
        // must not collapse them into SignIn.
        assert_eq!(main_pane("signing", false), MainPane::Signing);
        assert_eq!(main_pane("loading", true), MainPane::Loading);
        assert_eq!(main_pane("error", true), MainPane::Error);
    }

    #[test]
    fn not_signed_in_prompts_sign_in_even_with_no_applications() {
        // The empty state is a signed-in concept; before sign-in the user sees
        // the sign-in prompt whether or not Applications exist.
        assert_eq!(main_pane("unauth", false), MainPane::SignIn);
        assert_eq!(main_pane("unauth", true), MainPane::SignIn);
    }

    #[test]
    fn title_matches_the_extracted_slint_ladder() {
        // The exact strings the Slint shell's `?:` ladder produced (issue #47); Rust is
        // now their single source. SignIn and Error fold into "Not signed in".
        assert_eq!(MainPane::Matrix.title(), "Drift matrix");
        assert_eq!(MainPane::EmptyApps.title(), "No Applications");
        assert_eq!(MainPane::Loading.title(), "Loading…");
        assert_eq!(MainPane::Signing.title(), "Signing in…");
        assert_eq!(MainPane::SignIn.title(), "Not signed in");
        assert_eq!(MainPane::Error.title(), "Not signed in");
    }

    #[test]
    fn body_copy_matches_the_extracted_slint_ladder() {
        assert_eq!(
            MainPane::SignIn.body_copy(""),
            "Sign in to load this Application's secrets."
        );
        assert_eq!(
            MainPane::Signing.body_copy("ignored"),
            "A browser tab has opened — complete sign-in there.",
            "the signing copy is fixed, independent of any message"
        );
        assert_eq!(MainPane::Loading.body_copy(""), "Fetching secrets…");
    }

    #[test]
    fn error_body_copy_shows_the_reason_when_present_else_a_retry_hint() {
        // With a (scrubbed, error-safe) reason the body surfaces it; without one it
        // points the user at the banner above and the retry path.
        assert_eq!(
            MainPane::Error.body_copy("secret not found"),
            "Could not load — secret not found"
        );
        assert_eq!(
            MainPane::Error.body_copy(""),
            "Could not load. See the message above, then Sign in to retry."
        );
    }
}
