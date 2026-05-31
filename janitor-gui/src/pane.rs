//! What the main pane should render, decided in pure Rust so the GUI's
//! empty/blank choices are testable without driving Slint (matches the
//! `worker.rs` test seam; ADR 0003 keeps logic out of the `.slint` view).

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
    /// The stable string the `.slint` view switches on. Kept in lockstep with
    /// the `if root.pane == …` arms in `app.slint`.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pane_tokens_match_the_slint_arms() {
        // app.slint reads `root.pane` against these exact tokens.
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
}
