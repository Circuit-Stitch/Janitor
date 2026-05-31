//! `Session` (GUI↔AWS bridge): lazy browser sign-in + per-Application,
//! multi-Environment fetch, behind the same ADR 0010 §5 seam the rest of the
//! crate uses. Lives in the GUI's worker thread; never crosses threads. All
//! orchestration here is unit-tested against the `wire::fakes`; only the real
//! adapters + browser are untested shell.

use crate::error::SessionError;

/// Why one Environment's fetch failed — a masked, owned classification of
/// `SessionError` (no SDK text; THREAT-MODEL). `Copy` so it is trivial to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchFailReason {
    /// A fresh browser Sign-in is required (dead/again-rejected token).
    NeedsSignIn,
    /// AWS refused under policy.
    AccessDenied,
    /// The secret id/region does not resolve.
    NotFound,
    /// Throttled or transient.
    Throttled,
    /// Content we cannot handle (e.g. binary for an op that needs text).
    Unsupported,
    /// Anything else (the scrubbed `Sdk` catch-all).
    Other,
}

impl FetchFailReason {
    /// A short, user-facing phrase. Never contains SDK/secret text.
    pub fn describe(self) -> &'static str {
        match self {
            FetchFailReason::NeedsSignIn => "session expired — sign in again",
            FetchFailReason::AccessDenied => "access denied",
            FetchFailReason::NotFound => "secret not found",
            FetchFailReason::Throttled => "throttled, try again",
            FetchFailReason::Unsupported => "unsupported secret content",
            FetchFailReason::Other => "AWS error",
        }
    }
}

impl From<&SessionError> for FetchFailReason {
    fn from(e: &SessionError) -> Self {
        match e {
            SessionError::ReauthRequired => FetchFailReason::NeedsSignIn,
            SessionError::AccessDenied => FetchFailReason::AccessDenied,
            SessionError::NotFound => FetchFailReason::NotFound,
            SessionError::Throttled => FetchFailReason::Throttled,
            SessionError::Unsupported => FetchFailReason::Unsupported,
            SessionError::Sdk { .. } => FetchFailReason::Other,
        }
    }
}

/// A whole-Application load failure: at least one Environment failed, so no
/// matrix is shown (spec Decision 8 — never a partial matrix, never a fake Gap).
/// Each entry is `(environment_name, reason)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppError {
    pub failures: Vec<(String, FetchFailReason)>,
}

impl AppError {
    /// The synthetic "you must sign in first" error (no real Environment failed).
    pub fn needs_sign_in() -> Self {
        AppError {
            failures: vec![("(sign-in)".to_string(), FetchFailReason::NeedsSignIn)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_session_error_to_a_reason() {
        assert_eq!(
            FetchFailReason::from(&SessionError::ReauthRequired),
            FetchFailReason::NeedsSignIn
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::AccessDenied),
            FetchFailReason::AccessDenied
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::NotFound),
            FetchFailReason::NotFound
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::Throttled),
            FetchFailReason::Throttled
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::Unsupported),
            FetchFailReason::Unsupported
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::Sdk { context: "GetSecretValue".into() }),
            FetchFailReason::Other
        );
    }

    #[test]
    fn describe_never_leaks_sdk_text() {
        // The Sdk catch-all carries a context string; describe() must not surface it.
        let r = FetchFailReason::from(&SessionError::Sdk { context: "hunter2".into() });
        assert!(!r.describe().contains("hunter2"));
        assert_eq!(r.describe(), "AWS error");
    }

    #[test]
    fn needs_sign_in_names_a_synthetic_environment() {
        let e = AppError::needs_sign_in();
        assert_eq!(e.failures.len(), 1);
        assert_eq!(e.failures[0].1, FetchFailReason::NeedsSignIn);
    }
}
