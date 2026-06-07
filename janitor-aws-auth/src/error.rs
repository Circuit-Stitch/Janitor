//! Error taxonomy for the AWS-family Providers (ADR 0010 §9 / ADR 0024). Two
//! enums: one for Sign-in, one for live-Session fetch/brokering. Variants are
//! classified so the caller can tell retryable from fatal from re-auth. The
//! `Sdk` catch-all is scrubbed: it carries a short static-ish context string,
//! never a response body. The `From` impls at the bottom mask these into the
//! provider-agnostic `janitor_core::provider` port types (ADR 0019).

use janitor_core::provider::{FetchFailReason, SignInFailed};

/// Why a browser Sign-in failed. None of these implies a live Session exists.
#[derive(Debug, thiserror::Error)]
pub enum SignInError {
    #[error("could not launch a browser for Sign-in")]
    BrowserLaunch,
    #[error("timed out waiting for the Sign-in redirect")]
    ListenerTimeout,
    #[error("the Sign-in redirect could not be bound to a loopback port")]
    NoLoopbackPort,
    #[error("the Sign-in redirect failed CSRF state validation")]
    StateMismatch,
    #[error("the Identity Center token endpoint rejected the Sign-in")]
    TokenEndpoint,
    #[error("a network error occurred during Sign-in")]
    Network,
    /// Scrubbed catch-all: `context` is a short non-secret label, never a body.
    #[error("Sign-in failed: {context}")]
    Sdk { context: String },
}

/// Why an operation on a live Session failed.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The SSO token is dead — a fresh browser Sign-in is required. This is the
    /// ONLY variant that should trigger a browser (ADR 0002 / 0010 §4).
    #[error("the Session expired; a fresh Sign-in is required")]
    ReauthRequired,
    /// AWS refused the operation under policy; not retryable, not re-auth.
    #[error("access denied for this Mapping")]
    AccessDenied,
    /// The signed-in user is not entitled to the Mapping's permission set on its
    /// account — `GetRoleCredentials` returned Forbidden/AccessDenied (ADR 0018).
    /// Distinct from `AccessDenied` because it arms one in-session role
    /// re-resolution + retry in `Session::load`; `context` is the scrubbed,
    /// error-safe AWS `code: message` (never a Value/Credential/token).
    #[error("not entitled to this role: {context}")]
    RoleNotEntitled { context: String },
    /// The secret id/region does not resolve to a Set.
    #[error("no secret found for this Mapping")]
    NotFound,
    /// Throttled or transient; the SDK already retried internally. Propagated so
    /// the caller can surface it; no Janitor-level retry loop in this slice.
    #[error("the request was throttled or hit a transient error")]
    Throttled,
    /// The Set cannot be handled (e.g. binary — never revealable, ADR 0004).
    #[error("unsupported secret content for this operation")]
    Unsupported,
    /// Scrubbed catch-all: `context` is a short non-secret label, never a body.
    #[error("AWS call failed: {context}")]
    Sdk { context: String },
}

// ----------------------------------------------------------------------------
// Masking to the provider-agnostic port types (ADR 0019 / ADR 0024). These
// `From` impls live here — where the AWS taxonomy is defined — rather than in a
// Provider tail: both AWS-family tails produce these errors and mask them the
// same way, and the orphan rule forbids a tail crate (which owns neither the
// `From` trait nor the `janitor_core::provider` target type) from writing them.
// ----------------------------------------------------------------------------

/// Mask a per-fetch `SessionError` into the agnostic [`FetchFailReason`] (no SDK
/// text; THREAT-MODEL). The port type stays provider-agnostic and never learns
/// the AWS taxonomy.
impl From<&SessionError> for FetchFailReason {
    fn from(e: &SessionError) -> Self {
        match e {
            SessionError::ReauthRequired => FetchFailReason::NeedsSignIn,
            SessionError::AccessDenied => FetchFailReason::AccessDenied,
            // An un-recovered role denial surfaces as plain "access denied" — the
            // recovery attempt (ADR 0018) is upstream in `Session::load`; by the
            // time it becomes a `Failure`, recovery has already declined/failed.
            SessionError::RoleNotEntitled { .. } => FetchFailReason::AccessDenied,
            SessionError::NotFound => FetchFailReason::NotFound,
            SessionError::Throttled => FetchFailReason::Throttled,
            SessionError::Unsupported => FetchFailReason::Unsupported,
            SessionError::Sdk { .. } => FetchFailReason::Other,
        }
    }
}

/// Mask a `SignInError` into the agnostic [`SignInFailed`] at the port boundary
/// (ADR 0019). `SignInError`'s `Display` is already error-safe (static phrases /
/// scrubbed `Sdk` label, never secret material), so the wrapped message is safe
/// for the GUI banner; the browser/loopback *variants* never cross the port.
impl From<SignInError> for SignInFailed {
    fn from(e: SignInError) -> Self {
        SignInFailed::new(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_variants_do_not_print_secret_material() {
        // Whatever context we attach, Display/Debug must not be a dumping ground
        // for response bodies. We assert a representative secret string never
        // appears, documenting the contract (the producer in aws_impl.rs is
        // responsible for never putting secrets in `context`).
        let e = SessionError::Sdk {
            context: "GetSecretValue".into(),
        };
        let shown = format!("{e} | {e:?}");
        assert!(shown.contains("GetSecretValue"));
        assert!(!shown.contains("hunter2"), "no secret leaked");
    }

    #[test]
    fn role_not_entitled_display_carries_no_secret() {
        // Same scrubbed contract as Sdk: context is an error-safe code+message,
        // never a planted secret.
        let e = SessionError::RoleNotEntitled {
            context: "ForbiddenException: No access".into(),
        };
        let shown = format!("{e} | {e:?}");
        assert!(shown.contains("ForbiddenException"));
        assert!(!shown.contains("hunter2"), "no secret leaked");
    }

    #[test]
    fn reauth_is_distinct_from_access_denied() {
        // The two are handled differently by the facade; they must not be the
        // same variant.
        assert!(matches!(
            SessionError::ReauthRequired,
            SessionError::ReauthRequired
        ));
        assert!(matches!(
            SessionError::AccessDenied,
            SessionError::AccessDenied
        ));
    }

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
        // An un-recovered role denial surfaces as plain "access denied".
        assert_eq!(
            FetchFailReason::from(&SessionError::RoleNotEntitled {
                context: "Forbidden".into()
            }),
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
            FetchFailReason::from(&SessionError::Sdk {
                context: "GetSecretValue".into()
            }),
            FetchFailReason::Other
        );
    }

    #[test]
    fn describe_never_leaks_sdk_text() {
        // The Sdk catch-all carries a context string; describe() must not surface it.
        let r = FetchFailReason::from(&SessionError::Sdk {
            context: "hunter2".into(),
        });
        assert!(!r.describe().contains("hunter2"));
        assert_eq!(r.describe(), "AWS error");
    }

    #[test]
    fn sign_in_error_maps_to_the_agnostic_port_type_preserving_its_safe_display() {
        // The boundary masks the rich SignInError into the opaque port type. Its
        // Display is already error-safe (static phrases / scrubbed Sdk label), so
        // the wrapped message is the SAME string the GUI banner showed before this
        // refactor — no behavior change. The browser/loopback *variants* (the type
        // a file Provider would never produce) stay inside `aws` and never cross.
        for e in [
            SignInError::NoLoopbackPort,
            SignInError::StateMismatch,
            SignInError::Network,
            SignInError::Sdk {
                context: "TokenEndpoint".into(),
            },
        ] {
            let expected = e.to_string();
            let masked: SignInFailed = e.into();
            assert_eq!(
                masked.to_string(),
                expected,
                "the port preserves the error-safe banner string verbatim"
            );
        }
    }
}
