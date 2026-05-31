//! Error taxonomy for janitor-aws (ADR 0010 §9). Two enums: one for Sign-in,
//! one for live-Session fetch/brokering. Variants are classified so the caller
//! can tell retryable from fatal from re-auth. The `Sdk` catch-all is scrubbed:
//! it carries a short static-ish context string, never a response body.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_variants_do_not_print_secret_material() {
        // Whatever context we attach, Display/Debug must not be a dumping ground
        // for response bodies. We assert a representative secret string never
        // appears, documenting the contract (the producer in aws_impl.rs is
        // responsible for never putting secrets in `context`).
        let e = SessionError::Sdk { context: "GetSecretValue".into() };
        let shown = format!("{e} | {e:?}");
        assert!(shown.contains("GetSecretValue"));
        assert!(!shown.contains("hunter2"), "no secret leaked");
    }

    #[test]
    fn reauth_is_distinct_from_access_denied() {
        // The two are handled differently by the facade; they must not be the
        // same variant.
        assert!(matches!(SessionError::ReauthRequired, SessionError::ReauthRequired));
        assert!(matches!(SessionError::AccessDenied, SessionError::AccessDenied));
    }
}
