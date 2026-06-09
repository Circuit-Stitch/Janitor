//! The **`ResourceMethod`** seam (ADR 0031): the swappable resource tail of one
//! AWS-family Provider — the `load`/`reveal`/`write` analogue of ADR 0026's
//! Discovery `Steps`. Object-safe; a Method receives a *freshly-minted*
//! [`Credential`] from the shell ([`AwsFamilyProvider`](crate::family::AwsFamilyProvider))
//! and supplies only the divergent tail: read+shape one Set, (B5) non-stomping
//! write, an optional operator advisory, and the Discovery location pick.
//!
//! The shell owns everything provider-agnostic (the SSO token, the broker, the
//! force-refresh + re-Sign-in ladder, ADR 0018 stale-role recovery, the cache and
//! `reveal`), so a Method's `fetch` stays the pure "given this Credential, read +
//! shape" call — no auth resilience inside it.

use std::sync::Arc;

use async_trait::async_trait;

use janitor_core::config::{Mapping, Method};
use janitor_core::discovery::Steps;
use janitor_core::provider::FetchFailReason;
use janitor_core::secret::SecretShape;

use crate::error::SessionError;
use crate::types::{Credential, SsoToken};
use crate::write::{EnvEdit, WriteOutcome};

/// A failed Method read/write, masked for the port. Generalizes `janitor-ssm`'s
/// old `DotenvFetchError`: it folds the two failure sources a Method produces into
/// one classification the shell can act on, keeping `ReauthRequired`/`RoleNotEntitled`
/// distinguishable so the shell can run its resilience ladder.
#[derive(Debug)]
pub enum MethodError {
    /// An auth/transport/SDK failure (a `GetSecretValue` error, an SSM read error,
    /// a credential mint denial). The shell **may** run the recovery ladder on it
    /// (force-refresh, re-Sign-in, stale-role re-resolution). Masked via the shared
    /// `From<&SessionError>` impl — no SDK text crosses (THREAT-MODEL).
    Session(SessionError),
    /// The read succeeded but the payload is unusable — a malformed `.env`, a binary
    /// secret. **Not** subject to recovery (retrying cannot help); masked to
    /// [`FetchFailReason::Unsupported`]. `detail` is the producer's error-safe note
    /// (e.g. `"malformed .env line N"`) — never a Value or any line content.
    Content { detail: String },
}

impl MethodError {
    /// The masked, port-facing classification (drives control flow + a fallback
    /// label). Never carries SDK text, file content, or a Value.
    pub fn reason(&self) -> FetchFailReason {
        match self {
            MethodError::Session(e) => FetchFailReason::from(e),
            MethodError::Content { .. } => FetchFailReason::Unsupported,
        }
    }

    /// An error-safe detail string for the load banner + Diagnostic Log (ADR 0017):
    /// for a `Session` error the `SessionError`'s already-scrubbed `Display`; for a
    /// `Content` error the producer's note (e.g. `"malformed .env line N"`).
    pub fn detail(&self) -> String {
        match self {
            MethodError::Session(e) => e.to_string(),
            MethodError::Content { detail } => detail.clone(),
        }
    }

    /// Whether this is a dead-token failure (routes to re-Sign-in / `Step::Reauth`).
    /// A `Content` error is never a re-auth condition.
    pub fn is_reauth(&self) -> bool {
        matches!(self, MethodError::Session(SessionError::ReauthRequired))
    }
}

/// One AWS-family resource **Method** (ADR 0031): the swappable tail the shell
/// dispatches to per Mapping. Object-safe (via `async-trait`) so the shell holds a
/// `Box<dyn ResourceMethod>` per [`Method`]. It speaks only
/// `Mapping`/`SecretShape`/`Credential`/`Step` — no Provider-port or GUI vocabulary.
#[async_trait]
pub trait ResourceMethod: Send + Sync {
    /// The [`Method`] tag this backs — the registry key, used to assert a method
    /// was wired under the right slot.
    fn kind(&self) -> Method;

    /// Read and shape one Set, authorized by a freshly-minted `cred`. Pure: no
    /// resilience (the shell owns the ladder). A read failure maps to
    /// [`MethodError::Session`]; an unusable payload to [`MethodError::Content`].
    async fn fetch(&self, cred: &Credential, mapping: &Mapping)
        -> Result<SecretShape, MethodError>;

    /// (B5) Apply `edits` to the Set under the non-stomping CAS guard (ADR 0001 /
    /// ADR 0029), authorized by `cred`. v1 ships read-only, so the shell never calls
    /// this through the port yet; it shapes the seam the SSM writer maps onto and the
    /// future Secrets Manager staged-put write fits. A Method without a write path
    /// returns a masked [`MethodError`].
    async fn write(
        &self,
        cred: &Credential,
        mapping: &Mapping,
        edits: &[EnvEdit],
    ) -> Result<WriteOutcome, MethodError>;

    /// Whether this Method ever produces an operator [`advisory`](Self::advisory)
    /// — a static capability the shell checks *before* minting a probe Credential,
    /// so a Method with no side effect (Secrets Manager) costs no probe mint. `false`
    /// by default; the SSM method overrides to `true` (it always probes the org's
    /// session-logging policy, even when the runtime answer is "no logging").
    fn has_advisory(&self) -> bool {
        false
    }

    /// An operator **advisory** to surface before a read, authorized by `cred` (e.g.
    /// the SSM session-logging warning). Only probed when [`has_advisory`](Self::has_advisory)
    /// is `true`; the runtime answer may still be `None` (logging is off). Never a
    /// Value (THREAT-MODEL).
    async fn advisory(&self, _cred: &Credential, _mapping: &Mapping) -> Option<String> {
        None
    }

    /// The Method's Discovery *tail* as a [`Steps`] method (ADR 0026/0031): the
    /// shared `account → role → mint` front half composed with the Method's own
    /// location pick (a Secrets Manager secret, or an Instance + `.env` path). The
    /// shell wraps the returned `Box` in an `Orchestrator` and drives it; the chosen
    /// [`Method`] is stamped onto the `Done` Mapping by the shell.
    fn discovery_steps(
        &self,
        environment: String,
        region: String,
        token: Arc<SsoToken>,
        remembered: Option<Mapping>,
    ) -> Box<dyn Steps>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use janitor_core::discovery::StepPlan;

    /// A Method that overrides nothing optional — exercises the `has_advisory` /
    /// `advisory` defaults (the Secrets Manager method's shape).
    struct DefaultsMethod;
    #[async_trait]
    impl ResourceMethod for DefaultsMethod {
        fn kind(&self) -> Method {
            Method::SecretsManager
        }
        async fn fetch(
            &self,
            _cred: &Credential,
            _mapping: &Mapping,
        ) -> Result<SecretShape, MethodError> {
            Err(MethodError::Session(SessionError::NotFound))
        }
        async fn write(
            &self,
            _cred: &Credential,
            _mapping: &Mapping,
            _edits: &[crate::write::EnvEdit],
        ) -> Result<crate::write::WriteOutcome, MethodError> {
            Err(MethodError::Content {
                detail: "no write".into(),
            })
        }
        fn discovery_steps(
            &self,
            _environment: String,
            _region: String,
            _token: Arc<SsoToken>,
            _remembered: Option<Mapping>,
        ) -> Box<dyn Steps> {
            struct Empty;
            #[async_trait]
            impl Steps for Empty {
                async fn next(&mut self, _chosen: &[String]) -> StepPlan {
                    StepPlan::Terminal(janitor_core::provider::Step::Reauth)
                }
            }
            Box::new(Empty)
        }
    }

    #[tokio::test]
    async fn defaults_no_advisory_and_no_capability() {
        let m = DefaultsMethod;
        assert!(!m.has_advisory(), "default: no operator advisory");
        let cred = Credential::new(
            "a".into(),
            "b".into(),
            "c".into(),
            std::time::SystemTime::UNIX_EPOCH,
        );
        let mapping = Mapping {
            environment: "prod".into(),
            account_id: "1".into(),
            region: "r".into(),
            secret_id: "s".into(),
            permission_set: "ps".into(),
            method: Method::SecretsManager,
        };
        assert!(m.advisory(&cred, &mapping).await.is_none(), "default: None");
    }

    #[test]
    fn session_error_masks_through_the_session_variant() {
        // A recoverable auth error keeps its SessionError classification + safe
        // Display; the shell can still tell it is/ isn't a re-auth condition.
        let e = MethodError::Session(SessionError::AccessDenied);
        assert_eq!(e.reason(), FetchFailReason::AccessDenied);
        assert_eq!(e.detail(), "access denied for this Mapping");
        assert!(!e.is_reauth());

        let dead = MethodError::Session(SessionError::ReauthRequired);
        assert_eq!(dead.reason(), FetchFailReason::NeedsSignIn);
        assert!(dead.is_reauth());
    }

    #[test]
    fn content_error_is_unsupported_and_preserves_its_detail_without_recovery() {
        // The malformed-`.env` precise detail must survive the Content path (the
        // ADR 0031 open question), masked to Unsupported and never re-auth.
        let e = MethodError::Content {
            detail: "malformed .env line 4".into(),
        };
        assert_eq!(e.reason(), FetchFailReason::Unsupported);
        assert_eq!(e.detail(), "malformed .env line 4");
        assert!(!e.is_reauth());
    }

    #[test]
    fn content_detail_never_leaks_sdk_text_for_a_session_sdk_error() {
        // A scrubbed `Sdk` context masks to the catch-all reason; detail is the
        // SessionError's safe Display (the producer scrubs the context).
        let e = MethodError::Session(SessionError::Sdk {
            context: "GetSecretValue".into(),
        });
        assert_eq!(e.reason(), FetchFailReason::Other);
        assert!(!e.detail().contains("hunter2"));
    }
}
