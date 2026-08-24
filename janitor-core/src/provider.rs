//! The **Provider** port (ADR 0019): the single boundary the GUI depends on for
//! everything a [Provider](../../CONTEXT.md) does — Sign-in, loading an
//! Application's masked matrix, momentary reveal, and the guided Discovery walk.
//! It is the high-level, `Session`-shaped surface; each Provider owns its whole
//! pipeline internally and calls `core` (`Comparison::build`, `project`) for the
//! generic parts. AWS-specific vocabulary (accounts, roles, SSO, browser/loopback
//! Sign-in) stays *inside* each implementation and never crosses this port.
//!
//! The cross-boundary DTOs here are provider-agnostic in shape; a Provider's rich
//! internal error taxonomy is masked into these at the boundary (the same pattern
//! `janitor-aws` uses for `SessionError -> FetchFailReason`).

use async_trait::async_trait;

use crate::compare::RowKey;
use crate::config::{Application, Mapping, Method};
use crate::secret::Plaintext;
use crate::view::MatrixView;
use crate::write::{EnvEdit, WriteOutcome};

/// The port's agnostic Sign-in failure: an opaque, error-safe message. A Provider
/// maps its rich internal Sign-in error taxonomy (browser/loopback/OAuth mechanism
/// vocabulary a file Provider would never produce) into this at the boundary, so
/// nothing outside the Provider inspects those internal variants — the GUI shows
/// only the `Display` string or routes any failure back to "sign in again"
/// (ADR 0019). The wrapped message is already masked by the producer (THREAT-MODEL).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SignInFailed(String);

impl SignInFailed {
    /// Build from an already-error-safe message (a Provider's masked `Display`).
    pub fn new(message: impl Into<String>) -> Self {
        SignInFailed(message.into())
    }
}

/// Why one Environment's fetch failed — a masked, owned classification (no
/// Provider-internal text; THREAT-MODEL). `Copy` so it is trivial to carry. A
/// Provider maps its own per-fetch error taxonomy into this at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchFailReason {
    /// A fresh browser Sign-in is required (dead/again-rejected token).
    NeedsSignIn,
    /// The Provider refused under policy.
    AccessDenied,
    /// The secret id/region does not resolve.
    NotFound,
    /// Throttled or transient.
    Throttled,
    /// Content we cannot handle (e.g. binary for an op that needs text).
    Unsupported,
    /// Anything else (the scrubbed catch-all).
    Other,
}

impl FetchFailReason {
    /// A short, user-facing phrase. Never contains Provider-internal/secret text.
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

/// One Environment's failure within a whole-Application load: the Environment
/// name, the classified `reason` (drives control flow + a fallback label), and
/// the real, error-safe `detail` (ADR 0017). `detail` is what the banner and
/// Diagnostic Log show — never a Value/Credential/token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub environment: String,
    pub reason: FetchFailReason,
    pub detail: String,
}

/// A whole-Application load failure: at least one Environment failed, so no
/// matrix is shown (spec Decision 8 — never a partial matrix, never a fake Gap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppError {
    pub failures: Vec<Failure>,
}

impl AppError {
    /// The synthetic "you must sign in first" error (no real Environment failed).
    pub fn needs_sign_in() -> Self {
        AppError {
            failures: vec![Failure {
                environment: "(sign-in)".to_string(),
                reason: FetchFailReason::NeedsSignIn,
                detail: "a fresh Sign-in is required".to_string(),
            }],
        }
    }
}

/// A successful `Provider::load`: the masked matrix plus any Mappings whose
/// `permission_set` was auto-corrected this load (ADR 0018 stale-role recovery).
/// `corrected` is empty on the common path; when non-empty the GUI persists those
/// permission-set changes to Config (locations only).
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    pub view: MatrixView,
    pub corrected: Vec<Mapping>,
}

/// Which step of the guided walk produced an empty choice list, or which kind of
/// question an `Ask`/`Input` is posing. Carried by `Step::Empty`/`Ask`/`Input` so
/// the presenter can title the prompt or say "No accounts/roles/secrets you can
/// access" without the machine knowing about phrasing (ADR 0013). `Instances` and
/// `FilePath` are the remote-`.env`-over-SSM tail's labels (ADR 0025): `Instances`
/// titles the managed-Instance pick, `FilePath` titles the free-text `.env`-path
/// `Input`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum What {
    Accounts,
    Roles,
    Secrets,
    Instances,
    FilePath,
}

impl What {
    /// The question a picker or a text field puts above itself. The walk decides
    /// what it is asking for; this decides how that reads. Both shells render it.
    ///
    /// `FilePath` is posed as a free-text `Input` rather than a list `Ask`, so it
    /// never titles a picker. It is here so every variant has an answer.
    pub fn prompt(self) -> &'static str {
        match self {
            What::Accounts => "Choose an account:",
            What::Roles => "Choose a role:",
            What::Secrets => "Choose a secret:",
            What::Instances => "Choose an instance:",
            What::FilePath => "Choose a path:",
        }
    }
}

/// What the guided walk is currently asking, or its terminal outcome (ADR 0013).
/// `Ask` is presenter-ready: `choices` are the label lines to render in list
/// order and `default` is the index to pre-select (the remembered pick, if still
/// present); the typed items stay inside the Provider so the user's pick comes
/// back as a bare index. `what` lets the presenter title the list without knowing
/// the variant. `Done` carries the fully-formed Mapping ready to append.
/// `Empty`/`Failed` are masked terminal states (no Provider-internal text).
///
/// `Input` is the free-text counterpart of `Ask` (ADR 0025): instead of picking
/// one of N `choices`, the user types a value (e.g. a remote `.env` path). Its
/// `prompt` is the presenter-ready question line and `default` is the remembered
/// text to pre-fill — a path string, **not** an `Ask`'s `Option<usize>` index.
/// The typed value comes back via [`Provider::provide_input`]. No Provider in this
/// slice emits `Input`; it is the enabling rail the SSM Provider (#64) will ride.
#[derive(Debug)]
pub enum Step {
    Ask {
        what: What,
        choices: Vec<String>,
        default: Option<usize>,
    },
    Input {
        what: What,
        prompt: String,
        default: Option<String>,
    },
    Done(Mapping),
    Empty(What),
    Failed(FetchFailReason),
    /// The session is dead and could not be silently refreshed — a fresh browser
    /// Sign-in is required. A distinct terminal state (not `Failed`) so the
    /// presenter routes back to Sign-in rather than offering Back/Close (ADR 0013).
    Reauth,
}

/// The single boundary the GUI depends on (ADR 0019). It is the high-level,
/// `Session`-shaped surface a [Provider](../../CONTEXT.md) exposes: lazy Sign-in,
/// whole-Application load into a masked matrix, momentary reveal, and the guided
/// Discovery walk. Object-safe (via `async-trait`) so the GUI's worker can drive
/// `&mut dyn Provider`. A Provider that lacks a capability degrades gracefully
/// (no-auth Sign-in is a no-op; a presence-only Provider's `reveal` returns
/// `None`).
#[async_trait]
pub trait Provider: Send {
    /// Idempotent Sign-in (a no-op for a Provider without authentication). The
    /// rich internal failure is masked into the agnostic [`SignInFailed`].
    async fn sign_in(&mut self) -> Result<(), SignInFailed>;

    /// Load one Application: fetch every Environment and project the masked matrix
    /// (or a whole-app [`AppError`] naming the failed Environments — spec Decision
    /// 8). Plaintext Sets stay Provider-side; only the masked view crosses.
    async fn load(&mut self, app: &Application) -> Result<Loaded, AppError>;

    /// Momentary reveal of one cell's plaintext from the last load, as an owned
    /// [`Plaintext`] — the one explicit, on-demand plaintext crossing (ADR 0003),
    /// in the one type an exposed Value travels in (ADR 0035). `None` if the cell
    /// is gone/absent/unrevealable.
    fn reveal(&self, key: &RowKey, col: usize) -> Option<Plaintext>;

    /// Begin a guided [`Step`] walk for one new Environment (ADR 0013), backed by
    /// the chosen [`Method`] (ADR 0031). The method is picked *outside* the walk
    /// (the Manage window's per-row picker), so it is known before the first step
    /// and `core`'s `Step`/`What` surface needs no `Method` step. A Provider that
    /// has only one backend (the mock) ignores it. A failed Sign-in surfaces as the
    /// agnostic [`SignInFailed`].
    async fn begin_discovery(
        &mut self,
        method: Method,
        environment: String,
        region: String,
        remembered: Option<Mapping>,
    ) -> Result<Step, SignInFailed>;

    /// Feed the user's chosen index into the in-progress walk. `None` if no walk
    /// is in progress.
    async fn advance_discovery(&mut self, choice: usize) -> Option<Step>;

    /// Feed the user's typed text into a walk paused on a [`Step::Input`] (ADR 0025),
    /// the free-text counterpart of `advance_discovery`. `None` if no walk is in
    /// progress (or the Provider never poses an `Input` — the default for every
    /// Provider in this slice). The text is a location (a path), never a Value.
    async fn provide_input(&mut self, text: String) -> Option<Step>;

    /// Drain any operator **advisories** the Provider has accumulated since the
    /// last call: short, already-masked notes about an unavoidable, operator-
    /// visible side effect of a read — e.g. org-wide SSM session logging copies the
    /// remote file to S3/CloudWatch (ADR 0025, the remote-`.env` Provider). The
    /// worker surfaces each once, to both the Diagnostic Log and the Discovery
    /// wizard. Provider-agnostic: a Provider with no such side effect returns empty
    /// (the default). The strings are policy notes — never a Value/Credential/token
    /// (THREAT-MODEL).
    async fn take_advisories(&mut self) -> Vec<String> {
        Vec::new()
    }

    /// Apply `edits` to one Environment's Set under the non-stomping CAS engine
    /// (ADR 0001 / ADR 0029), authorized for `mapping` (its `method` selects the
    /// backend; ADR 0031/0032). Method-agnostic: the masked `WriteOutcome`
    /// distinguishes the CAS [`Applied`](WriteOutcome::Applied) from a
    /// [`Conflict`](WriteOutcome::Conflict) (the remote Set changed under us — re-read
    /// and retry), and any real failure is masked into a [`Failure`] (same taxonomy
    /// the read side uses; never a Value/Credential/SDK text — THREAT-MODEL).
    ///
    /// **v1 is read-only**: the worker only reaches this in deliberately-unlocked
    /// read-write mode (ADR 0004), and the GUI confirms the diff first. A Provider
    /// without a write path degrades gracefully — the default returns a masked
    /// [`FetchFailReason::Unsupported`] `Failure`, so a presence-only Provider need
    /// not override it. The edit Values reach only the Provider; nothing here logs
    /// them.
    async fn write(
        &mut self,
        mapping: &Mapping,
        _edits: &[EnvEdit],
    ) -> Result<WriteOutcome, Failure> {
        Err(Failure {
            environment: mapping.environment.clone(),
            reason: FetchFailReason::Unsupported,
            detail: "writes are not supported".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretShape;

    #[test]
    fn every_walk_step_has_a_question() {
        // The Slint shell built these inline. Both shells read them now (#97), so a
        // What added without a prompt has to fail here rather than render blank.
        assert_eq!(What::Accounts.prompt(), "Choose an account:");
        assert_eq!(What::Roles.prompt(), "Choose a role:");
        assert_eq!(What::Secrets.prompt(), "Choose a secret:");
        assert_eq!(What::Instances.prompt(), "Choose an instance:");
        assert_eq!(What::FilePath.prompt(), "Choose a path:");
    }

    #[test]
    fn sign_in_failed_display_is_the_masked_message() {
        // The port carries only an opaque, error-safe message the producer already
        // masked — Display surfaces exactly that (the GUI's banner string).
        let e = SignInFailed::new("a fresh Sign-in is required");
        assert_eq!(e.to_string(), "a fresh Sign-in is required");
    }

    #[test]
    fn describe_is_a_short_masked_phrase_per_reason() {
        // Pure, Provider-agnostic phrasing — never any internal/SDK text.
        assert_eq!(
            FetchFailReason::NeedsSignIn.describe(),
            "session expired — sign in again"
        );
        assert_eq!(FetchFailReason::AccessDenied.describe(), "access denied");
        assert_eq!(FetchFailReason::NotFound.describe(), "secret not found");
        assert_eq!(
            FetchFailReason::Throttled.describe(),
            "throttled, try again"
        );
        assert_eq!(
            FetchFailReason::Unsupported.describe(),
            "unsupported secret content"
        );
        assert_eq!(FetchFailReason::Other.describe(), "AWS error");
    }

    #[test]
    fn needs_sign_in_names_a_synthetic_environment() {
        let e = AppError::needs_sign_in();
        assert_eq!(e.failures.len(), 1);
        assert_eq!(e.failures[0].reason, FetchFailReason::NeedsSignIn);
    }

    #[test]
    fn port_dtos_are_send() {
        // The worker marshals these across the thread boundary, so the masked
        // matrix, the shaped Set it is built from, and the whole-app error must
        // all be `Send`.
        fn assert_send<T: Send>() {}
        assert_send::<MatrixView>();
        assert_send::<SecretShape>();
        assert_send::<AppError>();
        assert_send::<Loaded>();
        assert_send::<Step>();
        // The worker marshals a pending write's edits + outcome across the thread
        // boundary too (`Command::ApplyEdits` / the outcome `Event`).
        assert_send::<EnvEdit>();
        assert_send::<WriteOutcome>();
        assert_send::<Failure>();
    }

    #[test]
    fn provider_is_object_safe() {
        // The worker drives `&mut dyn Provider`; this only compiles if the trait
        // is object-safe (async-trait boxes the futures).
        fn _assert_object_safe(_: &mut dyn Provider) {}
    }

    /// A Provider that overrides only the required methods — exercises the graceful
    /// `write` default (a presence-only / read-only Provider that cannot mutate).
    struct ReadOnlyProvider;
    #[async_trait]
    impl Provider for ReadOnlyProvider {
        async fn sign_in(&mut self) -> Result<(), SignInFailed> {
            Ok(())
        }
        async fn load(&mut self, _app: &Application) -> Result<Loaded, AppError> {
            Err(AppError::needs_sign_in())
        }
        fn reveal(&self, _key: &RowKey, _col: usize) -> Option<Plaintext> {
            None
        }
        async fn begin_discovery(
            &mut self,
            _method: Method,
            _environment: String,
            _region: String,
            _remembered: Option<Mapping>,
        ) -> Result<Step, SignInFailed> {
            Ok(Step::Reauth)
        }
        async fn advance_discovery(&mut self, _choice: usize) -> Option<Step> {
            None
        }
        async fn provide_input(&mut self, _text: String) -> Option<Step> {
            None
        }
    }

    #[tokio::test]
    async fn write_default_is_a_masked_unsupported_failure() {
        // A Provider with no write path degrades gracefully: the default `write`
        // returns a masked Unsupported `Failure` naming the Environment, never a panic
        // and never any Value (THREAT-MODEL).
        let mut p = ReadOnlyProvider;
        let mapping = Mapping {
            environment: "prod".into(),
            account_id: "111".into(),
            region: "us-east-1".into(),
            secret_id: "s".into(),
            permission_set: "ps".into(),
            method: Method::SecretsManager,
        };
        let err = p
            .write(&mapping, &[crate::write::EnvEdit::set("A", "2")])
            .await
            .unwrap_err();
        assert_eq!(err.environment, "prod");
        assert_eq!(err.reason, FetchFailReason::Unsupported);
        assert!(
            !format!("{err:?}").contains('2'),
            "the masked failure must not echo the edit Value"
        );
    }
}
