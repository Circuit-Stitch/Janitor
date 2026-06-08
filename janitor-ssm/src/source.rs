//! Reading and shaping one remote `.env` (ADR 0025): pull the file off the
//! Instance through the [`RemoteFileReader`] seam, parse `KEY=VALUE` into the
//! same flat [`SecretShape`] a JSON Set produces, and mask any failure into the
//! port's [`FetchFailReason`]. The credential minting for a whole-Application
//! load is brokered per Environment by [`SsmSource`].
//!
//! Two failure sources fold into one masked classification at this seam, so no
//! raw SSM/SDK text and no `.env` line content ever reaches a Value, an `Event`,
//! or the Diagnostic Log (THREAT-MODEL): a read failure ([`SessionError`], via
//! the shared `From<&SessionError>` impl in `janitor-aws-auth`) and a malformed
//! `.env` ([`DotenvError`], B2's crate-local error → `Unsupported`).

use std::sync::Arc;

use zeroize::Zeroizing;

use janitor_core::config::Mapping;
use janitor_core::provider::FetchFailReason;
use janitor_core::secret::SecretShape;

use janitor_aws_auth::broker::CredentialBroker;
use janitor_aws_auth::error::SessionError;
use janitor_aws_auth::types::Credential;

use crate::dotenv::{parse_dotenv, DotenvError};
use crate::logging::{session_logging_advisory, LoggingPreference};
use crate::wire::RemoteFileReader;

/// Split a remote-`.env` `Mapping`'s `secret_id` — `"<instance-id>:<path>"`
/// (ADR 0025) — back into its `(instance_id, path)` parts. Splits on the **first**
/// `':'`: an instance id (`i-…`/`mi-…`) never contains one, and an absolute Unix
/// path does not start with one, so any `':'` in the remainder belongs to the
/// path. `None` if there is no `':'` (a malformed location).
pub(crate) fn split_secret_id(secret_id: &str) -> Option<(&str, &str)> {
    secret_id.split_once(':')
}

/// A failed remote-`.env` fetch, masked for the port. Folds the two failure
/// sources — a read error ([`SessionError`]) and a malformed `.env`
/// ([`DotenvError`]) — into one classified [`FetchFailReason`] plus an
/// error-safe `detail`, keeping `ReauthRequired` distinguishable so the walk can
/// route to `Step::Reauth` rather than a retryable `Failed` (ADR 0013).
#[derive(Debug)]
pub(crate) enum DotenvFetchError {
    /// The SSM read (or credential mint) failed. Masked via the shared
    /// `From<&SessionError>` impl (ADR 0024) — no SDK text crosses.
    Read(SessionError),
    /// The file was read but is not a well-formed `.env`. B2's `DotenvError`
    /// names only a 1-based line number (never line content); it maps to
    /// `Unsupported` here at the SSM seam (ADR 0025).
    Malformed(DotenvError),
}

impl DotenvFetchError {
    /// The masked, port-facing classification (drives control flow + a fallback
    /// label). Never carries SSM/SDK text or `.env` content.
    pub(crate) fn reason(&self) -> FetchFailReason {
        match self {
            DotenvFetchError::Read(e) => FetchFailReason::from(e),
            DotenvFetchError::Malformed(_) => FetchFailReason::Unsupported,
        }
    }

    /// An error-safe detail string for the load banner + Diagnostic Log
    /// (ADR 0017). For a read error this is the `SessionError`'s already-scrubbed
    /// `Display`; for a malformed `.env` it is `"malformed .env line N"` — never a
    /// Value, a Credential, or any `.env` line content.
    pub(crate) fn detail(&self) -> String {
        match self {
            DotenvFetchError::Read(e) => e.to_string(),
            DotenvFetchError::Malformed(e) => e.to_string(),
        }
    }

    /// Whether this is a dead-token failure (routes to `Step::Reauth`, not
    /// `Step::Failed`). A malformed `.env` is never a re-auth condition.
    pub(crate) fn is_reauth(&self) -> bool {
        matches!(self, DotenvFetchError::Read(SessionError::ReauthRequired))
    }
}

/// Read `path` off `instance_id` over the [`RemoteFileReader`] seam and parse it
/// into a [`SecretShape`]. The raw payload arrives in a zeroize-on-drop
/// [`RawSecret`] whose `secret_string` must be `take`n to read it (the field
/// cannot be moved out of a `Drop` type by value; ADR 0024). That `take` yields a
/// plain `String`, so it is immediately wrapped in [`Zeroizing`] — the whole-file
/// plaintext then lives only in a buffer that is scrubbed on drop, never a bare
/// `String` (THREAT-MODEL; decoded Entry Values land in the zeroizing `Value`,
/// ADR 0008). A `.env` is text: a response with no `secret_string` (binary/empty)
/// is `Unsupported`.
pub(crate) async fn read_and_parse(
    reader: &dyn RemoteFileReader,
    cred: &Credential,
    instance_id: &str,
    region: &str,
    path: &str,
) -> Result<SecretShape, DotenvFetchError> {
    let mut raw = reader
        .read_file(cred, instance_id, region, path)
        .await
        .map_err(DotenvFetchError::Read)?;
    match raw.secret_string.take() {
        Some(text) => {
            let text = Zeroizing::new(text);
            // Opt-in, threat-model-safe structural trace of the read payload (no
            // Value, no key text, no line content) — gated on `JANITOR_SSM_DIAG`
            // so the live harness can see *why* a real `.env` was rejected without
            // ever logging it (ADR 0025 §3 live verify).
            diag_dotenv_structure(&text);
            parse_dotenv(&text).map_err(|e| {
                let e = DotenvFetchError::Malformed(e);
                // `detail()` names only a 1-based line number, never content
                // (THREAT-MODEL) — log it so the live harness / Diagnostic Log can
                // pinpoint the offending line, as the masked port hides the reason.
                tracing::warn!(target: "janitor::ssm", "{}", e.detail());
                e
            })
        }
        // A `.env` is text; a binary or empty payload is not one we can compare.
        None => Err(DotenvFetchError::Read(SessionError::Unsupported)),
    }
}

/// Opt-in (`JANITOR_SSM_DIAG=1`) structural trace of a read `.env` payload, for
/// the live harness to diagnose a `Malformed`/`Unsupported` read **without ever
/// logging file content** (THREAT-MODEL). For each physical line it emits only the
/// 1-based line number, the byte length, a parser-relevant classification (blank /
/// comment / `has-eq` with the *key length* / `no-eq` / `empty-key`), and a flag
/// for any control characters (ANSI/PTY junk a non-interactive read shouldn't carry)
/// — never an Entry Name, a Value, or any line text.
fn diag_dotenv_structure(text: &str) {
    if std::env::var_os("JANITOR_SSM_DIAG").is_none() {
        return;
    }
    let line_count = text.lines().count();
    tracing::warn!(target: "janitor::ssm", "diag .env: {} bytes, {line_count} lines", text.len());
    for (index, line) in text.lines().enumerate() {
        let n = index + 1;
        let len = line.len();
        let control = line.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f);
        let trimmed = line.trim_start();
        let assignment = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let kind = if trimmed.is_empty() {
            "blank".to_string()
        } else if trimmed.starts_with('#') {
            "comment".to_string()
        } else if let Some(eq) = assignment.find('=') {
            let key_len = assignment[..eq].trim().len();
            if key_len == 0 {
                "empty-key".to_string()
            } else {
                format!("has-eq key_len={key_len}")
            }
        } else {
            "no-eq".to_string()
        };
        tracing::warn!(target: "janitor::ssm", "diag line {n}: len={len} kind={kind} control={control}");
    }
}

/// Mints a role Credential per Environment (via the shared [`CredentialBroker`])
/// and reads+parses that Environment's remote `.env`. The SSM analogue of
/// `janitor-aws`'s `AuthenticatedSource` — but simpler: the broker already
/// silently re-mints near expiry, and a dead token / denial surfaces as a masked
/// whole-app `Failure` that routes the GUI back to Sign-in, so this slice omits
/// the at-most-once force-refresh + re-Sign-in fetch ladder (it is the kind of
/// resilience #33/ADR 0026 will unify across both Providers, not re-duplicate).
pub(crate) struct SsmSource {
    broker: CredentialBroker,
    reader: Arc<dyn RemoteFileReader>,
}

impl SsmSource {
    pub(crate) fn new(broker: CredentialBroker, reader: Arc<dyn RemoteFileReader>) -> Self {
        SsmSource { broker, reader }
    }

    /// Fetch and shape the Set for `mapping`: split its `<instance-id>:<path>`
    /// location, mint a Credential for it, then read+parse the file.
    pub(crate) async fn fetch(&self, mapping: &Mapping) -> Result<SecretShape, DotenvFetchError> {
        let (instance_id, path) = split_secret_id(&mapping.secret_id)
            // A Mapping whose location is not `<instance-id>:<path>` resolves to
            // nothing — surface it masked, never echoing the malformed string.
            .ok_or(DotenvFetchError::Read(SessionError::NotFound))?;
        let cred = self
            .broker
            .credentials_for(mapping)
            .await
            .map_err(DotenvFetchError::Read)?;
        read_and_parse(
            self.reader.as_ref(),
            cred.as_ref(),
            instance_id,
            &mapping.region,
            path,
        )
        .await
    }

    /// Probe the org's SSM session-logging policy for `mapping` (mint a Credential,
    /// then ask `logging`) and distil it to an operator advisory (ADR 0025).
    /// `None` means "no logging configured" (or the mint failed — see below). Used
    /// by `load` to warn once per Application before any read.
    ///
    /// Only a *successful* mint warrants an advisory. A mint failure is the load's
    /// real error (surfaced per-Environment as a `Failure`), not a logging-policy
    /// uncertainty — raising the always-on fallback for it would mislead (it reads
    /// like a logging-permission problem when the user simply isn't entitled to the
    /// role). The fallback still fires when the cred mints but `GetDocument` itself
    /// is denied/unreachable (a genuine "can't determine logging" case).
    pub(crate) async fn logging_advisory(
        &self,
        mapping: &Mapping,
        logging: &dyn LoggingPreference,
    ) -> Option<String> {
        let cred = self.broker.credentials_for(mapping).await.ok()?;
        let probe = logging
            .session_logging(cred.as_ref(), &mapping.region)
            .await;
        session_logging_advisory(&probe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::fakes::FakeRemoteFileReader;
    use janitor_aws_auth::types::SsoToken;
    use janitor_aws_auth::wire::fakes::{CredSpec, FakeClock, FakeRoleClient};
    use janitor_aws_auth::wire::RawSecret;
    use std::time::{Duration, SystemTime};

    fn mapping(secret_id: &str) -> Mapping {
        Mapping {
            environment: "prod".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: secret_id.into(),
            permission_set: "ReadOnly".into(),
        }
    }
    fn cred() -> Credential {
        Credential::new("a".into(), "b".into(), "c".into(), SystemTime::UNIX_EPOCH)
    }
    fn broker(role: Arc<FakeRoleClient>) -> CredentialBroker {
        let token = Arc::new(SsoToken::new(
            "t".into(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(28800),
        ));
        CredentialBroker::new(token, role, Arc::new(FakeClock::at(0)))
    }
    fn cred_ok() -> Result<CredSpec, SessionError> {
        Ok(CredSpec {
            expires_in: Duration::from_secs(3600),
            tag: "t",
        })
    }

    // ---- split_secret_id ----

    #[test]
    fn split_secret_id_separates_instance_and_path_on_first_colon() {
        assert_eq!(
            split_secret_id("i-0abc:/app/.env"),
            Some(("i-0abc", "/app/.env"))
        );
    }

    #[test]
    fn split_secret_id_keeps_a_colon_inside_the_path() {
        // The instance id has no colon, so the first colon delimits; any later
        // colon belongs to the path.
        assert_eq!(
            split_secret_id("i-0abc:/weird:path/.env"),
            Some(("i-0abc", "/weird:path/.env"))
        );
    }

    #[test]
    fn split_secret_id_is_none_without_a_colon() {
        assert_eq!(split_secret_id("i-0abc"), None);
    }

    // ---- read_and_parse ----

    #[tokio::test]
    async fn read_and_parse_turns_dotenv_text_into_a_json_shape() {
        let reader = FakeRemoteFileReader::with_dotenv(vec!["A=1\nB=two"]);
        let shape = read_and_parse(&reader, &cred(), "i-0abc", "us-east-1", "/app/.env")
            .await
            .unwrap();
        assert!(matches!(shape, SecretShape::Json(_)));
        assert_eq!(
            reader.seen(),
            vec![("i-0abc".into(), "/app/.env".into())],
            "the instance + path are passed through to the reader"
        );
    }

    #[tokio::test]
    async fn read_failure_is_masked_to_its_reason_with_no_sdk_text() {
        let reader = FakeRemoteFileReader::new(vec![Err(SessionError::Sdk {
            context: "hunter2".into(),
        })]);
        let err = read_and_parse(&reader, &cred(), "i-0abc", "us-east-1", "/app/.env")
            .await
            .unwrap_err();
        assert_eq!(err.reason(), FetchFailReason::Other);
        assert!(
            !err.reason().describe().contains("hunter2"),
            "no SDK text leaks into the masked reason"
        );
    }

    #[tokio::test]
    async fn malformed_dotenv_is_unsupported_and_leaks_no_line_content() {
        // A line with no `=` is malformed; the masked error names only a line
        // number, never the offending content (THREAT-MODEL).
        let reader = FakeRemoteFileReader::with_dotenv(vec!["A=1\nNOTANASSIGNMENT_secret"]);
        let err = read_and_parse(&reader, &cred(), "i-0abc", "us-east-1", "/app/.env")
            .await
            .unwrap_err();
        assert_eq!(err.reason(), FetchFailReason::Unsupported);
        assert_eq!(err.detail(), "malformed .env line 2");
        assert!(
            !err.detail().contains("NOTANASSIGNMENT_secret"),
            "no .env line content leaks into the detail"
        );
        assert!(!err.is_reauth());
    }

    #[tokio::test]
    async fn binary_payload_is_unsupported() {
        let reader = FakeRemoteFileReader::new(vec![Ok(RawSecret {
            secret_string: None,
            secret_binary: Some(vec![0, 1, 2]),
        })]);
        let err = read_and_parse(&reader, &cred(), "i-0abc", "us-east-1", "/app/.env")
            .await
            .unwrap_err();
        assert_eq!(err.reason(), FetchFailReason::Unsupported);
    }

    #[tokio::test]
    async fn reauth_read_failure_is_flagged_for_reauth_routing() {
        let reader = FakeRemoteFileReader::new(vec![Err(SessionError::ReauthRequired)]);
        let err = read_and_parse(&reader, &cred(), "i-0abc", "us-east-1", "/app/.env")
            .await
            .unwrap_err();
        assert!(err.is_reauth());
        assert_eq!(err.reason(), FetchFailReason::NeedsSignIn);
    }

    // ---- SsmSource ----

    #[tokio::test]
    async fn source_mints_a_credential_then_reads_and_parses() {
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let reader = Arc::new(FakeRemoteFileReader::with_dotenv(vec!["A=1"]));
        let src = SsmSource::new(broker(role.clone()), reader.clone());
        let shape = src.fetch(&mapping("i-0abc:/app/.env")).await.unwrap();
        assert!(matches!(shape, SecretShape::Json(_)));
        assert_eq!(role.call_count(), 1, "minted exactly one credential");
        assert_eq!(reader.seen(), vec![("i-0abc".into(), "/app/.env".into())]);
    }

    #[tokio::test]
    async fn source_malformed_location_is_not_found_without_minting() {
        // A Mapping whose secret_id is not `<instance>:<path>` fails before any
        // credential is minted or any read attempted.
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let reader = Arc::new(FakeRemoteFileReader::new(vec![]));
        let src = SsmSource::new(broker(role.clone()), reader.clone());
        let err = src.fetch(&mapping("i-0abc-no-colon")).await.unwrap_err();
        assert_eq!(err.reason(), FetchFailReason::NotFound);
        assert_eq!(role.call_count(), 0, "no mint for an unresolvable location");
        assert_eq!(reader.call_count(), 0);
    }

    #[tokio::test]
    async fn source_propagates_a_dead_token_from_minting() {
        let role = Arc::new(FakeRoleClient::new(vec![Err(SessionError::ReauthRequired)]));
        let reader = Arc::new(FakeRemoteFileReader::new(vec![]));
        let src = SsmSource::new(broker(role), reader.clone());
        let err = src.fetch(&mapping("i-0abc:/app/.env")).await.unwrap_err();
        assert!(err.is_reauth());
        assert_eq!(reader.call_count(), 0, "no read when minting fails");
    }

    #[tokio::test]
    async fn logging_advisory_is_none_when_minting_fails() {
        // A mint failure (e.g. not entitled to the role) is the load's real error,
        // not a logging-policy uncertainty: no misleading always-on advisory even
        // though the scripted logging probe says S3 logging is on.
        use crate::logging::fakes::FakeLoggingPreference;
        use crate::logging::LoggingState;
        let role = Arc::new(FakeRoleClient::new(vec![Err(
            SessionError::RoleNotEntitled {
                context: "no access".into(),
            },
        )]));
        let logging = FakeLoggingPreference::always(LoggingState {
            s3: true,
            ..Default::default()
        });
        let src = SsmSource::new(broker(role), Arc::new(FakeRemoteFileReader::new(vec![])));
        assert!(src
            .logging_advisory(&mapping("i-0abc:/app/.env"), &logging)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn logging_advisory_warns_when_minted_and_logging_on() {
        // The complement: a successful mint plus a logging-on probe yields the
        // advisory (so the mint-failure short-circuit above didn't break the path).
        use crate::logging::fakes::FakeLoggingPreference;
        use crate::logging::LoggingState;
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let logging = FakeLoggingPreference::always(LoggingState {
            cloudwatch: true,
            ..Default::default()
        });
        let src = SsmSource::new(broker(role), Arc::new(FakeRemoteFileReader::new(vec![])));
        let adv = src
            .logging_advisory(&mapping("i-0abc:/app/.env"), &logging)
            .await
            .expect("logging-on yields an advisory");
        assert!(adv.contains("CloudWatch"));
    }
}
