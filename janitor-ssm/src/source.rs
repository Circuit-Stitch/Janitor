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
            parse_dotenv(&text).map_err(DotenvFetchError::Malformed)
        }
        // A `.env` is text; a binary or empty payload is not one we can compare.
        None => Err(DotenvFetchError::Read(SessionError::Unsupported)),
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
}
