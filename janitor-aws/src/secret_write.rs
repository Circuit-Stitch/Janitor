//! The Secrets Manager **non-stomping write** engine (ADR 0001 + its Amendment
//! 2026-06-25; #89). The read+shape path lives in [`SecretsClient`](crate::secrets);
//! this module is the Method's *write* tail: the flat-JSON merge, the staged-put /
//! atomic-CAS sequence (ADR 0001 steps 3–6), conflict model B, the bounded
//! replay-on-fresh retry, and the [`SecretsManagerWriter`] the `live-verify-sm-write`
//! binary drives. The analogue of `janitor-ssm`'s `write_dotenv`/`SsmWriter`.
//!
//! **Flat-JSON only.** A Set is merged via `serde_json`: parse the current blob,
//! replace/insert/remove the edited *top-level* keys, re-serialize, and preserve
//! every untouched key verbatim — including any non-string scalar value (a key we
//! did not edit is never re-typed). A Set that is **not** a flat JSON object —
//! nested (an object/array value), a top-level array, a bare non-JSON string, or
//! `secret_binary` — is refused as [`SecretWriteError::NotFlat`]; we never guess an
//! un-flatten. The flat [`EnvEdit`] unit fits directly — no new edit type.
//!
//! **Conflict model B (per-Entry conflict-stop), base = the write's own first read.**
//! Each attempt re-reads (this read is the CAS `base`, not the matrix-load version),
//! merges onto the *fresh* blob, stages, and atomically commits. On a CAS race
//! (commit fails because `AWSCURRENT` moved), the next attempt's re-read is compared
//! against the prior read: a key **we edited** that changed → stop with
//! [`WriteOutcome::Conflict`] (never auto-merge); only **other** keys changed →
//! replay onto fresh + retry, bounded by [`MAX_ATTEMPTS`]. A persistent race ends as
//! `Conflict`.
//!
//! THREAT-MODEL: the merged blob and every Value are held [`Zeroizing`] and reach
//! only the writer; the `ClientRequestToken` / `VersionId` are non-secret opaque ids
//! (OK to log). No Value and no SDK text crosses a `Failure`/`Event`/log/`Debug`.

use std::sync::Arc;

use serde_json::{Map, Value as JsonValue};
use uuid::Uuid;
use zeroize::Zeroizing;

use janitor_aws_auth::broker::CredentialBroker;
use janitor_aws_auth::error::SessionError;
use janitor_aws_auth::types::Credential;
use janitor_aws_auth::write::{EnvEdit, EnvWriteError, WriteOutcome};
use janitor_core::config::Mapping;
use janitor_core::provider::FetchFailReason;

use crate::wire::{CasOutcome, SecretsApi};

/// The bounded number of read-modify-write attempts before a persistent CAS race
/// surfaces as `Conflict` (ADR 0001 caps retries — each is a real round-trip and an
/// unbounded loop under contention is its own quota hazard). Mirrors the SSM writer.
const MAX_ATTEMPTS: u32 = 3;

/// A failed Secrets Manager write, masked for the port (mirrors `DotenvWriteError`).
#[derive(Debug)]
pub enum SecretWriteError {
    /// A read (the CAS re-read) or a write call failed. Masked via the shared
    /// `From<&SessionError>` impl — no SDK text crosses (THREAT-MODEL).
    Session(SessionError),
    /// The Set is not a flat JSON object we can safely merge (nested/array/bare
    /// string/binary). Never carries any Value or blob content.
    NotFlat,
    /// An edit could not be applied (an invalid key). Never carries a Value.
    Edit(EnvWriteError),
}

impl SecretWriteError {
    /// The masked, port-facing classification. Never carries SDK text or a Value.
    pub fn reason(&self) -> FetchFailReason {
        match self {
            SecretWriteError::Session(e) => FetchFailReason::from(e),
            SecretWriteError::NotFlat | SecretWriteError::Edit(_) => FetchFailReason::Unsupported,
        }
    }

    /// An error-safe detail string (ADR 0017): the `SessionError`'s already-scrubbed
    /// `Display`, a fixed phrase, or `EnvWriteError`'s key-less message — never a
    /// Value, a Credential, or any blob content.
    pub fn detail(&self) -> String {
        match self {
            SecretWriteError::Session(e) => e.to_string(),
            SecretWriteError::NotFlat => {
                "secret is not a flat JSON object (cannot merge safely)".to_string()
            }
            SecretWriteError::Edit(e) => e.to_string(),
        }
    }

    /// Whether this is a dead-token failure (routes to re-Sign-in, not a retry).
    pub fn is_reauth(&self) -> bool {
        matches!(
            self,
            SecretWriteError::Session(SessionError::ReauthRequired)
        )
    }
}

/// Fail closed if any edit targets an unwritable key — an empty top-level key. The
/// write orchestration calls this *before* any AWS round-trip, so a malformed edit
/// never triggers a wasted call. (Any non-empty string is a valid JSON object key,
/// so unlike the `.env` writer there is nothing further to reject.)
fn validate_edits(edits: &[EnvEdit]) -> Result<(), EnvWriteError> {
    if edits.iter().any(|e| e.key().is_empty()) {
        return Err(EnvWriteError::InvalidKey);
    }
    Ok(())
}

/// Parse `text` as a **flat** JSON object: a top-level object whose values are all
/// scalars (string/number/bool/null). `None` if the top level is not an object, the
/// JSON is invalid, or any value is itself an object/array (nested — we never guess
/// an un-flatten). A literal dotted key like `"a.b"` is a fine top-level key; only a
/// nested *structure* is refused.
fn parse_flat(text: &str) -> Option<Map<String, JsonValue>> {
    match serde_json::from_str::<JsonValue>(text).ok()? {
        JsonValue::Object(m) if m.values().all(|v| !v.is_object() && !v.is_array()) => Some(m),
        _ => None,
    }
}

/// Apply `edits` to a parsed flat object, returning the merged object. Untouched
/// keys (and their non-string scalar values) are preserved verbatim; a `Set` always
/// writes a JSON *string* (Janitor Values are strings); a `Remove` drops the key.
fn merge(current: &Map<String, JsonValue>, edits: &[EnvEdit]) -> Map<String, JsonValue> {
    let mut out = current.clone();
    for e in edits {
        match e {
            EnvEdit::Set { key, value } => {
                // The plaintext briefly lives in a (non-zeroizing) serde value here;
                // it is serialized into a Zeroizing buffer immediately below and the
                // serde tree drops at end of `write_secret`'s scope.
                out.insert(key.clone(), JsonValue::String(value.expose_owned()));
            }
            EnvEdit::Remove { key } => {
                out.remove(key);
            }
        }
    }
    out
}

/// Read-modify-write `edits` into the Secrets Manager Set `secret_id` in `region`,
/// authorized by `cred` (ADR 0001 steps 2–6 + conflict model B). See the module doc.
pub(crate) async fn write_secret(
    api: &dyn SecretsApi,
    cred: &Credential,
    secret_id: &str,
    region: &str,
    edits: &[EnvEdit],
) -> Result<WriteOutcome, SecretWriteError> {
    // Reject an unwritable key before any AWS round-trip (deterministic, fail-closed).
    validate_edits(edits).map_err(SecretWriteError::Edit)?;

    let edited_keys: Vec<&str> = edits.iter().map(EnvEdit::key).collect();
    // The edited keys' values from the PREVIOUS read, for the conflict-stop check.
    let mut prev_edited: Option<Vec<Option<JsonValue>>> = None;
    // The previous attempt's merged payload + token, so a byte-identical re-merge
    // reuses the idempotency token (ADR 0001 token rule); a *distinct* payload gets
    // a fresh one (AWS rejects a reused token paired with different data).
    let mut prev_merge: Option<(Zeroizing<String>, String)> = None;

    for _ in 0..MAX_ATTEMPTS {
        let mut read = api
            .get_secret_value(cred, secret_id, region)
            .await
            .map_err(SecretWriteError::Session)?;
        // Whole-blob plaintext: take()n out of the zeroize-on-drop RawSecret and
        // re-wrapped Zeroizing (a field can't be moved out of a Drop type, ADR 0024).
        let current_text = match read.raw.secret_string.take() {
            Some(s) => Zeroizing::new(s),
            None => return Err(SecretWriteError::NotFlat), // binary / empty
        };
        let current = parse_flat(&current_text).ok_or(SecretWriteError::NotFlat)?;
        // The CAS base: AWSCURRENT's VersionId, which the commit removes the label
        // from. GetSecretValue always returns one; without it we can't CAS safely.
        let version_id = read.version_id.ok_or_else(|| {
            SecretWriteError::Session(SessionError::Sdk {
                context: "GetSecretValue: no VersionId".into(),
            })
        })?;

        // Conflict-stop (model B): did a key WE edited change since our last read?
        if let Some(prev) = &prev_edited {
            for (key, was) in edited_keys.iter().zip(prev) {
                if current.get(*key) != was.as_ref() {
                    return Ok(WriteOutcome::Conflict);
                }
            }
        }
        prev_edited = Some(
            edited_keys
                .iter()
                .map(|k| current.get(*k).cloned())
                .collect(),
        );

        // Merge onto the FRESH blob (replay-on-fresh — a teammate's untouched keys
        // survive). A no-op merge writes nothing (don't manufacture a version).
        let merged = merge(&current, edits);
        if merged == current {
            return Ok(WriteOutcome::Applied);
        }
        let merged_text = Zeroizing::new(
            serde_json::to_string(&JsonValue::Object(merged)).expect("serialize a JSON object"),
        );

        // Fresh token per distinct payload; reuse on a byte-identical re-merge.
        let token = match &prev_merge {
            Some((prev_text, prev_token)) if **prev_text == *merged_text => prev_token.clone(),
            _ => Uuid::new_v4().to_string(),
        };
        prev_merge = Some((merged_text.clone(), token.clone()));
        // One pending stage label per token (ADR 0001 step 3); passing an explicit
        // stage means PutSecretValue does NOT move AWSCURRENT.
        let pending = format!("janitor-pending-{token}");

        let new_version = api
            .put_secret_value(
                cred,
                secret_id,
                region,
                merged_text.clone(),
                &token,
                std::slice::from_ref(&pending),
            )
            .await
            .map_err(SecretWriteError::Session)?;

        // Atomic CAS commit (step 4): move AWSCURRENT new<-current iff it still holds
        // `version_id`. A Mismatch means a concurrent write moved it.
        let outcome = api
            .update_secret_version_stage(
                cred,
                secret_id,
                region,
                "AWSCURRENT",
                Some(&new_version),
                Some(&version_id),
            )
            .await
            .map_err(SecretWriteError::Session)?;
        match outcome {
            CasOutcome::Committed => {
                // Settle (step 5): strip the temporary pending label.
                settle(api, cred, secret_id, region, &pending, &new_version).await;
                return Ok(WriteOutcome::Applied);
            }
            CasOutcome::Mismatch => {
                // Cleanup MANDATORY (step 6): strip the orphaned pending label so AWS
                // can reclaim the version (a quota hazard, not optional). Then retry.
                settle(api, cred, secret_id, region, &pending, &new_version).await;
            }
        }
    }
    Ok(WriteOutcome::Conflict)
}

/// Strip the temporary `pending` stage label from `version_id` (ADR 0001 step 5
/// settle / step 6 cleanup). Best-effort: a leftover label is harmless clutter, so a
/// committed write must not fail because the strip did — but it is always *attempted*
/// (the cleanup-on-failure case is a quota hazard if skipped).
async fn settle(
    api: &dyn SecretsApi,
    cred: &Credential,
    secret_id: &str,
    region: &str,
    pending: &str,
    version_id: &str,
) {
    if let Err(e) = api
        .update_secret_version_stage(cred, secret_id, region, pending, None, Some(version_id))
        .await
    {
        tracing::warn!(
            target: "janitor::aws",
            secret_id,
            "failed to strip pending stage label (harmless clutter): {e}"
        );
    }
}

/// Mints a role Credential per write (via the shared [`CredentialBroker`]) and
/// applies edits to that Environment's Secrets Manager Set. The write analogue of
/// [`SecretsClient`](crate::secrets); gated behind read-write mode at the call site
/// (ADR 0004); v1 reaches it only through the `live-verify-sm-write` binary.
pub struct SecretsManagerWriter {
    broker: CredentialBroker,
    api: Arc<dyn SecretsApi>,
}

impl SecretsManagerWriter {
    pub fn new(broker: CredentialBroker, api: Arc<dyn SecretsApi>) -> Self {
        SecretsManagerWriter { broker, api }
    }

    /// Mint a Credential for `mapping`, then read-modify-write its Set under the CAS
    /// guard.
    pub async fn write(
        &self,
        mapping: &Mapping,
        edits: &[EnvEdit],
    ) -> Result<WriteOutcome, SecretWriteError> {
        let cred = self
            .broker
            .credentials_for(mapping)
            .await
            .map_err(SecretWriteError::Session)?;
        write_secret(
            self.api.as_ref(),
            cred.as_ref(),
            &mapping.secret_id,
            &mapping.region,
            edits,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::fakes::{read_json, FakeSecretsApi};
    use janitor_aws_auth::types::SsoToken;
    use janitor_aws_auth::wire::fakes::{CredSpec, FakeClock, FakeRoleClient};
    use janitor_aws_auth::wire::RawSecret;
    use std::time::{Duration, SystemTime};

    fn cred() -> Credential {
        Credential::new("a".into(), "b".into(), "c".into(), SystemTime::UNIX_EPOCH)
    }
    fn set(key: &str, value: &str) -> EnvEdit {
        EnvEdit::set(key, value)
    }

    /// The single CAS-commit call (`move_to == Some`, version_stage == AWSCURRENT).
    fn commits(api: &FakeSecretsApi) -> Vec<crate::wire::fakes::StageCall> {
        api.stage_calls()
            .into_iter()
            .filter(|c| c.move_to.is_some())
            .collect()
    }
    /// The label-strip calls (settle/cleanup: `move_to == None`).
    fn strips(api: &FakeSecretsApi) -> Vec<crate::wire::fakes::StageCall> {
        api.stage_calls()
            .into_iter()
            .filter(|c| c.move_to.is_none())
            .collect()
    }

    // ---- happy path ----

    #[tokio::test]
    async fn applied_stages_merges_commits_and_settles() {
        let api = FakeSecretsApi::new(vec![])
            .reads(vec![read_json(r#"{"A":"1","B":"2"}"#, "v1")])
            .puts(vec![Ok("v2".into())])
            .stages(vec![Ok(CasOutcome::Committed)]);
        let outcome = write_secret(&api, &cred(), "myapp/prod", "us-east-1", &[set("B", "x")])
            .await
            .unwrap();
        assert_eq!(outcome, WriteOutcome::Applied);

        let puts = api.put_calls();
        assert_eq!(puts.len(), 1, "exactly one staged put");
        // serde_json sorts object keys; only B's value changed, A preserved verbatim.
        assert_eq!(puts[0].secret_string, r#"{"A":"1","B":"x"}"#);
        assert_eq!(
            puts[0].version_stages,
            vec![format!("janitor-pending-{}", puts[0].token)]
        );

        // The CAS commit moves the new version in, removes the base out.
        let commit = &commits(&api)[0];
        assert_eq!(commit.version_stage, "AWSCURRENT");
        assert_eq!(commit.move_to.as_deref(), Some("v2"));
        assert_eq!(
            commit.remove_from.as_deref(),
            Some("v1"),
            "CAS base is the read version"
        );
        // Settle stripped the pending label from the now-current version.
        let strip = &strips(&api)[0];
        assert_eq!(
            strip.version_stage,
            format!("janitor-pending-{}", puts[0].token)
        );
        assert_eq!(strip.move_to, None);
        assert_eq!(strip.remove_from.as_deref(), Some("v2"));
    }

    #[tokio::test]
    async fn preserves_untouched_non_string_scalar_verbatim() {
        // A key we did not edit keeps its non-string type (never re-typed).
        let api = FakeSecretsApi::new(vec![])
            .reads(vec![read_json(r#"{"A":1,"B":"2"}"#, "v1")])
            .puts(vec![Ok("v2".into())])
            .stages(vec![Ok(CasOutcome::Committed)]);
        write_secret(&api, &cred(), "s", "r", &[set("B", "x")])
            .await
            .unwrap();
        assert_eq!(api.put_calls()[0].secret_string, r#"{"A":1,"B":"x"}"#);
    }

    // ---- non-flat payloads → NotFlat (Unsupported), no write ----

    #[tokio::test]
    async fn non_flat_payloads_are_unsupported_and_never_write() {
        for blob in [
            r#"{"A":{"b":1}}"#,   // nested object
            r#"{"A":[1,2,3]}"#,   // array value
            r#"[1,2,3]"#,         // top-level array
            "just-a-token",       // bare non-JSON string
            r#""quoted-scalar""#, // top-level JSON string scalar
        ] {
            let api = FakeSecretsApi::new(vec![]).reads(vec![read_json(blob, "v1")]);
            let err = write_secret(&api, &cred(), "s", "r", &[set("B", "x")])
                .await
                .unwrap_err();
            assert_eq!(err.reason(), FetchFailReason::Unsupported, "blob {blob:?}");
            assert!(matches!(err, SecretWriteError::NotFlat));
            assert!(api.put_calls().is_empty(), "no write for {blob:?}");
            assert!(api.stage_calls().is_empty());
        }
    }

    #[tokio::test]
    async fn binary_payload_is_unsupported() {
        let api = FakeSecretsApi::new(vec![]).reads(vec![Ok(crate::wire::ReadSecret {
            raw: RawSecret {
                secret_string: None,
                secret_binary: Some(vec![1, 2, 3]),
            },
            version_id: Some("v1".into()),
        })]);
        let err = write_secret(&api, &cred(), "s", "r", &[set("B", "x")])
            .await
            .unwrap_err();
        assert!(matches!(err, SecretWriteError::NotFlat));
        assert!(api.put_calls().is_empty());
    }

    // ---- conflict model B ----

    #[tokio::test]
    async fn same_key_concurrent_change_stops_with_conflict() {
        // Attempt 1 CAS-fails; the re-read shows B (a key WE edited) changed → stop.
        let api = FakeSecretsApi::new(vec![])
            .reads(vec![
                read_json(r#"{"A":"1","B":"2"}"#, "v1"),
                read_json(r#"{"A":"1","B":"99"}"#, "v3"),
            ])
            .puts(vec![Ok("v2".into())])
            .stages(vec![Ok(CasOutcome::Mismatch)]);
        let outcome = write_secret(&api, &cred(), "s", "r", &[set("B", "x")])
            .await
            .unwrap();
        assert_eq!(outcome, WriteOutcome::Conflict, "stop, never auto-merge");
        assert_eq!(api.call_count(), 2, "re-read on CAS race");
        assert_eq!(api.put_calls().len(), 1, "only the first attempt staged");
    }

    #[tokio::test]
    async fn other_key_change_replays_onto_fresh_and_applies() {
        // Attempt 1 CAS-fails; the re-read shows a teammate's new C (B unchanged) →
        // replay B onto the FRESH blob, preserving C (non-stomp), and commit.
        let api = FakeSecretsApi::new(vec![])
            .reads(vec![
                read_json(r#"{"A":"1","B":"2"}"#, "v1"),
                read_json(r#"{"A":"1","B":"2","C":"3"}"#, "v3"),
            ])
            .puts(vec![Ok("v2".into()), Ok("v4".into())])
            .stages(vec![Ok(CasOutcome::Mismatch), Ok(CasOutcome::Committed)]);
        let outcome = write_secret(&api, &cred(), "s", "r", &[set("B", "x")])
            .await
            .unwrap();
        assert_eq!(outcome, WriteOutcome::Applied);
        let puts = api.put_calls();
        assert_eq!(puts.len(), 2);
        assert_eq!(puts[0].secret_string, r#"{"A":"1","B":"x"}"#);
        assert_eq!(
            puts[1].secret_string, r#"{"A":"1","B":"x","C":"3"}"#,
            "the retry preserves the teammate's C (replay-on-fresh)"
        );
        assert_ne!(
            puts[0].token, puts[1].token,
            "distinct payload → fresh token"
        );
        // The retry's CAS base is the FRESH read version.
        assert_eq!(commits(&api)[1].remove_from.as_deref(), Some("v3"));
    }

    #[tokio::test]
    async fn cas_failure_strips_the_orphaned_pending_label() {
        // The Mismatch path must clean up the version it staged (ADR 0001 step 6).
        let api = FakeSecretsApi::new(vec![])
            .reads(vec![
                read_json(r#"{"A":"1"}"#, "v1"),
                read_json(r#"{"A":"2"}"#, "v3"),
            ])
            .puts(vec![Ok("v2".into()), Ok("v4".into())])
            .stages(vec![Ok(CasOutcome::Mismatch), Ok(CasOutcome::Committed)]);
        write_secret(&api, &cred(), "s", "r", &[set("B", "x")])
            .await
            .unwrap();
        // A strip targeting the orphaned staged version v2 (its pending label, no move).
        let cleanup = strips(&api)
            .into_iter()
            .find(|c| c.remove_from.as_deref() == Some("v2"))
            .expect("the orphaned pending label was stripped");
        assert!(cleanup.version_stage.starts_with("janitor-pending-"));
        assert_eq!(cleanup.move_to, None);
    }

    #[tokio::test]
    async fn persistent_cas_race_exhausts_to_conflict() {
        // Every attempt CAS-fails on an unchanged blob (churn on no edited key);
        // bounded retries surface Conflict, never a silent stomp.
        let api = FakeSecretsApi::new(vec![])
            .reads(vec![
                read_json(r#"{"A":"1"}"#, "v1"),
                read_json(r#"{"A":"1"}"#, "v1"),
                read_json(r#"{"A":"1"}"#, "v1"),
            ])
            .puts(vec![Ok("v2".into()), Ok("v2".into()), Ok("v2".into())])
            .stages(vec![
                Ok(CasOutcome::Mismatch),
                Ok(CasOutcome::Mismatch),
                Ok(CasOutcome::Mismatch),
            ]);
        let outcome = write_secret(&api, &cred(), "s", "r", &[set("B", "x")])
            .await
            .unwrap();
        assert_eq!(outcome, WriteOutcome::Conflict);
        assert_eq!(api.call_count(), MAX_ATTEMPTS, "exactly MAX_ATTEMPTS reads");
        assert_eq!(api.put_calls().len(), MAX_ATTEMPTS as usize);
        // A byte-identical re-merge reuses the idempotency token (ADR 0001 token rule).
        let tokens: std::collections::HashSet<_> =
            api.put_calls().into_iter().map(|p| p.token).collect();
        assert_eq!(tokens.len(), 1, "identical payload reuses one token");
    }

    // ---- no-op skip + fail-closed ----

    #[tokio::test]
    async fn no_op_edit_writes_nothing() {
        // Setting B to its existing value (and removing an absent key) is a no-op:
        // Applied without manufacturing a version.
        let api = FakeSecretsApi::new(vec![]).reads(vec![read_json(r#"{"A":"1","B":"2"}"#, "v1")]);
        let outcome = write_secret(
            &api,
            &cred(),
            "s",
            "r",
            &[set("B", "2"), EnvEdit::remove("ABSENT")],
        )
        .await
        .unwrap();
        assert_eq!(outcome, WriteOutcome::Applied);
        assert_eq!(api.call_count(), 1, "read only");
        assert!(api.put_calls().is_empty(), "no PutSecretValue for a no-op");
        assert!(api.stage_calls().is_empty());
    }

    #[tokio::test]
    async fn invalid_key_fails_closed_without_any_io() {
        let api = FakeSecretsApi::new(vec![]); // no reads scripted → any call panics
        let err = write_secret(&api, &cred(), "s", "r", &[set("", "v")])
            .await
            .unwrap_err();
        assert_eq!(err.reason(), FetchFailReason::Unsupported);
        assert!(matches!(
            err,
            SecretWriteError::Edit(EnvWriteError::InvalidKey)
        ));
        assert_eq!(api.call_count(), 0, "no read for an invalid edit");
    }

    #[tokio::test]
    async fn read_failure_is_masked_and_skips_the_write() {
        let api = FakeSecretsApi::new(vec![]).reads(vec![Err(SessionError::AccessDenied)]);
        let err = write_secret(&api, &cred(), "s", "r", &[set("B", "x")])
            .await
            .unwrap_err();
        assert_eq!(err.reason(), FetchFailReason::AccessDenied);
        assert!(!err.is_reauth());
        assert!(api.put_calls().is_empty());
    }

    #[tokio::test]
    async fn reauth_read_failure_is_flagged_for_reauth_routing() {
        let api = FakeSecretsApi::new(vec![]).reads(vec![Err(SessionError::ReauthRequired)]);
        let err = write_secret(&api, &cred(), "s", "r", &[set("B", "x")])
            .await
            .unwrap_err();
        assert!(err.is_reauth());
        assert_eq!(err.reason(), FetchFailReason::NeedsSignIn);
    }

    // ---- SecretsManagerWriter (mint-then-write) ----

    #[tokio::test]
    async fn writer_mints_a_credential_then_writes() {
        let role = Arc::new(FakeRoleClient::new(vec![Ok(CredSpec {
            expires_in: Duration::from_secs(3600),
            tag: "t",
        })]));
        let token = Arc::new(SsoToken::new(
            "t".into(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(28800),
        ));
        let broker = CredentialBroker::new(token, role.clone(), Arc::new(FakeClock::at(0)));
        let api = Arc::new(
            FakeSecretsApi::new(vec![])
                .reads(vec![read_json(r#"{"A":"1"}"#, "v1")])
                .puts(vec![Ok("v2".into())])
                .stages(vec![Ok(CasOutcome::Committed)]),
        );
        let writer = SecretsManagerWriter::new(broker, api.clone());
        let mapping = Mapping {
            environment: "prod".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: "myapp/prod".into(),
            permission_set: "ReadOnly".into(),
            method: janitor_core::config::Method::SecretsManager,
        };
        let outcome = writer.write(&mapping, &[set("A", "2")]).await.unwrap();
        assert_eq!(outcome, WriteOutcome::Applied);
        assert_eq!(role.call_count(), 1, "minted exactly one credential");
        assert_eq!(api.put_calls()[0].secret_string, r#"{"A":"2"}"#);
    }
}
