//! Real Secrets Manager SDK adapter for the tail `wire.rs` `SecretsApi` trait
//! (ADR 0010 §5/§10, ADR 0024, ADR 0001). UNTESTED *shell* (the per-call client
//! build + the `wss`-free SDK glue), but every SDK operation is factored into a
//! `_with(client, …)` free function that is **replay-tested** against canned HTTP
//! (`StaticReplayClient`, ADR 0027) so the (de)serialization, the `VersionId`
//! extraction, and the CAS-mismatch classification run without live AWS. Error
//! mapping re-uses `janitor_aws_auth`'s shared `map_aws_err` (taxonomy tested there).

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_secretsmanager::Client;
use aws_smithy_runtime_api::client::result::SdkError;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use zeroize::Zeroizing;

use janitor_aws_auth::aws_impl::map_aws_err;
use janitor_aws_auth::error::SessionError;
use janitor_aws_auth::types::Credential;
use janitor_aws_auth::wire::RawSecret;

use crate::wire::{CasOutcome, ReadSecret, SecretSummary, SecretsApi};

/// Build a credential-scoped Secrets Manager client for `region` (ADR 0010 §10:
/// explicit Credential, no ambient provider). Mirrors the per-call build the SSM
/// tail uses; the SDK calls themselves are replay-tested through the `_with`
/// helpers.
fn build_client(cred: &Credential, region: &str) -> Client {
    let creds = aws_sdk_secretsmanager::config::Credentials::new(
        cred.access_key_id(),
        cred.secret_access_key(),
        Some(cred.session_token().to_string()),
        None,
        "janitor",
    );
    let conf = aws_sdk_secretsmanager::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(aws_sdk_secretsmanager::config::Region::new(
            region.to_string(),
        ))
        .credentials_provider(creds)
        .build();
    Client::from_conf(conf)
}

/// `GetSecretValue` → SDK-free [`ReadSecret`] (payload + the `AWSCURRENT`
/// `VersionId`, ADR 0001). Replay-tested.
async fn get_secret_value_with(
    client: &Client,
    secret_id: &str,
) -> Result<ReadSecret, SessionError> {
    let out = client
        .get_secret_value()
        .secret_id(secret_id)
        .send()
        .await
        .map_err(map_secret_err)?;
    // Metadata only: which secret, whether string or binary, and the non-secret
    // VersionId. NEVER the Value — the one field on this success path that is secret.
    tracing::info!(
        target: "janitor::aws",
        secret_id,
        version_id = out.version_id().unwrap_or("-"),
        kind = if out.secret_binary().is_some() { "binary" } else { "string" },
        "GetSecretValue ok"
    );
    Ok(ReadSecret {
        raw: RawSecret {
            secret_string: out.secret_string().map(|s| s.to_string()),
            secret_binary: out.secret_binary().map(|b| b.as_ref().to_vec()),
        },
        version_id: out.version_id().map(|s| s.to_string()),
    })
}

/// `ListSecrets` (paginated) → SDK-free [`SecretSummary`]s (name+ARN, never a
/// Value). Replay-tested.
async fn list_secrets_with(client: &Client) -> Result<Vec<SecretSummary>, SessionError> {
    let mut out = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let mut req = client.list_secrets();
        if let Some(t) = &next {
            req = req.next_token(t);
        }
        let page = req.send().await.map_err(map_secret_err)?;
        for s in page.secret_list() {
            out.push(SecretSummary {
                name: s.name().unwrap_or_default().to_string(),
                arn: s.arn().unwrap_or_default().to_string(),
            });
        }
        match page.next_token() {
            Some(t) => next = Some(t.to_string()),
            None => break,
        }
    }
    Ok(out)
}

/// `PutSecretValue` staging `secret_string` under `version_stages` (ADR 0001 step
/// 3). Returns the new `VersionId`. Replay-tested.
async fn put_secret_value_with(
    client: &Client,
    secret_id: &str,
    secret_string: Zeroizing<String>,
    client_request_token: &str,
    version_stages: &[String],
) -> Result<String, SessionError> {
    let out = client
        .put_secret_value()
        .secret_id(secret_id)
        // The SDK request owns this copy of the merged blob; the Zeroizing original
        // is scrubbed on drop. NEVER logged (only the non-secret VersionId is).
        .secret_string(secret_string.to_string())
        .client_request_token(client_request_token)
        .set_version_stages(Some(version_stages.to_vec()))
        .send()
        .await
        .map_err(map_secret_err)?;
    let version_id = out.version_id().unwrap_or_default().to_string();
    tracing::info!(target: "janitor::aws", secret_id, version_id, "PutSecretValue staged");
    Ok(version_id)
}

/// `UpdateSecretVersionStage` (ADR 0001 step 4/5/6). A commit (`move_to=Some`)
/// is a CAS: a mismatch surfaces as [`CasOutcome::Mismatch`]; a label-strip
/// (`move_to=None`) returns `Committed` on success. Replay-tested.
async fn update_stage_with(
    client: &Client,
    secret_id: &str,
    version_stage: &str,
    move_to: Option<&str>,
    remove_from: Option<&str>,
) -> Result<CasOutcome, SessionError> {
    let res = client
        .update_secret_version_stage()
        .secret_id(secret_id)
        .version_stage(version_stage)
        .set_move_to_version_id(move_to.map(str::to_string))
        .set_remove_from_version_id(remove_from.map(str::to_string))
        .send()
        .await;
    match res {
        Ok(_) => Ok(CasOutcome::Committed),
        Err(e) => classify_stage_err(secret_id, e),
    }
}

/// Classify an `UpdateSecretVersionStage` error. The CAS-precondition failure —
/// `AWSCURRENT` no longer on the version we tried to remove it from — surfaces as
/// [`CasOutcome::Mismatch`] so the writer cleans up + retries (never a stomp);
/// everything else is a real [`SessionError`].
///
/// PENDING LIVE VERIFICATION (ADR 0001 "to verify against the live API"): the
/// exact error shape for a stale-`RemoveFromVersionId` is treated here as
/// `InvalidParameterException`/`InvalidRequestException`. Misclassifying a genuine
/// bad-parameter error as a mismatch only costs bounded extra retries that end in
/// `WriteOutcome::Conflict` — safe (it can never stomp), just a misleading message
/// — so this errs toward the safe side until the live run pins the code.
fn classify_stage_err<E, R>(secret_id: &str, e: SdkError<E, R>) -> Result<CasOutcome, SessionError>
where
    E: ProvideErrorMetadata,
{
    let code = e
        .as_service_error()
        .and_then(|s| s.code())
        .map(str::to_string);
    if matches!(
        code.as_deref(),
        Some("InvalidParameterException") | Some("InvalidRequestException")
    ) {
        tracing::info!(
            target: "janitor::aws",
            secret_id,
            code = code.as_deref().unwrap_or("-"),
            "UpdateSecretVersionStage CAS mismatch (AWSCURRENT moved)"
        );
        return Ok(CasOutcome::Mismatch);
    }
    Err(map_aws_err("UpdateSecretVersionStage", e))
}

/// Real Secrets Manager client. Each method builds a credential-scoped client and
/// delegates to the replay-tested `_with` helper above.
pub struct AwsSecretsApi;
impl AwsSecretsApi {
    pub fn new() -> Self {
        AwsSecretsApi
    }
}
impl Default for AwsSecretsApi {
    fn default() -> Self {
        Self::new()
    }
}
#[async_trait]
impl SecretsApi for AwsSecretsApi {
    async fn get_secret_value(
        &self,
        cred: &Credential,
        secret_id: &str,
        region: &str,
    ) -> Result<ReadSecret, SessionError> {
        get_secret_value_with(&build_client(cred, region), secret_id).await
    }

    async fn list_secrets(
        &self,
        cred: &Credential,
        region: &str,
    ) -> Result<Vec<SecretSummary>, SessionError> {
        list_secrets_with(&build_client(cred, region)).await
    }

    async fn put_secret_value(
        &self,
        cred: &Credential,
        secret_id: &str,
        region: &str,
        secret_string: Zeroizing<String>,
        client_request_token: &str,
        version_stages: &[String],
    ) -> Result<String, SessionError> {
        put_secret_value_with(
            &build_client(cred, region),
            secret_id,
            secret_string,
            client_request_token,
            version_stages,
        )
        .await
    }

    async fn update_secret_version_stage(
        &self,
        cred: &Credential,
        secret_id: &str,
        region: &str,
        version_stage: &str,
        move_to: Option<&str>,
        remove_from: Option<&str>,
    ) -> Result<CasOutcome, SessionError> {
        update_stage_with(
            &build_client(cred, region),
            secret_id,
            version_stage,
            move_to,
            remove_from,
        )
        .await
    }
}

/// Map a Secrets Manager SDK error via the shared `map_aws_err` (ADR 0024). The
/// error body carries the code + message — never the Value — so the real detail
/// is logged and surfaced.
fn map_secret_err<E, R>(e: SdkError<E, R>) -> SessionError
where
    E: ProvideErrorMetadata,
{
    map_aws_err("SecretsManager", e)
}

// ---- Replay-transport coverage of the SDK-wrap (ADR 0027 Layer 1) ------------
//
// `StaticReplayClient` answers the real secretsmanager SDK client with canned
// awsJson1.1 HTTP, so `get_secret_value_with`/`put_secret_value_with`/
// `update_stage_with` run their real (de)serialization, the `VersionId`
// extraction (ADR 0001), and the CAS-mismatch classification — no live AWS.
#[cfg(test)]
mod replay_tests {
    use super::*;
    use aws_sdk_secretsmanager::config::{Credentials, Region};
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    /// An awsJson1.1 200 response carrying `body`.
    fn ok_json(body: &str) -> ReplayEvent {
        ReplayEvent::new(
            http::Request::builder()
                .uri("https://replay.test/")
                .body(SdkBody::empty())
                .unwrap(),
            http::Response::builder()
                .status(200)
                .header("content-type", "application/x-amz-json-1.1")
                .body(SdkBody::from(body.to_owned()))
                .unwrap(),
        )
    }

    /// An awsJson1.1 error response: the SDK resolves the code from
    /// `x-amzn-errortype`, which the classification switches on.
    fn err_json(status: u16, code: &str) -> ReplayEvent {
        ReplayEvent::new(
            http::Request::builder()
                .uri("https://replay.test/")
                .body(SdkBody::empty())
                .unwrap(),
            http::Response::builder()
                .status(status)
                .header("content-type", "application/x-amz-json-1.1")
                .header("x-amzn-errortype", code)
                .body(SdkBody::from(format!(
                    "{{\"__type\":\"{code}\",\"message\":\"{code} (replayed)\"}}"
                )))
                .unwrap(),
        )
    }

    fn client_with_replay(events: Vec<ReplayEvent>) -> Client {
        let creds = Credentials::new("ak", "sk", Some("st".into()), None, "test");
        let conf = aws_sdk_secretsmanager::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(creds)
            .http_client(StaticReplayClient::new(events))
            .retry_config(aws_smithy_types::retry::RetryConfig::disabled())
            .build();
        Client::from_conf(conf)
    }

    #[tokio::test]
    async fn get_secret_value_extracts_payload_and_version_id() {
        let body = r#"{"ARN":"arn:secret","Name":"myapp/prod","VersionId":"v-current","SecretString":"{\"A\":\"1\"}","VersionStages":["AWSCURRENT"]}"#;
        let mut read =
            get_secret_value_with(&client_with_replay(vec![ok_json(body)]), "myapp/prod")
                .await
                .expect("get");
        assert_eq!(read.version_id.as_deref(), Some("v-current"));
        assert_eq!(
            read.raw.secret_string.take().as_deref(),
            Some(r#"{"A":"1"}"#)
        );
    }

    #[tokio::test]
    async fn get_secret_value_maps_not_found() {
        // `ReadSecret` is deliberately non-Debug (it holds the secret payload), so
        // match rather than `expect_err`.
        match get_secret_value_with(
            &client_with_replay(vec![err_json(400, "ResourceNotFoundException")]),
            "missing",
        )
        .await
        {
            Err(SessionError::NotFound) => {}
            Err(other) => panic!("expected NotFound, got {other:?}"),
            Ok(_) => panic!("expected a not-found error"),
        }
    }

    #[tokio::test]
    async fn put_secret_value_returns_the_new_version_id() {
        let body = r#"{"ARN":"arn:secret","Name":"myapp/prod","VersionId":"v-new","VersionStages":["janitor-pending-x"]}"#;
        let version = put_secret_value_with(
            &client_with_replay(vec![ok_json(body)]),
            "myapp/prod",
            Zeroizing::new(r#"{"A":"2"}"#.to_string()),
            "tok-123",
            &["janitor-pending-x".to_string()],
        )
        .await
        .expect("put");
        assert_eq!(version, "v-new");
    }

    #[tokio::test]
    async fn update_stage_commit_succeeds() {
        let body = r#"{"ARN":"arn:secret","Name":"myapp/prod"}"#;
        let outcome = update_stage_with(
            &client_with_replay(vec![ok_json(body)]),
            "myapp/prod",
            "AWSCURRENT",
            Some("v-new"),
            Some("v-current"),
        )
        .await
        .expect("stage");
        assert_eq!(outcome, CasOutcome::Committed);
    }

    #[tokio::test]
    async fn update_stage_mismatch_is_classified_not_errored() {
        // The CAS precondition failed (AWSCURRENT moved); the writer must see a
        // Mismatch (clean up + retry), not a hard error.
        let outcome = update_stage_with(
            &client_with_replay(vec![err_json(400, "InvalidParameterException")]),
            "myapp/prod",
            "AWSCURRENT",
            Some("v-new"),
            Some("v-stale"),
        )
        .await
        .expect("classified, not errored");
        assert_eq!(outcome, CasOutcome::Mismatch);
    }

    #[tokio::test]
    async fn update_stage_real_error_propagates() {
        // A non-CAS error (e.g. access denied) is a real SessionError, never a Mismatch.
        let err = update_stage_with(
            &client_with_replay(vec![err_json(400, "AccessDeniedException")]),
            "myapp/prod",
            "janitor-pending-x",
            None,
            Some("v-new"),
        )
        .await
        .expect_err("denied");
        assert!(matches!(err, SessionError::AccessDenied));
    }

    #[tokio::test]
    async fn list_secrets_walks_pages() {
        let page1 = r#"{"SecretList":[{"Name":"a","ARN":"arn:a"}],"NextToken":"NEXT"}"#;
        let page2 = r#"{"SecretList":[{"Name":"b","ARN":"arn:b"}]}"#;
        let list = list_secrets_with(&client_with_replay(vec![ok_json(page1), ok_json(page2)]))
            .await
            .expect("list");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].arn, "arn:a");
        assert_eq!(list[1].name, "b");
    }
}
