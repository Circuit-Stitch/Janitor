//! Real Secrets Manager SDK adapter for the tail `wire.rs` `SecretsApi` trait
//! (ADR 0010 §5/§10, ADR 0024). UNTESTED shell: SDK signatures confirmed against
//! the installed crate versions. The Secrets Manager client uses the injected
//! per-Env Credential only. Error mapping re-uses `janitor_aws_auth`'s shared
//! `map_aws_err` (the classification taxonomy is tested there).

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_smithy_runtime_api::client::result::SdkError;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;

use janitor_aws_auth::aws_impl::map_aws_err;
use janitor_aws_auth::error::SessionError;
use janitor_aws_auth::types::Credential;
use janitor_aws_auth::wire::RawSecret;

use crate::wire::{SecretSummary, SecretsApi};

/// Real Secrets Manager client (`GetSecretValue`) using the injected Credential.
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
    ) -> Result<RawSecret, SessionError> {
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
        let client = aws_sdk_secretsmanager::Client::from_conf(conf);
        let out = client
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await
            .map_err(map_secret_err)?;
        // Metadata only: which secret + whether it was string or binary. NEVER
        // the Value — that is the one field on this success path that is secret.
        tracing::info!(
            target: "janitor::aws",
            secret_id,
            kind = if out.secret_binary().is_some() { "binary" } else { "string" },
            "GetSecretValue ok"
        );
        Ok(RawSecret {
            secret_string: out.secret_string().map(|s| s.to_string()),
            secret_binary: out.secret_binary().map(|b| b.as_ref().to_vec()),
        })
    }

    async fn list_secrets(
        &self,
        cred: &Credential,
        region: &str,
    ) -> Result<Vec<SecretSummary>, SessionError> {
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
        let client = aws_sdk_secretsmanager::Client::from_conf(conf);

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
}

/// Map a GetSecretValue SDK error via the shared `map_aws_err` (ADR 0024). The
/// error body carries the code (AccessDenied vs DecryptionFailure vs
/// ResourceNotFound vs Throttling) and message — never the Value — so the real
/// detail is logged and surfaced.
fn map_secret_err<E, R>(e: SdkError<E, R>) -> SessionError
where
    E: ProvideErrorMetadata,
{
    map_aws_err("GetSecretValue", e)
}
