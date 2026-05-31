//! Real AWS SDK adapters for the `wire.rs` traits (ADR 0010 §5/§10). UNTESTED
//! shell: SDK signatures confirmed against the installed crate versions. Rules:
//!  - Unauthenticated OIDC/SSO clients use NO credential provider.
//!  - The Secrets Manager client uses the injected per-Env Credential only.
//!  - `Sdk { context }` carries a short label, never a body.

use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_config::BehaviorVersion;

use crate::error::{SessionError, SignInError};
use crate::types::{Credential, SsoToken};
use crate::wire::{
    ClientRegistration, OidcClient, RawSecret, RoleCredentialClient, SecretsApi, TokenExchange,
};

/// Real OIDC client (`RegisterClient` + `CreateToken`).
pub struct AwsOidcClient {
    inner: aws_sdk_ssooidc::Client,
}

impl AwsOidcClient {
    /// Build with explicit region and NO credentials (ADR 0010 §10).
    pub async fn new(region: String) -> Self {
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .no_credentials()
            .load()
            .await;
        AwsOidcClient {
            inner: aws_sdk_ssooidc::Client::new(&conf),
        }
    }
}

#[async_trait]
impl OidcClient for AwsOidcClient {
    async fn register_client(
        &self,
        redirect_uris: &[String],
    ) -> Result<ClientRegistration, SignInError> {
        let mut req = self
            .inner
            .register_client()
            .client_name("janitor")
            .client_type("public")
            .grant_types("authorization_code")
            .grant_types("refresh_token")
            .scopes("sso:account:access");
        for uri in redirect_uris {
            req = req.redirect_uris(uri.clone());
        }
        let out = req.send().await.map_err(|_| SignInError::Sdk {
            context: "RegisterClient".into(),
        })?;
        Ok(ClientRegistration {
            client_id: out.client_id().unwrap_or_default().to_string(),
            client_secret: out.client_secret().unwrap_or_default().to_string(),
        })
    }

    async fn create_token(&self, ex: TokenExchange<'_>) -> Result<SsoToken, SignInError> {
        let out = self
            .inner
            .create_token()
            .client_id(ex.registration.client_id.as_str())
            .client_secret(ex.registration.client_secret.as_str())
            .grant_type("authorization_code")
            .code(ex.code)
            .code_verifier(ex.code_verifier)
            .redirect_uri(ex.redirect_uri)
            .send()
            .await
            .map_err(|_| SignInError::TokenEndpoint)?;
        let access = out
            .access_token()
            .ok_or(SignInError::TokenEndpoint)?
            .to_string();
        let expires_in = out.expires_in();
        let expires_at = SystemTime::now() + Duration::from_secs(expires_in.max(0) as u64);
        Ok(SsoToken::new(access, expires_at))
    }
}

/// Real role-credential client (`GetRoleCredentials`).
pub struct AwsRoleClient {
    inner: aws_sdk_sso::Client,
}
impl AwsRoleClient {
    pub async fn new(region: String) -> Self {
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .no_credentials()
            .load()
            .await;
        AwsRoleClient {
            inner: aws_sdk_sso::Client::new(&conf),
        }
    }
}
#[async_trait]
impl RoleCredentialClient for AwsRoleClient {
    async fn get_role_credentials(
        &self,
        token: &SsoToken,
        account_id: &str,
        permission_set: &str,
        _region: &str,
    ) -> Result<Credential, SessionError> {
        let out = self
            .inner
            .get_role_credentials()
            .access_token(token.expose())
            .account_id(account_id)
            .role_name(permission_set)
            .send()
            .await
            .map_err(map_role_err)?;
        let rc = out.role_credentials().ok_or(SessionError::Sdk {
            context: "GetRoleCredentials(empty)".into(),
        })?;
        let expiration =
            SystemTime::UNIX_EPOCH + Duration::from_millis(rc.expiration().max(0) as u64);
        Ok(Credential::new(
            rc.access_key_id().unwrap_or_default().to_string(),
            rc.secret_access_key().unwrap_or_default().to_string(),
            rc.session_token().unwrap_or_default().to_string(),
            expiration,
        ))
    }
}

/// Map a GetRoleCredentials SDK error to our taxonomy. Conservative for now:
/// everything → scrubbed Sdk (live-verify, Task 14, refines this). Uses
/// `discriminant` to avoid printing any error body.
fn map_role_err<E: std::fmt::Debug, R: std::fmt::Debug>(
    e: aws_smithy_runtime_api::client::result::SdkError<E, R>,
) -> SessionError {
    let label = format!("{:?}", std::mem::discriminant(&e));
    SessionError::Sdk {
        context: format!("GetRoleCredentials:{label}"),
    }
}

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
        Ok(RawSecret {
            secret_string: out.secret_string().map(|s| s.to_string()),
            secret_binary: out.secret_binary().map(|b| b.as_ref().to_vec()),
        })
    }
}

/// Map a GetSecretValue SDK error to our taxonomy. Conservative for now;
/// live-verify (Task 14) refines into NotFound/AccessDenied/Throttled.
fn map_secret_err<E: std::fmt::Debug, R: std::fmt::Debug>(
    e: aws_smithy_runtime_api::client::result::SdkError<E, R>,
) -> SessionError {
    let label = format!("{:?}", std::mem::discriminant(&e));
    SessionError::Sdk {
        context: format!("GetSecretValue:{label}"),
    }
}
