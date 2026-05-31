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
    AccountCatalog, AccountSummary, ClientRegistration, OidcClient, RawSecret,
    RoleCredentialClient, RoleSummary, SecretSummary, SecretsApi, TokenExchange,
};

/// The browser authorize endpoint for a registration: the value
/// `RegisterClient` returns when present, otherwise the canonical regional OIDC
/// endpoint `https://oidc.<region>.amazonaws.com/authorize`.
///
/// AWS returns a null `authorizationEndpoint` for at least some Identity Center
/// instances (verified live against the real `RegisterClient` endpoint —
/// Milestone B; this contradicts ADR 0011's "read the endpoint from the
/// response", so the derived fallback is required to build a valid `/authorize`
/// URL rather than `?response_type=...` with an empty host).
fn authorize_endpoint(from_response: Option<&str>, region: &str) -> String {
    match from_response {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => format!("https://oidc.{region}.amazonaws.com/authorize"),
    }
}

/// Real OIDC client (`RegisterClient` + `CreateToken`).
pub struct AwsOidcClient {
    inner: aws_sdk_ssooidc::Client,
    /// The SSO region, retained to derive the authorize endpoint when AWS
    /// returns a null `authorizationEndpoint` (see [`authorize_endpoint`]).
    region: String,
}

impl AwsOidcClient {
    /// Build with explicit region and NO credentials (ADR 0010 §10).
    pub async fn new(region: String) -> Self {
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region.clone()))
            .no_credentials()
            .load()
            .await;
        AwsOidcClient {
            inner: aws_sdk_ssooidc::Client::new(&conf),
            region,
        }
    }
}

#[async_trait]
impl OidcClient for AwsOidcClient {
    async fn register_client(
        &self,
        issuer_url: &str,
        redirect_uris: &[String],
    ) -> Result<ClientRegistration, SignInError> {
        let mut req = self
            .inner
            .register_client()
            .client_name("janitor")
            .client_type("public")
            .issuer_url(issuer_url)
            .grant_types("authorization_code")
            .grant_types("refresh_token")
            .scopes("sso:account:access");
        for uri in redirect_uris {
            req = req.redirect_uris(uri.clone());
        }
        let out = req.send().await.map_err(|e| {
            // Milestone B diagnostic (ADR 0010 §5/§9): RegisterClient is a
            // PRE-AUTH call — no SSO token or role credential is in play, so its
            // error body carries no secret material and is safe to print. This
            // de-blinds the issuer/registration step during live-verify; the
            // returned error stays the scrubbed `Sdk` variant.
            eprintln!("RegisterClient error: {e:?}");
            SignInError::Sdk {
                context: "RegisterClient".into(),
            }
        })?;
        Ok(ClientRegistration {
            client_id: out.client_id().unwrap_or_default().to_string(),
            client_secret: out.client_secret().unwrap_or_default().to_string(),
            // AWS returns `authorizationEndpoint: null` for some instances
            // (Milestone B); derive the regional endpoint when it's absent.
            authorization_endpoint: authorize_endpoint(out.authorization_endpoint(), &self.region),
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
            .map_err(|e| {
                // Milestone B diagnostic (ADR 0010 §5): CreateToken errors are
                // grant/PKCE validation failures (e.g. invalid_grant); no
                // success token exists on the error path, so printing is safe.
                eprintln!("CreateToken error: {e:?}");
                SignInError::TokenEndpoint
            })?;
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

#[async_trait]
impl AccountCatalog for AwsRoleClient {
    async fn list_accounts(&self, token: &SsoToken) -> Result<Vec<AccountSummary>, SessionError> {
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut req = self.inner.list_accounts().access_token(token.expose());
            if let Some(t) = &next {
                req = req.next_token(t);
            }
            let page = req.send().await.map_err(map_role_err)?;
            for a in page.account_list() {
                out.push(AccountSummary {
                    id: a.account_id().unwrap_or_default().to_string(),
                    name: a.account_name().unwrap_or_default().to_string(),
                });
            }
            match page.next_token() {
                Some(t) => next = Some(t.to_string()),
                None => break,
            }
        }
        Ok(out)
    }

    async fn list_account_roles(
        &self,
        token: &SsoToken,
        account_id: &str,
    ) -> Result<Vec<RoleSummary>, SessionError> {
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut req = self
                .inner
                .list_account_roles()
                .access_token(token.expose())
                .account_id(account_id);
            if let Some(t) = &next {
                req = req.next_token(t);
            }
            let page = req.send().await.map_err(map_role_err)?;
            for r in page.role_list() {
                out.push(RoleSummary {
                    name: r.role_name().unwrap_or_default().to_string(),
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

/// Map a GetSecretValue SDK error to our taxonomy. Conservative for now;
/// live-verify (Task 14) refines into NotFound/AccessDenied/Throttled.
fn map_secret_err<E: std::fmt::Debug, R: std::fmt::Debug>(
    e: aws_smithy_runtime_api::client::result::SdkError<E, R>,
) -> SessionError {
    // Milestone B diagnostic (ADR 0010 §5): a GetSecretValue ERROR response
    // never carries the secret value (that appears only on a SUCCESS output),
    // so its Debug — error code + message + ARN/principal, i.e. locations and
    // identity, never values — is safe to surface on stderr for the
    // human-gated live-verify. Lets us see the real code (AccessDenied vs
    // DecryptionFailure vs NotFound) instead of an opaque discriminant.
    eprintln!("GetSecretValue error: {e:?}");
    let label = format!("{:?}", std::mem::discriminant(&e));
    SessionError::Sdk {
        context: format!("GetSecretValue:{label}"),
    }
}

#[cfg(test)]
mod tests {
    use super::authorize_endpoint;

    #[test]
    fn authorize_endpoint_prefers_response_when_present() {
        // If AWS ever does return the endpoint, honor it verbatim.
        assert_eq!(
            authorize_endpoint(
                Some("https://oidc.eu-west-1.amazonaws.com/authorize"),
                "us-west-2"
            ),
            "https://oidc.eu-west-1.amazonaws.com/authorize"
        );
    }

    #[test]
    fn authorize_endpoint_derives_from_region_when_absent() {
        // AWS returns null (-> None) for some instances (Milestone B); also
        // guard the empty-string case. Both derive the regional endpoint.
        assert_eq!(
            authorize_endpoint(None, "us-west-2"),
            "https://oidc.us-west-2.amazonaws.com/authorize"
        );
        assert_eq!(
            authorize_endpoint(Some(""), "us-east-1"),
            "https://oidc.us-east-1.amazonaws.com/authorize"
        );
    }
}
