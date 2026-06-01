//! Real AWS SDK adapters for the `wire.rs` traits (ADR 0010 §5/§10). UNTESTED
//! shell: SDK signatures confirmed against the installed crate versions. Rules:
//!  - Unauthenticated OIDC/SSO clients use NO credential provider.
//!  - The Secrets Manager client uses the injected per-Env Credential only.
//!  - `Sdk { context }` carries a short label, never a body.

use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_smithy_runtime_api::client::result::SdkError;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;

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
        tracing::info!(target: "janitor::aws", issuer_url, "RegisterClient");
        let out = req.send().await.map_err(|e| {
            // RegisterClient is a PRE-AUTH call — no SSO token or role credential
            // is in play, so its error body carries no secret material. Log the
            // real detail; the returned error stays the scrubbed `Sdk` variant.
            let detail = err_detail(&e);
            tracing::warn!(target: "janitor::aws", op = "RegisterClient", "RegisterClient failed — {detail}");
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
                // CreateToken errors are grant/PKCE validation failures (e.g.
                // invalid_grant); no success token exists on the error path, so
                // the detail is safe to log.
                let detail = err_detail(&e);
                tracing::warn!(target: "janitor::aws", op = "CreateToken", "CreateToken failed — {detail}");
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
        tracing::info!(
            target: "janitor::aws",
            account_id,
            role = permission_set,
            "GetRoleCredentials ok"
        );
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

/// An error-safe "Code: message" extracted from an SDK error.
///
/// SAFE TO LOG/SURFACE: an SDK *error* response carries only an error code, a
/// human message, and sometimes an ARN / calling-principal — it can never carry
/// a secret Value (those appear only in a *success* body) nor the SSO token /
/// minted role credentials. Any secret *names/locations* it includes are already
/// in the user's Config (THREAT-MODEL: Config is a plaintext recon map). So
/// unlike a success body, this is fine for the diagnostic log and the banner.
fn err_detail<E, R>(e: &SdkError<E, R>) -> String
where
    E: ProvideErrorMetadata,
{
    if let Some(svc) = e.as_service_error() {
        let code = svc.code().unwrap_or("Unknown");
        return match svc.message() {
            Some(m) => format!("{code}: {m}"),
            None => code.to_string(),
        };
    }
    match e {
        SdkError::TimeoutError(_) => "request timed out".to_string(),
        SdkError::DispatchFailure(_) => "network/dispatch failure".to_string(),
        SdkError::ConstructionFailure(_) => "request construction failure".to_string(),
        SdkError::ResponseError(_) => "unexpected response".to_string(),
        _ => "unknown error".to_string(),
    }
}

/// Classify an AWS error *code* into our taxonomy. A dead/expired SSO token must
/// become [`SessionError::ReauthRequired`] so the facade re-Signs-in (ADR 0010
/// §4); everything else stays a scrubbed `Sdk` carrying the real, error-safe
/// detail so it reaches the diagnostic log and the banner. Pure — unit-tested.
fn classify_aws(op: &str, code: Option<&str>, detail: String) -> SessionError {
    let is_role = op == "GetRoleCredentials";
    match code {
        // ONLY a genuinely invalid/expired SSO token at the role step warrants a
        // re-Sign-in. A `ForbiddenException` ("No access") / `AccessDeniedException`
        // there is a *permanent entitlement denial* (the user lacks this permission
        // set on this account); routing it to re-Sign-in would loop the browser for
        // an error re-auth can never fix — so it falls through to `Sdk` below,
        // terminal, carrying the real detail to the banner + log.
        Some("UnauthorizedException") | Some("ExpiredTokenException") if is_role => {
            SessionError::ReauthRequired
        }
        // Role-step entitlement denial: the user lacks this permission set on this
        // account. A distinct variant (ADR 0018) so `Session::load` can attempt one
        // in-session role re-resolution + retry before surfacing it. Carries the
        // real detail forward (like `Sdk`) for the banner + log.
        Some("ForbiddenException") | Some("AccessDeniedException") | Some("AccessDenied")
            if is_role =>
        {
            SessionError::RoleNotEntitled { context: detail }
        }
        // Secret-step access-denied stays `AccessDenied` so the facade can force ONE
        // credential re-mint (a stale cached cred AWS now rejects) before giving up
        // (ADR 0010 §4).
        Some("AccessDeniedException") | Some("AccessDenied") => SessionError::AccessDenied,
        Some("ResourceNotFoundException") => SessionError::NotFound,
        Some("ThrottlingException")
        | Some("TooManyRequestsException")
        | Some("ThrottledException") => SessionError::Throttled,
        // Everything else — including role-step denials — keeps the real,
        // error-safe detail verbatim (not a bare discriminant).
        _ => SessionError::Sdk { context: detail },
    }
}

/// Map an SDK error: log the real (error-safe) detail under `target =
/// "janitor::aws"`, then classify it. The log line is what feeds the GUI log
/// pane and stderr; the returned `SessionError` carries the same detail onward.
fn map_aws_err<E, R>(op: &str, e: SdkError<E, R>) -> SessionError
where
    E: ProvideErrorMetadata,
{
    let code = e
        .as_service_error()
        .and_then(|s| s.code())
        .map(str::to_string);
    let detail = err_detail(&e);
    tracing::warn!(
        target: "janitor::aws",
        op,
        code = code.as_deref().unwrap_or("-"),
        "{op} failed — {detail}"
    );
    classify_aws(op, code.as_deref(), detail)
}

/// Map a GetRoleCredentials SDK error (see [`map_aws_err`]).
fn map_role_err<E, R>(e: SdkError<E, R>) -> SessionError
where
    E: ProvideErrorMetadata,
{
    map_aws_err("GetRoleCredentials", e)
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

/// Map a GetSecretValue SDK error (see [`map_aws_err`]). The error body carries
/// the code (AccessDenied vs DecryptionFailure vs ResourceNotFound vs Throttling)
/// and message — never the Value — so the real detail is logged and surfaced.
fn map_secret_err<E, R>(e: SdkError<E, R>) -> SessionError
where
    E: ProvideErrorMetadata,
{
    map_aws_err("GetSecretValue", e)
}

#[cfg(test)]
mod tests {
    use super::{authorize_endpoint, classify_aws};
    use crate::error::SessionError;

    #[test]
    fn only_token_invalidity_at_role_step_routes_to_reauth() {
        // A genuinely invalid/expired SSO token → re-Sign-in.
        for code in ["UnauthorizedException", "ExpiredTokenException"] {
            assert!(
                matches!(
                    classify_aws("GetRoleCredentials", Some(code), "d".into()),
                    SessionError::ReauthRequired
                ),
                "{code} at role step should be ReauthRequired"
            );
        }
    }

    #[test]
    fn role_step_entitlement_denials_are_role_not_entitled_keeping_detail() {
        // Re-auth-loop regression guard + the recovery trigger (ADR 0018):
        // ForbiddenException ("No access") and AccessDenied at the role step are
        // entitlement denials → `RoleNotEntitled` (which arms one in-session role
        // re-resolution + retry), carrying the real detail — NOT `ReauthRequired`
        // (which loops the browser) and NOT bare `AccessDenied`.
        for code in ["ForbiddenException", "AccessDeniedException"] {
            match classify_aws(
                "GetRoleCredentials",
                Some(code),
                format!("{code}: No access"),
            ) {
                SessionError::RoleNotEntitled { context } => {
                    assert_eq!(context, format!("{code}: No access"));
                }
                other => panic!("{code} at role step must be RoleNotEntitled, got {other:?}"),
            }
        }
    }

    #[test]
    fn secret_step_codes_classify_into_taxonomy() {
        assert!(matches!(
            classify_aws("GetSecretValue", Some("AccessDeniedException"), "d".into()),
            SessionError::AccessDenied
        ));
        assert!(matches!(
            classify_aws(
                "GetSecretValue",
                Some("ResourceNotFoundException"),
                "d".into()
            ),
            SessionError::NotFound
        ));
        assert!(matches!(
            classify_aws("GetSecretValue", Some("ThrottlingException"), "d".into()),
            SessionError::Throttled
        ));
    }

    #[test]
    fn unknown_codes_keep_the_real_detail_not_a_discriminant() {
        // The whole point of ADR 0017: an unclassified error carries its real,
        // error-safe detail onward (to the banner + Diagnostic Log), verbatim.
        let e = classify_aws(
            "GetSecretValue",
            Some("DecryptionFailure"),
            "DecryptionFailure: KMS denied".into(),
        );
        match e {
            SessionError::Sdk { context } => assert_eq!(context, "DecryptionFailure: KMS denied"),
            other => panic!("expected Sdk carrying detail, got {other:?}"),
        }
    }

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
