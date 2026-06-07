//! Real AWS SDK adapters for the front-half `wire.rs` traits (ADR 0010 §5/§10,
//! ADR 0024). UNTESTED shell: SDK signatures confirmed against the installed
//! crate versions. Rules:
//!  - Unauthenticated OIDC/SSO clients use NO credential provider.
//!  - `Sdk { context }` carries a short label, never a body.
//!
//! The pure error-classification (`classify_aws`) and the shared error-mapping
//! entry point (`map_aws_err`) live here and are unit-tested; the Secrets
//! Manager tail (`AwsSecretsApi`, in `janitor-aws`) re-uses `map_aws_err`.

use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_smithy_runtime_api::client::result::SdkError;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;

use crate::error::{SessionError, SignInError};
use crate::types::{Credential, SsoToken};
use crate::wire::{
    AccountCatalog, AccountSummary, ClientRegistration, OidcClient, RoleCredentialClient,
    RoleSummary, TokenExchange,
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

#[cfg(any(test, feature = "test-support"))]
impl AwsOidcClient {
    /// Build against an injected HTTP client — a `StaticReplayClient` in tests —
    /// so `register_client`/`create_token` run their real (de)serialization +
    /// error mapping without live AWS (ADR 0027). Identical to [`new`] except the
    /// transport is injected and retries are disabled (so a single canned error
    /// event isn't consumed by the SDK's internal throttle retry).
    ///
    /// [`new`]: AwsOidcClient::new
    pub async fn with_http_client(
        region: String,
        http: impl aws_smithy_runtime_api::client::http::HttpClient + 'static,
    ) -> Self {
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region.clone()))
            .no_credentials()
            .http_client(http)
            .retry_config(aws_smithy_types::retry::RetryConfig::disabled())
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
#[cfg(any(test, feature = "test-support"))]
impl AwsRoleClient {
    /// Build against an injected HTTP client (a `StaticReplayClient` in tests) so
    /// `get_role_credentials`/`list_accounts`/`list_account_roles` run their real
    /// (de)serialization, pagination, and error mapping without live AWS
    /// (ADR 0027). Identical to [`new`] except for the injected transport and
    /// disabled retries.
    ///
    /// [`new`]: AwsRoleClient::new
    pub async fn with_http_client(
        region: String,
        http: impl aws_smithy_runtime_api::client::http::HttpClient + 'static,
    ) -> Self {
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .no_credentials()
            .http_client(http)
            .retry_config(aws_smithy_types::retry::RetryConfig::disabled())
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
/// `pub` so the Secrets Manager tail (`janitor-aws`) re-uses it (ADR 0024).
pub fn map_aws_err<E, R>(op: &str, e: SdkError<E, R>) -> SessionError
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

    #[test]
    fn non_service_sdk_errors_map_to_scrubbed_sdk_with_safe_detail() {
        // Transport-level failures (no HTTP response, so no error code) flow
        // through `err_detail`'s non-service arms into a scrubbed `Sdk` carrying a
        // safe, body-free label — the only `err_detail` branches the replay tests
        // (which always return a response) can't reach.
        use super::map_aws_err;
        use aws_smithy_runtime_api::client::result::{ConnectorError, SdkError};
        type OpErr = aws_sdk_ssooidc::operation::create_token::CreateTokenError;
        type Resp = aws_smithy_runtime_api::client::orchestrator::HttpResponse;

        let cases: Vec<(SdkError<OpErr, Resp>, &str)> = vec![
            (SdkError::timeout_error("slow"), "request timed out"),
            (
                SdkError::dispatch_failure(ConnectorError::io("boom".into())),
                "network/dispatch failure",
            ),
            (
                SdkError::construction_failure("bad"),
                "request construction failure",
            ),
        ];
        for (err, expected) in cases {
            match map_aws_err("GetSecretValue", err) {
                SessionError::Sdk { context } => assert_eq!(context, expected),
                other => panic!("expected scrubbed Sdk, got {other:?}"),
            }
        }
    }
}

// ---- Replay-transport coverage of the SDK-wrap (ADR 0027 Layer 1) ------------
//
// `StaticReplayClient` answers the real ssooidc/sso SDK clients with canned HTTP,
// so `register_client`/`create_token`/`get_role_credentials`/`list_*` run their
// real (de)serialization, pagination, and the `SdkError → map_aws_err`
// classification — no live AWS. Error responses carry the exact `x-amzn-errortype`
// shapes from the ADR 0010 §5 verify list, so the classification is exercised
// against genuine `SdkError`s, not a hand-written code string (which the pure-fn
// tests above already cover).
#[cfg(test)]
mod replay_tests {
    use super::*;
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    /// A 200 response with a JSON body the SDK will deserialize.
    fn ok_json(body: &str) -> ReplayEvent {
        ReplayEvent::new(
            http::Request::builder()
                .uri("https://replay.test/")
                .body(SdkBody::empty())
                .unwrap(),
            http::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(SdkBody::from(body.to_owned()))
                .unwrap(),
        )
    }

    /// A restJson1 error response: status + `x-amzn-errortype` is how the SDK
    /// resolves the error code that `classify_aws` switches on.
    fn err_json(status: u16, code: &str) -> ReplayEvent {
        ReplayEvent::new(
            http::Request::builder()
                .uri("https://replay.test/")
                .body(SdkBody::empty())
                .unwrap(),
            http::Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .header("x-amzn-errortype", code)
                .body(SdkBody::from(format!(
                    "{{\"__type\":\"{code}\",\"message\":\"{code} (replayed)\"}}"
                )))
                .unwrap(),
        )
    }

    async fn oidc(events: Vec<ReplayEvent>) -> AwsOidcClient {
        AwsOidcClient::with_http_client("us-east-1".into(), StaticReplayClient::new(events)).await
    }
    async fn role(events: Vec<ReplayEvent>) -> AwsRoleClient {
        AwsRoleClient::with_http_client("us-east-1".into(), StaticReplayClient::new(events)).await
    }
    fn dummy_token() -> SsoToken {
        SsoToken::new(
            "sso-token".into(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(3600),
        )
    }
    fn registration() -> ClientRegistration {
        ClientRegistration {
            client_id: "c".into(),
            client_secret: "s".into(),
            authorization_endpoint: "https://oidc.us-east-1.amazonaws.com/authorize".into(),
        }
    }

    #[tokio::test]
    async fn register_client_maps_success_fields() {
        let body = r#"{"clientId":"cid","clientSecret":"sec","authorizationEndpoint":"https://oidc.eu-west-1.amazonaws.com/authorize"}"#;
        let reg = oidc(vec![ok_json(body)])
            .await
            .register_client(
                "https://identitycenter.amazonaws.com/ssoins-x",
                &["http://127.0.0.1/oauth/callback".into()],
            )
            .await
            .expect("register");
        assert_eq!(reg.client_id, "cid");
        assert_eq!(reg.client_secret, "sec");
        assert_eq!(
            reg.authorization_endpoint,
            "https://oidc.eu-west-1.amazonaws.com/authorize"
        );
    }

    #[tokio::test]
    async fn register_client_derives_authorize_endpoint_when_null() {
        // AWS returns a null authorizationEndpoint for some instances (Milestone
        // B); the wrap derives the regional endpoint from the client's region.
        let body = r#"{"clientId":"cid","clientSecret":"sec","authorizationEndpoint":null}"#;
        let reg = oidc(vec![ok_json(body)])
            .await
            .register_client("iss", &["http://127.0.0.1/oauth/callback".into()])
            .await
            .expect("register");
        assert_eq!(
            reg.authorization_endpoint,
            "https://oidc.us-east-1.amazonaws.com/authorize"
        );
    }

    #[tokio::test]
    async fn register_client_scrubs_errors_to_sdk_context() {
        // RegisterClient is pre-auth; any failure collapses to the scrubbed
        // `Sdk { context: "RegisterClient" }` (the real detail is logged, not returned).
        // `ClientRegistration` is intentionally non-Debug (it holds a client
        // secret), so match rather than `expect_err`.
        let result = oidc(vec![err_json(400, "InvalidClientMetadataException")])
            .await
            .register_client("iss", &["http://127.0.0.1/oauth/callback".into()])
            .await;
        match result {
            Err(SignInError::Sdk { context }) => assert_eq!(context, "RegisterClient"),
            Err(other) => panic!("expected scrubbed Sdk, got {other:?}"),
            Ok(_) => panic!("expected register failure"),
        }
    }

    #[tokio::test]
    async fn create_token_extracts_access_token() {
        let body = r#"{"accessToken":"AT-123","tokenType":"Bearer","expiresIn":3600}"#;
        let token = oidc(vec![ok_json(body)])
            .await
            .create_token(TokenExchange {
                registration: &registration(),
                code: "code",
                code_verifier: "ver",
                redirect_uri: "http://127.0.0.1:1/oauth/callback",
            })
            .await
            .expect("token");
        assert_eq!(token.expose(), "AT-123");
    }

    #[tokio::test]
    async fn create_token_maps_invalid_grant_to_token_endpoint() {
        let err = oidc(vec![err_json(400, "InvalidGrantException")])
            .await
            .create_token(TokenExchange {
                registration: &registration(),
                code: "bad",
                code_verifier: "ver",
                redirect_uri: "http://127.0.0.1:1/oauth/callback",
            })
            .await
            .expect_err("grant fails");
        assert!(matches!(err, SignInError::TokenEndpoint));
    }

    #[tokio::test]
    async fn get_role_credentials_maps_fields_and_reads_expiration() {
        // expiration is epoch+10_000s (in millis) — proves it is read from the
        // response, never a hardcoded 1h (ADR 0010 verify list).
        let exp_ms = 10_000_000u64;
        let body = format!(
            r#"{{"roleCredentials":{{"accessKeyId":"AKIA","secretAccessKey":"SECRET","sessionToken":"SESSION","expiration":{exp_ms}}}}}"#
        );
        let cred = role(vec![ok_json(&body)])
            .await
            .get_role_credentials(&dummy_token(), "111122223333", "ReadOnly", "us-east-1")
            .await
            .expect("creds");
        assert_eq!(cred.access_key_id(), "AKIA");
        assert_eq!(cred.secret_access_key(), "SECRET");
        assert_eq!(cred.session_token(), "SESSION");
        // The parsed 10_000s expiration drives staleness: fresh well before it,
        // stale just under the skew window.
        let skew = Duration::from_secs(60);
        assert!(!cred.is_stale(SystemTime::UNIX_EPOCH + Duration::from_secs(5_000), skew));
        assert!(cred.is_stale(SystemTime::UNIX_EPOCH + Duration::from_secs(9_999), skew));
    }

    #[tokio::test]
    async fn get_role_credentials_dead_token_is_reauth_required() {
        let err = role(vec![err_json(401, "UnauthorizedException")])
            .await
            .get_role_credentials(&dummy_token(), "111", "ReadOnly", "us-east-1")
            .await
            .expect_err("dead token");
        assert!(matches!(err, SessionError::ReauthRequired));
    }

    #[tokio::test]
    async fn get_role_credentials_forbidden_is_role_not_entitled() {
        // ForbiddenException isn't modeled for GetRoleCredentials, so the SDK
        // surfaces it as an unhandled service error — but the x-amzn-errortype
        // code still drives classification to RoleNotEntitled (ADR 0018), NOT a
        // browser-looping ReauthRequired.
        let err = role(vec![err_json(403, "ForbiddenException")])
            .await
            .get_role_credentials(&dummy_token(), "111", "Denied", "us-east-1")
            .await
            .expect_err("not entitled");
        match err {
            SessionError::RoleNotEntitled { context } => {
                assert!(
                    context.contains("ForbiddenException"),
                    "detail kept: {context}"
                );
            }
            other => panic!("expected RoleNotEntitled, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_role_credentials_not_found_and_throttle_classify() {
        let nf = role(vec![err_json(404, "ResourceNotFoundException")])
            .await
            .get_role_credentials(&dummy_token(), "111", "R", "us-east-1")
            .await
            .expect_err("nf");
        assert!(matches!(nf, SessionError::NotFound));
        // A single 429 suffices because the test constructor disables retries.
        let throttled = role(vec![err_json(429, "TooManyRequestsException")])
            .await
            .get_role_credentials(&dummy_token(), "111", "R", "us-east-1")
            .await
            .expect_err("throttle");
        assert!(matches!(throttled, SessionError::Throttled));
    }

    #[tokio::test]
    async fn list_accounts_follows_pagination() {
        let page1 = r#"{"accountList":[{"accountId":"111","accountName":"Prod","emailAddress":"p@x"}],"nextToken":"NEXT"}"#;
        let page2 = r#"{"accountList":[{"accountId":"222","accountName":"Dev"}],"nextToken":null}"#;
        let accounts = role(vec![ok_json(page1), ok_json(page2)])
            .await
            .list_accounts(&dummy_token())
            .await
            .expect("accounts");
        assert_eq!(accounts.len(), 2, "both pages walked");
        assert_eq!(accounts[0].id, "111");
        assert_eq!(accounts[0].name, "Prod");
        assert_eq!(accounts[1].id, "222");
        assert_eq!(accounts[1].name, "Dev");
    }

    #[tokio::test]
    async fn list_account_roles_maps_role_names() {
        let body = r#"{"roleList":[{"roleName":"ReadOnly","accountId":"111"},{"roleName":"Admin","accountId":"111"}],"nextToken":null}"#;
        let roles = role(vec![ok_json(body)])
            .await
            .list_account_roles(&dummy_token(), "111")
            .await
            .expect("roles");
        let names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["ReadOnly", "Admin"]);
    }

    #[tokio::test]
    async fn list_accounts_propagates_dead_token() {
        // The account/role enumeration reuses GetRoleCredentials' error mapping,
        // so a dead token surfaces as ReauthRequired here too.
        let err = role(vec![err_json(401, "UnauthorizedException")])
            .await
            .list_accounts(&dummy_token())
            .await
            .expect_err("dead token");
        assert!(matches!(err, SessionError::ReauthRequired));
    }
}
