//! Real `Authenticator` (ADR 0010 §3/§7): the full browser PKCE Sign-in. Shell
//! code — it opens a browser and binds a socket. The pure pieces it uses
//! (`pkce`, `state`, `loopback::query_param`) are tested elsewhere.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::browser::{self, BrowserOpener};
use crate::error::SignInError;
use crate::loopback::{bind_first_free, query_param, redirect_uris, wait_for_redirect};
use crate::pkce;
use crate::state;
use crate::types::SsoToken;
use crate::wire::{OidcClient, Reauth, TokenExchange};

/// How long to wait for the user to complete the browser Sign-in.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(180);

/// Drives a full Identity Center browser Sign-in.
pub struct Authenticator {
    oidc: Arc<dyn OidcClient>,
    /// The org's IAM Identity Center **SSO start URL** — the *instance* form
    /// `https://identitycenter.amazonaws.com/ssoins-…` from AWS' Get-credentials
    /// dialog, NOT the portal `https://<dir>.awsapps.com/start` URL (the portal
    /// form is rejected by `RegisterClient` as "Invalid start url" — Milestone B,
    /// ADR 0011). Passed to `RegisterClient` as `issuerUrl`; the `/authorize`
    /// endpoint comes back in the registration (with a region fallback).
    issuer_url: String,
    /// How the authorize URL reaches a browser — the pluggable Sign-in surface
    /// (ADR 0033). Defaults to the OS default browser via [`browser::select`]; the
    /// GUI injects the user's configured choice, tests inject a fake.
    opener: Arc<dyn BrowserOpener>,
}

impl Authenticator {
    /// Build with the OS default browser (the shared-cookie-jar opener).
    pub fn new(oidc: Arc<dyn OidcClient>, issuer_url: String) -> Self {
        Self::with_opener(oidc, issuer_url, browser::select(None))
    }

    /// Build with an injected [`BrowserOpener`] (ADR 0027/0033) — the production
    /// swap point (the GUI passes [`browser::select`]'s choice) and the test seam
    /// (a fake browser).
    pub fn with_opener(
        oidc: Arc<dyn OidcClient>,
        issuer_url: String,
        opener: Arc<dyn BrowserOpener>,
    ) -> Self {
        Authenticator {
            oidc,
            issuer_url,
            opener,
        }
    }

    /// Run the flow once, returning a fresh SSO token.
    pub async fn sign_in_once(&self) -> Result<SsoToken, SignInError> {
        // 1. Register a public client (issuer-scoped) for our loopback redirects.
        let uris = redirect_uris();
        let registration = self.oidc.register_client(&self.issuer_url, &uris).await?;

        // 2. Bind a loopback port from the registered set, THEN build the URL
        //    with that exact redirect_uri (ADR 0010 §7 ordering).
        let (listener, redirect_uri) = bind_first_free().await?;
        let pkce = pkce::generate();
        let csrf = state::generate();
        let authorize_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}&scopes=sso:account:access",
            registration.authorization_endpoint,
            urlencode(&registration.client_id),
            urlencode(&redirect_uri),
            urlencode(&pkce.challenge),
            urlencode(&csrf),
        );

        // 3. Open the Sign-in surface and wait for the redirect. Hold the surface
        //    guard across the wait, then drop it to dismiss the surface the moment
        //    the code arrives or the wait times out (cancel-on-code; a no-op for the
        //    external-browser openers — the user closes those). ADR 0033.
        let surface = self.opener.open(&authorize_url)?;
        let query = wait_for_redirect(listener, SIGN_IN_TIMEOUT).await;
        drop(surface);
        let query = query?;

        // 4. Verify CSRF state BEFORE using the code.
        let returned_state = query_param(&query, "state").unwrap_or_default();
        if !state::matches(&csrf, &returned_state) {
            return Err(SignInError::StateMismatch);
        }
        let code = query_param(&query, "code").ok_or(SignInError::TokenEndpoint)?;

        // 5. Exchange the code (+ PKCE verifier) for the SSO token.
        self.oidc
            .create_token(TokenExchange {
                registration: &registration,
                code: &code,
                code_verifier: &pkce.verifier,
                redirect_uri: &redirect_uri,
            })
            .await
    }
}

#[async_trait]
impl Reauth for Authenticator {
    async fn sign_in(&self) -> Result<SsoToken, SignInError> {
        self.sign_in_once().await
    }
}

/// Minimal percent-encoding for URL query values (RFC 3986 unreserved kept).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::SignInSurface;
    use crate::wire::fakes::FakeOidcClient;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[test]
    fn urlencode_escapes_reserved_and_keeps_unreserved() {
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(urlencode("a/b c"), "a%2Fb%20c");
        assert_eq!(urlencode("x:y"), "x%3Ay");
    }

    // ---- End-to-end `sign_in_once` coverage (ADR 0027 Layer 1) ----------------
    //
    // A fake browser-opener stands in for the real browser: it reads the loopback
    // `redirect_uri` and CSRF `state` straight out of the authorize URL Janitor
    // built, then connects to that loopback and sends the `?code=&state=` redirect
    // a real IdP would — driving the whole orchestration (register → bind → URL →
    // open → wait → CSRF check → token exchange) against a `FakeOidcClient`, with
    // no AWS and no browser.
    struct EchoOpener {
        /// Auth code to echo (None omits it, exercising the missing-code path).
        code: Option<String>,
        /// State to echo (None echoes the URL's real state; Some forces a mismatch).
        force_state: Option<String>,
    }
    impl BrowserOpener for EchoOpener {
        fn open(&self, url: &str) -> Result<Box<dyn SignInSurface>, SignInError> {
            let query = url
                .split_once('?')
                .map(|(_, q)| q.to_string())
                .unwrap_or_default();
            let redirect_uri =
                query_param(&query, "redirect_uri").expect("authorize URL carries redirect_uri");
            let state = self
                .force_state
                .clone()
                .or_else(|| query_param(&query, "state"))
                .expect("authorize URL carries state");
            // The loopback authority (host:port) the browser would be redirected to.
            let authority = redirect_uri
                .strip_prefix("http://")
                .and_then(|rest| rest.split('/').next())
                .expect("loopback redirect_uri")
                .to_string();
            let code = self.code.clone();
            // Spawn the "browser" round-trip; `sign_in_once` then awaits the
            // listener, which accepts this connection.
            tokio::spawn(async move {
                let mut s = TcpStream::connect(&authority)
                    .await
                    .expect("connect loopback");
                let q = match &code {
                    Some(c) => format!("code={c}&state={state}"),
                    None => format!("state={state}"),
                };
                let req = format!("GET /oauth/callback?{q} HTTP/1.1\r\nHost: x\r\n\r\n");
                s.write_all(req.as_bytes()).await.expect("write redirect");
                s.flush().await.expect("flush");
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf).await;
            });
            Ok(Box::new(()))
        }
    }

    fn authenticator(oidc: Arc<FakeOidcClient>, opener: EchoOpener) -> Authenticator {
        Authenticator::with_opener(
            oidc,
            "https://identitycenter.amazonaws.com/ssoins-test".into(),
            Arc::new(opener),
        )
    }

    #[tokio::test]
    async fn sign_in_once_returns_token_on_happy_path() {
        let oidc = Arc::new(FakeOidcClient::ok());
        let auth = authenticator(
            oidc.clone(),
            EchoOpener {
                code: Some("auth-code-123".into()),
                force_state: None,
            },
        );
        let token = auth.sign_in_once().await.expect("sign-in");
        assert_eq!(token.expose(), "fake-access-token");
        // Proof the loopback round-trip carried the browser's code through to the
        // token exchange — the whole shell executed, not just its ends.
        assert_eq!(oidc.seen_code().as_deref(), Some("auth-code-123"));
        assert_eq!(oidc.register_count(), 1);
        assert_eq!(oidc.token_count(), 1);
    }

    #[tokio::test]
    async fn sign_in_once_rejects_state_mismatch_before_token_exchange() {
        let oidc = Arc::new(FakeOidcClient::ok());
        let auth = authenticator(
            oidc.clone(),
            EchoOpener {
                code: Some("c".into()),
                force_state: Some("WRONG-STATE".into()),
            },
        );
        let err = auth.sign_in_once().await.expect_err("state mismatch");
        assert!(matches!(err, SignInError::StateMismatch));
        // CSRF is verified BEFORE the code is used — the token endpoint stays untouched.
        assert_eq!(oidc.token_count(), 0);
    }

    #[tokio::test]
    async fn sign_in_once_errors_when_redirect_carries_no_code() {
        let oidc = Arc::new(FakeOidcClient::ok());
        let auth = authenticator(
            oidc.clone(),
            EchoOpener {
                code: None,
                force_state: None,
            },
        );
        let err = auth.sign_in_once().await.expect_err("missing code");
        assert!(matches!(err, SignInError::TokenEndpoint));
        assert_eq!(oidc.token_count(), 0);
    }

    #[tokio::test]
    async fn sign_in_once_propagates_register_client_failure() {
        let oidc = Arc::new(FakeOidcClient::failing_register());
        let auth = authenticator(
            oidc.clone(),
            EchoOpener {
                code: Some("c".into()),
                force_state: None,
            },
        );
        let err = auth.sign_in_once().await.expect_err("register fails");
        assert!(matches!(err, SignInError::Sdk { .. }));
        // Registration failed first; the browser opener and token exchange never ran.
        assert_eq!(oidc.token_count(), 0);
    }

    #[tokio::test]
    async fn sign_in_once_propagates_create_token_failure() {
        let oidc = Arc::new(FakeOidcClient::failing_token());
        let auth = authenticator(
            oidc.clone(),
            EchoOpener {
                code: Some("c".into()),
                force_state: None,
            },
        );
        let err = auth.sign_in_once().await.expect_err("token fails");
        assert!(matches!(err, SignInError::TokenEndpoint));
        assert_eq!(oidc.token_count(), 1); // reached, then failed
    }
}
