//! Real `Authenticator` (ADR 0010 §3/§7): the full browser PKCE Sign-in. Shell
//! code — it opens a browser and binds a socket. The pure pieces it uses
//! (`pkce`, `state`, `loopback::query_param`) are tested elsewhere.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::error::SignInError;
use crate::loopback::{
    bind_first_free, open_browser, query_param, redirect_uris, wait_for_redirect,
};
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
}

impl Authenticator {
    pub fn new(oidc: Arc<dyn OidcClient>, issuer_url: String) -> Self {
        Authenticator { oidc, issuer_url }
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

        // 3. Open the browser and wait for the redirect.
        open_browser(&authorize_url)?;
        let query = wait_for_redirect(listener, SIGN_IN_TIMEOUT).await?;

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

    #[test]
    fn urlencode_escapes_reserved_and_keeps_unreserved() {
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(urlencode("a/b c"), "a%2Fb%20c");
        assert_eq!(urlencode("x:y"), "x%3Ay");
    }
}
