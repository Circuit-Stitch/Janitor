//! One-shot loopback listener + browser launch for the Auth Code redirect
//! (ADR 0010 §2a/§7). Untested shell: it does real socket + browser I/O. The
//! query-parsing helper is the one pure, testable piece and is unit-tested.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::error::SignInError;

/// The candidate loopback ports we bind, in order. These appear only in the
/// authorize/token `redirect_uri` (carrying the chosen port, via
/// [`bind_first_free`]); the value REGISTERED with RegisterClient is port-less
/// (see [`redirect_uris`]).
pub const LOOPBACK_PORTS: &[u16] = &[53690, 53691, 53692, 53693];

/// The loopback redirect URI we REGISTER with `RegisterClient`.
///
/// IAM Identity Center requires the loopback redirect PATH to be exactly
/// `/oauth/callback` for a public client. Any other path (`/callback`, `/`,
/// `/anything`) is rejected with a misleadingly-worded
/// `InvalidRedirectUriException` ("Requested client type must use loopback
/// interface for redirect") — the message blames the interface, but the real
/// constraint is the path. Verified empirically against the live
/// `RegisterClient` endpoint (Milestone B, ADR 0011); the AWS CLI's
/// `AuthCodeFetcher` uses this same `/oauth/callback` path.
///
/// We register port-less. Per RFC 8252 §7.3 the authorization server ignores a
/// loopback redirect's port when matching, so this single registration matches
/// whichever ephemeral port [`bind_first_free`] binds at authorize/token time
/// (confirmed: both port-less and port-bearing `/oauth/callback` register OK).
pub fn redirect_uris() -> Vec<String> {
    vec!["http://127.0.0.1/oauth/callback".to_string()]
}

/// Bind the first free registered loopback port; return (listener, its URI).
pub async fn bind_first_free() -> Result<(TcpListener, String), SignInError> {
    for port in LOOPBACK_PORTS {
        if let Ok(l) = TcpListener::bind(("127.0.0.1", *port)).await {
            // Path MUST be `/oauth/callback` to match what `redirect_uris`
            // registers — IAM Identity Center enforces this exact path.
            return Ok((l, format!("http://127.0.0.1:{port}/oauth/callback")));
        }
    }
    Err(SignInError::NoLoopbackPort)
}

/// Open the user's browser at `url`.
pub fn open_browser(url: &str) -> Result<(), SignInError> {
    open::that(url).map_err(|_| SignInError::BrowserLaunch)
}

/// Wait (up to `timeout`) for one redirect request, returning the raw query
/// string (everything after `?` in the request target).
pub async fn wait_for_redirect(
    listener: TcpListener,
    timeout: Duration,
) -> Result<String, SignInError> {
    let accept = async {
        let (mut stream, _) = listener.accept().await.map_err(|_| SignInError::Network)?;
        let mut buf = vec![0u8; 4096];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|_| SignInError::Network)?;
        let req = String::from_utf8_lossy(&buf[..n]);
        let target = first_request_target(&req).ok_or(SignInError::Network)?;
        let query = target
            .split_once('?')
            .map(|(_, q)| q.to_string())
            .unwrap_or_default();
        let body = "<html><body>Sign-in complete. You can close this tab.</body></html>";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
        Ok::<String, SignInError>(query)
    };
    tokio::time::timeout(timeout, accept)
        .await
        .map_err(|_| SignInError::ListenerTimeout)?
}

/// Extract the request target (e.g. `/callback?code=...`) from the first line.
fn first_request_target(req: &str) -> Option<&str> {
    let first_line = req.lines().next()?;
    // "GET /callback?code=...&state=... HTTP/1.1"
    first_line.split_whitespace().nth(1)
}

/// Pull a single query parameter's value from a `k=v&k2=v2` query string.
/// Minimal percent-decode for `%XX` and `+`. Pure + tested.
pub fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.replace('+', " ");
    let mut out = String::with_capacity(bytes.len());
    let mut chars = bytes.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h: String = chars.by_ref().take(2).collect();
            if let Ok(b) = u8::from_str_radix(&h, 16) {
                out.push(b as char);
                continue;
            }
            out.push('%');
            out.push_str(&h);
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_target_from_request_line() {
        let req = "GET /callback?code=abc&state=xyz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        assert_eq!(
            first_request_target(req),
            Some("/callback?code=abc&state=xyz")
        );
    }

    #[test]
    fn parses_query_params_with_decoding() {
        let q = "code=ab%2Fcd&state=xy+z";
        assert_eq!(query_param(q, "code").as_deref(), Some("ab/cd"));
        assert_eq!(query_param(q, "state").as_deref(), Some("xy z"));
        assert_eq!(query_param(q, "missing"), None);
    }

    #[test]
    fn registered_redirect_uri_uses_loopback_and_oauth_callback_path() {
        // IAM Identity Center requires the registered loopback redirect path to
        // be EXACTLY `/oauth/callback`; other paths are rejected with a
        // misleading "must use loopback interface" error (verified live,
        // Milestone B). We register port-less; the port is added at
        // authorize/token time by `bind_first_free`.
        assert_eq!(
            redirect_uris(),
            vec!["http://127.0.0.1/oauth/callback".to_string()]
        );
    }

    #[test]
    fn bound_redirect_uri_uses_oauth_callback_path() {
        // The authorize/token redirect_uri must share the registered path
        // (`/oauth/callback`) so the loopback match succeeds (RFC 8252 §7.3
        // ignores only the port, not the path).
        let (_listener, uri) = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bind_first_free())
            .expect("bind a loopback port");
        assert!(
            uri.starts_with("http://127.0.0.1:"),
            "literal loopback host"
        );
        assert!(
            uri.ends_with("/oauth/callback"),
            "path must be /oauth/callback, got {uri}"
        );
    }
}
