//! One-shot loopback listener + browser launch for the Auth Code redirect
//! (ADR 0010 §2a/§7). Untested shell: it does real socket + browser I/O. The
//! query-parsing helper is the one pure, testable piece and is unit-tested.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::error::SignInError;

/// The candidate loopback ports we register and try to bind, in order. Must
/// match the `redirect_uris` passed to RegisterClient (ADR 0010 §7).
pub const LOOPBACK_PORTS: &[u16] = &[53690, 53691, 53692, 53693];

/// Build the redirect URIs we register for these ports (literal 127.0.0.1).
pub fn redirect_uris() -> Vec<String> {
    LOOPBACK_PORTS.iter().map(|p| format!("http://127.0.0.1:{p}/callback")).collect()
}

/// Bind the first free registered loopback port; return (listener, its URI).
pub async fn bind_first_free() -> Result<(TcpListener, String), SignInError> {
    for port in LOOPBACK_PORTS {
        if let Ok(l) = TcpListener::bind(("127.0.0.1", *port)).await {
            return Ok((l, format!("http://127.0.0.1:{port}/callback")));
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
pub async fn wait_for_redirect(listener: TcpListener, timeout: Duration) -> Result<String, SignInError> {
    let accept = async {
        let (mut stream, _) = listener.accept().await.map_err(|_| SignInError::Network)?;
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.map_err(|_| SignInError::Network)?;
        let req = String::from_utf8_lossy(&buf[..n]);
        let target = first_request_target(&req).ok_or(SignInError::Network)?;
        let query = target.split_once('?').map(|(_, q)| q.to_string()).unwrap_or_default();
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
    tokio::time::timeout(timeout, accept).await.map_err(|_| SignInError::ListenerTimeout)?
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
        assert_eq!(first_request_target(req), Some("/callback?code=abc&state=xyz"));
    }

    #[test]
    fn parses_query_params_with_decoding() {
        let q = "code=ab%2Fcd&state=xy+z";
        assert_eq!(query_param(q, "code").as_deref(), Some("ab/cd"));
        assert_eq!(query_param(q, "state").as_deref(), Some("xy z"));
        assert_eq!(query_param(q, "missing"), None);
    }

    #[test]
    fn redirect_uris_use_literal_loopback_ip() {
        for uri in redirect_uris() {
            assert!(uri.starts_with("http://127.0.0.1:"), "must be literal 127.0.0.1");
            assert!(uri.ends_with("/callback"));
        }
    }
}
