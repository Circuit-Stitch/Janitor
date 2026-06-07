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

    // ---- Local-socket coverage of the listener shell (ADR 0027 Layer 1) -------
    //
    // `wait_for_redirect` is real socket I/O, declared "untested shell" by ADR
    // 0010 §5. It needs no AWS and no browser: bind an *ephemeral* loopback port
    // (NOT `bind_first_free`'s fixed set — that would contend across parallel
    // tests), then have the test itself connect and play the browser's role,
    // sending the redirect request the IdP would. This exercises accept → read →
    // target/query parse → the "close this tab" write, and the timeout/parse
    // error paths.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Bind `127.0.0.1:0`, run `wait_for_redirect` against it while the test
    /// sends `raw_request`, and return (listener result, the bytes the listener
    /// wrote back). One read on the server side mirrors production.
    async fn drive_redirect(raw_request: &str) -> (Result<String, SignInError>, String) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral");
        let addr = listener.local_addr().expect("local addr");
        let server = wait_for_redirect(listener, Duration::from_secs(5));
        let req = raw_request.to_string();
        let client = async move {
            let mut s = TcpStream::connect(addr).await.expect("connect");
            s.write_all(req.as_bytes()).await.expect("write request");
            s.flush().await.expect("flush");
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.expect("read response");
            String::from_utf8_lossy(&buf).into_owned()
        };
        tokio::join!(server, client)
    }

    #[tokio::test]
    async fn wait_for_redirect_returns_query_and_writes_close_page() {
        let (query, response) =
            drive_redirect("GET /oauth/callback?code=abc&state=xyz HTTP/1.1\r\nHost: x\r\n\r\n")
                .await;
        assert_eq!(query.expect("redirect captured"), "code=abc&state=xyz");
        // The listener answered the browser so the tab can close.
        assert!(response.contains("200 OK"), "status line: {response}");
        assert!(
            response.contains("You can close this tab"),
            "close page: {response}"
        );
    }

    #[tokio::test]
    async fn wait_for_redirect_returns_empty_query_when_no_question_mark() {
        // A request target with no `?` → empty query (the `unwrap_or_default`
        // branch), still a successful capture.
        let (query, _resp) =
            drive_redirect("GET /oauth/callback HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert_eq!(query.expect("captured"), "");
    }

    #[tokio::test]
    async fn wait_for_redirect_errors_when_request_line_has_no_target() {
        // A first line with no request target → `first_request_target` is None →
        // `SignInError::Network`. The listener never writes a response.
        let (query, _resp) = drive_redirect("GARBAGE\r\n\r\n").await;
        assert!(
            matches!(query, Err(SignInError::Network)),
            "unparseable request line must be Network, got {query:?}"
        );
    }

    #[tokio::test]
    async fn wait_for_redirect_times_out_when_no_request_arrives() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral");
        let err = wait_for_redirect(listener, Duration::from_millis(50))
            .await
            .expect_err("no client connected");
        assert!(
            matches!(err, SignInError::ListenerTimeout),
            "expected ListenerTimeout, got {err:?}"
        );
    }
}
