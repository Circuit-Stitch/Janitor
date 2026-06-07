//! Step-0 integration spike (ADR 0010 §2a): prove browser-open → loopback-catch
//! → code-extraction on this OS, against a HARDCODED fake authorize URL that
//! immediately redirects back to our loopback. Run manually:
//!
//!   cargo run -p janitor-aws --bin loopback-spike
//!
//! It opens a browser tab that bounces to 127.0.0.1 and the program prints the
//! extracted code/state, then exits. No AWS involved.

use std::time::Duration;

use janitor_aws_auth::loopback::{bind_first_free, open_browser, query_param, wait_for_redirect};

#[tokio::main]
async fn main() {
    let (listener, redirect_uri) = bind_first_free().await.expect("bind loopback");
    println!("listening on {redirect_uri}");

    // A real /authorize would redirect here with ?code=&state=. To prove the
    // shell without AWS, point the browser straight at our own loopback with
    // fake params.
    let fake_redirect = format!("{redirect_uri}?code=FAKE_CODE&state=FAKE_STATE");
    println!("opening browser at fake authorize redirect: {fake_redirect}");
    open_browser(&fake_redirect).expect("open browser");

    let query = wait_for_redirect(listener, Duration::from_secs(60))
        .await
        .expect("redirect");
    println!("got query: {query}");
    println!("code  = {:?}", query_param(&query, "code"));
    println!("state = {:?}", query_param(&query, "state"));
    assert_eq!(query_param(&query, "code").as_deref(), Some("FAKE_CODE"));
    println!("loopback spike OK");
}
