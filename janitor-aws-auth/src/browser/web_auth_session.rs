//! The macOS native Sign-in browser (ADR 0033): render the authorize URL in an
//! ephemeral `ASWebAuthenticationSession` (`prefersEphemeralWebBrowserSession`) so
//! the Identity Center portal cookie is isolated from other browser-based AWS tools
//! (the CLI) — with no separate browser app and no new cookie left behind.
//!
//! Selected by the [`NATIVE_SENTINEL`](super::NATIVE_SENTINEL) value of
//! `Config.browser_command`. Untested shell (ADR 0010 §5): it drives AppKit /
//! AuthenticationServices. The mechanism was proven on-device by `aswebauth-spike`
//! (ADR 0033 Decision 4): the **loopback listener catches the code from inside the
//! ephemeral session**, and the completion handler never fires for an `http`
//! loopback callback — so it is wired only as the error/cancel sink, and the
//! loopback stays the universal redirect catcher (like every other opener).
//!
//! ## Threading
//! The worker thread calls [`open`](BrowserOpener::open). AppKit and
//! `ASWebAuthenticationSession::{start,cancel}()` are main-thread-only, so both
//! creation and teardown hop to the **main thread** via the main GCD queue
//! (`dispatch2`) — drained by the GUI's Cocoa run loop (Slint owns the
//! `NSApplication`), keeping this crate GUI-framework-free (ADR 0003). The session
//! is main-thread-bound, so it crosses back to the worker only inside a
//! [`MainThreadBound`] (which is `Send`).
//!
//! ## Cancel-on-code
//! `open()` creates the session on main and hands a [`WebAuthGuard`] back to the
//! authenticator, which holds it across `wait_for_redirect` and **drops it the
//! moment the code arrives** — the drop hops to main and `cancel()`s the session,
//! closing the window (it does not auto-close: the http callback never fires the
//! completion handler). Creation is synchronous, so a failure (bad URL / no run
//! loop / `start()` false) returns `BrowserLaunch` fast, like the other openers —
//! not a silent degrade to a loopback timeout.

use std::cell::OnceCell;
use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use dispatch2::{DispatchQueue, MainThreadBound};
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{define_class, msg_send, AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{NSBackingStoreType, NSWindow, NSWindowStyleMask};
use objc2_authentication_services::{
    ASPresentationAnchor, ASWebAuthenticationPresentationContextProviding,
    ASWebAuthenticationSession,
};
use objc2_foundation::{
    NSError, NSObject, NSObjectProtocol, NSPoint, NSRect, NSSize, NSString, NSURL,
};

use crate::browser::{BrowserOpener, SignInSurface};
use crate::error::SignInError;

/// How long `open()` waits for the main thread to create the session before giving
/// up with `BrowserLaunch`. Generous — it only bites the pathological "no run loop"
/// case (e.g. `@native` set in a non-GUI context); a real GUI services the queue at
/// once.
const CREATE_TIMEOUT: Duration = Duration::from_secs(20);

/// Opens Sign-in in a macOS native ephemeral `ASWebAuthenticationSession`. Stateless.
pub struct WebAuthSessionBrowser;

impl BrowserOpener for WebAuthSessionBrowser {
    fn open(&self, url: &str) -> Result<Box<dyn SignInSurface>, SignInError> {
        // Surface only (no URL — it carries the client_id + PKCE challenge).
        tracing::info!(target: "janitor::aws", surface = "macos-native", "Opening Sign-in browser");
        let url = url.to_string();
        let (tx, rx) = mpsc::channel::<Option<MainThreadBound<SessionBundle>>>();
        // Create + start on the main GCD queue (drained by the GUI's run loop), then
        // hand the Send-wrapped bundle back so failures surface synchronously.
        DispatchQueue::main().exec_async(move || {
            let mtm = MainThreadMarker::new().expect("the main GCD queue runs on the main thread");
            let bound = create_session(mtm, &url).map(|b| MainThreadBound::new(b, mtm));
            let _ = tx.send(bound);
        });
        match rx.recv_timeout(CREATE_TIMEOUT) {
            Ok(Some(bundle)) => Ok(Box::new(WebAuthGuard {
                bundle: Some(bundle),
            })),
            // None (creation failed, logged on main) or timeout (no run loop).
            _ => Err(SignInError::BrowserLaunch),
        }
    }
}

/// The live session plus the objects that must outlive `open()` alongside it: the
/// anchor (the session holds it only *weakly*) and the completion block. All
/// main-thread-only, so the guard carries them in a [`MainThreadBound`].
struct SessionBundle {
    session: Retained<ASWebAuthenticationSession>,
    _anchor: Retained<WebAuthAnchor>,
    _completion: RcBlock<dyn Fn(*mut NSURL, *mut NSError)>,
}

/// The [`SignInSurface`] guard the authenticator holds across `wait_for_redirect`.
/// Dropping it dismisses the session (cancel-on-code); since the session is
/// main-thread-only, the drop hops back to the main GCD queue to `cancel()` and
/// release it there.
struct WebAuthGuard {
    bundle: Option<MainThreadBound<SessionBundle>>,
}

impl SignInSurface for WebAuthGuard {}

impl Drop for WebAuthGuard {
    fn drop(&mut self) {
        let Some(bound) = self.bundle.take() else {
            return;
        };
        DispatchQueue::main().exec_async(move || {
            let mtm = MainThreadMarker::new().expect("the main GCD queue runs on the main thread");
            let bundle = bound.into_inner(mtm); // extract on the main thread
            unsafe { bundle.session.cancel() }; // close the session window
                                                // `bundle` drops here, on main → releases session/anchor/block.
        });
    }
}

// ---- everything below runs on the main thread (via the dispatches above) --------

#[derive(Debug, Default)]
struct AnchorIvars {
    window: OnceCell<Retained<NSWindow>>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "JanitorWebAuthAnchor"]
    #[ivars = AnchorIvars]
    struct WebAuthAnchor;

    unsafe impl NSObjectProtocol for WebAuthAnchor {}

    // The session demands a non-nil NSWindow anchor before `start()` (else it
    // throws "Cannot start … without providing presentation context"). It keeps the
    // delegate only weakly, so the [`SessionBundle`] owns this for its whole life.
    unsafe impl ASWebAuthenticationPresentationContextProviding for WebAuthAnchor {
        #[unsafe(method_id(presentationAnchorForWebAuthenticationSession:))]
        fn anchor(&self, _s: &ASWebAuthenticationSession) -> Retained<ASPresentationAnchor> {
            // ASPresentationAnchor == NSObject; NSWindow is-a NSObject.
            let window = self
                .ivars()
                .window
                .get()
                .expect("anchor window set")
                .clone();
            unsafe { Retained::cast_unchecked::<ASPresentationAnchor>(window) }
        }
    }
);

impl WebAuthAnchor {
    fn new(mtm: MainThreadMarker, window: Retained<NSWindow>) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(AnchorIvars::default());
        let this: Retained<Self> = unsafe { msg_send![super(this), init] };
        let _ = this.ivars().window.set(window);
        this
    }
}

/// Create + start an ephemeral session for `url`, returning the bundle to keep
/// alive, or `None` on failure (logged). MUST run on the main thread.
fn create_session(mtm: MainThreadMarker, url: &str) -> Option<SessionBundle> {
    let Some(nsurl) = NSURL::URLWithString(&NSString::from_str(url)) else {
        tracing::error!(target: "janitor::aws", "macOS Sign-in URL did not parse");
        return None;
    };

    let anchor = WebAuthAnchor::new(mtm, tiny_window(mtm));
    // For an http loopback there is no custom scheme to intercept (ADR 0033
    // Decision 4): pass `None`; this handler is the error/cancel sink only.
    let completion = RcBlock::new(|_url: *mut NSURL, _err: *mut NSError| {});

    // The `callbackURLScheme` init is deprecated on macOS 26 for the callback-object
    // init, but that one requires a custom scheme / https host to match — an http
    // loopback matches neither — so the legacy `None` form is the correct call.
    #[allow(deprecated)]
    let session = unsafe {
        ASWebAuthenticationSession::initWithURL_callbackURLScheme_completionHandler(
            ASWebAuthenticationSession::alloc(),
            &nsurl,
            None,
            RcBlock::as_ptr(&completion),
        )
    };
    unsafe {
        session.setPrefersEphemeralWebBrowserSession(true); // isolated cookie jar
        let proto = ProtocolObject::from_ref(&*anchor);
        session.setPresentationContextProvider(Some(proto)); // REQUIRED before start()
        if !session.start() {
            tracing::error!(target: "janitor::aws", "macOS Sign-in session failed to start");
            return None;
        }
    }
    Some(SessionBundle {
        session,
        _anchor: anchor,
        _completion: completion,
    })
}

/// A 1×1 borderless window — the session only needs a non-nil NSWindow as a
/// positioning hint; it is never shown.
fn tiny_window(mtm: MainThreadMarker) -> Retained<NSWindow> {
    let rect = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(1.0, 1.0));
    unsafe {
        NSWindow::initWithContentRect_styleMask_backing_defer(
            NSWindow::alloc(mtm),
            rect,
            NSWindowStyleMask::Borderless,
            NSBackingStoreType::Buffered,
            false,
        )
    }
}
