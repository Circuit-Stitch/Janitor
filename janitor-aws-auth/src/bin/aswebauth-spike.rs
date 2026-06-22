//! macOS Sign-in browser spike (ADR 0033). Resolves the two deferred unknowns
//! before the real `ASWebAuthenticationSession` opener is written:
//!
//!   (A) Does the ephemeral in-session webview navigate to our HTTP loopback
//!       (`http://127.0.0.1:<port>/oauth/callback`) so our tokio listener
//!       catches the `?code=&state=`? (the authoritative success signal)
//!   (B) Does the session's completion handler fire for an `http` loopback
//!       callback? (expected NO — it only matches custom schemes / https
//!       associated-domains; so it is the dead/cancel path, not the success path)
//!
//! Run on a Mac:
//!   cargo run -p janitor-aws-auth --bin aswebauth-spike
//!   cargo run -p janitor-aws-auth --bin aswebauth-spike -- "<a real https authorize URL>"
//!
//! With no arg it self-redirects (mirrors `loopback-spike`): the session loads our
//! own loopback URL carrying fake `?code=&state=`, proving (A) with no AWS. Pass a
//! real authorize URL to watch a real `https -> http(127.0.0.1)` redirect hop.
//!
//! Throwaway untested shell (ADR 0010 §5). Threading note: this bin's `main()` IS
//! the main thread, so it sidesteps the worker->main marshalling the GUI opener
//! will need (`slint::invoke_from_event_loop`, worker.rs); the spike isolates the
//! Apple-side question only.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("aswebauth-spike is macOS-only (it drives ASWebAuthenticationSession).");
}

#[cfg(target_os = "macos")]
fn main() {
    macos::run();
}

#[cfg(target_os = "macos")]
mod macos {
    use std::cell::OnceCell;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::ProtocolObject;
    use objc2::{
        define_class, msg_send, AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly,
    };
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy, NSWindow};
    use objc2_authentication_services::{
        ASPresentationAnchor, ASWebAuthenticationPresentationContextProviding,
        ASWebAuthenticationSession,
    };
    use objc2_foundation::{NSError, NSObject, NSObjectProtocol, NSString, NSURL};

    use janitor_aws_auth::loopback::{bind_first_free, query_param, wait_for_redirect};

    /// Flipped by the completion handler so we can report unknown (B) after a grace
    /// window. The whole point of the spike is to observe whether this ever flips
    /// for an http callback.
    static COMPLETION_FIRED: AtomicBool = AtomicBool::new(false);

    // ---- The one ObjC subclass we must define: the presentation-context provider.
    // The session keeps it only WEAKLY and demands a non-nil NSWindow anchor before
    // start() (else it throws "Cannot start ... without providing presentation
    // context"), so we own it for the whole flow.
    #[derive(Debug, Default)]
    struct AnchorIvars {
        window: OnceCell<Retained<NSWindow>>,
    }

    define_class!(
        #[unsafe(super(NSObject))]
        #[thread_kind = MainThreadOnly]
        #[name = "JanitorSpikeAnchor"]
        #[ivars = AnchorIvars]
        struct AuthAnchor;

        unsafe impl NSObjectProtocol for AuthAnchor {}

        unsafe impl ASWebAuthenticationPresentationContextProviding for AuthAnchor {
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

    impl AuthAnchor {
        fn new(mtm: MainThreadMarker, window: Retained<NSWindow>) -> Retained<Self> {
            let this = Self::alloc(mtm).set_ivars(AnchorIvars::default());
            let this: Retained<Self> = unsafe { msg_send![super(this), init] };
            let _ = this.ivars().window.set(window);
            this
        }
    }

    pub fn run() {
        let mtm = MainThreadMarker::new().expect("aswebauth-spike must run on the main thread");

        // (a) NSApplication. Accessory = no Dock icon; the browser window still fronts.
        let app = NSApplication::sharedApplication(mtm);
        app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

        // (b) A tiny anchor window — only a positioning hint; never shown.
        let anchor = AuthAnchor::new(mtm, tiny_window(mtm));

        // (c) Bind the loopback on a background tokio thread (reusing the tested
        //     listener); it sends back the redirect_uri, then catches the code.
        let (uri_tx, uri_rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async move {
                let (listener, redirect_uri) = bind_first_free().await.expect("bind loopback");
                uri_tx.send(redirect_uri).expect("send redirect_uri");
                let query = match wait_for_redirect(listener, Duration::from_secs(120)).await {
                    Ok(q) => q,
                    Err(e) => {
                        // No redirect (e.g. the consent dialog was never approved).
                        // Exit cleanly rather than leaving app.run() spinning forever.
                        println!("[loopback] no redirect within timeout: {e:?}");
                        std::process::exit(1);
                    }
                };
                println!(
                    "[loopback] CAUGHT via socket: code={:?} state={:?}",
                    query_param(&query, "code"),
                    query_param(&query, "state"),
                );
                // Grace window so any completion handler can fire before we report.
                std::thread::sleep(Duration::from_secs(3));
                let fired = COMPLETION_FIRED.load(Ordering::SeqCst);
                println!(
                    "\n=== ADR 0033 spike result ===\n\
                     (A) loopback caught the code from inside the ephemeral session: YES\n\
                     (B) completion handler fired for the http callback: {}\n\
                     => production opener design: loopback-catches-the-code + {}\n",
                    if fired {
                        "YES (surprise — the handler is usable)"
                    } else {
                        "NO (expected)"
                    },
                    if fired {
                        "the-completion-handler"
                    } else {
                        "cancel-on-code"
                    },
                );
                std::process::exit(0);
            });
        });
        let redirect_uri = uri_rx.recv().expect("loopback redirect_uri");
        println!("[spike] listening on {redirect_uri}");

        // (d) Authorize URL. Default: point the session straight at our own loopback
        //     with fake params (no AWS) to prove (A); or pass a real https authorize
        //     URL as arg 1 to watch the real https->http redirect hop.
        let authorize_url = std::env::args()
            .nth(1)
            .unwrap_or_else(|| format!("{redirect_uri}?code=FAKE_CODE&state=FAKE_STATE"));
        println!("[spike] opening ephemeral session at: {authorize_url}");

        // (e) Completion handler — for an http loopback this is the dead/cancel path.
        //     Args are raw *mut (either may be null).
        let completion = RcBlock::new(move |url: *mut NSURL, err: *mut NSError| {
            COMPLETION_FIRED.store(true, Ordering::SeqCst);
            let callback = if url.is_null() {
                "<null>".to_string()
            } else {
                unsafe { &*url }
                    .absoluteString()
                    .map(|s| s.to_string())
                    .unwrap_or_default()
            };
            let err_code = if err.is_null() {
                None
            } else {
                Some(unsafe { &*err }.code())
            };
            println!("[completion] fired: callbackURL={callback} error_code={err_code:?}");
        });

        // (f) Build + configure (ephemeral) + start — all on the main thread.
        let url =
            NSURL::URLWithString(&NSString::from_str(&authorize_url)).expect("valid authorize URL");
        // The `callbackURLScheme` init is deprecated on macOS 26 in favour of the
        // callback-object init — but that one *requires* a custom scheme / https host
        // to match, and an http loopback matches neither, so the legacy init with
        // `None` is the semantically correct call here. (Production opener note: pass
        // a dummy never-matching scheme to the new API, or keep this legacy form.)
        #[allow(deprecated)]
        let session = unsafe {
            ASWebAuthenticationSession::initWithURL_callbackURLScheme_completionHandler(
                ASWebAuthenticationSession::alloc(),
                &url,
                None, // http loopback => no custom scheme for the OS to intercept
                RcBlock::as_ptr(&completion),
            )
        };
        unsafe {
            session.setPrefersEphemeralWebBrowserSession(true); // isolated cookie jar
            let proto = ProtocolObject::from_ref(&*anchor);
            session.setPresentationContextProvider(Some(proto)); // REQUIRED before start()
            let started = session.start();
            println!("[session] start() -> {started}");
            assert!(
                started,
                "start() failed — check anchor / main-thread / run-loop"
            );
        }

        // (g) Keep session + block + anchor alive for the whole flow (a drop cancels
        //     the session). Throwaway: leak them; the loopback thread process::exit()s.
        std::mem::forget(completion);
        std::mem::forget(anchor);
        std::mem::forget(session);

        // (h) Spin the main run loop so the UI + completion handler can fire.
        app.run();
    }

    /// A 1x1 borderless window — the session only needs a non-nil NSWindow anchor.
    fn tiny_window(mtm: MainThreadMarker) -> Retained<NSWindow> {
        use objc2_app_kit::{NSBackingStoreType, NSWindowStyleMask};
        use objc2_foundation::{NSPoint, NSRect, NSSize};
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
}
