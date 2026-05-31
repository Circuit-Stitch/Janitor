# GUI ↔ AWS bridge: a worker thread, a tested Session, and lazy sign-in

**Status:** accepted

## Context

ADR 0010/0011 landed real Identity Center auth in `janitor-aws` and proved it
end-to-end via `live-verify`, but the GUI still reads `MockSource`. The GUI is
single-threaded Slint; `janitor-aws::AuthenticatedSource::fetch` is async,
`&mut self`, and can block on a browser sign-in for seconds–minutes. `core`'s
`SecretSource` is sync by design (its doc comment already anticipated this
async seam). We need real data in the matrix without freezing the UI, without
pushing auth/AWS/compare logic into the thin GUI (ADR 0003), and without ever
writing a secret to disk.

## Decision

- **A worker `std::thread` owns a Tokio current-thread runtime and the auth
  session.** The UI sends `Command`s over an `mpsc` channel; the worker posts
  `Event`s back via `slint::Weak::upgrade_in_event_loop`. `core` stays sync; the
  async boundary is confined to the GUI↔AWS seam. A "sync adapter that
  `block_on`s on the UI thread" was rejected — it would freeze the window during
  sign-in.
- **The new logic lives in a tested `janitor-aws::Session`, not the GUI.**
  `Session` (built from the same `Arc<dyn …>` seams as `live-verify`) owns lazy
  sign-in, per-Application multi-Environment fetch, the whole-app error rule, and
  cell reveal — all unit-tested against the existing `wire::fakes`. The GUI gains
  only plumbing (worker thread, `Command`/`Event`, marshalling), consistent with
  ADR 0003 and ADR 0010 §5 (only the real adapters/browser stay untested).
- **Lazy, explicit sign-in.** The app opens signed-out and fully browsable
  (sidebar, settings, the manual editor). A Sign-in button (or any auth-needing
  action) starts the browser. `Session::sign_in` is idempotent (also serves as
  ensure-signed-in).
- **Secrets stay in the worker; reveal is an async round-trip.** Fetched
  `SecretShape`s live only in `Session::cached`; the UI holds the masked
  `MatrixView` + `RowKey`s. A reveal sends the key, gets one plaintext `String`
  back, and the existing auto-hide timer clears it. Plaintext touches the UI
  thread only at that sanctioned moment (ADR 0003), never the whole Set.
- **Whole-app error on partial failure.** If any Environment fails, the matrix
  is not shown; one banner names the failed Environments and why
  (`FetchFailReason`, a masked mapping of `SessionError` with no SDK text). A
  fetch failure is never rendered as a Gap (the high-signal finding).
- **`JANITOR_MOCK=1` keeps the GUI offline-runnable** via `MockSource`, served
  through the same `Event` path so there is one UI rendering path.
- **Terminology: "SSO start URL".** The label matches AWS' Get-credentials
  dialog; `Config.sso_start_url` is unchanged. The value is the instance form
  (`…/ssoins-…`), not the portal `…/start` URL (Milestone B #1). The internal
  `Authenticator` arg stays `issuer_url` (the literal SDK field).

## Consequences

- `janitor-gui` now depends on `janitor-aws` + `tokio` (worker runtime). The
  worker/marshalling is untested shell; the `Session` it drives is fully tested.
- `wire::fakes` gains a `FakeReauth` (additive; no existing test changed).
- **Implementation note — the UI-thread `thread_local`.** Slint's
  `upgrade_in_event_loop` closure is `Send + 'static`, but the shared
  `Rc<RefCell<AppState>>` is `!Send`, so the worker→UI bridge cannot capture it.
  The bridge therefore reaches the state through a UI-thread `thread_local`
  (published before the worker is spawned, and only ever touched on the UI
  thread). The outer closure captures only the `Send` `Weak<MainWindow>`.
- **Graceful shutdown.** The UI sends `Command::Shutdown` to the worker when
  `ui.run()` returns, ending the worker loop so the `Session` (and its cached
  secrets) is dropped on close ahead of process teardown. This is best-effort —
  the worker thread is not joined — but the invariant holds either way: if the
  drop runs, the zeroizing cache is cleared; if the process exits first, nothing
  was ever written to disk.
- Live re-verification (browser + real org) is human-gated, like `live-verify`,
  and deferred to a hands-on session. The mock path is verified by launching it
  (`JANITOR_MOCK=1`).
- **Known limitations (tracked follow-ups, not blockers):**
  - The worker reads `sso_start_url`/`sso_region` once at startup; editing them
    in Settings persists to `Config` but takes effect on the next launch.
  - After a real load *error*, selecting a different Application records the
    selection but does not auto-reload; the user re-triggers via Sign in/Refresh.
  - `SignInError` reaches the banner via its `Display` (a short, leak-tested
    non-secret label) rather than the load path's `FetchFailReason::describe()`;
    unifying both error surfaces on one masked mapping is a future hardening.
- **Deferred (unchanged from spec):** discovery-driven column assembly,
  per-column error rendering, and the typed `GetSecretValue` error mapping
  (separate Milestone-B follow-up).
