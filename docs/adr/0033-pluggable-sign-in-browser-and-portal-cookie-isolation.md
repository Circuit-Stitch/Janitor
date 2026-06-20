# Pluggable Sign-in browser component, and Identity Center portal-cookie isolation

**Status:** accepted (implemented — presets backend + the component seam; macOS
native opener and the Settings UI are deferred slices, see Consequences)

**Related:** [ADR 0002](0002-identity-center-only-memory-only-auth.md) (Identity
Center-only, memory-only auth — the browser Sign-in this swaps the *surface* of),
[ADR 0010](0010-aws-auth-architecture-and-untested-shell.md) (the auth architecture
and the "untested shell" boundary the openers sit on), [ADR 0027](0027-injected-transport-and-browser-test-seams.md)
(the injected `BrowserOpener` test seam this promotes into a component),
[ADR 0003](0003-core-gui-split-slint-and-secret-display.md) (real logic in tested
crates, not the GUI; and why the GUI stays a softer-trust zone),
[ADR 0011](0011-guided-sign-in-and-discovery.md) (the `issuerUrl` form + the pure
`select::resolve` pattern this `select` mirrors), [ADR 0017](0017-error-taxonomy-and-diagnostic-log.md)
(the masked Diagnostic Log the opener logs its surface to), [THREAT-MODEL](../THREAT-MODEL.md)
(nothing-secret-on-disk; the host browser as an out-of-scope surface).

## Context

A user signed into Janitor on one AWS account, then ran `aws sso login` for a second
account in the **same Identity Center org** and was never prompted — the CLI silently
reused the org's portal session and minted a token for the wrong identity, needing an
`aws sso logout` to fix. The reported framing was "Janitor's credentials collide with
the system AWS CLI," and the proposed fixes were to **bundle the AWS CLI** and **keep
Janitor's own `~/.aws` config**.

Reading the code dissolved both the framing and the fixes:

- **There is no on-disk credential collision.** Every SDK client is built with
  `.no_credentials()` or with explicit in-memory minted `Credential`s
  (`aws_impl.rs`); Janitor never touches `~/.aws`, the SSO cache, or `AWS_PROFILE`.
  The SSO token is memory-only and dies with the process (ADR 0002).
- **Janitor needs no secondary program.** It speaks to AWS purely through the Rust
  SDK and reads SSM over a pure-Rust data channel (no `session-manager-plugin`,
  ADR 0025). The only `std::process` use was `exit()`.
- The **one** shared surface is the **system browser's Identity Center portal
  cookie**: Janitor's Sign-in (`open::that` → OS default browser) leaves a portal
  session cookie that a subsequent CLI `aws sso login` for the same org rides
  silently. Janitor opens that browser but does not own it — it cannot read, clear,
  or isolate the system browser's cookie jar.

So "keep our own `~/.aws`" would *manufacture* the one thing the threat model forbids
(an SSO-token + role-cred cache on disk), and "bundle the CLI" solves nothing. The
real, narrow problem is: **let the user isolate Janitor's Sign-in browser session
from other browser-based AWS tools** — which means rendering the authorize step in a
cookie jar the CLI never touches.

Two heavier pivots were explored and rejected (see Alternatives): a cross-platform
embedded webview via `wry`, and a full **Rust-lib + KMP/Compose** frontend rewrite.
Both founder on the same facts: Slint owns the event loop and macOS UI is
main-thread-bound, and Compose-desktop is JVM-on-all-three — so neither delivers
native auth "for free" on desktop, and the KMP path additionally regresses the
secret-in-memory posture (revealed Values would live in GC heap, not zeroizing Rust
buffers).

## Decision

Make the Sign-in browser a **pluggable component** behind the existing
`BrowserOpener` seam, and ship a zero-dependency **presets** strategy now; structure
the component so a macOS-native opener slots in later.

1. **Component: `janitor-aws-auth::browser`.** The `BrowserOpener` port moves out of
   `authenticator.rs` into its own module alongside its implementations and a single
   swap point:
   - `BrowserOpener::open(url) -> Result<(), SignInError>` — the port. **Fire-and-
     forget:** the opener only renders the authorize URL; the **loopback listener
     stays the universal redirect catcher**, so every strategy shares one redirect
     mechanism and the port stays one method.
   - `select(command: Option<&str>) -> Arc<dyn BrowserOpener>` — the swap point,
     mirroring ADR 0011's pure `select::resolve`. A private `choose()` decides the
     `Strategy` (pure, unit-tested); `select` constructs it. Adding a strategy is one
     match arm + one file.
   - `DefaultBrowser` — the OS default browser (`open::that`); shared cookie jar,
     today's behaviour.
   - `CommandBrowser` — spawns a user-configured command with `{url}` substituted,
     **shell-free** (whitespace-split; the URL is one argument, never interpolated
     into a shell line, so its `&`/`?`/`=` can't be reinterpreted). The parse
     (`build_browser_command`) is pure and unit-tested; only the spawn is shell.

2. **Config: `browser_command: Option<String>`.** `None` → OS default (unchanged
   behaviour); `Some("firefox -private-window {url}")` → a private/incognito window
   whose cookie jar is separate from the CLI's. A non-secret launch command, safe on
   disk (THREAT-MODEL). No migration: the field is `Option`, the struct is
   `#[serde(default)]`, and `None` is simply omitted from the TOML. Discriminating on
   `Option<String>` (not a TOML-awkward Config enum) keeps the modularity in `select`;
   an enum is the upgrade path when a third (native) strategy lands.

3. **Why presets, not auto-detect.** "Optimistically open incognito" was rejected: it
   needs per-OS default-browser detection + per-browser flag maps, **Safari has no
   such flag** (a silent no-op on a default-Safari Mac), and a silent fallback to the
   shared browser gives *false confidence on a security control*. A `CommandBrowser`
   either runs the chosen command or fails loudly. The opener logs its surface
   (`os-default` / `command` + program) to the Diagnostic Log so the active path is
   auditable; it never logs the URL (it carries the client_id + PKCE challenge).

4. **macOS native opener — structured, deferred.** The best macOS primitive is
   `ASWebAuthenticationSession` (ephemeral cookie store via
   `prefersEphemeralWebBrowserSession`; presents over the app with no second event
   loop, so it sidesteps Slint's main-thread ownership). It slots in behind `select`
   as a `#[cfg(target_os = "macos")]` strategy. It is **not** built here: it needs the
   `objc2-authentication-services` dependency and resolving two unknowns that require a
   real device, not a guess:
   - whether it will hand back an **http loopback** callback (it matches by scheme; AWS
     Identity Center registers `http://127.0.0.1/...`), or whether we keep the loopback
     and **cancel the session** when the code arrives;
   - marshalling the start onto Slint's main thread (`invoke_from_event_loop`) with the
     callback returned to the worker over a channel.

## Consequences

- **Shipped:** the `browser` component (port + `select`/`choose` + `DefaultBrowser` +
  `CommandBrowser` with the pure tested parse), the `Config.browser_command` field
  wired through `Authenticator::with_opener` in the GUI worker, and Diagnostic-Log
  surface logging. `Authenticator::new` keeps the OS default (the live-verify binaries
  and the live test are unchanged). Coverage holds; the workspace suite is green
  (+ the new `browser` tests).
- A user can isolate the portal cookie **today, with no new dependency**, by setting
  `browser_command` to a private/incognito launch (Chrome `--incognito`, Firefox
  `-private-window`, Edge `--inprivate`). Because Janitor already does a fresh Sign-in
  every launch (no token cache, ADR 0002), incognito costs no extra UX and leaves no
  cookie behind.
- **Deferred slices:** (a) the macOS `ASWebAuthenticationSession` strategy + its spike
  (the two unknowns above); (b) a Settings control — a presets dropdown (System
  default / Chrome incognito / Firefox private / Custom) writing `browser_command`,
  preferred over a raw text field for discoverability. Until then the field is set by
  editing `config.toml`.
- **Not isolating below the browser.** The OS browser's cookie jar remains the host's;
  `DefaultBrowser` users still share the portal session with the CLI. That is an
  accepted residual (the host browser is outside Janitor's control, THREAT-MODEL),
  now with an opt-in escape via `CommandBrowser`.
- **Security posture unchanged.** No secret is added to disk (a command string is not a
  Value); revealed Values stay in Rust zeroizing buffers + transient Slint state — the
  KMP path's GC-heap regression is avoided by *not* taking it.
- **Per-OS native isolation stays parked behind demand.** The component makes adding
  WebView2 (Windows) / WebKitGTK (Linux) strategies a localized change, but they carry
  real cost (Linux reintroduces a WebKitGTK runtime dependency) and are deferred until
  a distributed user needs in-app isolation there.

## Alternatives considered

- **Bundle the AWS CLI** — rejected: Janitor never calls the CLI; pure overhead.
- **Janitor-managed `~/.aws` (own SSO/cred cache)** — rejected: manufactures an
  on-disk SSO-token + role-cred cache, violating the nothing-secret-on-disk invariant
  (ADR 0002 / THREAT-MODEL).
- **Export Janitor's Session to a subshell** (env-var creds for `aws`) — rejected by
  the user: handing role creds to a shell bypasses the read-only / never-stomp engine,
  and the user does not want the Session shared outside Janitor.
- **Optimistic auto-incognito** (detect default browser, force incognito) — rejected:
  per-OS detection + per-browser flag maps, no Safari support, and silent fallback =
  false confidence on a security control. Presets are explicit and fail loudly.
- **Embedded webview via `wry`** (single cross-platform crate) — rejected as the
  default: Slint can't host an in-window webview and owns the event loop; macOS UI is
  main-thread-bound and wry has known macOS event-loop/focus issues; Linux needs a
  WebKitGTK runtime dependency (the "secondary program" the user wanted gone). Where a
  native opener *is* warranted, the per-OS primitive (ASWebAuthenticationSession) beats
  wry on macOS.
- **Rust-lib + KMP/Compose-Multiplatform frontend** — rejected: Compose-desktop is JVM
  on all three OSes, so native auth is *not* free on desktop (still a Kotlin/Native →
  `.dylib` → JNI shim per OS); it adds a JVM runtime and a bleeding-edge Rust↔Kotlin
  FFI; and it regresses the secret-in-memory posture (revealed Values in GC heap). KMP
  earns its keep only for a mobile target, which a masked secret-drift matrix is not.
