# GUI ↔ AWS bridge: a worker-threaded, lazily-authenticated real data source for the matrix

**Status:** accepted (design); not yet implemented

**Related:** ADR 0010 (the `janitor-aws` auth crate this consumes), ADR 0011
(guided sign-in / the real assembly path replayed here), ADR 0002 (memory-only
auth), ADR 0003 (core holds the logic; GUI is a thin view), ADR 0004 (read-only
v1), THREAT-MODEL.md. A new **ADR 0012** records the sync-core / async-worker
boundary decision; this spec is its design detail.

**Audience:** the next implementer. Assumes the ADRs above are read, plus a
reading of `janitor-aws/src/bin/live-verify.rs` (the existing real assembly) and
`janitor-gui/src/main.rs` (the current mock-fed shell).

## Goal (one sentence)

Feed the existing masked drift matrix with **real** AWS Secrets Manager data for
one already-configured Application at a time — signing in lazily through the
browser, off the UI thread — without pushing any auth/AWS/compare logic into the
GUI and without ever writing a secret to disk.

## Scope

**In.** The "minimal bridge": the matrix you see today, fed by real AWS for an
Application whose `Mapping`s already exist in `Config` (loaded from disk, or
entered via a minimal in-app editor). A worker thread owns the async runtime and
the auth session; the GUI talks to it over a channel. Lazy, explicit sign-in.
A `--mock` / `JANITOR_MOCK=1` path keeps the GUI runnable offline.

**Out (deferred to later slices).**
- **Discovery-driven column assembly** (browser `ListAccounts`/`ListAccountRoles`/
  `ListSecrets` to *build* an Application). This slice consumes pre-existing
  `Mapping`s only; the manual editor is the authoring path for now.
- **Per-column error rendering.** Partial fetch failure is a *whole-app* error
  this slice (see Decisions).
- **Any mutation** (read-only v1, ADR 0004).
- **Typed `GetSecretValue` error mapping** (a separate, already-tracked
  Milestone-B follow-up in `janitor-aws`).

## Decisions (the eight that shaped this)

1. **Slice width: minimal bridge first.** Real AWS feeds the existing matrix,
   one Application at a time. Discovery-driven assembly is a later slice.
2. **Async boundary: a worker thread + channels.** A dedicated `std::thread`
   owns a Tokio runtime *and* the auth session. The GUI sends `Command`s and
   receives `Event`s. `janitor-core` stays synchronous; async is confined to the
   GUI↔AWS seam. (A "sync adapter that `block_on`s on the UI thread" was
   rejected: it would freeze the window during the seconds-to-minutes browser
   sign-in.)
3. **Sign-in timing: lazy + explicit.** The app opens **signed-out** and fully
   browsable (sidebar, settings, the manual editor). A **Sign in** button — and
   any action needing auth — starts the browser. Matches "borrow credentials on
   demand."
4. **Authoring: load/save `config.toml` + a minimal Mapping editor.** The GUI
   reads `Config::load()` (replacing the hardcoded seed) and persists edits via
   `Config::save()`. The settings panel gains per-Environment fields
   (account / region / secret-id / permission-set), replacing the current
   placeholder `add_app` that hardcodes account `000000000000`.
5. **Terminology: "SSO start URL" (no rename).** AWS's own *Get credentials*
   dialog labels `https://identitycenter.amazonaws.com/ssoins-…` as **"SSO start
   URL"** (beside "SSO Region"). The `Config` field is already `sso_start_url`,
   so it matches AWS exactly — no new field, no migration. The only change is the
   visible GUI label `"Start URL"` → `"SSO start URL"`. The internal
   `Authenticator` arg stays `issuer_url` because that is the literal
   `aws-sdk-ssooidc` `RegisterClient` field name (`issuerUrl`) the value maps to;
   a code comment records the mapping.
   - **Watch-out (carried from Milestone B #1):** the value must be the
     **instance/issuer form** (`…/ssoins-…`) from the Get-credentials dialog, not
     the **portal form** (`https://<dir>.awsapps.com/start`) shown in the browser
     address bar — the portal form fails `RegisterClient` with *"Invalid start
     url provided."* The mock seed and an `authenticator.rs` doc comment currently
     use the misleading portal form as their example; this slice corrects those
     example strings (cosmetic on the mock path, which never calls AWS).
6. **Secret residency: secrets stay in the worker; reveal is an async
   round-trip.** Fetched `SecretShape`s live only in the worker. The UI holds the
   masked `MatrixView` + row keys. A cell click sends `Reveal` and gets one
   `Revealed{text}` back; the existing auto-hide timer clears it. Plaintext
   touches the UI thread only at that sanctioned moment (ADR 0003), never the
   whole set.
7. **Offline dev: mock behind a flag.** `JANITOR_MOCK=1` (or `--mock`) selects
   `MockSource` instead of the worker, so `cargo run -p janitor-gui` still works
   offline with no browser and the tracer-bullet stays runnable.
8. **Partial failure: whole-app error (minimal).** If *any* Environment fails to
   fetch, show one app-level error naming which Environments failed and why — no
   partial matrix. This never silently drops a column nor conflates a
   fetch-failure with a **Gap** (the high-signal finding). Per-column error
   rendering is a later slice.

## Architecture

Three crates keep their ADR-0003 roles. New behavior lands where it can be tested
against fakes, not in the GUI.

```
[Slint UI thread]                         [worker thread]
  AppState (selected, prefs,                Tokio runtime
   MatrixView, ui-state)                    Session {
        |                                     reauth, role_client,
        |  Command (std::sync::mpsc           secrets_api, clock,
        |   or tokio::mpsc)                    facade: Option<AuthenticatedSource>,
        v                                      cached: Vec<(String, SecretShape)>,  <-- secrets live HERE
   worker.send(Command) ------------------->  recv loop -> async Session call
        ^                                          |
        |  Event (Slint upgrade_in_event_loop)     | (core: Comparison::build + project
        +------------------------------------------+  run in the worker to make the
                                                       MASKED MatrixView that crosses back)
```

- **`janitor-core` — unchanged.** Stays sync. `Comparison::build`, `project`,
  `MatrixView`, `reveal_value`, `Config` load/save. The sync `SecretSource` seam
  is left as-is (its doc comment already anticipates this async seam; we satisfy
  it at the GUI↔AWS boundary rather than by making the trait async).
- **`janitor-aws` — gains a tested `Session` orchestrator** (below), behind the
  existing ADR-0010 §5 fake seam.
- **`janitor-gui` — gains plumbing only:** the worker thread, the Command/Event
  protocol, and `upgrade_in_event_loop` marshalling into the existing Slint
  model-mapping fns. No auth/AWS/compare logic (ADR 0003).

## Components

### `janitor-aws::Session` (new; the unit under test)

Lives in the worker thread; never crosses threads. Built from the *same*
`Arc<dyn …>` adapters `live-verify` builds, so it is unit-tested against the
existing `FakeReauth` / `FakeRoleClient` / `FakeSecretsApi`.

```rust
pub struct Session {
    reauth: Arc<dyn Reauth>,        // real = Authenticator; also handed to the facade for re-auth
    role_client: Arc<dyn RoleCredentialClient>,
    secrets_api: Arc<dyn SecretsApi>,
    clock: Arc<dyn Clock>,
    facade: Option<AuthenticatedSource>,   // None until first sign-in (lazy)
    cached: Vec<(String, SecretShape)>,    // current app's sets; replaced each load
}
```

- `ensure_signed_in() -> Result<(), SignInError>` — if `facade` is `None`:
  `reauth.sign_in()` for the **initial** token, then build `CredentialBroker` +
  `AuthenticatedSource` (live-verify lines ~199/234, **minus** discovery steps
  4–6). Reusing the `Reauth` seam for the initial token is what makes lazy
  sign-in fakeable.
- `load(app: &Application) -> Result<MatrixView, AppError>` — `ensure_signed_in`,
  then `facade.fetch(mapping)` for each Environment. **Any** failure → collect
  into `AppError { failures: Vec<(env_name, FetchFailReason)> }` (Decision 8).
  All succeed → store sets in `cached`, return `project(&Comparison::build(&sets))`
  — the masked view.
- `reveal(row_key: &str, col: usize) -> Option<String>` — `reveal_value(&cached,
  row_key, col)`; `None` if the key/col is gone (e.g. set replaced).

`AppError`/`FetchFailReason` are a small owned mapping over `SessionError`
(`AccessDenied | NotFound | NeedsSignIn | Throttled | Unsupported | Other`) — no
SDK text (THREAT-MODEL). Whether this enum lives in `janitor-aws` or a pure core
helper is an implementation detail; if any pure phrasing helper lands in
`janitor-core` it gets its own additive tests.

### `janitor-gui` worker + protocol (plumbing; untested shell)

```rust
enum Command { SignIn, LoadApp(Application), Reveal { row_key: String, col: usize }, Shutdown }

enum Event {
    SignInStarted, SignedIn, SignInFailed(String),
    AppLoading, AppLoaded(MatrixView), AppFailed(AppError),
    Revealed { row_key: String, col: usize, text: String }, RevealUnavailable,
}
```

- **Worker:** `std::thread::spawn`; inside, build a Tokio runtime and
  `rt.block_on` a receive loop over the `Command` channel; dispatch each to the
  async `Session`. Holds the only `Session`.
- **Worker → UI:** Slint's `Weak<MainWindow>` is `Send`; each `Event` is
  delivered via `weak.upgrade_in_event_loop(move |ui| …)` and rendered by the
  **existing** `to_row_models` / `env_models` / sort path. *(Exact
  `upgrade_in_event_loop` signature confirmed at implementation — it is Slint's
  canonical UI-thread marshalling call.)*
- **All payloads are `Send`.** Verify-at-impl: `SecretShape`/`Value` are `Send`
  (zeroizing types normally are) so they can live in the worker — confirmed, not
  assumed.

### Sidebar drift-count fix (correctness, not cosmetic)

Today `app_models` re-fetches **every** Application on **every** render to compute
drift badges — instant on the mock, but N sign-ins + a `GetSecretValue` storm
against real AWS. Fix: only the **selected** Application is fetched (lazily);
drift badges render only for Applications already loaded this session, blank
otherwise.

## UI state machine (per the selected app)

```
Unauthenticated ──SignIn──▶ SigningIn ──SignedIn──▶ Idle
     │                          │                     │
 matrix area:               SignInFailed         LoadApp(selected)
 "Sign in to load"          → banner; back            ▼
 (+ Sign in button)           to Unauth         AppLoading (spinner)
                                                 ▼            ▼
                                           AppLoaded      AppFailed
                                           (matrix)       (banner: envs + why)
```

- Opens **Unauthenticated**; sidebar/settings/editor usable. Selecting an app
  while unauthenticated just records the selection.
- The **Sign in** button (or a Refresh) drives `SigningIn`; the button disables
  while the browser is open (the browser is the modal).
- `ReauthRequired` **mid-session** is normally invisible: the facade's tested
  ladder silently re-signs-in once. Only a *failed* re-sign-in bubbles up (→
  "session expired — sign in again" → `Unauthenticated`).

## Error handling (taxonomy → plain banners; no raw SDK text)

| Source | Banner | Next state |
|---|---|---|
| `SignInError::*` | "Sign-in failed: <short reason>" | Unauthenticated |
| `SessionError::AccessDenied` (per env) | "<env>: access denied" | AppFailed |
| `SessionError::NotFound` (per env) | "<env>: secret not found" | AppFailed |
| `SessionError::ReauthRequired` (survives the facade retry) | "session expired — sign in again" | Unauthenticated |
| `SessionError::Throttled` | "<env>: throttled, try again" | AppFailed |
| `SessionError::Unsupported` | "<env>: unsupported secret content" | AppFailed |
| `SessionError::Sdk{context}` | "<env>: AWS error (<context>)" | AppFailed |

## Secret & disk discipline (invariants)

- `SecretShape`s live only in the worker's `cached`, replaced each `LoadApp`
  (old sets dropped → zeroized). Never serialized, never logged, never in an
  `Event` except the single user-requested `Revealed{text}`.
- `Config` save (settings + manual editor) writes **locations only** — unchanged.
- Read-only throughout (ADR 0004); no mutating call is reachable.

## Testing

- **`janitor-aws::Session`** (new logic, existing fakes): lazy sign-in happens
  **once** and is reused; initial-sign-in failure surfaces as `SignInError`;
  multi-env all-success returns sets in Environment order; **one env fails →
  whole-app `AppError` naming it** (Decision 8); `reveal` returns plaintext for a
  cached key and `None` after the set is replaced. Keeps `janitor-aws` at/above
  its current test bar.
- **`janitor-core`:** logic untouched; only *additive* tests if a pure helper
  (e.g. error→banner phrasing) lands there. **No existing assertion changes.**
  Per the project rule, if any existing test's covered behavior *would* change,
  stop and surface it before editing.
- **`janitor-gui`:** stays integration-tested-by-hand (thin shell). The worker
  marshalling/threading is untested I/O shell, consistent with ADR 0010 §5. The
  `--mock` path keeps it offline-runnable for UI work.
- **Coverage gate** (core-only, ≥80%) is unaffected.

## Risks & verify-at-implementation

- **`Send` of secret types** — confirm `SecretShape`/`Value` are `Send` before
  relying on worker residency. (Expected yes.)
- **`upgrade_in_event_loop` signature/semantics** — confirm against the Slint
  version in `Cargo.lock`; it is the canonical pattern but the exact closure/
  return shape is version-specific.
- **Channel choice** — `std::sync::mpsc` (UI→worker) is simplest; the worker's
  internal loop may prefer `tokio::mpsc` since it runs inside `block_on`. Decide
  at impl; both are `Send`.
- **First-run with empty Config** — opens Unauthenticated with no Applications;
  the manual editor is the path to the first Application. Document the
  instance-form SSO start URL in the field hint/help.
- **Live re-verification is human-gated** (browser + a real org). The pure
  `Session` logic is CI-tested; the end-to-end path is verified by hand, like
  `live-verify`.

## Out-of-scope cleanups intentionally included

- Relabel GUI field "Start URL" → "SSO start URL" (Decision 5).
- Correct the misleading **portal-form** example URLs in the mock seed and the
  `authenticator.rs` doc comment to the **instance form**.
- Replace the placeholder `add_app` (hardcoded account) with the real
  per-Environment Mapping editor (Decision 4).
