# SwiftUI shell over the Rust core — research

Date: 2026-08-20. Status: research input for an ADR. Not a decision record.

Consolidates five research passes: the `janitor-gui` inventory, the Rust API
surface, the Rust↔Swift FFI evaluation, an empirical App Sandbox probe, and the
App Store Connect CI path. Two passes were adversarially verified and failed
verification. Where that happened this document carries the correction, not the
original claim, and says so.

---

## 1. What is being built

`janitor-gui` is replaced by a native SwiftUI macOS shell over the existing Rust
core. Slint drops out, and with it the GPL obligation that blocks the Mac App
Store. Every non-GUI crate stays. `janitor-core`, `janitor-aws`,
`janitor-aws-auth`, `janitor-ssm`, and `janitor-mock` contain no Slint
dependency, so the auth ladder, the Provider port, the comparison engine, the
two AWS Methods, and the write engines are reused without change. The view is a
rewrite: 1,524 lines of Slint in `janitor-gui/ui/app.slint` plus roughly 2,000
lines of Slint-coupled Rust glue in `main.rs` and `worker.rs`.

The seam a Swift shell consumes is the worker's message protocol, not the
Provider trait. `core::provider::Provider` is `!Sync`, six of its seven methods
take `&mut self`, and every method except `reveal` is `async` — none of that
survives a C ABI. The worker already reduces all of it to a `Send` command
channel plus a `Send + 'static` event callback: 12 `Command` variants in,
23 `Event` variants out, over `std::sync::mpsc`, with a `Box<dyn Provider>`
owned exclusively by one thread running a current-thread Tokio runtime. That is
the FFI line. The work is to lift `worker.rs` and the portable pure seams out of
the bin-only `janitor-gui` crate into a library, wrap it in UniFFI, and
re-author the two windows in SwiftUI.

---

## 2. The GUI surface to be replaced

`janitor-gui` totals 7,403 lines: 5,661 Rust across 11 modules, 1,524 Slint,
199 in `examples/snapshot.rs`, 19 in `build.rs`. Roughly 2,865 Rust lines are
production code. The crate has **no `src/lib.rs`** — every module is a bin-local
`mod` and is unreachable from any other crate today
(`janitor-gui/src/main.rs:8-18`).

### Rust modules

| Module | Lines (total / prod) | Tests | What it is | Disposition |
|---|---|---|---|---|
| `main.rs` | 1,630 / 1,506 | — | Composition root, callback wiring, both windows' push functions, `AppState`, `apply_event` reducer | Split: reducer and Config flows re-author in Swift; guards move to Rust |
| `worker.rs` | 1,193 / 508 | 17 | Async bridge, `Command`/`Event`, `run_loop`, `build_family`, read-write lock | **Move to a library crate verbatim** |
| `view_tests.rs` | 1,193 | 26 | ADR 0021 view tests, bound to the Slint headless backend | Dies with the port |
| `rows.rs` | 391 / 142 | 11 | Matrix item list assembly, prefix grouping | Move to library or core |
| `update.rs` | 284 / 221 | 8 | Windows-only MSIX self-update via WinRT; stub elsewhere | Keep only if Windows ships from this tree |
| `logpane.rs` | 243 / 204 | 3 | 1,000-line ring buffer, `tracing` layer for `janitor*` targets, panic hook, filter level | Move to library |
| `scrollbar.rs` | 188 / 75 | 9 | Horizontal scrollbar geometry | **Delete** — native scroll views replace it |
| `sidebar.rs` | 182 / 75 | 6 | Sidebar rows, drift-badge suppression rule | Move to library |
| `pane.rs` | 170 / 86 | 8 | Which main pane to show | Move to library |
| `reveal.rs` | 108 / 27 | 6 | The "exactly one cell un-masks" predicate | **Move to library — security rule** |
| `errors.rs` | 79 / 21 | 4 | Error banner string | Move to library |

102 tests total. 26 die with Slint.

### Slint view — one file, two windows

`janitor-gui/ui/app.slint`, 1,524 lines. Two top-level `Window` components:
`MainWindow` at line 61 and `ManageWindow` at line 1364. Global Settings is not
a window — it is a dimmed backdrop plus a ~540px centered card inside
`MainWindow`, gated on `settings-open` (`:1176`, card at `:1199`). The Discovery
wizard is not a window either — three mutually exclusive conditional sections
inside `ManageWindow` (`:1474` status/terminal, `:1490` choice picker, `:1502`
free-text input).

| Region | Slint line | Notes for the SwiftUI shell |
|---|---|---|
| Sidebar (Applications, new-app field, `+`) | `:253` | Backed by `sidebar::SidebarApp` → `[AppItem]` |
| Top bar (badge, identity, breadcrumb, buttons) | `:301` | Three properties here are dead — see below |
| Error / signing status banner | `:365` | String from `errors.rs` |
| Main header (title, snapshot stamp, ARN subtitle) | `:406` | Snapshot label re-renders on a 30s timer |
| Group-by-prefix switch | `:440` | |
| Matrix header band | `:456` | Scrolls in lockstep with the body |
| Matrix body | `:573` | Freeze-pane, see below |
| Sticky group-header overlay | `:869-919` | Computed from `headers-before`/`rows-before` |
| Horizontal env scrollbar | `:938` | Hand-rolled; toggles by height, not `if`, to avoid a binding loop (`:930-937`) |
| Empty-apps / body-copy panes | `:1035`, `:1045` | |
| Diagnostic Log strip and panel | `:1056` | Polled every 400ms |
| Status bar with Aligned/Drift/Gap legend | `:1140` | |

The matrix is a freeze-pane: a fixed 46px STATE glyph column (`:231`) and a
resizable ENTRY column defaulting to 300px with a 200px floor (`:227-228`),
frozen at left, with env columns in a non-interactive `Flickable` (`:688`).
Column sizing uses a binding-loop-safe `available`/`col-w`/`envs-w` chain
(`:386-404`) and two clip-wrapper shields to stop max-width propagation
(`:534-546`). Roughly 400 lines of the Slint file exist to work around layout
limits that AppKit and SwiftUI solve natively.

### View-model surface

Four Slint structs carry the whole view model: `CellView` (4 fields, `:3`),
`MatrixItemView` (13 fields, `:12`), `AppItem` (4 fields, `:35`), `EnvRow`
(6 fields, `:42`). One global `Palette` with a `dot-color(state)` function
(`:55`). `MainWindow` exposes 46 properties and 25 callbacks; `ManageWindow`
exposes 10 and 8.

Five `MainWindow` callbacks are `pure` predicates whose handlers are tested Rust
functions called synchronously from inside the bindings: `is-cell-revealed` →
`reveal::is_revealed` (`main.rs:1160`), and the five `sb-*` callbacks →
`scrollbar::*` (`main.rs:1166-1170`).

### Behavior that lives in the GUI crate today

- **`apply_event`** (`main.rs:366-556`, ~190 lines) is a hand-written reducer.
  It holds a stale-load guard that drops an `AppLoaded` whose `app_name` no
  longer matches the selection (`:414-421`), a reveal race guard that drops a
  Value arriving after the press was released (`:425-431`), the ADR 0018
  corrections fold (`:424`), clipboard routing (`:453-467`), and audit-log line
  construction.
- **Config persistence policy** — `AppState::maybe_save` skips saving whenever
  `ProviderKind::Mock` is active, so seeded demo data cannot overwrite a real
  org's config (`main.rs:346-355`).
- **Config mutation flows** — `on_env_discovered` appends a `Mapping` to the
  bound (not selected) Application, sets `last_pick`, saves, refreshes, and
  conditionally reloads (`main.rs:563-594`); `fold_corrections` (`:604-624`);
  `rename_bound_app` (`:763-775`); `remove_bound_env` (`:780-791`).
- **Discovery wizard glue** — six functions pushing mutually exclusive states
  into the Manage window: `set_manage_status` (`:794`), `set_manage_terminal`
  (`:817`), `set_manage_choice` (`:829`, which also owns the `What` → prompt
  mapping), `set_manage_input` (`:841`), `clear_manage_choice` (`:865`),
  `refresh_manage_window` (`:880`).
- **The AWS composition root** — `worker::build_family`
  (`worker.rs:252-294`) constructs `AwsOidcClient`, `AwsRoleClient`,
  `SystemClock`, `Authenticator::with_opener` with the ADR 0033 browser
  selector, `SecretsManagerMethod`, `SsmDotenvMethod`, and the
  `BTreeMap<Method, Arc<dyn ResourceMethod>>` registry.
- **The read-write lock** — `run_loop` holds `let mut read_write = false`
  (`worker.rs:371`) and refuses `ApplyEdits` with `Event::WriteRefused` before
  any Provider call (`:464-472`). This is a worker invariant, not a UI
  affordance.
- **Clipboard** — one process-long `arboard` handle in a `thread_local`
  (`main.rs:59-64`), because X11 and Wayland serve the selection from the
  owning process. Entry names copy directly; Values require a worker round-trip.
- **Reveal** — press-and-hold. Pointer-down fires `reveal-cell`; pointer-up or
  cancel calls `hide-cell` and zeroes `revealed-row`/`col`/`text` inline
  (`app.slint:843-865`). No timeout auto-hide.
- **Three thread-locals** carry cross-window state because the worker's callback
  must be `Send` while `Rc` is not: `STATE`, `MANAGE`, `MAIN`, plus `CLIPBOARD`
  (`main.rs:48-64`).
- **Two timers** — the Diagnostic Log polls into the panel every 400ms
  (`main.rs:1447-1473`); the snapshot label re-renders every 30s (`:1480-1497`).

### Gaps and dead code

- `Command::ApplyEdits` is `#[allow(dead_code)]` with no producer
  (`worker.rs:78`). The cell-edit affordance and confirm-diff dialog are not
  built; the context menus show Edit / View history / Delete as
  `enabled: false` (`app.slint:661-663`, `:787-789`).
- Three `MainWindow` chrome properties are declared but never pushed from
  production Rust: `read-only` (hardcoded `true`), `identity`, and
  `session-remaining` (`app.slint:193-195`). Only `view_tests.rs:599` sets them.
  A literal port would reproduce a read-only badge that does not reflect the
  worker's actual lock state.
- No keyboard handling and no menu bar. `app.slint` contains no `FocusScope`,
  no key-pressed handler, and no shortcut.
- `main()` forces `SLINT_BACKEND=winit-software` unless overridden, because the
  femtovg GPU path needs OpenGL 2.0 that RDP and VM sessions lack
  (`main.rs:1031-1035`). No SwiftUI equivalent.
- The offline mock is a runtime switch: `JANITOR_MOCK` or `--mock` selects
  `ProviderKind::Mock` and `janitor_mock::seeded_config()`; otherwise
  `ProviderKind::Aws` and `Config::load()` (`main.rs:1042-1055`).

### Net-new work the current shell does not have

A real macOS menu bar. Keyboard navigation. App Sandbox entitlements.
Replacement tests for the 26 Slint view tests. An `NSPasteboard` bridge with the
concealed and transient types (see section 5).

**Accessibility is already decided: a revealed Value is exposed to VoiceOver.**
macOS gates third-party accessibility access behind an explicit TCC grant, and
hiding the reveal would make the feature unusable for blind operators. The
matrix cells get proper accessibility labels, and the revealed cell reads its
plaintext. This matches `THREAT-MODEL.md`, which already lists accessibility
APIs under trust boundary 3 (the host OS and display surface) as something
Janitor cannot defend below, and records the display side-channel as an explicit
non-goal.

---

## 3. The Rust seam

### The Provider port

`janitor-core/src/provider.rs:170` declares `pub trait Provider: Send` — bounded
`Send` only, never `Sync`. Object safety is pinned by a test (`:307-311`).

| Method | Signature | Line |
|---|---|---|
| `sign_in` | `async fn sign_in(&mut self) -> Result<(), SignInFailed>` | `:173` |
| `load` | `async fn load(&mut self, app: &Application) -> Result<Loaded, AppError>` | `:178` |
| `reveal` | `fn reveal(&self, key: &RowKey, col: usize) -> Option<String>` | `:183` |
| `begin_discovery` | `async fn begin_discovery(&mut self, method, environment, region, remembered) -> Result<Step, SignInFailed>` | `:191-197` |
| `advance_discovery` | `async fn advance_discovery(&mut self, choice: usize) -> Option<Step>` | `:201` |
| `provide_input` | `async fn provide_input(&mut self, text: String) -> Option<Step>` | `:207` |
| `take_advisories` | `async fn take_advisories(&mut self) -> Vec<String>` (defaulted) | `:217-219` |
| `write` | `async fn write(&mut self, mapping, edits) -> Result<WriteOutcome, Failure>` (defaulted to masked `Unsupported`) | `:235-245` |

`reveal` is the only non-async method and the only one taking `&self`. A
compile probe confirmed `Box<dyn Provider>` is **`Send` but not `Sync`** —
rustc rejects `sy::<Box<dyn Provider>>()` with E0277. Combined with the six
`&mut self` methods, exclusive single-thread ownership is structurally
required. A `Mutex` is not sufficient: it would still let a second caller start
a `load` while one is mid-await.

Two impls exist: `AwsFamilyProvider` (`janitor-aws-auth/src/family.rs:393`) and
`MockProvider` (`janitor-mock/src/provider.rs:42`).

`load` fails whole-Application on any single Environment failure — never a
partial matrix (`family.rs:501-503`).

### The worker

`janitor-gui/src/worker.rs:210` — `pub fn spawn(kind, config, on_event: impl
Fn(Event) + Send + 'static) -> Sender<Command>`. It creates a
`std::sync::mpsc::channel::<Command>()`, spawns an OS thread, builds a
`tokio::runtime::Builder::new_current_thread().enable_all()` runtime, and calls
`rt.block_on` (`:215-225`). The Provider is constructed inside that runtime
because AWS SDK client construction is async (`:222`, `:232-237`). The command
loop uses a blocking `rx.recv()` inside the async body (`:373`), which is legal
only because the thread runs nothing else.

The runtime has no Tokio worker threads, but `enable_all()` plus the AWS SDK and
hyper stack still uses the blocking pool for DNS and similar. The load-bearing
property is that the runtime is driven by `rt.block_on` on Janitor's own thread
and never by a foreign executor.

After every command that touched the Provider, `surface_advisories` relays
`take_advisories()` to both `tracing::warn!` and `Event::Warning`
(`:356-361`, `:505`).

### Types that cross, and which carry secret material

**Three of the 35 `Command`/`Event` variants carry secret material.**

| Type | Secret? | Definition |
|---|---|---|
| `Command::ApplyEdits { mapping, edits: Vec<EnvEdit> }` | **YES** — `EnvEdit::Set` holds `Zeroizing<String>` | `worker.rs:79-82`, `core/src/write.rs:40-45` |
| `Event::Revealed { row, col, text: String }` | **YES** — plaintext, non-zeroizing | `worker.rs:111-115` |
| `Event::CopyValue { row, col, text: String }` | **YES** — plaintext, non-zeroizing | `worker.rs:119-123` |
| `MatrixView` / `MatrixRow` / `MatrixCell` | No — masked by construction | `core/src/view.rs:11-45` |
| `Loaded { view, corrected }` | No | `core/src/provider.rs:105-109` |
| `Step` (`Ask`/`Input`/`Done`/`Empty`/`Failed`/`Reauth`) | No — labels are locations | `core/src/provider.rs:141-160` |
| `What` (`Accounts`/`Roles`/`Secrets`/`Instances`/`FilePath`) | No | `core/src/provider.rs:118-125` |
| `Failure { environment, reason, detail }` | No — `detail` is pre-masked | `core/src/provider.rs:74-79` |
| `AppError { failures: Vec<Failure> }` | No | `core/src/provider.rs:83-86` |
| `FetchFailReason` (6-variant `Copy`) | No — `describe()` returns fixed phrases | `core/src/provider.rs:40-68` |
| `SignInFailed(String)` | No — pre-masked, private field | `core/src/provider.rs:26-35` |
| `WriteOutcome` (`Applied`/`Conflict`, `Copy`) | No | `core/src/write.rs:25-32` |
| `EditSummary { key, action, value_len }` | No — key and length only | `core/src/write.rs:116-147` |
| `Mapping` / `Application` / `Method` / `Config` | No — locations only | `core/src/config/mod.rs:126-154` |
| `RowKey` (an `EntryName`) | No — a name, not a Value | `core/src/secret/name.rs:17-33` |

`MatrixCell` is `Present { len, group: u32, hex, kind } | Absent`. The module
doc states it carries no secret Values (`view.rs:1-4`).

**`SecretShape` never crosses the port.** It is
`Json(BTreeMap<EntryName, Value>) | Raw(Value) | Binary(SecretBytes)`
(`core/src/secret/shape.rs:51-60`), derives only `Debug`, and stays in the
Provider's `cached` field (`family.rs:139`, `:505`). `RawSecret` is
`#[derive(ZeroizeOnDrop)]` and lives entirely below the port
(`aws-auth/src/wire.rs:79-83`).

### The one plaintext crossing

`Provider::reveal` returns a plain `String`, not a `Zeroizing<String>`. Both
real implementations are verbatim
`reveal_value(&self.cached, key, col).map(|v| v.expose().to_string())`
(`family.rs:514`, `janitor-mock/src/provider.rs:66`). The plaintext leaves the
zeroizing `Value` as an ordinary heap allocation. The worker forwards it
unchanged (`worker.rs:419-421`, `:428-430`).

This is not a regression introduced by the port — the same copy exists inside
Slint's `SharedString` today. The FFI is the moment to close it or accept it
explicitly.

### Secret-handling invariants and where they are enforced

Secret material is held in exactly three wrapper kinds: `secrecy::SecretString`
(`Value.content`, `SsoToken.access_token`, `Credential`'s three fields),
`secrecy::SecretBox<[u8]>` (`SecretBytes`), and `zeroize::Zeroizing` /
`ZeroizeOnDrop` (`EnvEdit.value`, `RawSecret`, the Secrets Manager merged blob,
the SSM file text).

The "no Value in `Debug`" rule is enforced by hand-written impls, each with a
paired test asserting the plaintext does not appear: `Value`
(`value.rs:58-65` / `:86-100`), `EnvEdit` (`write.rs:76-87` / `:160-171`),
`Cell` (`compare/model.rs:80-96` / `:131-164`), `SecretShape`
(`shape.rs:150-165`), `SecretBytes` (`shape.rs:41-48`), `SsoToken` and
`Credential` (`aws-auth/src/types.rs:32-38`, `:84-90` / `:110-123`).
`EntryName` deliberately prints — names are metadata.

The "no SDK text in a `Failure`" rule is enforced at one place:
`impl From<&SessionError> for FetchFailReason` and `impl From<SignInError> for
SignInFailed` (`aws-auth/src/error.rs:73-99`, `:111-127`), with tests asserting
a planted `hunter2` never reaches `describe()` (`:185-187`).

### Serialization state

`Config`, `Application`, `Mapping`, and `Method` are the **only** serde-derived
types in `janitor-core` (`config/mod.rs:9,12,48,123,135,170`). No port DTO
derives `Serialize` or `Deserialize`. `Step` derives only `Debug` — no `Clone`,
no `PartialEq`. `EnvEdit` derives no `Clone`.

No crate declares a `cdylib` or `staticlib` crate-type. There is no existing FFI
boundary to extend.

### macOS pieces already in Rust

`WebAuthSessionBrowser` drives `ASWebAuthenticationSession` with
`prefersEphemeralWebBrowserSession`, selected by the `"@native"` sentinel in
`Config.browser_command` (`aws-auth/src/browser/web_auth_session.rs:1-31`,
`:62-84`; `browser/mod.rs:37-42`, `:109-116`). `open` is called on the worker
thread, hops to `DispatchQueue::main()`, and blocks the worker up to a 20-second
`CREATE_TIMEOUT` waiting for the main thread to create the session (`:17-30`,
`:55-58`, `:71-84`). It asserts `MainThreadMarker::new()` and requires a live
main-thread run loop. The comment at `:18-19` still says Slint owns the
`NSApplication` and needs updating.

`janitor-aws-auth/Cargo.toml:37-43` target-gates `objc2`, `block2`, `dispatch2`,
and `objc2-authentication-services` on `cfg(target_os = "macos")`.

---

## 4. The FFI recommendation

**Choose UniFFI. Put the boundary at the worker's `Command`/`Event` protocol.
Export zero `async fn` across it.**

The FFI evaluation failed adversarial verification on four points. The
comparative conclusion survived intact; the errors are in supporting detail and
the code sketch. Corrections are folded in below.

### Why UniFFI

UniFFI is the only candidate that makes "copy the secret out, never lend a
pointer" a compiler rule rather than a review rule. It has no Rust→foreign
borrow type. `&[u8]` is documented as flowing foreign→Rust only: it cannot be
returned, used in a callback result, or used as a trait-method return value.
Foreign-trait methods cannot take references at all, so every event payload is
by value.

The `&T` → `[ByRef] T` row in the builtin type table carries **no** documented
direction constraint. The one-way rule is documented only for `&[u8]`. The
conclusion still holds — a `&T` return needs a lifetime UniFFI cannot express,
and `[ByRef]` is a WebIDL argument attribute — but it is an inference, not a
documented guarantee.

Janitor's Rust side is already a command/event loop, so the FFI mirrors a shape
that exists rather than inventing a request/response API that would force Tokio
to be driven by Swift's executor.

### Why not the others

**swift-bridge** — disqualified by the borrow constraint. Its built-in type set
includes `&str ↔ RustStr`, a Rust→Swift pointer plus length. Its own Safety
chapter demonstrates a use-after-free (`let name: RustStr = someType.name();
someType.drop(); name.toString()`) and states "It isn't possible for
`swift-bridge` to mitigate this". Handing Swift a `RustStr` into a
`SecretString` that Rust later zeroes is one keyword away in every signature.
Secondary: dormant since 2026-01-06 (v0.1.59, 92 open issues plus 9 open PRs).

**cxx / Swift C++ interop** — two generators in series, and the seam does not
hold. Swift does not import C++ class templates; only instantiated
specializations reachable through a typedef. In `cxx.h`, `Slice<T>`
(`:185-186`), `Box<T>` (`:290-291`), and `Vec<T>` (`:339-340`) are exactly class
templates. `rust::String` (`:44`) and `rust::Str` (`:120`) are plain classes, so
the objection lands on the container vocabulary types, not on `rust::String`.

**cbindgen plus a hand-rolled C ABI** — the honest fallback if the isolation
issue below proves unworkable. cbindgen emits headers, never marshalling. 12
commands and 23 events with a `MatrixView` nested three levels deep become
hundreds of lines of hand-written unsafe lower and lift, and the borrow rule
degrades to a code-review rule. Record it as Plan B.

### License posture of the candidates

`uniffi` is MPL-2.0 (file-level copyleft, build-time codegen plus a small
runtime crate). `cbindgen` is MPL-2.0. `swift-bridge` is Apache-2.0 / MIT.
`cxx` is MIT / Apache-2.0. None imposes Slint's whole-program GPL obligation.

### Shape of the port

1. New crate `janitor-ffi`, `crate-type = ["staticlib"]`, with
   `uniffi::setup_scaffolding!()`. It depends on core, aws, aws-auth, ssm, and
   mock, and absorbs today's `worker.rs` wholesale — `Command`, `Event`,
   `run_loop`, `build_provider`, `build_family`, `discovery_event`,
   `write_event`, `surface_advisories` — plus `reveal.rs`'s `is_revealed`.
2. `janitor-core` stays untouched. Mirror `Application`
   (`config/mod.rs:49`), `Mapping` (`:136`), `Method` (`:126`), `EntryState`
   (`compare/model.rs:35`), `LeafKind` (`secret/value.rs:8`), `FetchFailReason`
   (`provider.rs:41`), and `Failure` (`provider.rs:75`) with
   `#[uniffi::remote(Record)]` / `#[uniffi::remote(Enum)]` — all have public
   fields or variants.
3. **`SignInFailed` cannot use `#[uniffi::remote(Record)]`.** It is
   `pub struct SignInFailed(String)` with a **private** field
   (`provider.rs:28`); a mirror in another crate cannot reach it. Use the remote
   custom-type path instead, going through the public `SignInFailed::new`
   (`provider.rs:32`) and the `thiserror` `#[error("{0}")]` Display
   (`provider.rs:26-27`):

   ```rust
   uniffi::custom_type!(SignInFailed, String, {
       remote,
       lower: |e| e.to_string(),
       try_lift: |s| Ok(SignInFailed::new(s)),
   });
   ```

   It is also the `Err` half of `sign_in` and `begin_discovery`, so
   `uniffi::Error` semantics may be wanted rather than a Record.
4. **`usize` is not a UniFFI builtin.** `MatrixCell::Present { len: usize }`
   (`view.rs:38`) and the two `len: usize` fields in `compare/model.rs:52,59`
   need a hand-written FFI DTO with a `From` conversion to `u64`.
5. **Do not send `RowKey`/`EntryName` to Swift.** Swift cannot construct one —
   `EntryName` has only `from_path(&[String])` and `segments()`
   (`secret/name.rs:17-33`). Swift addresses cells by `(row, col)` and the
   worker resolves the key.

   **This requires new worker state.** The worker does *not* hold the last
   `MatrixView` today: `run_loop`'s only local state is
   `let mut read_write = false` (`worker.rs:363-372`), and the `LoadApp` arm
   moves the view straight out into `Event::AppLoaded` (`:394-408`). Add
   `let mut last_view: Option<MatrixView>` and clone before the send —
   `MatrixView` does derive `Clone` (`view.rs:10`). Cheap, but it means the
   worker starts holding a whole matrix it previously did not.
6. Move the reducer guards down into `run_loop`: the stale-load guard, the ADR
   0018 `corrected` Config write, and the auto-`LoadApp`-after-`SignedIn`. Swift
   then only maps events onto `@Observable` state.

### The event sink

**The trait method must return a `Result`.** UniFFI's foreign-traits
documentation states that all methods of a Rust trait exposed to foreign code
should return a `Result` with a compatible error type, "otherwise these errors
will panic", and that a missing `From<uniffi::UnexpectedUniFFICallbackError>`
impl makes the generated code panic. The sink is called from inside `run_loop`
on the worker thread, so a panic there kills the worker silently.

```rust
// janitor-ffi/src/lib.rs
#[uniffi::export(foreign)]
pub trait EventSink: Send + Sync {
    // By value — foreign trait methods cannot take references.
    // Result, not () — a foreign-side failure otherwise panics the worker.
    fn on_event(&self, event: JanitorEvent) -> Result<(), EventSinkError>;
}

impl From<uniffi::UnexpectedUniFFICallbackError> for EventSinkError { /* … */ }

#[derive(uniffi::Object)]
pub struct JanitorEngine { tx: std::sync::mpsc::Sender<Command> }

#[uniffi::export]
impl JanitorEngine {
    #[uniffi::constructor]
    pub fn new(kind: ProviderKind, sink: Arc<dyn EventSink>) -> Arc<Self> {
        // Identical to worker::spawn — thread + current_thread runtime + run_loop,
        // except `on_event(ev)` becomes `let _ = sink.on_event(ev.into());`.
    }
    // Every method returns immediately. Tokio stays inside the worker thread.
    pub fn sign_in(&self)                    { let _ = self.tx.send(Command::SignIn); }
    pub fn load_app(&self, index: u32)       { /* … */ }
    pub fn reveal(&self, row: u32, col: u32) { /* fire-and-forget */ }
    pub fn end_reveal(&self)                 { /* … */ }
    pub fn set_read_write(&self, on: bool)   { /* … */ }
    pub fn shutdown(&self)                   { /* … */ }
}
```

```swift
// Generated bindings live in their own nonisolated module.
final class StreamSink: EventSink, @unchecked Sendable {
    let continuation: AsyncStream<JanitorEvent>.Continuation
    func onEvent(event: JanitorEvent) throws { continuation.yield(event) }
}

@Observable @MainActor final class JanitorModel {
    private let core: JanitorEngine
    init() {
        var c: AsyncStream<JanitorEvent>.Continuation!
        let stream = AsyncStream<JanitorEvent> { c = $0 }
        core = JanitorEngine(kind: .aws, sink: StreamSink(continuation: c))
        Task { for await ev in stream { apply(ev) } }   // the single hop to MainActor
    }
}
```

### The reveal round-trip

1. Press on cell `(r, c)` → `core.reveal(row: r, col: c)`, returns instantly.
2. Worker resolves the `RowKey` from its own cached view, calls
   `provider.reveal(&key, col)`. The returned `String` is already a copy out of
   `SecretString` (`family.rs:514`).
3. `sink.on_event(.revealed(row:col:text:))`. UniFFI lowers `text` into a
   `RustBuffer`; Swift lifts it into a Swift `String` and calls the generated
   free. Swift is never handed a pointer into the zeroizing buffer.
4. Swift stores `revealed: (row, col, text)?` on the `@MainActor` model, gated
   by `is_revealed` exported from `janitor-ffi` so the "exactly one cell
   un-masks" rule stays tested Rust.
5. Release → `revealed = nil` and `core.end_reveal()`.

Declare step 3's payload as a UniFFI custom type bridged over `String` with an
explicit `lower` closure, so the project's single plaintext crossing is one
greppable symbol.

### The trade-off, stated plainly

UniFFI's weakest area is exactly the toolchain in play. Two issues are open
against it:

- **#2818** — under Xcode 26's `SWIFT_DEFAULT_ACTOR_ISOLATION=MainActor` the
  generated bindings inherit `@MainActor` and fail to compile (raw pointers,
  deinits, synchronous C interop). The documented workaround is a `sed`
  post-processing step. A proposed `[bindings.swift] default_isolation` option
  is neither in the 0.32 config table nor in the changelog; the single
  maintainer comment is "I think we'd be fine with this".
- **#2448** — async-generated Swift does not conform to `Sendable`.

The recommendation buys out of both. Put the generated Swift in its own module
compiled with `.defaultIsolation(nil)` (SwiftPM 6.2+; the only valid arguments
are `MainActor.self` and `nil`) or `SWIFT_DEFAULT_ACTOR_ISOLATION=nonisolated`
in Xcode. Export no `async fn` at all.

The price: Swift never gets an idiomatic `try await engine.load(app)`. It gets a
fire-and-forget call plus an `AsyncStream` of events.

UniFFI has no cancellation. Janitor already models teardown as
`Command::Shutdown` (`worker.rs:31`), so this costs nothing.

UniFFI's Swift bindings link as a static library:
`uniffi-bindgen-swift` takes the `.a` path directly and emits `--swift-sources`,
`--headers`, and `--modulemap`, with an `--xcframework` variant. All generated
`.swift` files must be compiled together in a single module, because the
generated code accesses external types without importing them. That constrains
any later split into multiple UniFFI'd crates.

### Local toolchain

Swift 6.3.3, target `arm64-apple-macosx26.0`, Xcode 26.6 (17F113).
`rustup target list --installed` already includes `x86_64-apple-darwin`.

---

## 5. App Sandbox: what breaks and the fix

Measured empirically against the real sandbox on macOS 26.5.2 (build 25F84)
using ad-hoc-signed `.app` bundles, then independently reproduced. This pass
failed adversarial verification on one material point (the clipboard) and
overstated four inferences as measurements. Both are corrected below.

> **Incident during this research.** The first sandbox probe wrote a test file
> to the hard-coded production Config path before it was parameterized. It
> overwrote `~/Library/Application Support/com.Janitor.Janitor/config.toml`
> (which existed, dated Jun 21 18:41) with the single line
> `sso_start_url="x"`. There are no Time Machine local snapshots on `/`, so it
> is unrecoverable. Lost: `sso_start_url`, `sso_region`, `secret_region`, any
> `browser_command`, `last_pick`, and saved Applications and Mappings. **No
> Values were in the file** — Config holds locations only. Re-enter via the GUI
> or `cargo run -p janitor-aws --bin live-verify`.
>
> Eight probe containers were also left behind at
> `~/Library/Containers/com.probe.{sbonly,sbclient,sbclientserver,execsb,childsb,lssb,acceptsb,trustsb}`.
> `containermanagerd` denies `rm` without Full Disk Access; delete them via
> Finder. A pre-existing `com.circuitstitch.apps.probe` was not created by this
> work.

| Surface | Under App Sandbox | Fix |
|---|---|---|
| **Loopback OAuth listener** (`aws-auth/src/loopback.rs:16`, `:38-47`, `:56-86`) | **Breaks hard.** `bind(127.0.0.1)` returns EPERM. Adding `network.client` does not help. Every Sign-in dies at `authenticator.rs:66` before a browser opens. | Add `com.apple.security.network.server`. Verified: with it, bind, listen, accept, and read of the exact `GET /oauth/callback?code=…&state=…` request all succeed. |
| **Outbound AWS calls** | **Breaks.** `connect()` to 1.1.1.1:443 returns EPERM. | Add `com.apple.security.network.client`. One boolean covers oidc, portal.sso, secretsmanager, ssm, tagging, and ssmmessages — App Sandbox has no per-host allowlist. |
| **`CommandBrowser`** (`aws-auth/src/browser/command.rs:33-36`) | **Unusable.** The `spawn` itself succeeds, so it fails silently. The child inherits the container: measured `child HOME=/Users/…/Library/Containers/com.probe.childsb/Data` and `child read-real-home=FAIL`. A real browser loses its own profile, cookies, and network-server rights. | Make the `Strategy::Command` arm `#[cfg(not(target_os = "macos"))]`. On macOS map any non-`@native`, non-empty `browser_command` to `Strategy::WebAuthSession`, not `Default`, so isolation is never silently downgraded. Offer exactly two Settings options on macOS. |
| **`DefaultBrowser`** (`open::that`) | **Works.** LaunchServices launches the target under launchd. Measured: `/usr/bin/open -g -j -a Calculator` exit 0, and `ps -o ppid=` on the Calculator PID returned `1`. | No change. `open::that` runs `/usr/bin/open <url>` (`open-5.3.5/src/macos.rs:4-5`), called at `loopback.rs:51`. |
| **`ASWebAuthenticationSession`** | Expected to work; **not measured**. No probe exercised AuthenticationServices. | Verify with a real sandboxed Sign-in before relying on it. |
| **Config path** (`core/src/config/mod.rs:217-221`) | **Relocates silently.** `$HOME` is redirected, so `directories` resolves into the container. Reads and writes there need no entitlement. The old path is unreadable from inside — measured `REAL_HOME_CONFIG_READ=FAIL` in all three sandboxed variants. | The miss surfaces as `NotFound` → `Config::default()` (`:237`), and the GUI swallows load errors (`main.rs:1055`) and save errors (`:352`). Write a migration note. Settle the bundle identifier. |
| **Clipboard** | **Carries Values, and is unprotected.** | See below — this is the one net-new macOS work item. |
| **SSM `wss` data channel** (`janitor-ssm/src/mgs/channel.rs:25-46`) | **No additional impact.** Pure outbound `connect_async`; no listener, no local socket, no `session-manager-plugin` subprocess. | Covered by `network.client`. The write path's `mktemp`/`--reference`/`mv`/`sudo` run on the remote instance. |
| **Keychain** | **Nothing touches it.** Zero matches for `keychain\|keyring\|SecItem*\|kSecClass` across the workspace. | No `keychain-access-groups` entitlement. Keep it that way — caching the SSO token there would violate ADR 0002. |
| **TLS trust store** | **Unaffected.** `rustls-native-certs` reads Security.framework. Sandboxed and unsandboxed runs were byte-identical: User `errSecNoTrustSettings`, Admin 1 cert, System 157 certs, `SecTrustCopyAnchorCertificates` status 0. It enters only via `rustls-native-certs` → `aws-smithy-http-client` / `tokio-tungstenite`. | No entitlement, no switch to `webpki-roots`. |

### The clipboard correction

The original finding claimed "Clipboard use is Entry names only — never
Values". **That is false.** `Command::CopyValue { row, col, key }` calls
`provider.reveal(&key, col)` and relays `Event::CopyValue { row, col, text }`
(`worker.rs:428-430`); `apply_event` receives it and calls
`set_clipboard(&text)` (`main.rs:453-467`, call at `:465`). `text` is a revealed
Value.

`main.rs:182-183` says so: "**No auto-clear** for a Value yet — issue #59 tracks
the ADR 0005 clipboard hardening." ADR 0005 states plainly that copying a
revealed Value to the OS clipboard is allowed. `THREAT-MODEL.md:32` names the OS
clipboard as part of trust boundary 2, and `:57` lists clipboard lingering as a
defended risk via timeout clear.

**The comment at `janitor-gui/Cargo.toml:22-23` — "Only Entry names (metadata)
are ever placed on the clipboard — never Values" — is wrong. File it as a repo
bug.**

**Consequence: a required macOS control is missing from the plan.** ADR 0005
requires that a copied Value be excluded from clipboard history and cloud sync
where the OS exposes the flag, naming macOS Universal Clipboard. On macOS that
is an `NSPasteboard` obligation for the SwiftUI shell: write the item with
`org.nspasteboard.ConcealedType` and `NSPasteboardTypeTransient`, plus the ADR
0005 timeout clear that #59 tracks. `arboard` 3 sets neither. Today a revealed
Value syncs via Universal Clipboard to the user's other devices.

### Also corrected

- **Four claims were asserted as measurements but are inferences.** None of the
  seven probes exercised AuthenticationServices, so
  "ASWebAuthenticationSession works under sandbox" is unverified. The probes
  measured `/usr/bin/open -g -j -a Calculator` and an unclaimed URL scheme —
  never `open <https-url>`, the production invocation. No real browser was
  launched from inside a sandbox, so `CommandBrowser` being "structurally dead"
  is a well-supported deduction, not a measurement.
- **A reasoning slip:** the entitlement gates the `bind()`/`listen()` syscall,
  not the inbound-ness of any particular connection. The sandboxed bind fails
  with no client process in existence at all.
- **ADR 0007's four objections** to the App Store route were "launch a browser,
  bind a localhost port, write an arbitrary config dir, drive the clipboard"
  (`docs/adr/0007-ci-and-distribution.md:71-74`). Correct scorecard: two
  measured (bind, config dir), one measured plus inferred (browser), one
  unmeasured and previously mis-characterized (clipboard).
- The device-grant sentence in ADR 0002 is at lines 25-26, not 22-25.
- There is a **second** `browser::select` call at `authenticator.rs:40`, inside
  `Authenticator::new`, used by four live-verify binaries and one integration
  test. It always yields `Strategy::Default`, so removing `CommandBrowser` on
  macOS stays localized.

### The escape hatch

ADR 0002 lines 25-26 already reserve the OAuth Device Authorization grant "as a
fallback for environments where binding a localhost port isn't possible". It is
not implemented — the `OidcClient` port has only `register_client` and
`create_token(authorization_code)` (`aws-auth/src/wire.rs:37-50`). Implementing
it deletes `network.server` and the entire loopback listener, at the cost of a
user-typed code. Keep it as the review contingency.

The loopback path is forced by AWS, not chosen. IAM Identity Center rejects any
redirect path other than `/oauth/callback` with an
`InvalidRedirectUriException` reading "Requested client type must use loopback
interface for redirect", verified live in Milestone B
(`loopback.rs:18-35`). A custom URL scheme is not an option for a public client.

### The entitlements plist

Exactly two entitlements beyond the sandbox itself. A validated copy (with
explanatory XML comments, so it is not byte-identical to this listing) is at
`/private/tmp/claude-501/-Volumes-OWCKioxia2TB-dev-Code-Janitor/aa893cf1-b012-44f2-8c1a-404f5ee52b93/scratchpad/Janitor.entitlements`.
`plutil -lint` reports OK.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.app-sandbox</key>
	<true/>
	<key>com.apple.security.network.client</key>
	<true/>
	<key>com.apple.security.network.server</key>
	<true/>
	<key>com.apple.application-identifier</key>
	<string>$(TeamIdentifierPrefix)$(CFBundleIdentifier)</string>
	<key>com.apple.developer.team-identifier</key>
	<string>$(TeamIdentifierPrefix)</string>
</dict>
</plist>
```

Deliberately absent, and verified unnecessary: `files.user-selected.*`,
`files.downloads.*`, `keychain-access-groups`, `personal-information.*`,
`device.*`, `print`, and every `temporary-exception.*`. No hardened-runtime
`cs.*` exceptions — no JIT, no unsigned memory, no dyld environment variables,
no library loading outside the bundle.

There is no credential-chain surface to account for. Every AWS client is
constructed with explicit credentials and no profile lookup:
`aws-auth/src/aws_impl.rs:52-55`, `:77-80`, `:166-170`, `:189-193` all chain
`.no_credentials()` after an explicit `.region(...)`; `janitor-aws/src/aws_impl.rs:35-42`
and `janitor-ssm/src/transport.rs:63-68`, `:80-86` use `config::Builder::new()`
with an explicit `credentials_provider`. No `~/.aws` reads, no IMDS.

### Bundle identifier conflict

Packaging declares `com.circuitstitch.apps.janitor`
(`janitor-gui/Cargo.toml:63`). `ProjectDirs` builds `com.Janitor.Janitor`
(`core/src/config/mod.rs:218`). Under sandbox that nests as
`~/Library/Containers/com.circuitstitch.apps.janitor/Data/Library/Application Support/com.Janitor.Janitor/`.
The doc comment at `config/mod.rs:213-216` flags the triple as an unsettled
"stable path contract" whose change silently orphans users. The sandbox move
breaks it once regardless.

One latent fragility: `getpwuid` is **not** redirected under sandbox (measured
`getpwuid_home=/Users/kylefalconer` in every sandboxed run). `dirs-sys` falls
back to `getpwuid_r` when `$HOME` is unset (`dirs-sys-0.4.1/src/lib.rs:34-52`),
producing a path outside the container. `fs::read_to_string` would then return
EPERM, not NotFound, and `load_from` would return `ConfigError::Io` rather than
defaulting (`config/mod.rs:237`). Harden `:237` to treat `PermissionDenied` as
"no config".

Docs referencing the config path: `CONTEXT.md:77` ("plaintext, OS config dir"),
`docs/iam_setup.md:137` and `docs/handoffs/2026-05-31-identity-center-auth-milestone-b.md:106`
(Windows path only), `docs/adr/0007-ci-and-distribution.md:21-22`.

### Documents the port must edit

`THREAT-MODEL.md:32` is the only occurrence of "Slint" in that file, and it is
trust boundary 2: plaintext transiently lives in Slint widget state and, on
copy, the OS clipboard. ADR 0003 names Slint too. Both need rewording for Swift.

---

## 6. The App Store CI path

> **Superseded by ADR 0035.** Delivery moved to **Xcode Cloud** (the AnimalSpin
> pattern), with the Rust arriving as a prebuilt `JanitorKit.xcframework` from
> `depot.circuitstitch.com` (the Gonger pattern). Xcode Cloud owns signing and the
> upload, so the three `APP_STORE_CONNECT_*` secrets and the Mac Installer
> Distribution certificate are no longer needed, and Xcode Cloud never runs cargo.
>
> This section is kept as the rejected alternative. Its findings on the macOS/iOS
> export deltas, `CODE_SIGNING_ALLOWED=NO` stripping the sandbox entitlement, and
> universal-by-default archives all still hold and still inform the Xcode target.


The sibling pattern — archive on a hosted Mac, then one
`xcodebuild -exportArchive` that cloud-signs and uploads with an App Store
Connect API key — transfers, with three deltas.

| | iOS (sibling) | macOS (Janitor) |
|---|---|---|
| Export artifact | `.ipa` | `.pkg` (`IDEDistributionCreatePKGStep`) |
| Certificates minted | Apple Distribution | Mac App Distribution **plus Mac Installer Distribution** |
| Archive destination | `generic/platform=iOS` | `generic/platform=macOS` |
| Archive signing | `CODE_SIGNING_ALLOWED=NO` | `CODE_SIGN_IDENTITY=-` (entitlements must survive) |
| `ARCHS` | device arm64 | universal by default — pin it |
| Extra ExportOptions key | — | `installerSigningCertificate` (manual signing only; omit under automatic) |
| Dropped ExportOptions keys | — | `thinning`, `stripSwiftSymbols`, `manifest`, ODR keys |
| Entitlements | none | `app-sandbox`, `network.client`, `network.server` |
| Hardened runtime | n/a | set `ENABLE_HARDENED_RUNTIME=YES` (default is NO) |
| Unchanged | `method=app-store-connect`, `destination=upload`, `signingStyle=automatic`, `teamID`, `manageAppVersionAndBuildNumber=false`, `uploadSymbols` | |

### Delta 1 — a second certificate, and the one unproven step

A macOS store export additionally demands a **Mac Installer Distribution**
certificate to sign the `.pkg`. Proved by running a real export offline: it
fails with `No signing certificate "Mac Installer Distribution" found` **even
under `signingStyle=automatic`**. The certificate has portal identifier
`MAC_INSTALLER_DISTRIBUTION`, automatic selector `3rd Party Mac Developer
Installer`, platform mac, distribution type store.

The public App Store Connect API `CertificateType` enum exposes
`MAC_APP_DISTRIBUTION` and `MAC_INSTALLER_DISTRIBUTION` but **no `*_MANAGED`
variants**, so cloud-managed certificates are not addressable through it. At
least one public project hit this and resolved it by storing a `.p12` in
secrets. Apple DTS states `codesign` cannot use a cloud-managed certificate
while Xcode's export pipeline can, because signing is delegated to a web
service; nothing in that thread addresses `pkg`/`productsign`.

Plan for the cloud path. Keep a `.p12` fallback ready. The first armed run
answers it in about twenty minutes.

### Delta 2 — `CODE_SIGNING_ALLOWED=NO` strips the sandbox entitlement

Proved locally. Archiving with `CODE_SIGNING_ALLOWED=NO` yields
`Signature=adhoc, linker-signed`, `Sealed Resources=none`, and
`codesign -d --entitlements` prints nothing. Archiving the same app with
`CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual PROVISIONING_PROFILE_SPECIFIER=
DEVELOPMENT_TEAM=` embeds `com.apple.security.app-sandbox` and
`com.apple.security.network.client`, sets the identifier, and seals resources —
still with no certificate and no registered device. **Use ad-hoc, not
no-signing.** The build otherwise succeeds and review rejects it.

### Delta 3 — universal by default

A macOS Release archive has `ARCHS = arm64 x86_64`, `ONLY_ACTIVE_ARCH = NO`, and
records both architectures in the archive Info.plist. Janitor's current dmg is
Apple Silicon only (`.github/workflows/release.yml:221-239`).

**Correction to the original finding:** GitHub's macOS 26 runners are **not**
arm64-only. `macos-26-intel` and `macos-26-large` are x64 images; `macos-26`,
`macos-latest`, and `macos-26-xlarge` are arm64. The free/standard `macos-26`
label is arm64; x64 macOS 26 runners exist as larger, paid runners. The argument
for cross-compiling plus `lipo` rests on cost and simplicity, not availability.
GA was 2026-02-26; default Xcode is 26.4.1; `macos-latest` began pointing at
macos-26 on 2026-06-15.

### Building the Rust staticlib

No crate declares `staticlib` or `cdylib` today, so `janitor-ffi` is new. The
exact native link line from `cargo rustc -p janitor-aws --lib --release
--crate-type staticlib -- --print native-static-libs`:

```
-framework Security -framework CoreFoundation -framework AuthenticationServices
-framework AppKit -framework CoreVideo -framework CoreData -framework CoreText
-framework CoreImage -framework CoreGraphics -framework CloudKit
-framework QuartzCore -framework Foundation -lSystem -lobjc -liconv -lc -lm
```

`AuthenticationServices` and `AppKit` are already linked from Rust for the
`ASWebAuthenticationSession` opener.

One script, `apple/build-rust.sh`, called by both CI and Xcode:

```bash
#!/usr/bin/env bash
set -euo pipefail
# Xcode exports SDKROOT/CPATH/LIBRARY_PATH into script phases and they poison
# cargo's host build scripts. Drop them and let cargo pick per --target.
unset SDKROOT CPATH LIBRARY_PATH MACOSX_DEPLOYMENT_TARGET
export PATH="$HOME/.cargo/bin:$PATH"   # Xcode.app's GUI has no rustup on PATH
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/apple/build"; mkdir -p "$out"
targets=(aarch64-apple-darwin)
[ "${JANITOR_UNIVERSAL:-0}" = 1 ] && targets+=(x86_64-apple-darwin)
for t in "${targets[@]}"; do cargo build --release --target "$t" -p janitor-ffi; done
lipo -create $(printf "$root/target/%s/release/libjanitor_ffi.a " "${targets[@]}") \
     -output "$out/libjanitor_ffi.a"
strip -S "$out/libjanitor_ffi.a"
```

Wire it as an Xcode pre-build Run Script phase. Pin
`ENABLE_USER_SCRIPT_SANDBOXING = NO` — an XcodeGen-generated project resolves it
to NO, but Xcode's own new-project template sets YES, which blocks cargo from
reading `~/.cargo` and writing `target/`. A Run Script phase invoked through the
`xcodebuild` CLI inherits the invoking shell's PATH (verified locally: the phase
resolved `command -v cargo`). That does not hold when launched from Xcode.app.

The `macos-26` image carries Rust 1.97.1, Cargo 1.97.1, Rustup 1.29.0, and
seven Xcode 26.x versions with 26.6 as default. No toolchain install step; add
`rustup target add x86_64-apple-darwin` only for the universal build.
`Swatinem/rust-cache@v2` works because cargo's target dir stays at the workspace
root, outside DerivedData.

### Where the job goes

Add one job beside the existing lanes. Change nothing in `setup`,
`verify-version`, `linux-rpm`, `linux-portable`, `windows`, or the packaging
metadata. Two touch points:

1. The `release` job gates on `needs: [setup, verify-version, linux-rpm,
   linux-portable, macos, windows]` with an `always()` plus per-job result check
   (`release.yml:333-345`). Add `macos-appstore` to `needs` and one clause:
   `&& (needs.macos-appstore.result == 'success' || needs.macos-appstore.result == 'skipped')`.
2. **Do not** add a `.pkg` glob to `files:`. A Mac App Store `.pkg` is an upload
   artifact, not something a user installs.

The existing `macos:` cargo-packager dmg job (`release.yml:221`) stays while
`janitor-gui` is still the Linux and Windows binary. It is also still the version
authority (`janitor-gui/Cargo.toml:3`, currently 0.1.4), which `verify-version`
extracts with a one-line grep and sed (`release.yml:134`). When the Slint macOS
binary is dropped, replace that job with a second export off the same archive
(`method=developer-id`, `destination=export`, then `xcrun notarytool` and a dmg).

`janitor-gui/Cargo.toml:80-84` records that Windows is **not** packaged by
cargo-packager any more — ADR 0034 moved it to `janitor-gui/msix/AppxManifest.xml`.
What that manifest holds is Linux and macOS packaging plus the
`[target.'cfg(windows)'.dependencies] windows = "0.62.2"` block at `:39-40`.

### Job sketch

```yaml
  # ── macOS App Store: SwiftUI shell over the Rust core ─────────────────────
  # Skip-gated on MACOS_APPSTORE_ENABLED exactly like the Windows job: while the
  # variable is unset the job is SKIPPED and the run stays green, so nothing here
  # can block a Linux release. Attaches NOTHING to the GitHub Release.
  macos-appstore:
    name: macOS App Store (.pkg → App Store Connect)
    needs: [verify-version, setup]
    if: vars.MACOS_APPSTORE_ENABLED == 'true'
    runs-on: macos-26          # free/standard label is Apple Silicon
    environment: release       # scopes the ASC key to a reviewable environment
    timeout-minutes: 60
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v5
        with:
          ref: ${{ needs.setup.outputs.ref }}

      # The image carries several Xcode 26 point releases; pin the newest.
      # No `| head -1`: SIGPIPE under `set -o pipefail` exits 141 with no output.
      - name: Select Xcode 26
        run: |
          set -euo pipefail
          XCODE="$(ls -d /Applications/Xcode_26*.app 2>/dev/null | sort -V | tail -1)"
          [ -n "$XCODE" ] || { echo "::error::no Xcode 26 on this image"; exit 1; }
          echo "DEVELOPER_DIR=$XCODE/Contents/Developer" >> "$GITHUB_ENV"
          "$XCODE/Contents/Developer/usr/bin/xcodebuild" -version

      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: aarch64-apple-darwin,x86_64-apple-darwin
      - uses: Swatinem/rust-cache@v2

      # BEFORE the build: xcodebuild says nothing about a bad key until the
      # export, and what it says then is `keyPathInvalid`, naming the path
      # rather than the reason. Accepts the .p8 as Apple gives it, or base64.
      - name: Write the App Store Connect API key
        env:
          API_KEY_P8: ${{ secrets.APP_STORE_CONNECT_API_KEY_P8 }}
        run: |
          set -euo pipefail
          KEY="$RUNNER_TEMP/private_keys/AuthKey.p8"
          mkdir -p "$RUNNER_TEMP/private_keys"
          [ -n "${API_KEY_P8:-}" ] || { echo "::error::APP_STORE_CONNECT_API_KEY_P8 is empty"; exit 1; }
          if printf '%s' "$API_KEY_P8" | grep -q "BEGIN PRIVATE KEY"; then
            printf '%s\n' "$API_KEY_P8" > "$KEY"
          else
            printf '%s' "$API_KEY_P8" | base64 --decode > "$KEY" 2>/dev/null || true
          fi
          grep -q "BEGIN PRIVATE KEY" "$KEY" || { echo "::error::secret is neither a .p8 nor base64 of one"; exit 1; }

      # One version authority: janitor-gui/Cargo.toml, the same grep+sed
      # verify-version already uses. The build number is the run number, because
      # App Store Connect refuses a CFBundleVersion it has seen for a version.
      - name: Resolve version and build number
        run: |
          set -euo pipefail
          ver="$(grep -m1 -E '^version[[:space:]]*=' janitor-gui/Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
          echo "MARKETING_VERSION=$ver"         >> "$GITHUB_ENV"
          echo "BUILD=${{ github.run_number }}" >> "$GITHUB_ENV"

      - name: Build the Rust core as a staticlib
        run: ./apple/build-rust.sh          # JANITOR_UNIVERSAL=1 for an Intel slice

      - name: Generate the Xcode project
        env:
          DEVELOPMENT_TEAM: ${{ vars.APP_STORE_DEVELOPMENT_TEAM }}
        run: |
          brew install --quiet xcodegen
          cd apple && xcodegen generate

      # AD-HOC signed, NOT CODE_SIGNING_ALLOWED=NO. Automatic signing at archive
      # time would ask for a development profile, which needs a Mac registered to
      # the team; distribution signing needs no devices and belongs at export.
      # But unlike iOS, skipping signing entirely DROPS THE ENTITLEMENTS, and the
      # Mac App Store requires the app-sandbox one.
      - name: Archive (Release, macOS, ad-hoc signed)
        run: |
          set -euo pipefail
          xcodebuild archive \
            -project apple/Janitor.xcodeproj \
            -scheme Janitor \
            -configuration Release \
            -destination 'generic/platform=macOS' \
            -archivePath "$RUNNER_TEMP/Janitor.xcarchive" \
            CODE_SIGN_STYLE=Manual \
            CODE_SIGN_IDENTITY=- \
            PROVISIONING_PROFILE_SPECIFIER= \
            DEVELOPMENT_TEAM= \
            ENABLE_USER_SCRIPT_SANDBOXING=NO \
            ENABLE_HARDENED_RUNTIME=YES \
            ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
            MARKETING_VERSION="$MARKETING_VERSION" \
            CURRENT_PROJECT_VERSION="$BUILD"

      - name: Assert the sandbox entitlement survived the archive
        run: |
          set -euo pipefail
          APP="$RUNNER_TEMP/Janitor.xcarchive/Products/Applications/Janitor.app"
          codesign -d --entitlements - "$APP" 2>/dev/null | grep -q app-sandbox \
            || { echo "::error::archive carries no app-sandbox entitlement"; exit 1; }

      # Generated, never committed. A dry run (destination=export) exports
      # locally, so it never burns a build number in App Store Connect.
      - name: Write ExportOptions.plist
        run: |
          set -euo pipefail
          DEST=$([ "${{ needs.setup.outputs.do_release }}" = "true" ] && echo upload || echo export)
          cat > "$RUNNER_TEMP/ExportOptions.plist" <<PLIST
          <?xml version="1.0" encoding="UTF-8"?>
          <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
          <plist version="1.0">
          <dict>
            <key>destination</key><string>$DEST</string>
            <key>method</key><string>app-store-connect</string>
            <key>teamID</key><string>${{ vars.APP_STORE_DEVELOPMENT_TEAM }}</string>
            <key>signingStyle</key><string>automatic</string>
            <key>manageAppVersionAndBuildNumber</key><false/>
            <key>testFlightInternalTestingOnly</key><false/>
            <key>uploadSymbols</key><true/>
          </dict>
          </plist>
          PLIST

      # One command signs the .app, builds and signs the .pkg, and uploads it.
      # THE MAC INSTALLER DISTRIBUTION CERTIFICATE IS THE ONE UNPROVEN ASSET.
      # If this fails with `No signing certificate "Mac Installer Distribution"
      # found`, import a .p12 into a throwaway keychain before this step.
      - name: Export and upload to App Store Connect
        env:
          KEY_ID: ${{ secrets.APP_STORE_CONNECT_API_KEY_ID }}
          ISSUER_ID: ${{ secrets.APP_STORE_CONNECT_API_ISSUER_ID }}
        run: |
          set -euo pipefail
          xcodebuild -exportArchive \
            -archivePath "$RUNNER_TEMP/Janitor.xcarchive" \
            -exportOptionsPlist "$RUNNER_TEMP/ExportOptions.plist" \
            -exportPath "$RUNNER_TEMP/export" \
            -allowProvisioningUpdates \
            -authenticationKeyPath "$RUNNER_TEMP/private_keys/AuthKey.p8" \
            -authenticationKeyID "$KEY_ID" \
            -authenticationKeyIssuerID "$ISSUER_ID"

      # The archive's own logs say why signing or upload failed, and they live
      # inside the archive rather than in the step output.
      - name: Upload the build logs on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: macos-appstore-logs
          path: |
            ${{ runner.temp }}/Janitor.xcarchive/Logs/**
            ${{ runner.temp }}/export/**
          retention-days: 7
          if-no-files-found: warn
```

### Secrets and variables

| Name | Kind | State |
|---|---|---|
| `APP_STORE_CONNECT_API_KEY_P8` | Secret | Exists as a Circuit-Stitch **org** secret, visibility **PRIVATE**. Janitor is a **PUBLIC** repo, so it cannot read it. |
| `APP_STORE_CONNECT_API_KEY_ID` | Secret | Same. |
| `APP_STORE_CONNECT_API_ISSUER_ID` | Secret | Same. |
| `APP_STORE_DEVELOPMENT_TEAM` | Variable | Exists as an org variable, `GDV76FJJZ5`, visibility ALL. Nothing to do. |
| `MACOS_APPSTORE_ENABLED` | Variable | **New**, repo-level, `'true'` to arm the job. Mirrors `WINDOWS_SIGNING_ENABLED`. |
| `MACOS_INSTALLER_CERT_P12_BASE64` | Secret | Only if cloud signing will not mint the installer certificate. |
| `MACOS_INSTALLER_CERT_PASSWORD` | Secret | Same. |

Fix the visibility by setting the three secrets on this repo's `release`
environment rather than widening org visibility. That is the tighter choice for
a public repo.

Not a secret, but a prerequisite: the App Store Connect app record and the App
ID for `com.circuitstitch.apps.janitor` must exist before the first run. Cloud
signing mints certificates and profiles, not app records. The API key needs a
role that permits cloud signing.

Unchanged: `WINDOWS_SIGNING_ENABLED`, the five `AZURE_*` variables,
`CODECOV_TOKEN`.

### No sibling precedent

No repo on this machine has ever run a macOS App Store upload. `deferno-kmp` has
a macOS SwiftUI job that is ad-hoc signed, build-and-test only, plus an iOS-only
TestFlight upload. `WirelessOrderTelegraph-kmp`'s release workflow is iOS-only
and that repo has never had a tag.

---

## 7. Open questions a human must answer

1. **Is `janitor-gui` deleted, or kept as the Windows and Linux shell?** This
   decides whether the worker *moves* into `janitor-ffi` or must be *shared*,
   which would make `janitor-gui` depend on `janitor-ffi` and force a feature
   flag so it builds without UniFFI scaffolding off macOS. It also decides the
   fate of `update.rs`, the MSIX manifest, and the `.appinstaller`.
2. **Does the Swift side receive the revealed plaintext at all?** A
   THREAT-MODEL decision that must be made before the FFI shape is fixed.
   Options: a Rust-owned handle with an explicit zeroizing free, a
   caller-supplied buffer, or an accepted un-zeroized Swift `String` (which is
   what happens inside Slint today).
3. **Will `-allowProvisioningUpdates` with an Admin-role API key mint the Mac
   Installer Distribution certificate?** Nothing on this machine or in Apple's
   public docs settles it. The first armed run answers it. If not, one
   certificate goes into secrets and the "nothing stored" property is lost for
   exactly that asset.
4. **Does Apple's cloud signing sign the `.pkg`'s CMS installer signature at
   all, or only Mach-O code signatures?** `productsign` and `productbuild` use a
   different mechanism than `codesign`, and Apple's DTS statement covers code
   signing only.
5. **Will App Review accept `com.apple.security.network.server` for a
   credential-adjacent app** on the RFC 8252 and AWS-constraint justification,
   or push toward the device-code grant? No local test settles this.
6. **Should the Device Authorization grant be implemented now as insurance?** It
   deletes `network.server` and the whole loopback listener, at the cost of a
   new `OidcClient` method, a new wizard step, and worse UX.
7. **Which bundle identifier wins** — keep `com.circuitstitch.apps.janitor` and
   accept the doubled container path, or change the `ProjectDirs` triple? The
   "stable path contract" breaks once either way.
8. **Is a migration path for existing Developer ID users in scope?** Options: a
   documented manual copy, a one-time Import panel behind
   `files.user-selected.read-only`, or nothing. Adding a file entitlement solely
   for migration is a real cost against a minimal set.
9. **Should config path resolution stay in `janitor-core` via `directories`, or
   move to the shell?** Shell-owned resolution would use `FileManager`'s
   container API and drop the `$HOME`/`getpwuid` fragility, at the cost of
   splitting a core responsibility across the boundary.
10. **Where do the ~850 lines of pure GUI seams go** — `janitor-core`,
    `janitor-ffi`, or reimplemented in Swift? Moving them keeps 38 tests;
    reimplementing duplicates security-relevant rules in an untested layer.
11. **What replaces the 26 view tests?** XCUITest, snapshot tests, or an
    accepted reduction. ADR 0021's motivation was that pure-view changes had no
    red-green loop.
12. **Is the Manage window a real secondary window, a sheet, or an inspector?**
    Whichever form wins, the binding rule must survive: the window stays bound to
    the Application it opened for, and the sidebar selection does not retarget it.
13. **Does the SwiftUI shell keep the Rust `ASWebAuthenticationSession` opener,
    or reimplement it in Swift?** If Swift, delete the `objc2`/`block2`/
    `dispatch2`/`objc2-authentication-services` target deps from
    `janitor-aws-auth/Cargo.toml`.
14. **Arm64-only or universal?** Decides whether `apple/build-rust.sh` runs one
    cargo target or two, and whether `aws-lc-sys` must cross-compile to x86_64 on
    an arm64 runner.
15. **What is the `ITSAppUsesNonExemptEncryption` determination?** Janitor
    bundles `aws-lc-rs` 1.17.0, `aws-lc-sys` 0.41.0, `ring` 0.17.14, and
    `rustls` 0.21.12 and 0.23.40 (`Cargo.lock:581,591,5201,5305,5317`). The
    sibling's "every primitive comes from the OS" reasoning does not carry over.
    This is a legal statement, not a build setting.
16. **What license does the project move to?** All six crates declare
    `license = "GPL-3.0-only"` on line 5 and the repo LICENSE is GPLv3. Dropping
    Slint removes the *cause* of the GPL, not the license. The App Store conflict
    is GPLv3 **§10** (no further restrictions) plus the §3 anti-DRM provisions —
    **not §6**, which is the GPLv2 numbering. Relicensing is feasible:
    `git shortlog -sne --all` shows one human across 232 commits plus a bot.
17. **Which crate becomes the version authority once the Slint GUI is gone?**
    `verify-version`, the bump job, and the new `MARKETING_VERSION` step all
    point at `janitor-gui/Cargo.toml` and need repointing in one change.
18. **Does the port close out the pending #80 slice** (in-matrix cell edit plus
    confirm-diff dialog)? `Command::ApplyEdits` and `core::write::summarize_edits`
    exist with no producer, so the SwiftUI shell could ship it natively rather
    than porting a dead rail. If so, export `summarize_edits` so the masked key
    and length summary stays in tested Rust, matching the `is_revealed`
    precedent.
19. **Should the ≥80% coverage gate follow the logic that moves out of
    `janitor-gui`?** `run_loop`, `discovery_event`, and `write_event` have real
    tests today but `janitor-gui` is excluded from the gate. Does `janitor-ffi`
    get a gate, or does the gate track only its non-FFI half?
20. **Is `destination=upload` reliable for macOS in Xcode 26**, or should the job
    export locally and upload with `xcrun altool --upload-app -t macos`? One
    forum report claims the API key does not work for the upload destination.

---

## 8. Risks

**Security and correctness**

1. **The revealed plaintext is copied into a `RustBuffer` and then a Swift
   `String`; neither intermediate is zeroed.** Same softer-zone acceptance the
   threat model already makes for Slint widget state, but ADR 0003 and
   `THREAT-MODEL.md:32` both name Slint specifically and go stale after the port.
2. **A copied Value syncs via Universal Clipboard today.** ADR 0005 requires
   exclusion from clipboard history and cloud sync. `arboard` sets neither the
   concealed nor transient pasteboard type, and #59's timeout clear is
   unimplemented. This is net-new macOS work, not a port of existing behavior.
3. **`apply_event` holds two race guards that are easy to lose in a rewrite.**
   The stale-load guard (`main.rs:414-421`) and the reveal release race
   (`:425-431`). Losing the second flashes a secret on screen after the user let
   go.
4. **`reveal::is_revealed` is the tested predicate that exactly one cell
   un-masks.** Reimplementing it in Swift moves a security rule out of tested
   Rust, against ADR 0003.
5. **`Box<dyn Provider>` is `!Sync` and six of seven methods take `&mut self`.**
   Any FFI design that lets Swift call from more than one thread, or re-enter
   while an async call is in flight, is unsound. Safety must come from a
   single-consumer channel, not a mutex.
6. **`Provider::write` accepts `&[EnvEdit]`,** whose `Set` variant carries the
   new plaintext. Constructing those over FFI means plaintext crosses *into*
   Rust as a C string that Swift allocated and will not zeroize. `EnvEdit::set`
   zeroize-wraps on the Rust side (`write.rs:54-59`); the Swift original is
   unmanaged.
7. **The read-write lock is a plain `bool` local in the worker loop**
   (`worker.rs:371`). Re-hosting the worker must carry that invariant
   deliberately — it is the tested backstop for a non-negotiable invariant, not
   a UI affordance.

**Port mechanics**

8. **~2,500 lines of tested, Slint-independent Rust are bin-local `mod`s** and
   are deleted with the crate unless extracted first. `janitor-gui` has no
   `src/lib.rs`.
9. **The AWS composition root lives in the GUI crate** (`worker.rs:252-294`).
   Deleting `janitor-gui` orphans the `Authenticator`, browser selector, role
   client, and two-Method registry unless they move first.
10. **All 26 ADR 0021 view tests are Slint-harness-bound** and become
    unrunnable. Click routing, freeze-pane alignment, sticky-header pinning, and
    reveal press-and-hold have no other guard.
11. **UniFFI #2818 is open.** The Xcode 26 isolation mitigation is a build
    setting, not code, and must be verified on the actual runner. The fallback is
    a `sed` post-processing step in CI, which is fragile.
12. **UniFFI #2448 is open.** Avoided by exporting zero `async fn`, which becomes
    a standing constraint a future contributor could break silently. Worth a
    compile-time or review guard.
13. **`usize` is not a UniFFI builtin,** so the `MatrixCell` mirror is
    hand-written and can drift from `janitor-core` without the compiler noticing
    unless the `From` impl is exhaustively matched.
14. **The `ASWebAuthenticationSession` opener depends on a live `NSApplication`
    run loop** with a 20-second creation timeout and a main-queue hop. That
    contract held under Slint. It is untested shell with no CI coverage, and a
    regression breaks Sign-in entirely, surfacing only on-device.
15. **Three chrome properties are dead** (`read-only`, `identity`,
    `session-remaining`). A literal port reproduces a hardcoded read-only badge
    that does not reflect the worker's lock state.

**Distribution**

16. **The Mac Installer Distribution certificate is not proven cloud-mintable.**
    If it is not, the "nothing stored in secrets" property is lost for exactly
    one certificate.
17. **Copying `CODE_SIGNING_ALLOWED=NO` verbatim produces an archive with no
    entitlements.** The build succeeds, the upload may succeed, and review
    rejects it. The explicit `grep app-sandbox` assertion turns that into a fast
    CI failure.
18. **`com.apple.security.network.server` is technically ungated but is a human
    review surface.** A secrets manager that opens a listening socket invites
    questions. Budget at least one review round-trip.
19. **The config relocation is invisible in code but loud to users.** Every
    existing macOS user's Applications and Mappings appear to vanish on first
    App Store launch. No error, no prompt, no log.
20. **Silent save failures.** `main.rs:352` does `let _ = self.config.save();`.
    Latent inside the container, but combined with the swallowed load it means a
    broken config path presents as an app that quietly forgets everything.
    Surface it to the Diagnostic Log while touching this area.
21. **`github.run_number` as `CFBundleVersion` is monotonic only while the
    workflow file keeps its identity.** Renaming or recreating `release.yml`
    resets it, and App Store Connect refuses a version it has seen.
22. **App Store Connect secrets within reach of a public repository widen the
    blast radius.** Scope them to the `release` environment and keep the job off
    `pull_request` triggers.
23. **A universal archive requires cross-compiling `aws-lc-sys` to x86_64 on an
    arm64 runner** — a failure point the current Apple Silicon-only dmg has never
    exercised. Pin `ARCHS=arm64` for bring-up.
24. **Dropping the Slint macOS binary leaves the `macos:` dmg job with nothing to
    package.** Re-base it on a second export from the same archive in the same
    change, or direct-download users lose their artifact.
25. **Removing `CommandBrowser` on macOS narrows a shipped security control.**
    ADR 0033's motivation was letting a user isolate the portal cookie from the
    AWS CLI. Make the macOS fallback `@native`, not `Default`, so isolation is
    never silently downgraded, and say so in release notes.
26. **`swift-bridge`'s dormancy is a fact today, not permanently.** Record in the
    ADR that it lost on the `RustStr` borrow, not on activity level, so a revival
    does not automatically reopen the decision.
