# GUI ↔ AWS Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Feed the existing masked drift matrix with real AWS Secrets Manager data for one already-configured Application at a time — signing in lazily through the browser, off the UI thread — without pushing auth/AWS/compare logic into the GUI and without ever writing a secret to disk.

**Architecture:** A new tested `Session` orchestrator in `janitor-aws` owns the lazy-auth + multi-environment fetch logic (built from the same `Arc<dyn …>` seams `live-verify` uses, so it is unit-tested against the existing fakes). `janitor-gui` gains plumbing only: a worker `std::thread` that owns a Tokio runtime + the `Session`, a `Command`/`Event` channel, and `Weak::upgrade_in_event_loop` marshalling into the existing Slint model-mapping fns. `janitor-core` is unchanged. A `JANITOR_MOCK=1` backend keeps the GUI runnable offline.

**Tech Stack:** Rust 2021, Tokio 1.52 (current-thread runtime in the worker), Slint 1.16 (`upgrade_in_event_loop`), `secrecy`/`zeroize` (already used), `async-trait`.

**Spec:** [`docs/superpowers/specs/2026-05-31-gui-aws-bridge-design.md`](../specs/2026-05-31-gui-aws-bridge-design.md). Read it first. This plan implements every Decision (1–8) and the in-scope cleanups from it.

---

## Orientation (read before starting)

These are the load-bearing facts the tasks build on. Verbatim signatures:

- **`janitor-core::source::SecretSource`** (`janitor-core/src/source.rs`) — sync: `fn fetch(&self, &Mapping) -> Result<SecretShape, FetchError>`. **Left untouched.** `MockSource` (`janitor-core/src/mock.rs`) implements it.
- **`janitor-core::config`** — `Config { sso_start_url, sso_region, secret_region, last_pick: Option<Mapping>, applications: Vec<Application> }`; `Application { name: String, environments: Vec<Mapping> }`; `Mapping { environment, account_id, region, secret_id, permission_set }` (all `String`). `Config::load() -> Result<Config, ConfigError>`, `Config::save(&self) -> Result<(), ConfigError>`. All `Clone`.
- **`janitor-core::view`** — `MatrixView { environments: Vec<String>, rows: Vec<MatrixRow> }` (`Clone`, `PartialEq`); `MatrixRow { key: RowKey, name, state, cells }`; `fn project(&Comparison) -> MatrixView`; `fn reveal_value<'a>(sets: &'a [(String, SecretShape)], key: &RowKey, col: usize) -> Option<&'a Value>`; `fn sort_rows(&mut MatrixView, SortKey)`; `enum SortKey { Name, GapFirst }`.
- **`janitor-core::compare`** — `Comparison::build(&[(String, SecretShape)]) -> Comparison` (borrows the sets); `enum RowKey { Entry(EntryName), WholeSet }` (`Clone`, `PartialEq`, `Eq`); `enum EntryState { Aligned, Drift, Gap }`.
- **`janitor-core::secret`** — `SecretShape` (`Json(BTreeMap<EntryName,Value>)|Raw(Value)|Binary(SecretBytes)`); `Value::expose(&self) -> &str`. Both are `Send` (wrap `secrecy::SecretString`/`SecretBox`).
- **`janitor-aws::source`** — `struct AuthenticatedSource`; `AuthenticatedSource::new(broker: CredentialBroker, secrets: SecretsClient, reauth: Arc<dyn Reauth>, role_client: Arc<dyn RoleCredentialClient>, clock: Arc<dyn Clock>) -> Self`; `async fn fetch(&mut self, &Mapping) -> Result<SecretShape, SessionError>`. `trait Reauth: Send + Sync { async fn sign_in(&self) -> Result<SsoToken, SignInError>; }` — `Authenticator` implements it.
- **`janitor-aws::broker`** — `CredentialBroker::new(token: SsoToken, role_client: Arc<dyn RoleCredentialClient>, clock: Arc<dyn Clock>) -> Self`.
- **`janitor-aws::secrets`** — `SecretsClient::new(api: Arc<dyn SecretsApi>) -> Self`.
- **`janitor-aws::authenticator`** — `Authenticator::new(oidc: Arc<dyn OidcClient>, issuer_url: String) -> Self`; `async fn sign_in_once(&self) -> Result<SsoToken, SignInError>`.
- **`janitor-aws::aws_impl`** — `AwsOidcClient::new(region: String).await -> Self`; `AwsRoleClient::new(region: String).await -> Self` (impls both `RoleCredentialClient` and `AccountCatalog`); `AwsSecretsApi::new() -> Self` (impls `SecretsApi`).
- **`janitor-aws::error`** — `enum SessionError { ReauthRequired, AccessDenied, NotFound, Throttled, Unsupported, Sdk{context} }`; `enum SignInError { … , Sdk{context} }` (both `thiserror`, so `Display`).
- **`janitor-aws::types`** — `Clock` trait + `SystemClock`; `SsoToken`, `Credential` (zeroizing).
- **`janitor-aws::wire::fakes`** (`#[cfg(test)]`) — `FakeRoleClient::new(Vec<Result<CredSpec, SessionError>>)`, `CredSpec { expires_in: Duration, tag: &'static str }`, `FakeSecretsApi::new(Vec<Result<RawSecret, SessionError>>)`, `FakeClock::at(u64)`, `RawSecret { secret_string: Option<String>, secret_binary: Option<Vec<u8>> }`. **No `FakeReauth` exists in `wire::fakes` yet** (there is a private one inside `source.rs` tests) — Task 2 adds one here, additively.

**Windows/PowerShell note for the executor:** cargo's "Finished"/"Compiling" lines render red as `NativeCommandError` — **not** a failure; judge by exit code and `test result: ok`. Keep `git commit -m` messages single-line (PS here-string quoting is fragive); for multi-line use a `COMMIT_MSG.txt` file + `git commit -F`.

**Per the user's global rule:** if any *existing* test's asserted behavior would change, STOP and surface it before editing. This plan is purely additive to existing tests (it only adds a `FakeReauth` to `wire::fakes` and new test modules); no existing assertion changes. Flag it immediately if that turns out false.

---

## File structure

**Created:**
- `janitor-aws/src/session.rs` — the `Session` orchestrator + `AppError`/`FetchFailReason`. The new tested unit.
- `janitor-gui/src/worker.rs` — `Command`/`Event` enums, the worker thread, and the real-AWS adapter wiring. Untested shell.
- `docs/adr/0012-gui-aws-bridge-worker-and-lazy-sign-in.md` — the boundary decision.

**Modified:**
- `janitor-aws/src/wire.rs` — add `FakeReauth` to `#[cfg(test)] pub mod fakes` (additive).
- `janitor-aws/src/lib.rs` — `pub mod session;`.
- `janitor-gui/Cargo.toml` — add `janitor-aws` + `tokio` deps.
- `janitor-gui/ui/app.slint` — "SSO start URL" label; Sign-in button + auth/loading/error states; per-Environment Mapping editor.
- `janitor-gui/src/main.rs` — backend abstraction (real worker vs mock), state machine, `apply_event`, drift-count fix, `Config::load`/`save`, editor callbacks.
- `CLAUDE.md`, `README.md` — status + commands.

---

## Task 1: `AppError` / `FetchFailReason` (the masked failure model)

**Files:**
- Create: `janitor-aws/src/session.rs`
- Modify: `janitor-aws/src/lib.rs`

- [ ] **Step 1: Declare the module**

In `janitor-aws/src/lib.rs`, add `pub mod session;` in the tested-modules block (after `pub mod secrets;`):

```rust
pub mod secrets;
pub mod select;
pub mod session;
pub mod source;
```

- [ ] **Step 2: Write the failing test**

Create `janitor-aws/src/session.rs` with only the failure model + its tests:

```rust
//! `Session` (GUI↔AWS bridge): lazy browser sign-in + per-Application,
//! multi-Environment fetch, behind the same ADR 0010 §5 seam the rest of the
//! crate uses. Lives in the GUI's worker thread; never crosses threads. All
//! orchestration here is unit-tested against the `wire::fakes`; only the real
//! adapters + browser are untested shell.

use crate::error::SessionError;

/// Why one Environment's fetch failed — a masked, owned classification of
/// `SessionError` (no SDK text; THREAT-MODEL). `Copy` so it is trivial to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchFailReason {
    /// A fresh browser Sign-in is required (dead/again-rejected token).
    NeedsSignIn,
    /// AWS refused under policy.
    AccessDenied,
    /// The secret id/region does not resolve.
    NotFound,
    /// Throttled or transient.
    Throttled,
    /// Content we cannot handle (e.g. binary for an op that needs text).
    Unsupported,
    /// Anything else (the scrubbed `Sdk` catch-all).
    Other,
}

impl FetchFailReason {
    /// A short, user-facing phrase. Never contains SDK/secret text.
    pub fn describe(self) -> &'static str {
        match self {
            FetchFailReason::NeedsSignIn => "session expired — sign in again",
            FetchFailReason::AccessDenied => "access denied",
            FetchFailReason::NotFound => "secret not found",
            FetchFailReason::Throttled => "throttled, try again",
            FetchFailReason::Unsupported => "unsupported secret content",
            FetchFailReason::Other => "AWS error",
        }
    }
}

impl From<&SessionError> for FetchFailReason {
    fn from(e: &SessionError) -> Self {
        match e {
            SessionError::ReauthRequired => FetchFailReason::NeedsSignIn,
            SessionError::AccessDenied => FetchFailReason::AccessDenied,
            SessionError::NotFound => FetchFailReason::NotFound,
            SessionError::Throttled => FetchFailReason::Throttled,
            SessionError::Unsupported => FetchFailReason::Unsupported,
            SessionError::Sdk { .. } => FetchFailReason::Other,
        }
    }
}

/// A whole-Application load failure: at least one Environment failed, so no
/// matrix is shown (spec Decision 8 — never a partial matrix, never a fake Gap).
/// Each entry is `(environment_name, reason)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppError {
    pub failures: Vec<(String, FetchFailReason)>,
}

impl AppError {
    /// The synthetic "you must sign in first" error (no real Environment failed).
    pub fn needs_sign_in() -> Self {
        AppError {
            failures: vec![("(sign-in)".to_string(), FetchFailReason::NeedsSignIn)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_session_error_to_a_reason() {
        assert_eq!(
            FetchFailReason::from(&SessionError::ReauthRequired),
            FetchFailReason::NeedsSignIn
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::AccessDenied),
            FetchFailReason::AccessDenied
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::NotFound),
            FetchFailReason::NotFound
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::Throttled),
            FetchFailReason::Throttled
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::Unsupported),
            FetchFailReason::Unsupported
        );
        assert_eq!(
            FetchFailReason::from(&SessionError::Sdk { context: "GetSecretValue".into() }),
            FetchFailReason::Other
        );
    }

    #[test]
    fn describe_never_leaks_sdk_text() {
        // The Sdk catch-all carries a context string; describe() must not surface it.
        let r = FetchFailReason::from(&SessionError::Sdk { context: "hunter2".into() });
        assert!(!r.describe().contains("hunter2"));
        assert_eq!(r.describe(), "AWS error");
    }

    #[test]
    fn needs_sign_in_names_a_synthetic_environment() {
        let e = AppError::needs_sign_in();
        assert_eq!(e.failures.len(), 1);
        assert_eq!(e.failures[0].1, FetchFailReason::NeedsSignIn);
    }
}
```

- [ ] **Step 3: Run the test to verify it passes (compiles + green)**

Run: `cargo test -p janitor-aws session::tests -- --nocapture`
Expected: 3 tests pass (`maps_every_session_error_to_a_reason`, `describe_never_leaks_sdk_text`, `needs_sign_in_names_a_synthetic_environment`).

> This task is "test + minimal impl" in one file because the impl IS the unit. If the compile fails on a `SessionError` variant mismatch, the orientation list is stale — STOP and re-read `janitor-aws/src/error.rs`.

- [ ] **Step 4: Lint**

Run: `cargo clippy -p janitor-aws --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 5: Commit**

```bash
git add janitor-aws/src/session.rs janitor-aws/src/lib.rs
git commit -m "feat(aws): masked AppError/FetchFailReason for the GUI bridge (ADR 0012)"
```

---

## Task 2: `FakeReauth` test fake (additive)

**Files:**
- Modify: `janitor-aws/src/wire.rs` (the `#[cfg(test)] pub mod fakes` block)

- [ ] **Step 1: Add the fake**

In `janitor-aws/src/wire.rs`, inside `pub mod fakes { … }`, after the `FakeClock` impl and before the `#[test]` fns, add a `FakeReauth` that scripts a fixed token and counts calls (so Task 3 can assert "signed in exactly once"). It implements `crate::source::Reauth`:

```rust
    /// A scripted re-/sign-in: yields a fresh token (or a failure) and counts
    /// calls, so the Session's "sign in exactly once" contract is assertable.
    /// Additive — mirrors the private fake in `source.rs` tests; kept here so
    /// `session.rs` tests can share it without duplication.
    pub struct FakeReauth {
        pub calls: Mutex<u32>,
        pub fail: bool,
    }
    impl FakeReauth {
        pub fn ok() -> Self {
            FakeReauth { calls: Mutex::new(0), fail: false }
        }
        pub fn failing() -> Self {
            FakeReauth { calls: Mutex::new(0), fail: true }
        }
        pub fn count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }
    #[async_trait]
    impl crate::source::Reauth for FakeReauth {
        async fn sign_in(&self) -> Result<SsoToken, crate::error::SignInError> {
            *self.calls.lock().unwrap() += 1;
            if self.fail {
                Err(crate::error::SignInError::TokenEndpoint)
            } else {
                Ok(SsoToken::new(
                    "session-token".into(),
                    SystemTime::UNIX_EPOCH + Duration::from_secs(28800),
                ))
            }
        }
    }
```

- [ ] **Step 2: Add a self-test of the fake**

Inside the same `mod fakes`, add a `#[test]` near the other fake self-tests:

```rust
    #[test]
    fn fake_reauth_counts_and_can_fail() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let ok = FakeReauth::ok();
        rt.block_on(async {
            assert!(crate::source::Reauth::sign_in(&ok).await.is_ok());
        });
        assert_eq!(ok.count(), 1);

        let bad = FakeReauth::failing();
        rt.block_on(async {
            assert!(crate::source::Reauth::sign_in(&bad).await.is_err());
        });
        assert_eq!(bad.count(), 1);
    }
```

- [ ] **Step 3: Run it**

Run: `cargo test -p janitor-aws wire::fakes::fake_reauth_counts_and_can_fail -- --nocapture`
Expected: PASS. (`async_trait`, `Mutex`, `SsoToken`, `SystemTime`, `Duration` are already imported in `mod fakes`.)

- [ ] **Step 4: Confirm no existing test broke**

Run: `cargo test -p janitor-aws`
Expected: all pre-existing tests still pass (44+ now), plus the new one. This is the additive-only guarantee.

- [ ] **Step 5: Commit**

```bash
git add janitor-aws/src/wire.rs
git commit -m "test(aws): add shared FakeReauth to wire::fakes (additive)"
```

---

## Task 3: `Session` — lazy sign-in + per-Application load (whole-app error)

**Files:**
- Modify: `janitor-aws/src/session.rs`

- [ ] **Step 1: Write the failing tests**

Append to `janitor-aws/src/session.rs` (above the existing `#[cfg(test)] mod tests` add the struct + impl; then extend the test module). First, the struct and methods — insert after the `AppError` impl block and before `#[cfg(test)]`:

```rust
use std::sync::Arc;

use janitor_core::compare::Comparison;
use janitor_core::config::Application;
use janitor_core::secret::SecretShape;
use janitor_core::view::{project, MatrixView, reveal_value};
use janitor_core::compare::RowKey;

use crate::broker::CredentialBroker;
use crate::secrets::SecretsClient;
use crate::source::{AuthenticatedSource, Reauth};
use crate::types::Clock;
use crate::wire::{RoleCredentialClient, SecretsApi};

/// The GUI's authenticated session. Built from the same `Arc<dyn …>` seams as
/// `live-verify`; signs in lazily and caches the current Application's fetched
/// Sets (the only place plaintext lives on the worker side).
pub struct Session {
    reauth: Arc<dyn Reauth>,
    role_client: Arc<dyn RoleCredentialClient>,
    secrets_api: Arc<dyn SecretsApi>,
    clock: Arc<dyn Clock>,
    facade: Option<AuthenticatedSource>,
    cached: Vec<(String, SecretShape)>,
}

impl Session {
    /// Construct from the adapters. No I/O, no sign-in (lazy).
    pub fn new(
        reauth: Arc<dyn Reauth>,
        role_client: Arc<dyn RoleCredentialClient>,
        secrets_api: Arc<dyn SecretsApi>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Session {
            reauth,
            role_client,
            secrets_api,
            clock,
            facade: None,
            cached: Vec::new(),
        }
    }

    /// Whether a browser Sign-in has already happened this session.
    pub fn is_signed_in(&self) -> bool {
        self.facade.is_some()
    }

    /// Idempotent browser Sign-in: builds the broker + facade on first call
    /// from a fresh SSO token; a no-op once signed in (so it doubles as
    /// `ensure_signed_in`). The initial token comes through the same `Reauth`
    /// seam the facade uses for re-Sign-in, which is what makes this fakeable.
    pub async fn sign_in(&mut self) -> Result<(), crate::error::SignInError> {
        if self.facade.is_some() {
            return Ok(());
        }
        let token = self.reauth.sign_in().await?;
        let broker =
            CredentialBroker::new(token, Arc::clone(&self.role_client), Arc::clone(&self.clock));
        let secrets = SecretsClient::new(Arc::clone(&self.secrets_api));
        self.facade = Some(AuthenticatedSource::new(
            broker,
            secrets,
            Arc::clone(&self.reauth),
            Arc::clone(&self.role_client),
            Arc::clone(&self.clock),
        ));
        Ok(())
    }

    /// Load one Application: ensure signed in, fetch every Environment, and —
    /// if ANY Environment fails — return a whole-app error naming the failures
    /// (spec Decision 8). On full success, cache the Sets and return the masked
    /// view. The Sets (plaintext) never leave `self.cached`.
    pub async fn load(&mut self, app: &Application) -> Result<MatrixView, AppError> {
        self.sign_in().await.map_err(|_| AppError::needs_sign_in())?;
        let facade = self.facade.as_mut().expect("facade exists after sign_in");

        let mut sets: Vec<(String, SecretShape)> = Vec::new();
        let mut failures: Vec<(String, FetchFailReason)> = Vec::new();
        for m in &app.environments {
            match facade.fetch(m).await {
                Ok(shape) => sets.push((m.environment.clone(), shape)),
                Err(e) => failures.push((m.environment.clone(), FetchFailReason::from(&e))),
            }
        }
        if !failures.is_empty() {
            return Err(AppError { failures });
        }
        let view = project(&Comparison::build(&sets));
        self.cached = sets;
        Ok(view)
    }

    /// Momentary reveal of one cell's plaintext from the cached Sets, returned
    /// as an owned `String` so plaintext crosses to the UI thread only here and
    /// only on explicit request (ADR 0003). `None` if the cell is gone/absent/
    /// binary.
    pub fn reveal(&self, key: &RowKey, col: usize) -> Option<String> {
        reveal_value(&self.cached, key, col).map(|v| v.expose().to_string())
    }
}
```

Then add these tests inside the existing `#[cfg(test)] mod tests` (after the current ones). They use the fakes from Task 2:

```rust
    use crate::wire::fakes::{CredSpec, FakeClock, FakeReauth, FakeRoleClient, FakeSecretsApi};
    use crate::wire::RawSecret;
    use janitor_core::config::{Application, Mapping};
    use janitor_core::compare::{EntryState, RowKey};
    use janitor_core::secret::EntryName;
    use std::sync::Arc;
    use std::time::Duration;

    fn mapping(env: &str, secret_id: &str) -> Mapping {
        Mapping {
            environment: env.into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: secret_id.into(),
            permission_set: "ReadOnly".into(),
        }
    }
    fn cred_ok() -> Result<CredSpec, SessionError> {
        Ok(CredSpec { expires_in: Duration::from_secs(3600), tag: "t" })
    }
    fn secret_json(json: &str) -> Result<RawSecret, SessionError> {
        Ok(RawSecret { secret_string: Some(json.into()), secret_binary: None })
    }
    fn session(
        reauth: Arc<FakeReauth>,
        role: Arc<FakeRoleClient>,
        api: Arc<FakeSecretsApi>,
    ) -> Session {
        Session::new(reauth, role, api, Arc::new(FakeClock::at(0)))
    }

    #[tokio::test]
    async fn sign_in_is_idempotent_one_browser() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let mut s = session(reauth.clone(), role, api);
        assert!(!s.is_signed_in());
        s.sign_in().await.unwrap();
        s.sign_in().await.unwrap();
        assert!(s.is_signed_in());
        assert_eq!(reauth.count(), 1, "second sign_in must be a no-op");
    }

    #[tokio::test]
    async fn load_all_envs_succeed_returns_view_and_caches() {
        // Two envs, A aligned, plus a prod-only B → Gap. One mint per env, one
        // GetSecretValue per env.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let api = Arc::new(FakeSecretsApi::new(vec![
            secret_json(r#"{"A":"1","B":"x"}"#),
            secret_json(r#"{"A":"1"}"#),
        ]));
        let mut s = session(reauth, role, api);
        let app = Application {
            name: "app".into(),
            environments: vec![mapping("prod", "app/prod"), mapping("staging", "app/staging")],
        };
        let view = s.load(&app).await.unwrap();
        assert_eq!(view.environments, vec!["prod", "staging"]);
        // A is present in both & equal → Aligned; B is prod-only → Gap.
        let b = view.rows.iter().find(|r| r.name == "B").unwrap();
        assert_eq!(b.state, EntryState::Gap);
        // Cached → reveal works for A in prod (col 0).
        let key = RowKey::Entry(EntryName::from_path(&["A".to_string()]));
        assert_eq!(s.reveal(&key, 0), Some("1".to_string()));
    }

    #[tokio::test]
    async fn load_one_env_fails_is_whole_app_error_naming_it() {
        // prod succeeds, staging is AccessDenied → whole-app error, no matrix.
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![cred_ok(), cred_ok()]));
        let api = Arc::new(FakeSecretsApi::new(vec![
            secret_json(r#"{"A":"1"}"#),
            Err(SessionError::AccessDenied),
        ]));
        let mut s = session(reauth, role, api);
        let app = Application {
            name: "app".into(),
            environments: vec![mapping("prod", "app/prod"), mapping("staging", "app/staging")],
        };
        let err = s.load(&app).await.unwrap_err();
        assert_eq!(err.failures.len(), 1);
        assert_eq!(err.failures[0].0, "staging");
        assert_eq!(err.failures[0].1, FetchFailReason::AccessDenied);
    }

    #[tokio::test]
    async fn load_maps_signin_failure_to_needs_sign_in() {
        let reauth = Arc::new(FakeReauth::failing());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let mut s = session(reauth, role, api);
        let app = Application { name: "a".into(), environments: vec![mapping("prod", "a/prod")] };
        let err = s.load(&app).await.unwrap_err();
        assert_eq!(err.failures[0].1, FetchFailReason::NeedsSignIn);
    }

    #[tokio::test]
    async fn reveal_is_none_before_load_and_for_absent() {
        let reauth = Arc::new(FakeReauth::ok());
        let role = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let s = session(reauth, role, api);
        let key = RowKey::Entry(EntryName::from_path(&["A".to_string()]));
        assert!(s.reveal(&key, 0).is_none(), "nothing cached yet");
    }
```

- [ ] **Step 2: Run the tests to verify they fail (then pass)**

Because the impl is included in Step 1, run:
Run: `cargo test -p janitor-aws session -- --nocapture`
Expected: all session tests pass: `sign_in_is_idempotent_one_browser`, `load_all_envs_succeed_returns_view_and_caches`, `load_one_env_fails_is_whole_app_error_naming_it`, `load_maps_signin_failure_to_needs_sign_in`, `reveal_is_none_before_load_and_for_absent`, plus Task 1's three.

> If `EntryName::from_path` isn't found, confirm its path: it is `janitor_core::secret::EntryName` (re-exported) with `from_path(&[String]) -> EntryName` (used the same way in `janitor-core/src/view.rs` tests).

- [ ] **Step 3: Assert the secret types are `Send` (compile-time lock for the worker)**

Add this test to the same module (it makes the spec's `Send` risk a compile error if it ever regresses):

```rust
    #[test]
    fn matrixview_and_shape_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<MatrixView>();
        assert_send::<SecretShape>();
        assert_send::<AppError>();
    }
```

Run: `cargo test -p janitor-aws session::tests::matrixview_and_shape_are_send`
Expected: PASS (compiles → the bound holds).

- [ ] **Step 4: Lint + full crate test**

Run: `cargo clippy -p janitor-aws --all-targets -- -D warnings`
Run: `cargo test -p janitor-aws`
Expected: clean; all green.

- [ ] **Step 5: Commit**

```bash
git add janitor-aws/src/session.rs
git commit -m "feat(aws): Session — lazy sign-in + whole-app load + reveal (ADR 0012)"
```

---

## Task 4: GUI dependencies

**Files:**
- Modify: `janitor-gui/Cargo.toml`

- [ ] **Step 1: Add deps**

Replace the `[dependencies]` block in `janitor-gui/Cargo.toml` with:

```toml
[dependencies]
janitor-core = { path = "../janitor-core" }
janitor-aws = { path = "../janitor-aws" }
slint = "1"
tokio = { version = "1", features = ["rt", "sync", "time", "macros"] }
```

(`rt` not `rt-multi-thread`: the worker uses a single current-thread runtime. `sync` for the channel if we use `tokio::mpsc`; this plan uses `std::sync::mpsc` for UI→worker and `tokio::sync::mpsc` is not required — keep `sync` only if used. We use `std::sync::mpsc`, so `sync` can be dropped; left in for the worker's optional internal use. Final lint will catch an unused feature only via `cargo-udeps`, not clippy — leave as-is.)

- [ ] **Step 2: Verify it resolves**

Run: `cargo build -p janitor-gui`
Expected: builds (no code uses the new deps yet, so this only proves resolution). On Windows this also pulls `janitor-aws`'s AWS SDK crates into the GUI build — expect a longer first compile.

- [ ] **Step 3: Commit**

```bash
git add janitor-gui/Cargo.toml
git commit -m "build(gui): depend on janitor-aws + tokio for the worker bridge"
```

---

## Task 5: Worker module — `Command`/`Event` + the thread

**Files:**
- Create: `janitor-gui/src/worker.rs`
- Modify: `janitor-gui/src/main.rs` (add `mod worker;` near the top, after `slint::include_modules!();`)

> This is untested I/O shell (ADR 0010 §5 posture). Steps are build-and-compile, not red-green. Its correctness is proven by running the app (Task 9) — the *logic* it calls is already tested in `Session`.

- [ ] **Step 1: Declare the module**

In `janitor-gui/src/main.rs`, immediately after `slint::include_modules!();` add:

```rust
mod worker;
```

- [ ] **Step 2: Write the protocol + worker**

Create `janitor-gui/src/worker.rs`:

```rust
//! The GUI's async bridge: a worker thread owns a Tokio current-thread runtime
//! and the `janitor_aws::Session`. The UI sends `Command`s; the worker runs the
//! async Session calls and posts `Event`s back onto the Slint event loop. This
//! is untested I/O shell (ADR 0010 §5); all real logic lives in `Session`.

use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

use janitor_aws::aws_impl::{AwsOidcClient, AwsRoleClient, AwsSecretsApi};
use janitor_aws::authenticator::Authenticator;
use janitor_aws::session::{AppError, Session};
use janitor_aws::types::SystemClock;
use janitor_core::compare::RowKey;
use janitor_core::config::{Application, Config};
use janitor_core::view::MatrixView;

/// UI → worker.
pub enum Command {
    SignIn,
    LoadApp(Application),
    Reveal { row: usize, col: usize, key: RowKey },
    Shutdown,
}

/// Worker → UI. Rendered by `apply_event` on the UI thread.
pub enum Event {
    SignInStarted,
    SignedIn,
    SignInFailed(String),
    AppLoading,
    AppLoaded(MatrixView),
    AppFailed(AppError),
    Revealed { row: usize, col: usize, text: String },
    RevealUnavailable,
}

/// Spawn the worker. `on_event` is invoked (on the UI thread, via the caller's
/// marshalling) for each emitted Event. Returns the command Sender.
///
/// `config` supplies the org locations (`sso_start_url` as the issuer URL,
/// `sso_region` for the SDK clients). Adapters are built once at startup; the
/// browser Sign-in is deferred to the first `SignIn`/`LoadApp` (lazy).
pub fn spawn(
    config: Config,
    on_event: impl Fn(Event) + Send + 'static,
) -> Sender<Command> {
    let (tx, rx) = std::sync::mpsc::channel::<Command>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build worker runtime");
        rt.block_on(async move {
            let mut session = build_session(&config).await;
            run_loop(rx, &mut session, &on_event).await;
        });
    });
    tx
}

/// Build the real adapters (no ambient credentials — ADR 0010 §10) and the
/// lazy `Session`. Mirrors `live-verify` steps 2 + facade assembly, minus
/// discovery.
async fn build_session(config: &Config) -> Session {
    let oidc = Arc::new(AwsOidcClient::new(config.sso_region.clone()).await);
    let role_client = Arc::new(AwsRoleClient::new(config.sso_region.clone()).await);
    let secrets_api = Arc::new(AwsSecretsApi::new());
    let clock = Arc::new(SystemClock);
    // `sso_start_url` holds the SSO start URL (AWS' term); passed as RegisterClient
    // `issuerUrl`. Must be the instance form (…/ssoins-…), not the portal …/start.
    let authenticator = Arc::new(Authenticator::new(oidc, config.sso_start_url.clone()));
    Session::new(authenticator, role_client, secrets_api, clock)
}

async fn run_loop(
    rx: Receiver<Command>,
    session: &mut Session,
    on_event: &(impl Fn(Event) + Send + 'static),
) {
    // `recv()` is blocking; that is fine on the worker's own thread.
    while let Ok(cmd) = rx.recv() {
        match cmd {
            Command::Shutdown => break,
            Command::SignIn => {
                on_event(Event::SignInStarted);
                match session.sign_in().await {
                    Ok(()) => on_event(Event::SignedIn),
                    Err(e) => on_event(Event::SignInFailed(e.to_string())),
                }
            }
            Command::LoadApp(app) => {
                on_event(Event::AppLoading);
                match session.load(&app).await {
                    Ok(view) => on_event(Event::AppLoaded(view)),
                    Err(e) => on_event(Event::AppFailed(e)),
                }
            }
            Command::Reveal { row, col, key } => match session.reveal(&key, col) {
                Some(text) => on_event(Event::Revealed { row, col, text }),
                None => on_event(Event::RevealUnavailable),
            },
        }
    }
}
```

- [ ] **Step 3: Build**

Run: `cargo build -p janitor-gui`
Expected: compiles. `main.rs` doesn't call `worker::spawn` yet (Task 8), so `dead_code` warnings on `Command`/`Event` variants are expected — that's fine until Task 8 wires them. (If the build fails on `SignInError: Display`, note it derives `thiserror::Error` → `Display` is present.)

- [ ] **Step 4: Commit**

```bash
git add janitor-gui/src/worker.rs janitor-gui/src/main.rs
git commit -m "feat(gui): worker thread + Command/Event protocol over Session (ADR 0012)"
```

---

## Task 6: Slint UI — SSO label, auth/loading/error states, Sign-in button

**Files:**
- Modify: `janitor-gui/ui/app.slint`

> Shell. Build-and-eyeball. The matrix/reveal structure already exists; this adds state chrome and renames one label.

- [ ] **Step 1: Add state inputs + callbacks to `MainWindow`**

In `janitor-gui/ui/app.slint`, add these properties/callbacks to the `MainWindow` interface block (next to the existing `in property`/`callback` declarations, e.g. after `callback select-app(int);`):

```slint
    // Auth / load state (driven by the worker). status: one of
    // "unauth" | "signing" | "loading" | "loaded" | "error".
    in property <string> status: "unauth";
    in property <string> status-message;        // banner text for "error"/"signing"
    callback sign-in();
    callback refresh();
```

- [ ] **Step 2: Relabel the SSO field (Decision 5)**

Change the settings Start URL label (currently `Text { text: "Start URL"; … }`):

```slint
                Text { text: "SSO start URL"; color: #c8ccd4; width: 120px; }
```

- [ ] **Step 3: Add the header Sign-in/Refresh control + status banner**

Replace the main-pane header `HorizontalLayout` (the one containing `"Payments matrix"` + the Settings button) with a state-aware version, and add a banner row beneath it:

```slint
            HorizontalLayout {
                Text {
                    text: root.status == "loaded" ? "Drift matrix"
                        : root.status == "loading" ? "Loading…"
                        : root.status == "signing" ? "Signing in…"
                        : "Not signed in";
                    color: #c8ccd4;
                    horizontal-stretch: 1;
                }
                if root.status == "unauth" || root.status == "error" : Button {
                    text: "Sign in";
                    clicked => { root.sign-in(); }
                }
                if root.status == "loaded" : Button {
                    text: "Refresh";
                    clicked => { root.refresh(); }
                }
                Button {
                    text: root.settings-open ? "Close settings" : "Settings";
                    clicked => { root.toggle-settings(); }
                }
            }

            if root.status == "error" || (root.status == "signing" && root.status-message != "") : Rectangle {
                height: 28px;
                background: root.status == "error" ? #3a1d1d : #1d2a3a;
                HorizontalLayout {
                    padding: 6px;
                    Text {
                        text: root.status-message;
                        color: root.status == "error" ? #e0a3a3 : #a3c0e0;
                        overflow: elide;
                    }
                }
            }
```

- [ ] **Step 4: Show a placeholder instead of the matrix when not loaded**

Wrap the existing environments-header + `ScrollView` matrix block so it only shows when `status == "loaded"`, with a placeholder otherwise. Put the existing `HorizontalLayout { … "ENTRY" … }` and the `ScrollView { … }` inside:

```slint
            if root.status == "loaded" : VerticalLayout {
                spacing: 6px;
                // ↓ the existing ENTRY header HorizontalLayout goes here
                // ↓ the existing ScrollView { … } goes here
            }
            if root.status != "loaded" : Rectangle {
                vertical-stretch: 1;
                Text {
                    text: root.status == "unauth" ? "Sign in to load this Application's secrets."
                        : root.status == "signing" ? "A browser tab has opened — complete sign-in there."
                        : root.status == "loading" ? "Fetching secrets…"
                        : "Could not load. See the message above, then Sign in to retry.";
                    color: #6b7280;
                    horizontal-alignment: center;
                    vertical-alignment: center;
                }
            }
```

(Move the existing two blocks verbatim into the `if status == "loaded"` layout. Don't duplicate them.)

- [ ] **Step 5: Build**

Run: `cargo build -p janitor-gui`
Expected: compiles. The new callbacks (`sign-in`, `refresh`) are not yet bound in `main.rs` — Slint generates them; binding happens in Task 8. (Unbound callbacks are fine; they just do nothing if invoked.)

- [ ] **Step 6: Commit**

```bash
git add janitor-gui/ui/app.slint
git commit -m "feat(gui): auth/loading/error chrome + 'SSO start URL' label (ADR 0012)"
```

---

## Task 7: Slint UI — minimal per-Environment Mapping editor (Decision 4)

**Files:**
- Modify: `janitor-gui/ui/app.slint`

> Minimal editor: existing Environments are shown with a per-row Remove; a single "add environment" form (5 fields) appends to the selected Application; "Add application" creates an empty one. Editing = remove + re-add (keeps the Slint bounded — no two-way model binding).

- [ ] **Step 1: Add an EnvRow struct + inputs/callbacks**

At the top of `app.slint` (next to the other `export struct`s), add:

```slint
export struct EnvRow {
    environment: string,
    account_id: string,
    region: string,
    secret_id: string,
    permission_set: string,
}
```

Add to `MainWindow`:

```slint
    // Environments of the currently-selected Application, for the editor.
    in property <[EnvRow]> selected-envs;
    callback add-env(string, string, string, string, string); // env, account, region, secret_id, perm
    callback remove-env(int);
```

- [ ] **Step 2: Replace the settings "Applications" block**

In the settings overlay, replace the existing `Text { text: "Applications"; … }` + the `for app[i] in apps` row list + the add-by-name `HorizontalLayout`, with this editor (it keeps the app list with Remove, adds the selected app's environments + an add-env form):

```slint
            Text { text: "Applications"; color: #8a8f98; }
            for app[i] in apps : HorizontalLayout {
                spacing: 8px;
                Text {
                    text: app.name + (app.selected ? "  (selected)" : "");
                    color: app.selected ? #ffd479 : white;
                    horizontal-stretch: 1;
                }
                Button { text: "Select"; clicked => { root.select-app(i); } }
                Button { text: "Remove"; clicked => { root.remove-app(i); } }
            }
            HorizontalLayout {
                spacing: 8px;
                new-app := LineEdit { placeholder-text: "New Application name"; horizontal-stretch: 1; }
                Button { text: "Add application"; clicked => { root.add-app(new-app.text); } }
            }

            Text { text: "Environments of the selected Application"; color: #8a8f98; }
            for env[i] in selected-envs : HorizontalLayout {
                spacing: 8px;
                Text { text: env.environment; color: white; width: 90px; }
                Text { text: env.account-id; color: #9aa0aa; width: 130px; }
                Text { text: env.region; color: #9aa0aa; width: 90px; }
                Text { text: env.secret-id; color: #9aa0aa; horizontal-stretch: 1; overflow: elide; }
                Button { text: "Remove"; clicked => { root.remove-env(i); } }
            }
            HorizontalLayout {
                spacing: 6px;
                e-env := LineEdit { placeholder-text: "env (prod)"; width: 90px; }
                e-acct := LineEdit { placeholder-text: "account id"; width: 130px; }
                e-region := LineEdit { placeholder-text: "region"; width: 90px; }
                e-secret := LineEdit { placeholder-text: "secret id / ARN"; horizontal-stretch: 1; }
                e-perm := LineEdit { placeholder-text: "permission set"; width: 130px; }
                Button {
                    text: "Add env";
                    clicked => {
                        root.add-env(e-env.text, e-acct.text, e-region.text, e-secret.text, e-perm.text);
                    }
                }
            }
```

- [ ] **Step 3: Build**

Run: `cargo build -p janitor-gui`
Expected: compiles. New callbacks unbound until Task 8.

- [ ] **Step 4: Commit**

```bash
git add janitor-gui/ui/app.slint
git commit -m "feat(gui): minimal per-Environment Mapping editor (ADR 0012)"
```

---

## Task 8: `main.rs` — backend abstraction, state machine, event handling

**Files:**
- Modify: `janitor-gui/src/main.rs`

> The heart of the wiring. A `Backend` enum hides mock-vs-real behind one `dispatch`; one `apply_event` updates the UI for both. Drift-count fix included. Still shell (verified by running in Task 9), but each piece calls already-tested `Session`/core logic.

- [ ] **Step 1: Imports + backend + state**

At the top of `main.rs`, after `mod worker;`, add imports and replace the `use` block as needed:

```rust
use std::env;
use std::sync::mpsc::Sender;

use janitor_aws::session::AppError;
use janitor_core::compare::{Comparison, EntryState, RowKey};
use janitor_core::config::{Application, Config, Mapping};
use janitor_core::mock::MockSource;
use janitor_core::secret::SecretShape;
use janitor_core::source::SecretSource;
use janitor_core::view::{project, reveal_value, sort_rows, MatrixView, SortKey};

use worker::{Command, Event};
```

(Keep the existing `slint::*`, `Rc`, `RefCell`, `Duration` imports; drop any now-unused ones at the final clippy step.)

Add a backend that serves the SAME `Event`s for mock and real:

```rust
/// Where matrix data comes from. Both arms feed the one `apply_event` path.
enum Backend {
    /// Real AWS via the worker thread.
    Real(Sender<Command>),
    /// Offline: MockSource, served synchronously on the UI thread. Holds the
    /// last-loaded Sets so reveal works without a worker.
    Mock {
        source: MockSource,
        cached: RefCell<Vec<(String, SecretShape)>>,
    },
}
```

- [ ] **Step 2: AppState + the mock dispatch + apply_event**

Replace the existing `Preferences`/`AppState`/`render` region with state that tracks the matrix + status, and add `dispatch`/`apply_event`. Keep `Preferences` as-is and extend `AppState`:

```rust
struct Preferences {
    sort: SortKey,
    auto_hide_secs: u64,
    dark: bool,
}

struct AppState {
    backend: Backend,
    config: Config,
    selected: usize,
    prefs: Preferences,
    /// Current masked view (empty until an app loads).
    view: MatrixView,
    /// "unauth" | "signing" | "loading" | "loaded" | "error".
    status: String,
}

/// Send a command to whichever backend is active. Mock serves it inline by
/// invoking `apply_event` synchronously; real forwards to the worker (whose
/// replies arrive via `upgrade_in_event_loop`).
fn dispatch(ui: &MainWindow, state: &Rc<RefCell<AppState>>, cmd: Command) {
    let is_mock = matches!(state.borrow().backend, Backend::Mock { .. });
    if is_mock {
        // Synchronous mock: translate the command to event(s) immediately.
        match cmd {
            Command::SignIn => apply_event(ui, state, Event::SignedIn),
            Command::LoadApp(app) => {
                let view = {
                    let st = state.borrow();
                    let Backend::Mock { source, cached } = &st.backend else { unreachable!() };
                    let sets: Vec<(String, SecretShape)> = app
                        .environments
                        .iter()
                        .map(|m| (m.environment.clone(), source.fetch(m).expect("mock never fails")))
                        .collect();
                    let v = project(&Comparison::build(&sets));
                    *cached.borrow_mut() = sets;
                    v
                };
                apply_event(ui, state, Event::AppLoaded(view));
            }
            Command::Reveal { row, col, key } => {
                let ev = {
                    let st = state.borrow();
                    let Backend::Mock { cached, .. } = &st.backend else { unreachable!() };
                    match reveal_value(&cached.borrow(), &key, col).map(|v| v.expose().to_string()) {
                        Some(text) => Event::Revealed { row, col, text },
                        None => Event::RevealUnavailable,
                    }
                };
                apply_event(ui, state, ev);
            }
            Command::Shutdown => {}
        }
    } else if let Backend::Real(tx) = &state.borrow().backend {
        let _ = tx.send(cmd);
    }
}

/// Apply one Event to the UI + state. Called on the UI thread (directly for
/// mock; via `upgrade_in_event_loop` for the worker).
fn apply_event(ui: &MainWindow, state: &Rc<RefCell<AppState>>, ev: Event) {
    match ev {
        Event::SignInStarted => set_status(ui, state, "signing", ""),
        Event::SignedIn => {
            // Auto-load the selected app once signed in.
            let app = { let st = state.borrow(); st.config.applications.get(st.selected).cloned() };
            if let Some(app) = app {
                dispatch(ui, state, Command::LoadApp(app));
            } else {
                set_status(ui, state, "loaded", "");
            }
        }
        Event::SignInFailed(msg) => set_status(ui, state, "error", &format!("Sign-in failed: {msg}")),
        Event::AppLoading => set_status(ui, state, "loading", ""),
        Event::AppLoaded(mut view) => {
            let sort = state.borrow().prefs.sort;
            sort_rows(&mut view, sort);
            state.borrow_mut().view = view;
            set_status(ui, state, "loaded", "");
            push_matrix(ui, state);
        }
        Event::AppFailed(err) => set_status(ui, state, "error", &banner(&err)),
        Event::Revealed { row, col, text } => {
            ui.set_revealed_row(row as i32);
            ui.set_revealed_col(col as i32);
            ui.set_revealed_text(text.into());
            schedule_auto_hide(ui, state);
        }
        Event::RevealUnavailable => { /* leave masked */ }
    }
}

/// "<env>: <reason>; …" — no SDK text (reasons come from the tested describe()).
fn banner(err: &AppError) -> String {
    err.failures
        .iter()
        .map(|(env, r)| format!("{env}: {}", r.describe()))
        .collect::<Vec<_>>()
        .join("; ")
}

fn set_status(ui: &MainWindow, state: &Rc<RefCell<AppState>>, status: &str, msg: &str) {
    state.borrow_mut().status = status.to_string();
    ui.set_status(status.into());
    ui.set_status_message(msg.into());
}
```

- [ ] **Step 3: Matrix push, drift fix, reveal scheduling**

Add the rendering helpers. **Drift-count fix:** sidebar badges only for the loaded selected app (no per-app refetch).

```rust
/// Push the current view's rows/envs + sidebar into the UI.
fn push_matrix(ui: &MainWindow, state: &Rc<RefCell<AppState>>) {
    // Clear any stale reveal whenever the matrix changes (ADR 0003).
    ui.set_revealed_row(-1);
    ui.set_revealed_col(-1);
    ui.set_revealed_text(SharedString::new());
    let st = state.borrow();
    ui.set_environments(env_models(&st.view));
    ui.set_rows(to_row_models(&st.view));
    ui.set_apps(app_models(&st.config, st.selected, &st.view, &st.status));
    ui.set_selected_envs(env_rows(&st.config, st.selected));
}

/// Sidebar items. Drift badge shows ONLY for the selected, loaded app — never a
/// per-app refetch (that would be a sign-in/GetSecretValue storm on real AWS).
fn app_models(config: &Config, selected: usize, view: &MatrixView, status: &str) -> ModelRc<AppItem> {
    let items: Vec<AppItem> = config
        .applications
        .iter()
        .enumerate()
        .map(|(i, app)| {
            let drift = if i == selected && status == "loaded" {
                let n = view.rows.iter().filter(|r| r.state == EntryState::Drift).count();
                if n > 0 { format!("{n} drift").into() } else { SharedString::new() }
            } else {
                SharedString::new()
            };
            AppItem {
                name: app.name.clone().into(),
                subtitle: format!("{} envs", app.environments.len()).into(),
                drift,
                selected: i == selected,
            }
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(items)))
}

/// Editor rows for the selected app's environments.
fn env_rows(config: &Config, selected: usize) -> ModelRc<EnvRow> {
    let rows: Vec<EnvRow> = config
        .applications
        .get(selected)
        .map(|app| {
            app.environments
                .iter()
                .map(|m| EnvRow {
                    environment: m.environment.clone().into(),
                    account_id: m.account_id.clone().into(),
                    region: m.region.clone().into(),
                    secret_id: m.secret_id.clone().into(),
                    permission_set: m.permission_set.clone().into(),
                })
                .collect()
        })
        .unwrap_or_default();
    ModelRc::from(Rc::new(VecModel::from(rows)))
}

fn schedule_auto_hide(ui: &MainWindow, state: &Rc<RefCell<AppState>>) {
    let secs = state.borrow().prefs.auto_hide_secs;
    let ui_weak = ui.as_weak();
    slint::Timer::single_shot(Duration::from_secs(secs), move || {
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_revealed_text(SharedString::new());
            ui.set_revealed_row(-1);
            ui.set_revealed_col(-1);
        }
    });
}
```

(Keep the existing `to_row_models`, `env_models`, `dots`, `glyph_for`, `state_label` fns unchanged.)

- [ ] **Step 4: `main()` — choose backend, wire callbacks**

Replace `fn main()` with the backend-aware version:

```rust
fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;

    let mock = env::var("JANITOR_MOCK").is_ok() || env::args().any(|a| a == "--mock");
    let config = if mock { seeded_config() } else { Config::load().unwrap_or_default() };

    let state = Rc::new(RefCell::new(AppState {
        backend: Backend::Mock { source: MockSource::new(), cached: RefCell::new(Vec::new()) },
        config: config.clone(),
        selected: 0,
        prefs: Preferences { sort: SortKey::Name, auto_hide_secs: 5, dark: true },
        view: MatrixView { environments: Vec::new(), rows: Vec::new() },
        status: "unauth".to_string(),
    }));

    // Real backend: spawn the worker, marshalling its Events onto the UI loop.
    if !mock {
        let ui_weak = ui.as_weak();
        let state_for_events = state.clone();
        let tx = worker::spawn(config.clone(), move |ev| {
            let state = state_for_events.clone();
            let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                apply_event(&ui, &state, ev);
            });
        });
        state.borrow_mut().backend = Backend::Real(tx);
    }

    // Initial chrome.
    {
        let st = state.borrow();
        ui.set_sso_start_url(st.config.sso_start_url.as_str().into());
        ui.set_sso_region(st.config.sso_region.as_str().into());
        ui.set_dark(st.prefs.dark);
        ui.set_status(st.status.as_str().into());
    }
    push_matrix(&ui, &state);
    // Mock opens already "signed in" → load the first app immediately.
    if mock {
        if let Some(app) = state.borrow().config.applications.first().cloned() {
            dispatch(&ui, &state, Command::LoadApp(app));
        }
    }

    // Sign in.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_sign_in(move || dispatch(&ui_weak.unwrap(), &state, Command::SignIn));
    }
    // Refresh (reload selected app).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_refresh(move || {
            let app = { let st = state.borrow(); st.config.applications.get(st.selected).cloned() };
            if let Some(app) = app { dispatch(&ui_weak.unwrap(), &state, Command::LoadApp(app)); }
        });
    }
    // Sidebar selection → load that app (real: only if signed in; else prompt).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_select_app(move |index| {
            let ui = ui_weak.unwrap();
            state.borrow_mut().selected = index as usize;
            let (app, signed) = {
                let st = state.borrow();
                let signed = st.status == "loaded" || st.status == "loading"
                    || matches!(st.backend, Backend::Mock { .. });
                (st.config.applications.get(index as usize).cloned(), signed)
            };
            if let (Some(app), true) = (app, signed) {
                dispatch(&ui, &state, Command::LoadApp(app));
            } else {
                push_matrix(&ui, &state); // just update sidebar selection
            }
        });
    }
    // Reveal → round-trip (real) or inline (mock); both via dispatch.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_reveal_cell(move |row, col| {
            let ui = ui_weak.unwrap();
            let key = {
                let st = state.borrow();
                st.view.rows.get(row as usize).map(|r| r.key.clone())
            };
            if let Some(key) = key {
                dispatch(&ui, &state, Command::Reveal { row: row as usize, col: col as usize, key });
            }
        });
    }
    // Settings toggle.
    {
        let ui_weak = ui.as_weak();
        ui.on_toggle_settings(move || {
            let ui = ui_weak.unwrap();
            ui.set_settings_open(!ui.get_settings_open());
        });
    }
    // Save SSO fields → config + persist (real only; mock is ephemeral).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_save_sso(move || {
            let ui = ui_weak.unwrap();
            let mut st = state.borrow_mut();
            st.config.sso_start_url = ui.get_sso_start_url().to_string();
            st.config.sso_region = ui.get_sso_region().to_string();
            if !matches!(st.backend, Backend::Mock { .. }) { let _ = st.config.save(); }
        });
    }
    // Add application (empty).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_add_app(move |name| {
            let name = name.trim().to_string();
            if name.is_empty() { return; }
            {
                let mut st = state.borrow_mut();
                st.config.applications.push(Application { name, environments: Vec::new() });
                st.selected = st.config.applications.len() - 1;
                if !matches!(st.backend, Backend::Mock { .. }) { let _ = st.config.save(); }
            }
            push_matrix(&ui_weak.unwrap(), &state);
        });
    }
    // Remove application (clamp selection).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_remove_app(move |index| {
            let index = index as usize;
            {
                let mut st = state.borrow_mut();
                if index < st.config.applications.len() {
                    st.config.applications.remove(index);
                    if st.selected >= st.config.applications.len() && !st.config.applications.is_empty() {
                        st.selected = st.config.applications.len() - 1;
                    }
                    if !matches!(st.backend, Backend::Mock { .. }) { let _ = st.config.save(); }
                }
            }
            push_matrix(&ui_weak.unwrap(), &state);
        });
    }
    // Add environment to the selected application.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_add_env(move |env, account, region, secret, perm| {
            let env = env.trim().to_string();
            if env.is_empty() { return; }
            {
                let mut st = state.borrow_mut();
                let selected = st.selected;
                if let Some(app) = st.config.applications.get_mut(selected) {
                    app.environments.push(Mapping {
                        environment: env,
                        account_id: account.trim().to_string(),
                        region: region.trim().to_string(),
                        secret_id: secret.trim().to_string(),
                        permission_set: perm.trim().to_string(),
                    });
                }
                if !matches!(st.backend, Backend::Mock { .. }) { let _ = st.config.save(); }
            }
            push_matrix(&ui_weak.unwrap(), &state);
        });
    }
    // Remove environment.
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_remove_env(move |index| {
            let index = index as usize;
            {
                let mut st = state.borrow_mut();
                let selected = st.selected;
                if let Some(app) = st.config.applications.get_mut(selected) {
                    if index < app.environments.len() { app.environments.remove(index); }
                }
                if !matches!(st.backend, Backend::Mock { .. }) { let _ = st.config.save(); }
            }
            push_matrix(&ui_weak.unwrap(), &state);
        });
    }
    // Theme / sort / auto-hide (unchanged behavior).
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_set_theme(move |dark| {
            state.borrow_mut().prefs.dark = dark;
            ui_weak.unwrap().set_dark(dark);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let state = state.clone();
        ui.on_set_sort(move |index| {
            state.borrow_mut().prefs.sort = if index == 1 { SortKey::GapFirst } else { SortKey::Name };
            // Re-sort the current view in place.
            {
                let mut st = state.borrow_mut();
                let sort = st.prefs.sort;
                sort_rows(&mut st.view, sort);
            }
            push_matrix(&ui_weak.unwrap(), &state);
        });
    }
    {
        let state = state.clone();
        ui.on_set_auto_hide(move |secs| {
            state.borrow_mut().prefs.auto_hide_secs = secs.max(1) as u64;
        });
    }

    ui.run()
}
```

- [ ] **Step 5: Build + lint**

Run: `cargo build -p janitor-gui`
Run: `cargo clippy -p janitor-gui --all-targets -- -D warnings`
Expected: compiles clean. Remove any now-unused imports flagged by clippy (e.g. if `fetch_sets`/`build_app` from the old code are gone, delete them; they are replaced by `dispatch`/mock path). Delete the old `render`, `fetch_sets`, `build_app`, `drift_count` fns if clippy flags them unused.

- [ ] **Step 6: Commit**

```bash
git add janitor-gui/src/main.rs
git commit -m "feat(gui): backend abstraction + state machine + drift-count fix (ADR 0012)"
```

---

## Task 9: Verify the app runs (mock, then note the live path)

**Files:** none (verification).

- [ ] **Step 1: Run the mock GUI**

Run: `$env:JANITOR_MOCK=1; cargo run -p janitor-gui`
Expected: window opens; first app's masked matrix shows immediately (status "loaded"); sidebar shows the seeded apps; the selected app shows a "N drift" badge. Clicking a cell reveals plaintext for ~5s then re-masks. Switching apps reloads instantly. Open Settings → the label reads "SSO start URL"; the Environments editor lists the selected app's envs with Remove; "Add env" appends a row.

> If the window doesn't open, this is the Slint/winit shell — check the console for a platform error, not a logic bug.

- [ ] **Step 2: Confirm the real path compiles & is reachable (no live AWS in CI)**

Run: `cargo run -p janitor-gui` (no mock) **only in a real desktop session with a configured org** — this opens a browser on "Sign in". In CI/headless, skip; the compile in Task 8 already proves the path builds. Document in the commit that live verification is human-gated (next session, like `live-verify`).

- [ ] **Step 3: Commit (verification note only, if anything was tweaked)**

If Steps 1–2 required a fix, commit it with `fix(gui): …`. Otherwise no commit.

---

## Task 10: ADR 0012

**Files:**
- Create: `docs/adr/0012-gui-aws-bridge-worker-and-lazy-sign-in.md`

- [ ] **Step 1: Write the ADR**

Create `docs/adr/0012-gui-aws-bridge-worker-and-lazy-sign-in.md` following the existing ADR format (see 0010/0011):

```markdown
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
- Live re-verification (browser + real org) is human-gated, like `live-verify`,
  and deferred to a hands-on session.
- **Deferred (unchanged from spec):** discovery-driven column assembly,
  per-column error rendering, and the typed `GetSecretValue` error mapping
  (separate Milestone-B follow-up).
```

- [ ] **Step 2: Commit**

```bash
git add docs/adr/0012-gui-aws-bridge-worker-and-lazy-sign-in.md
git commit -m "docs: ADR 0012 — GUI↔AWS bridge (worker thread + lazy sign-in)"
```

---

## Task 11: Docs + example-URL cleanup

> Closes the spec's "Out-of-scope cleanups intentionally included" #2: the
> misleading **portal-form** example URLs. The `authenticator.rs` doc comment is
> in the real auth path and is now actively wrong (Milestone B #1 proved the
> portal `…/start` URL is rejected by `RegisterClient`); the mock seed is
> cosmetic. Both corrected to the instance form `https://identitycenter.amazonaws.com/ssoins-…`.

**Files:**
- Modify: `CLAUDE.md`, `README.md`
- Modify: `janitor-aws/src/authenticator.rs` (doc comment), `janitor-gui/src/main.rs` (`seeded_config` mock URL)

- [ ] **Step 1: Update the CLAUDE.md status banner**

In `CLAUDE.md`, update the top status blockquote to note the bridge landed: the GUI now reads real AWS via a worker-threaded `janitor-aws::Session` (lazy sign-in; `JANITOR_MOCK=1` for offline), with the matrix fed one Application at a time; reference ADR 0012. Change "**Not yet wired:** the GUI still reads the mock source…" to reflect it is now wired (mock behind a flag), and move discovery/per-column/typed-error to the deferred list.

- [ ] **Step 2: Update commands**

In `CLAUDE.md` Commands and `README.md`, add:

```bash
cargo run -p janitor-gui                 # real AWS (browser sign-in; needs a configured org)
$env:JANITOR_MOCK=1; cargo run -p janitor-gui   # offline mock (Windows PowerShell)
JANITOR_MOCK=1 cargo run -p janitor-gui          # offline mock (bash)
```

- [ ] **Step 3: Fix the misleading `Authenticator` doc comment**

In `janitor-aws/src/authenticator.rs`, the `issuer_url` field doc currently reads `e.g. https://my-org.awsapps.com/start` — the portal form `RegisterClient` rejects (Milestone B #1). Replace that doc comment (the `/// The org's IAM Identity Center start/issuer URL …` block above `issuer_url: String,`) with:

```rust
    /// The org's IAM Identity Center **SSO start URL** — the *instance* form
    /// `https://identitycenter.amazonaws.com/ssoins-…` from AWS' Get-credentials
    /// dialog, NOT the portal `https://<dir>.awsapps.com/start` URL (the portal
    /// form is rejected by `RegisterClient` as "Invalid start url" — Milestone B,
    /// ADR 0011). Passed to `RegisterClient` as `issuerUrl`; the `/authorize`
    /// endpoint comes back in the registration (with a region fallback).
    issuer_url: String,
```

Run: `cargo build -p janitor-aws`
Expected: compiles (comment-only change).

- [ ] **Step 4: Fix the mock seed example URL**

In `janitor-gui/src/main.rs`, `seeded_config()` sets `sso_start_url: "https://acme.awsapps.com/start".into(),` — change it to the instance form so the offline mock doesn't model a URL that would fail live:

```rust
        sso_start_url: "https://identitycenter.amazonaws.com/ssoins-mockmock0000".into(),
```

Run: `cargo build -p janitor-gui`
Expected: compiles (cosmetic; the mock path never calls AWS).

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md README.md janitor-aws/src/authenticator.rs janitor-gui/src/main.rs
git commit -m "docs: GUI reads real AWS via the worker bridge + fix portal-form URLs (ADR 0012)"
```

---

## Task 12: Full-workspace verification

**Files:** none.

- [ ] **Step 1: Format**

Run: `cargo fmt --all`
Then: `cargo fmt --all -- --check`
Expected: no diff.

- [ ] **Step 2: Lint everything**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: clean across all three crates.

- [ ] **Step 3: Test everything**

Run: `cargo test --workspace`
Expected: all green — `janitor-core` (unchanged count), `janitor-aws` (prior count + Task 1/2/3 additions), `janitor-gui` (none/shell). Confirm `test result: ok` for each crate (ignore the red `NativeCommandError` on the "Finished" line).

- [ ] **Step 4: Coverage gate (core only, unaffected)**

Run: `cargo llvm-cov -p janitor-core`
Expected: ≥80% (this slice didn't touch core; the gate should be unchanged).

- [ ] **Step 5: Run the mock once more end-to-end**

Run: `$env:JANITOR_MOCK=1; cargo run -p janitor-gui`
Expected: matrix loads, reveal works, editor works, no panics. Close the window.

- [ ] **Step 6: Final commit (if fmt/clippy touched anything)**

```bash
git add -A
git commit -m "style: cargo fmt + clippy clean across the workspace (ADR 0012)"
```

---

## Done criteria

- `Session` (lazy sign-in, whole-app load, reveal) is unit-tested against fakes; `FetchFailReason`/`AppError` masked-error mapping is tested; `Send` of `MatrixView`/`SecretShape`/`AppError` is asserted at compile time.
- `janitor-gui` shows the masked matrix from real AWS for one Application at a time, signing in lazily off the UI thread; secrets live only in the worker; reveal round-trips; partial failure is a whole-app banner.
- `JANITOR_MOCK=1` runs offline.
- "SSO start URL" label; manual per-Environment Mapping editor; `Config` load/save wired.
- `cargo fmt --check`, `cargo clippy --all-targets -D warnings`, `cargo test --workspace` all green; core coverage ≥80%.
- ADR 0012 + docs updated. Live verification (browser + real org) is human-gated and explicitly deferred to a hands-on session (the remaining Milestone-B checklist items and the typed `GetSecretValue` mapping are unchanged, separate follow-ups).
