# Identity Center Auth (Headless Vertical Slice) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the headless vertical slice from [ADR 0010](../../adr/0010-aws-adapter-crate-and-auth-object-model.md): a browser PKCE Sign-in → in-memory SSO token → `GetRoleCredentials` for one Environment → one `GetSecretValue` → `SecretShape` → masked print, in a new `janitor-aws` crate, with all refresh/error/parse logic tested against fakes and only the browser/loopback shell left untested.

**Architecture:** A third workspace crate `janitor-aws` (async/tokio) depends on `janitor-core` for domain types. Three decomposed objects (`Authenticator`, `CredentialBroker`, `SecretsClient`), each behind a narrow SDK-wrapping trait whose I/O are our own SDK-free owned types, are composed by a thin **tested** `AuthenticatedSource` facade that owns the orchestration (chained escalation, at-most-once caps). Real impls wrap the AWS SDK; fakes drive unit tests. `janitor-core` is untouched.

**Tech Stack:** Rust 2021, tokio, `aws-config` / `aws-sdk-ssooidc` / `aws-sdk-sso` / `aws-sdk-secretsmanager`, `secrecy` (zeroizing), `sha2` + `base64` (PKCE), `rand` (PKCE/state nonces), `open` (browser launch), `tokio::net::TcpListener` (one-shot loopback), `thiserror`.

**Read before starting:** ADR 0010 (the design this implements), ADR 0002 (the auth decision), `docs/THREAT-MODEL.md`, `CONTEXT.md` (glossary: Sign-in, Session, Credential), and the memory note `subagent-execution-gotchas` (forbid branch-changing git in subagent prompts; trust `cargo` over stale red-phase diagnostics).

**Two key conventions this plan follows:**
1. **The tested surface has zero placeholders.** Pure functions, the broker, the facade, the secrets mapping, the error taxonomy, and all *fakes* are given in full. The only code that references the AWS SDK API directly is the untestable adapter shell (Tasks 12–14); there, exact SDK method/field names must be confirmed against the *installed* `docs.rs/aws-sdk-ssooidc` (etc.) version, because the SDK — not our logic — owns those shapes. That is the boundary ADR 0010 §5 calls "the only untested code," not a plan placeholder.
2. **Surface any test-behavior change.** Per the user's global rule, if at any point an existing test's asserted behavior changes, STOP and surface it before proceeding. This slice only *adds* tests and a new crate; `janitor-core` and `janitor-gui` are not modified, so no existing test should change. If you find yourself editing an existing test, that is a red flag — stop and report.

---

## File structure

**New crate `janitor-aws/`** (joins workspace `members`):

| File | Responsibility |
|---|---|
| `janitor-aws/Cargo.toml` | Crate manifest + deps |
| `janitor-aws/src/lib.rs` | Module wiring + crate-level docs |
| `janitor-aws/src/pkce.rs` | PKCE verifier + S256 challenge + base64url (pure, tested) |
| `janitor-aws/src/state.rs` | CSRF `state` nonce gen + verify (pure, tested) |
| `janitor-aws/src/error.rs` | `SignInError` + `SessionError` taxonomy (tested: no-leak) |
| `janitor-aws/src/types.rs` | `SsoToken`, `Credential`, `Clock`/`SystemClock` (tested) |
| `janitor-aws/src/wire.rs` | Narrow SDK-wrap traits + SDK-free I/O structs + fakes |
| `janitor-aws/src/broker.rs` | `CredentialBroker` (cache, skew re-mint) (tested w/ fakes) |
| `janitor-aws/src/secrets.rs` | `SecretsClient` mapping → `SecretShape` (tested w/ fakes) |
| `janitor-aws/src/source.rs` | `AuthenticatedSource` facade orchestration (tested w/ fakes) |
| `janitor-aws/src/loopback.rs` | One-shot loopback listener + browser open (shell, untested) |
| `janitor-aws/src/authenticator.rs` | Real `Authenticator` (RegisterClient→browser→CreateToken) (shell) |
| `janitor-aws/src/aws_impl.rs` | Real SDK adapters implementing the `wire.rs` traits (shell) |
| `janitor-aws/src/bin/loopback-spike.rs` | Step-0 integration spike (manual) |
| `janitor-aws/src/bin/live-verify.rs` | Human-run live verification harness |

**Modified (workspace plumbing only):**
- `Cargo.toml` (workspace `members`)
- `.github/workflows/ci.yml` (note; coverage gate stays core-only)
- `CLAUDE.md` status line + `README.md` (final task)

---

## Phase 0 — Crate plumbing

### Task 0: Create `janitor-aws` crate skeleton

**Files:**
- Create: `janitor-aws/Cargo.toml`
- Create: `janitor-aws/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 1: Add the crate to the workspace**

Edit `Cargo.toml` (workspace root):

```toml
[workspace]
resolver = "2"
members = ["janitor-core", "janitor-gui", "janitor-aws"]
```

- [ ] **Step 2: Write the crate manifest**

Create `janitor-aws/Cargo.toml`. Versions: pin to the latest released at implementation time; the ones below are known-good families. The AWS SDK crates move fast — run `cargo add` rather than hand-editing if unsure.

```toml
[package]
name = "janitor-aws"
version = "0.1.0"
edition = "2021"
license = "GPL-3.0-only"
description = "Janitor's AWS adapter: Identity Center auth + Secrets Manager I/O (ADR 0010)."

[dependencies]
janitor-core = { path = "../janitor-core" }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "time", "sync"] }
aws-config = "1"
aws-sdk-ssooidc = "1"
aws-sdk-sso = "1"
aws-sdk-secretsmanager = "1"
aws-smithy-runtime-api = "1"   # for typed SdkError inspection in aws_impl.rs
secrecy = "0.10"
zeroize = "1"
thiserror = "2"
sha2 = "0.10"
base64 = "0.22"
rand = "0.8"
open = "5"

[dev-dependencies]
tokio = { version = "1", features = ["rt", "macros", "time", "test-util"] }
```

- [ ] **Step 3: Write the lib root**

Create `janitor-aws/src/lib.rs`:

```rust
//! `janitor-aws` — Janitor's AWS adapter (ADR 0010).
//!
//! Async-native. Holds Identity Center Sign-in (browser Auth Code + PKCE),
//! per-Environment role-Credential brokering, and Secrets Manager reads.
//! Depends on `janitor-core` for domain types (`Mapping`, `SecretShape`,
//! `Value`); contains **no GUI** and does not touch `janitor-core`'s sync
//! `SecretSource` (that seam stays untouched until the GUI integration slice).
//!
//! ## Trust & memory posture
//! Nothing here is persisted. The SSO token and role Credentials live only in
//! memory, in zeroizing buffers. The client registration is re-created each
//! launch (never cached). See ADR 0002 / ADR 0010 / THREAT-MODEL.md.
//!
//! ## Test seam
//! Every SDK operation sits behind a narrow trait in [`wire`] whose inputs and
//! outputs are our own SDK-free types, so the brokering/orchestration logic is
//! unit-tested against fakes. Only [`loopback`], [`authenticator`], and
//! [`aws_impl`] (the browser/listener + real SDK calls) are untested.

pub mod broker;
pub mod error;
pub mod pkce;
pub mod secrets;
pub mod source;
pub mod state;
pub mod types;
pub mod wire;

// Untested shell (real I/O); compiled but not coverage-gated.
pub mod aws_impl;
pub mod authenticator;
pub mod loopback;
```

- [ ] **Step 4: Verify it builds**

Run: `cargo build -p janitor-aws`
Expected: FAILS to compile — the `pub mod` lines reference files that don't exist yet. That is expected; this step only confirms the manifest + workspace wiring parse. (If `cargo` complains about the workspace or a missing dependency *download*, fix that now; module-not-found errors are fine and resolved by later tasks.)

To get a clean green here instead, temporarily comment out all `pub mod` lines, run `cargo build -p janitor-aws` (expect: PASS, empty crate), then uncomment. Choose whichever the executor prefers; the modules land next.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml janitor-aws/Cargo.toml janitor-aws/src/lib.rs
git commit -m "feat(aws): scaffold janitor-aws crate in the workspace (ADR 0010)"
```

---

## Phase 1 — Pure, fully-tested units (no AWS, no async)

### Task 1: PKCE pure functions

**Files:**
- Create: `janitor-aws/src/pkce.rs`

PKCE per RFC 7636: a high-entropy `code_verifier` (43–128 chars from the unreserved set), and a `code_challenge = base64url-no-pad(SHA256(verifier))` with method `S256`. The RFC's Appendix B gives a known-answer vector we test against.

- [ ] **Step 1: Write the failing tests**

```rust
//! PKCE (RFC 7636) — code verifier + S256 challenge. Pure; the only untested
//! caller is the browser/listener shell. The verifier is secret-adjacent (it
//! proves possession of the auth code) but short-lived and not a stored secret.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// A generated PKCE pair: the verifier (sent later to `CreateToken`) and the
/// challenge (sent to `/authorize`).
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// base64url **without padding**, per RFC 7636 §4.2.
pub fn base64url_no_pad(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The S256 challenge for a given verifier: base64url-no-pad(SHA256(verifier)).
pub fn s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64url_no_pad(&digest)
}

/// Generate a fresh PKCE pair with a 32-byte (256-bit) random verifier source,
/// base64url-encoded to a 43-char verifier (within the RFC's 43–128 range).
pub fn generate() -> Pkce {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let verifier = base64url_no_pad(&raw);
    let challenge = s256_challenge(&verifier);
    Pkce { verifier, challenge }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B known-answer vector.
    #[test]
    fn s256_matches_rfc7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(s256_challenge(verifier), expected);
    }

    #[test]
    fn base64url_is_unpadded_and_urlsafe() {
        // 0xfb bytes encode to chars that differ between standard and url-safe
        // alphabets, and any input whose length isn't a multiple of 3 would be
        // padded with '=' in the padded variant.
        let out = base64url_no_pad(&[0xfb, 0xff, 0xfe]);
        assert!(!out.contains('='), "must be unpadded");
        assert!(!out.contains('+') && !out.contains('/'), "must be url-safe");
    }

    #[test]
    fn generated_verifier_is_in_rfc_length_range() {
        let p = generate();
        assert!(
            (43..=128).contains(&p.verifier.len()),
            "verifier length {} out of RFC 7636 range",
            p.verifier.len()
        );
        // The challenge must verify against the verifier.
        assert_eq!(s256_challenge(&p.verifier), p.challenge);
    }

    #[test]
    fn two_generates_differ() {
        assert_ne!(generate().verifier, generate().verifier, "must be random");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail, then pass**

Because Step 1 includes the implementation alongside the tests (the functions are tiny and inseparable from their known-answer vectors), run:

Run: `cargo test -p janitor-aws --lib pkce`
Expected: PASS (4 tests). If the RFC vector test fails, the base64url alphabet or padding is wrong — fix `base64url_no_pad` before moving on; that vector is the canary.

- [ ] **Step 3: Commit**

```bash
git add janitor-aws/src/pkce.rs
git commit -m "feat(aws): PKCE verifier + S256 challenge with RFC 7636 vector (ADR 0010)"
```

---

### Task 2: CSRF `state` pure functions

**Files:**
- Create: `janitor-aws/src/state.rs`

The `state` parameter is a CSRF nonce: generated before opening the browser, echoed back on the redirect, and **must match** or the callback is rejected (it stops a forged-code injection).

- [ ] **Step 1: Write the module with tests**

```rust
//! CSRF `state` nonce for the Auth Code flow. Generated before the browser
//! opens, echoed on the redirect, and required to match. A mismatch means the
//! callback is forged/replayed and the Sign-in must abort (ADR 0010 §6).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;

/// A freshly generated opaque state nonce (url-safe, ~43 chars / 256 bits).
pub fn generate() -> String {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

/// Whether the state returned on the redirect matches what we sent. Compared in
/// length-then-content; both operands are in-process values the same user owns,
/// so there is no cross-trust timing channel to defend (cf. core's `bytes_eq`).
pub fn matches(expected: &str, returned: &str) -> bool {
    // Constant-time-ish: avoid early return on first differing byte. Not a
    // security boundary here, but cheap and signals intent.
    if expected.len() != returned.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.bytes().zip(returned.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_state_is_nonempty_and_random() {
        let a = generate();
        let b = generate();
        assert!(!a.is_empty());
        assert_ne!(a, b, "state must be unpredictable");
    }

    #[test]
    fn matching_state_accepted() {
        let s = generate();
        assert!(matches(&s, &s));
    }

    #[test]
    fn mismatched_state_rejected() {
        let s = generate();
        assert!(!matches(&s, "attacker-supplied-value"));
        assert!(!matches(&s, &format!("{s}x")), "length differs → reject");
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p janitor-aws --lib state`
Expected: PASS (3 tests).

- [ ] **Step 3: Commit**

```bash
git add janitor-aws/src/state.rs
git commit -m "feat(aws): CSRF state nonce gen + mismatch-rejecting verify (ADR 0010)"
```

---

### Task 3: Error taxonomy

**Files:**
- Create: `janitor-aws/src/error.rs`

Two enums (ADR 0010 §9): `SignInError` for `sign_in()`, `SessionError` for fetch/brokering. The `Sdk` catch-all must be **scrubbed** — its `Display`/`Debug` must never carry a secret or a raw response body.

- [ ] **Step 1: Write the module with tests**

```rust
//! Error taxonomy for janitor-aws (ADR 0010 §9). Two enums: one for Sign-in,
//! one for live-Session fetch/brokering. Variants are classified so the caller
//! can tell retryable from fatal from re-auth. The `Sdk` catch-all is scrubbed:
//! it carries a short static-ish context string, never a response body.

/// Why a browser Sign-in failed. None of these implies a live Session exists.
#[derive(Debug, thiserror::Error)]
pub enum SignInError {
    #[error("could not launch a browser for Sign-in")]
    BrowserLaunch,
    #[error("timed out waiting for the Sign-in redirect")]
    ListenerTimeout,
    #[error("the Sign-in redirect could not be bound to a loopback port")]
    NoLoopbackPort,
    #[error("the Sign-in redirect failed CSRF state validation")]
    StateMismatch,
    #[error("the Identity Center token endpoint rejected the Sign-in")]
    TokenEndpoint,
    #[error("a network error occurred during Sign-in")]
    Network,
    /// Scrubbed catch-all: `context` is a short non-secret label, never a body.
    #[error("Sign-in failed: {context}")]
    Sdk { context: String },
}

/// Why an operation on a live Session failed.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The SSO token is dead — a fresh browser Sign-in is required. This is the
    /// ONLY variant that should trigger a browser (ADR 0002 / 0010 §4).
    #[error("the Session expired; a fresh Sign-in is required")]
    ReauthRequired,
    /// AWS refused the operation under policy; not retryable, not re-auth.
    #[error("access denied for this Mapping")]
    AccessDenied,
    /// The secret id/region does not resolve to a Set.
    #[error("no secret found for this Mapping")]
    NotFound,
    /// Throttled or transient; the SDK already retried internally. Propagated so
    /// the caller can surface it; no Janitor-level retry loop in this slice.
    #[error("the request was throttled or hit a transient error")]
    Throttled,
    /// The Set cannot be handled (e.g. binary — never revealable, ADR 0004).
    #[error("unsupported secret content for this operation")]
    Unsupported,
    /// Scrubbed catch-all: `context` is a short non-secret label, never a body.
    #[error("AWS call failed: {context}")]
    Sdk { context: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_variants_do_not_print_secret_material() {
        // Whatever context we attach, Display/Debug must not be a dumping ground
        // for response bodies. We assert a representative secret string never
        // appears, documenting the contract (the producer in aws_impl.rs is
        // responsible for never putting secrets in `context`).
        let e = SessionError::Sdk { context: "GetSecretValue".into() };
        let shown = format!("{e} | {e:?}");
        assert!(shown.contains("GetSecretValue"));
        assert!(!shown.contains("hunter2"), "no secret leaked");
    }

    #[test]
    fn reauth_is_distinct_from_access_denied() {
        // The two are handled differently by the facade; they must not be the
        // same variant.
        assert!(matches!(SessionError::ReauthRequired, SessionError::ReauthRequired));
        assert!(matches!(SessionError::AccessDenied, SessionError::AccessDenied));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p janitor-aws --lib error`
Expected: PASS (2 tests).

- [ ] **Step 3: Commit**

```bash
git add janitor-aws/src/error.rs
git commit -m "feat(aws): SignInError + SessionError taxonomy, scrubbed Sdk catch-all (ADR 0010)"
```

---

### Task 4: Domain types — `SsoToken`, `Credential`, `Clock`

**Files:**
- Create: `janitor-aws/src/types.rs`

Zeroizing secret holders + an injectable clock so expiry is testable without sleeping (ADR 0010 §4). Expiry is `SystemTime` (UTC instant), compared against the clock; we **never hardcode a lifetime** — `Credential.expiration` comes from AWS.

- [ ] **Step 1: Write the module with tests**

```rust
//! In-memory, zeroizing auth material + an injectable clock.
//!
//! `SsoToken` and `Credential` hold secret strings in `secrecy::SecretString`
//! so they are zeroized on drop and never `Debug`/`Display` the plaintext. The
//! `Clock` seam lets the broker's near-expiry math be tested without sleeping.

use std::time::{Duration, SystemTime};

use secrecy::{ExposeSecret, SecretString};

/// The SSO access token from `CreateToken`. Drives `GetRoleCredentials` until it
/// expires; its in-memory lifetime *is* the Session (CONTEXT.md). Never cached.
pub struct SsoToken {
    access_token: SecretString,
    /// When the SSO token itself expires (a fresh Sign-in is needed after this).
    pub expires_at: SystemTime,
}

impl SsoToken {
    pub fn new(access_token: String, expires_at: SystemTime) -> Self {
        SsoToken { access_token: SecretString::from(access_token), expires_at }
    }
    /// Expose the token for a `GetRoleCredentials` call. Callers must not retain.
    pub fn expose(&self) -> &str {
        self.access_token.expose_secret()
    }
}

impl std::fmt::Debug for SsoToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoToken").field("expires_at", &self.expires_at).finish()
    }
}

/// One Environment's short-lived role Credential from `GetRoleCredentials`.
/// All three secret fields are zeroizing; `expiration` is read from AWS, never
/// hardcoded (ADR 0002).
pub struct Credential {
    access_key_id: SecretString,
    secret_access_key: SecretString,
    session_token: SecretString,
    pub expiration: SystemTime,
}

impl Credential {
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        expiration: SystemTime,
    ) -> Self {
        Credential {
            access_key_id: SecretString::from(access_key_id),
            secret_access_key: SecretString::from(secret_access_key),
            session_token: SecretString::from(session_token),
            expiration,
        }
    }
    pub fn access_key_id(&self) -> &str { self.access_key_id.expose_secret() }
    pub fn secret_access_key(&self) -> &str { self.secret_access_key.expose_secret() }
    pub fn session_token(&self) -> &str { self.session_token.expose_secret() }

    /// True when this Credential is within `skew` of expiry (or already past),
    /// per the clock — i.e. it should be re-minted before use.
    pub fn is_stale(&self, now: SystemTime, skew: Duration) -> bool {
        match self.expiration.checked_sub(skew) {
            Some(deadline) => now >= deadline,
            None => true, // expiration - skew underflows → treat as stale
        }
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential").field("expiration", &self.expiration).finish()
    }
}

/// Injectable clock so expiry logic is testable without real time.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// Production clock.
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> SystemTime { SystemTime::now() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_and_credential_debug_redact_secrets() {
        let t = SsoToken::new("super-secret-token".into(), SystemTime::UNIX_EPOCH);
        assert!(!format!("{t:?}").contains("super-secret-token"));

        let c = Credential::new(
            "AKIA".into(), "wJalr-secret".into(), "sess".into(), SystemTime::UNIX_EPOCH,
        );
        let shown = format!("{c:?}");
        assert!(!shown.contains("wJalr-secret"));
        assert!(!shown.contains("AKIA"));
    }

    #[test]
    fn is_stale_respects_skew() {
        let base = SystemTime::UNIX_EPOCH;
        let exp = base + Duration::from_secs(3600);
        let c = Credential::new("a".into(), "b".into(), "c".into(), exp);
        let skew = Duration::from_secs(60);

        // Well before expiry-minus-skew → fresh.
        assert!(!c.is_stale(base + Duration::from_secs(3000), skew));
        // Exactly at expiry-minus-skew (3600-60=3540) → stale (>=).
        assert!(c.is_stale(base + Duration::from_secs(3540), skew));
        // Past expiry → stale.
        assert!(c.is_stale(base + Duration::from_secs(4000), skew));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p janitor-aws --lib types`
Expected: PASS (2 tests).

- [ ] **Step 3: Commit**

```bash
git add janitor-aws/src/types.rs
git commit -m "feat(aws): zeroizing SsoToken/Credential + injectable Clock (ADR 0010)"
```

---

## Phase 2 — Narrow SDK-wrap traits + fakes (the test seam)

### Task 5: `wire.rs` — traits, SDK-free I/O types, and fakes

**Files:**
- Create: `janitor-aws/src/wire.rs`

This is the seam that makes everything above testable. Each trait wraps exactly the SDK ops we use; inputs/outputs are **our** owned types (no SDK types leak in), so fakes are trivial and the broker/facade tests never touch AWS. Traits are async (`async_trait`-free using the 2021 `impl Future` return is awkward across trait objects, so we use boxed futures via `async-trait`). **Add `async-trait = "0.1"` to `[dependencies]` now** (amend `janitor-aws/Cargo.toml`).

- [ ] **Step 1: Add `async-trait` dependency**

Amend `janitor-aws/Cargo.toml` `[dependencies]`:

```toml
async-trait = "0.1"
```

- [ ] **Step 2: Write the module with fakes and tests**

```rust
//! The SDK seam (ADR 0010 §5). Each trait wraps the AWS ops we use; all I/O are
//! our own SDK-free types, so the brokering/orchestration logic is tested
//! against the fakes here without any AWS dependency. Real impls live in
//! `aws_impl.rs` (untested shell).

use async_trait::async_trait;
use std::time::SystemTime;

use crate::error::{SessionError, SignInError};
use crate::types::{Credential, SsoToken};

/// A public-client registration from `RegisterClient`. The `client_secret` is a
/// public-client secret (not confidential — PKCE is what protects the flow), but
/// we still hold it as an opaque string and never log it.
#[derive(Clone)]
pub struct ClientRegistration {
    pub client_id: String,
    pub client_secret: String,
}

/// Inputs needed to exchange an auth code for an SSO token.
pub struct TokenExchange<'a> {
    pub registration: &'a ClientRegistration,
    pub code: &'a str,
    pub code_verifier: &'a str,
    pub redirect_uri: &'a str,
}

/// Wraps the unauthenticated OIDC ops: `RegisterClient` + `CreateToken`.
#[async_trait]
pub trait OidcClient: Send + Sync {
    /// `RegisterClient` for a public client with the given loopback redirect
    /// URIs and the `authorization_code` + `refresh_token` grants.
    async fn register_client(
        &self,
        redirect_uris: &[String],
    ) -> Result<ClientRegistration, SignInError>;

    /// `CreateToken` with `grant_type=authorization_code` + PKCE `code_verifier`.
    /// Returns the SSO access token + its expiry.
    async fn create_token(&self, ex: TokenExchange<'_>) -> Result<SsoToken, SignInError>;
}

/// Wraps `GetRoleCredentials` (mints a role Credential from the SSO token).
#[async_trait]
pub trait RoleCredentialClient: Send + Sync {
    /// `GetRoleCredentials` for `(account_id, permission_set)` using `token`.
    /// Maps `UnauthorizedException` (dead token) → `SessionError::ReauthRequired`.
    async fn get_role_credentials(
        &self,
        token: &SsoToken,
        account_id: &str,
        permission_set: &str,
        region: &str,
    ) -> Result<Credential, SessionError>;
}

/// The raw payload of one `GetSecretValue` response, SDK-free. Exactly one of
/// the two fields is `Some` (mirrors the AWS API).
pub struct RawSecret {
    pub secret_string: Option<String>,
    pub secret_binary: Option<Vec<u8>>,
}

/// Wraps `GetSecretValue`.
#[async_trait]
pub trait SecretsApi: Send + Sync {
    /// `GetSecretValue` for `secret_id` in `region`, authorized by `cred`.
    async fn get_secret_value(
        &self,
        cred: &Credential,
        secret_id: &str,
        region: &str,
    ) -> Result<RawSecret, SessionError>;
}

// ----------------------------------------------------------------------------
// Fakes for unit tests. Behind `cfg(test)` so they never ship.
// ----------------------------------------------------------------------------
#[cfg(test)]
pub mod fakes {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    /// A scripted role-credential client: each call pops the next scripted
    /// outcome, and records how many times it was called (to assert "exactly
    /// once" re-mint behavior).
    pub struct FakeRoleClient {
        pub outcomes: Mutex<Vec<Result<CredSpec, SessionError>>>,
        pub calls: Mutex<u32>,
    }

    /// A description of a Credential to mint (fakes can't build real secrets
    /// meaningfully; they just need distinguishable expiries).
    #[derive(Clone)]
    pub struct CredSpec {
        pub expires_in: Duration,
        pub tag: &'static str, // distinguishes successive mints in assertions
    }

    impl FakeRoleClient {
        pub fn new(outcomes: Vec<Result<CredSpec, SessionError>>) -> Self {
            FakeRoleClient { outcomes: Mutex::new(outcomes), calls: Mutex::new(0) }
        }
        pub fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl RoleCredentialClient for FakeRoleClient {
        async fn get_role_credentials(
            &self,
            _token: &SsoToken,
            _account_id: &str,
            _permission_set: &str,
            _region: &str,
        ) -> Result<Credential, SessionError> {
            *self.calls.lock().unwrap() += 1;
            let next = {
                let mut v = self.outcomes.lock().unwrap();
                if v.is_empty() {
                    panic!("FakeRoleClient called more times than scripted");
                }
                v.remove(0)
            };
            next.map(|spec| {
                // Use a fixed base instant so tests are deterministic; the broker
                // is driven by an injected clock, not real time.
                let base = SystemTime::UNIX_EPOCH;
                Credential::new(
                    format!("AKIA-{}", spec.tag),
                    format!("secret-{}", spec.tag),
                    format!("session-{}", spec.tag),
                    base + spec.expires_in,
                )
            })
        }
    }

    /// A scripted secrets client.
    pub struct FakeSecretsApi {
        pub outcomes: Mutex<Vec<Result<RawSecret, SessionError>>>,
        pub calls: Mutex<u32>,
    }
    impl FakeSecretsApi {
        pub fn new(outcomes: Vec<Result<RawSecret, SessionError>>) -> Self {
            FakeSecretsApi { outcomes: Mutex::new(outcomes), calls: Mutex::new(0) }
        }
        pub fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }
    #[async_trait]
    impl SecretsApi for FakeSecretsApi {
        async fn get_secret_value(
            &self,
            _cred: &Credential,
            _secret_id: &str,
            _region: &str,
        ) -> Result<RawSecret, SessionError> {
            *self.calls.lock().unwrap() += 1;
            let mut v = self.outcomes.lock().unwrap();
            if v.is_empty() {
                panic!("FakeSecretsApi called more times than scripted");
            }
            v.remove(0)
        }
    }

    /// A controllable clock for broker/facade tests.
    pub struct FakeClock {
        pub now: Mutex<SystemTime>,
    }
    impl FakeClock {
        pub fn at(secs_after_epoch: u64) -> Self {
            FakeClock {
                now: Mutex::new(SystemTime::UNIX_EPOCH + Duration::from_secs(secs_after_epoch)),
            }
        }
        pub fn advance(&self, by: Duration) {
            let mut n = self.now.lock().unwrap();
            *n += by;
        }
    }
    impl crate::types::Clock for FakeClock {
        fn now(&self) -> SystemTime {
            *self.now.lock().unwrap()
        }
    }

    #[test]
    fn fake_role_client_counts_calls_and_scripts_outcomes() {
        // A tiny self-test of the fake itself, so later tasks can trust it.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let fake = FakeRoleClient::new(vec![
            Ok(CredSpec { expires_in: Duration::from_secs(3600), tag: "first" }),
            Err(SessionError::ReauthRequired),
        ]);
        let token = SsoToken::new("t".into(), SystemTime::UNIX_EPOCH);
        rt.block_on(async {
            let c = fake.get_role_credentials(&token, "acct", "ps", "us-east-1").await.unwrap();
            assert_eq!(c.access_key_id(), "AKIA-first");
            let e = fake.get_role_credentials(&token, "acct", "ps", "us-east-1").await.unwrap_err();
            assert!(matches!(e, SessionError::ReauthRequired));
        });
        assert_eq!(fake.call_count(), 2);
    }
}
```

- [ ] **Step 3: Run the fake's self-test**

Run: `cargo test -p janitor-aws --lib wire`
Expected: PASS (1 test). This proves the fakes compile and behave, so later tasks can rely on them.

- [ ] **Step 4: Commit**

```bash
git add janitor-aws/Cargo.toml janitor-aws/src/wire.rs
git commit -m "feat(aws): narrow SDK-wrap traits + SDK-free I/O types + test fakes (ADR 0010)"
```

---

## Phase 3 — Tested orchestration objects

### Task 6: `CredentialBroker` — cache + near-expiry re-mint

**Files:**
- Create: `janitor-aws/src/broker.rs`

Owns the `SsoToken`; caches one `Credential` per `(account_id, permission_set, region)`; `credentials_for(&Mapping)` (note `&self`, ADR 0010) returns a currently-valid Credential, silently re-minting when stale. Cache is behind a `tokio::sync::Mutex` (interior mutability + `&self`, async-aware).

- [ ] **Step 1: Write the failing tests**

```rust
//! `CredentialBroker` (ADR 0010 §3/§4): owns the SSO token, brokers one role
//! Credential per Environment from it, silently re-minting near expiry. No
//! browser — a dead token surfaces as `SessionError::ReauthRequired` from the
//! role-credential client and is propagated for the facade to handle.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::error::SessionError;
use crate::types::{Clock, Credential, SsoToken};
use crate::wire::RoleCredentialClient;
use janitor_core::config::Mapping;

/// Re-mint a role Credential when it is within this window of expiry.
pub const REFRESH_SKEW: Duration = Duration::from_secs(60);

/// Brokers per-Environment Credentials from one SSO token.
pub struct CredentialBroker {
    token: SsoToken,
    role_client: Arc<dyn RoleCredentialClient>,
    clock: Arc<dyn Clock>,
    cache: Mutex<HashMap<String, Arc<Credential>>>,
}

impl CredentialBroker {
    pub fn new(
        token: SsoToken,
        role_client: Arc<dyn RoleCredentialClient>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        CredentialBroker { token, role_client, clock, cache: Mutex::new(HashMap::new()) }
    }

    fn cache_key(m: &Mapping) -> String {
        format!("{}|{}|{}", m.account_id, m.permission_set, m.region)
    }

    /// Return a currently-valid Credential for `mapping`, minting or re-minting
    /// via `GetRoleCredentials` when the cache is empty or the cached Credential
    /// is within `REFRESH_SKEW` of expiry. `&self`: the cache is interior.
    pub async fn credentials_for(&self, mapping: &Mapping) -> Result<Arc<Credential>, SessionError> {
        let key = Self::cache_key(mapping);
        let now = self.clock.now();
        {
            let cache = self.cache.lock().await;
            if let Some(cred) = cache.get(&key) {
                if !cred.is_stale(now, REFRESH_SKEW) {
                    return Ok(Arc::clone(cred));
                }
            }
        }
        // Stale or absent → mint. (A dead token returns ReauthRequired here.)
        let fresh = self
            .role_client
            .get_role_credentials(&self.token, &mapping.account_id, &mapping.permission_set, &mapping.region)
            .await?;
        let fresh = Arc::new(fresh);
        self.cache.lock().await.insert(key, Arc::clone(&fresh));
        Ok(fresh)
    }

    /// Force a re-mint for `mapping` regardless of cache freshness (used by the
    /// facade when `GetSecretValue` rejects a not-yet-expired cached Credential).
    pub async fn force_refresh(&self, mapping: &Mapping) -> Result<Arc<Credential>, SessionError> {
        let fresh = Arc::new(
            self.role_client
                .get_role_credentials(&self.token, &mapping.account_id, &mapping.permission_set, &mapping.region)
                .await?,
        );
        self.cache.lock().await.insert(Self::cache_key(mapping), Arc::clone(&fresh));
        Ok(fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::fakes::{CredSpec, FakeClock, FakeRoleClient};

    fn mapping() -> Mapping {
        Mapping {
            environment: "prod".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: "myapp/prod".into(),
            permission_set: "ReadOnly".into(),
        }
    }

    #[tokio::test]
    async fn first_call_mints_and_second_call_hits_cache() {
        let role = Arc::new(FakeRoleClient::new(vec![Ok(CredSpec {
            expires_in: Duration::from_secs(3600),
            tag: "first",
        })]));
        let clock = Arc::new(FakeClock::at(0));
        let broker = CredentialBroker::new(
            SsoToken::new("token".into(), std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(28800)),
            role.clone(),
            clock,
        );
        let c1 = broker.credentials_for(&mapping()).await.unwrap();
        let c2 = broker.credentials_for(&mapping()).await.unwrap();
        assert_eq!(c1.access_key_id(), "AKIA-first");
        assert_eq!(c2.access_key_id(), "AKIA-first");
        assert_eq!(role.call_count(), 1, "second call must hit cache, not re-mint");
    }

    #[tokio::test]
    async fn near_expiry_triggers_remint() {
        let role = Arc::new(FakeRoleClient::new(vec![
            Ok(CredSpec { expires_in: Duration::from_secs(3600), tag: "first" }),
            Ok(CredSpec { expires_in: Duration::from_secs(7200), tag: "second" }),
        ]));
        let clock = Arc::new(FakeClock::at(0));
        let broker = CredentialBroker::new(
            SsoToken::new("token".into(), std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(28800)),
            role.clone(),
            clock.clone(),
        );
        let first = broker.credentials_for(&mapping()).await.unwrap();
        assert_eq!(first.access_key_id(), "AKIA-first");
        // Advance to within REFRESH_SKEW of the first credential's expiry (3600).
        clock.advance(Duration::from_secs(3550));
        let second = broker.credentials_for(&mapping()).await.unwrap();
        assert_eq!(second.access_key_id(), "AKIA-second", "stale → re-minted");
        assert_eq!(role.call_count(), 2);
    }

    #[tokio::test]
    async fn dead_token_surfaces_reauth_required() {
        let role = Arc::new(FakeRoleClient::new(vec![Err(SessionError::ReauthRequired)]));
        let clock = Arc::new(FakeClock::at(0));
        let broker = CredentialBroker::new(
            SsoToken::new("token".into(), std::time::SystemTime::UNIX_EPOCH),
            role,
            clock,
        );
        let err = broker.credentials_for(&mapping()).await.unwrap_err();
        assert!(matches!(err, SessionError::ReauthRequired));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p janitor-aws --lib broker`
Expected: FAIL — but since Step 1 includes the implementation, this should compile and PASS directly. If it fails to compile because `Mapping`'s field names differ, check `janitor-core/src/config/mod.rs` (`environment`, `account_id`, `region`, `secret_id`, `permission_set`) and fix the test/impl to match. If a test *assertion* fails, fix `broker.rs`, not the test.

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p janitor-aws --lib broker`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add janitor-aws/src/broker.rs
git commit -m "feat(aws): CredentialBroker with cache + near-expiry re-mint (ADR 0010)"
```

---

### Task 7: `SecretsClient` — map `GetSecretValue` → `SecretShape`

**Files:**
- Create: `janitor-aws/src/secrets.rs`

Maps the raw response to a `SecretShape` via core's constructors (ADR 0010 §3): `secret_string` present → `from_secret_string` (which itself picks Json vs Raw); `secret_binary` present → `from_secret_binary`; neither → `SessionError::NotFound` (an empty/odd response). This wraps the `SecretsApi` trait so the mapping is tested without AWS.

- [ ] **Step 1: Write the failing tests**

```rust
//! `SecretsClient` (ADR 0010 §3): fetch one Set via the `SecretsApi` seam and
//! map it to a core `SecretShape`. The mapping is the first thing to get right,
//! so it is tested here against fakes; binary stays opaque (ADR 0004).

use std::sync::Arc;

use janitor_core::secret::SecretShape;
use janitor_core::config::Mapping;

use crate::error::SessionError;
use crate::types::Credential;
use crate::wire::SecretsApi;

/// Fetches and shapes one Secret Set.
pub struct SecretsClient {
    api: Arc<dyn SecretsApi>,
}

impl SecretsClient {
    pub fn new(api: Arc<dyn SecretsApi>) -> Self {
        SecretsClient { api }
    }

    /// `GetSecretValue` for `mapping`, authorized by `cred`, mapped to a shape.
    pub async fn fetch(
        &self,
        cred: &Credential,
        mapping: &Mapping,
    ) -> Result<SecretShape, SessionError> {
        let raw = self.api.get_secret_value(cred, &mapping.secret_id, &mapping.region).await?;
        match (raw.secret_string, raw.secret_binary) {
            (Some(s), _) => Ok(SecretShape::from_secret_string(&s)),
            (None, Some(b)) => Ok(SecretShape::from_secret_binary(b)),
            (None, None) => Err(SessionError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::RawSecret;
    use crate::wire::fakes::FakeSecretsApi;
    use std::time::SystemTime;

    fn cred() -> Credential {
        Credential::new("a".into(), "b".into(), "c".into(), SystemTime::UNIX_EPOCH)
    }
    fn mapping() -> Mapping {
        Mapping {
            environment: "prod".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: "myapp/prod".into(),
            permission_set: "ReadOnly".into(),
        }
    }

    #[tokio::test]
    async fn json_object_string_becomes_json_shape() {
        let api = Arc::new(FakeSecretsApi::new(vec![Ok(RawSecret {
            secret_string: Some(r#"{"A":"1"}"#.into()),
            secret_binary: None,
        })]));
        let shape = SecretsClient::new(api).fetch(&cred(), &mapping()).await.unwrap();
        assert!(matches!(shape, SecretShape::Json(_)));
    }

    #[tokio::test]
    async fn non_json_string_becomes_raw_shape() {
        let api = Arc::new(FakeSecretsApi::new(vec![Ok(RawSecret {
            secret_string: Some("just-a-token".into()),
            secret_binary: None,
        })]));
        let shape = SecretsClient::new(api).fetch(&cred(), &mapping()).await.unwrap();
        assert!(matches!(shape, SecretShape::Raw(_)));
    }

    #[tokio::test]
    async fn binary_becomes_binary_shape() {
        let api = Arc::new(FakeSecretsApi::new(vec![Ok(RawSecret {
            secret_string: None,
            secret_binary: Some(vec![1, 2, 3, 4]),
        })]));
        let shape = SecretsClient::new(api).fetch(&cred(), &mapping()).await.unwrap();
        match shape {
            SecretShape::Binary(b) => assert_eq!(b.len(), 4),
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_response_is_not_found() {
        let api = Arc::new(FakeSecretsApi::new(vec![Ok(RawSecret {
            secret_string: None,
            secret_binary: None,
        })]));
        let err = SecretsClient::new(api).fetch(&cred(), &mapping()).await.unwrap_err();
        assert!(matches!(err, SessionError::NotFound));
    }

    #[tokio::test]
    async fn propagates_access_denied() {
        let api = Arc::new(FakeSecretsApi::new(vec![Err(SessionError::AccessDenied)]));
        let err = SecretsClient::new(api).fetch(&cred(), &mapping()).await.unwrap_err();
        assert!(matches!(err, SessionError::AccessDenied));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p janitor-aws --lib secrets`
Expected: PASS (5 tests).

- [ ] **Step 3: Commit**

```bash
git add janitor-aws/src/secrets.rs
git commit -m "feat(aws): SecretsClient maps GetSecretValue to SecretShape (ADR 0010)"
```

---

### Task 8: `AuthenticatedSource` facade — the orchestration

**Files:**
- Create: `janitor-aws/src/source.rs`

The load-bearing part (ADR 0010 §4): one chained escalation. The facade holds the broker (rebuildable on re-auth) + a `SecretsClient` + a re-Sign-in capability (an `OidcClient` + the redirect URIs + a way to drive the browser). To keep the facade **testable without a browser**, re-Sign-in is abstracted behind a small `Reauth` trait; the real impl (Task 11) drives the browser, the fake just yields a scripted fresh token.

- [ ] **Step 1: Write the facade with the `Reauth` seam and failing tests**

```rust
//! `AuthenticatedSource` (ADR 0010 §4): composes the broker + secrets client and
//! owns the chained escalation — at most one force-refresh and at most one
//! re-Sign-in per `fetch`. Re-Sign-in is behind the `Reauth` seam so the whole
//! orchestration is tested without a browser.

use std::sync::Arc;

use async_trait::async_trait;
use janitor_core::config::Mapping;
use janitor_core::secret::SecretShape;

use crate::broker::CredentialBroker;
use crate::error::{SessionError, SignInError};
use crate::secrets::SecretsClient;
use crate::types::{Clock, SsoToken};
use crate::wire::RoleCredentialClient;

/// The capability to perform a fresh browser Sign-in and yield a new SSO token.
/// Real impl drives the browser (Task 11); the test fake yields a scripted token.
#[async_trait]
pub trait Reauth: Send + Sync {
    async fn sign_in(&self) -> Result<SsoToken, SignInError>;
}

/// An authenticated data source over one Identity Center Session.
pub struct AuthenticatedSource {
    broker: CredentialBroker,
    secrets: SecretsClient,
    reauth: Arc<dyn Reauth>,
    role_client: Arc<dyn RoleCredentialClient>,
    clock: Arc<dyn Clock>,
}

impl AuthenticatedSource {
    pub fn new(
        broker: CredentialBroker,
        secrets: SecretsClient,
        reauth: Arc<dyn Reauth>,
        role_client: Arc<dyn RoleCredentialClient>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        AuthenticatedSource { broker, secrets, reauth, role_client, clock }
    }

    /// Fetch and shape the Set for `mapping`, handling the two refreshes with
    /// at-most-once caps (ADR 0010 §4):
    ///
    /// 1. credentials_for → GetSecretValue. On success, done.
    /// 2. On an auth-class GetSecretValue failure, force_refresh once, retry.
    ///    - forced refresh OK but retry still auth-fails → AccessDenied.
    ///    - forced refresh itself raises ReauthRequired → step 3.
    /// 3. credentials_for raising ReauthRequired (in step 1 or 2): re-Sign-in
    ///    once, rebuild the broker on the fresh token, retry from step 1. Still
    ///    ReauthRequired after a fresh Sign-in → fatal (AccessDenied).
    pub async fn fetch(&mut self, mapping: &Mapping) -> Result<SecretShape, SessionError> {
        match self.try_once(mapping).await {
            Ok(shape) => Ok(shape),
            Err(SessionError::ReauthRequired) => {
                // One re-Sign-in, rebuild broker on the fresh token, one retry.
                let token = self.reauth.sign_in().await.map_err(|_| SessionError::ReauthRequired)?;
                self.broker = CredentialBroker::new(token, Arc::clone(&self.role_client), Arc::clone(&self.clock));
                match self.try_once(mapping).await {
                    Ok(shape) => Ok(shape),
                    // Still unauthorized even after a fresh Sign-in → fatal.
                    Err(SessionError::ReauthRequired) => Err(SessionError::AccessDenied),
                    Err(other) => Err(other),
                }
            }
            Err(other) => Err(other),
        }
    }

    /// One pass: mint/get a credential, GetSecretValue, and on an auth-class
    /// failure force_refresh **once** then retry. Surfaces ReauthRequired up to
    /// `fetch` (which owns the re-Sign-in).
    async fn try_once(&self, mapping: &Mapping) -> Result<SecretShape, SessionError> {
        let cred = self.broker.credentials_for(mapping).await?; // may be ReauthRequired
        match self.secrets.fetch(&cred, mapping).await {
            Ok(shape) => Ok(shape),
            Err(SessionError::AccessDenied) => {
                // Could be a stale cached credential AWS now rejects, OR a true
                // policy denial — indistinguishable at this layer (ADR 0010 §4).
                // Force one re-mint and retry; a true denial costs one wasted mint.
                let cred = self.broker.force_refresh(mapping).await?; // may be ReauthRequired
                match self.secrets.fetch(&cred, mapping).await {
                    Ok(shape) => Ok(shape),
                    Err(SessionError::AccessDenied) => Err(SessionError::AccessDenied),
                    Err(other) => Err(other),
                }
            }
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SsoToken;
    use crate::wire::fakes::{CredSpec, FakeClock, FakeRoleClient, FakeSecretsApi};
    use crate::wire::RawSecret;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    fn mapping() -> Mapping {
        Mapping {
            environment: "prod".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: "myapp/prod".into(),
            permission_set: "ReadOnly".into(),
        }
    }

    /// A scripted re-Sign-in: records calls, yields a fresh token each time.
    struct FakeReauth {
        calls: Mutex<u32>,
        fail: bool,
    }
    impl FakeReauth {
        fn ok() -> Self { FakeReauth { calls: Mutex::new(0), fail: false } }
        fn count(&self) -> u32 { *self.calls.lock().unwrap() }
    }
    #[async_trait]
    impl Reauth for FakeReauth {
        async fn sign_in(&self) -> Result<SsoToken, SignInError> {
            *self.calls.lock().unwrap() += 1;
            if self.fail {
                Err(SignInError::TokenEndpoint)
            } else {
                Ok(SsoToken::new("fresh-token".into(), SystemTime::UNIX_EPOCH + Duration::from_secs(28800)))
            }
        }
    }

    fn build(
        role: Arc<FakeRoleClient>,
        api: Arc<FakeSecretsApi>,
        reauth: Arc<FakeReauth>,
    ) -> AuthenticatedSource {
        let clock = Arc::new(FakeClock::at(0));
        let token = SsoToken::new("t0".into(), SystemTime::UNIX_EPOCH + Duration::from_secs(28800));
        let broker = CredentialBroker::new(token, role.clone(), clock.clone());
        let secrets = SecretsClient::new(api);
        AuthenticatedSource::new(broker, secrets, reauth, role, clock)
    }

    #[tokio::test]
    async fn happy_path_fetches_without_refresh_or_reauth() {
        let role = Arc::new(FakeRoleClient::new(vec![Ok(CredSpec { expires_in: Duration::from_secs(3600), tag: "a" })]));
        let api = Arc::new(FakeSecretsApi::new(vec![Ok(RawSecret { secret_string: Some(r#"{"A":"1"}"#.into()), secret_binary: None })]));
        let reauth = Arc::new(FakeReauth::ok());
        let mut src = build(role.clone(), api.clone(), reauth.clone());
        let shape = src.fetch(&mapping()).await.unwrap();
        assert!(matches!(shape, SecretShape::Json(_)));
        assert_eq!(role.call_count(), 1);
        assert_eq!(api.call_count(), 1);
        assert_eq!(reauth.count(), 0);
    }

    #[tokio::test]
    async fn stale_credential_force_refreshes_once_then_succeeds() {
        // First GetSecretValue → AccessDenied (stale cred); force_refresh mints a
        // second credential; retry succeeds.
        let role = Arc::new(FakeRoleClient::new(vec![
            Ok(CredSpec { expires_in: Duration::from_secs(3600), tag: "stale" }),
            Ok(CredSpec { expires_in: Duration::from_secs(3600), tag: "fresh" }),
        ]));
        let api = Arc::new(FakeSecretsApi::new(vec![
            Err(SessionError::AccessDenied),
            Ok(RawSecret { secret_string: Some(r#"{"A":"1"}"#.into()), secret_binary: None }),
        ]));
        let reauth = Arc::new(FakeReauth::ok());
        let mut src = build(role.clone(), api.clone(), reauth.clone());
        let shape = src.fetch(&mapping()).await.unwrap();
        assert!(matches!(shape, SecretShape::Json(_)));
        assert_eq!(role.call_count(), 2, "one initial mint + one force_refresh");
        assert_eq!(api.call_count(), 2, "one denied + one retry");
        assert_eq!(reauth.count(), 0, "no browser for a stale role credential");
    }

    #[tokio::test]
    async fn true_denial_force_refreshes_once_then_gives_access_denied() {
        let role = Arc::new(FakeRoleClient::new(vec![
            Ok(CredSpec { expires_in: Duration::from_secs(3600), tag: "a" }),
            Ok(CredSpec { expires_in: Duration::from_secs(3600), tag: "b" }),
        ]));
        let api = Arc::new(FakeSecretsApi::new(vec![
            Err(SessionError::AccessDenied),
            Err(SessionError::AccessDenied),
        ]));
        let reauth = Arc::new(FakeReauth::ok());
        let mut src = build(role.clone(), api.clone(), reauth.clone());
        let err = src.fetch(&mapping()).await.unwrap_err();
        assert!(matches!(err, SessionError::AccessDenied));
        assert_eq!(role.call_count(), 2, "exactly one wasted re-mint, no loop");
        assert_eq!(api.call_count(), 2);
        assert_eq!(reauth.count(), 0);
    }

    #[tokio::test]
    async fn dead_token_re_signs_in_once_then_succeeds() {
        // First credentials_for → ReauthRequired (dead token). After re-Sign-in
        // the rebuilt broker mints OK and the fetch succeeds.
        let role = Arc::new(FakeRoleClient::new(vec![
            Err(SessionError::ReauthRequired),
            Ok(CredSpec { expires_in: Duration::from_secs(3600), tag: "after-reauth" }),
        ]));
        let api = Arc::new(FakeSecretsApi::new(vec![
            Ok(RawSecret { secret_string: Some(r#"{"A":"1"}"#.into()), secret_binary: None }),
        ]));
        let reauth = Arc::new(FakeReauth::ok());
        let mut src = build(role.clone(), api.clone(), reauth.clone());
        let shape = src.fetch(&mapping()).await.unwrap();
        assert!(matches!(shape, SecretShape::Json(_)));
        assert_eq!(reauth.count(), 1, "exactly one browser Sign-in");
        assert_eq!(role.call_count(), 2);
    }

    #[tokio::test]
    async fn still_unauthorized_after_reauth_is_fatal() {
        // Both before and after re-Sign-in the role client says ReauthRequired
        // (e.g. a not-entitled Mapping). Must NOT loop the browser; classify fatal.
        let role = Arc::new(FakeRoleClient::new(vec![
            Err(SessionError::ReauthRequired),
            Err(SessionError::ReauthRequired),
        ]));
        let api = Arc::new(FakeSecretsApi::new(vec![]));
        let reauth = Arc::new(FakeReauth::ok());
        let mut src = build(role.clone(), api.clone(), reauth.clone());
        let err = src.fetch(&mapping()).await.unwrap_err();
        assert!(matches!(err, SessionError::AccessDenied), "fatal, not another browser");
        assert_eq!(reauth.count(), 1, "browser opened at most once");
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p janitor-aws --lib source`
Expected: PASS (5 tests). If the "still unauthorized after reauth" test loops or panics on an empty `FakeSecretsApi`, the cap logic is wrong — the second `try_once` must return `ReauthRequired` from `credentials_for` *before* touching the secrets API. Fix `source.rs`, not the test.

- [ ] **Step 3: Commit**

```bash
git add janitor-aws/src/source.rs
git commit -m "feat(aws): AuthenticatedSource facade — chained escalation w/ at-most-once caps (ADR 0010)"
```

---

## Phase 4 — The untested shell (real I/O)

> ⚠️ **These tasks are the boundary ADR 0010 §5 calls "the only untested code."** They reference the AWS SDK and OS browser/sockets. Exact SDK method and field names **must be confirmed against the installed crate versions** via `docs.rs/aws-sdk-ssooidc`, `docs.rs/aws-sdk-sso`, `docs.rs/aws-sdk-secretsmanager` (or `cargo doc --open`). The shapes below are the known API as of writing; treat a compile error here as "confirm the current SDK signature," not a logic bug.

### Task 9: Loopback spike binary (step-0 integration flush)

**Files:**
- Create: `janitor-aws/src/loopback.rs`
- Create: `janitor-aws/src/bin/loopback-spike.rs`

Prove browser-open → loopback-catch → code-extraction on Windows **before any SDK wiring** (ADR 0010 §2a). The listener is a one-shot `tokio::net::TcpListener` that reads the first request line, extracts `code`/`state` from the query, returns a tiny HTML page, and shuts down.

- [ ] **Step 1: Write the loopback module**

```rust
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
```

- [ ] **Step 2: Run the pure-helper tests**

Run: `cargo test -p janitor-aws --lib loopback`
Expected: PASS (3 tests — the pure helpers; the socket/browser fns aren't unit-tested).

- [ ] **Step 3: Write the spike binary**

Create `janitor-aws/src/bin/loopback-spike.rs`:

```rust
//! Step-0 integration spike (ADR 0010 §2a): prove browser-open → loopback-catch
//! → code-extraction on this OS, against a HARDCODED fake authorize URL that
//! immediately redirects back to our loopback. Run manually:
//!
//!   cargo run -p janitor-aws --bin loopback-spike
//!
//! It should open a browser tab that bounces to 127.0.0.1 and the program should
//! print the extracted code/state, then exit. No AWS involved.

use std::time::Duration;

use janitor_aws::loopback::{bind_first_free, open_browser, query_param, wait_for_redirect};

#[tokio::main]
async fn main() {
    let (listener, redirect_uri) = bind_first_free().await.expect("bind loopback");
    println!("listening on {redirect_uri}");

    // A real /authorize would redirect here with ?code=&state=. To prove the
    // shell without AWS, point the browser straight at our own loopback with
    // fake params (httpbin's redirect is an alternative if offline testing is ok).
    let fake_redirect = format!("{redirect_uri}?code=FAKE_CODE&state=FAKE_STATE");
    println!("opening browser at fake authorize redirect: {fake_redirect}");
    open_browser(&fake_redirect).expect("open browser");

    let query = wait_for_redirect(listener, Duration::from_secs(60)).await.expect("redirect");
    println!("got query: {query}");
    println!("code  = {:?}", query_param(&query, "code"));
    println!("state = {:?}", query_param(&query, "state"));
    assert_eq!(query_param(&query, "code").as_deref(), Some("FAKE_CODE"));
    println!("loopback spike OK");
}
```

- [ ] **Step 4: Manually run the spike on Windows**

Run: `cargo run -p janitor-aws --bin loopback-spike`
Expected: a browser tab opens and bounces to `127.0.0.1`, the terminal prints `code = Some("FAKE_CODE")` and `loopback spike OK`. This is the integration-risk flush; if the port can't bind or the browser doesn't open, resolve it now (firewall prompt is normal on first run — allow it).

- [ ] **Step 5: Commit**

```bash
git add janitor-aws/src/loopback.rs janitor-aws/src/bin/loopback-spike.rs
git commit -m "feat(aws): one-shot loopback listener + browser launch + step-0 spike (ADR 0010)"
```

---

### Task 10: Real SDK adapters (`aws_impl.rs`)

**Files:**
- Create: `janitor-aws/src/aws_impl.rs`

Implement the `wire.rs` traits over the real SDK. **This is shell code — confirm every SDK call against the installed crate docs.** Key obligations from ADR 0010 §10: build the OIDC/SSO clients with **no credential provider** (`no_credentials()`); build the Secrets Manager client with the **injected `Credential`**, never the default chain; map errors to our taxonomy; never put secrets/bodies in `SessionError::Sdk { context }`.

- [ ] **Step 1: Write the adapters**

> The block below is the intended structure. Method names like `register_client()`, `create_token()`, `get_role_credentials()`, `get_secret_value()` and their setters/getters are the documented SDK surface; if a setter differs (e.g. `set_grant_types` vs `grant_types`), follow the installed SDK. Build clients with explicit region + `no_credentials()` for the unauthenticated calls.

```rust
//! Real AWS SDK adapters for the `wire.rs` traits (ADR 0010 §5/§10). UNTESTED
//! shell: confirm SDK signatures against the installed crate docs. Two rules:
//!  - Unauthenticated OIDC/SSO clients use NO credential provider.
//!  - The Secrets Manager client uses the injected per-Env Credential only.
//!  - `SessionError::Sdk { context }` carries a short label, never a body.

use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_config::BehaviorVersion;

use crate::error::{SessionError, SignInError};
use crate::types::{Credential, SsoToken};
use crate::wire::{
    ClientRegistration, OidcClient, RawSecret, RoleCredentialClient, SecretsApi, TokenExchange,
};

/// Real OIDC client (`RegisterClient` + `CreateToken`).
pub struct AwsOidcClient {
    inner: aws_sdk_ssooidc::Client,
}

impl AwsOidcClient {
    /// Build with explicit region and NO credentials (the calls are authorized
    /// by request body, not SigV4 ambient creds — ADR 0010 §10).
    pub async fn new(region: String) -> Self {
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .no_credentials()
            .load()
            .await;
        AwsOidcClient { inner: aws_sdk_ssooidc::Client::new(&conf) }
    }
}

#[async_trait]
impl OidcClient for AwsOidcClient {
    async fn register_client(
        &self,
        redirect_uris: &[String],
    ) -> Result<ClientRegistration, SignInError> {
        let mut req = self
            .inner
            .register_client()
            .client_name("janitor")
            .client_type("public")
            .grant_types("authorization_code")
            .grant_types("refresh_token")
            .scopes("sso:account:access");
        for uri in redirect_uris {
            req = req.redirect_uris(uri.clone());
        }
        let out = req.send().await.map_err(|_| SignInError::Sdk { context: "RegisterClient".into() })?;
        Ok(ClientRegistration {
            client_id: out.client_id().unwrap_or_default().to_string(),
            client_secret: out.client_secret().unwrap_or_default().to_string(),
        })
    }

    async fn create_token(&self, ex: TokenExchange<'_>) -> Result<SsoToken, SignInError> {
        let out = self
            .inner
            .create_token()
            .client_id(&ex.registration.client_id)
            .client_secret(&ex.registration.client_secret)
            .grant_type("authorization_code")
            .code(ex.code)
            .code_verifier(ex.code_verifier)
            .redirect_uri(ex.redirect_uri)
            .send()
            .await
            .map_err(|_| SignInError::TokenEndpoint)?;
        let access = out.access_token().ok_or(SignInError::TokenEndpoint)?.to_string();
        // expires_in is seconds from now (i32). Read it; never hardcode.
        let expires_in = out.expires_in();
        let expires_at = SystemTime::now() + Duration::from_secs(expires_in.max(0) as u64);
        Ok(SsoToken::new(access, expires_at))
    }
}

/// Real role-credential client (`GetRoleCredentials`).
pub struct AwsRoleClient {
    inner: aws_sdk_sso::Client,
}
impl AwsRoleClient {
    pub async fn new(region: String) -> Self {
        let conf = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .no_credentials()
            .load()
            .await;
        AwsRoleClient { inner: aws_sdk_sso::Client::new(&conf) }
    }
}
#[async_trait]
impl RoleCredentialClient for AwsRoleClient {
    async fn get_role_credentials(
        &self,
        token: &SsoToken,
        account_id: &str,
        permission_set: &str,
        _region: &str,
    ) -> Result<Credential, SessionError> {
        let out = self
            .inner
            .get_role_credentials()
            .access_token(token.expose())
            .account_id(account_id)
            .role_name(permission_set)
            .send()
            .await
            .map_err(map_role_err)?;
        let rc = out.role_credentials().ok_or(SessionError::Sdk { context: "GetRoleCredentials(empty)".into() })?;
        // expiration is epoch MILLISECONDS (i64) per the SSO API. Read it.
        let expiration = SystemTime::UNIX_EPOCH + Duration::from_millis(rc.expiration().max(0) as u64);
        Ok(Credential::new(
            rc.access_key_id().unwrap_or_default().to_string(),
            rc.secret_access_key().unwrap_or_default().to_string(),
            rc.session_token().unwrap_or_default().to_string(),
            expiration,
        ))
    }
}

/// Map a GetRoleCredentials SDK error to our taxonomy. UnauthorizedException →
/// ReauthRequired (dead token). VERIFY whether not-entitled is distinguishable
/// (ADR 0010 verify list); until then both map to ReauthRequired and the facade
/// cap prevents a browser loop.
fn map_role_err<E: std::fmt::Debug>(e: aws_sdk_sso::error::SdkError<E>) -> SessionError {
    // Inspect the typed service error if present; fall back to scrubbed Sdk.
    // Pseudocode shape — confirm the SdkError matching API for the installed SDK:
    //   if let SdkError::ServiceError(se) = &e { match se.err() { Unauthorized => ReauthRequired, ... } }
    let label = format!("{:?}", std::mem::discriminant(&e));
    // NOTE: discriminant() avoids printing the error body (which may carry data).
    SessionError::Sdk { context: format!("GetRoleCredentials:{label}") }
}

/// Real Secrets Manager client (`GetSecretValue`) using the injected Credential.
pub struct AwsSecretsApi {
    region: String,
}
impl AwsSecretsApi {
    pub fn new(region: String) -> Self {
        AwsSecretsApi { region }
    }
}
#[async_trait]
impl SecretsApi for AwsSecretsApi {
    async fn get_secret_value(
        &self,
        cred: &Credential,
        secret_id: &str,
        region: &str,
    ) -> Result<RawSecret, SessionError> {
        // Build a per-call client with the injected Credential ONLY (ADR 0010 §10).
        let creds = aws_sdk_secretsmanager::config::Credentials::new(
            cred.access_key_id(),
            cred.secret_access_key(),
            Some(cred.session_token().to_string()),
            None,
            "janitor",
        );
        let conf = aws_sdk_secretsmanager::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(aws_sdk_secretsmanager::config::Region::new(region.to_string()))
            .credentials_provider(creds)
            .build();
        let client = aws_sdk_secretsmanager::Client::from_conf(conf);
        let out = client
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await
            .map_err(map_secret_err)?;
        Ok(RawSecret {
            secret_string: out.secret_string().map(|s| s.to_string()),
            secret_binary: out.secret_binary().map(|b| b.as_ref().to_vec()),
        })
    }
}

/// Map a GetSecretValue SDK error to our taxonomy. Confirm variant names against
/// the installed secretsmanager SDK (ResourceNotFound, AccessDenied, throttling).
fn map_secret_err<E: std::fmt::Debug>(e: aws_sdk_secretsmanager::error::SdkError<E>) -> SessionError {
    let label = format!("{:?}", std::mem::discriminant(&e));
    SessionError::Sdk { context: format!("GetSecretValue:{label}") }
}
```

> **Implementer note on error mapping:** the `map_*_err` functions above are deliberately conservative (everything → scrubbed `Sdk`) so the crate compiles before the live-verify pass. Resolving the ADR 0010 verify list (Task 14) means replacing the `discriminant` fallback with real matches: `GetRoleCredentials` `UnauthorizedException` → `ReauthRequired`; `GetSecretValue` `ResourceNotFoundException` → `NotFound`, `AccessDeniedException` → `AccessDenied`, throttling → `Throttled`. Until then the facade still behaves safely (an `Sdk` error is fatal-but-bounded; it just isn't classified).

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p janitor-aws`
Expected: PASS. Compile errors here are almost always SDK-signature mismatches — open `cargo doc -p aws-sdk-ssooidc --open` (etc.) and align. Do **not** add `unwrap()` on network results; keep the error mapping.

- [ ] **Step 3: Commit**

```bash
git add janitor-aws/src/aws_impl.rs
git commit -m "feat(aws): real SDK adapters (no-cred OIDC/SSO, injected-cred Secrets) (ADR 0010 §10)"
```

---

### Task 11: Real `Authenticator` + `Reauth` impl

**Files:**
- Create: `janitor-aws/src/authenticator.rs`

Compose `RegisterClient` → build `/authorize` URL with PKCE+state → open browser → catch redirect on loopback → verify state → `CreateToken`. Implements the `Reauth` trait so the facade can re-Sign-in. Shell code (drives the browser).

- [ ] **Step 1: Write the authenticator**

```rust
//! Real `Authenticator` (ADR 0010 §3/§7): the full browser PKCE Sign-in. Shell
//! code — it opens a browser and binds a socket. The pure pieces it uses
//! (`pkce`, `state`, `loopback::query_param`) are tested elsewhere.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::error::SignInError;
use crate::loopback::{bind_first_free, open_browser, query_param, redirect_uris, wait_for_redirect};
use crate::pkce;
use crate::source::Reauth;
use crate::state;
use crate::types::SsoToken;
use crate::wire::{OidcClient, TokenExchange};

/// How long to wait for the user to complete the browser Sign-in.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(180);

/// Drives a full Identity Center browser Sign-in.
pub struct Authenticator {
    oidc: Arc<dyn OidcClient>,
    /// The Identity Center start/authorize host config: the OIDC issuer's
    /// authorization endpoint base (from the org's SSO start URL / region).
    authorize_endpoint: String,
}

impl Authenticator {
    pub fn new(oidc: Arc<dyn OidcClient>, authorize_endpoint: String) -> Self {
        Authenticator { oidc, authorize_endpoint }
    }

    /// Run the flow once, returning a fresh SSO token.
    pub async fn sign_in_once(&self) -> Result<SsoToken, SignInError> {
        // 1. Register a public client for our loopback redirect URIs.
        let uris = redirect_uris();
        let registration = self.oidc.register_client(&uris).await?;

        // 2. Bind a loopback port from the registered set, THEN build the URL
        //    with that exact redirect_uri (ADR 0010 §7 ordering).
        let (listener, redirect_uri) = bind_first_free().await?;
        let pkce = pkce::generate();
        let csrf = state::generate();
        let authorize_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}&scopes=sso:account:access",
            self.authorize_endpoint,
            urlencode(&registration.client_id),
            urlencode(&redirect_uri),
            urlencode(&pkce.challenge),
            urlencode(&csrf),
        );

        // 3. Open the browser and wait for the redirect.
        open_browser(&authorize_url)?;
        let query = wait_for_redirect(listener, SIGN_IN_TIMEOUT).await?;

        // 4. Verify CSRF state BEFORE using the code.
        let returned_state = query_param(&query, "state").unwrap_or_default();
        if !state::matches(&csrf, &returned_state) {
            return Err(SignInError::StateMismatch);
        }
        let code = query_param(&query, "code").ok_or(SignInError::TokenEndpoint)?;

        // 5. Exchange the code (+ PKCE verifier) for the SSO token.
        self.oidc
            .create_token(TokenExchange {
                registration: &registration,
                code: &code,
                code_verifier: &pkce.verifier,
                redirect_uri: &redirect_uri,
            })
            .await
    }
}

#[async_trait]
impl Reauth for Authenticator {
    async fn sign_in(&self) -> Result<SsoToken, SignInError> {
        self.sign_in_once().await
    }
}

/// Minimal percent-encoding for URL query values (RFC 3986 unreserved kept).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_escapes_reserved_and_keeps_unreserved() {
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(urlencode("a/b c"), "a%2Fb%20c");
        assert_eq!(urlencode("x:y"), "x%3Ay");
    }
}
```

- [ ] **Step 2: Run the pure-helper test + build**

Run: `cargo test -p janitor-aws --lib authenticator`
Expected: PASS (1 test — `urlencode`).
Run: `cargo build -p janitor-aws`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add janitor-aws/src/authenticator.rs
git commit -m "feat(aws): real Authenticator (RegisterClient→browser PKCE→CreateToken) (ADR 0010)"
```

---

## Phase 5 — Wire-up + live verify

### Task 12: `live-verify` binary

**Files:**
- Create: `janitor-aws/src/bin/live-verify.rs`

The human-run harness (ADR 0010 §5): compose the real adapters via `AuthenticatedSource`, fetch ONE Mapping, and print the masked `MatrixView` (single-environment) using core's `project()` — **never** a raw Value (ADR 0010 §2 output discipline). It prints a checklist of error paths to force by hand.

- [ ] **Step 1: Write the binary**

```rust
//! Live verification harness (ADR 0010 §5, Milestone B). Run by a human against
//! a real Identity Center org:
//!
//!   cargo run -p janitor-aws --bin live-verify -- \
//!       --authorize-endpoint https://oidc.<region>.amazonaws.com/authorize \
//!       --sso-region <region> \
//!       --account-id <acct> --role <permission-set> \
//!       --secret-region <region> --secret-id <name-or-arn>
//!
//! Prints only a MASKED single-environment matrix (never a Value), then a
//! checklist of error paths to force by hand to close the ADR 0010 verify list.

use std::env;
use std::sync::Arc;

use janitor_aws::authenticator::Authenticator;
use janitor_aws::aws_impl::{AwsOidcClient, AwsRoleClient, AwsSecretsApi};
use janitor_aws::broker::CredentialBroker;
use janitor_aws::secrets::SecretsClient;
use janitor_aws::source::AuthenticatedSource;
use janitor_aws::types::SystemClock;
use janitor_core::compare::Comparison;
use janitor_core::config::Mapping;
use janitor_core::view::project;

fn arg(flag: &str) -> Option<String> {
    let args: Vec<String> = env::args().collect();
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

#[tokio::main]
async fn main() {
    let authorize_endpoint = arg("--authorize-endpoint").expect("--authorize-endpoint");
    let sso_region = arg("--sso-region").expect("--sso-region");
    let account_id = arg("--account-id").expect("--account-id");
    let role = arg("--role").expect("--role");
    let secret_region = arg("--secret-region").expect("--secret-region");
    let secret_id = arg("--secret-id").expect("--secret-id");

    let mapping = Mapping {
        environment: "live".into(),
        account_id,
        region: secret_region.clone(),
        secret_id,
        permission_set: role,
    };

    let oidc = Arc::new(AwsOidcClient::new(sso_region.clone()).await);
    let role_client = Arc::new(AwsRoleClient::new(sso_region).await);
    let secrets_api = Arc::new(AwsSecretsApi::new(secret_region));
    let clock = Arc::new(SystemClock);

    let authenticator = Arc::new(Authenticator::new(oidc, authorize_endpoint));

    // Initial Sign-in (this opens the browser).
    println!("Signing in (a browser tab will open)...");
    let token = authenticator.sign_in_once().await.expect("sign-in");
    println!("Signed in. SSO token acquired (held in memory only).");

    let broker = CredentialBroker::new(token, role_client.clone(), clock.clone());
    let secrets = SecretsClient::new(secrets_api);
    let mut source = AuthenticatedSource::new(broker, secrets, authenticator, role_client, clock);

    let shape = source.fetch(&mapping).await.expect("fetch");

    // Output discipline: project to a MASKED matrix, never print a Value.
    let sets = vec![(mapping.environment.clone(), shape)];
    let comparison = Comparison::build(&sets);
    let view = project(&comparison);
    println!("\nMASKED MATRIX (single environment):");
    println!("environments: {:?}", view.environments);
    for row in &view.rows {
        println!("  {} [{:?}] -> {:?}", row.name, row.state, row.cells);
    }

    println!("\n--- ADR 0010 verify checklist (force these by hand) ---");
    println!("[ ] token-expiry → re-Sign-in: wait out / revoke the SSO token, re-run, confirm ONE browser reopen");
    println!("[ ] access-denied: point --secret-id at a denied secret, confirm AccessDenied (not a browser loop)");
    println!("[ ] not-found: point --secret-id at a missing name, confirm NotFound");
    println!("[ ] throttle: (optional) hammer GetSecretValue, confirm Throttled surfaces");
    println!("[ ] confirm roleCredentials.expiration is read (not a hardcoded 1h)");
    println!("[ ] confirm loopback redirect_uri exact-match accepted by /authorize + CreateToken");
}
```

- [ ] **Step 2: Build (don't run yet — Milestone B)**

Run: `cargo build -p janitor-aws --bin live-verify`
Expected: PASS. (Running it is Task 14, the human-gated milestone.)

- [ ] **Step 3: Commit**

```bash
git add janitor-aws/src/bin/live-verify.rs
git commit -m "feat(aws): live-verify harness — masked single-env matrix + verify checklist (ADR 0010)"
```

---

### Task 13: Full workspace green + docs wiring (Milestone A close)

> **STATUS (2026-05-30, resumed session): Steps 1–4 DONE, Step 5 (commit) NOT yet done — awaiting user.**
> The file edits are written to disk but **not committed** (working tree dirty on
> `feat/identity-center-auth`). Workspace verified green earlier this session
> (`cargo test --workspace` ✓, clippy `-D warnings` ✓, fmt ✓, `janitor-core`
> llvm-cov **98.15%** ≥80% ✓).
> **Deviation from plan (surfaced to user):** Step 3 as written said to paste a CI
> *comment* claiming "janitor-aws is exercised by `cargo test --workspace` above" —
> but no such step existed (`ci.yml` only ran `cargo llvm-cov -p janitor-core`, so
> janitor-aws tests never ran in CI). Resolved by **adding a real `Test (workspace)`
> step** running `cargo test --workspace` before the coverage step, plus the
> core-only-gate comment. This strengthens CI (more tests run); it is not a test
> regression. README was also more stale than the plan assumed (claimed a single
> `janitor-core` crate, predating the GUI) and was refreshed to reflect all three
> crates + ADRs 0009/0010.

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `CLAUDE.md` (status blurb)
- Modify: `README.md` (commands, if it lists them)

- [ ] **Step 1: Confirm the whole workspace is green**

Run: `cargo fmt --all -- --check`
Expected: PASS (run `cargo fmt --all` first if not).
Run: `cargo clippy --all-targets --all-features -- -D warnings`
Expected: PASS (no warnings). Fix any clippy findings in `janitor-aws`.
Run: `cargo test --workspace`
Expected: PASS — all `janitor-core` tests (unchanged) + the new `janitor-aws` unit tests. Confirm the core count is unchanged from before this slice (no existing test altered).

- [ ] **Step 2: Confirm core coverage gate still passes**

Run: `cargo llvm-cov -p janitor-core --fail-under-lines 80`
Expected: PASS — `janitor-core` is untouched, so coverage is unchanged.

- [ ] **Step 3: Add a CI note (gate stays core-only)**

Edit `.github/workflows/ci.yml`, updating the coverage step's comment to record the deliberate decision that `janitor-aws` is exercised by `cargo test --workspace` but not line-gated (its untestable browser/loopback/SDK shell would drag a blanket gate below 80% — ADR 0010 §5):

```yaml
      - name: coverage (janitor-core ≥80%)
        # janitor-aws is exercised by `cargo test --workspace` above but is NOT
        # line-gated: its browser/loopback/SDK shell is untestable by design
        # (ADR 0010 §5); a blanket gate would fail on shell lines, so the tested
        # logic is proven by its unit tests instead.
        run: |
          cargo install cargo-llvm-cov --locked
          cargo llvm-cov -p janitor-core --fail-under-lines 80
```

- [ ] **Step 4: Update the CLAUDE.md status blurb**

Edit the status line at the top of `CLAUDE.md` to note the headless auth slice landed (code-complete / Milestone A), real Identity Center Sign-in now exists in `janitor-aws` behind the tested facade, and Milestone B (live verification) is the open follow-up. Keep it to the existing one-paragraph style.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml CLAUDE.md README.md
git commit -m "docs(aws): record headless auth slice (Milestone A); CI note keeps gate core-only (ADR 0010)"
```

---

## Phase 6 — Live verification (Milestone B, human-gated)

### Task 14: Run `live-verify` against the real org and resolve the verify list

**Files:**
- Modify: `janitor-aws/src/aws_impl.rs` (error mapping, per observations)
- Modify: `janitor-aws/src/wire.rs` fakes / tests (correct to match reality)
- Modify: `docs/adr/0010-aws-adapter-crate-and-auth-object-model.md` (tick the verify list)

> This task requires a human at a browser with a real Identity Center org. It is the ADR 0010 "Definition of done — Milestone B" gate. It does not block Milestone A from merging.

- [ ] **Step 1: Drive the happy path**

Run `live-verify` (see its header for the exact flags) against a real org + a readable secret. Confirm: a browser opens, Sign-in completes, the masked matrix prints, **no Value appears** in output.

- [ ] **Step 2: Force each error path on the checklist**

For each checklist line the binary prints, force the condition and record the **actual** AWS error shape:
- token-expiry → re-Sign-in (confirm exactly one browser reopen; no loop)
- access-denied (confirm `AccessDenied`, exactly one wasted re-mint, no loop)
- not-found (confirm `NotFound`)
- confirm `roleCredentials.expiration` is read, not hardcoded
- confirm the loopback `redirect_uri` exact-match rule

- [ ] **Step 3: Correct the error mapping and the fakes to match reality**

Replace the conservative `discriminant`-based fallbacks in `aws_impl.rs::map_role_err` / `map_secret_err` with real matches on the observed SDK error variants (`UnauthorizedException` → `ReauthRequired`, `ResourceNotFoundException` → `NotFound`, `AccessDeniedException` → `AccessDenied`, throttling → `Throttled`). **If any observed behavior contradicts a fake** (e.g. `GetRoleCredentials` *does* distinguish not-entitled from dead-token), update the fake and its driving test to match, and — per the user's global rule — **surface that the test's asserted behavior changed and why** before committing.

- [ ] **Step 4: Re-run the tested suite**

Run: `cargo test --workspace`
Expected: PASS with the corrected mappings/fakes.

- [ ] **Step 5: Tick the ADR verify list**

Edit ADR 0010's "To verify against the live API" section, marking each item resolved with a one-line note on what AWS actually does. Flip the ADR's Milestone B to closed.

- [ ] **Step 6: Commit**

```bash
git add janitor-aws/src/aws_impl.rs janitor-aws/src/wire.rs docs/adr/0010-aws-adapter-crate-and-auth-object-model.md
git commit -m "feat(aws): live-verify resolved — real error mapping + ADR 0010 verify list closed (Milestone B)"
```

---

## Self-review checklist (run after writing; for the executor's awareness)

- **Spec coverage vs ADR 0010:** §1 crate → Task 0; §2 headless scope + output discipline → Tasks 12; §2a spike → Task 9; §3 three objects + facade → Tasks 6/7/8/10/11; §4 orchestration caps → Task 8; §5 wrap-traits + fakes + live-verify-binary → Tasks 5/12/14; §6 PKCE+state pure fns → Tasks 1/2; §7 loopback → Task 9; §8 memory-only registration → Task 11 (register each Sign-in, nothing persisted); §9 error taxonomy → Task 3; §10 bypass default cred chain → Task 10; Definition of done A/B → Tasks 13/14; verify list → Task 14.
- **`&self` on `credentials_for`:** Task 6 (interior `Mutex`), as ADR 0010 requires for future N-Env concurrency.
- **No existing test modified:** Tasks only add a crate; Task 13 Step 1 explicitly re-confirms the core test count. Task 14 is the one place a fake/test may change — gated behind the surface-it rule.
- **Type consistency:** `Mapping` fields (`environment/account_id/region/secret_id/permission_set`), `SecretShape::{from_secret_string,from_secret_binary}`, `Comparison::build(&[(String, SecretShape)])`, `project(&Comparison) -> MatrixView` all match `janitor-core` as read at planning time. `CredSpec`/`FakeClock`/`FakeRoleClient`/`FakeSecretsApi`/`RawSecret`/`TokenExchange`/`ClientRegistration` are defined in Task 5 and used consistently in Tasks 6/7/8.
- **Known soft spots (SDK boundary, Tasks 10–11):** exact SDK setter/getter names and `SdkError` matching must be confirmed against installed crate docs; this is the ADR-sanctioned untested shell, not a logic gap.
