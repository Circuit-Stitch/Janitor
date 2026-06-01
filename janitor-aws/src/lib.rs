//! `janitor-aws` — Janitor's AWS adapter (ADR 0010).
//!
//! Async-native. Holds Identity Center Sign-in (browser Auth Code + PKCE),
//! per-Environment role-Credential brokering, and Secrets Manager reads.
//! Depends on `janitor-core` for domain types (`Mapping`, `SecretShape`,
//! `Value`) and the `Provider` port its `Session` implements (ADR 0019);
//! contains **no GUI**.
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
pub mod discovery;
pub mod error;
pub mod pkce;
pub mod presenter;
pub mod secrets;
pub mod session;
pub mod source;
pub mod state;
pub mod types;
pub mod wire;

// Untested shell (real I/O); compiled but not coverage-gated.
pub mod authenticator;
pub mod aws_impl;
pub mod loopback;
