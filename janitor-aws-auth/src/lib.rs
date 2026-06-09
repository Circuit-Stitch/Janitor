//! `janitor-aws-auth` — Janitor's shared AWS Identity Center access layer
//! (ADR 0024). The front half of every AWS-family Provider: browser Auth Code +
//! PKCE Sign-in, the account/role catalog, per-Environment role-Credential
//! brokering, the zeroizing `SsoToken`/`Credential` types, and the generic AWS
//! error taxonomy. Depends on `janitor-core` only; contains **no** Secrets
//! Manager (or any other Provider-tail) logic and **no GUI**.
//!
//! ## Trust & memory posture
//! Nothing here is persisted. The SSO token and role Credentials live only in
//! memory, in zeroizing buffers. The client registration is re-created each
//! launch (never cached). See ADR 0002 / ADR 0010 / THREAT-MODEL.md.
//!
//! ## Test seam
//! Every SDK operation sits behind a narrow trait in [`wire`] whose inputs and
//! outputs are our own SDK-free types, so the brokering/orchestration logic is
//! unit-tested against the fakes in [`wire::fakes`]. Only [`loopback`],
//! [`authenticator`], and [`aws_impl`] (the browser/listener + real SDK calls)
//! are untested. The fakes are exposed to dependent crates' tests via the
//! `test-support` feature (ADR 0024); they are not compiled into normal builds.

pub mod authwalk;
pub mod broker;
pub mod error;
pub mod pkce;
pub mod state;
pub mod types;
pub mod wire;

// Untested shell (real I/O); compiled but not coverage-gated.
pub mod authenticator;
pub mod aws_impl;
pub mod loopback;
