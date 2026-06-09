//! `janitor-aws` — Janitor's Secrets Manager resource **Method** (ADR 0010 /
//! ADR 0024 / ADR 0031).
//!
//! Async-native. The shared Identity Center front half (Sign-in, account/role
//! catalog, credential brokering, the zeroizing `SsoToken`/`Credential` types,
//! the AWS error taxonomy) plus the generic `AwsFamilyProvider` shell (the fetch
//! ladder + ADR 0018 recovery + the `Provider` port) live in `janitor-aws-auth`;
//! this crate holds only the Secrets Manager *tail*: `GetSecretValue` reads
//! ([`SecretsClient`](secrets)), the SM Discovery walk ([`discovery`]), and the
//! [`SecretsManagerMethod`](method::SecretsManagerMethod) that wraps them behind
//! the shared `ResourceMethod` seam. Depends on `janitor-core` for domain types
//! (`Mapping`, `SecretShape`, `Value`) and on `janitor-aws-auth` for the auth
//! primitives + the Provider shell (ADR 0031); contains **no GUI**.
//!
//! ## Trust & memory posture
//! Nothing here is persisted. The SSO token and role Credentials live only in
//! memory, in zeroizing buffers (in `janitor-aws-auth`). See ADR 0002 / ADR
//! 0010 / THREAT-MODEL.md.
//!
//! ## Test seam
//! Each SDK operation sits behind a narrow trait whose inputs and outputs are
//! our own SDK-free types, so the orchestration logic is unit-tested against
//! fakes (the front-half fakes come from `janitor_aws_auth::wire::fakes` via its
//! `test-support` feature; the Secrets Manager `FakeSecretsApi` lives in
//! [`wire`]). Only [`aws_impl`] (the real SDK calls) is untested.

pub mod discovery;
pub mod method;
pub mod presenter;
pub mod secrets;
pub mod wire;

pub use method::SecretsManagerMethod;

// Untested shell (real I/O); compiled but not coverage-gated.
pub mod aws_impl;
