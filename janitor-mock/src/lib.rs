//! `janitor-mock` — Janitor's **offline** [Provider](../../CONTEXT.md) (ADR 0019).
//!
//! Peer to `janitor-aws`, it depends on **`janitor-core` only — never
//! `janitor-aws`**; that independence is the substitutability proof. It holds all
//! the demo data (the canned Payments Sets, the deterministic FNV fabrication, the
//! seeded demo `Config`, and a tiny fabricated org for the Discovery picker) and
//! drives the same `core` pipeline (`Comparison::build`, `project`) a real
//! Provider does. No authentication, no network: `sign_in` succeeds instantly,
//! `reveal` returns the cached Value, and Discovery is a trivial local stub.

mod config;
mod data;
mod provider;

pub use config::seeded_config;
pub use provider::MockProvider;
