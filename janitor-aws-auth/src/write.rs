//! The method-agnostic **write seam** types (ADR 0031 / ADR 0032).
//!
//! These now live in `janitor-core` (ADR 0032): the
//! [`Provider::write`](janitor_core::provider::Provider::write) port speaks them, and
//! `core` cannot depend on any AWS crate. This module **re-exports** them so every
//! AWS-family caller — the [`ResourceMethod`](crate::method::ResourceMethod) write
//! method here, plus `janitor-aws` / `janitor-ssm` — keeps its existing
//! `janitor_aws_auth::write::…` paths unchanged. There is exactly one set of types;
//! nothing is converted at the boundary.
//!
//! See [`janitor_core::write`] for the definitions, the [`EnvEdit`] Debug-redaction
//! and [`summarize_edits`](janitor_core::write::summarize_edits) confirm-diff masking,
//! and their tests.

pub use janitor_core::write::{EditAction, EditSummary, EnvEdit, EnvWriteError, WriteOutcome};
