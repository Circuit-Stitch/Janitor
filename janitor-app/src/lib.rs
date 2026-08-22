//! `janitor-app` — Janitor's shell-agnostic application layer.
//!
//! One crate sits between the core and the shells, and it holds two things: the
//! worker that drives a `Provider` on its own thread, and the composition root that
//! builds the real AWS-family Provider out of the adapter crates.
//!
//! It exists because of the crate graph. `janitor-aws`, `janitor-aws-auth`,
//! `janitor-ssm`, and `janitor-mock` all depend on `janitor-core`, so `janitor-core`
//! cannot name them back — Cargo rejects the cycle. The composition root has to sit
//! above all four, and the worker owns it, so both land here
//! (ADR 0035, Amendment 2026-08-21).
//!
//! Every shell drives this crate: the Slint shell in `Janitor-slint` links it
//! directly, and the SwiftUI shell in `Janitor-macos` reaches it through the UniFFI
//! boundary that `Command` and `Event` will export (ADR 0035 / ADR 0036). Nothing
//! here names a toolkit, and no variant describes a platform only one shell has.
//! Presentation seams — what a shell renders, never how it looks — stay in
//! `janitor-core`.

pub mod worker;

// The UniFFI boundary (ADR 0035). Optional, so a Slint build compiles none of it.
// `setup_scaffolding!` has to sit at the crate root: the code it generates for the
// `ffi` module names `crate::UniFfiTag`.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!("janitor");
#[cfg(feature = "uniffi")]
pub mod ffi;
