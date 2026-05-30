//! `janitor-core` — the security-critical core of Janitor.
//!
//! Holds everything that matters and is testable without a GUI (ADR 0003):
//! the secret-shape model (parsing AWS Secret Sets into comparable Entries),
//! the comparison engine (the Aligned/Drift/Gap matrix), zeroizing secret
//! types, and Config load/save. **No GUI dependencies.**
//! Targets ≥80% line coverage.
//!
//! ## AWS access (future slices)
//! This foundation slice is entirely offline. When Identity Center auth
//! (ADR 0002) and Secrets Manager I/O (ADR 0005) land, core logic must depend
//! on an **AWS-client trait**, with the concrete AWS SDK adapter isolated in
//! its own module, so the network stays mockable and the coverage gate stays
//! reachable. Do not wire the SDK directly into the modules here.

pub mod compare;
pub mod config;
pub mod secret;
pub mod mock;
pub mod source;
pub mod view;
