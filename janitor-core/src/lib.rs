//! `janitor-core` — the security-critical core of Janitor.
//!
//! Holds everything that matters and is testable without a GUI (ADR 0003): the
//! secret-shape model that parses AWS Secret Sets into comparable Entries, the
//! comparison engine that projects the Aligned/Drift/Gap matrix, zeroizing secret
//! types, Config load/save, the `Provider` port every backend implements, the
//! shared Discovery orchestrator, and the write seam. **No GUI dependencies.**
//! Targets ≥80% line coverage.
//!
//! ## The shared presentation seams
//!
//! `errors`, `logpane`, `pane`, `reveal`, `rows`, and `sidebar` decide what a shell
//! renders, without deciding how it looks. They were bin-local modules in
//! `janitor-gui` until #96 moved them here, because Janitor has two shells and both
//! drive all six (ADR 0035). Each is pure and tested; a shell maps the result onto
//! its own widgets and holds no logic of its own.
//!
//! ## AWS access
//!
//! Core stays offline and mockable. AWS reaches it only through the `Provider`
//! port; the concrete SDK adapters live in `janitor-aws`, `janitor-aws-auth`, and
//! `janitor-ssm`, which depend on this crate and never the other way around. Do not
//! wire an SDK client into the modules here.

pub mod cluster;
pub mod compare;
pub mod config;
pub mod discovery;
pub mod errors;
pub mod logpane;
pub mod pane;
pub mod provider;
pub mod region;
pub mod reveal;
pub mod rows;
pub mod secret;
pub mod select;
pub mod sidebar;
pub mod view;
pub mod write;
