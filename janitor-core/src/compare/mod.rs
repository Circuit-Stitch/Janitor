//! The comparison engine: turn already-fetched Secret Sets into a masked
//! Aligned/Drift/Gap matrix (ADR 0009). Pure and synchronous — it consumes
//! `SecretShape`s and never touches AWS.

mod engine;
mod model;

pub use model::{Cell, Comparison, EntryState, GroupId, Row, RowKey};
