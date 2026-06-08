//! The pure-Rust Session Manager (MGS) data-channel transport (ADR 0025 §3,
//! transport b). It speaks the agent's binary message protocol directly over the
//! `StartSession` `StreamUrl` WebSocket, so reading a remote `.env` needs **no**
//! `session-manager-plugin` binary.
//!
//! - [`frame`] — the AgentMessage byte codec (pure, fully tested).
//! - [`protocol`] — the session state machine + driver (pure logic + a thin
//!   driver tested against a fake channel).
//! - [`channel`] — the real `wss` socket adapter (the only untested shell here).

pub mod frame;
pub mod protocol;

mod channel;

pub use channel::TungsteniteChannel;
pub use protocol::{read_command_output, DataChannel, MgsError, SessionState};
