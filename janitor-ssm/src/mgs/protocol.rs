//! The Session Manager data-channel protocol (ADR 0025 §3, transport b): the
//! state machine that drives one `AWS-StartNonInteractiveCommand` session over
//! the WebSocket [`DataChannel`] and accumulates the command's stdout.
//!
//! The protocol is split so almost all of it is **pure, tested logic**:
//!
//! - [`SessionState`] is a deterministic state machine: given an incoming
//!   [`AgentMessage`] it returns the [`Outgoing`] messages to send (acks, the
//!   handshake response) and accumulates stdout — no I/O, no clock, no UUIDs.
//! - [`read_command_output`] is the thin driver: it opens the channel handshake,
//!   loops `recv → on_message → send`, and stamps each outgoing message with a
//!   fresh UUID + timestamp. It is exercised end-to-end against a scripted
//!   [`DataChannel`] fake in tests; only the real socket impl ([`super::channel`])
//!   is the untested shell (ADR 0010 §5).
//!
//! Flow for a non-interactive `cat`:
//! 1. send the OpenDataChannel handshake (a JSON **text** frame);
//! 2. agent → `output_stream_data`/`handshake_request`; we ack + reply
//!    `input_stream_data`/`handshake_response` (Success for `SessionType`;
//!    `KMSEncryption` is unsupported — Janitor's pure transport does not do the
//!    KMS data-key exchange, so an encrypted session fails fast and masked);
//! 3. agent → `handshake_complete`, then `output_stream_data`/`Output` frames
//!    carrying stdout (acked, accumulated by sequence number), then an exit code;
//! 4. a non-zero exit (e.g. `cat` on a missing/denied path) → masked failure.
//!
//! Nothing here logs or `Debug`-prints a payload — stdout is the `.env`'s bytes
//! (a Value). [`MgsError`] carries only structural context, never payload bytes.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::frame::{message_type, payload_type, AgentMessage, FLAG_FIN, FLAG_SYN};

/// The client version advertised in the OpenDataChannel handshake + handshake
/// response. The agent does not pin a specific value; this only needs to be a
/// non-empty version-shaped string.
const CLIENT_VERSION: &str = "1.2.0.0-janitor";

/// `ActionStatus` values in a handshake response (`amazon-ssm-agent` contract).
const ACTION_SUCCESS: i32 = 1;
const ACTION_UNSUPPORTED: i32 = 3;

/// A failure of the data-channel transport. Every variant is masked — it carries
/// only structural/protocol context, **never** a payload byte (THREAT-MODEL). The
/// transport boundary maps these onto `SessionError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MgsError {
    /// The WebSocket send/recv failed (the real channel surfaces socket errors
    /// here). `context` is a fixed label, never payload text.
    #[error("ssm data channel: {0}")]
    Channel(String),
    /// A received frame or handshake payload was malformed.
    #[error("ssm protocol: {0}")]
    Protocol(String),
    /// The session negotiated KMS encryption, which this transport does not
    /// implement (the org enabled session-data encryption).
    #[error("ssm session encryption (KMS) is not supported")]
    KmsEncryptionUnsupported,
    /// The remote command exited non-zero (e.g. `cat` on a missing/denied path).
    #[error("remote command failed")]
    CommandFailed,
    /// The channel closed before the command's output completed.
    #[error("ssm data channel closed early")]
    ClosedEarly,
}

/// The WebSocket data channel seam. The real impl ([`super::channel`]) speaks
/// `wss` via tungstenite; tests use a scripted fake, so the whole driver is
/// covered without a socket. Object-safe so the driver takes `&mut dyn`.
#[async_trait]
pub trait DataChannel: Send {
    /// Send the OpenDataChannel handshake as a WebSocket **text** frame.
    async fn send_text(&mut self, text: String) -> Result<(), MgsError>;
    /// Send a serialized [`AgentMessage`] as a WebSocket **binary** frame.
    async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<(), MgsError>;
    /// Receive the next WebSocket binary frame's bytes; `None` on clean close.
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, MgsError>;
}

/// One message the state machine wants sent, minus the per-send UUID + timestamp
/// the driver stamps on (keeping the state machine deterministic). `schema_version`
/// is always 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub message_type: String,
    pub payload_type: u32,
    pub flags: u64,
    pub sequence_number: i64,
    pub payload: Vec<u8>,
}

impl Outgoing {
    /// Stamp the per-send UUID + timestamp to make a wire-ready [`AgentMessage`].
    /// `created_date` must be non-zero (the agent's `Validate` rejects zero).
    fn into_agent_message(self, message_id: Uuid, created_date: u64) -> AgentMessage {
        AgentMessage {
            message_type: self.message_type,
            schema_version: 1,
            created_date,
            sequence_number: self.sequence_number,
            flags: self.flags,
            message_id,
            payload_type: self.payload_type,
            payload: self.payload,
        }
    }
}

// ---- handshake / acknowledge JSON payloads (amazon-ssm-agent contract) ----

#[derive(Serialize)]
struct OpenDataChannelInput {
    #[serde(rename = "MessageSchemaVersion")]
    message_schema_version: String,
    #[serde(rename = "RequestId")]
    request_id: String,
    #[serde(rename = "TokenValue")]
    token_value: String,
    #[serde(rename = "ClientId")]
    client_id: String,
    #[serde(rename = "ClientVersion")]
    client_version: String,
}

#[derive(Serialize)]
struct AcknowledgeContent {
    #[serde(rename = "AcknowledgedMessageType")]
    message_type: String,
    #[serde(rename = "AcknowledgedMessageId")]
    message_id: String,
    #[serde(rename = "AcknowledgedMessageSequenceNumber")]
    sequence_number: i64,
    #[serde(rename = "IsSequentialMessage")]
    is_sequential_message: bool,
}

#[derive(Deserialize)]
struct HandshakeRequestPayload {
    #[serde(rename = "RequestedClientActions", default)]
    requested_client_actions: Vec<RequestedClientAction>,
}

#[derive(Deserialize)]
struct RequestedClientAction {
    #[serde(rename = "ActionType")]
    action_type: String,
}

#[derive(Serialize)]
struct HandshakeResponsePayload {
    #[serde(rename = "ClientVersion")]
    client_version: String,
    #[serde(rename = "ProcessedClientActions")]
    processed_client_actions: Vec<ProcessedClientAction>,
    #[serde(rename = "Errors")]
    errors: Vec<String>,
}

#[derive(Serialize)]
struct ProcessedClientAction {
    #[serde(rename = "ActionType")]
    action_type: String,
    #[serde(rename = "ActionStatus")]
    action_status: i32,
    #[serde(rename = "ActionResult")]
    action_result: Option<serde_json::Value>,
    #[serde(rename = "Error")]
    error: String,
}

/// The deterministic data-channel state machine. Feed it each incoming
/// [`AgentMessage`] via [`on_message`](Self::on_message); it returns what to send
/// and accumulates stdout. No I/O, no clock, no randomness — fully unit-tested.
#[derive(Default)]
pub struct SessionState {
    /// stdout chunks keyed by their sequence number, so [`finish`](Self::finish)
    /// concatenates them in order regardless of arrival order.
    output: BTreeMap<i64, Vec<u8>>,
    /// Our outgoing `input_stream_data` sequence (SYN on the first).
    out_seq: i64,
    /// Whether we have already answered a `handshake_request`. The agent
    /// retransmits the unacked `handshake_request` at the data-channel layer; we
    /// must keep acking each copy but answer the handshake only once (re-answering
    /// restarts the handshake and bumps our sequence).
    handshake_responded: bool,
    exit_code: Option<i64>,
    channel_closed: bool,
    error: Option<MgsError>,
}

impl SessionState {
    pub fn new() -> Self {
        SessionState::default()
    }

    /// Whether the session has reached a terminal state (the driver stops).
    pub fn done(&self) -> bool {
        self.error.is_some() || self.exit_code.is_some() || self.channel_closed
    }

    /// Process one incoming message, returning the messages to send back.
    pub fn on_message(&mut self, msg: &AgentMessage) -> Vec<Outgoing> {
        match msg.message_type.as_str() {
            message_type::OUTPUT_STREAM_DATA => self.on_output(msg),
            message_type::CHANNEL_CLOSED => {
                self.channel_closed = true;
                Vec::new()
            }
            // Flow-control + the agent's acks of our messages: nothing to do
            // (Janitor only reads, so it never pauses sending).
            _ => Vec::new(),
        }
    }

    /// Handle an `output_stream_data` message: always ack it, then act on its
    /// payload type.
    fn on_output(&mut self, msg: &AgentMessage) -> Vec<Outgoing> {
        let mut out = vec![self.ack(msg)];
        match msg.payload_type {
            payload_type::HANDSHAKE_REQUEST => {
                // Answer the handshake once; later (retransmitted) copies are only
                // acked, not re-answered.
                if !self.handshake_responded {
                    if let Some(resp) = self.handshake_response(msg) {
                        out.push(resp);
                    }
                    self.handshake_responded = true;
                }
            }
            payload_type::OUTPUT => {
                // Accumulate stdout by sequence number (deduped — a re-sent frame
                // overwrites with the same bytes).
                self.output.insert(msg.sequence_number, msg.payload.clone());
            }
            payload_type::EXIT_CODE => {
                self.exit_code = Some(parse_exit_code(&msg.payload));
            }
            payload_type::STDERR | payload_type::ERROR => {
                // Never store stderr/error bytes (they can echo the path or file
                // content); their presence is treated as a failed read.
                self.error.get_or_insert(MgsError::CommandFailed);
            }
            // HANDSHAKE_COMPLETE and anything else: just the ack.
            _ => {}
        }
        out
    }

    /// Build an `acknowledge` for a received message (shared with [`WriteSession`]).
    fn ack(&self, msg: &AgentMessage) -> Outgoing {
        build_ack(msg)
    }

    /// Build the `handshake_response` for a `handshake_request`, advancing
    /// `out_seq` and recording a KMS-unsupported / malformed error on `self` as the
    /// shared [`build_handshake_response`] reports it.
    fn handshake_response(&mut self, msg: &AgentMessage) -> Option<Outgoing> {
        match build_handshake_response(&msg.payload, self.out_seq) {
            Ok((out, kms_unsupported)) => {
                if let Some(e) = kms_unsupported {
                    self.error = Some(e);
                }
                self.out_seq += 1;
                Some(out)
            }
            Err(e) => {
                self.error = Some(e);
                None
            }
        }
    }

    /// Assemble the terminal result: the accumulated stdout on success, or a
    /// masked [`MgsError`] on failure.
    ///
    /// Completion signal (resolved by the live spike, ADR 0025 §3): an
    /// `EXIT_CODE = 0` is the strongest proof, but **`AWS-StartNonInteractiveCommand`
    /// does not reliably emit one** — it streams stdout then ends the session with
    /// `channel_closed`. So a clean `channel_closed` is taken as completion and the
    /// accumulated stdout (in sequence order) is returned. The remaining
    /// fail-closed guard is the **abrupt drop**: if the socket ends (`recv` →
    /// `None`) *without* a `channel_closed`, the read was torn down mid-stream and
    /// is [`MgsError::ClosedEarly`] rather than a silently-truncated `.env`. A
    /// non-zero exit code is still a failure (`cat` on a missing/denied path).
    pub fn finish(self) -> Result<Vec<u8>, MgsError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        match self.exit_code {
            Some(0) => Ok(self.output.into_values().flatten().collect()),
            Some(_) => Err(MgsError::CommandFailed),
            // A clean session end (the agent sent `channel_closed`): take the
            // streamed output as complete.
            None if self.channel_closed => Ok(self.output.into_values().flatten().collect()),
            // The socket dropped with no clean close — a torn-down/truncated read.
            None => Err(MgsError::ClosedEarly),
        }
    }
}

/// Parse the exit-code payload (the agent sends it as an ASCII integer). An
/// unparseable code is treated as success (0) — we already have whatever stdout
/// arrived; the live spike confirms the exact encoding (ADR 0025 §3).
fn parse_exit_code(payload: &[u8]) -> i64 {
    String::from_utf8_lossy(payload)
        .trim()
        .parse::<i64>()
        .unwrap_or(0)
}

// ---- shared building blocks (used by both the read and write drivers) ----

/// Build an `acknowledge` for a received message. SYN|FIN (3) marks a
/// self-contained control message, exactly as the SSM agent / session-manager-
/// plugin send acks; with flags=0 the agent treats it as a mid-stream data frame
/// and never registers the ack, retransmitting the unacked message until it gives
/// up (channel_closed) — verified live (ADR 0025 §3).
fn build_ack(msg: &AgentMessage) -> Outgoing {
    let content = AcknowledgeContent {
        message_type: msg.message_type.clone(),
        message_id: msg.message_id.to_string(),
        sequence_number: msg.sequence_number,
        is_sequential_message: true,
    };
    Outgoing {
        message_type: message_type::ACKNOWLEDGE.into(),
        payload_type: 0,
        flags: FLAG_SYN | FLAG_FIN,
        sequence_number: 0,
        payload: serde_json::to_vec(&content).expect("ack json"),
    }
}

/// Build the `handshake_response` for a `handshake_request` at outgoing sequence
/// `seq`. Responds Success to `SessionType`; marks `KMSEncryption` Unsupported and
/// returns it as the second tuple element (the pure transport cannot do the KMS
/// data-key exchange, so the caller fails the session). `Err` only on a malformed
/// request payload.
fn build_handshake_response(
    req_payload: &[u8],
    seq: i64,
) -> Result<(Outgoing, Option<MgsError>), MgsError> {
    let req: HandshakeRequestPayload = serde_json::from_slice(req_payload)
        .map_err(|_| MgsError::Protocol("handshake request".into()))?;
    let mut kms_unsupported = None;
    let processed: Vec<ProcessedClientAction> = req
        .requested_client_actions
        .iter()
        .map(|a| {
            if a.action_type == "KMSEncryption" {
                kms_unsupported = Some(MgsError::KmsEncryptionUnsupported);
                ProcessedClientAction {
                    action_type: a.action_type.clone(),
                    action_status: ACTION_UNSUPPORTED,
                    action_result: None,
                    error: "unsupported".into(),
                }
            } else {
                ProcessedClientAction {
                    action_type: a.action_type.clone(),
                    action_status: ACTION_SUCCESS,
                    action_result: None,
                    error: String::new(),
                }
            }
        })
        .collect();
    let resp = HandshakeResponsePayload {
        client_version: CLIENT_VERSION.into(),
        processed_client_actions: processed,
        errors: Vec::new(),
    };
    let flags = if seq == 0 { FLAG_SYN } else { 0 };
    Ok((
        Outgoing {
            message_type: message_type::INPUT_STREAM_DATA.into(),
            payload_type: payload_type::HANDSHAKE_RESPONSE,
            flags,
            sequence_number: seq,
            payload: serde_json::to_vec(&resp).expect("handshake json"),
        },
        kms_unsupported,
    ))
}

/// Serialize the OpenDataChannel handshake (a JSON **text** frame) carrying the
/// session token. Shared by the read and write drivers.
fn open_data_channel_text(token_value: &str, client_id: Uuid) -> Result<String, MgsError> {
    let open = OpenDataChannelInput {
        message_schema_version: "1.0".into(),
        request_id: Uuid::new_v4().to_string(),
        token_value: token_value.into(),
        client_id: client_id.to_string(),
        client_version: CLIENT_VERSION.into(),
    };
    serde_json::to_string(&open).map_err(|_| MgsError::Protocol("open".into()))
}

/// Drive one read over `channel`: open the data channel, run the session to
/// completion, and return the command's stdout bytes. The only non-deterministic
/// inputs (the per-message UUID and `now` timestamp) are injected so tests stay
/// deterministic; everything else is the pure [`SessionState`].
pub async fn read_command_output(
    channel: &mut dyn DataChannel,
    token_value: &str,
    client_id: Uuid,
    now_millis: &(dyn Fn() -> u64 + Send + Sync),
) -> Result<Vec<u8>, MgsError> {
    channel
        .send_text(open_data_channel_text(token_value, client_id)?)
        .await?;
    tracing::debug!(target: "janitor::ssm", "sent OpenDataChannel handshake; awaiting agent");

    // The data channel is a single ordered WebSocket, so frames are consumed in
    // arrival order and the loop stops as soon as the session is terminal (an exit
    // code or a channel close). [`SessionState`]'s by-sequence buffering is
    // belt-and-suspenders for any intra-batch reordering, not a license to read
    // past the terminal frame — completeness is proven by the exit code, not by
    // draining (see [`SessionState::finish`]).
    let mut state = SessionState::new();
    while !state.done() {
        let Some(bytes) = channel.recv().await? else {
            break; // socket closed
        };
        let msg = AgentMessage::deserialize(&bytes)
            .map_err(|_| MgsError::Protocol("agent frame".into()))?;
        // Structural only — message type / payload type / sequence / flags, never
        // the payload (which can be the `.env` contents).
        tracing::debug!(
            target: "janitor::ssm",
            msg_type = %msg.message_type,
            payload_type = msg.payload_type,
            seq = msg.sequence_number,
            flags = msg.flags,
            // Length only (never the bytes — they can be the `.env`'s contents):
            // lets the live harness see the output chunking without leaking content.
            payload_len = msg.payload.len(),
            "rx agent message"
        );
        for out in state.on_message(&msg) {
            let am = out.into_agent_message(Uuid::new_v4(), nonzero(now_millis()));
            // Our outgoing payloads are only acks + the handshake response — never
            // file contents — so logging the payload here is safe and shows the
            // acknowledged sequence number.
            tracing::debug!(
                target: "janitor::ssm",
                msg_type = %am.message_type,
                payload_type = am.payload_type,
                seq = am.sequence_number,
                flags = am.flags,
                payload = %String::from_utf8_lossy(&am.payload),
                "tx agent message"
            );
            channel.send_binary(am.serialize()).await?;
        }
    }
    let result = state.finish();
    match &result {
        Ok(b) => tracing::debug!(target: "janitor::ssm", bytes = b.len(), "ssm read complete"),
        Err(e) => {
            tracing::warn!(target: "janitor::ssm", "ssm session ended without a clean read — {e}")
        }
    }
    result
}

/// The agent rejects a zero `CreatedDate`; coerce 0 to 1 so a clock that returns
/// the epoch can never produce an invalid outgoing message.
fn nonzero(millis: u64) -> u64 {
    millis.max(1)
}

// ============================ write path (ADR 0029) ============================

/// The default size of each streamed `input_stream_data` chunk. The agent reads
/// the pty in fixed buffers, so any chunk size works; this keeps a few-KB `.env`
/// to a handful of frames.
const INPUT_CHUNK_SIZE: usize = 1024;

/// The outcome of a remote `.env` write, parsed from the small status tokens the
/// CAS-guarded command prints (ADR 0029). Distinct from an [`MgsError`] (a
/// transport/protocol failure): both `Applied` and `Conflict` are *successful*
/// round-trips of the protocol — the command ran and reported its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// `JANITOR_OK` — the CAS matched and the atomic replace committed.
    Applied,
    /// `JANITOR_CONFLICT` — the file's `sha256` no longer matched what we read, so
    /// the command refused (ADR 0001). The caller re-reads, re-applies, retries.
    Conflict,
}

/// Scan the command's accumulated stdout for the status token. `CONFLICT` is
/// checked first (it is printed and the command exits *before* any `OK` could
/// appear); robust to surrounding pty banner noise since it is a substring search.
/// Pure.
fn scan_write_outcome(stdout: &[u8]) -> Option<WriteOutcome> {
    if contains_subslice(stdout, b"JANITOR_CONFLICT") {
        Some(WriteOutcome::Conflict)
    } else if contains_subslice(stdout, b"JANITOR_OK") {
        Some(WriteOutcome::Applied)
    } else {
        None
    }
}

/// Whether `haystack` contains `needle` as a contiguous subslice.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The deterministic data-channel state machine for a **write** (ADR 0029): like
/// [`SessionState`] it answers the handshake and acks every output frame, but
/// after `handshake_complete` it **streams** the base64 content as
/// `input_stream_data`/`Output` frames (chunked, sequenced after the handshake
/// response's seq 0, `FLAG_FIN` on the last), then accumulates the command's
/// stdout to parse the `JANITOR_OK`/`JANITOR_CONFLICT` token. No I/O, no clock,
/// no randomness — fully unit-tested.
///
/// The base64 content is the encoding of a secret file, so it is held in a
/// zeroizing buffer and **never** logged; the driver logs only structural fields.
pub struct WriteSession {
    /// The base64 bytes to stream into the remote `head -c N | base64 -d`.
    content: zeroize::Zeroizing<Vec<u8>>,
    chunk_size: usize,
    /// Our outgoing `input_stream_data` sequence (the handshake response takes 0;
    /// content frames continue from 1).
    out_seq: i64,
    handshake_responded: bool,
    /// Whether the content frames have been emitted (only once, at handshake_complete).
    streamed: bool,
    /// Command stdout chunks by sequence number, concatenated in order at
    /// [`finish`](Self::finish) to scan for the status token.
    stdout: BTreeMap<i64, Vec<u8>>,
    channel_closed: bool,
    error: Option<MgsError>,
}

impl WriteSession {
    /// Build a write session that will stream `content_b64` once the handshake
    /// completes. `content_b64` is the base64 of the new file bytes.
    pub fn new(content_b64: Vec<u8>) -> Self {
        Self::with_chunk_size(content_b64, INPUT_CHUNK_SIZE)
    }

    fn with_chunk_size(content_b64: Vec<u8>, chunk_size: usize) -> Self {
        WriteSession {
            content: zeroize::Zeroizing::new(content_b64),
            chunk_size: chunk_size.max(1),
            out_seq: 0,
            handshake_responded: false,
            streamed: false,
            stdout: BTreeMap::new(),
            channel_closed: false,
            error: None,
        }
    }

    /// Whether the session has reached a terminal state (the driver stops): an
    /// error, or a clean channel close (the command exited).
    pub fn done(&self) -> bool {
        self.error.is_some() || self.channel_closed
    }

    /// Process one incoming message, returning the messages to send back (acks, the
    /// handshake response, and — at handshake_complete — the streamed content frames).
    pub fn on_message(&mut self, msg: &AgentMessage) -> Vec<Outgoing> {
        match msg.message_type.as_str() {
            message_type::OUTPUT_STREAM_DATA => self.on_output(msg),
            message_type::CHANNEL_CLOSED => {
                self.channel_closed = true;
                Vec::new()
            }
            // The agent's acks of our streamed frames + flow control: nothing to do
            // (the WebSocket/TCP is reliable, so v1 streams without retransmit).
            _ => Vec::new(),
        }
    }

    fn on_output(&mut self, msg: &AgentMessage) -> Vec<Outgoing> {
        let mut out = vec![build_ack(msg)];
        match msg.payload_type {
            payload_type::HANDSHAKE_REQUEST => {
                if !self.handshake_responded {
                    match build_handshake_response(&msg.payload, self.out_seq) {
                        Ok((resp, kms)) => {
                            if let Some(e) = kms {
                                self.error = Some(e);
                            }
                            self.out_seq += 1;
                            out.push(resp);
                        }
                        Err(e) => self.error = Some(e),
                    }
                    self.handshake_responded = true;
                }
            }
            payload_type::HANDSHAKE_COMPLETE => {
                // The agent is ready and the command is running under the pty; stream
                // the content now (once). A KMS-failed handshake never reaches here.
                if !self.streamed && self.error.is_none() {
                    out.extend(self.input_frames());
                    self.streamed = true;
                }
            }
            payload_type::OUTPUT => {
                self.stdout.insert(msg.sequence_number, msg.payload.clone());
            }
            // STDERR/ERROR fold into the pty's output stream for an interactive
            // session; they are not a distinct failure here. EXIT_CODE (if any) is
            // not the completion signal — the status token + channel_closed are.
            _ => {}
        }
        out
    }

    /// Chunk the base64 content into `input_stream_data`/`Output` frames, sequenced
    /// from the current `out_seq`, `FLAG_FIN` on the last. Empty content → no frames
    /// (the remote `head -c 0` completes immediately).
    fn input_frames(&mut self) -> Vec<Outgoing> {
        let chunks: Vec<Vec<u8>> = self
            .content
            .chunks(self.chunk_size)
            .map(|c| c.to_vec())
            .collect();
        let n = chunks.len();
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| {
                let seq = self.out_seq;
                self.out_seq += 1;
                Outgoing {
                    message_type: message_type::INPUT_STREAM_DATA.into(),
                    payload_type: payload_type::OUTPUT,
                    flags: if i + 1 == n { FLAG_FIN } else { 0 },
                    sequence_number: seq,
                    payload: chunk,
                }
            })
            .collect()
    }

    /// The terminal result: the parsed [`WriteOutcome`] on a clean close, or a
    /// masked [`MgsError`]. A clean close with neither token is a [`MgsError::CommandFailed`]
    /// (the command ran but reported nothing — e.g. `sudo`/`mktemp` failed); an
    /// abrupt socket drop with no token is [`MgsError::ClosedEarly`].
    pub fn finish(self) -> Result<WriteOutcome, MgsError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let stdout: Vec<u8> = self.stdout.into_values().flatten().collect();
        match scan_write_outcome(&stdout) {
            Some(outcome) => Ok(outcome),
            None if self.channel_closed => Err(MgsError::CommandFailed),
            None => Err(MgsError::ClosedEarly),
        }
    }
}

/// Drive one write over `channel`: open the data channel, answer the handshake,
/// stream `content_b64` after `handshake_complete`, and parse the command's status
/// token. Mirrors [`read_command_output`] (UUID + clock injected for determinism),
/// but **never logs an outgoing payload** — the streamed frames carry the base64 of
/// a secret file (THREAT-MODEL).
pub async fn write_command_output(
    channel: &mut dyn DataChannel,
    token_value: &str,
    client_id: Uuid,
    content_b64: Vec<u8>,
    now_millis: &(dyn Fn() -> u64 + Send + Sync),
) -> Result<WriteOutcome, MgsError> {
    channel
        .send_text(open_data_channel_text(token_value, client_id)?)
        .await?;
    tracing::debug!(target: "janitor::ssm", "sent OpenDataChannel handshake (write); awaiting agent");

    let mut state = WriteSession::new(content_b64);
    while !state.done() {
        let Some(bytes) = channel.recv().await? else {
            break; // socket closed
        };
        let msg = AgentMessage::deserialize(&bytes)
            .map_err(|_| MgsError::Protocol("agent frame".into()))?;
        // Structural only — never the payload (it can be the pty echo of our
        // streamed content) (THREAT-MODEL).
        tracing::debug!(
            target: "janitor::ssm",
            msg_type = %msg.message_type,
            payload_type = msg.payload_type,
            seq = msg.sequence_number,
            flags = msg.flags,
            payload_len = msg.payload.len(),
            "rx agent message (write)"
        );
        for out in state.on_message(&msg) {
            let am = out.into_agent_message(Uuid::new_v4(), nonzero(now_millis()));
            // Structural only — our outgoing payloads include the streamed base64
            // content, so the payload is NEVER logged (unlike the read driver, whose
            // outgoing are only acks).
            tracing::debug!(
                target: "janitor::ssm",
                msg_type = %am.message_type,
                payload_type = am.payload_type,
                seq = am.sequence_number,
                flags = am.flags,
                payload_len = am.payload.len(),
                "tx agent message (write)"
            );
            channel.send_binary(am.serialize()).await?;
        }
    }
    let result = state.finish();
    match &result {
        Ok(o) => tracing::debug!(target: "janitor::ssm", outcome = ?o, "ssm write complete"),
        Err(e) => {
            tracing::warn!(target: "janitor::ssm", "ssm write ended without a clean result — {e}")
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn out_msg(payload_type: u32, seq: i64, payload: &[u8]) -> AgentMessage {
        AgentMessage {
            message_type: message_type::OUTPUT_STREAM_DATA.into(),
            schema_version: 1,
            created_date: 1,
            sequence_number: seq,
            flags: 0,
            message_id: Uuid::from_u128(seq as u128 + 1),
            payload_type,
            payload: payload.to_vec(),
        }
    }
    fn handshake_request(actions: &[&str]) -> AgentMessage {
        let json = serde_json::json!({
            "AgentVersion": "3.0",
            "RequestedClientActions": actions
                .iter()
                .map(|a| serde_json::json!({"ActionType": a, "ActionParameters": {}}))
                .collect::<Vec<_>>(),
        });
        out_msg(
            payload_type::HANDSHAKE_REQUEST,
            0,
            serde_json::to_vec(&json).unwrap().as_slice(),
        )
    }

    // ---- SessionState (pure) ----

    #[test]
    fn acks_every_output_message() {
        let mut s = SessionState::new();
        let out = s.on_message(&out_msg(payload_type::OUTPUT, 5, b"A=1"));
        assert_eq!(out.len(), 1, "an output message is acked");
        assert_eq!(out[0].message_type, message_type::ACKNOWLEDGE);
        assert_eq!(
            out[0].flags,
            FLAG_SYN | FLAG_FIN,
            "acks are self-contained SYN|FIN control messages (the agent ignores flags=0 acks)"
        );
        // The ack names the acked sequence number.
        let content: serde_json::Value = serde_json::from_slice(&out[0].payload).unwrap();
        assert_eq!(content["AcknowledgedMessageSequenceNumber"], 5);
        assert_eq!(content["AcknowledgedMessageType"], "output_stream_data");
    }

    #[test]
    fn handshake_request_is_acked_and_answered_with_syn() {
        let mut s = SessionState::new();
        let out = s.on_message(&handshake_request(&["SessionType"]));
        assert_eq!(out.len(), 2, "ack + handshake response");
        assert_eq!(out[0].message_type, message_type::ACKNOWLEDGE);
        let resp = &out[1];
        assert_eq!(resp.message_type, message_type::INPUT_STREAM_DATA);
        assert_eq!(resp.payload_type, payload_type::HANDSHAKE_RESPONSE);
        assert_eq!(resp.flags, FLAG_SYN, "the first client message carries SYN");
        assert_eq!(resp.sequence_number, 0);
        let body: serde_json::Value = serde_json::from_slice(&resp.payload).unwrap();
        assert_eq!(
            body["ProcessedClientActions"][0]["ActionType"],
            "SessionType"
        );
        assert_eq!(
            body["ProcessedClientActions"][0]["ActionStatus"],
            ACTION_SUCCESS
        );
        assert!(!s.done(), "handshake alone is not terminal");
    }

    #[test]
    fn retransmitted_handshake_request_is_acked_but_not_re_answered() {
        // The agent retransmits the unacked handshake_request; we ack every copy
        // but answer the handshake only once (re-answering restarts it).
        let mut s = SessionState::new();
        let first = s.on_message(&handshake_request(&["SessionType"]));
        assert_eq!(first.len(), 2, "first: ack + handshake response");
        let second = s.on_message(&handshake_request(&["SessionType"]));
        assert_eq!(second.len(), 1, "retransmit: ack only, no second response");
        assert_eq!(second[0].message_type, message_type::ACKNOWLEDGE);
    }

    #[test]
    fn kms_encryption_action_makes_the_session_fail_unsupported() {
        let mut s = SessionState::new();
        let out = s.on_message(&handshake_request(&["SessionType", "KMSEncryption"]));
        // Still acks + responds (marking KMS Unsupported), but the session is now
        // terminally errored.
        let body: serde_json::Value = serde_json::from_slice(&out[1].payload).unwrap();
        let kms = body["ProcessedClientActions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["ActionType"] == "KMSEncryption")
            .unwrap();
        assert_eq!(kms["ActionStatus"], ACTION_UNSUPPORTED);
        assert!(s.done());
        assert_eq!(s.finish().unwrap_err(), MgsError::KmsEncryptionUnsupported);
    }

    #[test]
    fn assembles_output_in_sequence_order_even_if_out_of_order() {
        let mut s = SessionState::new();
        s.on_message(&out_msg(payload_type::OUTPUT, 2, b"two"));
        s.on_message(&out_msg(payload_type::OUTPUT, 1, b"one\n"));
        s.on_message(&out_msg(payload_type::EXIT_CODE, 3, b"0"));
        assert!(s.done());
        assert_eq!(s.finish().unwrap(), b"one\ntwo");
    }

    #[test]
    fn nonzero_exit_code_is_command_failed() {
        let mut s = SessionState::new();
        s.on_message(&out_msg(payload_type::OUTPUT, 1, b"partial"));
        s.on_message(&out_msg(payload_type::EXIT_CODE, 2, b"1"));
        assert_eq!(s.finish().unwrap_err(), MgsError::CommandFailed);
    }

    #[test]
    fn stderr_payload_fails_without_storing_its_bytes() {
        let mut s = SessionState::new();
        let out = s.on_message(&out_msg(
            payload_type::STDERR,
            1,
            b"cat: /secret/path: No such file",
        ));
        assert_eq!(out.len(), 1, "stderr is still acked");
        s.on_message(&out_msg(payload_type::EXIT_CODE, 2, b"1"));
        assert_eq!(s.finish().unwrap_err(), MgsError::CommandFailed);
    }

    #[test]
    fn channel_closed_with_no_exit_returns_accumulated_output() {
        // An empty file: channel closes with no Output frames and no exit code.
        let mut s = SessionState::new();
        s.on_message(&AgentMessage {
            message_type: message_type::CHANNEL_CLOSED.into(),
            ..out_msg(0, 9, b"")
        });
        assert!(s.done());
        assert_eq!(s.finish().unwrap(), b"");
    }

    #[test]
    fn channel_closed_with_output_and_no_exit_is_complete() {
        // AWS-StartNonInteractiveCommand streams stdout then ends with
        // channel_closed and no exit code (live-verified, ADR 0025 §3): a clean
        // close is the completion signal, so the streamed output is returned.
        let mut s = SessionState::new();
        s.on_message(&out_msg(payload_type::OUTPUT, 1, b"A=1\nB=2\n"));
        s.on_message(&AgentMessage {
            message_type: message_type::CHANNEL_CLOSED.into(),
            ..out_msg(0, 2, b"")
        });
        assert!(s.done());
        assert_eq!(s.finish().unwrap(), b"A=1\nB=2\n");
    }

    #[test]
    fn abrupt_socket_drop_with_output_is_closed_early() {
        // The fail-closed guard: a socket that ends WITHOUT a channel_closed is a
        // torn-down read, surfaced as ClosedEarly rather than truncated bytes.
        let mut s = SessionState::new();
        s.on_message(&out_msg(payload_type::OUTPUT, 1, b"A=1\nB=tw"));
        // No channel_closed, no exit code → the driver's recv returned None.
        assert!(!s.done(), "an abrupt drop is not a terminal protocol state");
        assert_eq!(s.finish().unwrap_err(), MgsError::ClosedEarly);
    }

    #[test]
    fn closed_before_any_output_is_closed_early() {
        // recv returned None (socket dropped) with nothing accumulated.
        let s = SessionState::new();
        assert_eq!(s.finish().unwrap_err(), MgsError::ClosedEarly);
    }

    #[test]
    fn exit_zero_with_output_succeeds() {
        let mut s = SessionState::new();
        s.on_message(&handshake_request(&["SessionType"]));
        s.on_message(&out_msg(payload_type::HANDSHAKE_COMPLETE, 1, b""));
        s.on_message(&out_msg(payload_type::OUTPUT, 2, b"A=1\nB=2\n"));
        s.on_message(&out_msg(payload_type::EXIT_CODE, 3, b"0"));
        assert_eq!(s.finish().unwrap(), b"A=1\nB=2\n");
    }

    // ---- read_command_output driver (vs a scripted fake channel) ----

    /// A scripted [`DataChannel`]: serves `incoming` serialized frames on `recv`
    /// (then `None`), and records everything sent so the test can assert acks /
    /// handshake responses went out.
    struct FakeChannel {
        incoming: Mutex<std::collections::VecDeque<Vec<u8>>>,
        sent_text: Mutex<Vec<String>>,
        sent_binary: Mutex<Vec<AgentMessage>>,
    }
    impl FakeChannel {
        fn new(incoming: Vec<AgentMessage>) -> Self {
            FakeChannel {
                incoming: Mutex::new(incoming.iter().map(|m| m.serialize()).collect()),
                sent_text: Mutex::new(Vec::new()),
                sent_binary: Mutex::new(Vec::new()),
            }
        }
    }
    #[async_trait]
    impl DataChannel for FakeChannel {
        async fn send_text(&mut self, text: String) -> Result<(), MgsError> {
            self.sent_text.lock().unwrap().push(text);
            Ok(())
        }
        async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<(), MgsError> {
            self.sent_binary
                .lock()
                .unwrap()
                .push(AgentMessage::deserialize(&bytes).unwrap());
            Ok(())
        }
        async fn recv(&mut self) -> Result<Option<Vec<u8>>, MgsError> {
            Ok(self.incoming.lock().unwrap().pop_front())
        }
    }

    #[tokio::test]
    async fn driver_runs_full_session_and_returns_stdout() {
        let mut ch = FakeChannel::new(vec![
            handshake_request(&["SessionType"]),
            out_msg(payload_type::HANDSHAKE_COMPLETE, 1, b""),
            out_msg(payload_type::OUTPUT, 2, b"A=1\n"),
            out_msg(payload_type::OUTPUT, 3, b"B=two\n"),
            out_msg(payload_type::EXIT_CODE, 4, b"0"),
        ]);
        let out = read_command_output(&mut ch, "tok", Uuid::nil(), &|| 1)
            .await
            .unwrap();
        assert_eq!(out, b"A=1\nB=two\n");

        // The OpenDataChannel handshake went out as a text frame carrying the token.
        let text = ch.sent_text.lock().unwrap();
        assert_eq!(text.len(), 1);
        let open: serde_json::Value = serde_json::from_str(&text[0]).unwrap();
        assert_eq!(open["TokenValue"], "tok");
        assert_eq!(open["MessageSchemaVersion"], "1.0");

        // We acked every incoming message and sent exactly one handshake response.
        let bin = ch.sent_binary.lock().unwrap();
        let acks = bin
            .iter()
            .filter(|m| m.message_type == message_type::ACKNOWLEDGE)
            .count();
        assert_eq!(acks, 5, "one ack per received output message");
        let responses = bin
            .iter()
            .filter(|m| m.payload_type == payload_type::HANDSHAKE_RESPONSE)
            .count();
        assert_eq!(responses, 1);
        // Every outgoing message has a non-zero CreatedDate (agent Validate).
        assert!(bin.iter().all(|m| m.created_date != 0));
    }

    #[tokio::test]
    async fn driver_maps_a_nonzero_exit_to_command_failed() {
        let mut ch = FakeChannel::new(vec![out_msg(payload_type::EXIT_CODE, 1, b"1")]);
        let err = read_command_output(&mut ch, "tok", Uuid::nil(), &|| 1)
            .await
            .unwrap_err();
        assert_eq!(err, MgsError::CommandFailed);
    }

    #[tokio::test]
    async fn driver_propagates_a_channel_send_error() {
        struct Failing;
        #[async_trait]
        impl DataChannel for Failing {
            async fn send_text(&mut self, _t: String) -> Result<(), MgsError> {
                Err(MgsError::Channel("connect".into()))
            }
            async fn send_binary(&mut self, _b: Vec<u8>) -> Result<(), MgsError> {
                Ok(())
            }
            async fn recv(&mut self) -> Result<Option<Vec<u8>>, MgsError> {
                Ok(None)
            }
        }
        let err = read_command_output(&mut Failing, "tok", Uuid::nil(), &|| 1)
            .await
            .unwrap_err();
        assert_eq!(err, MgsError::Channel("connect".into()));
    }

    // ---- WriteSession (pure) + write_command_output driver (ADR 0029) ----

    fn channel_closed(seq: i64) -> AgentMessage {
        AgentMessage {
            message_type: message_type::CHANNEL_CLOSED.into(),
            ..out_msg(0, seq, b"")
        }
    }

    /// The reassembled payload of all streamed content frames (input_stream_data /
    /// Output), in sequence order — i.e. exactly what the remote `head -c N` reads.
    fn streamed_content(frames: &[Outgoing]) -> Vec<u8> {
        let mut v: Vec<&Outgoing> = frames
            .iter()
            .filter(|o| {
                o.message_type == message_type::INPUT_STREAM_DATA
                    && o.payload_type == payload_type::OUTPUT
            })
            .collect();
        v.sort_by_key(|o| o.sequence_number);
        v.into_iter().flat_map(|o| o.payload.clone()).collect()
    }

    #[test]
    fn scan_write_outcome_prefers_conflict_and_is_substring_robust() {
        assert_eq!(
            scan_write_outcome(b"JANITOR_OK\n"),
            Some(WriteOutcome::Applied)
        );
        assert_eq!(
            scan_write_outcome(b"\x1b[0mJANITOR_OK\r\n"),
            Some(WriteOutcome::Applied),
            "robust to surrounding pty/banner noise"
        );
        assert_eq!(
            scan_write_outcome(b"JANITOR_CONFLICT\n"),
            Some(WriteOutcome::Conflict)
        );
        assert_eq!(scan_write_outcome(b"random output"), None);
        assert_eq!(scan_write_outcome(b""), None);
    }

    #[test]
    fn write_session_streams_chunked_content_with_fin_after_handshake_complete() {
        // Handshake first (ack + response, seq 0). Then handshake_complete triggers
        // the content stream: chunked, sequenced from 1, FIN only on the last frame.
        let mut s = WriteSession::with_chunk_size(b"ABCDEFG".to_vec(), 3);
        let hs = s.on_message(&handshake_request(&["SessionType"]));
        assert_eq!(hs.len(), 2, "ack + handshake response");
        assert_eq!(hs[1].payload_type, payload_type::HANDSHAKE_RESPONSE);
        assert_eq!(hs[1].sequence_number, 0);

        let done = s.on_message(&out_msg(payload_type::HANDSHAKE_COMPLETE, 1, b""));
        // ack + 3 content frames (3+3+1 bytes).
        let frames: Vec<&Outgoing> = done
            .iter()
            .filter(|o| o.payload_type == payload_type::OUTPUT)
            .collect();
        assert_eq!(frames.len(), 3, "7 bytes / chunk 3 → 3 frames");
        assert_eq!(
            frames[0].sequence_number, 1,
            "content seq continues after handshake's 0"
        );
        assert_eq!(frames[1].sequence_number, 2);
        assert_eq!(frames[2].sequence_number, 3);
        assert_eq!(frames[0].flags, 0);
        assert_eq!(
            frames[2].flags, FLAG_FIN,
            "only the last content frame is FIN"
        );
        assert_eq!(streamed_content(&done), b"ABCDEFG");

        // A second handshake_complete does not re-stream.
        let again = s.on_message(&out_msg(payload_type::HANDSHAKE_COMPLETE, 2, b""));
        assert_eq!(again.len(), 1, "ack only — content streamed once");
    }

    #[test]
    fn write_session_empty_content_streams_no_frames() {
        let mut s = WriteSession::new(Vec::new());
        s.on_message(&handshake_request(&["SessionType"]));
        let done = s.on_message(&out_msg(payload_type::HANDSHAKE_COMPLETE, 1, b""));
        assert_eq!(done.len(), 1, "ack only; head -c 0 needs no bytes");
    }

    #[test]
    fn write_session_parses_ok_and_conflict_at_clean_close() {
        for (token, expect) in [
            (b"JANITOR_OK\n".as_slice(), WriteOutcome::Applied),
            (b"JANITOR_CONFLICT\n".as_slice(), WriteOutcome::Conflict),
        ] {
            let mut s = WriteSession::new(b"Zg==".to_vec());
            s.on_message(&out_msg(payload_type::OUTPUT, 1, token));
            s.on_message(&channel_closed(2));
            assert!(s.done());
            assert_eq!(s.finish().unwrap(), expect);
        }
    }

    #[test]
    fn write_session_clean_close_with_no_token_is_command_failed() {
        let mut s = WriteSession::new(b"Zg==".to_vec());
        s.on_message(&out_msg(payload_type::OUTPUT, 1, b"some pty noise"));
        s.on_message(&channel_closed(2));
        assert_eq!(s.finish().unwrap_err(), MgsError::CommandFailed);
    }

    #[test]
    fn write_session_abrupt_drop_with_no_token_is_closed_early() {
        let mut s = WriteSession::new(b"Zg==".to_vec());
        s.on_message(&out_msg(payload_type::OUTPUT, 1, b"partial"));
        assert!(!s.done(), "no close yet");
        assert_eq!(s.finish().unwrap_err(), MgsError::ClosedEarly);
    }

    #[test]
    fn write_session_kms_handshake_fails_and_never_streams() {
        let mut s = WriteSession::with_chunk_size(b"ABCD".to_vec(), 2);
        s.on_message(&handshake_request(&["SessionType", "KMSEncryption"]));
        assert!(s.done(), "KMS-unsupported is terminal");
        // handshake_complete must not stream once errored.
        let after = s.on_message(&out_msg(payload_type::HANDSHAKE_COMPLETE, 1, b""));
        assert!(
            after.iter().all(|o| o.payload_type != payload_type::OUTPUT),
            "no content frames after a failed handshake"
        );
        assert_eq!(s.finish().unwrap_err(), MgsError::KmsEncryptionUnsupported);
    }

    #[tokio::test]
    async fn driver_runs_full_write_session_streams_content_and_parses_ok() {
        let content = b"SGVsbG8sIHdvcmxkIQ=="; // base64 of "Hello, world!"
        let mut ch = FakeChannel::new(vec![
            handshake_request(&["SessionType"]),
            out_msg(payload_type::HANDSHAKE_COMPLETE, 1, b""),
            out_msg(payload_type::OUTPUT, 2, b"JANITOR_OK\n"),
            channel_closed(3),
        ]);
        let outcome = write_command_output(&mut ch, "tok", Uuid::nil(), content.to_vec(), &|| 1)
            .await
            .unwrap();
        assert_eq!(outcome, WriteOutcome::Applied);

        let bin = ch.sent_binary.lock().unwrap();
        // The OpenDataChannel text frame carried the token.
        let text = ch.sent_text.lock().unwrap();
        assert_eq!(text.len(), 1);
        // Exactly one handshake response went out.
        let responses = bin
            .iter()
            .filter(|m| m.payload_type == payload_type::HANDSHAKE_RESPONSE)
            .count();
        assert_eq!(responses, 1);
        // Every incoming message was acked.
        let acks = bin
            .iter()
            .filter(|m| m.message_type == message_type::ACKNOWLEDGE)
            .count();
        assert_eq!(acks, 3);
        // The streamed content frames reassemble to exactly the base64 we passed.
        let frames: Vec<Outgoing> = bin
            .iter()
            .map(|m| Outgoing {
                message_type: m.message_type.clone(),
                payload_type: m.payload_type,
                flags: m.flags,
                sequence_number: m.sequence_number,
                payload: m.payload.clone(),
            })
            .collect();
        assert_eq!(streamed_content(&frames), content);
        // Every outgoing message has a non-zero CreatedDate (agent Validate).
        assert!(bin.iter().all(|m| m.created_date != 0));
    }

    #[tokio::test]
    async fn driver_maps_conflict_token_to_conflict_outcome() {
        let mut ch = FakeChannel::new(vec![
            handshake_request(&["SessionType"]),
            out_msg(payload_type::HANDSHAKE_COMPLETE, 1, b""),
            out_msg(payload_type::OUTPUT, 2, b"\nJANITOR_CONFLICT\n"),
            channel_closed(3),
        ]);
        let outcome = write_command_output(&mut ch, "tok", Uuid::nil(), b"Zg==".to_vec(), &|| 1)
            .await
            .unwrap();
        assert_eq!(outcome, WriteOutcome::Conflict);
    }

    #[tokio::test]
    async fn driver_write_propagates_a_send_error() {
        struct Failing;
        #[async_trait]
        impl DataChannel for Failing {
            async fn send_text(&mut self, _t: String) -> Result<(), MgsError> {
                Err(MgsError::Channel("connect".into()))
            }
            async fn send_binary(&mut self, _b: Vec<u8>) -> Result<(), MgsError> {
                Ok(())
            }
            async fn recv(&mut self) -> Result<Option<Vec<u8>>, MgsError> {
                Ok(None)
            }
        }
        let err = write_command_output(&mut Failing, "tok", Uuid::nil(), b"Zg==".to_vec(), &|| 1)
            .await
            .unwrap_err();
        assert_eq!(err, MgsError::Channel("connect".into()));
    }
}
