//! The Session Manager **AgentMessage** binary wire format (ADR 0025 §3,
//! transport b). This is the framing the SSM agent and the (normally Go)
//! `session-manager-plugin` exchange over the data-channel WebSocket; Janitor
//! reimplements it in pure Rust so the transport needs no external binary.
//!
//! The layout is fixed (a 120-byte header then the payload), every integer is
//! big-endian, and it is reproduced here byte-for-byte from the canonical
//! `amazon-ssm-agent` contract (`agent/session/contracts/agentmessage.go`):
//!
//! | field          | offset | len | type                                    |
//! |----------------|--------|-----|-----------------------------------------|
//! | HeaderLength   | 0      | 4   | u32 — always 116 (offset of PayloadLength) |
//! | MessageType    | 4      | 32  | ASCII, space-padded, trimmed on read    |
//! | SchemaVersion  | 36     | 4   | u32                                     |
//! | CreatedDate    | 40     | 8   | u64 — epoch millis                      |
//! | SequenceNumber | 48     | 8   | i64                                     |
//! | Flags          | 56     | 8   | u64 — bit0 SYN(1), bit1 FIN(2)          |
//! | MessageId      | 64     | 16  | UUID, **8-byte halves swapped** (see below) |
//! | PayloadDigest  | 80     | 32  | SHA-256(payload)                        |
//!
//! **MessageId byte order.** The wire MessageId is *not* the canonical UUID byte
//! sequence: the agent's `putUuid` writes the UUID's *least*-significant 8 bytes
//! (`uuid[8..16]`) first, then its *most*-significant 8 bytes (`uuid[0..8]`), and
//! `getUuid` reverses that on read. So the two 8-byte halves are transposed on the
//! wire (`wire = [uuid[8..16], uuid[0..8]]`). Reading the bytes verbatim yields a
//! UUID whose halves are swapped relative to what the agent tracks — which makes
//! the `AcknowledgedMessageId` we echo in an `acknowledge` *not match* the agent's
//! record, so the agent never clears the message from its outgoing buffer and
//! retransmits it indefinitely (stalling the output stream). [`swap_uuid_halves`]
//! performs this transposition; it is its own inverse, so the same call serves
//! both encode and decode. Verified byte-for-byte against `amazon-ssm-agent`
//! (`agentmessage.go`) and `session-manager-plugin` (`message/messageparser.go`).
//! | PayloadType    | 112    | 4   | u32 — see [`payload_type`]              |
//! | PayloadLength  | 116    | 4   | u32                                     |
//! | Payload        | 120    | var | bytes                                   |
//!
//! This module is **pure** (no I/O, no AWS): it serializes/deserializes byte
//! buffers, so the framing is fully unit-tested without a socket. The bytes it
//! carries can be a `.env`'s contents (a Value), so the payload is never logged
//! or `Debug`-printed (the `Debug` impl elides it; THREAT-MODEL).

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Header length up to (not including) the payload — the fixed offset of the
/// `Payload` field, and the total size of every AgentMessage's framing.
pub const HEADER_LEN: usize = 120;
/// The value written into the `HeaderLength` field: the offset of `PayloadLength`
/// (the agent's convention; see the contract), **not** [`HEADER_LEN`].
pub const HEADER_LENGTH_FIELD: u32 = 116;

// Flag bits (the `Flags` u64). SYN marks the first message in a stream so the
// peer fixes the starting sequence number; FIN marks the last.
pub const FLAG_SYN: u64 = 1;
pub const FLAG_FIN: u64 = 2;

/// MessageType string constants (the 32-byte, space-padded `MessageType` field).
/// The full set is listed to document the canonical `amazon-ssm-agent` contract;
/// the read path only matches the ones it acts on (`START_PUBLICATION` /
/// `PAUSE_PUBLICATION` are reference-only — Janitor never sends, so it ignores
/// flow control).
pub mod message_type {
    /// Agent → client: streamed stdout/stderr/exit-code and handshake payloads.
    pub const OUTPUT_STREAM_DATA: &str = "output_stream_data";
    /// Client → agent: stdin and the handshake response.
    pub const INPUT_STREAM_DATA: &str = "input_stream_data";
    /// Either direction: acknowledges a received data message by sequence number.
    pub const ACKNOWLEDGE: &str = "acknowledge";
    /// Agent → client: the session ended.
    pub const CHANNEL_CLOSED: &str = "channel_closed";
    /// Agent → client flow control (resume/pause sending). Janitor only reads, so
    /// these are observed but need no response.
    pub const START_PUBLICATION: &str = "start_publication";
    pub const PAUSE_PUBLICATION: &str = "pause_publication";
}

/// PayloadType constants (the `PayloadType` u32), for `*_stream_data` messages.
/// The full enum from the canonical contract is listed for reference; the read
/// path only acts on `OUTPUT`, `STDERR`, `ERROR`, `EXIT_CODE`, and the three
/// `HANDSHAKE_*` types — the rest (`SIZE`, `PARAMETER`, `FLAG`, `ENC_CHALLENGE_*`)
/// belong to interactive/port/encrypted sessions Janitor does not open.
pub mod payload_type {
    pub const OUTPUT: u32 = 1;
    pub const ERROR: u32 = 2;
    pub const SIZE: u32 = 3;
    pub const PARAMETER: u32 = 4;
    pub const HANDSHAKE_REQUEST: u32 = 5;
    pub const HANDSHAKE_RESPONSE: u32 = 6;
    pub const HANDSHAKE_COMPLETE: u32 = 7;
    pub const ENC_CHALLENGE_REQUEST: u32 = 8;
    pub const ENC_CHALLENGE_RESPONSE: u32 = 9;
    pub const FLAG: u32 = 10;
    pub const STDERR: u32 = 11;
    pub const EXIT_CODE: u32 = 12;
}

/// Why a byte buffer is not a well-formed AgentMessage. Carries only structural
/// facts (lengths) — never any payload bytes (THREAT-MODEL).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("agent message shorter than the {HEADER_LEN}-byte header ({0} bytes)")]
    TooShort(usize),
    #[error("agent message payload truncated (declared {declared}, have {available})")]
    PayloadTruncated { declared: usize, available: usize },
}

/// One decoded/decodable AgentMessage. `message_id` is a UUID; `payload` is the
/// raw bytes (the actual stdout/handshake/ack JSON). The `Debug` impl deliberately
/// elides `payload` because for `output_stream_data` it is the `.env` contents.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentMessage {
    pub message_type: String,
    pub schema_version: u32,
    pub created_date: u64,
    pub sequence_number: i64,
    pub flags: u64,
    pub message_id: Uuid,
    pub payload_type: u32,
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for AgentMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentMessage")
            .field("message_type", &self.message_type)
            .field("schema_version", &self.schema_version)
            .field("sequence_number", &self.sequence_number)
            .field("flags", &self.flags)
            .field("message_id", &self.message_id)
            .field("payload_type", &self.payload_type)
            // Elide payload: it can be secret (a remote `.env`'s bytes).
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl AgentMessage {
    /// Whether the SYN flag is set (first message in the stream).
    pub fn is_syn(&self) -> bool {
        self.flags & FLAG_SYN != 0
    }
    /// Whether the FIN flag is set (last message in the stream).
    pub fn is_fin(&self) -> bool {
        self.flags & FLAG_FIN != 0
    }

    /// Encode to the on-wire byte buffer. The payload digest is computed here, so
    /// callers never set it.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_LEN + self.payload.len()];
        buf[0..4].copy_from_slice(&HEADER_LENGTH_FIELD.to_be_bytes());
        write_padded(&mut buf[4..36], &self.message_type);
        buf[36..40].copy_from_slice(&self.schema_version.to_be_bytes());
        buf[40..48].copy_from_slice(&self.created_date.to_be_bytes());
        buf[48..56].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[56..64].copy_from_slice(&self.flags.to_be_bytes());
        // MessageId goes on the wire with its two 8-byte halves swapped (see the
        // module header) — match the agent so our echoed AcknowledgedMessageId lines
        // up with the agent's record.
        buf[64..80].copy_from_slice(&swap_uuid_halves(*self.message_id.as_bytes()));
        let digest = Sha256::digest(&self.payload);
        buf[80..112].copy_from_slice(&digest);
        buf[112..116].copy_from_slice(&self.payload_type.to_be_bytes());
        buf[116..120].copy_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf[120..].copy_from_slice(&self.payload);
        buf
    }

    /// Decode an on-wire byte buffer. The stored `PayloadDigest` is **not**
    /// re-validated (the agent does not validate it either; the channel is TLS).
    pub fn deserialize(bytes: &[u8]) -> Result<AgentMessage, FrameError> {
        if bytes.len() < HEADER_LEN {
            return Err(FrameError::TooShort(bytes.len()));
        }
        let message_type = String::from_utf8_lossy(&bytes[4..36])
            .trim_matches(|c| c == ' ' || c == '\0')
            .to_string();
        let payload_len = u32::from_be_bytes(bytes[116..120].try_into().unwrap()) as usize;
        let available = bytes.len() - HEADER_LEN;
        if available < payload_len {
            return Err(FrameError::PayloadTruncated {
                declared: payload_len,
                available,
            });
        }
        Ok(AgentMessage {
            message_type,
            schema_version: u32::from_be_bytes(bytes[36..40].try_into().unwrap()),
            created_date: u64::from_be_bytes(bytes[40..48].try_into().unwrap()),
            sequence_number: i64::from_be_bytes(bytes[48..56].try_into().unwrap()),
            flags: u64::from_be_bytes(bytes[56..64].try_into().unwrap()),
            // Undo the agent's 8-byte-half swap (see the module header) so
            // `message_id` is the UUID the agent actually tracks.
            message_id: Uuid::from_bytes(swap_uuid_halves(bytes[64..80].try_into().unwrap())),
            payload_type: u32::from_be_bytes(bytes[112..116].try_into().unwrap()),
            payload: bytes[HEADER_LEN..HEADER_LEN + payload_len].to_vec(),
        })
    }
}

/// Transpose the two 8-byte halves of a 16-byte UUID, converting between the
/// canonical UUID byte order and the agent's on-wire MessageId order (see the
/// module header). `wire[0..8] = uuid[8..16]`, `wire[8..16] = uuid[0..8]`. This is
/// its own inverse, so one function serves both encode and decode.
fn swap_uuid_halves(b: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&b[8..16]);
    out[8..16].copy_from_slice(&b[0..8]);
    out
}

/// Write `s` into a fixed-width field, **space-padded** to fill `dst` (matching
/// the agent's `putString`: fill with `' '`, then copy the string over the front;
/// truncate if longer than the field).
fn write_padded(dst: &mut [u8], s: &str) {
    dst.fill(b' ');
    let bytes = s.as_bytes();
    let n = bytes.len().min(dst.len());
    dst[..n].copy_from_slice(&bytes[..n]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(payload: &[u8]) -> AgentMessage {
        AgentMessage {
            message_type: message_type::OUTPUT_STREAM_DATA.into(),
            schema_version: 1,
            created_date: 0x0000_0190_1234_5678,
            sequence_number: 7,
            flags: FLAG_SYN,
            message_id: Uuid::from_bytes([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ]),
            payload_type: payload_type::OUTPUT,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn round_trips_all_fields() {
        let m = sample(b"A=1\nB=two");
        let back = AgentMessage::deserialize(&m.serialize()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn known_byte_layout() {
        let m = sample(b"hello");
        let bytes = m.serialize();
        // HeaderLength field is 116, not the 120-byte header size.
        assert_eq!(&bytes[0..4], &116u32.to_be_bytes());
        // MessageType is space-padded to 32 bytes.
        assert_eq!(&bytes[4..22], b"output_stream_data");
        assert_eq!(&bytes[22..36], b"              ", "padded with spaces");
        assert_eq!(&bytes[36..40], &1u32.to_be_bytes(), "schema version");
        assert_eq!(&bytes[48..56], &7i64.to_be_bytes(), "sequence number");
        assert_eq!(&bytes[56..64], &1u64.to_be_bytes(), "SYN flag");
        // MessageId on the wire has its two 8-byte halves swapped (agent contract):
        // the sample uuid is 01..10, so the wire is [09..10, 01..08].
        assert_eq!(
            &bytes[64..80],
            &[
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x07, 0x08,
            ],
            "uuid halves swapped on the wire"
        );
        // PayloadDigest is SHA-256 of the payload.
        assert_eq!(&bytes[80..112], &Sha256::digest(b"hello")[..]);
        assert_eq!(&bytes[112..116], &payload_type::OUTPUT.to_be_bytes());
        assert_eq!(&bytes[116..120], &5u32.to_be_bytes(), "payload length");
        assert_eq!(&bytes[120..], b"hello");
        assert_eq!(bytes.len(), HEADER_LEN + 5);
    }

    #[test]
    fn message_id_halves_are_swapped_on_the_wire_and_restored_on_read() {
        // The on-wire MessageId transposes the UUID's two 8-byte halves (agent
        // contract). A distinct-halves uuid makes the swap visible, and decoding
        // must recover the original — otherwise the AcknowledgedMessageId we echo
        // would not match the agent's record (endless retransmit / stalled output).
        let id = Uuid::from_bytes([
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ]);
        let mut m = sample(b"x");
        m.message_id = id;
        let bytes = m.serialize();
        // Wire layout: least-significant half (uuid[8..16]) first, then the
        // most-significant half (uuid[0..8]).
        assert_eq!(&bytes[64..72], &id.as_bytes()[8..16]);
        assert_eq!(&bytes[72..80], &id.as_bytes()[0..8]);
        // Round-trip recovers the exact UUID the agent tracks.
        assert_eq!(AgentMessage::deserialize(&bytes).unwrap().message_id, id);
    }

    #[test]
    fn empty_payload_has_only_the_header() {
        let m = sample(b"");
        let bytes = m.serialize();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(&bytes[116..120], &0u32.to_be_bytes());
        // SHA-256 of the empty string, the well-known constant.
        assert_eq!(&bytes[80..112], &Sha256::digest(b"")[..]);
        let back = AgentMessage::deserialize(&bytes).unwrap();
        assert!(back.payload.is_empty());
    }

    #[test]
    fn message_type_longer_than_field_is_truncated() {
        let mut m = sample(b"x");
        m.message_type = "a".repeat(40);
        let bytes = m.serialize();
        // Only the first 32 chars land in the field.
        assert_eq!(&bytes[4..36], "a".repeat(32).as_bytes());
        let back = AgentMessage::deserialize(&bytes).unwrap();
        assert_eq!(back.message_type, "a".repeat(32));
    }

    #[test]
    fn syn_and_fin_flag_helpers() {
        let mut m = sample(b"");
        m.flags = FLAG_SYN | FLAG_FIN;
        assert!(m.is_syn());
        assert!(m.is_fin());
        m.flags = 0;
        assert!(!m.is_syn());
        assert!(!m.is_fin());
    }

    #[test]
    fn too_short_is_rejected() {
        assert_eq!(
            AgentMessage::deserialize(&[0u8; 50]).unwrap_err(),
            FrameError::TooShort(50)
        );
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let mut bytes = sample(b"abcdef").serialize();
        bytes.truncate(HEADER_LEN + 2); // declared 6, only 2 present
        assert_eq!(
            AgentMessage::deserialize(&bytes).unwrap_err(),
            FrameError::PayloadTruncated {
                declared: 6,
                available: 2,
            }
        );
    }

    #[test]
    fn debug_elides_the_payload() {
        // The payload can be a `.env`'s contents — it must never be printed.
        let m = sample(b"SECRET=hunter2");
        let dbg = format!("{m:?}");
        assert!(
            !dbg.contains("hunter2"),
            "payload bytes must not appear in Debug"
        );
        assert!(dbg.contains("payload_len"));
    }
}
