//! The real WebSocket [`DataChannel`] over the Session Manager `StreamUrl`
//! (ADR 0025 §3, transport b). This is the **untested shell** (ADR 0010 §5): a
//! thin tungstenite adapter that turns the data channel's `wss` socket into the
//! `send_text`/`send_binary`/`recv` seam the pure protocol driver runs on. All
//! the protocol logic lives in [`super::protocol`] and is tested against a fake
//! channel; only this socket plumbing is exercised live (`live-verify-ssm`).
//!
//! TLS is rustls (no OpenSSL, no external binary) — the reason transport (b) was
//! chosen over shelling out to `session-manager-plugin`.

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

use super::protocol::{DataChannel, MgsError};

/// A connected Session Manager data channel.
pub struct TungsteniteChannel {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl TungsteniteChannel {
    /// Open the `wss` data channel at `stream_url` (from `StartSession`).
    pub async fn connect(stream_url: &str) -> Result<Self, MgsError> {
        // Log only the host (a public endpoint, e.g. `ssmmessages.<region>…`) —
        // never the full URL (it carries the session id) or the token (sent later
        // in the handshake, never in the URL).
        let host = stream_url
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("?");
        match connect_async(stream_url).await {
            Ok((ws, _resp)) => {
                tracing::debug!(target: "janitor::ssm", host, "SSM data channel open");
                Ok(TungsteniteChannel { ws })
            }
            Err(e) => {
                // The tungstenite error (HTTP status / TLS / IO) is the key
                // diagnostic and carries no secret.
                tracing::warn!(target: "janitor::ssm", host, "SSM data channel connect failed — {e}");
                Err(MgsError::Channel("connect".into()))
            }
        }
    }
}

#[async_trait]
impl DataChannel for TungsteniteChannel {
    async fn send_text(&mut self, text: String) -> Result<(), MgsError> {
        self.ws.send(Message::Text(text.into())).await.map_err(|e| {
            tracing::warn!(target: "janitor::ssm", "data channel send (text) failed — {e}");
            MgsError::Channel("send".into())
        })
    }

    async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<(), MgsError> {
        self.ws
            .send(Message::Binary(bytes.into()))
            .await
            .map_err(|e| {
                tracing::warn!(target: "janitor::ssm", "data channel send (binary) failed — {e}");
                MgsError::Channel("send".into())
            })
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>, MgsError> {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Binary(b))) => return Ok(Some(b.to_vec())),
                // A clean close: log the peer's close frame (code/reason are
                // diagnostic, e.g. an auth rejection — not secret).
                Some(Ok(Message::Close(c))) => {
                    tracing::debug!(target: "janitor::ssm", close = ?c, "data channel closed by peer");
                    return Ok(None);
                }
                None => return Ok(None),
                // Text/ping/pong/frame control: not protocol data — keep reading.
                Some(Ok(_)) => continue,
                Some(Err(e)) => {
                    tracing::warn!(target: "janitor::ssm", "data channel recv failed — {e}");
                    return Err(MgsError::Channel("recv".into()));
                }
            }
        }
    }
}
