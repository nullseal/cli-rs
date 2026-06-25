//! ControlTransport trait and Socket.IO implementation.

use anyhow::Result;
use serde_json::Value;

use nullseal_socketio::client::{EventReceiver, SocketIoClient, WsTransport};

use crate::events::{self, EventSenders, P2PEvents};

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Abstraction over the signaling transport (Socket.IO or DataChannel).
///
/// Implementations must be able to emit named events with JSON payloads and
/// report liveness.
pub trait ControlTransport: Send + 'static {
    fn emit(&self, event: &str, payload: &Value) -> Result<()>;
    fn is_alive(&self) -> bool;
}

// ── Socket.IO implementation ──────────────────────────────────────────────────

/// A `ControlTransport` backed by the `nullseal-socketio` crate.
pub struct SocketIoTransport {
    client: SocketIoClient,
}

impl SocketIoTransport {
    /// Connect to the signaling server and return (transport, events).
    ///
    /// Performs the Engine.IO + namespace handshake, then spawns a task to
    /// pump inbound events into the typed channels.
    pub async fn connect<T: WsTransport>(
        transport: T,
        namespace: &str,
    ) -> Result<(Self, P2PEvents)> {
        let (client, event_stream) = SocketIoClient::connect(transport, namespace).await?;
        let (senders, receivers) = events::create_channels();

        Self::spawn_pump(event_stream, senders);

        Ok((Self { client }, receivers))
    }

    fn spawn_pump(mut event_stream: EventReceiver, senders: EventSenders) {
        tokio::spawn(async move {
            while let Some(ev) = event_stream.recv().await {
                events::route_event(&senders, &ev.event, ev.payload);
            }
        });
    }
}

impl ControlTransport for SocketIoTransport {
    fn emit(&self, event: &str, payload: &Value) -> Result<()> {
        self.client.emit(event, payload)
    }

    fn is_alive(&self) -> bool {
        self.client.is_alive()
    }
}
