//! Async Socket.IO v4 client driver, generic over a `WsTransport` trait.
//!
//! The driver handles:
//! - Engine.IO handshake (open frame → namespace connect)
//! - Ping/pong keepalive (server sends ping, client replies pong)
//! - Liveness detection (deadline based on pingInterval + grace)
//! - Inbound event routing to an mpsc channel
//! - Outbound `emit()` for sending events

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::proto;

/// Grace period added to `pingInterval` for the default liveness deadline.
const LIVENESS_GRACE_MS: u64 = 5_000;

// ── Transport trait ───────────────────────────────────────────────────────────

/// Abstraction over a WebSocket connection for testability.
///
/// Implement this trait to provide a real or mock WebSocket transport.
pub trait WsTransport: Send + 'static {
    /// Send a text frame.
    fn send(
        &mut self,
        text: String,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Receive the next text frame. Returns `None` when the connection is closed.
    fn recv(&mut self) -> impl std::future::Future<Output = Option<String>> + Send;
}

// ── Public types ──────────────────────────────────────────────────────────────

/// An inbound event from the server.
#[derive(Debug, Clone)]
pub struct InboundEvent {
    pub event: String,
    pub payload: Value,
}

/// Stream of inbound events from the server.
pub type EventReceiver = mpsc::UnboundedReceiver<InboundEvent>;

/// The Socket.IO client handle. Use `emit()` to send events, `is_alive()` to
/// check liveness.
#[derive(Debug)]
pub struct SocketIoClient {
    tx: mpsc::UnboundedSender<String>,
    alive: Arc<AtomicBool>,
    namespace: String,
}

impl SocketIoClient {
    /// Connect to a Socket.IO v4 server over the given transport, joining `namespace`.
    ///
    /// Uses the default liveness deadline (`pingInterval + 5 s`).
    pub async fn connect<T: WsTransport>(
        transport: T,
        namespace: &str,
    ) -> Result<(Self, EventReceiver)> {
        Self::connect_with_deadline(transport, namespace, None).await
    }

    /// Connect with an explicit liveness `deadline`.
    ///
    /// `None` = `pingInterval + LIVENESS_GRACE_MS` (~30 s with default server config).
    pub async fn connect_with_deadline<T: WsTransport>(
        mut transport: T,
        namespace: &str,
        deadline: Option<Duration>,
    ) -> Result<(Self, EventReceiver)> {
        // Step 1: Engine.IO open — expect `0{...}`
        let open_msg = match transport.recv().await {
            Some(msg) => msg,
            None => bail!("transport closed before EIO open"),
        };
        let handshake = proto::parse_open(&open_msg)
            .ok_or_else(|| anyhow::anyhow!("expected EIO open, got: {open_msg}"))?;

        // Step 2: Send namespace connect
        let ns_connect = proto::encode_namespace_connect(namespace);
        transport.send(ns_connect).await?;

        // Step 3: Wait for namespace connect ack (handle pings during handshake)
        loop {
            let msg = match transport.recv().await {
                Some(m) => m,
                None => bail!("transport closed during namespace handshake"),
            };
            let frame = proto::parse_frame(&msg, namespace);
            match frame {
                proto::Frame::NamespaceAck { .. } => break,
                proto::Frame::ConnectError(e) => bail!("namespace connect error: {e}"),
                proto::Frame::Ping => {
                    transport.send(proto::PONG.to_owned()).await?;
                }
                _ => { /* ignore other frames during handshake */ }
            }
        }

        // Set up channels
        let (event_tx, event_rx) = mpsc::unbounded_channel::<InboundEvent>();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();

        let alive = Arc::new(AtomicBool::new(true));
        let alive_flag = alive.clone();
        let ns = namespace.to_owned();

        // Liveness deadline: pingInterval + grace (default ~30 s), or injected.
        let deadline_dur = deadline.unwrap_or_else(|| {
            Duration::from_millis(handshake.ping_interval + LIVENESS_GRACE_MS)
        });

        // Check cadence: deadline/2, clamped to [50 ms, 5 s].
        let check = (deadline_dur / 2)
            .clamp(Duration::from_millis(50), Duration::from_secs(5));

        // Spawn reader/writer loop
        tokio::spawn(async move {
            let mut last_activity = Instant::now();
            let mut deadline_interval = tokio::time::interval(check);
            deadline_interval.tick().await; // skip first immediate tick

            loop {
                tokio::select! {
                    biased;

                    // Outbound messages
                    msg = out_rx.recv() => {
                        match msg {
                            Some(m) => {
                                if transport.send(m).await.is_err() {
                                    break;
                                }
                            }
                            None => break, // sender dropped
                        }
                    }

                    // Inbound frames
                    frame = transport.recv() => {
                        match frame {
                            Some(text) => {
                                let parsed = proto::parse_frame(&text, &ns);
                                match parsed {
                                    proto::Frame::Ping => {
                                        last_activity = Instant::now();
                                        let _ = transport.send(proto::PONG.to_owned()).await;
                                    }
                                    proto::Frame::Pong => {
                                        last_activity = Instant::now();
                                    }
                                    proto::Frame::Event { event, payload } => {
                                        last_activity = Instant::now();
                                        let _ = event_tx.send(InboundEvent { event, payload });
                                    }
                                    proto::Frame::Disconnect => break,
                                    _ => {
                                        last_activity = Instant::now();
                                    }
                                }
                            }
                            None => break, // connection closed
                        }
                    }

                    // Liveness check
                    _ = deadline_interval.tick() => {
                        if last_activity.elapsed() > deadline_dur {
                            break;
                        }
                    }
                }
            }

            alive_flag.store(false, Ordering::Release);
        });

        Ok((
            SocketIoClient {
                tx: out_tx,
                alive,
                namespace: namespace.to_owned(),
            },
            event_rx,
        ))
    }

    /// Emit an event to the server.
    pub fn emit(&self, event: &str, payload: &Value) -> Result<()> {
        let frame = proto::encode_event(&self.namespace, event, payload);
        self.tx
            .send(frame)
            .map_err(|_| anyhow::anyhow!("socket closed"))?;
        Ok(())
    }

    /// Returns `true` if the background task is still alive.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Send a namespace disconnect and drop the outgoing channel.
    pub fn disconnect(&self) {
        let _ = self.tx.send(proto::encode_disconnect(&self.namespace));
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tokio::sync::Mutex;

    /// Mock transport that feeds scripted responses and records sent frames.
    ///
    /// When `stay_open` is true, `recv()` pends forever once the queue is empty
    /// (simulating a connection that stays open but sends nothing).
    /// When false, it returns `None` after a short delay (simulating closure).
    struct MockWs {
        incoming: Arc<Mutex<VecDeque<Option<String>>>>,
        sent: Arc<Mutex<Vec<String>>>,
        stay_open: bool,
    }

    impl MockWs {
        fn new(incoming: Vec<Option<String>>) -> Self {
            Self {
                incoming: Arc::new(Mutex::new(incoming.into())),
                sent: Arc::new(Mutex::new(Vec::new())),
                stay_open: false,
            }
        }

        fn new_stay_open(incoming: Vec<Option<String>>) -> Self {
            Self {
                incoming: Arc::new(Mutex::new(incoming.into())),
                sent: Arc::new(Mutex::new(Vec::new())),
                stay_open: true,
            }
        }

        fn sent_clone(&self) -> Arc<Mutex<Vec<String>>> {
            self.sent.clone()
        }

        fn incoming_clone(&self) -> Arc<Mutex<VecDeque<Option<String>>>> {
            self.incoming.clone()
        }
    }

    impl WsTransport for MockWs {
        async fn send(&mut self, text: String) -> Result<()> {
            self.sent.lock().await.push(text);
            Ok(())
        }

        async fn recv(&mut self) -> Option<String> {
            tokio::task::yield_now().await;
            let mut q = self.incoming.lock().await;
            match q.pop_front() {
                Some(item) => item,
                None => {
                    drop(q);
                    if self.stay_open {
                        // Pend forever — only the deadline can exit the loop
                        std::future::pending::<()>().await;
                        None
                    } else {
                        // Simulate transport closure after a short delay
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        None
                    }
                }
            }
        }
    }

    fn eio_open() -> String {
        r#"0{"sid":"test-sid","upgrades":[],"pingInterval":25000,"pingTimeout":20000,"maxPayload":100000}"#.to_owned()
    }

    fn ns_ack(ns: &str) -> String {
        format!(r#"40/{ns},{{"sid":"ns-sid"}}"#)
    }

    #[tokio::test]
    async fn handshake_completes_and_surfaces_event() {
        let mock = MockWs::new(vec![
            Some(eio_open()),
            Some(ns_ack("chat")),
            Some(r#"42/chat,["greeting",{"msg":"hello"}]"#.to_owned()),
            None, // close
        ]);

        let (client, mut events) = SocketIoClient::connect(mock, "chat").await.unwrap();

        // Should receive the event
        let ev = events.recv().await.unwrap();
        assert_eq!(ev.event, "greeting");
        assert_eq!(ev.payload["msg"], "hello");

        // After close, eventually goes not alive
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!client.is_alive());
    }

    #[tokio::test]
    async fn emit_sends_encoded_frame() {
        let mock = MockWs::new(vec![
            Some(eio_open()),
            Some(ns_ack("ns")),
            None,
        ]);
        let sent = mock.sent_clone();

        let (client, _events) = SocketIoClient::connect(mock, "ns").await.unwrap();

        client.emit("my-event", &serde_json::json!({"x": 1})).unwrap();
        // Give the spawn loop time to send
        tokio::time::sleep(Duration::from_millis(50)).await;

        let frames = sent.lock().await;
        // First frame is the namespace connect (40/ns,)
        assert_eq!(frames[0], "40/ns,");
        // Second frame is our emitted event
        assert!(frames[1].starts_with("42/ns,"));
        assert!(frames[1].contains("my-event"));
    }

    #[tokio::test]
    async fn ping_receives_pong_reply() {
        let mock = MockWs::new(vec![
            Some(eio_open()),
            Some(ns_ack("p")),
            Some("2".to_owned()), // server ping
            None,
        ]);
        let sent = mock.sent_clone();

        let (_client, _events) = SocketIoClient::connect(mock, "p").await.unwrap();

        // Wait for the pong to be sent
        tokio::time::sleep(Duration::from_millis(100)).await;

        let frames = sent.lock().await;
        // Should contain a "3" (pong) response
        assert!(frames.contains(&"3".to_owned()), "expected pong in {:?}", *frames);
    }

    #[tokio::test]
    async fn is_alive_true_after_connect() {
        let mock = MockWs::new(vec![
            Some(eio_open()),
            Some(ns_ack("x")),
            // Keep connection open with pings
            Some("2".to_owned()),
        ]);
        let incoming = mock.incoming_clone();

        let (client, _events) = SocketIoClient::connect(mock, "x").await.unwrap();

        assert!(client.is_alive());

        // Now close it
        incoming.lock().await.push_back(None);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!client.is_alive());
    }

    #[tokio::test]
    async fn closes_when_transport_returns_none() {
        let mock = MockWs::new(vec![
            Some(eio_open()),
            Some(ns_ack("t")),
            // No more frames — recv returns None after queue empties
        ]);

        let (client, _events) = SocketIoClient::connect(mock, "t").await.unwrap();
        assert!(client.is_alive());

        // After the mock returns None, connection dies
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!client.is_alive());
    }

    #[tokio::test]
    async fn liveness_deadline_fires_without_pings() {
        // stay_open mock: recv() pends forever once queue is empty,
        // so only the liveness deadline can exit the driver loop.
        let mock = MockWs::new_stay_open(vec![
            Some(eio_open()),
            Some(ns_ack("t")),
        ]);

        let (client, _ev) = SocketIoClient::connect_with_deadline(
            mock, "t", Some(Duration::from_millis(150)),
        ).await.unwrap();
        assert!(client.is_alive());

        // Wait longer than deadline + a check cycle
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(!client.is_alive(), "deadline should have killed the connection");
    }

    #[tokio::test]
    async fn disconnect_sends_frame() {
        let mock = MockWs::new(vec![
            Some(eio_open()),
            Some(ns_ack("d")),
            None,
        ]);
        let sent = mock.sent_clone();

        let (client, _events) = SocketIoClient::connect(mock, "d").await.unwrap();
        client.disconnect();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let frames = sent.lock().await;
        assert!(frames.contains(&"41/d,".to_owned()), "expected disconnect in {:?}", *frames);
    }

    #[tokio::test]
    async fn connect_error_returns_err() {
        let mock = MockWs::new(vec![
            Some(eio_open()),
            Some(r#"44/x,{"message":"unauthorized"}"#.to_owned()),
        ]);

        let result = SocketIoClient::connect(mock, "x").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("connect error"), "got: {err}");
    }

    #[tokio::test]
    async fn handles_ping_during_handshake() {
        let mock = MockWs::new(vec![
            Some(eio_open()),
            Some("2".to_owned()), // ping during handshake
            Some(ns_ack("h")),
            None,
        ]);
        let sent = mock.sent_clone();

        let (_client, _events) = SocketIoClient::connect(mock, "h").await.unwrap();

        let frames = sent.lock().await;
        // Should have responded with pong during handshake
        assert!(frames.contains(&"3".to_owned()));
    }
}
