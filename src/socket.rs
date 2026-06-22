// Phase 6: Minimal Socket.IO v4 client over WebSocket
//
// Connects to the backend's /p2p namespace and relays signaling messages
// (SDP offer/answer + ICE candidates) between sender and recipient.
//
// Uses tokio-tungstenite directly instead of rust_socketio to avoid
// namespace connection bugs in rust_socketio 0.6.

use anyhow::{bail, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};

// ── Public types ──────────────────────────────────────────────────────────────

/// Receivers for all server→client events on the /p2p namespace.
pub struct P2PEvents {
    pub joined: mpsc::UnboundedReceiver<()>,
    pub ready: mpsc::UnboundedReceiver<()>,
    pub offer: mpsc::UnboundedReceiver<Value>,
    pub answer: mpsc::UnboundedReceiver<Value>,
    pub ice: mpsc::UnboundedReceiver<Value>,
    pub error: mpsc::UnboundedReceiver<String>,
}

/// Thin wrapper around a WebSocket connection speaking Socket.IO v4.
pub struct P2PSocket {
    tx: mpsc::UnboundedSender<String>,
    alive: Arc<AtomicBool>,
}

impl P2PSocket {
    /// Connect to the signaling server's /p2p namespace and emit `p2p:join`.
    pub async fn connect(
        server_url: &str,
        session_id: &str,
        role: &str,
    ) -> Result<(P2PSocket, P2PEvents)> {
        // Build Engine.IO v4 WebSocket URL
        let ws_url = build_ws_url(server_url)?;

        let (ws, _) = connect_async(&ws_url).await?;
        let (mut sink, mut stream) = ws.split();

        // Step 1: Engine.IO open — receive `0{...}`
        let open_msg = read_text(&mut stream).await?;
        if !open_msg.starts_with('0') {
            bail!("expected EIO open, got: {open_msg}");
        }
        let eio_config: Value = serde_json::from_str(&open_msg[1..])?;
        let ping_interval = eio_config["pingInterval"].as_u64().unwrap_or(25000);

        // Step 2: Connect to /p2p namespace — send `40/p2p,`
        sink.send(Message::Text("40/p2p,".into())).await?;

        // Step 3: Wait for namespace connect ack `40/p2p,{...}`
        loop {
            let msg = read_text(&mut stream).await?;
            if msg.starts_with("40/p2p,") {
                break;
            }
            if msg.starts_with("44/p2p,") {
                bail!("namespace /p2p connect error: {msg}");
            }
            // Handle EIO ping during handshake
            if msg == "2" {
                sink.send(Message::Text("3".into())).await?;
            }
        }

        // Channels for events
        let (joined_tx, joined_rx) = mpsc::unbounded_channel::<()>();
        let (ready_tx, ready_rx) = mpsc::unbounded_channel::<()>();
        let (offer_tx, offer_rx) = mpsc::unbounded_channel::<Value>();
        let (answer_tx, answer_rx) = mpsc::unbounded_channel::<Value>();
        let (ice_tx, ice_rx) = mpsc::unbounded_channel::<Value>();
        let (error_tx, error_rx) = mpsc::unbounded_channel::<String>();

        // Channel for outgoing messages
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();

        // Spawn reader/writer loop
        // EIO4: the SERVER sends pings ("2") and the client replies with pongs ("3").
        // We track when the last server ping arrived; if none comes within
        // the deadline, the connection is considered dead.
        // Cap at 15s for faster dead-connection detection (server default is 45s).
        let ping_timeout = eio_config["pingTimeout"].as_u64().unwrap_or(20000);
        let raw_deadline_ms = ping_interval + ping_timeout;
        let server_deadline = std::time::Duration::from_millis(raw_deadline_ms.min(15_000));

        let alive = Arc::new(AtomicBool::new(true));
        let alive_flag = alive.clone();

        tokio::spawn(async move {
            let mut deadline = tokio::time::interval(server_deadline);
            deadline.tick().await; // skip first immediate tick
            // Client-side probe: send EIO ping every 10s to detect dead connections faster
            let mut probe = tokio::time::interval(std::time::Duration::from_secs(10));
            probe.tick().await; // skip first immediate tick
            let mut last_pong = tokio::time::Instant::now();

            loop {
                tokio::select! {
                    biased;

                    msg = out_rx.recv() => {
                        match msg {
                            Some(m) => {
                                if sink.send(Message::Text(m.into())).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }

                    frame = stream.next() => {
                        match frame {
                            Some(Ok(Message::Text(text))) => {
                                let text = text.to_string();
                                if text == "2" {
                                    // Server ping → reply with pong
                                    last_pong = tokio::time::Instant::now();
                                    let _ = sink.send(Message::Text("3".into())).await;
                                    continue;
                                }
                                if text == "3" {
                                    // Server pong (response to our probe) — just update timestamp
                                    last_pong = tokio::time::Instant::now();
                                    continue;
                                }
                                if let Some(json_str) = text.strip_prefix("42/p2p,") {
                                    if let Ok(arr) = serde_json::from_str::<Vec<Value>>(json_str) {
                                        if !arr.is_empty() {
                                            let event = arr[0].as_str().unwrap_or("");
                                            let data = arr.get(1).cloned().unwrap_or(Value::Null);
                                            match event {
                                                "p2p:joined" => { let _ = joined_tx.send(()); }
                                                "p2p:ready" => { let _ = ready_tx.send(()); }
                                                "p2p:offer" => { let _ = offer_tx.send(data); }
                                                "p2p:answer" => { let _ = answer_tx.send(data); }
                                                "p2p:ice" => { let _ = ice_tx.send(data); }
                                                "p2p:error" => {
                                                    let code = data["code"].as_str()
                                                        .unwrap_or("unknown").to_owned();
                                                    let _ = error_tx.send(code);
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                } else if text.starts_with("41/p2p") {
                                    break;
                                }
                            }
                            Some(Ok(Message::Close(_))) | None => break,
                            _ => {}
                        }
                    }

                    _ = deadline.tick() => {
                        // If no server ping arrived within the deadline, connection is dead
                        if last_pong.elapsed() > server_deadline {
                            break;
                        }
                    }

                    _ = probe.tick() => {
                        // Send client-side EIO ping to elicit a pong from the server
                        if sink.send(Message::Text("2".into())).await.is_err() {
                            break;
                        }
                    }
                }
            }

            alive_flag.store(false, Ordering::Release);
        });

        // Step 4: Emit p2p:join
        let join_msg = encode_event("p2p:join", &json!({ "sessionId": session_id, "role": role }));
        out_tx.send(join_msg)?;

        Ok((
            P2PSocket { tx: out_tx, alive },
            P2PEvents {
                joined: joined_rx,
                ready: ready_rx,
                offer: offer_rx,
                answer: answer_rx,
                ice: ice_rx,
                error: error_rx,
            },
        ))
    }

    pub async fn send_offer(&self, sdp: Value) -> Result<()> {
        self.tx.send(encode_event("p2p:offer", &json!({ "sdp": sdp })))?;
        Ok(())
    }

    pub async fn send_answer(&self, sdp: Value) -> Result<()> {
        self.tx.send(encode_event("p2p:answer", &json!({ "sdp": sdp })))?;
        Ok(())
    }

    pub async fn done(&self) -> Result<()> {
        self.tx.send(encode_event("p2p:done", &json!({})))?;
        Ok(())
    }

    /// Emit p2p:join with the given session and role.
    pub fn emit_join(&self, session_id: &str, role: &str) -> Result<()> {
        self.tx.send(encode_event("p2p:join", &json!({ "sessionId": session_id, "role": role })))?;
        Ok(())
    }

    /// Returns `true` if the underlying WebSocket task is still running.
    /// When `false`, the socket is dead and must be recreated with `connect()`.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    pub async fn disconnect(&self) -> Result<()> {
        let _ = self.tx.send("41/p2p,".to_owned());
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_ws_url(server_url: &str) -> Result<String> {
    let mut url = url::Url::parse(server_url)?;
    match url.scheme() {
        "http" => url.set_scheme("ws").unwrap(),
        "https" => url.set_scheme("wss").unwrap(),
        _ => {}
    }
    url.set_path("/socket.io/");
    url.query_pairs_mut()
        .append_pair("EIO", "4")
        .append_pair("transport", "websocket");
    Ok(url.to_string())
}

fn encode_event(event: &str, data: &Value) -> String {
    let arr = json!([event, data]);
    format!("42/p2p,{}", arr)
}

/// Read the next text frame from the WebSocket stream.
async fn read_text<S>(stream: &mut S) -> Result<String>
where
    S: StreamExt<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(t))) => return Ok(t.to_string()),
            Some(Ok(_)) => continue,
            Some(Err(e)) => bail!("websocket error: {e}"),
            None => bail!("websocket closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_event_formats_socketio_v4() {
        let msg = encode_event("p2p:join", &json!({"sessionId": "abc", "role": "sender"}));
        assert!(msg.starts_with("42/p2p,"));
        let json_part = msg.strip_prefix("42/p2p,").unwrap();
        let arr: Vec<Value> = serde_json::from_str(json_part).unwrap();
        assert_eq!(arr[0], "p2p:join");
        assert_eq!(arr[1]["sessionId"], "abc");
        assert_eq!(arr[1]["role"], "sender");
    }

    #[test]
    fn build_ws_url_converts_http_to_ws() {
        let url = build_ws_url("http://localhost:3001").unwrap();
        assert!(url.starts_with("ws://localhost:3001/socket.io/"));
        assert!(url.contains("EIO=4"));
        assert!(url.contains("transport=websocket"));
    }

    #[test]
    fn build_ws_url_converts_https_to_wss() {
        let url = build_ws_url("https://api.nullseal.com").unwrap();
        assert!(url.starts_with("wss://api.nullseal.com/socket.io/"));
    }

    #[tokio::test]
    async fn is_alive_true_initially_false_after_disconnect() {
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;

        // Bind a local WS server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn server that does EIO handshake then namespace connect
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(stream).await.unwrap();
            // EIO open
            ws.send(Message::Text(
                r#"0{"sid":"test","upgrades":[],"pingInterval":25000,"pingTimeout":20000,"maxPayload":100000}"#.into(),
            )).await.unwrap();
            // Wait for namespace connect request (40/p2p,)
            let _ = ws.next().await;
            // Send namespace connect ack
            ws.send(Message::Text("40/p2p,{\"sid\":\"nsid\"}".into())).await.unwrap();
            // Wait for p2p:join
            let _ = ws.next().await;
            // Send p2p:joined
            ws.send(Message::Text("42/p2p,[\"p2p:joined\"]".into())).await.unwrap();
            // Give client time to read
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            // Close the connection
            let _ = ws.close(None).await;
        });

        let server_url = format!("http://127.0.0.1:{}", addr.port());
        let (socket, mut events) = P2PSocket::connect(&server_url, "sess1", "sender").await.unwrap();

        // Wait for joined
        events.joined.recv().await.unwrap();

        // Should be alive right after connect
        assert!(socket.is_alive());

        // Wait for server to close connection
        server_handle.await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // After server closed, socket task should exit → is_alive = false
        assert!(!socket.is_alive());
    }
}
