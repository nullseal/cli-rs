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
        // pingInterval + pingTimeout, the connection is considered dead.
        let ping_timeout = eio_config["pingTimeout"].as_u64().unwrap_or(20000);
        let server_deadline = std::time::Duration::from_millis(ping_interval + ping_timeout);

        tokio::spawn(async move {
            let mut deadline = tokio::time::interval(server_deadline);
            deadline.tick().await; // skip first immediate tick
            let mut last_pong = tokio::time::Instant::now();

            loop {
                tokio::select! {
                    biased;

                    msg = out_rx.recv() => {
                        match msg {
                            Some(m) => {
                                if sink.send(Message::Text(m.into())).await.is_err() {
                                    return;
                                }
                            }
                            None => return,
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
                                    return;
                                }
                            }
                            Some(Ok(Message::Close(_))) | None => return,
                            _ => {}
                        }
                    }

                    _ = deadline.tick() => {
                        // If no server ping arrived within the deadline, connection is dead
                        if last_pong.elapsed() > server_deadline {
                            return;
                        }
                    }
                }
            }
        });

        // Step 4: Emit p2p:join
        let join_msg = encode_event("p2p:join", &json!({ "sessionId": session_id, "role": role }));
        out_tx.send(join_msg)?;

        Ok((
            P2PSocket { tx: out_tx },
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
