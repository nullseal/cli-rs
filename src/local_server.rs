/// Embedded Socket.IO v4 server + minimal single-session P2P relay for local mode.
///
/// Mirrors the core gateway's `/p2p` namespace semantics (join, both-ready, relay,
/// peer-disconnected) without DB/auth/rate-limit — just enough for two LAN peers
/// to run the same crate-B flow as online.

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::json;
use socketioxide::extract::{Data, SocketRef};
use socketioxide::SocketIo;
use tokio::sync::Mutex;

// ── Session state ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct Relay {
    generation: u64,
    sender_present: bool,
    recipient_present: bool,
    /// "(re-)joined since the last both-ready". both-ready only fires once BOTH are
    /// armed, then both are cleared — so after a DC-only drop (sockets stay alive)
    /// the sender doesn't re-offer until the recipient has actually re-joined and
    /// re-armed its PeerConnection. Without this, the sender re-offers too early and
    /// the recipient drains/misses the offer → resume stalls. (BUG-9)
    sender_armed: bool,
    recipient_armed: bool,
    /// Cumulative-ACK checkpoint (max `p2p:ack.through` seen). Reported in
    /// `p2p:joined` so a peer that re-joins after a drop resumes instead of
    /// restarting — mirrors the online server. (BUG-9)
    last_chunk_offset: u64,
    /// role of each socket id
    roles: std::collections::HashMap<String, String>,
}

type RelayState = Arc<Mutex<Relay>>;

const ROOM: &str = "session";

// ── Public API ────────────────────────────────────────────────────────────────

/// Start the local Socket.IO server on an ephemeral port and return the bound address.
/// The returned `JoinHandle` runs until dropped/aborted.
pub async fn start(ip: &str) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let relay: RelayState = Arc::new(Mutex::new(Relay::default()));

    let (layer, io) = SocketIo::new_layer();

    let state = relay.clone();
    io.ns("/p2p", move |socket: SocketRef| {
        let state = state.clone();
        register_handlers(socket, state);
        async {}
    });

    let app = axum::Router::new().layer(layer);

    let listener = tokio::net::TcpListener::bind(format!("{ip}:0")).await?;
    let addr = listener.local_addr()?;
    crate::commands::log::step(&format!("⚡ Local relay server on {addr}"));

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    Ok((addr, handle))
}

// ── Handler registration ──────────────────────────────────────────────────────

fn register_handlers(socket: SocketRef, state: RelayState) {
    // p2p:join
    {
        let st = state.clone();
        socket.on("p2p:join", move |socket: SocketRef, Data(payload): Data<serde_json::Value>| {
            let st = st.clone();
            async move {
                let role = payload["role"].as_str().unwrap_or("").to_owned();
                let sid = socket.id.to_string();
                socket.join(ROOM);

                let mut relay = st.lock().await;
                relay.roles.insert(sid, role.clone());
                match role.as_str() {
                    "sender" => { relay.sender_present = true; relay.sender_armed = true; }
                    "recipient" => { relay.recipient_present = true; relay.recipient_armed = true; }
                    _ => return,
                }

                let _ = socket.emit("p2p:joined", &json!({
                    "state": "JOINED",
                    "generation": relay.generation,
                    "lastChunkOffset": relay.last_chunk_offset,
                    "senderConnected": relay.sender_present,
                    "recipientConnected": relay.recipient_present,
                }));

                // both-ready only once BOTH peers have (re-)joined since the last
                // negotiation, then disarm — so a re-joining sender waits for the
                // recipient to re-arm before re-offering (resume race fix).
                if relay.sender_armed && relay.recipient_armed {
                    relay.generation += 1;
                    relay.sender_armed = false;
                    relay.recipient_armed = false;
                    let gen = relay.generation;
                    drop(relay);
                    let _ = socket.within(ROOM).emit("p2p:both-ready", &json!({ "generation": gen })).await;
                }
            }
        });
    }

    // Relay events: forward to the other peer
    for event in &[
        "p2p:offer", "p2p:answer", "p2p:ice", "p2p:metadata",
        "p2p:progress", "p2p:request", "p2p:dc-status",
    ] {
        let ev: &'static str = event;
        socket.on(ev, move |socket: SocketRef, Data(payload): Data<serde_json::Value>| async move {
            let _ = socket.to(ROOM).emit(ev, &payload).await;
        });
    }

    // p2p:ack — snoop the cumulative-ACK `through` (resume checkpoint) before
    // forwarding it unchanged to the peer. (BUG-9)
    {
        let st = state.clone();
        socket.on("p2p:ack", move |socket: SocketRef, Data(payload): Data<serde_json::Value>| {
            let st = st.clone();
            async move {
                if let Some(through) = payload.get("through").and_then(|v| v.as_u64()) {
                    let mut relay = st.lock().await;
                    if through > relay.last_chunk_offset {
                        relay.last_chunk_offset = through;
                    }
                }
                let _ = socket.to(ROOM).emit("p2p:ack", &payload).await;
            }
        });
    }

    // p2p:complete
    socket.on("p2p:complete", |socket: SocketRef, Data(payload): Data<serde_json::Value>| async move {
        let _ = socket.to(ROOM).emit("p2p:complete", &payload).await;
        let _ = socket.within(ROOM).emit("p2p:both-completed", &json!({})).await;
    });

    // p2p:delete
    socket.on("p2p:delete", |socket: SocketRef, Data(_payload): Data<serde_json::Value>| async move {
        let _ = socket.within(ROOM).emit("p2p:deleted", &json!({})).await;
    });

    // Disconnect
    {
        let st = state.clone();
        socket.on_disconnect(move |socket: SocketRef| {
            let st = st.clone();
            async move {
                let sid = socket.id.to_string();
                let mut relay = st.lock().await;
                if let Some(role) = relay.roles.remove(&sid) {
                    match role.as_str() {
                        "sender" => { relay.sender_present = false; relay.sender_armed = false; }
                        "recipient" => {
                            relay.recipient_present = false;
                            relay.recipient_armed = false;
                            // A fully-disconnected recipient (process gone) means the
                            // next recipient starts from scratch — drop the checkpoint
                            // so the sender restarts at 0. A same-process DC drop keeps
                            // its control socket alive, so this won't fire then.
                            relay.last_chunk_offset = 0;
                        }
                        _ => {}
                    }
                    drop(relay);
                    let _ = socket.to(ROOM).emit("p2p:peer-disconnected", &json!({ "role": role })).await;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use nullseal_p2p_control::control::P2PControl;
    use nullseal_p2p_control::transport::SocketIoTransport;
    use nullseal_socketio::transport::TungsteniteWs;
    use tokio::sync::mpsc::UnboundedReceiver;

    async fn connect_client(addr: SocketAddr, role: &str) -> P2PControl<SocketIoTransport> {
        let ws_url = format!("ws://{addr}/socket.io/?EIO=4&transport=websocket");
        let ws = TungsteniteWs::connect(&ws_url).await.unwrap();
        let (transport, evts) = SocketIoTransport::connect(ws, "p2p").await.unwrap();
        let control = P2PControl::new(transport, evts);
        control.join("local", role).unwrap();
        control
    }

    async fn recv_timeout<U>(rx: &mut UnboundedReceiver<U>) -> Option<U> {
        tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .ok()
            .flatten()
    }

    /// Drives the relay with two loopback crate-B clients: join sender + recipient
    /// → both receive both-ready; relay one offer → only the other peer gets it;
    /// drop one → the other gets peer-disconnected.
    #[tokio::test]
    async fn relay_routes_both_ready_offer_and_disconnect() {
        let (addr, _handle) = start("127.0.0.1").await.unwrap();

        // Sender joins first.
        let mut sender = connect_client(addr, "sender").await;
        recv_timeout(&mut sender.events.joined)
            .await
            .expect("sender joined");

        // Recipient joins → both-ready fires for both peers.
        let mut recipient = connect_client(addr, "recipient").await;
        recv_timeout(&mut recipient.events.joined)
            .await
            .expect("recipient joined");

        assert!(
            recv_timeout(&mut sender.events.both_ready).await.is_some(),
            "sender must receive both-ready"
        );
        assert!(
            recv_timeout(&mut recipient.events.both_ready).await.is_some(),
            "recipient must receive both-ready"
        );

        // Sender relays an offer → only the recipient receives it.
        sender
            .offer(&json!({ "type": "offer", "sdp": "v=0" }))
            .unwrap();
        assert!(
            recv_timeout(&mut recipient.events.offer).await.is_some(),
            "recipient must receive the relayed offer"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(400), sender.events.offer.recv())
                .await
                .is_err(),
            "sender must not receive its own offer"
        );

        // Drop the sender → recipient gets peer-disconnected.
        drop(sender);
        let ev = recv_timeout(&mut recipient.events.peer_disconnected)
            .await
            .expect("recipient must receive peer-disconnected");
        assert_eq!(ev["role"], "sender");
    }

    /// The relay snoops `p2p:ack.through` and reports it in `p2p:joined` so a
    /// re-joining peer resumes from the checkpoint instead of restarting. (BUG-9)
    #[tokio::test]
    async fn relay_persists_ack_checkpoint_for_resume() {
        let (addr, _handle) = start("127.0.0.1").await.unwrap();

        let mut sender = connect_client(addr, "sender").await;
        recv_timeout(&mut sender.events.joined).await.expect("sender joined");
        let mut recipient = connect_client(addr, "recipient").await;
        recv_timeout(&mut recipient.events.joined).await.expect("recipient joined");
        recv_timeout(&mut sender.events.both_ready).await.expect("sender both-ready");
        recv_timeout(&mut recipient.events.both_ready).await.expect("recipient both-ready");

        // Recipient acknowledges through chunk 42.
        recipient.ack(42).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Sender re-joins on its live socket → fresh `joined` must carry the checkpoint.
        sender.join("local", "sender").unwrap();
        let joined = recv_timeout(&mut sender.events.joined)
            .await
            .expect("sender re-joined");
        assert_eq!(
            joined["lastChunkOffset"].as_u64(),
            Some(42),
            "relay must report the snooped ACK checkpoint in joined"
        );
    }
}


