use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde_json::Value;
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::net::Protocol;
use str0m::{Event, IceConnectionState, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use nullseal_turn::indication;

use super::{LoopCmd, LoopEvent, TurnRelay};

/// A pending frame queued for SCTP delivery (text or binary).
enum PendingFrame {
    Text(String),
    Binary(Vec<u8>),
}

impl PendingFrame {
    fn is_binary(&self) -> bool {
        matches!(self, PendingFrame::Binary(_))
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            PendingFrame::Text(s) => s.as_bytes(),
            PendingFrame::Binary(b) => b,
        }
    }
}

/// Max frames written to SCTP per poll cycle. With bounded channel backpressure
/// + 8 MB thread stacks, we can be generous here to maintain throughput.
const MAX_DRAIN_PER_CYCLE: usize = 64;

/// Max frames buffered locally in `pending_sends` before we stop reading from
/// the command channel. This ensures true end-to-end backpressure: when str0m
/// can't keep up, pending_sends fills → we stop reading → channel fills →
/// sender's send_frame().await blocks.  Kept small so that sender-side
/// progress reporting stays close to actual SCTP delivery.
const MAX_PENDING: usize = 24;

/// Parse a browser RTCIceCandidateInit JSON to a str0m Candidate.
fn json_to_ice(v: &Value) -> Option<str0m::Candidate> {
    let s = v["candidate"]
        .as_str()
        .or_else(|| v["candidate"]["candidate"].as_str())?;
    str0m::Candidate::from_sdp_string(s).ok()
}

/// The sans-I/O event loop that drives str0m's state machine.
///
/// Owns the UDP socket and processes commands from the peer layer
/// while emitting events back via the channel.
pub async fn run(
    mut rtc: Rtc,
    socket: UdpSocket,
    local_addr: SocketAddr,
    cmd_rx: &mut mpsc::Receiver<LoopCmd>,
    event_tx: &mpsc::UnboundedSender<LoopEvent>,
    mut pending_offer: Option<SdpPendingOffer>,
    mut channel_id: Option<ChannelId>,
    mut turn_relay: Option<TurnRelay>,
) {
    let mut buf = vec![0u8; 65_535];
    let mut channel_open = false;
    let mut pending_sends: std::collections::VecDeque<PendingFrame> = std::collections::VecDeque::new();
    let mut closing = false;
    let mut drain_start: Option<Instant> = None;

    // TURN refresh interval (lifetime/2). Default 5 min if no allocation.
    let refresh_interval = turn_relay
        .as_ref()
        .map(|t| Duration::from_secs(t.allocation.lifetime as u64 / 2))
        .unwrap_or(Duration::from_secs(300));
    let mut refresh_deadline = Instant::now() + refresh_interval;

    loop {
        loop {
            // Drain pending sends while SCTP has capacity
            if channel_open && !pending_sends.is_empty() {
                if let Some(id) = channel_id {
                    let mut drained = 0usize;
                    while drained < MAX_DRAIN_PER_CYCLE {
                        let Some(frame) = pending_sends.front() else {
                            break;
                        };
                        if let Some(mut ch) = rtc.channel(id) {
                            match ch.write(frame.is_binary(), frame.as_bytes()) {
                                Ok(true) => {
                                    pending_sends.pop_front();
                                    drained += 1;
                                }
                                _ => break, // SCTP buffer full or error, wait for acks
                            }
                        } else {
                            break;
                        }
                    }
                }
            }

            // After closing + all pending data flushed, keep the loop alive
            // so rtc.poll_output() can emit Transmit outputs for the actual
            // UDP packets. Exit after a grace period to ensure delivery.
            if closing && pending_sends.is_empty() {
                if drain_start.is_none() {
                    drain_start = Some(Instant::now());
                }
                if drain_start.unwrap().elapsed() > std::time::Duration::from_secs(3) {
                    return;
                }
            }

            match rtc.poll_output() {
                Ok(Output::Timeout(deadline)) => {
                    let sleep = {
                        let now = Instant::now();
                        if deadline > now {
                            deadline - now
                        } else {
                            std::time::Duration::ZERO
                        }
                    };
                    tokio::select! {
                        biased;

                        result = socket.recv_from(&mut buf) => {
                            match result {
                                Ok((n, src)) => {
                                    if let Some(ref mut relay) = turn_relay {
                                        if src == relay.server_addr {
                                            // Packet from TURN server — Data indication or control response
                                            if let Some((peer, data)) = indication::parse_data_indication(&buf[..n]) {
                                                // Unwrap Data indication → feed str0m as relay traffic
                                                if let Ok(receive) = str0m::net::Receive::new(
                                                    Protocol::Udp, peer, relay.relay_addr, &data,
                                                ) {
                                                    if rtc.handle_input(Input::Receive(Instant::now(), receive)).is_err() {
                                                        return;
                                                    }
                                                }
                                            }
                                            // else: TURN control response (refresh/permission) — ignore
                                            break;
                                        }
                                    }
                                    // Direct ICE traffic — feed str0m unchanged
                                    if let Ok(receive) = str0m::net::Receive::new(
                                        Protocol::Udp, src, local_addr, &buf[..n],
                                    ) {
                                        if rtc.handle_input(Input::Receive(Instant::now(), receive)).is_err() {
                                            return;
                                        }
                                    }
                                }
                                Err(_) => return,
                            }
                        }

                        cmd = cmd_rx.recv(), if !closing => {
                            match cmd {
                                Some(LoopCmd::AddIceCandidate(v)) => {
                                    if let Some(c) = json_to_ice(&v) {
                                        rtc.add_remote_candidate(c);
                                    }
                                }
                                Some(LoopCmd::ApplyAnswer(v)) => {
                                    if let Some(sdp_str) = v["sdp"]["sdp"].as_str().or_else(|| v["sdp"].as_str()) {
                                        if let Ok(answer) = SdpAnswer::from_sdp_string(sdp_str) {
                                            if let Some(pending) = pending_offer.take() {
                                                let _ = rtc.sdp_api().accept_answer(pending, answer);
                                            }
                                        }
                                    }
                                }
                                Some(LoopCmd::SendData(frame)) => {
                                    pending_sends.push_back(PendingFrame::Text(frame));
                                    // Only batch more frames if pending_sends still has room
                                    while pending_sends.len() < MAX_PENDING {
                                        match cmd_rx.try_recv() {
                                            Ok(LoopCmd::SendData(f)) => pending_sends.push_back(PendingFrame::Text(f)),
                                            Ok(LoopCmd::SendBinary(b)) => pending_sends.push_back(PendingFrame::Binary(b)),
                                            Ok(LoopCmd::Close) => {
                                                // Drain all remaining SendData from channel
                                                while let Ok(remaining) = cmd_rx.try_recv() {
                                                    match remaining {
                                                        LoopCmd::SendData(f) => pending_sends.push_back(PendingFrame::Text(f)),
                                                        LoopCmd::SendBinary(b) => pending_sends.push_back(PendingFrame::Binary(b)),
                                                        _ => {}
                                                    }
                                                }
                                                closing = true;
                                                break;
                                            }
                                            Ok(LoopCmd::AddIceCandidate(v)) => {
                                                if let Some(c) = json_to_ice(&v) {
                                                    rtc.add_remote_candidate(c);
                                                }
                                            }
                                            Ok(LoopCmd::ApplyAnswer(v)) => {
                                                if let Some(sdp_str) = v["sdp"]["sdp"].as_str().or_else(|| v["sdp"].as_str()) {
                                                    if let Ok(answer) = SdpAnswer::from_sdp_string(sdp_str) {
                                                        if let Some(pending) = pending_offer.take() {
                                                            let _ = rtc.sdp_api().accept_answer(pending, answer);
                                                        }
                                                    }
                                                }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                }
                                Some(LoopCmd::SendBinary(frame)) => {
                                    pending_sends.push_back(PendingFrame::Binary(frame));
                                    // Batch more frames if room
                                    while pending_sends.len() < MAX_PENDING {
                                        match cmd_rx.try_recv() {
                                            Ok(LoopCmd::SendData(f)) => pending_sends.push_back(PendingFrame::Text(f)),
                                            Ok(LoopCmd::SendBinary(b)) => pending_sends.push_back(PendingFrame::Binary(b)),
                                            Ok(LoopCmd::Close) => {
                                                while let Ok(remaining) = cmd_rx.try_recv() {
                                                    match remaining {
                                                        LoopCmd::SendData(f) => pending_sends.push_back(PendingFrame::Text(f)),
                                                        LoopCmd::SendBinary(b) => pending_sends.push_back(PendingFrame::Binary(b)),
                                                        _ => {}
                                                    }
                                                }
                                                closing = true;
                                                break;
                                            }
                                            Ok(LoopCmd::AddIceCandidate(v)) => {
                                                if let Some(c) = json_to_ice(&v) {
                                                    rtc.add_remote_candidate(c);
                                                }
                                            }
                                            Ok(LoopCmd::ApplyAnswer(v)) => {
                                                if let Some(sdp_str) = v["sdp"]["sdp"].as_str().or_else(|| v["sdp"].as_str()) {
                                                    if let Ok(answer) = SdpAnswer::from_sdp_string(sdp_str) {
                                                        if let Some(pending) = pending_offer.take() {
                                                            let _ = rtc.sdp_api().accept_answer(pending, answer);
                                                        }
                                                    }
                                                }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                }
                                Some(LoopCmd::Close) | None => {
                                    // Drain all remaining frames from channel before closing
                                    while let Ok(remaining) = cmd_rx.try_recv() {
                                        match remaining {
                                            LoopCmd::SendData(f) => pending_sends.push_back(PendingFrame::Text(f)),
                                            LoopCmd::SendBinary(b) => pending_sends.push_back(PendingFrame::Binary(b)),
                                            _ => {}
                                        }
                                    }
                                    closing = true;
                                }
                            }
                        }

                        _ = tokio::time::sleep(sleep) => {
                            if rtc.handle_input(Input::Timeout(Instant::now())).is_err() {
                                return;
                            }
                        }

                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(refresh_deadline)), if turn_relay.is_some() => {
                            // TURN refresh — fire and forget
                            if let Some(ref relay) = turn_relay {
                                let msg = build_refresh_msg(&relay.allocation);
                                let _ = socket.send_to(&msg, relay.server_addr).await;
                            }
                            refresh_deadline = Instant::now() + refresh_interval;
                        }
                    }
                    break;
                }

                Ok(Output::Transmit(t)) => {
                    if let Some(ref mut relay) = turn_relay {
                        if t.source == relay.relay_addr {
                            // Relay traffic — wrap in Send indication
                            // Ensure CreatePermission for this peer
                            let peer_ip = t.destination.ip();
                            if !relay.permitted_ips.contains(&peer_ip) {
                                relay.permitted_ips.insert(peer_ip);
                                // Fire-and-forget CreatePermission
                                let perm_msg = create_permission_msg(&relay.allocation, &t.destination);
                                let _ = socket.send_to(&perm_msg, relay.server_addr).await;
                            }
                            let ind = indication::build_send_indication(&t.destination, &t.contents);
                            let _ = socket.send_to(&ind, relay.server_addr).await;
                        } else {
                            // Direct send (host/srflx candidate)
                            let _ = socket.send_to(&t.contents, t.destination).await;
                        }
                    } else {
                        let _ = socket.send_to(&t.contents, t.destination).await;
                    }
                }

                Ok(Output::Event(e)) => {
                    match e {
                        Event::IceConnectionStateChange(IceConnectionState::Disconnected) => {
                            let _ = event_tx.send(LoopEvent::Error(
                                "ICE disconnected (network change or peer lost)".to_string(),
                            ));
                            return;
                        }
                        Event::ChannelOpen(id, _label) => {
                            if channel_id.map_or(true, |cid| cid == id) {
                                channel_open = true;
                                // Capture the channel ID for incoming channels
                                // (receiver passes None initially since it doesn't
                                // know the ID until the remote peer opens it).
                                if channel_id.is_none() {
                                    channel_id = Some(id);
                                }
                                let _ = event_tx.send(LoopEvent::ChannelOpen);
                            }
                        }
                        Event::ChannelData(data) => {
                            if data.binary {
                                let _ = event_tx.send(LoopEvent::BinaryData(data.data));
                            } else if let Ok(s) = std::str::from_utf8(&data.data) {
                                let _ = event_tx.send(LoopEvent::Message(s.to_owned()));
                            }
                        }
                        Event::ChannelClose(_) => {
                            let _ = event_tx.send(LoopEvent::Done);
                            return;
                        }
                        _ => {}
                    }
                }

                Err(e) => {
                    let _ = event_tx.send(LoopEvent::Error(e.to_string()));
                    return;
                }
            }
        }
    }
}

// ── TURN message helpers (fire-and-forget, no response waiting) ───────────────

use nullseal_turn::allocate::{build_create_permission, build_refresh, new_txn_id};
use super::turn::TurnAllocation;

/// Build a CreatePermission request message for the given peer.
fn create_permission_msg(alloc: &TurnAllocation, peer: &SocketAddr) -> Vec<u8> {
    let txn_id = new_txn_id();
    build_create_permission(&txn_id, &alloc.username, &alloc.realm, &alloc.nonce, &alloc.key, peer)
}

/// Build a Refresh request message to keep the TURN allocation alive.
fn build_refresh_msg(alloc: &TurnAllocation) -> Vec<u8> {
    let txn_id = new_txn_id();
    build_refresh(&txn_id, &alloc.username, &alloc.realm, &alloc.nonce, &alloc.key, alloc.lifetime)
}

// ── Routing decision helpers (extracted for testability) ──────────────────────

/// Classify an inbound packet from the TURN server.
/// Returns `Some((peer_addr, data))` for Data indications, `None` for control.
#[cfg(test)]
pub(crate) fn classify_inbound_from_turn(buf: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
    indication::parse_data_indication(buf)
}

/// Determine whether an outbound transmit should be routed via TURN relay.
#[cfg(test)]
pub(crate) fn is_relay_routed(source: SocketAddr, relay_addr: SocketAddr) -> bool {
    source == relay_addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    fn test_relay_addr() -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 49163)
    }
    fn test_peer_addr() -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9999)
    }
    fn test_local_addr() -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000)
    }

    #[test]
    fn outbound_relay_source_is_relay_routed() {
        assert!(is_relay_routed(test_relay_addr(), test_relay_addr()));
    }

    #[test]
    fn outbound_direct_source_is_not_relay_routed() {
        assert!(!is_relay_routed(test_local_addr(), test_relay_addr()));
    }

    #[test]
    fn send_indication_round_trips_through_parse() {
        let peer = test_peer_addr();
        let payload = b"hello relay world";
        let indication_bytes = indication::build_send_indication(&peer, payload);
        // Send indications use method 0x0016; Data indications use 0x0017.
        // parse_data_indication only parses Data indications (0x0017).
        // Build a Data indication manually by replacing the method type.
        let mut data_ind = indication_bytes.clone();
        // STUN/TURN header: first 2 bytes = method type
        // Send = 0x0016, Data = 0x0017
        data_ind[1] = 0x17;
        let parsed = classify_inbound_from_turn(&data_ind);
        assert!(parsed.is_some(), "Data indication should parse successfully");
        let (parsed_peer, parsed_data) = parsed.unwrap();
        assert_eq!(parsed_peer, peer);
        assert_eq!(parsed_data, payload);
    }

    #[test]
    fn turn_control_response_is_not_data_indication() {
        // A STUN Binding response (method 0x0101) should NOT be treated as Data
        let stun_response = vec![
            0x01, 0x01, // Binding Success Response
            0x00, 0x00, // Length: 0
            0x21, 0x12, 0xA4, 0x42, // Magic Cookie
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, // Transaction ID
        ];
        assert!(classify_inbound_from_turn(&stun_response).is_none());
    }

    #[test]
    fn create_permission_msg_is_valid_stun() {
        let alloc = super::super::turn::TurnAllocation {
            relayed: test_relay_addr(),
            srflx: test_local_addr(),
            lifetime: 600,
            realm: "nullseal".to_string(),
            nonce: "testnonce".to_string(),
            username: "testuser".to_string(),
            key: nullseal_turn::auth::long_term_key("testuser", "nullseal", "testpass"),
        };
        let peer = test_peer_addr();
        let msg = create_permission_msg(&alloc, &peer);
        // Should be valid STUN: starts with method, has magic cookie
        assert!(msg.len() >= 20, "STUN message too short");
        assert_eq!(&msg[4..8], &[0x21, 0x12, 0xA4, 0x42], "Missing STUN magic cookie");
        // Method type for CreatePermission = 0x0008
        assert_eq!(msg[0] & 0x3F, 0x00);
        assert_eq!(msg[1], 0x08);
    }

    #[test]
    fn refresh_msg_is_valid_stun() {
        let alloc = super::super::turn::TurnAllocation {
            relayed: test_relay_addr(),
            srflx: test_local_addr(),
            lifetime: 600,
            realm: "nullseal".to_string(),
            nonce: "testnonce".to_string(),
            username: "testuser".to_string(),
            key: nullseal_turn::auth::long_term_key("testuser", "nullseal", "testpass"),
        };
        let msg = build_refresh_msg(&alloc);
        assert!(msg.len() >= 20, "STUN message too short");
        assert_eq!(&msg[4..8], &[0x21, 0x12, 0xA4, 0x42], "Missing STUN magic cookie");
        // Method type for Refresh = 0x0004
        assert_eq!(msg[0] & 0x3F, 0x00);
        assert_eq!(msg[1], 0x04);
    }

    #[tokio::test]
    async fn relay_routing_loopback_send_indication_reaches_turn_server() {
        // Simulate: event loop sends a Send indication to TURN server
        // when transmit.source == relay_addr
        let turn_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let turn_addr = turn_socket.local_addr().unwrap();
        let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = test_relay_addr();
        let peer = test_peer_addr();
        let payload = b"data through relay";

        // Simulate what the event loop does for relay-routed transmits:
        // Build Send indication and send to TURN server
        assert!(is_relay_routed(relay_addr, relay_addr));
        let ind = indication::build_send_indication(&peer, payload);
        client_socket.send_to(&ind, turn_addr).await.unwrap();

        // TURN server receives the Send indication
        let mut buf = vec![0u8; 65535];
        let (n, from) = turn_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(from, client_socket.local_addr().unwrap());

        // Verify it's a valid Send indication (method 0x0016)
        assert!(n >= 20);
        assert_eq!(buf[1], 0x16, "Expected Send indication method");

        // Build a Data indication (what coturn would relay back)
        // and verify classify_inbound_from_turn can parse it
        let mut data_ind = buf[..n].to_vec();
        data_ind[1] = 0x17; // Convert Send→Data indication
        let parsed = classify_inbound_from_turn(&data_ind);
        assert!(parsed.is_some());
        let (parsed_peer, parsed_data) = parsed.unwrap();
        assert_eq!(parsed_peer, peer);
        assert_eq!(parsed_data, payload);
    }
}
