// Phase 7: str0m-based WebRTC DataChannel abstraction
//
// str0m 0.20 with apple-crypto feature — pure Rust, sans-I/O.
// No rcgen dependency (rcgen has a coherence conflict with Rust >=1.96).
//
// Architecture: str0m is sans-I/O — the caller owns the UDP socket and
// drives the state machine via rtc.poll_output() / rtc.handle_input().
// Each peer spawns a tokio task for the event loop, communicating with
// the command layer via tokio mpsc channels.
//
// ICE: str0m does NOT trickle ICE candidate events. Local candidates are
// added before SDP creation and embedded in the offer/answer. Remote
// candidates from the browser are added via add_remote_candidate().
//
// DataChannel framing (JSON, matches the frontend protocol):
//   { type: "metadata", contentType, encryptionMetadata, fileMetadata, totalSize }
//   { type: "chunk", data: <base64 slice> }
//   { type: "end" }

use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{bail, Result};
use serde_json::{json, Value};
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::net::Protocol;
use str0m::{Candidate, Event, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::api::IceServer as ApiIceServer;
use crate::crypto::EncryptionMetadata;

const CHUNK_SIZE: usize = 16 * 1024;

// ── ICE candidate conversion ─────────────────────────────────────────────────

/// Parse a browser RTCIceCandidateInit JSON to a str0m Candidate.
fn json_to_ice(v: &Value) -> Option<Candidate> {
    let s = v["candidate"].as_str()
        .or_else(|| v["candidate"]["candidate"].as_str())?;
    Candidate::from_sdp_string(s).ok()
}

// ── Shared event loop ─────────────────────────────────────────────────────────

enum LoopCmd {
    AddIceCandidate(Value),
    ApplyAnswer(Value),
    SendData(String),
    Close,
}

pub enum LoopEvent {
    ChannelOpen,
    Message(String),
    Done,
    Error(String),
}

pub fn discover_local_ip() -> std::net::IpAddr {
    // Try to find a real LAN IP first, falling back to any routable IP.
    // On multi-homed hosts (e.g., Tailscale + LAN), prefer the LAN IP
    // because Tailscale IPs (100.64.0.0/10) don't work for same-machine
    // TCP connections on macOS (traffic goes through the tunnel instead
    // of kernel loopback).
    if let Some(lan_ip) = discover_lan_ip() {
        return lan_ip;
    }

    // Fallback: probe via UDP connect to find any outbound IP
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

/// Discover a LAN-suitable IP by enumerating network interfaces.
/// Skips loopback, Tailscale (100.64.0.0/10), link-local, and other non-LAN IPs.
/// Returns None if no private LAN interface is found.
fn discover_lan_ip() -> Option<std::net::IpAddr> {
    let output = std::process::Command::new("ifconfig")
        .output()
        .or_else(|_| std::process::Command::new("ip").args(["addr", "show"]).output())
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            let ip_str = rest.split(|c: char| c.is_whitespace() || c == '/')
                .next()
                .unwrap_or("");
            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                if is_private_lan_ip(&std::net::IpAddr::V4(ip)) {
                    return Some(std::net::IpAddr::V4(ip));
                }
            }
        }
    }
    None
}

/// Check if an IP is a standard private/LAN address (not Tailscale/CGNAT).
fn is_private_lan_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            // 10.0.0.0/8
            if o[0] == 10 { return true; }
            // 172.16.0.0/12
            if o[0] == 172 && (o[1] & 0xF0) == 16 { return true; }
            // 192.168.0.0/16
            if o[0] == 192 && o[1] == 168 { return true; }
            false
        }
        _ => false,
    }
}

async fn bind_udp(bind_ip: Option<std::net::IpAddr>) -> Result<(UdpSocket, SocketAddr)> {
    let ip = bind_ip.unwrap_or_else(discover_local_ip);
    // Always bind to 0.0.0.0 so the socket can receive from any interface.
    // Use the specified/discovered IP only for the ICE candidate address.
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let port = socket.local_addr()?.port();
    let effective_addr = SocketAddr::new(ip, port);
    Ok((socket, effective_addr))
}

async fn event_loop(
    mut rtc: Rtc,
    socket: UdpSocket,
    local_addr: SocketAddr,
    cmd_rx: &mut mpsc::UnboundedReceiver<LoopCmd>,
    event_tx: &mpsc::UnboundedSender<LoopEvent>,
    mut pending_offer: Option<SdpPendingOffer>,
    channel_id: Option<ChannelId>,
) {
    let mut buf = vec![0u8; 65_535];
    let mut channel_open = false;
    let mut pending_sends: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let mut closing = false;
    let mut drain_start: Option<Instant> = None;

    loop {
        loop {
            // Drain pending sends while SCTP has capacity
            if channel_open && !pending_sends.is_empty() {
                if let Some(id) = channel_id {
                    while let Some(frame) = pending_sends.front() {
                        if let Some(mut ch) = rtc.channel(id) {
                            match ch.write(false, frame.as_bytes()) {
                                Ok(true) => { pending_sends.pop_front(); }
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
                                    pending_sends.push_back(frame);
                                    // Batch: drain all remaining commands from the channel
                                    while let Ok(cmd) = cmd_rx.try_recv() {
                                        match cmd {
                                            LoopCmd::SendData(f) => pending_sends.push_back(f),
                                            LoopCmd::Close => { closing = true; break; }
                                            LoopCmd::AddIceCandidate(v) => {
                                                if let Some(c) = json_to_ice(&v) {
                                                    rtc.add_remote_candidate(c);
                                                }
                                            }
                                            LoopCmd::ApplyAnswer(v) => {
                                                if let Some(sdp_str) = v["sdp"]["sdp"].as_str().or_else(|| v["sdp"].as_str()) {
                                                    if let Ok(answer) = SdpAnswer::from_sdp_string(sdp_str) {
                                                        if let Some(pending) = pending_offer.take() {
                                                            let _ = rtc.sdp_api().accept_answer(pending, answer);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                Some(LoopCmd::Close) | None => {
                                    closing = true;
                                }
                            }
                        }

                        _ = tokio::time::sleep(sleep) => {
                            if rtc.handle_input(Input::Timeout(Instant::now())).is_err() {
                                return;
                            }
                        }
                    }
                    break;
                }

                Ok(Output::Transmit(t)) => {
                    let _ = socket.send_to(&t.contents, t.destination).await;
                }

                Ok(Output::Event(e)) => {
                    match e {
                        Event::ChannelOpen(id, _label) => {
                            if channel_id.map_or(true, |cid| cid == id) {
                                channel_open = true;
                                let _ = event_tx.send(LoopEvent::ChannelOpen);
                            }
                        }
                        Event::ChannelData(data) => {
                            if let Ok(s) = std::str::from_utf8(&data.data) {
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

// ── Public output type ────────────────────────────────────────────────────────

pub struct ReceivedTransfer {
    pub content_type: String,
    pub encryption_metadata: EncryptionMetadata,
    pub file_metadata: Option<Value>,
    pub encrypted_payload: String,
}

// ── SenderPeer ────────────────────────────────────────────────────────────────

pub struct SenderPeer {
    cmd_tx: mpsc::UnboundedSender<LoopCmd>,
    event_rx: mpsc::UnboundedReceiver<LoopEvent>,
    offer_sdp: String,
    loop_handle: tokio::task::JoinHandle<()>,
}

impl SenderPeer {
    pub async fn new(_ice_servers: Vec<ApiIceServer>, bind_ip: Option<std::net::IpAddr>) -> Result<Self> {
        let (socket, local_addr) = bind_udp(bind_ip).await?;
        let mut rtc = build_rtc(local_addr)?;

        let mut api = rtc.sdp_api();
        let channel_id = api.add_channel("nullseal-transfer".to_string());
        let (offer, pending) = api
            .apply()
            .ok_or_else(|| anyhow::anyhow!("no SDP changes to apply"))?;
        let offer_sdp = offer.to_sdp_string();

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let loop_handle = tokio::spawn(async move {
            event_loop(
                rtc,
                socket,
                local_addr,
                &mut cmd_rx,
                &event_tx,
                Some(pending),
                Some(channel_id),
            )
            .await;
        });

        Ok(SenderPeer { cmd_tx, event_rx, offer_sdp, loop_handle })
    }

    pub fn offer_sdp_json(&self) -> Value {
        json!({ "type": "offer", "sdp": self.offer_sdp })
    }

    pub fn handle_answer(&self, sdp: Value) -> Result<()> {
        self.cmd_tx
            .send(LoopCmd::ApplyAnswer(sdp))
            .map_err(|_| anyhow::anyhow!("event loop closed"))
    }

    pub fn add_ice_candidate(&self, payload: Value) -> Result<()> {
        self.cmd_tx
            .send(LoopCmd::AddIceCandidate(payload))
            .map_err(|_| anyhow::anyhow!("event loop closed"))
    }

    pub async fn next_event(&mut self) -> Option<LoopEvent> {
        self.event_rx.recv().await
    }

    pub fn send_frame(&self, frame: String) -> Result<()> {
        self.cmd_tx
            .send(LoopCmd::SendData(frame))
            .map_err(|_| anyhow::anyhow!("event loop closed"))
    }

    pub fn send_verify(&self, proof: &str) -> Result<()> {
        self.send_frame(json!({ "type": "verify", "proof": proof }).to_string())
    }

    pub fn send_transfer(
        &self,
        encrypted_payload: &str,
        content_type: &str,
        encryption_metadata: &EncryptionMetadata,
        file_metadata: Option<&Value>,
        on_progress: &dyn Fn(usize, usize),
    ) -> Result<()> {
        let total = encrypted_payload.len();
        self.send_frame(
            json!({
                "type": "metadata",
                "contentType": content_type,
                "encryptionMetadata": serde_json::to_value(encryption_metadata)?,
                "fileMetadata": file_metadata,
                "totalSize": total,
            })
            .to_string(),
        )?;

        let mut sent = 0usize;
        for chunk in encrypted_payload.as_bytes().chunks(CHUNK_SIZE) {
            let data = std::str::from_utf8(chunk).unwrap_or_default();
            self.send_frame(json!({ "type": "chunk", "data": data }).to_string())?;
            sent += chunk.len();
            on_progress(sent, total);
        }

        self.send_frame(json!({ "type": "end" }).to_string())?;
        Ok(())
    }

    pub fn close(&self) {
        let _ = self.cmd_tx.send(LoopCmd::Close);
    }

    pub async fn wait_closed(self) {
        let _ = self.loop_handle.await;
    }
}

// ── ReceiverPeer ──────────────────────────────────────────────────────────────

pub struct ReceiverPeer {
    cmd_tx: mpsc::UnboundedSender<LoopCmd>,
    event_rx: mpsc::UnboundedReceiver<LoopEvent>,
    answer_sdp: String,
}

impl ReceiverPeer {
    pub async fn from_offer(
        offer_payload: Value,
        _ice_servers: Vec<ApiIceServer>,
        bind_ip: Option<std::net::IpAddr>,
    ) -> Result<Self> {
        let (socket, local_addr) = bind_udp(bind_ip).await?;
        let mut rtc = build_rtc(local_addr)?;

        let offer_sdp_str = offer_payload["sdp"]["sdp"]
            .as_str()
            .or_else(|| offer_payload["sdp"].as_str())
            .ok_or_else(|| anyhow::anyhow!("missing sdp in offer"))?;

        let offer = SdpOffer::from_sdp_string(offer_sdp_str)
            .map_err(|e| anyhow::anyhow!("invalid SDP offer: {e}"))?;
        let answer = rtc
            .sdp_api()
            .accept_offer(offer)
            .map_err(|e| anyhow::anyhow!("failed to accept offer: {e}"))?;
        let answer_sdp = answer.to_sdp_string();

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            event_loop(rtc, socket, local_addr, &mut cmd_rx, &event_tx, None, None).await;
        });

        Ok(ReceiverPeer { cmd_tx, event_rx, answer_sdp })
    }

    pub fn answer_sdp_json(&self) -> Value {
        json!({ "type": "answer", "sdp": self.answer_sdp })
    }

    pub fn add_ice_candidate(&self, payload: Value) -> Result<()> {
        self.cmd_tx
            .send(LoopCmd::AddIceCandidate(payload))
            .map_err(|_| anyhow::anyhow!("event loop closed"))
    }

    pub async fn next_event(&mut self) -> Option<LoopEvent> {
        self.event_rx.recv().await
    }

    pub async fn receive_transfer(
        &mut self,
        expected_proof: &str,
        on_progress: &dyn Fn(usize, usize),
    ) -> Result<ReceivedTransfer> {
        let mut content_type = String::new();
        let mut enc_meta: Option<EncryptionMetadata> = None;
        let mut file_meta: Option<Value> = None;
        let mut chunks: Vec<String> = Vec::new();
        let mut total_size: usize = 0;
        let mut received: usize = 0;
        let mut verified = false;

        loop {
            match self.event_rx.recv().await {
                Some(LoopEvent::Message(text)) => {
                    let v: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    match v["type"].as_str() {
                        Some("verify") => {
                            let proof = v["proof"].as_str().unwrap_or("");
                            if proof != expected_proof {
                                bail!("Wrong password.");
                            }
                            verified = true;
                        }
                        Some("metadata") => {
                            content_type = v["contentType"]
                                .as_str()
                                .unwrap_or("text")
                                .to_owned();
                            enc_meta =
                                serde_json::from_value(v["encryptionMetadata"].clone()).ok();
                            file_meta = if v["fileMetadata"].is_null() {
                                None
                            } else {
                                Some(v["fileMetadata"].clone())
                            };
                            total_size = v["totalSize"].as_u64().unwrap_or(0) as usize;
                        }
                        Some("chunk") => {
                            if let Some(data) = v["data"].as_str() {
                                received += data.len();
                                chunks.push(data.to_owned());
                                on_progress(received, total_size);
                            }
                        }
                        Some("end") => break,
                        _ => {}
                    }
                }
                Some(LoopEvent::Error(e)) => bail!("WebRTC error: {e}"),
                Some(LoopEvent::Done) | None => bail!("DataChannel closed before end frame"),
                _ => {}
            }
        }

        Ok(ReceivedTransfer {
            content_type,
            encryption_metadata: enc_meta
                .ok_or_else(|| anyhow::anyhow!("no metadata frame received"))?,
            file_metadata: file_meta,
            encrypted_payload: chunks.concat(),
        })
    }

    pub fn close(&self) {
        let _ = self.cmd_tx.send(LoopCmd::Close);
    }
}

// ── Rtc builder ───────────────────────────────────────────────────────────────

fn build_rtc(local_addr: SocketAddr) -> Result<Rtc> {
    let mut rtc = Rtc::new(Instant::now());
    let candidate = Candidate::host(local_addr, "udp")
        .map_err(|e| anyhow::anyhow!("failed to create host candidate: {e}"))?;
    rtc.add_local_candidate(candidate);
    Ok(rtc)
}
