use std::net::SocketAddr;
use std::time::Instant;

use serde_json::Value;
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::net::Protocol;
use str0m::{Event, IceConnectionState, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::{LoopCmd, LoopEvent};

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
                    let mut drained = 0usize;
                    while drained < MAX_DRAIN_PER_CYCLE {
                        let Some(frame) = pending_sends.front() else {
                            break;
                        };
                        if let Some(mut ch) = rtc.channel(id) {
                            match ch.write(false, frame.as_bytes()) {
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
                                    // Only batch more frames if pending_sends still has room
                                    while pending_sends.len() < MAX_PENDING {
                                        match cmd_rx.try_recv() {
                                            Ok(LoopCmd::SendData(f)) => pending_sends.push_back(f),
                                            Ok(LoopCmd::Close) => {
                                                // Drain all remaining SendData from channel
                                                while let Ok(remaining) = cmd_rx.try_recv() {
                                                    if let LoopCmd::SendData(f) = remaining {
                                                        pending_sends.push_back(f);
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
                                    // Drain all remaining SendData from channel before closing
                                    while let Ok(remaining) = cmd_rx.try_recv() {
                                        if let LoopCmd::SendData(f) = remaining {
                                            pending_sends.push_back(f);
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
                    }
                    break;
                }

                Ok(Output::Transmit(t)) => {
                    let _ = socket.send_to(&t.contents, t.destination).await;
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
