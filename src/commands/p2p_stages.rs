//! Extracted P2P stage helpers shared by sender and receiver flows.
//!
//! Each function represents one stage of the P2P connection lifecycle,
//! making the retry loops in `share.rs` and `get.rs` more readable.

use anyhow::{bail, Result};
use serde_json::Value;

use crate::retry;
use crate::socket::P2PEvents;
use crate::webrtc::{LoopEvent, ReceiverPeer, SenderPeer};

/// Wait for `p2p:ready` event (sender side).
/// On first attempt waits indefinitely; on retries uses `PEER_TIMEOUT_SECS`.
pub async fn await_ready(events: &mut P2PEvents, first_attempt: bool) -> Result<bool> {
    if first_attempt {
        tokio::select! {
            biased;
            r = events.ready.recv() => {
                r.ok_or_else(|| anyhow::anyhow!("socket closed before ready — session may have expired"))?;
                Ok(true)
            }
            err = events.error.recv() => {
                bail!("signaling error while waiting for recipient: {}", err.unwrap_or_else(|| "unknown".into()));
            }
        }
    } else {
        tokio::select! {
            biased;
            r = events.ready.recv() => {
                r.ok_or_else(|| anyhow::anyhow!("socket closed before ready"))?;
                Ok(true)
            }
            err = events.error.recv() => {
                bail!("signaling error: {}", err.unwrap_or_else(|| "unknown".into()));
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(retry::PEER_TIMEOUT_SECS)) => {
                Ok(false)
            }
        }
    }
}

/// Wait for SDP offer (receiver side).
/// On first attempt waits indefinitely; on retries uses `PEER_TIMEOUT_SECS`.
pub async fn await_offer(events: &mut P2PEvents, first_attempt: bool) -> Result<Option<Value>> {
    if first_attempt {
        let offer = loop {
            tokio::select! {
                biased;
                o = events.offer.recv() => {
                    if let Some(offer) = o {
                        break offer;
                    }
                    bail!("socket closed before offer");
                }
                err = events.error.recv() => {
                    if let Some(code) = err {
                        bail!("signaling error: {code}");
                    }
                }
            }
        };
        Ok(Some(offer))
    } else {
        let mut got_offer = None;
        tokio::select! {
            biased;
            o = events.offer.recv() => {
                if let Some(offer) = o {
                    got_offer = Some(offer);
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(retry::PEER_TIMEOUT_SECS)) => {}
        }
        Ok(got_offer)
    }
}

/// Wait for SDP answer + relay ICE candidates (sender side).
/// Returns the answer SDP value.
pub async fn await_answer(
    sender: &SenderPeer,
    events: &mut P2PEvents,
) -> Result<()> {
    loop {
        tokio::select! {
            biased;
            answer = events.answer.recv() => {
                if let Some(sdp) = answer {
                    sender.handle_answer(sdp)?;
                    return Ok(());
                }
                bail!("socket closed before answer");
            }
            ice = events.ice.recv() => {
                if let Some(c) = ice {
                    sender.add_ice_candidate(c)?;
                }
            }
            err = events.error.recv() => {
                if let Some(code) = err {
                    bail!("signaling error: {code}");
                }
            }
        }
    }
}

/// Wait for DataChannel to open on sender peer, relaying ICE candidates.
/// Returns `true` if channel opened, `false` on timeout/error.
pub async fn await_sender_channel(
    sender: &mut SenderPeer,
    events: &mut P2PEvents,
) -> Result<bool> {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(retry::CHANNEL_TIMEOUT_SECS),
        async {
            loop {
                tokio::select! {
                    biased;
                    event = sender.next_event() => {
                        match event {
                            Some(LoopEvent::ChannelOpen) => return Ok::<bool, anyhow::Error>(true),
                            Some(LoopEvent::Error(e)) => {
                                eprintln!("\x1b[1;33m⚠\x1b[0m WebRTC error: {e}");
                                return Ok(false);
                            }
                            None => return Ok(false),
                            _ => {}
                        }
                    }
                    ice = events.ice.recv() => {
                        if let Some(c) = ice {
                            sender.add_ice_candidate(c)?;
                        }
                    }
                }
            }
        },
    )
    .await;
    Ok(matches!(result, Ok(Ok(true))))
}

/// Wait for DataChannel to open on receiver peer, relaying ICE candidates.
/// Returns `true` if channel opened, `false` on timeout/error.
pub async fn await_receiver_channel(
    receiver: &mut ReceiverPeer,
    events: &mut P2PEvents,
) -> Result<bool> {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(retry::CHANNEL_TIMEOUT_SECS),
        async {
            loop {
                tokio::select! {
                    biased;
                    event = receiver.next_event() => {
                        match event {
                            Some(LoopEvent::ChannelOpen) => return Ok::<bool, anyhow::Error>(true),
                            Some(LoopEvent::Error(e)) => {
                                eprintln!("\x1b[1;33m⚠\x1b[0m WebRTC error: {e}");
                                return Ok(false);
                            }
                            Some(LoopEvent::Done) | None => return Ok(false),
                            _ => {}
                        }
                    }
                    ice = events.ice.recv() => {
                        if let Some(c) = ice {
                            receiver.add_ice_candidate(c)?;
                        }
                    }
                }
            }
        },
    )
    .await;
    Ok(matches!(result, Ok(Ok(true))))
}
