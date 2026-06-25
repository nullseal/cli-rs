//! Extracted P2P stage helpers shared by sender and receiver flows.
//!
//! Each function represents one stage of the P2P connection lifecycle,
//! making the retry loops in `share.rs` and `get.rs` more readable.

use anyhow::{bail, Result};
use serde_json::Value;

use crate::retry;
use nullseal_p2p_control::events::P2PEvents;
use crate::p2p::connection::ConnAction;
use crate::webrtc::{LoopEvent, ReceiverPeer, SenderPeer};

/// Extract the backoff delay (ms) from a `ConnectionMachine` action list, i.e. the
/// `ArmRetryTimer { delay_ms }` the machine emitted when it scheduled a retry.
/// Returns 0 if none (e.g. the action was `Stopped`/`Expired`).
pub fn retry_delay_ms(acts: &[ConnAction]) -> u64 {
    acts.iter()
        .find_map(|a| match a {
            ConnAction::ArmRetryTimer { delay_ms } => Some(*delay_ms),
            _ => None,
        })
        .unwrap_or(0)
}

/// Drain all currently-buffered messages from an unbounded receiver, returning
/// how many were discarded. Used on retry to clear **stale** signaling left over
/// from a previous negotiation round so the next stage acts only on fresh
/// events. In particular, a leftover `both_ready` must not make the sender fire
/// an offer against a stale state → the server rejects it with `invalid_state`.
pub fn drain<T>(rx: &mut tokio::sync::mpsc::UnboundedReceiver<T>) -> usize {
    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    count
}

/// A signaling `p2p:error` code is FATAL only when the session is gone or has
/// been taken over by another socket — there is nothing to wait for. Everything
/// else (notably `peer_timeout`, `negotiation_timeout`, `transfer_stalled`) is a
/// transient state-machine timeout: the peer simply hasn't (re)joined yet, so we
/// keep waiting / retry instead of aborting the whole transfer.
pub fn is_fatal_signaling_error(code: &str) -> bool {
    matches!(
        code,
        "session_unavailable" | "session_deleted" | "evicted" | "invalid_payload"
    )
}

/// Wait for `p2p:both-ready` event (sender side).
/// On first attempt waits indefinitely; on retries uses `PEER_TIMEOUT_SECS`.
pub async fn await_ready(events: &mut P2PEvents, first_attempt: bool) -> Result<bool> {
    if first_attempt {
        loop {
            tokio::select! {
                biased;
                r = events.both_ready.recv() => {
                    r.ok_or_else(|| anyhow::anyhow!("socket closed before ready — session may have expired"))?;
                    crate::commands::log::event("both-ready received");
                    return Ok(true);
                }
                err = events.error.recv() => {
                    let code = err.unwrap_or_else(|| "unknown".into());
                    if is_fatal_signaling_error(&code) {
                        bail!("signaling error while waiting for recipient: {code}");
                    }
                    // Recoverable (e.g. peer_timeout): the recipient just hasn't
                    // joined yet — keep waiting for them.
                    crate::commands::log::event(&format!("waiting for recipient ({code})…"));
                }
            }
        }
    } else {
        tokio::select! {
            biased;
            r = events.both_ready.recv() => {
                r.ok_or_else(|| anyhow::anyhow!("socket closed before ready"))?;
                Ok(true)
            }
            err = events.error.recv() => {
                let code = err.unwrap_or_else(|| "unknown".into());
                if is_fatal_signaling_error(&code) {
                    bail!("signaling error: {code}");
                }
                // Recoverable — report "not ready" so the caller schedules a retry.
                Ok(false)
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
                        crate::commands::log::event("offer received");
                        break offer;
                    }
                    bail!("socket closed before offer");
                }
                err = events.error.recv() => {
                    if let Some(code) = err {
                        if is_fatal_signaling_error(&code) {
                            bail!("signaling error: {code}");
                        }
                        // Recoverable (e.g. peer_timeout): the sender hasn't
                        // (re)joined yet — keep waiting for the offer.
                        crate::commands::log::event(&format!("waiting for sender ({code})…"));
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
                    crate::commands::log::event("answer received");
                    sender.handle_answer(sdp)?;
                    return Ok(());
                }
                bail!("socket closed before answer");
            }
            ice = events.ice.recv() => {
                if let Some(c) = ice {
                    crate::commands::log::event("ICE candidate received");
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
                                crate::commands::log::event(&format!("WebRTC error: {e}"));
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
                                crate::commands::log::event(&format!("WebRTC error: {e}"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn drain_discards_all_buffered_messages() {
        let (tx, mut rx) = mpsc::unbounded_channel::<i32>();
        for i in 0..5 {
            tx.send(i).unwrap();
        }
        assert_eq!(drain(&mut rx), 5);
        assert!(rx.try_recv().is_err(), "receiver must be empty after drain");
    }

    #[test]
    fn drain_on_empty_returns_zero() {
        let (_tx, mut rx) = mpsc::unbounded_channel::<i32>();
        assert_eq!(drain(&mut rx), 0);
    }

    #[test]
    fn drain_clears_stale_then_fresh_message_survives() {
        // Models the bug: a stale `both_ready` is buffered from a previous round.
        // After draining, a FRESH `both_ready` (from this re-join) must be the one
        // the next `await_ready` consumes.
        let (tx, mut rx) = mpsc::unbounded_channel::<&str>();
        tx.send("stale-both-ready").unwrap();
        assert_eq!(drain(&mut rx), 1);
        tx.send("fresh-both-ready").unwrap();
        assert_eq!(
            rx.try_recv().unwrap(),
            "fresh-both-ready",
            "the fresh event after drain must be the next one read",
        );
    }

    // ── Signaling error classification ───────────────────────────────────────

    #[test]
    fn fatal_errors_are_classified_fatal() {
        for code in ["session_unavailable", "session_deleted", "evicted", "invalid_payload"] {
            assert!(is_fatal_signaling_error(code), "{code} should be fatal");
        }
    }

    #[test]
    fn transient_timeouts_are_not_fatal() {
        // These are the ones that previously aborted the whole transfer.
        for code in ["peer_timeout", "negotiation_timeout", "transfer_stalled", "invalid_state", "unknown"] {
            assert!(!is_fatal_signaling_error(code), "{code} should be recoverable");
        }
    }

    // ── await_ready error handling ───────────────────────────────────────────

    /// Build a `P2PEvents` whose `both_ready` and `error` channels we control;
    /// the other channels are present but unused by `await_ready`.
    fn make_events() -> (
        mpsc::UnboundedSender<serde_json::Value>,
        mpsc::UnboundedSender<String>,
        P2PEvents,
    ) {
        let (both_ready_tx, both_ready) = mpsc::unbounded_channel();
        let (error_tx, error) = mpsc::unbounded_channel();
        let (_jt, joined) = mpsc::unbounded_channel();
        let (_ot, offer) = mpsc::unbounded_channel();
        let (_at, answer) = mpsc::unbounded_channel();
        let (_it, ice) = mpsc::unbounded_channel();
        let (_mt, metadata) = mpsc::unbounded_channel();
        let (_pt, progress) = mpsc::unbounded_channel();
        let (_ct, complete) = mpsc::unbounded_channel();
        let (_bct, both_completed) = mpsc::unbounded_channel();
        let (_pdt, peer_disconnected) = mpsc::unbounded_channel();
        let (_prt, peer_reconnected) = mpsc::unbounded_channel();
        let (_akt, ack) = mpsc::unbounded_channel();
        let (_rqt, request) = mpsc::unbounded_channel();
        let (_dst, dc_status) = mpsc::unbounded_channel();
        let (_dt, deleted) = mpsc::unbounded_channel();
        let events = P2PEvents {
            joined, both_ready, offer, answer, ice, metadata, progress, complete,
            both_completed, peer_disconnected, peer_reconnected, ack,
            request, dc_status, deleted, error,
        };
        (both_ready_tx, error_tx, events)
    }

    #[tokio::test]
    async fn await_ready_returns_true_on_both_ready() {
        let (both_ready_tx, _err, mut events) = make_events();
        both_ready_tx.send(serde_json::json!({"generation": 1})).unwrap();
        assert!(await_ready(&mut events, true).await.unwrap());
    }

    #[tokio::test]
    async fn await_ready_retry_peer_timeout_is_not_ready_not_error() {
        // The reported bug: peer_timeout on a retry must NOT abort the transfer.
        let (_br, error_tx, mut events) = make_events();
        error_tx.send("peer_timeout".to_string()).unwrap();
        assert_eq!(
            await_ready(&mut events, false).await.unwrap(),
            false,
            "peer_timeout on retry → not-ready (caller retries), not a hard error",
        );
    }

    #[tokio::test]
    async fn await_ready_fatal_error_aborts() {
        let (_br, error_tx, mut events) = make_events();
        error_tx.send("session_deleted".to_string()).unwrap();
        assert!(await_ready(&mut events, false).await.is_err());
    }

    #[tokio::test]
    async fn await_ready_first_attempt_skips_recoverable_then_becomes_ready() {
        let (both_ready_tx, error_tx, mut events) = make_events();
        error_tx.send("peer_timeout".to_string()).unwrap(); // buffered, recoverable
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let _ = both_ready_tx.send(serde_json::json!({}));
        });
        assert!(
            await_ready(&mut events, true).await.unwrap(),
            "first attempt skips peer_timeout and then becomes ready",
        );
    }
}
