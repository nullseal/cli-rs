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

/// The peer side of `await_answer`, so the timeout path can be unit-tested
/// without binding a UDP socket or spawning a WebRTC event loop.
pub trait AnswerSink {
    fn handle_answer(&self, sdp: Value) -> Result<()>;
    fn add_ice_candidate(&self, payload: Value) -> Result<()>;
}

impl AnswerSink for SenderPeer {
    fn handle_answer(&self, sdp: Value) -> Result<()> {
        SenderPeer::handle_answer(self, sdp)
    }
    fn add_ice_candidate(&self, payload: Value) -> Result<()> {
        SenderPeer::add_ice_candidate(self, payload)
    }
}

/// The message shown when the recipient never answers our offer. Names the
/// causes an operator can actually act on — a silent hang here has, in the
/// field, always meant WebRTC negotiation never completed on the far side.
/// (Pure — for testing.)
pub fn answer_timeout_error(secs: u64) -> String {
    format!(
        "No answer from the recipient after {secs}s — the recipient never completed \
         WebRTC negotiation. Check that UDP is permitted between the two hosts and \
         that a local security agent (VPN, firewall or endpoint protection) is not \
         blocking it. Run both sides with --verbose to see whether any ICE \
         candidates were gathered."
    )
}

/// Wait for SDP answer + relay ICE candidates (sender side).
///
/// Bounded by `retry::ANSWER_TIMEOUT_SECS`. This used to be an unbounded loop:
/// if the recipient never answered, the sender sat silent forever with no
/// output at any verbosity. Its sibling `await_sender_channel` has always been
/// bounded the same way.
pub async fn await_answer(sender: &SenderPeer, events: &mut P2PEvents) -> Result<()> {
    await_answer_inner(sender, events, retry::ANSWER_TIMEOUT_SECS).await
}

async fn await_answer_inner<S: AnswerSink>(
    sender: &S,
    events: &mut P2PEvents,
    timeout_secs: u64,
) -> Result<()> {
    let waiting = async {
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
    };

    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), waiting).await {
        Ok(result) => result,
        Err(_) => bail!(answer_timeout_error(timeout_secs)),
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

    // ── await_answer bounding ────────────────────────────────────────────────

    /// Records what `await_answer` handed to the peer, without any real WebRTC.
    #[derive(Default)]
    struct FakeSink {
        answers: std::sync::Mutex<Vec<Value>>,
        candidates: std::sync::Mutex<Vec<Value>>,
    }

    impl AnswerSink for FakeSink {
        fn handle_answer(&self, sdp: Value) -> Result<()> {
            self.answers.lock().unwrap().push(sdp);
            Ok(())
        }
        fn add_ice_candidate(&self, payload: Value) -> Result<()> {
            self.candidates.lock().unwrap().push(payload);
            Ok(())
        }
    }

    /// Extend `make_events` with handles for the answer + ice channels.
    fn make_answer_events() -> (
        mpsc::UnboundedSender<serde_json::Value>, // answer
        mpsc::UnboundedSender<serde_json::Value>, // ice
        mpsc::UnboundedSender<String>,            // error
        P2PEvents,
    ) {
        let (answer_tx, answer) = mpsc::unbounded_channel();
        let (ice_tx, ice) = mpsc::unbounded_channel();
        let (error_tx, error) = mpsc::unbounded_channel();
        let (_jt, joined) = mpsc::unbounded_channel();
        let (_brt, both_ready) = mpsc::unbounded_channel();
        let (_ot, offer) = mpsc::unbounded_channel();
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
        (answer_tx, ice_tx, error_tx, events)
    }

    #[tokio::test(start_paused = true)]
    async fn await_answer_times_out_instead_of_hanging_forever() {
        // The bug: no answer ever arrives → the old unbounded loop waited forever
        // with no output. Now it must bail with an actionable message.
        let (_answer_tx, _ice_tx, _err_tx, mut events) = make_answer_events();
        let sink = FakeSink::default();
        let err = await_answer_inner(&sink, &mut events, retry::ANSWER_TIMEOUT_SECS)
            .await
            .expect_err("a missing answer must not hang — it must time out");
        assert_eq!(err.to_string(), answer_timeout_error(retry::ANSWER_TIMEOUT_SECS));
    }

    #[tokio::test(start_paused = true)]
    async fn await_answer_relays_ice_then_returns_on_answer() {
        // The happy path must survive the timeout wrapper: candidates arriving
        // before the answer are still relayed, and the answer still resolves.
        let (answer_tx, ice_tx, _err_tx, mut events) = make_answer_events();
        ice_tx.send(serde_json::json!({"candidate": "candidate:1 1 udp 1 10.0.0.1 5000 typ host"})).unwrap();
        // The select is `biased` toward the answer, so send it only after the
        // candidate has had a chance to be drained (paused clock: no real wait).
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let _ = answer_tx.send(serde_json::json!({"type": "answer", "sdp": "v=0"}));
        });
        let sink = FakeSink::default();
        await_answer_inner(&sink, &mut events, retry::ANSWER_TIMEOUT_SECS)
            .await
            .expect("an answer within the budget must succeed");
        assert_eq!(sink.answers.lock().unwrap().len(), 1);
        assert_eq!(
            sink.candidates.lock().unwrap().len(),
            1,
            "candidates received while waiting must still be relayed to the peer",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn await_answer_still_reports_signaling_errors() {
        let (_answer_tx, _ice_tx, err_tx, mut events) = make_answer_events();
        err_tx.send("session_deleted".to_string()).unwrap();
        let sink = FakeSink::default();
        let err = await_answer_inner(&sink, &mut events, retry::ANSWER_TIMEOUT_SECS)
            .await
            .expect_err("a signaling error must surface, not wait for the timeout");
        assert!(err.to_string().contains("session_deleted"));
    }

    #[test]
    fn answer_timeout_error_is_actionable() {
        let msg = answer_timeout_error(30);
        assert!(msg.contains("30s"));
        assert!(msg.contains("never completed"), "must name the likely cause");
        assert!(msg.contains("UDP"), "must tell the operator what to check");
        assert!(msg.contains("--verbose"), "must point at the ICE diagnostics");
    }

    #[test]
    fn answer_timeout_is_its_own_constant() {
        // Must not silently ride on an unrelated timeout.
        assert_eq!(retry::ANSWER_TIMEOUT_SECS, 30);
        assert_ne!(retry::ANSWER_TIMEOUT_SECS, retry::CHANNEL_TIMEOUT_SECS);
        assert_ne!(retry::ANSWER_TIMEOUT_SECS, retry::PEER_TIMEOUT_SECS);
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
