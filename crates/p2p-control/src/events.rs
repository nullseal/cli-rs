//! Typed P2P event channels and inbound router.

use serde_json::Value;
use tokio::sync::mpsc;

// ── Event name constants ──────────────────────────────────────────────────────

pub const EV_JOINED: &str = "p2p:joined";
pub const EV_BOTH_READY: &str = "p2p:both-ready";
pub const EV_OFFER: &str = "p2p:offer";
pub const EV_ANSWER: &str = "p2p:answer";
pub const EV_ICE: &str = "p2p:ice";
pub const EV_METADATA: &str = "p2p:metadata";
pub const EV_PROGRESS: &str = "p2p:progress";
pub const EV_COMPLETE: &str = "p2p:complete";
pub const EV_BOTH_COMPLETED: &str = "p2p:both-completed";
pub const EV_PEER_DISCONNECTED: &str = "p2p:peer-disconnected";
pub const EV_PEER_RECONNECTED: &str = "p2p:peer-reconnected";
pub const EV_ACK: &str = "p2p:ack";
pub const EV_REQUEST: &str = "p2p:request";
pub const EV_DC_STATUS: &str = "p2p:dc-status";
pub const EV_DELETED: &str = "p2p:deleted";
pub const EV_ERROR: &str = "p2p:error";

// ── Typed receivers ───────────────────────────────────────────────────────────

/// Receivers for all server→client events on the /p2p namespace.
pub struct P2PEvents {
    pub joined: mpsc::UnboundedReceiver<Value>,
    pub both_ready: mpsc::UnboundedReceiver<Value>,
    pub offer: mpsc::UnboundedReceiver<Value>,
    pub answer: mpsc::UnboundedReceiver<Value>,
    pub ice: mpsc::UnboundedReceiver<Value>,
    pub metadata: mpsc::UnboundedReceiver<Value>,
    pub progress: mpsc::UnboundedReceiver<Value>,
    pub complete: mpsc::UnboundedReceiver<Value>,
    pub both_completed: mpsc::UnboundedReceiver<()>,
    pub peer_disconnected: mpsc::UnboundedReceiver<Value>,
    pub peer_reconnected: mpsc::UnboundedReceiver<Value>,
    pub ack: mpsc::UnboundedReceiver<Value>,
    pub request: mpsc::UnboundedReceiver<Value>,
    pub dc_status: mpsc::UnboundedReceiver<Value>,
    pub deleted: mpsc::UnboundedReceiver<()>,
    pub error: mpsc::UnboundedReceiver<String>,
}

/// Senders for routing inbound events to the typed channels.
pub(crate) struct EventSenders {
    pub joined: mpsc::UnboundedSender<Value>,
    pub both_ready: mpsc::UnboundedSender<Value>,
    pub offer: mpsc::UnboundedSender<Value>,
    pub answer: mpsc::UnboundedSender<Value>,
    pub ice: mpsc::UnboundedSender<Value>,
    pub metadata: mpsc::UnboundedSender<Value>,
    pub progress: mpsc::UnboundedSender<Value>,
    pub complete: mpsc::UnboundedSender<Value>,
    pub both_completed: mpsc::UnboundedSender<()>,
    pub peer_disconnected: mpsc::UnboundedSender<Value>,
    pub peer_reconnected: mpsc::UnboundedSender<Value>,
    pub ack: mpsc::UnboundedSender<Value>,
    pub request: mpsc::UnboundedSender<Value>,
    pub dc_status: mpsc::UnboundedSender<Value>,
    pub deleted: mpsc::UnboundedSender<()>,
    pub error: mpsc::UnboundedSender<String>,
}

/// Create a matched pair of (senders, receivers).
pub(crate) fn create_channels() -> (EventSenders, P2PEvents) {
    let (joined_tx, joined_rx) = mpsc::unbounded_channel();
    let (both_ready_tx, both_ready_rx) = mpsc::unbounded_channel();
    let (offer_tx, offer_rx) = mpsc::unbounded_channel();
    let (answer_tx, answer_rx) = mpsc::unbounded_channel();
    let (ice_tx, ice_rx) = mpsc::unbounded_channel();
    let (metadata_tx, metadata_rx) = mpsc::unbounded_channel();
    let (progress_tx, progress_rx) = mpsc::unbounded_channel();
    let (complete_tx, complete_rx) = mpsc::unbounded_channel();
    let (both_completed_tx, both_completed_rx) = mpsc::unbounded_channel();
    let (peer_disconnected_tx, peer_disconnected_rx) = mpsc::unbounded_channel();
    let (peer_reconnected_tx, peer_reconnected_rx) = mpsc::unbounded_channel();
    let (ack_tx, ack_rx) = mpsc::unbounded_channel();
    let (request_tx, request_rx) = mpsc::unbounded_channel();
    let (dc_status_tx, dc_status_rx) = mpsc::unbounded_channel();
    let (deleted_tx, deleted_rx) = mpsc::unbounded_channel();
    let (error_tx, error_rx) = mpsc::unbounded_channel();

    let senders = EventSenders {
        joined: joined_tx,
        both_ready: both_ready_tx,
        offer: offer_tx,
        answer: answer_tx,
        ice: ice_tx,
        metadata: metadata_tx,
        progress: progress_tx,
        complete: complete_tx,
        both_completed: both_completed_tx,
        peer_disconnected: peer_disconnected_tx,
        peer_reconnected: peer_reconnected_tx,
        ack: ack_tx,
        request: request_tx,
        dc_status: dc_status_tx,
        deleted: deleted_tx,
        error: error_tx,
    };

    let receivers = P2PEvents {
        joined: joined_rx,
        both_ready: both_ready_rx,
        offer: offer_rx,
        answer: answer_rx,
        ice: ice_rx,
        metadata: metadata_rx,
        progress: progress_rx,
        complete: complete_rx,
        both_completed: both_completed_rx,
        peer_disconnected: peer_disconnected_rx,
        peer_reconnected: peer_reconnected_rx,
        ack: ack_rx,
        request: request_rx,
        dc_status: dc_status_rx,
        deleted: deleted_rx,
        error: error_rx,
    };

    (senders, receivers)
}

/// Route an inbound event (by name + payload) to the correct typed channel.
/// Unknown events are silently dropped.
pub(crate) fn route_event(senders: &EventSenders, event: &str, payload: Value) {
    match event {
        EV_JOINED => { let _ = senders.joined.send(payload); }
        EV_BOTH_READY => { let _ = senders.both_ready.send(payload); }
        EV_OFFER => { let _ = senders.offer.send(payload); }
        EV_ANSWER => { let _ = senders.answer.send(payload); }
        EV_ICE => { let _ = senders.ice.send(payload); }
        EV_METADATA => { let _ = senders.metadata.send(payload); }
        EV_PROGRESS => { let _ = senders.progress.send(payload); }
        EV_COMPLETE => { let _ = senders.complete.send(payload); }
        EV_BOTH_COMPLETED => { let _ = senders.both_completed.send(()); }
        EV_PEER_DISCONNECTED => { let _ = senders.peer_disconnected.send(payload); }
        EV_PEER_RECONNECTED => { let _ = senders.peer_reconnected.send(payload); }
        EV_ACK => { let _ = senders.ack.send(payload); }
        EV_REQUEST => { let _ = senders.request.send(payload); }
        EV_DC_STATUS => { let _ = senders.dc_status.send(payload); }
        EV_DELETED => { let _ = senders.deleted.send(()); }
        EV_ERROR => {
            let code = payload["code"].as_str().unwrap_or("unknown").to_owned();
            let _ = senders.error.send(code);
        }
        _ => {}
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn route_joined_event() {
        let (senders, mut events) = create_channels();
        let payload = json!({"sessionId": "s1", "role": "sender"});
        route_event(&senders, EV_JOINED, payload.clone());
        assert_eq!(events.joined.try_recv().unwrap(), payload);
    }

    #[test]
    fn route_both_ready_event() {
        let (senders, mut events) = create_channels();
        let payload = json!({"resumeFrom": 0});
        route_event(&senders, EV_BOTH_READY, payload.clone());
        assert_eq!(events.both_ready.try_recv().unwrap(), payload);
    }

    #[test]
    fn route_offer_event() {
        let (senders, mut events) = create_channels();
        let payload = json!({"sdp": {"type": "offer", "sdp": "v=0..."}});
        route_event(&senders, EV_OFFER, payload.clone());
        assert_eq!(events.offer.try_recv().unwrap(), payload);
    }

    #[test]
    fn route_answer_event() {
        let (senders, mut events) = create_channels();
        let payload = json!({"sdp": {"type": "answer", "sdp": "v=0..."}});
        route_event(&senders, EV_ANSWER, payload.clone());
        assert_eq!(events.answer.try_recv().unwrap(), payload);
    }

    #[test]
    fn route_ice_event() {
        let (senders, mut events) = create_channels();
        let payload = json!({"candidate": "candidate:..."});
        route_event(&senders, EV_ICE, payload.clone());
        assert_eq!(events.ice.try_recv().unwrap(), payload);
    }

    #[test]
    fn route_ack_event() {
        let (senders, mut events) = create_channels();
        let payload = json!({"through": 42});
        route_event(&senders, EV_ACK, payload.clone());
        assert_eq!(events.ack.try_recv().unwrap(), payload);
    }

    #[test]
    fn route_request_event() {
        let (senders, mut events) = create_channels();
        let payload = json!({"from": 10});
        route_event(&senders, EV_REQUEST, payload.clone());
        assert_eq!(events.request.try_recv().unwrap(), payload);
    }

    #[test]
    fn route_both_completed_carries_unit() {
        let (senders, mut events) = create_channels();
        route_event(&senders, EV_BOTH_COMPLETED, json!(null));
        assert_eq!(events.both_completed.try_recv().unwrap(), ());
    }

    #[test]
    fn route_deleted_carries_unit() {
        let (senders, mut events) = create_channels();
        route_event(&senders, EV_DELETED, json!(null));
        assert_eq!(events.deleted.try_recv().unwrap(), ());
    }

    #[test]
    fn route_error_extracts_code() {
        let (senders, mut events) = create_channels();
        route_event(&senders, EV_ERROR, json!({"code": "session_expired"}));
        assert_eq!(events.error.try_recv().unwrap(), "session_expired");
    }

    #[test]
    fn route_error_unknown_code_when_missing() {
        let (senders, mut events) = create_channels();
        route_event(&senders, EV_ERROR, json!({}));
        assert_eq!(events.error.try_recv().unwrap(), "unknown");
    }

    #[test]
    fn route_unknown_event_dropped() {
        let (senders, mut events) = create_channels();
        route_event(&senders, "p2p:nonexistent", json!({"x": 1}));
        assert!(events.joined.try_recv().is_err());
        assert!(events.error.try_recv().is_err());
        assert!(events.ack.try_recv().is_err());
    }

    #[test]
    fn route_peer_disconnected_event() {
        let (senders, mut events) = create_channels();
        let payload = json!({"reason": "timeout"});
        route_event(&senders, EV_PEER_DISCONNECTED, payload.clone());
        assert_eq!(events.peer_disconnected.try_recv().unwrap(), payload);
    }

    #[test]
    fn route_dc_status_event() {
        let (senders, mut events) = create_channels();
        let payload = json!({"connected": true});
        route_event(&senders, EV_DC_STATUS, payload.clone());
        assert_eq!(events.dc_status.try_recv().unwrap(), payload);
    }

    #[test]
    fn route_metadata_event() {
        let (senders, mut events) = create_channels();
        let payload = json!({"contentType": "file"});
        route_event(&senders, EV_METADATA, payload.clone());
        assert_eq!(events.metadata.try_recv().unwrap(), payload);
    }

    #[test]
    fn route_progress_event() {
        let (senders, mut events) = create_channels();
        let payload = json!({"chunkIndex": 5, "totalChunks": 10});
        route_event(&senders, EV_PROGRESS, payload.clone());
        assert_eq!(events.progress.try_recv().unwrap(), payload);
    }

    #[test]
    fn route_complete_event() {
        let (senders, mut events) = create_channels();
        let payload = json!({"role": "sender", "checksum": "abc"});
        route_event(&senders, EV_COMPLETE, payload.clone());
        assert_eq!(events.complete.try_recv().unwrap(), payload);
    }
}
