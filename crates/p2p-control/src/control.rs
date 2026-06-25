//! P2PControl — typed emit API + event receivers.

use anyhow::Result;
use serde_json::{json, Value};

use crate::events::P2PEvents;
use crate::transport::ControlTransport;

// ── P2PControl ────────────────────────────────────────────────────────────────

/// High-level P2P control handle.
///
/// Wraps a `ControlTransport` with a typed emit API and holds the inbound
/// event receivers.
pub struct P2PControl<T: ControlTransport> {
    transport: T,
    pub events: P2PEvents,
}

impl<T: ControlTransport> P2PControl<T> {
    pub fn new(transport: T, events: P2PEvents) -> Self {
        Self { transport, events }
    }

    // ── Emit API ──────────────────────────────────────────────────────────────

    pub fn join(&self, session_id: &str, role: &str) -> Result<()> {
        self.transport.emit("p2p:join", &json!({
            "sessionId": session_id,
            "role": role,
        }))
    }

    pub fn offer(&self, sdp: &Value) -> Result<()> {
        self.transport.emit("p2p:offer", &json!({ "sdp": sdp }))
    }

    pub fn answer(&self, sdp: &Value) -> Result<()> {
        self.transport.emit("p2p:answer", &json!({ "sdp": sdp }))
    }

    pub fn ice(&self, candidate: &Value) -> Result<()> {
        self.transport.emit("p2p:ice", candidate)
    }

    pub fn metadata(&self, metadata: &Value) -> Result<()> {
        self.transport.emit("p2p:metadata", metadata)
    }

    pub fn progress(&self, chunk_index: u64, total_chunks: usize) -> Result<()> {
        self.transport.emit("p2p:progress", &json!({
            "chunkIndex": chunk_index,
            "totalChunks": total_chunks,
        }))
    }

    pub fn complete(&self, role: &str, checksum: &str) -> Result<()> {
        self.transport.emit("p2p:complete", &json!({
            "role": role,
            "checksum": checksum,
        }))
    }

    pub fn ack(&self, through: u64) -> Result<()> {
        self.transport.emit("p2p:ack", &json!({
            "through": through,
        }))
    }

    pub fn request(&self, from: u64) -> Result<()> {
        self.transport.emit("p2p:request", &json!({
            "from": from,
        }))
    }

    pub fn dc_status(&self, connected: bool) -> Result<()> {
        self.transport.emit("p2p:dc-status", &json!({
            "connected": connected,
        }))
    }

    pub fn delete(&self) -> Result<()> {
        self.transport.emit("p2p:delete", &json!({}))
    }

    pub fn is_alive(&self) -> bool {
        self.transport.is_alive()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use crate::events;

    struct MockTransport {
        calls: Arc<Mutex<Vec<(String, Value)>>>,
        alive: bool,
    }

    impl MockTransport {
        fn new() -> (Self, Arc<Mutex<Vec<(String, Value)>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (Self { calls: calls.clone(), alive: true }, calls)
        }
    }

    impl ControlTransport for MockTransport {
        fn emit(&self, event: &str, payload: &Value) -> Result<()> {
            self.calls.lock().unwrap().push((event.to_owned(), payload.clone()));
            Ok(())
        }

        fn is_alive(&self) -> bool {
            self.alive
        }
    }

    #[test]
    fn join_emits_correct_payload() {
        let (mock, calls) = MockTransport::new();
        let (_senders, events) = events::create_channels();
        let ctrl = P2PControl::new(mock, events);

        ctrl.join("sess1", "sender").unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, "p2p:join");
        assert_eq!(recorded[0].1["sessionId"], "sess1");
        assert_eq!(recorded[0].1["role"], "sender");
    }

    #[test]
    fn offer_emits_correct_payload() {
        let (mock, calls) = MockTransport::new();
        let (_senders, events) = events::create_channels();
        let ctrl = P2PControl::new(mock, events);

        let sdp = json!({"type": "offer", "sdp": "v=0..."});
        ctrl.offer(&sdp).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded[0].0, "p2p:offer");
        assert_eq!(recorded[0].1["sdp"], sdp);
    }

    #[test]
    fn answer_emits_correct_payload() {
        let (mock, calls) = MockTransport::new();
        let (_senders, events) = events::create_channels();
        let ctrl = P2PControl::new(mock, events);

        let sdp = json!({"type": "answer", "sdp": "v=0..."});
        ctrl.answer(&sdp).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded[0].0, "p2p:answer");
        assert_eq!(recorded[0].1["sdp"], sdp);
    }

    #[test]
    fn ack_emits_through() {
        let (mock, calls) = MockTransport::new();
        let (_senders, events) = events::create_channels();
        let ctrl = P2PControl::new(mock, events);

        ctrl.ack(42).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded[0].0, "p2p:ack");
        assert_eq!(recorded[0].1["through"], 42);
    }

    #[test]
    fn request_emits_from() {
        let (mock, calls) = MockTransport::new();
        let (_senders, events) = events::create_channels();
        let ctrl = P2PControl::new(mock, events);

        ctrl.request(10).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded[0].0, "p2p:request");
        assert_eq!(recorded[0].1["from"], 10);
    }

    #[test]
    fn progress_emits_camel_case_keys() {
        let (mock, calls) = MockTransport::new();
        let (_senders, events) = events::create_channels();
        let ctrl = P2PControl::new(mock, events);

        ctrl.progress(5, 100).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded[0].0, "p2p:progress");
        assert_eq!(recorded[0].1["chunkIndex"], 5);
        assert_eq!(recorded[0].1["totalChunks"], 100);
    }

    #[test]
    fn complete_emits_role_and_checksum() {
        let (mock, calls) = MockTransport::new();
        let (_senders, events) = events::create_channels();
        let ctrl = P2PControl::new(mock, events);

        ctrl.complete("sender", "sha256abc").unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded[0].0, "p2p:complete");
        assert_eq!(recorded[0].1["role"], "sender");
        assert_eq!(recorded[0].1["checksum"], "sha256abc");
    }

    #[test]
    fn dc_status_emits_connected() {
        let (mock, calls) = MockTransport::new();
        let (_senders, events) = events::create_channels();
        let ctrl = P2PControl::new(mock, events);

        ctrl.dc_status(true).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded[0].0, "p2p:dc-status");
        assert_eq!(recorded[0].1["connected"], true);
    }

    #[test]
    fn delete_emits_empty_payload() {
        let (mock, calls) = MockTransport::new();
        let (_senders, events) = events::create_channels();
        let ctrl = P2PControl::new(mock, events);

        ctrl.delete().unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded[0].0, "p2p:delete");
        assert_eq!(recorded[0].1, json!({}));
    }

    #[test]
    fn is_alive_delegates_to_transport() {
        let (mock, _calls) = MockTransport::new();
        let (_senders, events) = events::create_channels();
        let ctrl = P2PControl::new(mock, events);
        assert!(ctrl.is_alive());
    }

    #[test]
    fn ice_emits_candidate_directly() {
        let (mock, calls) = MockTransport::new();
        let (_senders, events) = events::create_channels();
        let ctrl = P2PControl::new(mock, events);

        let candidate = json!({"candidate": "candidate:...", "sdpMLineIndex": 0});
        ctrl.ice(&candidate).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded[0].0, "p2p:ice");
        assert_eq!(recorded[0].1, candidate);
    }

    #[test]
    fn metadata_emits_value_directly() {
        let (mock, calls) = MockTransport::new();
        let (_senders, events) = events::create_channels();
        let ctrl = P2PControl::new(mock, events);

        let meta = json!({"contentType": "file", "fileName": "test.txt"});
        ctrl.metadata(&meta).unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded[0].0, "p2p:metadata");
        assert_eq!(recorded[0].1, meta);
    }
}
