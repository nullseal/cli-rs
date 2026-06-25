//! P2P v2 receiver data-plane adapter — thin I/O around `ReceiverEngine` + `codec`.
//!
//! Decodes binary DataChannel frames, drives the ReceiverEngine, decrypts each
//! delivered chunk (injected decryptor), and emits `p2p:ack` / `p2p:request` via
//! the injected transport. Contains NO protocol decisions — those live in
#![allow(dead_code)] // library/adapter surface — exercised by #[cfg(test)]
//! `ReceiverEngine`.
//!
//! Mirrors the web `user/src/lib/p2p/receiver-adapter.ts`.

use anyhow::Result;

use super::codec;
use super::receiver_engine::{ReceiverAction, ReceiverEngine};

// ── Traits (injected I/O — unit-testable with fakes) ─────────────────────────

pub trait ReceiverTransport {
    fn emit_ack(&mut self, through: u64);
    fn emit_request(&mut self, from: u64);
}

pub trait ReceiverDecryptorT {
    fn decrypt_chunk_at(&mut self, ciphertext: &[u8], index: u64) -> Result<Vec<u8>>;
}

// ── Adapter outputs (returned to caller for flexible handling) ───────────────

#[derive(Debug)]
pub enum AdapterOutput {
    Deliver { index: u64, plaintext: Vec<u8> },
    Complete,
    Ack { through: u64 },
    Request { from: u64 },
}

// ── ReceiverAdapter ──────────────────────────────────────────────────────────

pub struct ReceiverAdapter<T: ReceiverTransport, D: ReceiverDecryptorT> {
    engine: ReceiverEngine,
    decryptor: D,
    transport: T,
    finished: bool,
}

impl<T: ReceiverTransport, D: ReceiverDecryptorT> ReceiverAdapter<T, D> {
    pub fn new(engine: ReceiverEngine, decryptor: D, transport: T) -> Self {
        ReceiverAdapter {
            engine,
            decryptor,
            transport,
            finished: false,
        }
    }

    /// Feed one raw binary frame (chunk/end) from the DataChannel.
    /// Returns adapter outputs for the caller to handle (deliver plaintext, complete).
    pub fn on_frame(&mut self, frame: &[u8], now: u64) -> Vec<AdapterOutput> {
        if self.finished {
            return vec![];
        }
        let decoded = match codec::decode(frame) {
            Ok(f) => f,
            Err(_) => return vec![],
        };
        match decoded {
            codec::Frame::Chunk { index, payload } => {
                let actions = self.engine.chunk(index, now);
                self.apply_all(actions, Some(payload))
            }
            codec::Frame::End { total_chunks } => {
                let actions = self.engine.end(total_chunks);
                self.apply_all(actions, None)
            }
        }
    }

    /// Timer pulse — periodic ACK and stall-driven resend requests.
    pub fn tick(&mut self, now: u64) -> Vec<AdapterOutput> {
        if self.finished {
            return vec![];
        }
        let actions = self.engine.tick(now);
        self.apply_all(actions, None)
    }

    /// Note control-plane traffic (feeds stall detection).
    pub fn control_activity(&mut self, now: u64) {
        self.engine.control_activity(now);
    }

    pub fn is_complete(&self) -> bool {
        self.finished
    }

    /// Access pending acks (for loopback test pumping).
    pub fn pending_acks(&self) -> &[u64] {
        &[]
    }

    /// Access pending requests (for loopback test pumping).
    pub fn pending_requests(&self) -> &[u64] {
        &[]
    }

    /// Mutable access to transport (for loopback test pumping).
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    // ── internals ────────────────────────────────────────────────────────────

    fn apply_all(
        &mut self,
        actions: Vec<ReceiverAction>,
        payload: Option<&[u8]>,
    ) -> Vec<AdapterOutput> {
        let mut outputs = Vec::new();
        for action in actions {
            if let Some(out) = self.apply(action, payload) {
                outputs.push(out);
            }
        }
        outputs
    }

    fn apply(&mut self, action: ReceiverAction, payload: Option<&[u8]>) -> Option<AdapterOutput> {
        match action {
            ReceiverAction::Deliver { index } => {
                let ciphertext = payload?;
                match self.decryptor.decrypt_chunk_at(ciphertext, index) {
                    Ok(plaintext) => Some(AdapterOutput::Deliver { index, plaintext }),
                    Err(_) => None, // decryption failure — skip
                }
            }
            ReceiverAction::Ack { through } => {
                self.transport.emit_ack(through);
                Some(AdapterOutput::Ack { through })
            }
            ReceiverAction::Request { from } => {
                self.transport.emit_request(from);
                Some(AdapterOutput::Request { from })
            }
            ReceiverAction::Complete => {
                self.finished = true;
                Some(AdapterOutput::Complete)
            }
            ReceiverAction::Ignore => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeDecryptor;
    impl ReceiverDecryptorT for FakeDecryptor {
        fn decrypt_chunk_at(&mut self, ciphertext: &[u8], _index: u64) -> Result<Vec<u8>> {
            Ok(ciphertext.to_vec())
        }
    }

    #[derive(Default)]
    struct MemTransport {
        pub acks: Vec<u64>,
        pub requests: Vec<u64>,
    }
    impl ReceiverTransport for MemTransport {
        fn emit_ack(&mut self, through: u64) {
            self.acks.push(through);
        }
        fn emit_request(&mut self, from: u64) {
            self.requests.push(from);
        }
    }

    #[test]
    fn in_order_chunks_deliver_and_ack_on_batch() {
        let engine = ReceiverEngine::new(4, 250, 5000, 0);
        let mut adapter = ReceiverAdapter::new(engine, FakeDecryptor, MemTransport::default());

        let data = vec![0xaa, 0xbb, 0xcc];
        for i in 0..4u64 {
            let frame = codec::encode_chunk(i, &data);
            let outputs = adapter.on_frame(&frame, 0);
            // Each chunk delivers
            assert!(outputs.iter().any(|o| matches!(o, AdapterOutput::Deliver { index, .. } if *index == i)));
        }
        // After 4th chunk (batch boundary), should have emitted ack
        assert_eq!(adapter.transport_mut().acks, vec![3]);
    }

    #[test]
    fn gap_triggers_request() {
        let engine = ReceiverEngine::new(64, 250, 5000, 0);
        let mut adapter = ReceiverAdapter::new(engine, FakeDecryptor, MemTransport::default());

        // Send chunk 0
        let frame0 = codec::encode_chunk(0, &[0x01]);
        adapter.on_frame(&frame0, 0);

        // Skip chunk 1, send chunk 5 → should request from 1
        let frame5 = codec::encode_chunk(5, &[0x05]);
        let outputs = adapter.on_frame(&frame5, 0);
        assert!(outputs.iter().any(|o| matches!(o, AdapterOutput::Request { from: 1 })));
        assert_eq!(adapter.transport_mut().requests, vec![1]);
    }

    #[test]
    fn end_completes_when_contiguous() {
        let engine = ReceiverEngine::new(64, 250, 5000, 0);
        let mut adapter = ReceiverAdapter::new(engine, FakeDecryptor, MemTransport::default());

        for i in 0..3u64 {
            let frame = codec::encode_chunk(i, &[i as u8]);
            adapter.on_frame(&frame, 0);
        }
        let end_frame = codec::encode_end(3);
        let outputs = adapter.on_frame(&end_frame, 0);
        assert!(outputs.iter().any(|o| matches!(o, AdapterOutput::Complete)));
        assert!(adapter.is_complete());
    }

    #[test]
    fn end_with_gap_requests_missing() {
        let engine = ReceiverEngine::new(64, 250, 5000, 0);
        let mut adapter = ReceiverAdapter::new(engine, FakeDecryptor, MemTransport::default());

        // Only deliver chunk 0
        let frame0 = codec::encode_chunk(0, &[0x00]);
        adapter.on_frame(&frame0, 0);

        // End says total=3 but we only have 0
        let end_frame = codec::encode_end(3);
        let outputs = adapter.on_frame(&end_frame, 0);
        assert!(outputs.iter().any(|o| matches!(o, AdapterOutput::Request { from: 1 })));
        assert!(!adapter.is_complete());
    }
}
