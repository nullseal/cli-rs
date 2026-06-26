//! P2P v2 sender data-plane adapter — thin I/O around `SenderEngine` + `codec`.
//!
//! Translates engine actions into wire effects: a JSON metadata string frame,
//! binary chunk/end frames (via codec), paced by transport back-pressure.
//! Reacts to cumulative `p2p:ack` and gap `p2p:request`. Contains NO protocol
//! decisions — those live in `SenderEngine`.
//!
//! Mirrors the web `user/src/lib/p2p/sender-adapter.ts`.

use anyhow::Result;
use serde_json::{json, Value};

use super::codec;
use super::sender_engine::{SenderAction, SenderEngine};

// ── Traits (injected I/O — unit-testable with fakes) ─────────────────────────

pub trait SenderTransport {
    fn send_text(&mut self, s: String);
    fn send_binary(&mut self, b: Vec<u8>);
}

pub trait SenderCipherT {
    fn metadata(&self) -> Value;
    fn chunk_index(&self) -> u64;
    fn skip_to(&mut self, index: u64);
    fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>>;
}

// ── SenderAdapter ────────────────────────────────────────────────────────────

pub struct SenderAdapter<'a, T: SenderTransport, C: SenderCipherT> {
    engine: SenderEngine,
    cipher: C,
    transport: T,
    plaintext: &'a [u8],
    chunk_size: usize,
    total: u64,
    meta_extra: Value,
    finished: bool,
}

impl<'a, T: SenderTransport, C: SenderCipherT> SenderAdapter<'a, T, C> {
    pub fn new(
        engine: SenderEngine,
        cipher: C,
        transport: T,
        plaintext: &'a [u8],
        chunk_size: usize,
        total: u64,
        meta_extra: Value,
    ) -> Self {
        SenderAdapter {
            engine,
            cipher,
            transport,
            plaintext,
            chunk_size,
            total,
            meta_extra,
            finished: false,
        }
    }

    /// (Re)open the channel and begin streaming from `resume_from`.
    pub fn start(&mut self, resume_from: u64) {
        self.finished = false;
        self.cipher_align(resume_from);
        let actions = self.engine.open(resume_from);
        self.apply_all(actions);
    }

    /// Recipient confirmed everything through chunk `through`.
    pub fn on_ack(&mut self, through: u64) {
        if self.finished {
            return;
        }
        let actions = self.engine.ack(through);
        self.apply_all(actions);
        if through >= self.total - 1 {
            self.finish();
        }
    }

    /// Recipient asks to resend from `from` (stall / gap repair).
    pub fn on_request(&mut self, from: u64) {
        if self.finished {
            return;
        }
        self.cipher_align(from);
        let actions = self.engine.request(from);
        self.apply_all(actions);
    }

    /// Recipient signalled completion out-of-band (e.g. `p2p:complete`).
    pub fn complete(&mut self) {
        self.finish();
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Highest chunk index sent so far (for progress reporting).
    pub fn engine_sent_through(&self) -> Option<u64> {
        self.engine.sent_through()
    }

    /// Mutable access to transport (for flushing queued frames).
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    // ── internals ────────────────────────────────────────────────────────────

    fn apply_all(&mut self, actions: Vec<SenderAction>) {
        for action in actions {
            if self.finished {
                break;
            }
            self.apply(action);
        }
    }

    fn apply(&mut self, action: SenderAction) {
        match action {
            SenderAction::Metadata { resume_from } => {
                self.cipher_align(resume_from);
                let mut meta = self.meta_extra.clone();
                if let Some(obj) = meta.as_object_mut() {
                    obj.insert(
                        "type".to_string(),
                        json!("metadata"),
                    );
                    obj.insert(
                        "streamEncryptionMetadata".to_string(),
                        self.cipher.metadata(),
                    );
                    obj.insert("totalChunks".to_string(), json!(self.total));
                    obj.insert("resumeFromChunk".to_string(), json!(resume_from));
                }
                self.transport.send_text(meta.to_string());
            }
            SenderAction::Chunk { index } => {
                self.cipher_align(index);
                let offset = (index as usize) * self.chunk_size;
                let end = (offset + self.chunk_size).min(self.plaintext.len());
                let plaintext_chunk = &self.plaintext[offset..end];
                match self.cipher.encrypt_chunk(plaintext_chunk) {
                    Ok(ciphertext) => {
                        let frame = codec::encode_chunk(index, &ciphertext);
                        self.transport.send_binary(frame);
                    }
                    Err(_) => {
                        // Encryption failure — mark finished to avoid infinite loop.
                        self.finish();
                    }
                }
            }
            SenderAction::End { total } => {
                let frame = codec::encode_end(total);
                self.transport.send_binary(frame);
            }
        }
    }

    fn cipher_align(&mut self, index: u64) {
        if self.cipher.chunk_index() != index {
            self.cipher.skip_to(index);
        }
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::codec::decode;
    use crate::p2p::receiver_engine::ReceiverEngine;

    // ── fakes ────────────────────────────────────────────────────────────────

    /// Identity cipher: ciphertext == plaintext; tracks nonce counter.
    struct FakeCipher {
        counter: u64,
    }
    impl FakeCipher {
        fn new() -> Self {
            FakeCipher { counter: 0 }
        }
    }
    impl SenderCipherT for FakeCipher {
        fn metadata(&self) -> Value {
            json!({ "algorithm": "identity" })
        }
        fn chunk_index(&self) -> u64 {
            self.counter
        }
        fn skip_to(&mut self, index: u64) {
            self.counter = index;
        }
        fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
            self.counter += 1;
            Ok(plaintext.to_vec())
        }
    }

    /// Identity decryptor for receiver side of loopback.
    struct FakeDecryptor;
    impl super::super::receiver_adapter::ReceiverDecryptorT for FakeDecryptor {
        fn decrypt_chunk_at(&mut self, ciphertext: &[u8], _index: u64) -> Result<Vec<u8>> {
            Ok(ciphertext.to_vec())
        }
    }

    /// In-memory transport that collects frames.
    struct MemTransport {
        text_frames: Vec<String>,
        binary_frames: Vec<Vec<u8>>,
    }
    impl MemTransport {
        fn new() -> Self {
            MemTransport {
                text_frames: Vec::new(),
                binary_frames: Vec::new(),
            }
        }
    }
    impl SenderTransport for MemTransport {
        fn send_text(&mut self, s: String) {
            self.text_frames.push(s);
        }
        fn send_binary(&mut self, b: Vec<u8>) {
            self.binary_frames.push(b);
        }
    }

    /// Receiver transport that collects ack/request calls.
    #[derive(Default)]
    struct MemRecvTransport {
        acks: Vec<u64>,
        requests: Vec<u64>,
    }
    impl super::super::receiver_adapter::ReceiverTransport for MemRecvTransport {
        fn emit_ack(&mut self, through: u64) {
            self.acks.push(through);
        }
        fn emit_request(&mut self, from: u64) {
            self.requests.push(from);
        }
    }

    fn make_plaintext(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 37 + 11) & 0xff) as u8).collect()
    }

    // ── loopback harness ─────────────────────────────────────────────────────

    use crate::p2p::receiver_adapter::ReceiverAdapter;

    struct Loopback {
        plaintext: Vec<u8>,
        chunk_size: usize,
        _total: u64,
        delivered: Vec<(u64, Vec<u8>)>,
        sender_finished: bool,
        receiver_complete: bool,
    }

    /// Run a full sender↔receiver loopback with optional frame dropping.
    fn run_loopback(
        plaintext: &[u8],
        chunk_size: usize,
        total: u64,
        window: u64,
        batch: u64,
        resume_from: u64,
        drop_fn: Option<&dyn Fn(&[u8]) -> bool>,
    ) -> Loopback {
        // Sender side
        let engine = SenderEngine::new(total, window);
        let cipher = FakeCipher::new();
        let transport = MemTransport::new();
        let mut sender = SenderAdapter::new(
            engine,
            cipher,
            transport,
            plaintext,
            chunk_size,
            total,
            json!({ "contentType": "text" }),
        );

        // Receiver side
        let recv_engine = ReceiverEngine::new(batch, 250, 5000, resume_from);
        let decryptor = FakeDecryptor;
        let recv_transport = MemRecvTransport::default();
        let mut delivered: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut receiver_complete = false;
        let mut receiver = ReceiverAdapter::new(recv_engine, decryptor, recv_transport);

        // Start sender
        sender.start(resume_from);

        // Pump loop: drain sender frames → receiver, then receiver ctrl → sender
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 100_000 {
                break;
            }

            // Collect binary frames from sender transport
            let binary_frames: Vec<Vec<u8>> =
                sender.transport.binary_frames.drain(..).collect();

            if binary_frames.is_empty() && receiver.pending_acks().is_empty() && receiver.pending_requests().is_empty() {
                break;
            }

            // Feed binary frames to receiver
            for frame in binary_frames {
                if let Some(drop_check) = drop_fn {
                    if drop_check(&frame) {
                        continue; // drop this frame
                    }
                }
                let actions = receiver.on_frame(&frame, 0);
                for action in actions {
                    match action {
                        crate::p2p::receiver_adapter::AdapterOutput::Deliver { index, plaintext: pt } => {
                            delivered.push((index, pt));
                        }
                        crate::p2p::receiver_adapter::AdapterOutput::Complete => {
                            receiver_complete = true;
                            sender.complete();
                        }
                        _ => {}
                    }
                }
            }

            // Feed acks/requests from receiver back to sender
            let acks: Vec<u64> = receiver.transport_mut().acks.drain(..).collect();
            let requests: Vec<u64> = receiver.transport_mut().requests.drain(..).collect();
            for through in acks {
                sender.on_ack(through);
            }
            for from in requests {
                sender.on_request(from);
            }
        }

        Loopback {
            plaintext: plaintext.to_vec(),
            chunk_size,
            _total: total,
            delivered,
            sender_finished: sender.is_finished(),
            receiver_complete,
        }
    }

    impl Loopback {
        fn reassemble(&self) -> Vec<u8> {
            let mut out = vec![0u8; self.plaintext.len()];
            for (index, bytes) in &self.delivered {
                let offset = (*index as usize) * self.chunk_size;
                let end = (offset + bytes.len()).min(out.len());
                out[offset..end].copy_from_slice(&bytes[..end - offset]);
            }
            out
        }
    }

    // ── tests ────────────────────────────────────────────────────────────────

    #[test]
    fn loopback_full_transfer_delivers_every_chunk_in_order() {
        let chunk_size = 8;
        let total = 10u64;
        let plaintext = make_plaintext((total as usize) * chunk_size - 3); // last chunk partial
        let lb = run_loopback(&plaintext, chunk_size, total, 4, 4, 0, None);

        let indices: Vec<u64> = lb.delivered.iter().map(|(i, _)| *i).collect();
        assert_eq!(indices, (0..total).collect::<Vec<_>>(), "chunks 0..9 in order");
        assert_eq!(lb.reassemble(), plaintext, "reassembled bytes match");
        assert!(lb.receiver_complete, "receiver completed");
        assert!(lb.sender_finished, "sender finished");
    }

    #[test]
    fn loopback_window_1_stop_and_wait_still_completes() {
        let chunk_size = 4;
        let total = 6u64;
        let plaintext = make_plaintext((total as usize) * chunk_size);
        let lb = run_loopback(&plaintext, chunk_size, total, 1, 1, 0, None);

        assert_eq!(lb.reassemble(), plaintext);
        assert!(lb.receiver_complete && lb.sender_finished);
    }

    #[test]
    fn loopback_dropped_chunk_triggers_request_resend_recovery() {
        let chunk_size = 8;
        let total = 10u64;
        let plaintext = make_plaintext((total as usize) * chunk_size);

        // Use a Cell for the dropped flag (closure must be Fn, not FnMut)
        use std::cell::Cell;
        let dropped_cell = Cell::new(false);
        let drop_fn = |frame: &[u8]| -> bool {
            if dropped_cell.get() {
                return false;
            }
            if let Ok(crate::p2p::codec::Frame::Chunk { index: 2, .. }) = decode(frame) {
                dropped_cell.set(true);
                return true;
            }
            false
        };

        let lb = run_loopback(&plaintext, chunk_size, total, 4, 4, 0, Some(&drop_fn));

        assert!(dropped_cell.get(), "a chunk was actually dropped");
        // Every index must be delivered
        let indices: std::collections::HashSet<u64> =
            lb.delivered.iter().map(|(i, _)| *i).collect();
        for i in 0..total {
            assert!(indices.contains(&i), "index {i} delivered");
        }
        assert_eq!(lb.reassemble(), plaintext, "recovered bytes match");
        assert!(lb.receiver_complete && lb.sender_finished);
    }

    #[test]
    fn loopback_resume_from_checkpoint_sends_only_tail() {
        let chunk_size = 8;
        let total = 10u64;
        let resume_from = 4u64;
        let plaintext = make_plaintext((total as usize) * chunk_size);
        let lb = run_loopback(&plaintext, chunk_size, total, 4, 4, resume_from, None);

        let indices: Vec<u64> = lb.delivered.iter().map(|(i, _)| *i).collect();
        assert_eq!(indices, (4..10).collect::<Vec<_>>(), "only tail 4..9 delivered");

        // Metadata frame must advertise resume point
        // (checked via sender transport text_frames in the adapter directly)
        assert!(lb.receiver_complete && lb.sender_finished);
    }

    #[test]
    fn metadata_frame_contains_expected_fields() {
        let chunk_size = 8;
        let total = 5u64;
        let plaintext = make_plaintext((total as usize) * chunk_size);

        let engine = SenderEngine::new(total, 10);
        let cipher = FakeCipher::new();
        let transport = MemTransport::new();
        let mut sender = SenderAdapter::new(
            engine,
            cipher,
            transport,
            &plaintext,
            chunk_size,
            total,
            json!({ "contentType": "file", "contentChecksum": "abc123" }),
        );
        sender.start(2);

        assert!(!sender.transport.text_frames.is_empty());
        let meta: Value = serde_json::from_str(&sender.transport.text_frames[0]).unwrap();
        assert_eq!(meta["type"], "metadata");
        assert_eq!(meta["contentType"], "file");
        assert_eq!(meta["contentChecksum"], "abc123");
        assert_eq!(meta["totalChunks"], 5);
        assert_eq!(meta["resumeFromChunk"], 2);
        assert_eq!(meta["streamEncryptionMetadata"]["algorithm"], "identity");
    }
}
