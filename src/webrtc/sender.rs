use anyhow::Result;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::api::IceServer as ApiIceServer;
use crate::crypto::EncryptionMetadata;

use super::event_loop;
use super::net::bind_udp;
use super::{build_rtc, LoopCmd, LoopEvent, CHUNK_SIZE};

/// Bounded channel capacity — kept small so the sender's progress display
/// closely tracks what the event loop has actually consumed.  Together with
/// MAX_PENDING in event_loop.rs the sender can be at most ~28 frames
/// (~448 KB) ahead of SCTP writes.
const CMD_CHANNEL_CAPACITY: usize = 4;

pub struct SenderPeer {
    cmd_tx: mpsc::Sender<LoopCmd>,
    event_rx: mpsc::UnboundedReceiver<LoopEvent>,
    offer_sdp: String,
    loop_handle: tokio::task::JoinHandle<()>,
}

impl SenderPeer {
    pub async fn new(
        _ice_servers: Vec<ApiIceServer>,
        bind_ip: Option<std::net::IpAddr>,
    ) -> Result<Self> {
        let (socket, local_addr) = bind_udp(bind_ip).await?;
        let mut rtc = build_rtc(local_addr)?;

        let mut api = rtc.sdp_api();
        let channel_id = api.add_channel("nullseal-transfer".to_string());
        let (offer, pending) = api
            .apply()
            .ok_or_else(|| anyhow::anyhow!("no SDP changes to apply"))?;
        let offer_sdp = offer.to_sdp_string();

        let (cmd_tx, mut cmd_rx) = mpsc::channel(CMD_CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let loop_handle = tokio::spawn(async move {
            event_loop::run(
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

        Ok(SenderPeer {
            cmd_tx,
            event_rx,
            offer_sdp,
            loop_handle,
        })
    }

    pub fn offer_sdp_json(&self) -> Value {
        json!({ "type": "offer", "sdp": self.offer_sdp })
    }

    pub fn handle_answer(&self, sdp: Value) -> Result<()> {
        self.cmd_tx
            .try_send(LoopCmd::ApplyAnswer(sdp))
            .map_err(|_| anyhow::anyhow!("event loop closed"))
    }

    pub fn add_ice_candidate(&self, payload: Value) -> Result<()> {
        self.cmd_tx
            .try_send(LoopCmd::AddIceCandidate(payload))
            .map_err(|_| anyhow::anyhow!("event loop closed"))
    }

    pub async fn next_event(&mut self) -> Option<LoopEvent> {
        self.event_rx.recv().await
    }

    pub async fn send_frame(&self, frame: String) -> Result<()> {
        self.cmd_tx
            .send(LoopCmd::SendData(frame))
            .await
            .map_err(|_| anyhow::anyhow!("event loop closed"))
    }

    pub fn send_verify(&self, proof: &str) -> Result<()> {
        self.cmd_tx
            .try_send(LoopCmd::SendData(
                json!({ "type": "verify", "proof": proof }).to_string(),
            ))
            .map_err(|_| anyhow::anyhow!("event loop closed"))
    }

    pub async fn send_transfer(
        &self,
        encrypted_payload: &str,
        content_type: &str,
        encryption_metadata: &EncryptionMetadata,
        file_metadata: Option<&Value>,
        content_checksum: &str,
        on_progress: &dyn Fn(usize, usize),
    ) -> Result<()> {
        let total = encrypted_payload.len();
        self.send_frame(
            json!({
                "type": "metadata",
                "contentType": content_type,
                "encryptionMetadata": serde_json::to_value(encryption_metadata)?,
                "fileMetadata": file_metadata,
                "contentChecksum": content_checksum,
                "totalSize": total,
            })
            .to_string(),
        ).await?;

        let mut sent = 0usize;
        for chunk in encrypted_payload.as_bytes().chunks(CHUNK_SIZE) {
            let data = std::str::from_utf8(chunk).unwrap_or_default();
            self.send_frame(json!({ "type": "chunk", "data": data }).to_string()).await?;
            sent += chunk.len();
            on_progress(sent, total);
        }

        self.send_frame(json!({ "type": "end" }).to_string()).await?;
        Ok(())
    }

    /// Wait for resume frame from receiver, returns the chunk index to start from.
    /// If no resume frame received within timeout, returns 0.
    pub async fn wait_for_resume(&mut self, timeout_ms: u64) -> usize {
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            tokio::select! {
                biased;
                event = self.event_rx.recv() => {
                    match event {
                        Some(LoopEvent::Message(text)) => {
                            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                                if v["type"].as_str() == Some("resume") {
                                    let idx = v["chunkIndex"].as_i64().unwrap_or(-1);
                                    return if idx < 0 { 0 } else { (idx as usize) + 1 };
                                }
                            }
                        }
                        Some(LoopEvent::Error(e)) => {
                            eprintln!("\x1b[1;33m⚠\x1b[0m Resume wait error: {e}");
                            return 0;
                        }
                        Some(LoopEvent::Done) | None => return 0,
                        _ => {}
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return 0;
                }
            }
        }
    }

    /// Send transfer starting from a specific chunk index (for resume support).
    pub async fn send_transfer_from(
        &self,
        encrypted_payload: &str,
        content_type: &str,
        encryption_metadata: &EncryptionMetadata,
        file_metadata: Option<&Value>,
        content_checksum: &str,
        start_chunk: usize,
        on_progress: &dyn Fn(usize, usize),
    ) -> Result<()> {
        let total = encrypted_payload.len();
        self.send_frame(
            json!({
                "type": "metadata",
                "contentType": content_type,
                "encryptionMetadata": serde_json::to_value(encryption_metadata)?,
                "fileMetadata": file_metadata,
                "contentChecksum": content_checksum,
                "totalSize": total,
                "resumeFromChunk": start_chunk,
            })
            .to_string(),
        ).await?;

        let chunks: Vec<&[u8]> = encrypted_payload.as_bytes().chunks(CHUNK_SIZE).collect();
        let mut sent = start_chunk * CHUNK_SIZE;
        on_progress(sent.min(total), total);

        for chunk in chunks.iter().skip(start_chunk) {
            let data = std::str::from_utf8(chunk).unwrap_or_default();
            self.send_frame(json!({ "type": "chunk", "data": data }).to_string()).await?;
            sent += chunk.len();
            on_progress(sent.min(total), total);
        }

        self.send_frame(json!({ "type": "end" }).to_string()).await?;
        Ok(())
    }

    pub fn close(&self) {
        let _ = self.cmd_tx.try_send(LoopCmd::Close);
    }

    /// Send Close and wait for the event loop to finish flushing all queued data.
    pub async fn close_and_flush(&self) {
        // Use .send() to ensure Close reaches the event loop even when channel is full
        let _ = self.cmd_tx.send(LoopCmd::Close).await;
    }

    pub async fn wait_closed(self) {
        let _ = self.loop_handle.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_sender_peer() -> (
        SenderPeer,
        mpsc::Receiver<LoopCmd>,
        mpsc::UnboundedSender<LoopEvent>,
    ) {
        let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let loop_handle = tokio::spawn(async {});
        let peer = SenderPeer {
            cmd_tx,
            event_rx,
            offer_sdp: String::new(),
            loop_handle,
        };
        (peer, cmd_rx, event_tx)
    }

    fn test_enc_meta() -> EncryptionMetadata {
        EncryptionMetadata {
            algorithm: "aes-256-gcm".to_string(),
            kdf: "pbkdf2".to_string(),
            iterations: 100_000,
            salt: "salt".to_string(),
            iv: "iv".to_string(),
        }
    }

    #[tokio::test]
    async fn send_transfer_from_metadata_includes_resume_from_chunk() {
        let (peer, mut cmd_rx, _event_tx) = mock_sender_peer();
        let enc_meta = test_enc_meta();
        peer.send_transfer_from("hello", "text", &enc_meta, None, "checksum", 5, &|_, _| {})
            .await
            .unwrap();

        if let Some(LoopCmd::SendData(frame)) = cmd_rx.recv().await {
            let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
            assert_eq!(v["type"], "metadata");
            assert_eq!(v["resumeFromChunk"], 5);
            assert_eq!(v["totalSize"], 5);
            assert_eq!(v["contentType"], "text");
        } else {
            panic!("expected SendData command");
        }
    }

    #[tokio::test]
    async fn send_transfer_from_with_start_0_has_resume_from_chunk_0() {
        let (peer, mut cmd_rx, _event_tx) = mock_sender_peer();
        let enc_meta = test_enc_meta();
        peer.send_transfer_from("ab", "text", &enc_meta, None, "c", 0, &|_, _| {})
            .await
            .unwrap();

        if let Some(LoopCmd::SendData(frame)) = cmd_rx.recv().await {
            let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
            assert_eq!(v["resumeFromChunk"], 0);
        } else {
            panic!("expected SendData command");
        }
    }

    #[tokio::test]
    async fn wait_for_resume_returns_0_on_timeout() {
        let (cmd_tx, _cmd_rx) = mpsc::channel(CMD_CHANNEL_CAPACITY);
        let (_event_tx, event_rx) = mpsc::unbounded_channel::<LoopEvent>();
        let loop_handle = tokio::spawn(async {});
        let mut peer = SenderPeer {
            cmd_tx,
            event_rx,
            offer_sdp: String::new(),
            loop_handle,
        };
        let start = std::time::Instant::now();
        let result = peer.wait_for_resume(100).await;
        let elapsed = start.elapsed().as_millis();
        assert_eq!(result, 0);
        assert!(elapsed >= 90, "should have waited ~100ms, got {elapsed}ms");
    }

    #[tokio::test]
    async fn wait_for_resume_returns_chunk_index_plus_1() {
        let (cmd_tx, _cmd_rx) = mpsc::channel(CMD_CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let loop_handle = tokio::spawn(async {});
        let mut peer = SenderPeer {
            cmd_tx,
            event_rx,
            offer_sdp: String::new(),
            loop_handle,
        };
        event_tx
            .send(LoopEvent::Message(
                serde_json::json!({"type": "resume", "chunkIndex": 7}).to_string(),
            ))
            .unwrap();
        let result = peer.wait_for_resume(2000).await;
        assert_eq!(result, 8);
    }

    #[tokio::test]
    async fn wait_for_resume_returns_0_on_channel_close() {
        let (cmd_tx, _cmd_rx) = mpsc::channel(CMD_CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let loop_handle = tokio::spawn(async {});
        let mut peer = SenderPeer {
            cmd_tx,
            event_rx,
            offer_sdp: String::new(),
            loop_handle,
        };
        event_tx.send(LoopEvent::Done).unwrap();
        let result = peer.wait_for_resume(2000).await;
        assert_eq!(result, 0);
    }

    #[tokio::test]
    async fn close_and_flush_delivers_close_after_queued_data() {
        // Fill the channel with data, then call close_and_flush.
        // Verify Close arrives AFTER the data.
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<LoopCmd>(4); // small capacity
        let (_event_tx, event_rx) = mpsc::unbounded_channel();
        let loop_handle = tokio::spawn(async {});
        let peer = SenderPeer {
            cmd_tx,
            event_rx,
            offer_sdp: String::new(),
            loop_handle,
        };

        // Fill channel to capacity
        for i in 0..4 {
            peer.send_frame(format!("frame-{i}")).await.unwrap();
        }

        // close_and_flush must wait for space (channel full) and then deliver Close
        let flush_handle = tokio::spawn(async move {
            peer.close_and_flush().await;
        });

        // Drain data frames
        let mut frames = Vec::new();
        for _ in 0..4 {
            if let Some(LoopCmd::SendData(f)) = cmd_rx.recv().await {
                frames.push(f);
            }
        }

        // Now Close should arrive
        flush_handle.await.unwrap();
        let close_cmd = cmd_rx.recv().await;
        assert!(matches!(close_cmd, Some(LoopCmd::Close)));
        assert_eq!(frames, vec!["frame-0", "frame-1", "frame-2", "frame-3"]);
    }
}
