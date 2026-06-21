use anyhow::{bail, Result};
use serde_json::{json, Value};
use str0m::change::SdpOffer;
use tokio::sync::mpsc;

use crate::api::IceServer as ApiIceServer;
use crate::crypto::EncryptionMetadata;

use super::event_loop;
use super::net::bind_udp;
use super::{build_rtc, LoopCmd, LoopEvent, ReceivedTransfer};

pub struct ReceiverPeer {
    cmd_tx: mpsc::Sender<LoopCmd>,
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

        let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            event_loop::run(rtc, socket, local_addr, &mut cmd_rx, &event_tx, None, None).await;
        });

        Ok(ReceiverPeer {
            cmd_tx,
            event_rx,
            answer_sdp,
        })
    }

    pub fn answer_sdp_json(&self) -> Value {
        json!({ "type": "answer", "sdp": self.answer_sdp })
    }

    pub fn add_ice_candidate(&self, payload: Value) -> Result<()> {
        self.cmd_tx
            .try_send(LoopCmd::AddIceCandidate(payload))
            .map_err(|_| anyhow::anyhow!("event loop closed"))
    }

    pub async fn next_event(&mut self) -> Option<LoopEvent> {
        self.event_rx.recv().await
    }

    /// Send resume frame to sender indicating last received chunk index.
    /// Sends multiple times for reliability (sender only uses the first one).
    pub fn send_resume(&self, last_chunk_index: i64) -> Result<()> {
        let frame = json!({ "type": "resume", "chunkIndex": last_chunk_index }).to_string();
        // Send 3 times — redundancy guards against the sender's 2-5s timeout
        // expiring before the first frame arrives (e.g. TURN relay latency).
        for _ in 0..3 {
            self.cmd_tx
                .try_send(LoopCmd::SendData(frame.clone()))
                .map_err(|_| anyhow::anyhow!("event loop closed"))?;
        }
        Ok(())
    }

    pub async fn receive_transfer(
        &mut self,
        expected_proof: &str,
        on_progress: &dyn Fn(usize, usize),
        external_chunks: &mut Vec<String>,
        resume_from_chunk_out: &mut usize,
    ) -> Result<ReceivedTransfer> {
        let mut content_type = String::new();
        let mut enc_meta: Option<EncryptionMetadata> = None;
        let mut file_meta: Option<Value> = None;
        let mut content_checksum: Option<String> = None;
        let mut total_size: usize = 0;
        let mut received: usize = 0;
        let mut _verified = false;

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
                            _verified = true;
                        }
                        Some("metadata") => {
                            content_type =
                                v["contentType"].as_str().unwrap_or("text").to_owned();
                            enc_meta =
                                serde_json::from_value(v["encryptionMetadata"].clone()).ok();
                            file_meta = if v["fileMetadata"].is_null() {
                                None
                            } else {
                                Some(v["fileMetadata"].clone())
                            };
                            content_checksum =
                                v["contentChecksum"].as_str().map(|s| s.to_owned());
                            total_size = v["totalSize"].as_u64().unwrap_or(0) as usize;
                            *resume_from_chunk_out =
                                v["resumeFromChunk"].as_u64().unwrap_or(0) as usize;
                        }
                        Some("chunk") => {
                            if let Some(data) = v["data"].as_str() {
                                received += data.len();
                                external_chunks.push(data.to_owned());
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
            encrypted_payload: external_chunks.concat(),
            content_checksum,
        })
    }

    pub fn close(&self) {
        let _ = self.cmd_tx.try_send(LoopCmd::Close);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn send_resume_sends_three_redundant_frames() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
        let (_event_tx, event_rx) = mpsc::unbounded_channel();
        let peer = ReceiverPeer {
            cmd_tx,
            event_rx,
            answer_sdp: String::new(),
        };

        peer.send_resume(5).unwrap();

        // Should receive exactly 3 SendData commands
        let mut count = 0;
        while let Ok(cmd) = cmd_rx.try_recv() {
            if let LoopCmd::SendData(frame) = cmd {
                let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
                assert_eq!(v["type"], "resume");
                assert_eq!(v["chunkIndex"], 5);
                count += 1;
            }
        }
        assert_eq!(count, 3, "send_resume must send 3 redundant frames");
    }

    #[tokio::test]
    async fn send_resume_negative_one_sends_minus_one() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
        let (_event_tx, event_rx) = mpsc::unbounded_channel();
        let peer = ReceiverPeer {
            cmd_tx,
            event_rx,
            answer_sdp: String::new(),
        };

        peer.send_resume(-1).unwrap();

        if let Ok(LoopCmd::SendData(frame)) = cmd_rx.try_recv() {
            let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
            assert_eq!(v["chunkIndex"], -1);
        } else {
            panic!("expected SendData");
        }
    }

    #[tokio::test]
    async fn receive_transfer_extracts_resume_from_chunk() {
        let (cmd_tx, _cmd_rx) = mpsc::channel(256);
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let mut peer = ReceiverPeer {
            cmd_tx,
            event_rx,
            answer_sdp: String::new(),
        };

        // Simulate sender sending verify, metadata with resumeFromChunk=3, one chunk, end
        event_tx.send(LoopEvent::Message(
            serde_json::json!({"type": "verify", "proof": "abc"}).to_string()
        )).unwrap();
        event_tx.send(LoopEvent::Message(
            serde_json::json!({
                "type": "metadata",
                "contentType": "text",
                "encryptionMetadata": {
                    "algorithm": "aes-256-gcm",
                    "kdf": "pbkdf2",
                    "iterations": 100000,
                    "salt": "s",
                    "iv": "i"
                },
                "fileMetadata": null,
                "contentChecksum": "check",
                "totalSize": 100,
                "resumeFromChunk": 3
            }).to_string()
        )).unwrap();
        event_tx.send(LoopEvent::Message(
            serde_json::json!({"type": "chunk", "data": "hello"}).to_string()
        )).unwrap();
        event_tx.send(LoopEvent::Message(
            serde_json::json!({"type": "end"}).to_string()
        )).unwrap();

        let mut chunks = Vec::new();
        let mut resume_from: usize = 0;
        let result = peer.receive_transfer("abc", &|_, _| {}, &mut chunks, &mut resume_from).await.unwrap();

        assert_eq!(resume_from, 3, "must extract resumeFromChunk from metadata");
        assert_eq!(result.content_type, "text");
        assert_eq!(chunks, vec!["hello".to_string()]);
    }
}
