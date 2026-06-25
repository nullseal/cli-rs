use anyhow::Result;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::api::IceServer as ApiIceServer;

use super::event_loop;
use super::net::bind_udp;
use super::{build_rtc, setup_turn, LoopCmd, LoopEvent};

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
        ice_servers: Vec<ApiIceServer>,
        bind_ip: Option<std::net::IpAddr>,
    ) -> Result<Self> {
        Self::new_inner(ice_servers, bind_ip, false).await
    }

    /// Create a sender peer in relay-only mode (only relay candidate, no host/srflx).
    pub async fn new_relay_only(
        ice_servers: Vec<ApiIceServer>,
        bind_ip: Option<std::net::IpAddr>,
    ) -> Result<Self> {
        Self::new_inner(ice_servers, bind_ip, true).await
    }

    async fn new_inner(
        ice_servers: Vec<ApiIceServer>,
        bind_ip: Option<std::net::IpAddr>,
        relay_only: bool,
    ) -> Result<Self> {
        let (socket, local_addr) = bind_udp(bind_ip).await?;
        let mut rtc = if relay_only {
            super::build_rtc_relay_only(local_addr)?
        } else {
            build_rtc(local_addr)?
        };

        // Attempt TURN allocation (no-op if no TURN server configured)
        let turn_relay = setup_turn(&socket, local_addr, &ice_servers, &mut rtc).await;

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
                turn_relay,
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

    pub async fn send_binary(&self, data: Vec<u8>) -> Result<()> {
        self.cmd_tx
            .send(LoopCmd::SendBinary(data))
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

    #[tokio::test]
    async fn close_and_flush_delivers_close_after_queued_data() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<LoopCmd>(4);
        let (_event_tx, event_rx) = mpsc::unbounded_channel();
        let loop_handle = tokio::spawn(async {});
        let peer = SenderPeer {
            cmd_tx,
            event_rx,
            offer_sdp: String::new(),
            loop_handle,
        };

        for i in 0..4 {
            peer.send_frame(format!("frame-{i}")).await.unwrap();
        }

        let flush_handle = tokio::spawn(async move {
            peer.close_and_flush().await;
        });

        let mut frames = Vec::new();
        for _ in 0..4 {
            if let Some(LoopCmd::SendData(f)) = cmd_rx.recv().await {
                frames.push(f);
            }
        }

        flush_handle.await.unwrap();
        let close_cmd = cmd_rx.recv().await;
        assert!(matches!(close_cmd, Some(LoopCmd::Close)));
        assert_eq!(frames, vec!["frame-0", "frame-1", "frame-2", "frame-3"]);
    }
}
