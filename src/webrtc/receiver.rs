use anyhow::Result;
use serde_json::{json, Value};
use str0m::change::SdpOffer;
use tokio::sync::mpsc;

use crate::api::IceServer as ApiIceServer;

use super::event_loop::{self, IceDebug};
use super::ice_log;
use super::net::bind_udp;
use super::{build_rtc, setup_turn, LoopCmd, LoopEvent};

pub struct ReceiverPeer {
    cmd_tx: mpsc::Sender<LoopCmd>,
    event_rx: mpsc::UnboundedReceiver<LoopEvent>,
    answer_sdp: String,
}

impl ReceiverPeer {
    pub async fn from_offer(
        offer_payload: Value,
        ice_servers: Vec<ApiIceServer>,
        bind_ip: Option<std::net::IpAddr>,
    ) -> Result<Self> {
        Self::from_offer_inner(offer_payload, ice_servers, bind_ip, false).await
    }

    /// Accept an offer in relay-only mode (only relay candidate, no host/srflx).
    pub async fn from_offer_relay_only(
        offer_payload: Value,
        ice_servers: Vec<ApiIceServer>,
        bind_ip: Option<std::net::IpAddr>,
    ) -> Result<Self> {
        Self::from_offer_inner(offer_payload, ice_servers, bind_ip, true).await
    }

    async fn from_offer_inner(
        offer_payload: Value,
        ice_servers: Vec<ApiIceServer>,
        bind_ip: Option<std::net::IpAddr>,
        relay_only: bool,
    ) -> Result<Self> {
        let (socket, local_addr) = bind_udp(bind_ip).await?;
        let (mut rtc, mut gathered) = if relay_only {
            super::build_rtc_relay_only(local_addr)?
        } else {
            build_rtc(local_addr)?
        };

        // Attempt TURN allocation (no-op if no TURN server configured)
        let turn_relay =
            setup_turn(&socket, local_addr, &ice_servers, &mut rtc, &mut gathered).await;

        // Gathering is finished here — the CLI does not trickle, so whatever is
        // in `gathered` now is everything the sender will ever hear about.
        ice_log::log_gathered(&gathered);

        let offer_sdp_str = offer_payload["sdp"]["sdp"]
            .as_str()
            .or_else(|| offer_payload["sdp"].as_str())
            .ok_or_else(|| anyhow::anyhow!("missing sdp in offer"))?;

        // The sender's candidates ride in the offer (no trickle) — record them so
        // the selected-pair line can name the remote candidate's type.
        let remote_candidates = ice_log::parse_sdp_candidates(offer_sdp_str);
        crate::commands::log::event(&format!(
            "ICE remote candidates in offer: {}",
            remote_candidates.len()
        ));

        let offer = SdpOffer::from_sdp_string(offer_sdp_str)
            .map_err(|e| anyhow::anyhow!("invalid SDP offer: {e}"))?;
        let answer = rtc
            .sdp_api()
            .accept_offer(offer)
            .map_err(|e| anyhow::anyhow!("failed to accept offer: {e}"))?;
        let answer_sdp = answer.to_sdp_string();

        // What actually rides back to the sender inside the answer.
        ice_log::log_sent_in_sdp(&answer_sdp, "answer");

        let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            event_loop::run(
                rtc,
                socket,
                local_addr,
                &mut cmd_rx,
                &event_tx,
                None,
                None,
                turn_relay,
                IceDebug::new(gathered, remote_candidates),
            )
            .await;
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

    /// Send a text frame back to the sender (the sync handshake's `syncMeta`).
    pub async fn send_frame(&self, frame: String) -> Result<()> {
        self.cmd_tx
            .send(LoopCmd::SendData(frame))
            .await
            .map_err(|_| anyhow::anyhow!("event loop closed"))
    }

    /// Send a binary frame back to the sender over the same DataChannel.
    ///
    /// The v2 single-payload flow is one-directional (its ACKs ride the
    /// signaling channel), but the direct multi-file transfer (task 058) needs a
    /// real answer channel — manifest acks, per-file ok/fail. The event loop
    /// captures the incoming channel's id on `ChannelOpen`, so writing back needs
    /// no extra setup.
    pub async fn send_binary(&self, data: Vec<u8>) -> Result<()> {
        self.cmd_tx
            .send(LoopCmd::SendBinary(data))
            .await
            .map_err(|_| anyhow::anyhow!("event loop closed"))
    }

    pub fn close(&self) {
        let _ = self.cmd_tx.try_send(LoopCmd::Close);
    }

    /// Close and wait for the event loop to drain (mirrors `SenderPeer`), so the
    /// last frames we wrote actually reach the wire before the process exits.
    pub async fn close_and_flush(&self) {
        let _ = self.cmd_tx.send(LoopCmd::Close).await;
    }
}
