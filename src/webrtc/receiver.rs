use anyhow::Result;
use serde_json::{json, Value};
use str0m::change::SdpOffer;
use tokio::sync::mpsc;

use crate::api::IceServer as ApiIceServer;

use super::event_loop;
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
        let mut rtc = if relay_only {
            super::build_rtc_relay_only(local_addr)?
        } else {
            build_rtc(local_addr)?
        };

        // Attempt TURN allocation (no-op if no TURN server configured)
        let turn_relay = setup_turn(&socket, local_addr, &ice_servers, &mut rtc).await;

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
            event_loop::run(rtc, socket, local_addr, &mut cmd_rx, &event_tx, None, None, turn_relay).await;
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

    pub fn close(&self) {
        let _ = self.cmd_tx.try_send(LoopCmd::Close);
    }
}
