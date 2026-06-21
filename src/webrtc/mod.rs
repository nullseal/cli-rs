// Phase 7: str0m-based WebRTC DataChannel abstraction
//
// str0m 0.20 with apple-crypto feature — pure Rust, sans-I/O.
//
// Architecture: str0m is sans-I/O — the caller owns the UDP socket and
// drives the state machine via rtc.poll_output() / rtc.handle_input().
// Each peer spawns a tokio task for the event loop, communicating with
// the command layer via tokio mpsc channels.
//
// Module structure:
//   net.rs        — IP discovery + UDP binding
//   event_loop.rs — sans-I/O event loop driving str0m
//   sender.rs     — SenderPeer (creates offer, sends data)
//   receiver.rs   — ReceiverPeer (accepts offer, receives data)

mod event_loop;
pub mod net;
mod receiver;
mod sender;

use std::net::SocketAddr;
use std::time::Instant;

use anyhow::Result;
use serde_json::Value;
use str0m::{Candidate, Rtc};

use crate::crypto::EncryptionMetadata;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use net::discover_local_ip;
pub use receiver::ReceiverPeer;
pub use sender::SenderPeer;

// ── Shared constants ──────────────────────────────────────────────────────────

pub(crate) const CHUNK_SIZE: usize = 16 * 1024;

// ── Shared types ──────────────────────────────────────────────────────────────

pub(crate) enum LoopCmd {
    AddIceCandidate(Value),
    ApplyAnswer(Value),
    SendData(String),
    Close,
}

pub enum LoopEvent {
    ChannelOpen,
    Message(String),
    Done,
    Error(String),
}

/// Completed transfer received over DataChannel.
pub struct ReceivedTransfer {
    pub content_type: String,
    pub encryption_metadata: EncryptionMetadata,
    pub file_metadata: Option<Value>,
    pub encrypted_payload: String,
    pub content_checksum: Option<String>,
}

// ── Shared builder ────────────────────────────────────────────────────────────

fn build_rtc(local_addr: SocketAddr) -> Result<Rtc> {
    let mut rtc = Rtc::new(Instant::now());
    let candidate = Candidate::host(local_addr, "udp")
        .map_err(|e| anyhow::anyhow!("failed to create host candidate: {e}"))?;
    rtc.add_local_candidate(candidate);
    Ok(rtc)
}
