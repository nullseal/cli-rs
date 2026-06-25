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
pub mod turn;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use anyhow::Result;
use serde_json::Value;
use str0m::{Candidate, Rtc};
use tokio::net::UdpSocket;

use crate::api::IceServer as ApiIceServer;
use nullseal_turn::allocate::Credentials;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use net::discover_local_ip;
pub use receiver::ReceiverPeer;
pub use sender::SenderPeer;

// ── Shared types ──────────────────────────────────────────────────────────────

pub(crate) enum LoopCmd {
    AddIceCandidate(Value),
    ApplyAnswer(Value),
    SendData(String),
    SendBinary(Vec<u8>),
    Close,
}

pub enum LoopEvent {
    ChannelOpen,
    Message(String),
    BinaryData(Vec<u8>),
    Done,
    Error(String),
}

// ── Shared builder ────────────────────────────────────────────────────────────

/// The loopback host candidate to additionally advertise so a peer on the SAME
/// machine (a browser at 127.0.0.1, or the e2e/CI harness) can always pair.
/// Returns `None` when `local_addr` is already loopback (nothing to add).
fn loopback_candidate_addr(local_addr: SocketAddr) -> Option<SocketAddr> {
    let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
    if local_addr.ip() == lo {
        None
    } else {
        Some(SocketAddr::new(lo, local_addr.port()))
    }
}

fn build_rtc(local_addr: SocketAddr) -> Result<Rtc> {
    build_rtc_inner(local_addr, false)
}

fn build_rtc_relay_only(local_addr: SocketAddr) -> Result<Rtc> {
    build_rtc_inner(local_addr, true)
}

fn build_rtc_inner(local_addr: SocketAddr, relay_only: bool) -> Result<Rtc> {
    let mut rtc = Rtc::new(Instant::now());

    if !relay_only {
        let candidate = Candidate::host(local_addr, "udp")
            .map_err(|e| anyhow::anyhow!("failed to create host candidate: {e}"))?;
        rtc.add_local_candidate(candidate);

        if let Some(lo) = loopback_candidate_addr(local_addr) {
            if let Ok(c) = Candidate::host(lo, "udp") {
                rtc.add_local_candidate(c);
            }
        }
    }
    Ok(rtc)
}

// ── TURN relay state ──────────────────────────────────────────────────────────

/// TURN relay state passed to the event loop for encapsulation.
pub(crate) struct TurnRelay {
    /// TURN server address to send indications to.
    pub server_addr: SocketAddr,
    /// Relay address allocated by the TURN server (used to match Transmit.source).
    pub relay_addr: SocketAddr,
    /// Allocation credentials for refresh/permissions.
    pub allocation: turn::TurnAllocation,
    /// Peer IPs for which CreatePermission has been sent.
    pub permitted_ips: HashSet<IpAddr>,
}

/// Attempt TURN allocation using the first TURN server in `ice_servers`.
/// On success, injects relay + srflx candidates into `rtc` and returns TurnRelay.
/// Returns `None` if no TURN server with credentials is found.
pub(crate) async fn setup_turn(
    socket: &UdpSocket,
    local_addr: SocketAddr,
    ice_servers: &[ApiIceServer],
    rtc: &mut Rtc,
) -> Option<TurnRelay> {
    // Find first TURN server with credentials
    let (turn_uri, username, credential) = ice_servers.iter().find_map(|s| {
        let username = s.username.as_deref()?;
        let credential = s.credential.as_deref()?;
        // Extract URI string from urls (can be string or array)
        let uri = s.urls.as_str().map(String::from).or_else(|| {
            s.urls.as_array()?.iter().find_map(|u| {
                let u = u.as_str()?;
                if u.starts_with("turn:") || u.starts_with("turns:") {
                    Some(u.to_string())
                } else {
                    None
                }
            })
        })?;
        if uri.starts_with("turn:") || uri.starts_with("turns:") {
            Some((uri, username.to_string(), credential.to_string()))
        } else {
            None
        }
    })?;

    let server_addr = turn::parse_turn_uri(&turn_uri).ok()?;
    let creds = Credentials {
        username: username.clone(),
        password: credential,
    };

    let alloc = turn::allocate(socket, server_addr, creds).await.ok()?;

    // Inject relay candidate
    if let Ok(c) = Candidate::relayed(alloc.relayed, local_addr, "udp") {
        rtc.add_local_candidate(c);
    }
    // Inject server-reflexive candidate
    if let Ok(c) = Candidate::server_reflexive(alloc.srflx, local_addr, "udp") {
        rtc.add_local_candidate(c);
    }

    Some(TurnRelay {
        server_addr,
        relay_addr: alloc.relayed,
        allocation: alloc,
        permitted_ips: HashSet::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_candidate_added_for_lan_addr() {
        let lan: SocketAddr = "192.168.1.50:54321".parse().unwrap();
        assert_eq!(
            loopback_candidate_addr(lan),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 54321)),
            "a LAN host candidate must be paired with a loopback candidate for same-machine peers",
        );
    }

    #[test]
    fn no_extra_loopback_when_already_loopback() {
        let lo: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        assert_eq!(loopback_candidate_addr(lo), None);
    }

    #[test]
    fn build_rtc_succeeds_for_lan_and_loopback() {
        assert!(build_rtc("192.168.1.50:54321".parse().unwrap()).is_ok());
        assert!(build_rtc("127.0.0.1:40000".parse().unwrap()).is_ok());
    }
}
