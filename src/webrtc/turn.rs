//! Async TURN client — drives the pure `nullseal-turn` AllocateMachine over UDP.
//!
//! This module owns only the socket I/O + timers. All message encoding/decoding
//! and state transitions live in the `nullseal-turn` crate (task 007).

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use nullseal_turn::allocate::{
    Action, AllocateMachine, Credentials,
    build_create_permission, build_refresh, new_txn_id,
};

/// Result of a successful TURN allocation.
#[derive(Debug, Clone)]
pub struct TurnAllocation {
    /// The relay address allocated by the TURN server.
    pub relayed: SocketAddr,
    /// Server-reflexive address (our public IP as seen by the TURN server).
    pub srflx: SocketAddr,
    /// Lifetime in seconds.
    pub lifetime: u32,
    /// Credentials used (needed for refresh/permission).
    pub username: String,
    pub realm: String,
    pub nonce: String,
    /// The long-term credential key (MD5).
    pub key: [u8; 16],
}

/// UDP recv timeout for TURN messages.
const RECV_TIMEOUT: Duration = Duration::from_secs(3);
/// Max retransmissions for the initial unauthenticated Allocate (UDP loss).
const MAX_RETRANSMITS: u8 = 3;

/// Perform a TURN allocation against the given server.
///
/// Drives the pure `AllocateMachine` from `nullseal-turn` over the provided UDP socket.
/// Captures realm/nonce from the 401 challenge for use in refresh/permission calls.
/// Returns the allocation details on success.
pub async fn allocate(
    socket: &UdpSocket,
    server: SocketAddr,
    creds: Credentials,
) -> Result<TurnAllocation> {
    let txn_id = new_txn_id();
    let (mut machine, initial_msg) = AllocateMachine::start(creds.clone(), txn_id);

    socket.send_to(&initial_msg, server).await?;

    let mut buf = [0u8; 2048];
    let mut retransmits = 0u8;
    // Track realm/nonce from the 401 challenge
    let mut captured_realm = String::new();
    let mut captured_nonce = String::new();

    loop {
        let recv_result = timeout(RECV_TIMEOUT, socket.recv_from(&mut buf)).await;

        match recv_result {
            Ok(Ok((len, _src))) => {
                // Sniff realm/nonce from 401 responses before passing to machine
                if let Some(parsed) = nullseal_turn::message::decode(&buf[..len]) {
                    for attr in &parsed.attrs {
                        match attr {
                            nullseal_turn::attr::Attribute::Realm(r) => {
                                captured_realm = r.clone();
                            }
                            nullseal_turn::attr::Attribute::Nonce(n) => {
                                captured_nonce = n.clone();
                            }
                            _ => {}
                        }
                    }
                }

                let actions = machine.handle(&buf[..len]);
                for action in actions {
                    match action {
                        Action::SendDatagram(data) => {
                            socket.send_to(&data, server).await?;
                        }
                        Action::Allocated(alloc) => {
                            let key = nullseal_turn::auth::long_term_key(
                                &creds.username, &captured_realm, &creds.password,
                            );
                            return Ok(TurnAllocation {
                                relayed: alloc.relayed,
                                srflx: alloc.srflx,
                                lifetime: alloc.lifetime,
                                username: creds.username.clone(),
                                realm: captured_realm,
                                nonce: captured_nonce,
                                key,
                            });
                        }
                        Action::Error(e) => {
                            return Err(anyhow!("TURN allocate failed: {}", e));
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                return Err(anyhow!("UDP recv error: {}", e));
            }
            Err(_timeout) => {
                retransmits += 1;
                if retransmits > MAX_RETRANSMITS {
                    return Err(anyhow!("TURN allocate timed out after {} retransmits", MAX_RETRANSMITS));
                }
                socket.send_to(&initial_msg, server).await?;
            }
        }
    }
}

/// Send a Refresh request to keep the allocation alive.
///
/// Should be called at `lifetime / 2` intervals.
#[allow(dead_code)] // blocking version; event loop uses fire-and-forget
pub async fn refresh(
    socket: &UdpSocket,
    server: SocketAddr,
    alloc: &TurnAllocation,
    lifetime: u32,
) -> Result<()> {
    let txn_id = new_txn_id();
    let msg = build_refresh(
        &txn_id,
        &alloc.username,
        &alloc.realm,
        &alloc.nonce,
        &alloc.key,
        lifetime,
    );
    socket.send_to(&msg, server).await?;

    // Wait for success response
    let mut buf = [0u8; 2048];
    let recv_result = timeout(RECV_TIMEOUT, socket.recv_from(&mut buf)).await;
    match recv_result {
        Ok(Ok((len, _))) => {
            if let Some(parsed) = nullseal_turn::message::decode(&buf[..len]) {
                if parsed.class == nullseal_turn::message::Class::Success {
                    return Ok(());
                }
                // Check for error
                for attr in &parsed.attrs {
                    if let nullseal_turn::attr::Attribute::ErrorCode { code, reason } = attr {
                        return Err(anyhow!("TURN refresh error {}: {}", code, reason));
                    }
                }
            }
            Err(anyhow!("TURN refresh: unexpected response"))
        }
        Ok(Err(e)) => Err(anyhow!("UDP recv error during refresh: {}", e)),
        Err(_) => Err(anyhow!("TURN refresh timed out")),
    }
}

/// Send a CreatePermission request for the given peer address.
#[allow(dead_code)] // blocking version; event loop uses fire-and-forget
pub async fn create_permission(
    socket: &UdpSocket,
    server: SocketAddr,
    alloc: &TurnAllocation,
    peer: &SocketAddr,
) -> Result<()> {
    let txn_id = new_txn_id();
    let msg = build_create_permission(
        &txn_id,
        &alloc.username,
        &alloc.realm,
        &alloc.nonce,
        &alloc.key,
        peer,
    );
    socket.send_to(&msg, server).await?;

    // Wait for success response
    let mut buf = [0u8; 2048];
    let recv_result = timeout(RECV_TIMEOUT, socket.recv_from(&mut buf)).await;
    match recv_result {
        Ok(Ok((len, _))) => {
            if let Some(parsed) = nullseal_turn::message::decode(&buf[..len]) {
                if parsed.class == nullseal_turn::message::Class::Success {
                    return Ok(());
                }
                for attr in &parsed.attrs {
                    if let nullseal_turn::attr::Attribute::ErrorCode { code, reason } = attr {
                        return Err(anyhow!("TURN CreatePermission error {}: {}", code, reason));
                    }
                }
            }
            Err(anyhow!("TURN CreatePermission: unexpected response"))
        }
        Ok(Err(e)) => Err(anyhow!("UDP recv error during CreatePermission: {}", e)),
        Err(_) => Err(anyhow!("TURN CreatePermission timed out")),
    }
}

/// Parse a TURN URI (e.g. "turn:host:port") into a SocketAddr.
pub fn parse_turn_uri(uri: &str) -> Result<SocketAddr> {
    let stripped = uri
        .strip_prefix("turn:")
        .or_else(|| uri.strip_prefix("turns:"))
        .unwrap_or(uri);
    // Handle "host:port" or "host:port?transport=udp"
    let addr_part = stripped.split('?').next().unwrap_or(stripped);
    addr_part
        .parse::<SocketAddr>()
        .or_else(|_| {
            // Try resolving as hostname:port
            use std::net::ToSocketAddrs;
            addr_part
                .to_socket_addrs()
                .map_err(|e| anyhow!("failed to resolve TURN URI '{}': {}", uri, e))?
                .next()
                .ok_or_else(|| anyhow!("no addresses resolved for TURN URI '{}'", uri))
        })
}

// ── Integration test (gated with #[ignore]) ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_turn_uri_ip_port() {
        let addr = parse_turn_uri("turn:127.0.0.1:3478").unwrap();
        assert_eq!(addr, "127.0.0.1:3478".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_turn_uri_bare_ip_port() {
        let addr = parse_turn_uri("127.0.0.1:3478").unwrap();
        assert_eq!(addr, "127.0.0.1:3478".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_turn_uri_with_query() {
        let addr = parse_turn_uri("turn:127.0.0.1:3478?transport=udp").unwrap();
        assert_eq!(addr, "127.0.0.1:3478".parse::<SocketAddr>().unwrap());
    }

    /// Integration test against a running coturn server.
    ///
    /// **Prerequisites:**
    /// 1. Start coturn with TURN enabled (not stun-only):
    ///    ```
    ///    docker compose -f docker-compose.coturn.yml up -d
    ///    ```
    ///    The compose file must be configured with `--lt-cred-mech` and a test user.
    ///    See `docs/guides/setup.md` for the required coturn configuration.
    ///
    /// 2. Run this test:
    ///    ```
    ///    cargo test -p nullseal turn_integration -- --ignored
    ///    ```
    #[tokio::test]
    #[ignore]
    async fn turn_integration_allocate_and_permission() {
        // These match the coturn config in docker-compose.coturn.yml
        let server: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let creds = Credentials {
            username: "nullseal".to_string(),
            password: "nullseal-turn-test".to_string(),
        };

        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let alloc = allocate(&socket, server, creds).await.unwrap();

        println!("=== TURN Allocation Succeeded ===");
        println!("  Relayed address: {}", alloc.relayed);
        println!("  Server-reflexive: {}", alloc.srflx);
        println!("  Lifetime: {}s", alloc.lifetime);
        println!("  Realm: {}", alloc.realm);
        println!("  Nonce: {}", alloc.nonce);

        assert_ne!(alloc.relayed.port(), 0);
        assert_ne!(alloc.srflx.port(), 0);
        assert!(alloc.lifetime > 0);

        // Test CreatePermission for an arbitrary peer
        let peer: SocketAddr = "10.0.0.1:9999".parse().unwrap();
        create_permission(&socket, server, &alloc, &peer).await.unwrap();
        println!("  CreatePermission for {} succeeded", peer);

        // Test Refresh
        refresh(&socket, server, &alloc, alloc.lifetime).await.unwrap();
        println!("  Refresh succeeded");
        println!("=== All TURN operations verified ===");
    }
}
