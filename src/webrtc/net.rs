use std::net::SocketAddr;

use anyhow::Result;
use tokio::net::UdpSocket;

/// Discover the best local IP for WebRTC/LAN communication.
/// Prefers real LAN IPs over Tailscale/CGNAT IPs.
pub fn discover_local_ip() -> std::net::IpAddr {
    if let Some(lan_ip) = discover_lan_ip() {
        return lan_ip;
    }

    // Fallback: probe via UDP connect to find any outbound IP
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

/// Discover a LAN-suitable IP by enumerating network interfaces.
/// Skips loopback, Tailscale (100.64.0.0/10), link-local, and other non-LAN IPs.
fn discover_lan_ip() -> Option<std::net::IpAddr> {
    let output = std::process::Command::new("ifconfig")
        .output()
        .or_else(|_| std::process::Command::new("ip").args(["addr", "show"]).output())
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            let ip_str = rest
                .split(|c: char| c.is_whitespace() || c == '/')
                .next()
                .unwrap_or("");
            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                if is_private_lan_ip(&std::net::IpAddr::V4(ip)) {
                    return Some(std::net::IpAddr::V4(ip));
                }
            }
        }
    }
    None
}

/// Check if an IP is a standard private/LAN address (not Tailscale/CGNAT).
fn is_private_lan_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            // 10.0.0.0/8
            if o[0] == 10 {
                return true;
            }
            // 172.16.0.0/12
            if o[0] == 172 && (o[1] & 0xF0) == 16 {
                return true;
            }
            // 192.168.0.0/16
            if o[0] == 192 && o[1] == 168 {
                return true;
            }
            false
        }
        _ => false,
    }
}

/// Extract the host part of `host`, `host:port` or `[v6]:port` as an IP address.
/// Returns `None` when the host is a name (e.g. `localhost`) rather than a literal.
fn parse_host_ip(addr: &str) -> Option<std::net::IpAddr> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
        return Some(ip);
    }
    addr.split(':').next()?.parse().ok()
}

/// Choose the IP the **receiver** advertises in its ICE host candidate.
///
/// `sender_addr` is the *sender's* `host[:port]` (from `-a`, or from mDNS
/// discovery) — the address of the *other* machine. It must never be reused as
/// our own bind/advertise address: doing so makes the sender aim its
/// connectivity checks at its own IP and learn ours only peer-reflexively
/// (`remote unknown` in the selected pair).
///
/// - Loopback sender (`127.0.0.1`, `::1`): both ends are on this machine, so
///   keep loopback. This is the same-host path the whole e2e suite exercises.
/// - Anything else (LAN IP, or a name we cannot resolve to a literal): use
///   *this* machine's own LAN IP via [`discover_local_ip`].
pub fn receiver_bind_ip(sender_addr: &str) -> Option<std::net::IpAddr> {
    receiver_bind_ip_with(sender_addr, discover_local_ip)
}

/// Testable core of [`receiver_bind_ip`] — `own_ip` stands in for this machine's
/// address so the two-machine case can be pinned without a second machine.
fn receiver_bind_ip_with(
    sender_addr: &str,
    own_ip: impl FnOnce() -> std::net::IpAddr,
) -> Option<std::net::IpAddr> {
    match parse_host_ip(sender_addr) {
        Some(ip) if ip.is_loopback() => Some(ip),
        _ => Some(own_ip()),
    }
}

pub async fn bind_udp(bind_ip: Option<std::net::IpAddr>) -> Result<(UdpSocket, SocketAddr)> {
    let ip = bind_ip.unwrap_or_else(discover_local_ip);
    // Always bind to 0.0.0.0 so the socket can receive from any interface.
    // Use the specified/discovered IP only for the ICE candidate address.
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let port = socket.local_addr()?.port();
    let effective_addr = SocketAddr::new(ip, port);
    Ok((socket, effective_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn private_10_x_is_lan() {
        assert!(is_private_lan_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_lan_ip(&IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
    }

    #[test]
    fn private_172_16_is_lan() {
        assert!(is_private_lan_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_lan_ip(&IpAddr::V4(Ipv4Addr::new(172, 31, 255, 254))));
    }

    #[test]
    fn private_172_32_is_not_lan() {
        assert!(!is_private_lan_ip(&IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))));
    }

    #[test]
    fn private_192_168_is_lan() {
        assert!(is_private_lan_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(is_private_lan_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 255, 254))));
    }

    #[test]
    fn tailscale_cgnat_is_not_lan() {
        assert!(!is_private_lan_ip(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!is_private_lan_ip(&IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))));
    }

    #[test]
    fn public_ip_is_not_lan() {
        assert!(!is_private_lan_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_lan_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn loopback_is_not_lan() {
        assert!(!is_private_lan_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn ipv6_is_not_lan() {
        assert!(!is_private_lan_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn discover_local_ip_returns_valid_ip() {
        let ip = discover_local_ip();
        assert!(!ip.is_unspecified());
    }

    // ── receiver_bind_ip ─────────────────────────────────────────────────────
    // The receiver must advertise ITS OWN address, never the sender's. On one
    // machine the two coincide, which is why this went unnoticed; `own_ip` here
    // is a distinct host so the difference is observable.
    const OWN: fn() -> IpAddr = || IpAddr::V4(Ipv4Addr::new(192, 168, 0, 235));

    #[test]
    fn remote_sender_yields_our_own_ip_not_the_senders() {
        // Field repro: sender 192.168.0.128, receiver 192.168.0.235.
        let chosen = receiver_bind_ip_with("192.168.0.128:56270", OWN);
        assert_eq!(
            chosen,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 235))),
            "receiver must advertise its own LAN IP, not the sender's",
        );
        assert_ne!(chosen, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 128))));
    }

    #[test]
    fn remote_sender_without_port_still_yields_our_own_ip() {
        assert_eq!(
            receiver_bind_ip_with("10.0.0.7", OWN),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 235))),
        );
    }

    #[test]
    fn loopback_sender_keeps_loopback() {
        // Same-machine runs (and the entire e2e suite) pass `-a 127.0.0.1`.
        // Switching these to the LAN IP would change same-host behavior.
        assert_eq!(
            receiver_bind_ip_with("127.0.0.1:8080", OWN),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        );
        assert_eq!(
            receiver_bind_ip_with("127.0.0.1", OWN),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        );
        assert_eq!(
            receiver_bind_ip_with("[::1]:8080", OWN),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        );
    }

    #[test]
    fn hostname_sender_falls_back_to_our_own_ip() {
        // Unchanged from the previous behavior: an unparseable host meant
        // `None`, which `bind_udp` resolved via `discover_local_ip()`.
        assert_eq!(
            receiver_bind_ip_with("some-host.local:8080", OWN),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 235))),
        );
    }

    #[test]
    fn parse_host_ip_handles_the_forms_we_accept() {
        assert_eq!(
            parse_host_ip("192.168.0.128:56270"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 128))),
        );
        assert_eq!(
            parse_host_ip("192.168.0.128"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 128))),
        );
        assert_eq!(parse_host_ip("[::1]:9"), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(parse_host_ip("::1"), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(parse_host_ip("localhost:8080"), None);
    }

    #[test]
    fn receiver_bind_ip_uses_real_discovery_for_a_remote_sender() {
        // The public wrapper must resolve to a usable local address, never the
        // sender's.
        let chosen = receiver_bind_ip("192.168.0.128:56270").unwrap();
        assert!(!chosen.is_unspecified());
        assert_eq!(chosen, discover_local_ip());
    }

    #[tokio::test]
    async fn bind_udp_with_none_succeeds() {
        let (socket, addr) = bind_udp(None).await.unwrap();
        assert!(addr.port() > 0);
        drop(socket);
    }

    #[tokio::test]
    async fn bind_udp_with_explicit_ip_uses_that_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let (_socket, addr) = bind_udp(Some(ip)).await.unwrap();
        assert_eq!(addr.ip(), ip);
        assert!(addr.port() > 0);
    }
}
