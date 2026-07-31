//! ICE observability — verbose-only diagnostics for candidate gathering,
//! candidate exchange, and the finally selected candidate pair.
//!
//! Why this module exists: the CLI does **not** trickle ICE. Every local
//! candidate is added to the `Rtc` up-front (host + loopback in
//! [`super::build_rtc_inner`], relay + srflx in [`super::setup_turn`]) and then
//! travels to the peer inside the SDP offer/answer. That makes two failure
//! modes indistinguishable from the old logs:
//!
//! 1. **Nothing was gathered** — e.g. a local security agent prevented the UDP
//!    socket from producing a usable candidate, or relay-only mode ran without a
//!    reachable TURN server. The SDP then leaves with zero candidates and the
//!    peer has nothing to connect to.
//! 2. **Something was gathered but never reached the peer** — the SDP carried
//!    candidates but the peer never acted on them.
//!
//! The helpers here make the difference visible: what we gathered, what actually
//! rode out in the SDP, and which pair (if any) won. Everything is emitted
//! through `commands::log::event`, i.e. `--verbose` only.
//!
//! The parsing/formatting half is pure and unit-tested; only the `log_*`
//! functions touch the logger.

use std::net::SocketAddr;

use serde_json::Value;

/// One ICE candidate reduced to the three fields worth logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateInfo {
    /// `host` / `srflx` / `relay` / `prflx` (whatever the SDP `typ` said).
    pub kind: String,
    /// Transport, normally `udp`.
    pub proto: String,
    /// `ip:port` (`[ip]:port` for IPv6).
    pub addr: String,
}

impl CandidateInfo {
    /// `"host udp 192.168.1.5:52341"` — the shape used in every log line.
    pub fn describe(&self) -> String {
        format!("{} {} {}", self.kind, self.proto, self.addr)
    }
}

/// Render `ip` + `port` the way a socket address is normally written, keeping
/// IPv6 unambiguous (`[::1]:4000` rather than `::1:4000`).
fn join_addr(ip: &str, port: &str) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

/// Parse one candidate line into a [`CandidateInfo`].
///
/// Accepts both the SDP attribute form (`a=candidate:...`) and the bare form
/// used by `RTCIceCandidateInit.candidate` (`candidate:...`). The grammar is
/// `candidate:<foundation> <component> <transport> <priority> <ip> <port> typ <kind> …`
/// (RFC 5245 §15.1); anything shorter or without `typ` is not a candidate we can
/// describe, so it is skipped rather than guessed at.
pub fn parse_candidate_line(line: &str) -> Option<CandidateInfo> {
    let line = line.trim();
    let line = line.strip_prefix("a=").unwrap_or(line);
    let rest = line.strip_prefix("candidate:")?;
    let parts: Vec<&str> = rest.split_whitespace().collect();
    // foundation, component, transport, priority, ip, port, "typ", kind
    if parts.len() < 8 || parts[6] != "typ" {
        return None;
    }
    Some(CandidateInfo {
        kind: parts[7].to_string(),
        proto: parts[2].to_ascii_lowercase(),
        addr: join_addr(parts[4], parts[5]),
    })
}

/// Every candidate carried by an SDP blob, in document order.
pub fn parse_sdp_candidates(sdp: &str) -> Vec<CandidateInfo> {
    sdp.lines().filter_map(parse_candidate_line).collect()
}

/// Pull the candidate out of a signaling `p2p:ice` payload. Mirrors the shapes
/// `event_loop::json_to_ice` accepts: `{candidate: "candidate:…"}` (browser
/// `RTCIceCandidateInit`) and the doubly-nested `{candidate: {candidate: "…"}}`.
pub fn candidate_from_json(v: &Value) -> Option<CandidateInfo> {
    let s = v["candidate"]
        .as_str()
        .or_else(|| v["candidate"]["candidate"].as_str())?;
    parse_candidate_line(s)
}

/// Best-known type for `addr` among `known`, or `"unknown"` when we never saw a
/// candidate for it (e.g. a peer-reflexive address discovered on the wire).
pub fn lookup_kind(known: &[CandidateInfo], addr: SocketAddr) -> String {
    let want = addr.to_string();
    known
        .iter()
        .find(|c| c.addr == want)
        .map(|c| c.kind.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The one line that answers "which path actually won?".
pub fn format_selected_pair(
    local: &[CandidateInfo],
    remote: &[CandidateInfo],
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> String {
    format!(
        "ICE selected pair: local {} udp {} \u{2194} remote {} udp {}",
        lookup_kind(local, local_addr),
        local_addr,
        lookup_kind(remote, remote_addr),
        remote_addr,
    )
}

/// The single most valuable line for diagnosing a silent P2P hang: we gathered
/// nothing at all, so the SDP we are about to send is empty and the peer has
/// nowhere to connect. Deliberately spells out the likely cause.
pub const NO_LOCAL_CANDIDATES: &str =
    "ICE gathering finished with ZERO local candidates — no host, srflx or relay \
     address could be gathered. This connection CANNOT succeed. A local firewall \
     or endpoint-security agent is most likely blocking UDP socket binding, or no \
     usable network interface was found.";

/// Warn that the SDP we are handing to the signaling layer carries no candidates
/// (the peer will therefore never learn how to reach us).
pub fn no_candidates_in_sdp(which: &str) -> String {
    format!(
        "ICE candidates sent: NONE — the SDP {which} carries no candidate lines, \
         so the peer has no address to connect to."
    )
}

// ── Logging (verbose only) ───────────────────────────────────────────────────

/// Log every local candidate we gathered, then the total — or the loud
/// zero-candidate warning when gathering produced nothing.
pub fn log_gathered(candidates: &[CandidateInfo]) {
    for c in candidates {
        crate::commands::log::event(&format!("ICE local candidate gathered: {}", c.describe()));
    }
    if candidates.is_empty() {
        crate::commands::log::event(NO_LOCAL_CANDIDATES);
    } else {
        crate::commands::log::event(&format!(
            "ICE gathering complete: {} local candidate(s)",
            candidates.len()
        ));
    }
}

/// Log the candidates actually embedded in the SDP `offer`/`answer` we are about
/// to relay to the peer. `which` is `"offer"` or `"answer"`.
///
/// This is the outgoing mirror of the `ICE candidate received` line: because the
/// CLI does not trickle, the SDP *is* the candidate exchange.
pub fn log_sent_in_sdp(sdp: &str, which: &str) {
    let candidates = parse_sdp_candidates(sdp);
    for c in &candidates {
        crate::commands::log::event(&format!(
            "ICE candidate sent (in {which}): {}",
            c.describe()
        ));
    }
    if candidates.is_empty() {
        crate::commands::log::event(&no_candidates_in_sdp(which));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_host_candidate_line() {
        let c = parse_candidate_line(
            "a=candidate:1 1 UDP 2130706175 192.168.1.5 52341 typ host",
        )
        .expect("host candidate must parse");
        assert_eq!(c.kind, "host");
        assert_eq!(c.proto, "udp", "transport is normalized to lowercase");
        assert_eq!(c.addr, "192.168.1.5:52341");
        assert_eq!(c.describe(), "host udp 192.168.1.5:52341");
    }

    #[test]
    fn parses_bare_candidate_line_without_a_prefix() {
        let c = parse_candidate_line(
            "candidate:2 1 udp 1694498815 203.0.113.9 41200 typ srflx raddr 192.168.1.5 rport 52341",
        )
        .unwrap();
        assert_eq!(c.kind, "srflx");
        assert_eq!(c.addr, "203.0.113.9:41200");
    }

    #[test]
    fn parses_relay_candidate() {
        let c =
            parse_candidate_line("candidate:3 1 udp 41885439 198.51.100.7 3478 typ relay").unwrap();
        assert_eq!(c.describe(), "relay udp 198.51.100.7:3478");
    }

    #[test]
    fn ipv6_addresses_are_bracketed() {
        let c = parse_candidate_line("candidate:4 1 udp 2130706175 ::1 40000 typ host").unwrap();
        assert_eq!(c.addr, "[::1]:40000");
    }

    #[test]
    fn non_candidate_and_malformed_lines_are_skipped() {
        assert!(parse_candidate_line("a=ice-ufrag:abcd").is_none());
        assert!(parse_candidate_line("").is_none());
        // Truncated (no typ/kind) — we must not invent a type.
        assert!(parse_candidate_line("candidate:1 1 udp 2130706175 192.168.1.5 52341").is_none());
    }

    #[test]
    fn parses_all_candidates_from_an_sdp_blob() {
        let sdp = "v=0\r\n\
                   a=ice-ufrag:xyz\r\n\
                   a=candidate:1 1 udp 2130706175 192.168.1.5 52341 typ host\r\n\
                   a=candidate:2 1 udp 2130706175 127.0.0.1 52341 typ host\r\n\
                   a=candidate:3 1 udp 41885439 198.51.100.7 3478 typ relay\r\n\
                   a=end-of-candidates\r\n";
        let found = parse_sdp_candidates(sdp);
        assert_eq!(found.len(), 3);
        assert_eq!(
            found.iter().map(|c| c.describe()).collect::<Vec<_>>(),
            vec![
                "host udp 192.168.1.5:52341",
                "host udp 127.0.0.1:52341",
                "relay udp 198.51.100.7:3478",
            ]
        );
    }

    #[test]
    fn an_sdp_without_candidates_parses_to_nothing() {
        // The exact field-failure shape we need to be able to SEE.
        let sdp = "v=0\r\na=ice-ufrag:xyz\r\na=ice-pwd:secret\r\n";
        assert!(parse_sdp_candidates(sdp).is_empty());
    }

    #[test]
    fn candidate_from_json_handles_both_signaling_shapes() {
        let flat = serde_json::json!({
            "candidate": "candidate:1 1 udp 2130706175 192.168.1.5 52341 typ host"
        });
        let nested = serde_json::json!({
            "candidate": { "candidate": "candidate:1 1 udp 2130706175 10.0.0.4 5000 typ host" }
        });
        assert_eq!(candidate_from_json(&flat).unwrap().addr, "192.168.1.5:52341");
        assert_eq!(candidate_from_json(&nested).unwrap().addr, "10.0.0.4:5000");
        assert!(candidate_from_json(&serde_json::json!({})).is_none());
    }

    #[test]
    fn lookup_kind_finds_known_and_falls_back_to_unknown() {
        let known = vec![
            parse_candidate_line("candidate:1 1 udp 1 192.168.1.5 52341 typ host").unwrap(),
            parse_candidate_line("candidate:2 1 udp 1 198.51.100.7 3478 typ relay").unwrap(),
        ];
        assert_eq!(lookup_kind(&known, "192.168.1.5:52341".parse().unwrap()), "host");
        assert_eq!(lookup_kind(&known, "198.51.100.7:3478".parse().unwrap()), "relay");
        assert_eq!(
            lookup_kind(&known, "203.0.113.1:9999".parse().unwrap()),
            "unknown",
            "an address we never advertised must not be mislabeled",
        );
    }

    #[test]
    fn selected_pair_line_names_both_ends_with_types() {
        let local = vec![parse_candidate_line("candidate:1 1 udp 1 192.168.1.5 52341 typ host").unwrap()];
        let remote = vec![parse_candidate_line("candidate:2 1 udp 1 192.168.1.7 49812 typ host").unwrap()];
        assert_eq!(
            format_selected_pair(
                &local,
                &remote,
                "192.168.1.5:52341".parse().unwrap(),
                "192.168.1.7:49812".parse().unwrap(),
            ),
            "ICE selected pair: local host udp 192.168.1.5:52341 \u{2194} remote host udp 192.168.1.7:49812",
        );
    }

    #[test]
    fn zero_candidate_warnings_name_the_likely_cause() {
        assert!(NO_LOCAL_CANDIDATES.contains("ZERO local candidates"));
        assert!(NO_LOCAL_CANDIDATES.contains("UDP"));
        assert!(no_candidates_in_sdp("offer").contains("offer"));
        assert!(no_candidates_in_sdp("answer").contains("NONE"));
    }
}
