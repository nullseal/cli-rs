//! Send/Data indication codecs for the TURN relay data path.
//!
//! Send indications wrap outbound packets to the TURN server for relay.
//! Data indications carry inbound peer traffic from the TURN server.
//! Neither uses MESSAGE-INTEGRITY (indications are unauthenticated;
//! permissions gate relay access).

use std::net::SocketAddr;

use crate::allocate::new_txn_id;
use crate::attr::Attribute;
use crate::message::{self, Class, MessageBuilder, Method};

/// Build a Send indication (Method::Send / Class::Indication).
///
/// Wraps `data` destined for `peer` into a TURN Send indication
/// containing XOR-PEER-ADDRESS + DATA attributes. No MESSAGE-INTEGRITY.
pub fn build_send_indication(peer: &SocketAddr, data: &[u8]) -> Vec<u8> {
    let txn_id = new_txn_id();
    let mut builder = MessageBuilder::new(Method::Send, Class::Indication, txn_id);
    builder.add_xor_peer_address(peer);
    // DATA attribute (0x0013)
    builder.add_raw_attr(0x0013, data);
    builder.build_raw()
}

/// Parse a Data indication (Method::Data / Class::Indication).
///
/// Returns `(peer_address, payload)` extracted from XOR-PEER-ADDRESS + DATA attributes.
/// Returns None if the message is not a Data indication or is missing required attrs.
pub fn parse_data_indication(bytes: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
    let msg = message::decode(bytes)?;

    // Must be Data / Indication
    if msg.method != Method::Data.code() || msg.class != Class::Indication {
        return None;
    }

    let mut peer: Option<SocketAddr> = None;
    let mut payload: Option<Vec<u8>> = None;

    for a in &msg.attrs {
        match a {
            Attribute::XorPeerAddress(addr) => peer = Some(*addr),
            Attribute::Data(d) => payload = Some(d.clone()),
            _ => {}
        }
    }

    Some((peer?, payload?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, IpAddr};

    #[test]
    fn send_indication_roundtrip_ipv4() {
        let peer: SocketAddr = "10.0.0.1:9999".parse().unwrap();
        let data = b"hello relay world";

        let indication = build_send_indication(&peer, data);

        // Decode as a raw STUN message
        let msg = message::decode(&indication).expect("should decode");
        assert_eq!(msg.method, Method::Send.code());
        assert_eq!(msg.class, Class::Indication);

        // Check XOR-PEER-ADDRESS
        let mut found_peer = None;
        let mut found_data = None;
        for attr in &msg.attrs {
            match attr {
                Attribute::XorPeerAddress(a) => found_peer = Some(*a),
                Attribute::Data(d) => found_data = Some(d.clone()),
                _ => {}
            }
        }
        assert_eq!(found_peer, Some(peer));
        assert_eq!(found_data.as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn send_indication_roundtrip_ipv6() {
        let peer = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            12345,
        );
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];

        let indication = build_send_indication(&peer, &data);

        let msg = message::decode(&indication).expect("should decode");
        assert_eq!(msg.method, Method::Send.code());
        assert_eq!(msg.class, Class::Indication);

        let mut found_peer = None;
        let mut found_data = None;
        for attr in &msg.attrs {
            match attr {
                Attribute::XorPeerAddress(a) => found_peer = Some(*a),
                Attribute::Data(d) => found_data = Some(d.clone()),
                _ => {}
            }
        }
        assert_eq!(found_peer, Some(peer));
        assert_eq!(found_data, Some(data));
    }

    #[test]
    fn data_indication_parse_valid() {
        // Build a Data indication manually (simulating what coturn sends)
        let peer: SocketAddr = "192.168.1.100:4000".parse().unwrap();
        let payload = b"peer says hi";

        let txn_id = new_txn_id();
        let mut builder = MessageBuilder::new(Method::Data, Class::Indication, txn_id);
        builder.add_xor_peer_address(&peer);
        builder.add_raw_attr(0x0013, payload);
        let raw = builder.build_raw();

        let (parsed_peer, parsed_data) = parse_data_indication(&raw).unwrap();
        assert_eq!(parsed_peer, peer);
        assert_eq!(parsed_data, payload);
    }

    #[test]
    fn data_indication_rejects_non_indication() {
        // A Data Success response should be rejected
        let txn_id = new_txn_id();
        let builder = MessageBuilder::new(Method::Data, Class::Success, txn_id);
        let raw = builder.build_raw();
        assert!(parse_data_indication(&raw).is_none());
    }

    #[test]
    fn data_indication_rejects_wrong_method() {
        // A Send indication is not a Data indication
        let peer: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let indication = build_send_indication(&peer, b"test");
        assert!(parse_data_indication(&indication).is_none());
    }

    #[test]
    fn data_indication_rejects_missing_data_attr() {
        // Data indication with only XOR-PEER-ADDRESS, no DATA
        let txn_id = new_txn_id();
        let peer: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let mut builder = MessageBuilder::new(Method::Data, Class::Indication, txn_id);
        builder.add_xor_peer_address(&peer);
        let raw = builder.build_raw();
        assert!(parse_data_indication(&raw).is_none());
    }

    #[test]
    fn data_indication_rejects_missing_peer_attr() {
        // Data indication with only DATA, no XOR-PEER-ADDRESS
        let txn_id = new_txn_id();
        let mut builder = MessageBuilder::new(Method::Data, Class::Indication, txn_id);
        builder.add_raw_attr(0x0013, b"payload");
        let raw = builder.build_raw();
        assert!(parse_data_indication(&raw).is_none());
    }

    #[test]
    fn send_indication_odd_size_data_padded() {
        // Verify odd-sized data is properly padded (STUN requires 4-byte alignment)
        let peer: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let data = b"abc"; // 3 bytes — needs 1 byte padding

        let indication = build_send_indication(&peer, data);

        // Total length should be 4-byte aligned
        assert_eq!(indication.len() % 4, 0);

        // Should still round-trip correctly
        let msg = message::decode(&indication).unwrap();
        let mut found_data = None;
        for attr in &msg.attrs {
            if let Attribute::Data(d) = attr {
                found_data = Some(d.clone());
            }
        }
        assert_eq!(found_data.as_deref(), Some(data.as_slice()));
    }
}
