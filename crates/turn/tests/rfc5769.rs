//! RFC 5769 byte-exact test vectors + allocate state machine tests.

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use nullseal_turn::attr::{decode_xor_address, encode_xor_address, Attribute};
    use nullseal_turn::auth;
    use nullseal_turn::message::{self, Class, MessageBuilder, Method};

    // ========================================================================
    // RFC 5769 §2.1 — Sample Request (short-term auth, with FINGERPRINT)
    // ========================================================================

    /// Full request bytes from RFC 5769 Appendix A.
    const RFC5769_REQUEST: [u8; 108] = hex!(
        "0001005821 12a442 b7e7a701 bc34d686 fa87dfae"
        "80220010 5354554e 20746573 7420636c 69656e74"
        "00240004 6e0001ff"
        "80290008 932ff9b1 51263b36"
        "00060009 6576746a 3a683676 59202020"
        "00080014 9aeaa70c bfd8cb56 781ef2b5 b2d3f249 c1b571a2"
        "80280004 e57a3bcf"
    );

    #[test]
    fn rfc5769_request_decode() {
        let msg = message::decode(&RFC5769_REQUEST).unwrap();
        assert_eq!(msg.class, Class::Request);
        assert_eq!(msg.method, Method::Binding.code());
        assert_eq!(msg.txn_id, hex!("b7e7a701 bc34d686 fa87dfae"));

        // Check SOFTWARE attr
        assert!(msg.attrs.iter().any(|a| matches!(a, Attribute::Software(s) if s == "STUN test client")));
        // Check USERNAME attr
        assert!(msg.attrs.iter().any(|a| matches!(a, Attribute::Username(s) if s == "evtj:h6vY")));
        // Check MESSAGE-INTEGRITY
        let expected_mi = hex!("9aeaa70c bfd8cb56 781ef2b5 b2d3f249 c1b571a2");
        assert!(msg.attrs.iter().any(|a| matches!(a, Attribute::MessageIntegrity(h) if *h == expected_mi)));
        // Check FINGERPRINT
        assert!(msg.attrs.iter().any(|a| matches!(a, Attribute::Fingerprint(v) if *v == 0xe57a3bcf)));
    }

    #[test]
    fn rfc5769_request_verify_integrity() {
        // Short-term auth: key = SASLprep(password) as raw bytes
        let key = b"VOkJxbRl1RmTxUk/WvJxBt";

        // MESSAGE-INTEGRITY is computed over everything up to (not including) the MI attr,
        // with the length field adjusted to include MI (24 bytes: 4 header + 20 value).
        // In the test vector, MI starts at offset 80 (header=4+value area before MI).
        // The length field in the header for MI computation = offset_of_MI_end - 20 = attrs_before_MI + 24.
        // From the vector: total attrs before MI = 0x0058 - 24 - 8 = 56 bytes... 
        // Actually let's compute it properly:
        // Header says length = 0x0058 = 88. That includes SOFTWARE(20) + PRIORITY(8) + ICE-CONTROLLED(12) + USERNAME(16) + MI(24) + FP(8) = 88. ✓
        // For MI computation, length field = attrs_up_to_and_including_MI = 88 - 8(FP) = 80.
        // Message up to MI attr starts at byte 80+20 = offset 100... wait.
        // Let's just verify: bytes 0..80 with length field = 80 should produce the expected HMAC.
        
        // Actually per spec: the header length for MI computation includes MI itself.
        // The message to HMAC = header (with adjusted length) + attrs before MI.
        // Adjusted length = (offset of MI from start of attrs) + 24.
        
        // In our vector: MI is at offset 80 from message start. Attrs start at 20.
        // So MI attr starts at offset 80. Attrs before MI = 80-20 = 60 bytes. 
        // Adjusted length for MI = 60 + 24 = 84 = 0x0054.
        // Wait, but the vector has length 0x0058 which is 88. That includes FP.
        // For MI: length = 88 - 8 = 80. Message to hash = bytes[0..80] with bytes[2..4] = 0x0050.
        // Hmm, let me recalculate.

        // Total message = 108 bytes. Header = 20. Attrs = 88 bytes total.
        // Attrs: SOFTWARE(4+16+0=20) + PRIORITY(4+4=8) + ICE-CONTROLLED(4+8=12) + USERNAME(4+9+3pad=16) + MI(4+20=24) + FP(4+4=8) = 88. ✓
        // MI starts at byte 20+20+8+12+16 = 76. So MI attr header is at offset 76.
        // For MI computation: message = bytes[0..76], with length field = 76 - 20 + 24 = 80.

        let mut msg_for_mi = RFC5769_REQUEST[..76].to_vec();
        // Set length field to include MI: (76-20) + 24 = 80
        let adjusted_len: u16 = 80;
        msg_for_mi[2] = (adjusted_len >> 8) as u8;
        msg_for_mi[3] = adjusted_len as u8;

        let computed = auth::compute_message_integrity(&msg_for_mi, key);
        let expected = hex!("9aeaa70c bfd8cb56 781ef2b5 b2d3f249 c1b571a2");
        assert_eq!(computed, expected);
    }

    #[test]
    fn rfc5769_request_verify_fingerprint() {
        // FINGERPRINT is computed over everything up to (not including) the FP attr,
        // with length field adjusted to include FP (8 bytes).
        // FP attr starts at offset 108 - 8 = 100.
        // Adjusted length = (100-20) + 8 = 88 = 0x0058 (same as in the vector since FP is last).
        
        let msg_for_fp = &RFC5769_REQUEST[..100];
        // Length field is already 0x0058 which includes FP, so it's correct.
        let computed = auth::compute_fingerprint(msg_for_fp);
        assert_eq!(computed, 0xe57a3bcf);
    }

    // ========================================================================
    // RFC 5769 §2.2 — Sample IPv4 Response
    // ========================================================================

    const RFC5769_RESPONSE_IPV4: [u8; 80] = hex!(
        "01010 03c 2112a442 b7e7a701 bc34d686 fa87dfae"
        "8022000b 74657374 20766563 746f7220"
        "00200008 0001a147 e112a643"
        "00080014 2b91f599 fd9e90c3 8c7489f9 2af9ba53 f06be7d7"
        "80280004 c07d4c96"
    );

    #[test]
    fn rfc5769_response_ipv4_decode() {
        let msg = message::decode(&RFC5769_RESPONSE_IPV4).unwrap();
        assert_eq!(msg.class, Class::Success);
        assert_eq!(msg.method, Method::Binding.code());
        assert_eq!(msg.txn_id, hex!("b7e7a701 bc34d686 fa87dfae"));

        // Check XOR-MAPPED-ADDRESS → 192.0.2.1:32853
        let expected_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32853);
        assert!(msg.attrs.iter().any(|a| matches!(a, Attribute::XorMappedAddress(addr) if *addr == expected_addr)));

        // Check SOFTWARE
        assert!(msg.attrs.iter().any(|a| matches!(a, Attribute::Software(s) if s == "test vector")));
    }

    #[test]
    fn rfc5769_response_ipv4_verify_integrity() {
        let key = b"VOkJxbRl1RmTxUk/WvJxBt";
        // MI attr starts at offset: 20 (header) + 16 (SOFTWARE: 4+11+1pad=16) + 12 (XOR-MAPPED: 4+8=12) = 48
        // Wait: SOFTWARE = type(2)+len(2)+value(11)+pad(1) = 16. XOR-MAPPED = type(2)+len(2)+value(8) = 12.
        // MI starts at 20 + 16 + 12 = 48. 
        // For MI: adjusted length = (48-20) + 24 = 52.
        let mut msg_for_mi = RFC5769_RESPONSE_IPV4[..48].to_vec();
        let adjusted_len: u16 = 52;
        msg_for_mi[2] = (adjusted_len >> 8) as u8;
        msg_for_mi[3] = adjusted_len as u8;

        let computed = auth::compute_message_integrity(&msg_for_mi, key);
        let expected = hex!("2b91f599 fd9e90c3 8c7489f9 2af9ba53 f06be7d7");
        assert_eq!(computed, expected);
    }

    #[test]
    fn rfc5769_response_ipv4_verify_fingerprint() {
        // FP starts at offset 80 - 8 = 72.
        // Adjusted length = (72-20) + 8 = 60 = 0x003c (matches header).
        let computed = auth::compute_fingerprint(&RFC5769_RESPONSE_IPV4[..72]);
        assert_eq!(computed, 0xc07d4c96);
    }

    #[test]
    fn rfc5769_response_ipv4_xor_address() {
        // XOR-MAPPED-ADDRESS value bytes (after the TLV header):
        // 00 01 a1 47 e1 12 a6 43
        let txn_id = hex!("b7e7a701 bc34d686 fa87dfae");
        let value = hex!("0001a147 e112a643");
        let addr = decode_xor_address(&value, &txn_id).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32853));

        // Round-trip
        let encoded = encode_xor_address(&addr, &txn_id);
        assert_eq!(encoded, value.to_vec());
    }

    // ========================================================================
    // RFC 5769 §2.3 — Sample IPv6 Response
    // ========================================================================

    const RFC5769_RESPONSE_IPV6: [u8; 92] = hex!(
        "0101 0048 2112a442 b7e7a701 bc34d686 fa87dfae"
        "8022000b 74657374 20766563 746f7220"
        "00200014 0002a147 0113a9fa a5d3f179 bc25f4b5 bed2b9d9"
        "00080014 a382954e 4be67bf1 1784c97c 8292c275 bfe3ed41"
        "80280004 c8fb0b4c"
    );

    #[test]
    fn rfc5769_response_ipv6_decode() {
        let msg = message::decode(&RFC5769_RESPONSE_IPV6).unwrap();
        assert_eq!(msg.class, Class::Success);
        assert_eq!(msg.method, Method::Binding.code());

        let expected_addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0x11, 0x2233, 0x4455, 0x6677)),
            32853,
        );
        assert!(msg.attrs.iter().any(|a| matches!(a, Attribute::XorMappedAddress(addr) if *addr == expected_addr)));
    }

    #[test]
    fn rfc5769_response_ipv6_verify_integrity() {
        let key = b"VOkJxbRl1RmTxUk/WvJxBt";
        // SOFTWARE: 4+11+1pad = 16. XOR-MAPPED-ADDRESS (IPv6): 4+20 = 24.
        // MI starts at 20 + 16 + 24 = 60.
        // Adjusted length = (60-20) + 24 = 64.
        let mut msg_for_mi = RFC5769_RESPONSE_IPV6[..60].to_vec();
        let adjusted_len: u16 = 64;
        msg_for_mi[2] = (adjusted_len >> 8) as u8;
        msg_for_mi[3] = adjusted_len as u8;

        let computed = auth::compute_message_integrity(&msg_for_mi, key);
        let expected = hex!("a382954e 4be67bf1 1784c97c 8292c275 bfe3ed41");
        assert_eq!(computed, expected);
    }

    #[test]
    fn rfc5769_response_ipv6_verify_fingerprint() {
        // FP at offset 92-8=84. Length field = (84-20)+8 = 72 = 0x0048.
        let computed = auth::compute_fingerprint(&RFC5769_RESPONSE_IPV6[..84]);
        assert_eq!(computed, 0xc8fb0b4c);
    }

    #[test]
    fn rfc5769_response_ipv6_xor_address() {
        let txn_id = hex!("b7e7a701 bc34d686 fa87dfae");
        // XOR-MAPPED-ADDRESS value (20 bytes for IPv6):
        let value = hex!("0002a147 0113a9fa a5d3f179 bc25f4b5 bed2b9d9");
        let addr = decode_xor_address(&value, &txn_id).unwrap();
        let expected = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0x11, 0x2233, 0x4455, 0x6677)),
            32853,
        );
        assert_eq!(addr, expected);

        // Round-trip
        let encoded = encode_xor_address(&addr, &txn_id);
        assert_eq!(encoded, value.to_vec());
    }

    // ========================================================================
    // RFC 5769 §2.4 — Sample Request with Long-Term Authentication
    // ========================================================================

    const RFC5769_REQUEST_LTC: [u8; 116] = hex!(
        "00010060 2112a442 78ad3433 c6ad72c0 29da412e"
        "00060012 e3839ee3 8388e383 aae38383 e382afe3 82b90000"
        "0015001c 662f2f34 39396b39 35346436 4f4c3334 6f4c3946 53547679 36347341"
        "0014000b 6578616d 706c652e 6f726700"
        "00080014 f6702465 6dd64a3e 02b8e071 2e85c9a2 8ca89666"
    );

    #[test]
    fn rfc5769_request_ltc_decode() {
        let msg = message::decode(&RFC5769_REQUEST_LTC).unwrap();
        assert_eq!(msg.class, Class::Request);
        assert_eq!(msg.method, Method::Binding.code());
        assert_eq!(msg.txn_id, hex!("78ad3433 c6ad72c0 29da412e"));

        // Username is UTF-8 "マトリックス"
        let expected_username = "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}";
        assert!(msg.attrs.iter().any(|a| matches!(a, Attribute::Username(s) if s == expected_username)));

        // Realm = "example.org"
        assert!(msg.attrs.iter().any(|a| matches!(a, Attribute::Realm(s) if s == "example.org")));

        // Nonce = "f//499k954d6OL34oL9FSTvy64sA"
        assert!(msg.attrs.iter().any(|a| matches!(a, Attribute::Nonce(s) if s == "f//499k954d6OL34oL9FSTvy64sA")));
    }

    #[test]
    fn rfc5769_request_ltc_verify_integrity() {
        // Long-term key = MD5(username ":" realm ":" password)
        // Username (after SASLprep): "マトリックス", password (after SASLprep): "TheMatrIX", realm: "example.org"
        let username = "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}";
        let key = auth::long_term_key(username, "example.org", "TheMatrIX");

        // MI is the last attribute. It starts at offset 116-24=92.
        // Adjusted length for MI = (92-20) + 24 = 96 = 0x0060 (matches header).
        let mut msg_for_mi = RFC5769_REQUEST_LTC[..92].to_vec();
        let adjusted_len: u16 = 96;
        msg_for_mi[2] = (adjusted_len >> 8) as u8;
        msg_for_mi[3] = adjusted_len as u8;

        let computed = auth::compute_message_integrity(&msg_for_mi, &key);
        let expected = hex!("f6702465 6dd64a3e 02b8e071 2e85c9a2 8ca89666");
        assert_eq!(computed, expected);
    }

    #[test]
    fn rfc5769_long_term_key() {
        // Verify the key itself. From RFC 5389 the key for these creds should be:
        // MD5("マトリックス:example.org:TheMatrIX")
        let username = "\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}";
        let key = auth::long_term_key(username, "example.org", "TheMatrIX");
        // Known key value from the RFC (not explicitly stated but we can verify via the HMAC)
        // We verify transitively: if the HMAC matches the expected bytes, the key is correct.
        assert_eq!(key.len(), 16);
    }

    // ========================================================================
    // Message type encode/decode
    // ========================================================================

    #[test]
    fn msg_type_encode_binding_request() {
        let typ = message::encode_msg_type(Method::Binding, Class::Request);
        assert_eq!(typ, 0x0001);
    }

    #[test]
    fn msg_type_encode_binding_success() {
        let typ = message::encode_msg_type(Method::Binding, Class::Success);
        assert_eq!(typ, 0x0101);
    }

    #[test]
    fn msg_type_encode_binding_error() {
        let typ = message::encode_msg_type(Method::Binding, Class::Error);
        assert_eq!(typ, 0x0111);
    }

    #[test]
    fn msg_type_encode_allocate_request() {
        let typ = message::encode_msg_type(Method::Allocate, Class::Request);
        assert_eq!(typ, 0x0003);
    }

    #[test]
    fn msg_type_encode_allocate_success() {
        let typ = message::encode_msg_type(Method::Allocate, Class::Success);
        assert_eq!(typ, 0x0103);
    }

    #[test]
    fn msg_type_encode_allocate_error() {
        let typ = message::encode_msg_type(Method::Allocate, Class::Error);
        assert_eq!(typ, 0x0113);
    }

    #[test]
    fn msg_type_roundtrip() {
        for method in [Method::Binding, Method::Allocate, Method::Refresh, Method::Send, Method::Data, Method::CreatePermission] {
            for class in [Class::Request, Class::Indication, Class::Success, Class::Error] {
                let typ = message::encode_msg_type(method, class);
                let (decoded_method, decoded_class) = message::decode_msg_type(typ);
                assert_eq!(decoded_method, method.code());
                assert_eq!(decoded_class, class);
            }
        }
    }

    // ========================================================================
    // XOR address round-trip
    // ========================================================================

    #[test]
    fn xor_address_ipv4_roundtrip() {
        let txn_id = hex!("aabbccdd eeff0011 22334455");
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 50)), 3478);
        let encoded = encode_xor_address(&addr, &txn_id);
        let decoded = decode_xor_address(&encoded, &txn_id).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn xor_address_ipv6_roundtrip() {
        let txn_id = hex!("aabbccdd eeff0011 22334455");
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0)),
            12345,
        );
        let encoded = encode_xor_address(&addr, &txn_id);
        let decoded = decode_xor_address(&encoded, &txn_id).unwrap();
        assert_eq!(decoded, addr);
    }

    // ========================================================================
    // MessageBuilder — encode then decode round-trip
    // ========================================================================

    #[test]
    fn builder_roundtrip_with_integrity_and_fingerprint() {
        let txn_id = hex!("0102030405060708090a0b0c");
        let key = auth::long_term_key("user", "realm.org", "pass123");
        let mut builder = MessageBuilder::new(Method::Allocate, Class::Request, txn_id);
        builder.add_requested_transport(17);
        builder.add_username("user");
        builder.add_realm("realm.org");
        builder.add_nonce("abc123nonce");

        let msg_bytes = builder.build_with_integrity(&key);

        // Should decode successfully
        let parsed = message::decode(&msg_bytes).unwrap();
        assert_eq!(parsed.method, Method::Allocate.code());
        assert_eq!(parsed.class, Class::Request);
        assert_eq!(parsed.txn_id, txn_id);

        // Verify attributes present
        assert!(parsed.attrs.iter().any(|a| matches!(a, Attribute::RequestedTransport(17))));
        assert!(parsed.attrs.iter().any(|a| matches!(a, Attribute::Username(s) if s == "user")));
        assert!(parsed.attrs.iter().any(|a| matches!(a, Attribute::Realm(s) if s == "realm.org")));
        assert!(parsed.attrs.iter().any(|a| matches!(a, Attribute::Nonce(s) if s == "abc123nonce")));
        assert!(parsed.attrs.iter().any(|a| matches!(a, Attribute::MessageIntegrity(_))));
        assert!(parsed.attrs.iter().any(|a| matches!(a, Attribute::Fingerprint(_))));
    }

    // ========================================================================
    // Allocate state machine tests
    // ========================================================================

    use nullseal_turn::allocate::{Action, AllocateMachine, Credentials};

    /// Build a fake 401 response with REALM + NONCE.
    fn build_401_response(txn_id: &[u8; 12], realm: &str, nonce: &str) -> Vec<u8> {
        let mut builder = MessageBuilder::new(Method::Allocate, Class::Error, *txn_id);
        // ERROR-CODE 401
        let error_val = nullseal_turn::attr::encode_error_code(401, "Unauthorized");
        builder.add_raw_attr(0x0009, &error_val);
        builder.add_realm(realm);
        builder.add_nonce(nonce);
        builder.build_raw()
    }

    /// Build a fake Allocate success response.
    fn build_allocate_success(
        txn_id: &[u8; 12],
        relayed: SocketAddr,
        srflx: SocketAddr,
        lifetime: u32,
    ) -> Vec<u8> {
        let mut builder = MessageBuilder::new(Method::Allocate, Class::Success, *txn_id);
        let relay_val = encode_xor_address(&relayed, txn_id);
        builder.add_raw_attr(0x0016, &relay_val); // XOR-RELAYED-ADDRESS
        let srflx_val = encode_xor_address(&srflx, txn_id);
        builder.add_raw_attr(0x0020, &srflx_val); // XOR-MAPPED-ADDRESS
        builder.add_lifetime(lifetime);
        builder.build_raw()
    }

    /// Build a fake 438 Stale Nonce response.
    fn build_438_response(txn_id: &[u8; 12], realm: &str, nonce: &str) -> Vec<u8> {
        let mut builder = MessageBuilder::new(Method::Allocate, Class::Error, *txn_id);
        let error_val = nullseal_turn::attr::encode_error_code(438, "Stale Nonce");
        builder.add_raw_attr(0x0009, &error_val);
        builder.add_realm(realm);
        builder.add_nonce(nonce);
        builder.build_raw()
    }

    #[test]
    fn allocate_full_handshake() {
        let creds = Credentials {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };
        let txn_id = hex!("aabbccdd eeff0011 22334455");

        let (mut machine, initial_msg) = AllocateMachine::start(creds, txn_id);

        // Initial message should be a valid STUN Allocate request
        let parsed = message::decode(&initial_msg).unwrap();
        assert_eq!(parsed.method, Method::Allocate.code());
        assert_eq!(parsed.class, Class::Request);
        assert_eq!(parsed.txn_id, txn_id);
        // Should have REQUESTED-TRANSPORT but no MESSAGE-INTEGRITY (unauthenticated)
        assert!(parsed.attrs.iter().any(|a| matches!(a, Attribute::RequestedTransport(17))));
        assert!(!parsed.attrs.iter().any(|a| matches!(a, Attribute::MessageIntegrity(_))));

        // Server responds with 401
        let resp_401 = build_401_response(&txn_id, "turn.example.com", "nonce123abc");
        let actions = machine.handle(&resp_401);

        // Should emit a SendDatagram with an authenticated Allocate
        assert_eq!(actions.len(), 1);
        let auth_msg = match &actions[0] {
            Action::SendDatagram(data) => data.clone(),
            other => panic!("Expected SendDatagram, got {:?}", other),
        };

        let parsed_auth = message::decode(&auth_msg).unwrap();
        assert_eq!(parsed_auth.method, Method::Allocate.code());
        assert_eq!(parsed_auth.class, Class::Request);
        // Should have USERNAME, REALM, NONCE, MESSAGE-INTEGRITY
        assert!(parsed_auth.attrs.iter().any(|a| matches!(a, Attribute::Username(s) if s == "testuser")));
        assert!(parsed_auth.attrs.iter().any(|a| matches!(a, Attribute::Realm(s) if s == "turn.example.com")));
        assert!(parsed_auth.attrs.iter().any(|a| matches!(a, Attribute::Nonce(s) if s == "nonce123abc")));
        assert!(parsed_auth.attrs.iter().any(|a| matches!(a, Attribute::MessageIntegrity(_))));

        // Server responds with success
        let relayed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 49152);
        let srflx = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 54321);
        let success = build_allocate_success(&parsed_auth.txn_id, relayed, srflx, 600);
        let actions = machine.handle(&success);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::Allocated(a) => {
                assert_eq!(a.relayed, relayed);
                assert_eq!(a.srflx, srflx);
                assert_eq!(a.lifetime, 600);
            }
            other => panic!("Expected Allocated, got {:?}", other),
        }
    }

    #[test]
    fn allocate_stale_nonce_recovery() {
        let creds = Credentials {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        let txn_id = hex!("112233445566778899aabbcc");

        let (mut machine, _initial) = AllocateMachine::start(creds, txn_id);

        // 401 challenge
        let resp_401 = build_401_response(&txn_id, "realm", "nonce1");
        let actions = machine.handle(&resp_401);
        let auth_msg = match &actions[0] {
            Action::SendDatagram(d) => d.clone(),
            _ => panic!(),
        };
        let parsed = message::decode(&auth_msg).unwrap();

        // Server responds with 438 Stale Nonce
        let resp_438 = build_438_response(&parsed.txn_id, "realm", "nonce2_fresh");
        let actions = machine.handle(&resp_438);

        // Should retry with new nonce
        assert_eq!(actions.len(), 1);
        let retry_msg = match &actions[0] {
            Action::SendDatagram(d) => d.clone(),
            other => panic!("Expected SendDatagram, got {:?}", other),
        };
        let parsed_retry = message::decode(&retry_msg).unwrap();
        assert!(parsed_retry.attrs.iter().any(|a| matches!(a, Attribute::Nonce(s) if s == "nonce2_fresh")));

        // Now server sends success
        let relayed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5000);
        let srflx = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 6000);
        let success = build_allocate_success(&parsed_retry.txn_id, relayed, srflx, 300);
        let actions = machine.handle(&success);

        match &actions[0] {
            Action::Allocated(a) => {
                assert_eq!(a.relayed, relayed);
                assert_eq!(a.srflx, srflx);
                assert_eq!(a.lifetime, 300);
            }
            other => panic!("Expected Allocated, got {:?}", other),
        }
    }

    #[test]
    fn allocate_ignores_wrong_txn_id() {
        let creds = Credentials {
            username: "u".to_string(),
            password: "p".to_string(),
        };
        let txn_id = hex!("aabbccddeeff001122334455");
        let (mut machine, _) = AllocateMachine::start(creds, txn_id);

        // Response with wrong txn_id
        let wrong_txn = hex!("000000000000000000000000");
        let resp = build_401_response(&wrong_txn, "r", "n");
        let actions = machine.handle(&resp);
        assert!(actions.is_empty());
    }

    // ========================================================================
    // Refresh + CreatePermission encoder tests
    // ========================================================================

    use nullseal_turn::allocate::{build_refresh, build_create_permission};

    #[test]
    fn refresh_encodes_correctly() {
        let txn_id = hex!("0102030405060708090a0b0c");
        let key = auth::long_term_key("user", "realm", "pass");
        let msg = build_refresh(&txn_id, "user", "realm", "nonce", &key, 600);
        let parsed = message::decode(&msg).unwrap();
        assert_eq!(parsed.method, Method::Refresh.code());
        assert_eq!(parsed.class, Class::Request);
        assert!(parsed.attrs.iter().any(|a| matches!(a, Attribute::Lifetime(600))));
        assert!(parsed.attrs.iter().any(|a| matches!(a, Attribute::MessageIntegrity(_))));
    }

    #[test]
    fn create_permission_encodes_correctly() {
        let txn_id = hex!("0102030405060708090a0b0c");
        let key = auth::long_term_key("user", "realm", "pass");
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 9999);
        let msg = build_create_permission(&txn_id, "user", "realm", "nonce", &key, &peer);
        let parsed = message::decode(&msg).unwrap();
        assert_eq!(parsed.method, Method::CreatePermission.code());
        assert_eq!(parsed.class, Class::Request);
        assert!(parsed.attrs.iter().any(|a| matches!(a, Attribute::XorPeerAddress(a) if *a == peer)));
        assert!(parsed.attrs.iter().any(|a| matches!(a, Attribute::MessageIntegrity(_))));
    }

    // ========================================================================
    // Edge cases
    // ========================================================================

    #[test]
    fn decode_rejects_truncated() {
        assert!(message::decode(&[0u8; 10]).is_none());
        assert!(message::decode(&[]).is_none());
    }

    #[test]
    fn decode_rejects_bad_magic_cookie() {
        let mut data = [0u8; 20];
        data[4] = 0xFF; // wrong cookie
        assert!(message::decode(&data).is_none());
    }

    #[test]
    fn decode_rejects_first_two_bits_set() {
        let mut data = RFC5769_REQUEST;
        data[0] |= 0x80; // set first bit
        assert!(message::decode(&data).is_none());
    }
}
