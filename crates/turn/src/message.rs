//! STUN message: 20-byte header + attributes. Encode/decode with MESSAGE-INTEGRITY + FINGERPRINT support.

use crate::attr::{self, Attribute};

/// Magic cookie value (RFC 5389 §6).
pub const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN header size in bytes.
pub const HEADER_SIZE: usize = 20;

/// STUN message class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    Success,
    Error,
}

/// STUN/TURN methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Binding,
    Allocate,
    Refresh,
    Send,
    Data,
    CreatePermission,
}

impl Method {
    pub fn code(self) -> u16 {
        match self {
            Self::Binding => 0x001,
            Self::Allocate => 0x003,
            Self::Refresh => 0x004,
            Self::Send => 0x006,
            Self::Data => 0x007,
            Self::CreatePermission => 0x008,
        }
    }

    pub fn from_code(c: u16) -> Option<Self> {
        match c {
            0x001 => Some(Self::Binding),
            0x003 => Some(Self::Allocate),
            0x004 => Some(Self::Refresh),
            0x006 => Some(Self::Send),
            0x007 => Some(Self::Data),
            0x008 => Some(Self::CreatePermission),
            _ => None,
        }
    }
}

/// Encode method + class into the 2-byte message type field (RFC 5389 §6 bit layout).
/// Bits: M11 M10 M9 M8 M7 C1 M6 M5 M4 C0 M3 M2 M1 M0
pub fn encode_msg_type(method: Method, class: Class) -> u16 {
    let m = method.code();
    let (c0, c1) = match class {
        Class::Request => (0, 0),
        Class::Indication => (1, 0),
        Class::Success => (0, 1),
        Class::Error => (1, 1),
    };
    // method bits: m[11:0], class bits c1, c0
    let m0_3 = m & 0xF;
    let m4_6 = (m >> 4) & 0x7;
    let m7_11 = (m >> 7) & 0x1F;

    (m7_11 << 9) | (c1 << 8) | (m4_6 << 5) | (c0 << 4) | m0_3
}

/// Decode the 2-byte message type field into method code + class.
pub fn decode_msg_type(typ: u16) -> (u16, Class) {
    let c0 = (typ >> 4) & 1;
    let c1 = (typ >> 8) & 1;
    let class = match (c0, c1) {
        (0, 0) => Class::Request,
        (1, 0) => Class::Indication,
        (0, 1) => Class::Success,
        (1, 1) => Class::Error,
        _ => unreachable!(),
    };
    let m0_3 = typ & 0xF;
    let m4_6 = (typ >> 5) & 0x7;
    let m7_11 = (typ >> 9) & 0x1F;
    let method = m0_3 | (m4_6 << 4) | (m7_11 << 7);
    (method, class)
}

/// A parsed STUN message.
#[derive(Debug, Clone)]
pub struct StunMessage {
    pub method: u16,
    pub class: Class,
    pub txn_id: [u8; 12],
    pub attrs: Vec<Attribute>,
}

/// Decode a STUN message from raw bytes. Returns None if malformed.
pub fn decode(data: &[u8]) -> Option<StunMessage> {
    if data.len() < HEADER_SIZE {
        return None;
    }
    // First two bits must be 0
    if data[0] & 0xC0 != 0 {
        return None;
    }
    let typ = u16::from_be_bytes([data[0], data[1]]);
    let length = u16::from_be_bytes([data[2], data[3]]) as usize;
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return None;
    }
    if data.len() < HEADER_SIZE + length {
        return None;
    }
    let mut txn_id = [0u8; 12];
    txn_id.copy_from_slice(&data[8..20]);
    let (method, class) = decode_msg_type(typ);
    let attrs = attr::decode_attrs(&data[HEADER_SIZE..HEADER_SIZE + length], &txn_id);
    Some(StunMessage { method, class, txn_id, attrs })
}

/// Builder for constructing STUN messages.
pub struct MessageBuilder {
    pub method: Method,
    pub class: Class,
    pub txn_id: [u8; 12],
    /// Raw attribute bytes (already TLV-encoded, without integrity/fingerprint).
    attrs_buf: Vec<u8>,
}

impl MessageBuilder {
    pub fn new(method: Method, class: Class, txn_id: [u8; 12]) -> Self {
        Self { method, class, txn_id, attrs_buf: Vec::new() }
    }

    /// Add a raw attribute (type + value encoded as TLV).
    pub fn add_raw_attr(&mut self, typ: u16, value: &[u8]) {
        attr::encode_attr(&mut self.attrs_buf, typ, value);
    }

    pub fn add_software(&mut self, name: &str) {
        self.add_raw_attr(0x8022, name.as_bytes());
    }

    pub fn add_username(&mut self, name: &str) {
        self.add_raw_attr(0x0006, name.as_bytes());
    }

    pub fn add_realm(&mut self, realm: &str) {
        self.add_raw_attr(0x0014, realm.as_bytes());
    }

    pub fn add_nonce(&mut self, nonce: &str) {
        self.add_raw_attr(0x0015, nonce.as_bytes());
    }

    pub fn add_requested_transport(&mut self, proto: u8) {
        let val = [proto, 0x00, 0x00, 0x00];
        self.add_raw_attr(0x0019, &val);
    }

    pub fn add_lifetime(&mut self, seconds: u32) {
        self.add_raw_attr(0x000D, &seconds.to_be_bytes());
    }

    pub fn add_xor_peer_address(&mut self, addr: &std::net::SocketAddr) {
        let val = attr::encode_xor_address(addr, &self.txn_id);
        self.add_raw_attr(0x0012, &val);
    }

    /// Build the final message bytes WITHOUT integrity or fingerprint.
    pub fn build_raw(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(HEADER_SIZE + self.attrs_buf.len());
        let typ = encode_msg_type(self.method, self.class);
        msg.extend_from_slice(&typ.to_be_bytes());
        msg.extend_from_slice(&(self.attrs_buf.len() as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&self.txn_id);
        msg.extend_from_slice(&self.attrs_buf);
        msg
    }

    /// Build with MESSAGE-INTEGRITY and FINGERPRINT appended.
    pub fn build_with_integrity(&self, key: &[u8]) -> Vec<u8> {
        use crate::auth;
        let mut msg = Vec::with_capacity(HEADER_SIZE + self.attrs_buf.len() + 24 + 8);
        let typ = encode_msg_type(self.method, self.class);
        // Length includes attrs + MESSAGE-INTEGRITY (4+20=24)
        let len_with_integrity = self.attrs_buf.len() + 24;
        msg.extend_from_slice(&typ.to_be_bytes());
        msg.extend_from_slice(&(len_with_integrity as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&self.txn_id);
        msg.extend_from_slice(&self.attrs_buf);

        // Compute HMAC-SHA1 over msg so far (with length adjusted to include MI)
        let hmac = auth::compute_message_integrity(&msg, key);
        attr::encode_attr(&mut msg, 0x0008, &hmac);

        // Now add FINGERPRINT: adjust length to include fingerprint (4+4=8)
        let total_attr_len = self.attrs_buf.len() + 24 + 8;
        msg[2] = (total_attr_len >> 8) as u8;
        msg[3] = total_attr_len as u8;

        let crc = auth::compute_fingerprint(&msg);
        attr::encode_attr(&mut msg, 0x8028, &crc.to_be_bytes());

        msg
    }

    /// Build with MESSAGE-INTEGRITY only (no FINGERPRINT). Used by long-term auth (RFC 5769 §2.4).
    pub fn build_with_integrity_only(&self, key: &[u8]) -> Vec<u8> {
        use crate::auth;
        let mut msg = Vec::with_capacity(HEADER_SIZE + self.attrs_buf.len() + 24);
        let typ = encode_msg_type(self.method, self.class);
        let len_with_integrity = self.attrs_buf.len() + 24;
        msg.extend_from_slice(&typ.to_be_bytes());
        msg.extend_from_slice(&(len_with_integrity as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&self.txn_id);
        msg.extend_from_slice(&self.attrs_buf);

        let hmac = auth::compute_message_integrity(&msg, key);
        attr::encode_attr(&mut msg, 0x0008, &hmac);
        msg
    }

    /// Build with FINGERPRINT only (no MESSAGE-INTEGRITY).
    pub fn build_with_fingerprint(&self) -> Vec<u8> {
        use crate::auth;
        let mut msg = Vec::with_capacity(HEADER_SIZE + self.attrs_buf.len() + 8);
        let typ = encode_msg_type(self.method, self.class);
        let total_attr_len = self.attrs_buf.len() + 8;
        msg.extend_from_slice(&typ.to_be_bytes());
        msg.extend_from_slice(&(total_attr_len as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&self.txn_id);
        msg.extend_from_slice(&self.attrs_buf);

        let crc = auth::compute_fingerprint(&msg);
        attr::encode_attr(&mut msg, 0x8028, &crc.to_be_bytes());
        msg
    }
}
