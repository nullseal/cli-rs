//! STUN/TURN attribute types and TLV encode/decode (4-byte padded).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::message::MAGIC_COOKIE;

/// Well-known STUN/TURN attribute type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AttrType {
    MappedAddress = 0x0001,
    Username = 0x0006,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    Lifetime = 0x000D,
    Data = 0x0013,
    Realm = 0x0014,
    Nonce = 0x0015,
    XorRelayedAddress = 0x0016,
    RequestedTransport = 0x0019,
    XorMappedAddress = 0x0020,
    XorPeerAddress = 0x0012,
    Software = 0x8022,
    Fingerprint = 0x8028,
    // ICE attributes (used in RFC 5769 test vectors)
    Priority = 0x0024,
    IceControlled = 0x8029,
}

impl AttrType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0001 => Some(Self::MappedAddress),
            0x0006 => Some(Self::Username),
            0x0008 => Some(Self::MessageIntegrity),
            0x0009 => Some(Self::ErrorCode),
            0x000D => Some(Self::Lifetime),
            0x0013 => Some(Self::Data),
            0x0014 => Some(Self::Realm),
            0x0015 => Some(Self::Nonce),
            0x0016 => Some(Self::XorRelayedAddress),
            0x0019 => Some(Self::RequestedTransport),
            0x0020 => Some(Self::XorMappedAddress),
            0x0012 => Some(Self::XorPeerAddress),
            0x8022 => Some(Self::Software),
            0x8028 => Some(Self::Fingerprint),
            0x0024 => Some(Self::Priority),
            0x8029 => Some(Self::IceControlled),
            _ => None,
        }
    }
}

/// A decoded STUN attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    Software(String),
    Username(String),
    Realm(String),
    Nonce(String),
    MessageIntegrity([u8; 20]),
    Fingerprint(u32),
    XorMappedAddress(SocketAddr),
    XorRelayedAddress(SocketAddr),
    XorPeerAddress(SocketAddr),
    MappedAddress(SocketAddr),
    ErrorCode { code: u16, reason: String },
    Lifetime(u32),
    RequestedTransport(u8),
    Data(Vec<u8>),
    Priority(u32),
    IceControlled(u64),
    Unknown { typ: u16, data: Vec<u8> },
}

/// Pad length to 4-byte boundary.
pub fn padded_len(len: usize) -> usize {
    (len + 3) & !3
}

/// Encode an attribute into the buffer (type + length + value + padding).
pub fn encode_attr(buf: &mut Vec<u8>, typ: u16, value: &[u8]) {
    buf.extend_from_slice(&typ.to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
    // Pad to 4-byte boundary with zeros
    let pad = padded_len(value.len()) - value.len();
    for _ in 0..pad {
        buf.push(0x00);
    }
}

/// Encode an XOR-mapped address attribute value (no TLV header).
pub fn encode_xor_address(addr: &SocketAddr, txn_id: &[u8; 12]) -> Vec<u8> {
    let mut val = Vec::new();
    val.push(0x00); // reserved
    match addr.ip() {
        IpAddr::V4(ip) => {
            val.push(0x01); // family IPv4
            let xport = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
            val.extend_from_slice(&xport.to_be_bytes());
            let ip_bytes = ip.octets();
            let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                val.push(ip_bytes[i] ^ cookie_bytes[i]);
            }
        }
        IpAddr::V6(ip) => {
            val.push(0x02); // family IPv6
            let xport = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
            val.extend_from_slice(&xport.to_be_bytes());
            let ip_bytes = ip.octets();
            let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
            // XOR with magic cookie (4 bytes) || transaction id (12 bytes)
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&cookie_bytes);
            xor_key[4..].copy_from_slice(txn_id);
            for i in 0..16 {
                val.push(ip_bytes[i] ^ xor_key[i]);
            }
        }
    }
    val
}

/// Decode an XOR-mapped address from attribute value bytes.
pub fn decode_xor_address(data: &[u8], txn_id: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < 4 {
        return None;
    }
    let family = data[1];
    let xport = u16::from_be_bytes([data[2], data[3]]);
    let port = xport ^ (MAGIC_COOKIE >> 16) as u16;
    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();

    match family {
        0x01 => {
            // IPv4
            if data.len() < 8 {
                return None;
            }
            let mut ip = [0u8; 4];
            for i in 0..4 {
                ip[i] = data[4 + i] ^ cookie_bytes[i];
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return None;
            }
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&cookie_bytes);
            xor_key[4..].copy_from_slice(txn_id);
            let mut ip = [0u8; 16];
            for i in 0..16 {
                ip[i] = data[4 + i] ^ xor_key[i];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => None,
    }
}

/// Decode attributes from a byte slice (starting after the 20-byte STUN header).
pub fn decode_attrs(data: &[u8], txn_id: &[u8; 12]) -> Vec<Attribute> {
    let mut attrs = Vec::new();
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let typ = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + len > data.len() {
            break;
        }
        let value = &data[pos..pos + len];
        let attr = match AttrType::from_u16(typ) {
            Some(AttrType::Software) => {
                Attribute::Software(String::from_utf8_lossy(value).into_owned())
            }
            Some(AttrType::Username) => {
                Attribute::Username(String::from_utf8_lossy(value).into_owned())
            }
            Some(AttrType::Realm) => {
                Attribute::Realm(String::from_utf8_lossy(value).into_owned())
            }
            Some(AttrType::Nonce) => {
                Attribute::Nonce(String::from_utf8_lossy(value).into_owned())
            }
            Some(AttrType::MessageIntegrity) => {
                if len == 20 {
                    let mut hmac = [0u8; 20];
                    hmac.copy_from_slice(value);
                    Attribute::MessageIntegrity(hmac)
                } else {
                    Attribute::Unknown { typ, data: value.to_vec() }
                }
            }
            Some(AttrType::Fingerprint) => {
                if len == 4 {
                    let v = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                    Attribute::Fingerprint(v)
                } else {
                    Attribute::Unknown { typ, data: value.to_vec() }
                }
            }
            Some(AttrType::XorMappedAddress) => {
                match decode_xor_address(value, txn_id) {
                    Some(addr) => Attribute::XorMappedAddress(addr),
                    None => Attribute::Unknown { typ, data: value.to_vec() },
                }
            }
            Some(AttrType::XorRelayedAddress) => {
                match decode_xor_address(value, txn_id) {
                    Some(addr) => Attribute::XorRelayedAddress(addr),
                    None => Attribute::Unknown { typ, data: value.to_vec() },
                }
            }
            Some(AttrType::XorPeerAddress) => {
                match decode_xor_address(value, txn_id) {
                    Some(addr) => Attribute::XorPeerAddress(addr),
                    None => Attribute::Unknown { typ, data: value.to_vec() },
                }
            }
            Some(AttrType::MappedAddress) => {
                Attribute::Unknown { typ, data: value.to_vec() }
            }
            Some(AttrType::ErrorCode) => {
                if len >= 4 {
                    let class = (value[2] & 0x07) as u16;
                    let number = value[3] as u16;
                    let code = class * 100 + number;
                    let reason = String::from_utf8_lossy(&value[4..]).into_owned();
                    Attribute::ErrorCode { code, reason }
                } else {
                    Attribute::Unknown { typ, data: value.to_vec() }
                }
            }
            Some(AttrType::Lifetime) => {
                if len == 4 {
                    let v = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                    Attribute::Lifetime(v)
                } else {
                    Attribute::Unknown { typ, data: value.to_vec() }
                }
            }
            Some(AttrType::RequestedTransport) => {
                if len >= 1 {
                    Attribute::RequestedTransport(value[0])
                } else {
                    Attribute::Unknown { typ, data: value.to_vec() }
                }
            }
            Some(AttrType::Data) => {
                Attribute::Data(value.to_vec())
            }
            Some(AttrType::Priority) => {
                if len == 4 {
                    let v = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                    Attribute::Priority(v)
                } else {
                    Attribute::Unknown { typ, data: value.to_vec() }
                }
            }
            Some(AttrType::IceControlled) => {
                if len == 8 {
                    let v = u64::from_be_bytes([
                        value[0], value[1], value[2], value[3],
                        value[4], value[5], value[6], value[7],
                    ]);
                    Attribute::IceControlled(v)
                } else {
                    Attribute::Unknown { typ, data: value.to_vec() }
                }
            }
            None => Attribute::Unknown { typ, data: value.to_vec() },
        };
        attrs.push(attr);
        pos += padded_len(len);
    }
    attrs
}

/// Encode an ERROR-CODE attribute value.
pub fn encode_error_code(code: u16, reason: &str) -> Vec<u8> {
    let class = (code / 100) as u8;
    let number = (code % 100) as u8;
    let mut val = vec![0x00, 0x00, class, number];
    val.extend_from_slice(reason.as_bytes());
    val
}
