//! STUN authentication: long-term credential key, HMAC-SHA1 MESSAGE-INTEGRITY, CRC32 FINGERPRINT.

use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use md5::Digest;

type HmacSha1 = Hmac<Sha1>;

/// XOR constant for FINGERPRINT (RFC 5389 §15.5).
const FINGERPRINT_XOR: u32 = 0x5354554E;

/// Compute the long-term credential key: MD5(username ":" realm ":" password).
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let input = format!("{}:{}:{}", username, realm, password);
    let digest = Md5::digest(input.as_bytes());
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest);
    key
}

/// Compute MESSAGE-INTEGRITY: HMAC-SHA1 over the message bytes.
/// The message passed in must already have its length field adjusted to include
/// the MESSAGE-INTEGRITY attribute (header says attrs end at MI inclusive).
pub fn compute_message_integrity(msg: &[u8], key: &[u8]) -> [u8; 20] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let result = mac.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// Verify MESSAGE-INTEGRITY of a message.
/// `msg_up_to_mi` is the message bytes from the start up to (not including) the MI attribute TLV,
/// with the header length field adjusted to include MI.
pub fn verify_message_integrity(msg_up_to_mi: &[u8], key: &[u8], expected: &[u8; 20]) -> bool {
    let computed = compute_message_integrity(msg_up_to_mi, key);
    // Constant-time compare
    computed == *expected
}

/// Compute FINGERPRINT: CRC32 over message bytes XOR'd with 0x5354554E.
/// The message passed in must have its length field adjusted to include the FINGERPRINT attribute.
pub fn compute_fingerprint(msg: &[u8]) -> u32 {
    use crc::{Crc, CRC_32_ISO_HDLC};
    const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    CRC32.checksum(msg) ^ FINGERPRINT_XOR
}
