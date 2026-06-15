use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const ITERATIONS: u32 = 250_000;
const SALT_LEN: usize = 16;
const IV_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    pub kdf: String,
    pub iterations: u32,
    pub salt: String,
    pub iv: String,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Wrong password or corrupted data")]
    DecryptFailed,
}

pub struct EncryptResult {
    pub encrypted_payload: String,
    pub encryption_metadata: EncryptionMetadata,
}

fn derive_key(password: &str, salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    key
}

pub fn encrypt_bytes(plaintext: &[u8], password: &str) -> EncryptResult {
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);
    encrypt_bytes_with(&salt, &iv, plaintext, password)
}

fn encrypt_bytes_with(salt: &[u8], iv: &[u8], plaintext: &[u8], password: &str) -> EncryptResult {
    let key = derive_key(password, salt, ITERATIONS);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(iv), plaintext)
        .expect("AES-GCM encryption should not fail");

    EncryptResult {
        encrypted_payload: B64.encode(&ciphertext),
        encryption_metadata: EncryptionMetadata {
            algorithm: "AES-GCM".into(),
            kdf: "PBKDF2".into(),
            iterations: ITERATIONS,
            salt: B64.encode(salt),
            iv: B64.encode(iv),
        },
    }
}

pub fn decrypt_bytes(
    encrypted_payload: &str,
    metadata: &EncryptionMetadata,
    password: &str,
) -> Result<Vec<u8>, CryptoError> {
    let salt = B64.decode(&metadata.salt).map_err(|_| CryptoError::DecryptFailed)?;
    let iv = B64.decode(&metadata.iv).map_err(|_| CryptoError::DecryptFailed)?;
    let ciphertext = B64.decode(encrypted_payload).map_err(|_| CryptoError::DecryptFailed)?;

    let key = derive_key(password, &salt, metadata.iterations);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    cipher
        .decrypt(Nonce::from_slice(&iv), ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptFailed)
}

pub fn sha256_hex(text: &str) -> String {
    let hash = Sha256::digest(text.as_bytes());
    format!("{hash:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_text() {
        let plain = b"hello world";
        let result = encrypt_bytes(plain, "strongpassword");
        let decrypted =
            decrypt_bytes(&result.encrypted_payload, &result.encryption_metadata, "strongpassword")
                .unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn round_trip_binary() {
        let plain: Vec<u8> = (0u8..=255).collect();
        let result = encrypt_bytes(&plain, "anotherpassword");
        let decrypted = decrypt_bytes(
            &result.encrypted_payload,
            &result.encryption_metadata,
            "anotherpassword",
        )
        .unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn wrong_password_fails() {
        let result = encrypt_bytes(b"secret", "correct");
        let err =
            decrypt_bytes(&result.encrypted_payload, &result.encryption_metadata, "wrong");
        assert!(err.is_err());
    }

    #[test]
    fn sha256_hex_known_value() {
        // echo -n "password" | sha256sum
        assert_eq!(
            sha256_hex("password"),
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        );
    }

    #[test]
    fn metadata_fields_are_correct() {
        let result = encrypt_bytes(b"test", "pass");
        let m = &result.encryption_metadata;
        assert_eq!(m.algorithm, "AES-GCM");
        assert_eq!(m.kdf, "PBKDF2");
        assert_eq!(m.iterations, 250_000);
        assert_eq!(B64.decode(&m.salt).unwrap().len(), SALT_LEN);
        assert_eq!(B64.decode(&m.iv).unwrap().len(), IV_LEN);
    }

    // Cross-compatibility test: uses deterministic salt+iv to produce a ciphertext,
    // then verifies Rust can both encrypt and decrypt using the same key material as
    // the Web Crypto API would use with those parameters.
    #[test]
    fn ts_cross_compat_deterministic() {
        let salt: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let iv: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let password = "testpassword";
        let plaintext = b"cross compat";

        let result = encrypt_bytes_with(&salt, &iv, plaintext, password);
        let decrypted =
            decrypt_bytes(&result.encrypted_payload, &result.encryption_metadata, password)
                .unwrap();
        assert_eq!(decrypted, plaintext);
        // metadata encodes to standard base64 (not URL-safe), matching Node.js Buffer.from().toString('base64')
        assert_eq!(result.encryption_metadata.salt, "AAECAwQFBgcICQoLDA0ODw==");
        assert_eq!(result.encryption_metadata.iv, "AAECAwQFBgcICQoL");
    }
}
