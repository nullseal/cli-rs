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
/// Default chunk size for streaming encryption (16 KB plaintext per chunk).
pub const STREAM_CHUNK_SIZE: usize = 16 * 1024;

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

pub fn sha256_bytes(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("{hash:x}")
}

// ── Streaming Encryption ──────────────────────────────────────────────────────

/// Metadata sent once before streaming chunks.
/// Receiver uses this to derive the same key and decrypt each chunk.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StreamEncryptionMetadata {
    pub algorithm: String,
    pub kdf: String,
    pub iterations: u32,
    pub salt: String,
    pub base_iv: String,
    pub chunk_size: usize,
    pub total_chunks: usize,
    pub total_plaintext_size: u64,
}

/// Per-chunk streaming encryptor.
/// Derives the AES-256-GCM key once from password + salt, then encrypts
/// each chunk with IV = base_iv XOR chunk_index.
pub struct StreamCipher {
    cipher: Aes256Gcm,
    base_iv: [u8; IV_LEN],
    salt: [u8; SALT_LEN],
    chunk_index: u64,
    total_chunks: usize,
    total_plaintext_size: u64,
}

impl StreamCipher {
    /// Create a new streaming encryptor for the given password and total plaintext size.
    pub fn new(password: &str, total_plaintext_size: u64) -> Self {
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; SALT_LEN];
        let mut base_iv = [0u8; IV_LEN];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut base_iv);

        let key = derive_key(password, &salt, ITERATIONS);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        let total_chunks = if total_plaintext_size == 0 {
            0
        } else {
            (total_plaintext_size as usize + STREAM_CHUNK_SIZE - 1) / STREAM_CHUNK_SIZE
        };

        Self {
            cipher,
            base_iv,
            salt,
            chunk_index: 0,
            total_chunks,
            total_plaintext_size,
        }
    }

    /// Create with explicit salt and base_iv (for deterministic tests and cross-compat).
    #[allow(dead_code)]
    pub fn with_params(
        password: &str,
        salt: [u8; SALT_LEN],
        base_iv: [u8; IV_LEN],
        total_plaintext_size: u64,
    ) -> Self {
        let key = derive_key(password, &salt, ITERATIONS);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        let total_chunks = if total_plaintext_size == 0 {
            0
        } else {
            (total_plaintext_size as usize + STREAM_CHUNK_SIZE - 1) / STREAM_CHUNK_SIZE
        };

        Self {
            cipher,
            base_iv,
            salt,
            chunk_index: 0,
            total_chunks,
            total_plaintext_size,
        }
    }

    /// Returns the metadata to send to the recipient before streaming.
    pub fn metadata(&self) -> StreamEncryptionMetadata {
        StreamEncryptionMetadata {
            algorithm: "AES-GCM".into(),
            kdf: "PBKDF2".into(),
            iterations: ITERATIONS,
            salt: B64.encode(self.salt),
            base_iv: B64.encode(self.base_iv),
            chunk_size: STREAM_CHUNK_SIZE,
            total_chunks: self.total_chunks,
            total_plaintext_size: self.total_plaintext_size,
        }
    }

    /// Encrypt a single chunk. Returns ciphertext + GCM tag (plaintext.len() + 16 bytes).
    /// Advances the internal chunk counter.
    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.derive_nonce(self.chunk_index);
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| CryptoError::DecryptFailed)?;
        self.chunk_index += 1;
        Ok(ciphertext)
    }

    /// Current chunk index (number of chunks encrypted so far).
    pub fn chunk_index(&self) -> u64 {
        self.chunk_index
    }

    /// Skip to a specific chunk index (for resume support).
    /// The next `encrypt_chunk` call will use this index for nonce derivation.
    pub fn skip_to(&mut self, index: u64) {
        self.chunk_index = index;
    }

    /// Derive nonce for a given chunk index: base_iv XOR index (big-endian in last 8 bytes).
    fn derive_nonce(&self, index: u64) -> [u8; IV_LEN] {
        let mut nonce = self.base_iv;
        let index_bytes = index.to_be_bytes(); // 8 bytes
        // XOR into the last 8 bytes of the 12-byte nonce
        for i in 0..8 {
            nonce[IV_LEN - 8 + i] ^= index_bytes[i];
        }
        nonce
    }
}

/// Per-chunk streaming decryptor.
/// Reconstructs the same key from password + metadata, then decrypts each chunk.
pub struct StreamDecryptor {
    cipher: Aes256Gcm,
    base_iv: [u8; IV_LEN],
    chunk_index: u64,
    #[allow(dead_code)]
    pub total_chunks: usize,
    #[allow(dead_code)]
    pub total_plaintext_size: u64,
}

impl StreamDecryptor {
    /// Create a decryptor from the metadata received from the sender.
    pub fn from_metadata(
        metadata: &StreamEncryptionMetadata,
        password: &str,
    ) -> Result<Self, CryptoError> {
        let salt = B64.decode(&metadata.salt).map_err(|_| CryptoError::DecryptFailed)?;
        let base_iv_vec = B64.decode(&metadata.base_iv).map_err(|_| CryptoError::DecryptFailed)?;

        if salt.len() != SALT_LEN || base_iv_vec.len() != IV_LEN {
            return Err(CryptoError::DecryptFailed);
        }

        let key = derive_key(password, &salt, metadata.iterations);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        let mut base_iv = [0u8; IV_LEN];
        base_iv.copy_from_slice(&base_iv_vec);

        Ok(Self {
            cipher,
            base_iv,
            chunk_index: 0,
            total_chunks: metadata.total_chunks,
            total_plaintext_size: metadata.total_plaintext_size,
        })
    }

    /// Decrypt a single chunk. Returns plaintext.
    /// Advances the internal chunk counter.
    #[allow(dead_code)]
    pub fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.derive_nonce(self.chunk_index);
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| CryptoError::DecryptFailed)?;
        self.chunk_index += 1;
        Ok(plaintext)
    }

    /// Decrypt a chunk at a specific index (for resume support).
    /// Sets internal counter to index + 1 after decryption.
    pub fn decrypt_chunk_at(&mut self, ciphertext: &[u8], index: u64) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.derive_nonce(index);
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| CryptoError::DecryptFailed)?;
        self.chunk_index = index + 1;
        Ok(plaintext)
    }

    /// Current chunk index (number of chunks decrypted so far).
    #[allow(dead_code)]
    pub fn chunk_index(&self) -> u64 {
        self.chunk_index
    }

    /// Skip to a specific chunk index (for resume — recipient already has these chunks).
    pub fn skip_to(&mut self, index: u64) {
        self.chunk_index = index;
    }

    /// Derive nonce for a given chunk index: base_iv XOR index (big-endian in last 8 bytes).
    fn derive_nonce(&self, index: u64) -> [u8; IV_LEN] {
        let mut nonce = self.base_iv;
        let index_bytes = index.to_be_bytes();
        for i in 0..8 {
            nonce[IV_LEN - 8 + i] ^= index_bytes[i];
        }
        nonce
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChallengeMetadata {
    pub salt: String,
    pub iv: String,
    pub iterations: u32,
}

pub struct ChallengeResult {
    pub challenge_plaintext: String,
    pub encrypted_challenge: String,
    pub challenge_metadata: ChallengeMetadata,
}

pub fn generate_challenge(password: &str) -> ChallengeResult {
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    let challenge_plaintext: String = random.iter().map(|b| format!("{b:02x}")).collect();

    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    let password_hash = sha256_hex(password);
    let key = derive_key(&password_hash, &salt, ITERATIONS);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&iv), challenge_plaintext.as_bytes())
        .expect("AES-GCM encryption should not fail");

    ChallengeResult {
        challenge_plaintext,
        encrypted_challenge: B64.encode(&ciphertext),
        challenge_metadata: ChallengeMetadata {
            salt: B64.encode(salt),
            iv: B64.encode(iv),
            iterations: ITERATIONS,
        },
    }
}

pub fn decrypt_challenge(
    encrypted_challenge: &str,
    metadata: &ChallengeMetadata,
    password: &str,
) -> Result<String, CryptoError> {
    let salt = B64.decode(&metadata.salt).map_err(|_| CryptoError::DecryptFailed)?;
    let iv = B64.decode(&metadata.iv).map_err(|_| CryptoError::DecryptFailed)?;
    let ciphertext = B64.decode(encrypted_challenge).map_err(|_| CryptoError::DecryptFailed)?;

    let password_hash = sha256_hex(password);
    let key = derive_key(&password_hash, &salt, metadata.iterations);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let plaintext = cipher
        .decrypt(Nonce::from_slice(&iv), ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptFailed)?;

    String::from_utf8(plaintext).map_err(|_| CryptoError::DecryptFailed)
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

    // ── StreamCipher tests ────────────────────────────────────────────────────

    #[test]
    fn stream_cipher_round_trip_single_chunk() {
        let plaintext = b"hello stream encryption";
        let mut enc = StreamCipher::new("password123", plaintext.len() as u64);
        let meta = enc.metadata();
        let ciphertext = enc.encrypt_chunk(plaintext).unwrap();

        let mut dec = StreamDecryptor::from_metadata(&meta, "password123").unwrap();
        let decrypted = dec.decrypt_chunk(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn stream_cipher_round_trip_multi_chunk() {
        // 40 KB plaintext → 3 chunks (16KB + 16KB + 8KB)
        let plaintext: Vec<u8> = (0..40_000).map(|i| (i % 256) as u8).collect();
        let mut enc = StreamCipher::new("multipass", plaintext.len() as u64);
        let meta = enc.metadata();
        assert_eq!(meta.total_chunks, 3);

        let mut chunks = Vec::new();
        for chunk_data in plaintext.chunks(STREAM_CHUNK_SIZE) {
            chunks.push(enc.encrypt_chunk(chunk_data).unwrap());
        }

        let mut dec = StreamDecryptor::from_metadata(&meta, "multipass").unwrap();
        let mut result = Vec::new();
        for ct in &chunks {
            result.extend(dec.decrypt_chunk(ct).unwrap());
        }
        assert_eq!(result, plaintext);
    }

    #[test]
    fn stream_cipher_wrong_password_fails() {
        let plaintext = b"secret data";
        let mut enc = StreamCipher::new("correct", plaintext.len() as u64);
        let meta = enc.metadata();
        let ciphertext = enc.encrypt_chunk(plaintext).unwrap();

        let mut dec = StreamDecryptor::from_metadata(&meta, "wrong").unwrap();
        assert!(dec.decrypt_chunk(&ciphertext).is_err());
    }

    #[test]
    fn stream_cipher_chunk_index_advances() {
        let mut enc = StreamCipher::new("pass", 32768);
        assert_eq!(enc.chunk_index(), 0);
        enc.encrypt_chunk(&[0u8; 16384]).unwrap();
        assert_eq!(enc.chunk_index(), 1);
        enc.encrypt_chunk(&[0u8; 16384]).unwrap();
        assert_eq!(enc.chunk_index(), 2);
    }

    #[test]
    fn stream_cipher_different_nonces_per_chunk() {
        // Same plaintext, different chunk indices → different ciphertexts
        let plaintext = [42u8; 100];
        let salt = [0u8; SALT_LEN];
        let base_iv = [0u8; IV_LEN];
        let mut enc = StreamCipher::with_params("pass", salt, base_iv, 200);
        let ct1 = enc.encrypt_chunk(&plaintext).unwrap();
        let ct2 = enc.encrypt_chunk(&plaintext).unwrap();
        assert_ne!(ct1, ct2); // different nonces → different ciphertext
    }

    #[test]
    fn stream_cipher_resume_decrypt_at() {
        let plaintext: Vec<u8> = (0..48_000).map(|i| (i % 256) as u8).collect();
        let chunks: Vec<&[u8]> = plaintext.chunks(STREAM_CHUNK_SIZE).collect();
        let mut enc = StreamCipher::new("resume", plaintext.len() as u64);
        let meta = enc.metadata();

        let mut encrypted: Vec<Vec<u8>> = Vec::new();
        for c in &chunks {
            encrypted.push(enc.encrypt_chunk(c).unwrap());
        }

        // Simulate resume: skip first chunk, decrypt from index 1
        let mut dec = StreamDecryptor::from_metadata(&meta, "resume").unwrap();
        dec.skip_to(1);
        let d1 = dec.decrypt_chunk(&encrypted[1]).unwrap();
        assert_eq!(d1, chunks[1]);
        let d2 = dec.decrypt_chunk(&encrypted[2]).unwrap();
        assert_eq!(d2, chunks[2]);
    }

    #[test]
    fn stream_cipher_deterministic_cross_compat() {
        // Deterministic params for cross-platform testing with TypeScript
        let salt: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let base_iv: [u8; 12] = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120];
        let password = "streamtest";
        let plaintext = b"streaming cross compat test data";

        let mut enc = StreamCipher::with_params(password, salt, base_iv, plaintext.len() as u64);
        let meta = enc.metadata();
        let ciphertext = enc.encrypt_chunk(plaintext).unwrap();

        // Verify metadata encodes correctly
        assert_eq!(meta.salt, "AAECAwQFBgcICQoLDA0ODw==");
        assert_eq!(meta.base_iv, "ChQeKDI8RlBaZG54");
        assert_eq!(meta.chunk_size, STREAM_CHUNK_SIZE);
        assert_eq!(meta.total_chunks, 1);
        assert_eq!(meta.total_plaintext_size, 32);

        // Round-trip
        let mut dec = StreamDecryptor::from_metadata(&meta, password).unwrap();
        let decrypted = dec.decrypt_chunk(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn stream_cipher_metadata_serialization() {
        let enc = StreamCipher::new("pass", 100_000);
        let meta = enc.metadata();
        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: StreamEncryptionMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.algorithm, "AES-GCM");
        assert_eq!(deserialized.iterations, ITERATIONS);
        assert_eq!(deserialized.chunk_size, STREAM_CHUNK_SIZE);
        assert_eq!(deserialized.total_chunks, 7); // ceil(100000/16384)
    }
}
