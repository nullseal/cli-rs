use std::path::PathBuf;

use anyhow::{bail, Result};

use crate::api::{ApiClient, P2PVerifyError};
use crate::crypto::{decrypt_bytes, decrypt_challenge, sha256_bytes, sha256_hex};
use crate::local_signal::SignalClient;
use crate::socket::P2PSocket;
use crate::webrtc::ReceiverPeer;

use super::{confirm_unsafe_file, prompt_manual_retry};

const MIN_PASSWORD_LEN: usize = 3;

fn server_url(server: Option<&str>) -> Result<String> {
    server
        .map(str::to_owned)
        .or_else(|| std::env::var("CLI_APPS_CORE_URL").ok())
        .or_else(|| option_env!("CLI_APPS_CORE_URL").map(str::to_owned))
        .ok_or_else(|| anyhow::anyhow!("CLI_APPS_CORE_URL environment variable is not set"))
}

// ── URL parsing ───────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub enum ParsedUrl {
    Server { id: String },
    P2p { id: String },
    BareId { id: String },
}

pub fn parse_share_url(input: &str) -> ParsedUrl {
    // Only parse as URL if it starts with http
    if input.starts_with("http://") || input.starts_with("https://") {
        if let Ok(url) = url::Url::parse(input) {
            let parts: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();
            match parts.as_slice() {
                ["p2p", id] => return ParsedUrl::P2p { id: id.to_string() },
                ["s", id] => return ParsedUrl::Server { id: id.to_string() },
                _ => {}
            }
        }
    }
    // Support "p2p/ID" and "s/ID" prefix without full URL
    if let Some(id) = input.strip_prefix("p2p/") {
        if !id.is_empty() {
            return ParsedUrl::P2p { id: id.to_owned() };
        }
    }
    if let Some(id) = input.strip_prefix("s/") {
        if !id.is_empty() {
            return ParsedUrl::Server { id: id.to_owned() };
        }
    }
    ParsedUrl::BareId { id: input.to_owned() }
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(
    url_or_id: impl Into<String>,
    password: impl Into<String>,
    output_dir: Option<String>,
    server: Option<String>,
    log: &mut dyn FnMut(&str),
) -> Result<()> {
    let url_or_id = url_or_id.into();
    let password = password.into();

    if password.len() < MIN_PASSWORD_LEN {
        bail!("Password must be at least {MIN_PASSWORD_LEN} characters.");
    }

    match parse_share_url(&url_or_id) {
        ParsedUrl::Server { id } => {
            run_server(&id, &password, output_dir.as_deref(), server.as_deref(), log).await
        }
        ParsedUrl::P2p { id } => {
            run_p2p(&id, &password, output_dir.as_deref(), server.as_deref(), log).await
        }
        ParsedUrl::BareId { id } => {
            // Try server first; if not found, fall back to P2P
            let result = run_server(&id, &password, output_dir.as_deref(), server.as_deref(), log).await;
            if matches!(&result, Err(e) if e.to_string().contains("not found")) {
                return run_p2p(&id, &password, output_dir.as_deref(), server.as_deref(), log).await;
            }
            result
        }
    }
}

// ── Server mode ───────────────────────────────────────────────────────────────

async fn run_server(
    share_id: &str,
    password: &str,
    output_dir: Option<&str>,
    server: Option<&str>,
    log: &mut dyn FnMut(&str),
) -> Result<()> {
    let client = ApiClient::new(server_url(server)?);

    // Step 1: fetch metadata (includes encrypted challenge + verifyId)
    let metadata = client.get_share_metadata(share_id).await?;

    // Step 2: decrypt challenge to prove password knowledge
    let answer = decrypt_challenge(
        &metadata.encrypted_challenge,
        &metadata.challenge_metadata,
        password,
    )
    .map_err(|_| anyhow::anyhow!("Wrong password or corrupted data"))?;

    // Step 3: submit answer to get payload (server auto-consumes one-time shares)
    let payload = client.get_share_payload(share_id, &answer, &metadata.verify_id).await?;
    log(&format!("Received {}, decrypting…", super::format_size(payload.encrypted_payload.len())));
    let decrypted = decrypt_bytes(&payload.encrypted_payload, &payload.encryption_metadata, password)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let actual_checksum = sha256_bytes(&decrypted);
    if actual_checksum != payload.content_checksum {
        eprintln!("\x1b[1;33m⚠\x1b[0m Warning: Content integrity check failed. This share may have been tampered with.");
        if !metadata.one_time_read {
            let _ = client.report_malformed(share_id).await;
        }
    }

    if payload.content_type == "file" {
        if let Some(fm) = &payload.file_metadata {
            let dir = output_dir.unwrap_or(".");
            let filepath = PathBuf::from(dir).join(&fm.filename);
            confirm_unsafe_file(&fm.filename)?;
            if filepath.exists() {
                bail!("File already exists: {}", filepath.display());
            }
            std::fs::write(&filepath, &decrypted)?;
            log(&format!("Saved: {}", filepath.display()));
            return Ok(());
        }
    }

    log(std::str::from_utf8(&decrypted).unwrap_or("(binary data)"));
    Ok(())
}

// ── P2P mode ──────────────────────────────────────────────────────────────────

async fn run_p2p(
    session_id: &str,
    password: &str,
    output_dir: Option<&str>,
    server: Option<&str>,
    log: &mut dyn FnMut(&str),
) -> Result<()> {
    let base = server_url(server)?;
    let client = ApiClient::new(&base);

    // 1. Check session status
    let session = client.get_p2p_session(session_id).await?;
    if session.status == "expired" {
        bail!("Session is expired or unavailable.");
    }

    // 2. Verify password
    let proof = sha256_hex(password);
    client.verify_p2p_session(session_id, &proof).await.map_err(|e| match e {
        P2PVerifyError::WrongPassword { attempts_left } => {
            anyhow::anyhow!("Wrong password. {attempts_left} attempt(s) left.")
        }
        P2PVerifyError::IpBlocked => {
            anyhow::anyhow!("Too many failed attempts. Try again in 1 hour.")
        }
        P2PVerifyError::Api(api_err) => anyhow::anyhow!("{api_err}"),
    })?;

    // 3. Fetch ICE servers
    let ice_servers = client.get_ice_servers().await.unwrap_or_default();

    // 4. Connect socket as recipient
    let (socket, mut events) = P2PSocket::connect(&base, session_id, "recipient").await?;

    // 5. Wait for joined ack
    events
        .joined
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("socket closed before joined"))?;
    log("Connected. Waiting for sender…");

    // Retry loop for WebRTC connection + transfer
    const MAX_RETRIES: u32 = 3;
    const BACKOFF_MS: [u64; 3] = [1000, 2000, 4000];

    const OFFER_TIMEOUT_SECS: u64 = 10;

    let mut attempt = 0u32;
    let mut last_chunk_index: i64 = -1;
    let mut all_chunks: Vec<String> = Vec::new();

    loop {
        // 6. Wait for SDP offer from sender — with timeout during retries
        let offer_result = if attempt == 0 {
            // First attempt: wait indefinitely for sender's offer
            let offer = loop {
                tokio::select! {
                    biased;
                    o = events.offer.recv() => {
                        if let Some(offer) = o {
                            break offer;
                        }
                        bail!("socket closed before offer");
                    }
                    err = events.error.recv() => {
                        if let Some(code) = err {
                            bail!("signaling error: {code}");
                        }
                    }
                }
            };
            Some(offer)
        } else {
            // Retry: timeout if offer doesn't arrive within 10s
            let mut got_offer = None;
            tokio::select! {
                biased;
                o = events.offer.recv() => {
                    if let Some(offer) = o {
                        got_offer = Some(offer);
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(OFFER_TIMEOUT_SECS)) => {}
            }
            got_offer
        };

        let offer = match offer_result {
            Some(o) => o,
            None => {
                attempt += 1;
                if attempt > MAX_RETRIES {
                    if !prompt_manual_retry().await {
                        bail!("Sender did not reconnect after {MAX_RETRIES} retries.");
                    }
                    attempt = 0;
                    socket.emit_join(session_id, "recipient")?;
                    continue;
                }
                let delay = BACKOFF_MS.get((attempt - 1) as usize).copied().unwrap_or(4000);
                eprintln!("\x1b[1;33m⟳\x1b[0m Retrying ({attempt}/{MAX_RETRIES}) — no offer received…");
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                socket.emit_join(session_id, "recipient")?;
                continue;
            }
        };

        // 7. Create WebRTC receiver peer from offer, send answer back
        let mut receiver = ReceiverPeer::from_offer(offer, ice_servers.clone(), None).await?;
        socket.send_answer(receiver.answer_sdp_json()).await?;

        // 8. Relay ICE candidates while waiting for DataChannel open (10s timeout)
        let channel_open;
        let channel_result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            async {
                loop {
                    tokio::select! {
                        biased;
                        event = receiver.next_event() => {
                            match event {
                                Some(crate::webrtc::LoopEvent::ChannelOpen) => return Ok::<bool, anyhow::Error>(true),
                                Some(crate::webrtc::LoopEvent::Error(e)) => {
                                    eprintln!("\x1b[1;33m⚠\x1b[0m WebRTC error: {e}");
                                    return Ok(false);
                                }
                                Some(crate::webrtc::LoopEvent::Done) | None => return Ok(false),
                                _ => {}
                            }
                        }
                        ice = events.ice.recv() => {
                            if let Some(c) = ice {
                                receiver.add_ice_candidate(c)?;
                            }
                        }
                    }
                }
            },
        )
        .await;
        channel_open = matches!(channel_result, Ok(Ok(true)));

        if !channel_open {
            attempt += 1;
            if attempt > MAX_RETRIES {
                if !prompt_manual_retry().await {
                    bail!("WebRTC connection failed after {MAX_RETRIES} retries.");
                }
                attempt = 0;
                socket.emit_join(session_id, "recipient")?;
                continue;
            }
            let delay = BACKOFF_MS.get((attempt - 1) as usize).copied().unwrap_or(4000);
            eprintln!("\x1b[1;33m⟳\x1b[0m Retrying ({attempt}/{MAX_RETRIES})…");
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            socket.emit_join(session_id, "recipient")?;
            continue;
        }

        // Reset retry counter on successful connection
        attempt = 0;

        log("Transfer started…");

        // 9. Send resume frame to sender
        receiver.send_resume(last_chunk_index)?;

        // 10. Collect the full transfer (metadata + chunks + end)
        let mut round_chunks: Vec<String> = Vec::new();
        let prior_bytes: usize = all_chunks.iter().map(|c| c.len()).sum();
        let transfer_result = receiver.receive_transfer(&proof, &|received, total| {
            let effective = prior_bytes + received;
            eprint!("\rReceiving: {}/{}\x1b[K", super::format_size(effective), super::format_size(total));
        }, &mut round_chunks).await;

        match transfer_result {
            Ok(transfer) => {
                eprintln!();

                // Build full payload from prior rounds + this round
                let full_payload = if all_chunks.is_empty() {
                    transfer.encrypted_payload
                } else {
                    let prior: String = all_chunks.concat();
                    format!("{}{}", prior, transfer.encrypted_payload)
                };

                // 11. Decrypt
                let decrypted = decrypt_bytes(
                    &full_payload,
                    &transfer.encryption_metadata,
                    password,
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;

                if let Some(expected) = &transfer.content_checksum {
                    let actual = sha256_bytes(&decrypted);
                    if actual != *expected {
                        eprintln!("\x1b[1;33m⚠\x1b[0m Warning: Content integrity check failed. This share may have been tampered with.");
                    }
                }

                // 12. Output
                if transfer.content_type == "file" {
                    if let Some(fm) = &transfer.file_metadata {
                        let filename = fm["filename"]
                            .as_str()
                            .unwrap_or("received_file");
                        let dir = output_dir.unwrap_or(".");
                        let filepath = PathBuf::from(dir).join(filename);
                        confirm_unsafe_file(filename)?;
                        if filepath.exists() {
                            bail!("File already exists: {}", filepath.display());
                        }
                        std::fs::write(&filepath, &decrypted)?;
                        log(&format!("Saved: {}", filepath.display()));
                    } else {
                        log(std::str::from_utf8(&decrypted).unwrap_or("(binary data)"));
                    }
                } else {
                    log(std::str::from_utf8(&decrypted).unwrap_or("(binary data)"));
                }

                // 13. Cleanup
                receiver.close();
                socket.disconnect().await?;
                return Ok(());
            }
            Err(e) => {
                // Save partial chunks for resume on next attempt
                last_chunk_index += round_chunks.len() as i64;
                all_chunks.extend(round_chunks);

                // Transfer interrupted — retry if possible
                attempt += 1;
                if attempt > MAX_RETRIES {
                    if !prompt_manual_retry().await {
                        bail!("Transfer failed after {MAX_RETRIES} retries: {e}");
                    }
                    attempt = 0;
                    socket.emit_join(session_id, "recipient")?;
                    continue;
                }
                let delay = BACKOFF_MS.get((attempt - 1) as usize).copied().unwrap_or(4000);
                eprintln!("\n\x1b[1;33m⟳\x1b[0m Transfer interrupted: {e}. Retrying ({attempt}/{MAX_RETRIES})…");
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                socket.emit_join(session_id, "recipient")?;
                continue;
            }
        }
    }
}

// ── Local mode (no server) ────────────────────────────────────────────────────

/// Fully local receive — connects to sender's TCP signaling server, does WebRTC locally.
pub async fn run_local(
    password: impl Into<String>,
    output_dir: Option<String>,
    ip: Option<String>,
    log: &mut dyn FnMut(&str),
) -> Result<()> {
    let password = password.into();
    if password.len() < MIN_PASSWORD_LEN {
        bail!("Password must be at least {MIN_PASSWORD_LEN} characters.");
    }

    let proof = sha256_hex(&password);

    // 1. Resolve sender address
    let addr = match ip {
        Some(a) => {
            eprintln!("\x1b[1;34m📡\x1b[0m Connecting to {a}…");
            a
        }
        None => crate::local::discover_addr(std::time::Duration::from_secs(30))?,
    };

    // 2. Connect to sender's signaling server
    let mut signal = SignalClient::connect(&addr).await?;
    log("Connected to sender.");

    // 3. Wait for offer
    let msg = signal.recv_or_bail().await?;
    let offer = match msg["type"].as_str() {
        Some("offer") => msg,
        _ => bail!("expected offer, got: {}", msg["type"]),
    };

    // 4. Create WebRTC receiver peer from offer, send answer back
    let bind_ip: Option<std::net::IpAddr> = addr.split(':')
        .next()
        .and_then(|h| h.parse().ok());
    let mut receiver = ReceiverPeer::from_offer(offer, vec![], bind_ip).await?;
    signal.send_answer(receiver.answer_sdp_json()).await?;

    // 5. Wait for DataChannel open
    loop {
        match receiver.next_event().await {
            Some(crate::webrtc::LoopEvent::ChannelOpen) => {
                log("Transfer started…");
                break;
            }
            Some(crate::webrtc::LoopEvent::Error(e)) => bail!("WebRTC error: {e}"),
            Some(crate::webrtc::LoopEvent::Done) | None => bail!("WebRTC closed before transfer"),
            _ => {}
        }
    }

    // 6. Receive transfer (verify + metadata + chunks + end)
    let mut chunks: Vec<String> = Vec::new();
    let transfer = receiver.receive_transfer(&proof, &|received, total| {
        eprint!("\rReceiving: {}/{}\x1b[K", super::format_size(received), super::format_size(total));
    }, &mut chunks).await?;
    eprintln!();

    // 7. Decrypt
    let decrypted = decrypt_bytes(
        &transfer.encrypted_payload,
        &transfer.encryption_metadata,
        &password,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    if let Some(expected) = &transfer.content_checksum {
        let actual = sha256_bytes(&decrypted);
        if actual != *expected {
            eprintln!("\x1b[1;33m⚠\x1b[0m Warning: Content integrity check failed. This share may have been tampered with.");
        }
    }

    // 8. Output
    if transfer.content_type == "file" {
        if let Some(fm) = &transfer.file_metadata {
            let filename = fm["filename"]
                .as_str()
                .unwrap_or("received_file");
            let dir = output_dir.as_deref().unwrap_or(".");
            let filepath = PathBuf::from(dir).join(filename);
            confirm_unsafe_file(filename)?;
            if filepath.exists() {
                bail!("File already exists: {}", filepath.display());
            }
            std::fs::write(&filepath, &decrypted)?;
            log(&format!("Saved: {}", filepath.display()));
        } else {
            log(std::str::from_utf8(&decrypted).unwrap_or("(binary data)"));
        }
    } else {
        log(std::str::from_utf8(&decrypted).unwrap_or("(binary data)"));
    }

    // 9. Cleanup
    receiver.close();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use crate::crypto::{encrypt_bytes, generate_challenge, sha256_bytes};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mock_server() -> (MockServer, String) {
        let server = MockServer::start().await;
        let url = server.uri();
        (server, url)
    }

    // ── parse_share_url ──────────────────────────────────────────────────────

    #[test]
    fn parses_server_url() {
        assert_eq!(
            parse_share_url("https://nullseal.com/s/abc123"),
            ParsedUrl::Server { id: "abc123".into() }
        );
    }

    #[test]
    fn parses_p2p_url() {
        assert_eq!(
            parse_share_url("https://nullseal.com/p2p/sess123"),
            ParsedUrl::P2p { id: "sess123".into() }
        );
    }

    #[test]
    fn bare_id_is_bare_id() {
        assert_eq!(
            parse_share_url("abc123def456"),
            ParsedUrl::BareId { id: "abc123def456".into() }
        );
    }

    #[test]
    fn p2p_prefix_is_p2p_mode() {
        assert_eq!(
            parse_share_url("p2p/sess456"),
            ParsedUrl::P2p { id: "sess456".into() }
        );
    }

    #[test]
    fn s_prefix_is_server_mode() {
        assert_eq!(
            parse_share_url("s/abc789"),
            ParsedUrl::Server { id: "abc789".into() }
        );
    }

    // ── server get ───────────────────────────────────────────────────────────

    /// Helper: mount both metadata and payload mocks for a text share.
    async fn mount_text_share(server: &MockServer, share_id: &str, plaintext: &[u8], password: &str) {
        let r = encrypt_bytes(plaintext, password);
        let challenge = generate_challenge(password);
        let verify_id = "v".repeat(32);
        let checksum = sha256_bytes(plaintext);

        Mock::given(method("GET"))
            .and(path(format!("/shares/{share_id}/metadata")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "shareId": share_id,
                "contentType": "text",
                "oneTimeRead": false,
                "encryptedChallenge": challenge.encrypted_challenge,
                "challengeMetadata": {
                    "salt": challenge.challenge_metadata.salt,
                    "iv": challenge.challenge_metadata.iv,
                    "iterations": challenge.challenge_metadata.iterations
                },
                "verifyId": verify_id,
                "contentChecksum": checksum
            })))
            .mount(server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/shares/{share_id}/payload")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "contentType": "text",
                "encryptedPayload": r.encrypted_payload,
                "encryptionMetadata": {
                    "algorithm": r.encryption_metadata.algorithm,
                    "kdf": r.encryption_metadata.kdf,
                    "iterations": r.encryption_metadata.iterations,
                    "salt": r.encryption_metadata.salt,
                    "iv": r.encryption_metadata.iv
                },
                "fileMetadata": null,
                "contentChecksum": checksum
            })))
            .mount(server)
            .await;
    }

    /// Helper: mount both metadata and payload mocks for a file share.
    async fn mount_file_share(server: &MockServer, share_id: &str, content: &[u8], password: &str, filename: &str) {
        let r = encrypt_bytes(content, password);
        let challenge = generate_challenge(password);
        let verify_id = "v".repeat(32);
        let checksum = sha256_bytes(content);

        Mock::given(method("GET"))
            .and(path(format!("/shares/{share_id}/metadata")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "shareId": share_id,
                "contentType": "file",
                "oneTimeRead": false,
                "encryptedChallenge": challenge.encrypted_challenge,
                "challengeMetadata": {
                    "salt": challenge.challenge_metadata.salt,
                    "iv": challenge.challenge_metadata.iv,
                    "iterations": challenge.challenge_metadata.iterations
                },
                "verifyId": verify_id,
                "contentChecksum": checksum
            })))
            .mount(server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/shares/{share_id}/payload")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "contentType": "file",
                "encryptedPayload": r.encrypted_payload,
                "encryptionMetadata": {
                    "algorithm": r.encryption_metadata.algorithm,
                    "kdf": r.encryption_metadata.kdf,
                    "iterations": r.encryption_metadata.iterations,
                    "salt": r.encryption_metadata.salt,
                    "iv": r.encryption_metadata.iv
                },
                "fileMetadata": { "filename": filename, "mimeType": "application/octet-stream", "size": content.len(), "extension": ".zip" },
                "contentChecksum": checksum
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn decrypts_and_logs_text() {
        let (server, url) = mock_server().await;
        mount_text_share(&server, "abc123", b"top secret", "mypassword").await;

        let mut logged = String::new();
        run("https://example.com/s/abc123", "mypassword", None, Some(url), &mut |s| {
            logged = s.to_owned()
        })
        .await
        .unwrap();

        assert_eq!(logged, "top secret");
    }

    #[tokio::test]
    async fn wrong_password_errors() {
        let (server, url) = mock_server().await;
        // Encrypt challenge with "correctpass" — client will try "wrongpass" and fail locally
        mount_text_share(&server, "abc", b"secret", "correctpass").await;

        let err = run("https://example.com/s/abc", "wrongpass", None, Some(url), &mut |_| {})
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.to_lowercase().contains("wrong password") || msg.to_lowercase().contains("corrupted"),
            "unexpected error: {msg:?}"
        );
    }

    #[tokio::test]
    async fn saves_file_to_output_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let password = "filepass";
        let content = b"\x00\x01\x02\x03";

        let (server, url) = mock_server().await;
        mount_file_share(&server, "fid", content, password, "data.zip").await;

        let dir = tmp.path().to_str().unwrap().to_owned();
        run("https://example.com/s/fid", password, Some(dir.clone()), Some(url), &mut |_| {})
            .await
            .unwrap();

        let saved = std::fs::read(Path::new(&dir).join("data.zip")).unwrap();
        assert_eq!(saved, content);
    }

    #[tokio::test]
    async fn errors_if_output_file_exists() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("data.zip"), b"existing").unwrap();

        let password = "filepass";
        let (server, url) = mock_server().await;
        mount_file_share(&server, "dup", b"\x01", password, "data.zip").await;

        let dir = tmp.path().to_str().unwrap().to_owned();
        let err = run("https://example.com/s/dup", password, Some(dir), Some(url), &mut |_| {})
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.to_lowercase().contains("already exists"), "unexpected error: {msg:?}");
    }

    #[tokio::test]
    async fn decrypts_file_and_saves() {
        let tmp = tempfile::tempdir().unwrap();
        let password = "pass123";
        let content = b"file content bytes";

        let (server, url) = mock_server().await;
        mount_file_share(&server, "file1", content, password, "doc.zip").await;

        let dir = tmp.path().to_str().unwrap().to_owned();
        run("https://example.com/s/file1", password, Some(dir.clone()), Some(url), &mut |_| {})
            .await
            .unwrap();

        let saved = std::fs::read(Path::new(&dir).join("doc.zip")).unwrap();
        assert_eq!(saved, content);
    }

    #[tokio::test]
    async fn propagates_share_unavailable() {
        let (server, url) = mock_server().await;
        Mock::given(method("GET"))
            .and(path("/shares/gone/metadata"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        // Use full URL so it's parsed as explicit server mode (no P2P fallback)
        let share_url = format!("{}/s/gone", url);
        let err = run(share_url, "password", None, Some(url), &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("not found") || err.to_string().to_lowercase().contains("unavailable"));
    }

    #[tokio::test]
    async fn rejects_short_password() {
        let err = run("abc123", "ab", None, None, &mut |_| {}).await.unwrap_err();
        assert!(err.to_string().contains("Password"));
    }

    // ── P2P verify pre-connect ────────────────────────────────────────────────

    #[tokio::test]
    async fn p2p_expired_session_errors_before_verify() {
        let (server, url) = mock_server().await;
        Mock::given(method("GET"))
            .and(path("/p2p/sessions/s1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sessionId": "s1", "status": "expired", "expiresAt": ""
            })))
            .mount(&server)
            .await;

        let err = run("https://nullseal.com/p2p/s1", "password", None, Some(url), &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("expired"));
    }

    #[tokio::test]
    async fn p2p_wrong_password_from_verify() {
        let (server, url) = mock_server().await;
        Mock::given(method("GET"))
            .and(path("/p2p/sessions/s2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sessionId": "s2", "status": "waiting", "expiresAt": ""
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/p2p/sessions/s2/verify"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "code": "wrong_password", "attemptsLeft": 1
            })))
            .mount(&server)
            .await;

        let err = run("https://nullseal.com/p2p/s2", "password", None, Some(url), &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("wrong password"));
    }

    // ── parse_share_url: additional edge cases ───────────────────────────

    #[test]
    fn parses_http_server_url() {
        assert_eq!(
            parse_share_url("http://localhost:3000/s/local123"),
            ParsedUrl::Server { id: "local123".into() }
        );
    }

    #[test]
    fn parses_http_p2p_url() {
        assert_eq!(
            parse_share_url("http://localhost:3000/p2p/sess999"),
            ParsedUrl::P2p { id: "sess999".into() }
        );
    }

    #[test]
    fn unknown_url_path_is_bare_id() {
        // URL with unrecognized path should fall through to BareId
        assert_eq!(
            parse_share_url("https://nullseal.com/other/abc"),
            ParsedUrl::BareId { id: "https://nullseal.com/other/abc".into() }
        );
    }

    #[test]
    fn empty_p2p_prefix_is_bare_id() {
        // "p2p/" with no ID should be BareId
        assert_eq!(
            parse_share_url("p2p/"),
            ParsedUrl::BareId { id: "p2p/".into() }
        );
    }

    #[test]
    fn empty_s_prefix_is_bare_id() {
        // "s/" with no ID should be BareId
        assert_eq!(
            parse_share_url("s/"),
            ParsedUrl::BareId { id: "s/".into() }
        );
    }

    #[test]
    fn short_id_is_bare_id() {
        assert_eq!(
            parse_share_url("x"),
            ParsedUrl::BareId { id: "x".into() }
        );
    }

    // ── server get: additional cases ─────────────────────────────────────

    #[tokio::test]
    async fn decrypts_file_and_saves_bare_id() {
        let tmp = tempfile::tempdir().unwrap();
        let password = "testpass";
        let content = b"file content here";

        let (server, url) = mock_server().await;
        mount_file_share(&server, "fid2", content, password, "test.pdf").await;

        let dir = tmp.path().to_str().unwrap().to_owned();
        run("s/fid2", password, Some(dir.clone()), Some(url), &mut |_| {})
            .await
            .unwrap();

        let saved = std::fs::read(Path::new(&dir).join("test.pdf")).unwrap();
        assert_eq!(saved, content);
    }

    #[test]
    fn bare_id_parsed_as_bare_id_variant() {
        // Verify BareId is the parsed result for plain IDs
        let parsed = parse_share_url("bare123");
        assert_eq!(parsed, ParsedUrl::BareId { id: "bare123".into() });
    }
}
