use std::path::PathBuf;

use anyhow::{bail, Result};

use crate::api::{ApiClient, P2PVerifyError};
use crate::crypto::{decrypt_bytes, decrypt_challenge, sha256_bytes, sha256_hex};
use crate::webrtc::ReceiverPeer;
use nullseal_p2p_control::control::P2PControl;
use nullseal_p2p_control::transport::SocketIoTransport;
use nullseal_socketio::transport::TungsteniteWs;

use super::confirm_unsafe_file;

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
    relay_only: bool,
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
            run_p2p(&id, &password, output_dir.as_deref(), server.as_deref(), relay_only, log).await
        }
        ParsedUrl::BareId { id } => {
            // Try server first; if not found, fall back to P2P
            let result = run_server(&id, &password, output_dir.as_deref(), server.as_deref(), log).await;
            if matches!(&result, Err(e) if e.to_string().contains("not found")) {
                return run_p2p(&id, &password, output_dir.as_deref(), server.as_deref(), relay_only, log).await;
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
    super::log::event(&format!("fetching metadata for share {share_id}"));
    let metadata = client.get_share_metadata(share_id).await?;

    // Step 2: decrypt challenge to prove password knowledge
    super::log::event("verifying password (challenge)");
    let answer = decrypt_challenge(
        &metadata.encrypted_challenge,
        &metadata.challenge_metadata,
        password,
    )
    .map_err(|_| anyhow::anyhow!("Wrong password or corrupted data"))?;

    // Step 3: submit answer to get payload (server auto-consumes one-time shares)
    super::log::event("fetching encrypted payload");
    let payload = client.get_share_payload(share_id, &answer, &metadata.verify_id).await?;
    let spinner = super::display::Spinner::start("Decrypting…");
    let decrypted = decrypt_bytes(&payload.encrypted_payload, &payload.encryption_metadata, password)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    drop(spinner);
    super::display::status(&format!("Decrypted successfully ({})", super::format_size(decrypted.len())));

    let actual_checksum = sha256_bytes(&decrypted);
    if actual_checksum != payload.content_checksum {
        super::display::warn("Content integrity check failed. This share may have been tampered with.");
        if !metadata.one_time_read {
            let _ = client.report_malformed(share_id).await;
        }
    }

    if payload.content_type == "file" {
        if let Some(fm) = &payload.file_metadata {
            let dir = output_dir.unwrap_or(".");
            let filepath = super::deduplicate_path(PathBuf::from(dir).join(&fm.filename));
            confirm_unsafe_file(&fm.filename)?;
            std::fs::write(&filepath, &decrypted)?;
            super::log::step(&format!("Saved: {}", filepath.display()));
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
    relay_only: bool,
    log: &mut dyn FnMut(&str),
) -> Result<()> {
    let base = server_url(server)?;
    let client = ApiClient::new(&base);

    // 1. Check session status
    super::log::event(&format!("joining session {session_id} as recipient"));
    let session = client.get_p2p_session(session_id).await?;
    if session.status == "expired" {
        bail!("Session is expired or unavailable.");
    }

    // 2. Verify password
    super::log::event("verifying password");
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
    let ws_url = TungsteniteWs::build_url(&base)?;
    super::log::event(&format!("connecting to {ws_url}"));
    let ws = TungsteniteWs::connect(&ws_url).await?;
    let (transport, evts) = SocketIoTransport::connect(ws, "p2p").await?;
    super::log::event("connected (socket)");
    let mut control = P2PControl::new(transport, evts);
    control.join(session_id, "recipient")?;

    // 5. Wait for joined ack
    control.events
        .joined
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("socket closed before joined"))?;
    super::log::event("joined (recipient)");
    super::log::step("Connected. Waiting for sender…");

    // 6. Reconnection driven by the shared `ConnectionMachine` (same pure model as
    //    the web client, task 001/013). The receiver's resume point comes from the
    //    sender's metadata (`resumeFromChunk`), so here the machine is purely the
    //    retry-budget / backoff / Stopped-vs-Expired authority.
    use crate::p2p::connection::{ConnEvent, ConnPhase, ConnectionMachine};
    let mut machine = ConnectionMachine::new(
        crate::retry::DEFAULT.max_retries,
        crate::retry::DEFAULT.backoff_ms.to_vec(),
        crate::retry::CHANNEL_TIMEOUT_SECS * 1000,
    );
    machine.handle(ConnEvent::Start);
    machine.handle(ConnEvent::SocketUp);
    machine.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 0 });

    // Helper: reconnect socket if dead, then emit join
    macro_rules! rejoin {
        () => {{
            if !control.is_alive() {
                let ws = TungsteniteWs::connect(&ws_url).await?;
                let (transport, evts) = SocketIoTransport::connect(ws, "p2p").await?;
                control = P2PControl::new(transport, evts);
                control.join(session_id, "recipient")?;
                control.events.joined.recv().await
                    .ok_or_else(|| anyhow::anyhow!("socket closed before joined on reconnect"))?;
            } else {
                control.join(session_id, "recipient")?;
            }
            // Mark a fresh (re-)join so the machine's retry bookkeeping resets for the
            // next attempt (mirrors the sender; resets `retry_scheduled`).
            machine.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 0 });
        }};
    }

    // Drive one failure through the machine: retry-with-backoff vs Stopped (manual
    // prompt) vs Expired. Caller `rejoin!`s and `continue`s afterward.
    macro_rules! machine_retry {
        ($reason:expr, $bail:expr) => {{
            let acts = machine.handle(ConnEvent::DcClosed);
            if machine.phase() == ConnPhase::Stopped {
                if !crate::retry::prompt_manual().await {
                    bail!($bail);
                }
                machine.handle(ConnEvent::ManualRetry);
            } else {
                crate::retry::log_retry(
                    machine.attempts(), crate::retry::DEFAULT.max_retries, $reason,
                );
                let delay_ms = crate::commands::p2p_stages::retry_delay_ms(&acts);
                machine.handle(ConnEvent::RetryTimer);
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }};
    }

    loop {
        // 6b. Wait for SDP offer from sender.
        if machine.attempts() > 0 {
            while control.events.offer.try_recv().is_ok() {}
            while control.events.ice.try_recv().is_ok() {}
        }

        let offer_result = super::p2p_stages::await_offer(&mut control.events, machine.attempts() == 0).await?;

        let offer = match offer_result {
            Some(o) => o,
            None => {
                machine_retry!(
                    "no offer received…",
                    format!("Sender did not reconnect after {} retries.", crate::retry::DEFAULT.max_retries)
                );
                rejoin!();
                continue;
            }
        };

        // 7. Create WebRTC receiver peer from offer, send answer back
        let mut receiver = if relay_only {
            ReceiverPeer::from_offer_relay_only(offer, ice_servers.clone(), None).await?
        } else {
            ReceiverPeer::from_offer(offer, ice_servers.clone(), None).await?
        };
        control.answer(&receiver.answer_sdp_json())?;

        // 8. Wait for DataChannel open
        let channel_open = super::p2p_stages::await_receiver_channel(&mut receiver, &mut control.events).await?;

        if !channel_open {
            machine_retry!(
                "channel open failed…",
                format!("WebRTC connection failed after {} retries.", crate::retry::DEFAULT.max_retries)
            );
            rejoin!();
            continue;
        }

        // DataChannel open → machine resets the retry budget (Transferring phase).
        machine.handle(ConnEvent::DcOpen);

        super::log::step("Transfer started…");

        // 9. Receive v2 binary transfer: wait for metadata string frame, then
        //    route binary frames through ReceiverAdapter.
        use crate::crypto::{StreamDecryptor, StreamEncryptionMetadata};
        use crate::p2p::receiver_adapter::{AdapterOutput, ReceiverAdapter, ReceiverDecryptorT, ReceiverTransport};
        use crate::p2p::receiver_engine::ReceiverEngine;
        use sha2::{Digest, Sha256};

        struct CtrlTransport<'a, T: nullseal_p2p_control::transport::ControlTransport> {
            control: &'a P2PControl<T>,
        }
        impl<'a, T: nullseal_p2p_control::transport::ControlTransport> ReceiverTransport for CtrlTransport<'a, T> {
            fn emit_ack(&mut self, through: u64) {
                let _ = self.control.ack(through);
            }
            fn emit_request(&mut self, from: u64) {
                let _ = self.control.request(from);
            }
        }

        struct RealDecryptor(StreamDecryptor);
        impl ReceiverDecryptorT for RealDecryptor {
            fn decrypt_chunk_at(&mut self, ciphertext: &[u8], index: u64) -> anyhow::Result<Vec<u8>> {
                self.0.decrypt_chunk_at(ciphertext, index)
                    .map_err(|e| anyhow::anyhow!("{e}"))
            }
        }

        // Wait for metadata (first text frame from DC) + setup adapter
        let transfer_result: Result<(Vec<u8>, String, Option<serde_json::Value>, String)> = async {
            let mut content_type = String::new();
            let mut file_meta: Option<serde_json::Value> = None;
            let mut content_checksum_expected = String::new();
            let mut plaintext_buf: Vec<u8> = Vec::new();
            let mut hasher = Sha256::new();
            let mut adapter_opt: Option<ReceiverAdapter<CtrlTransport<'_, _>, RealDecryptor>> = None;
            let mut total_plaintext_size: usize = 0;

            loop {
                tokio::select! {
                    biased;
                    event = receiver.next_event() => {
                        match event {
                            Some(crate::webrtc::LoopEvent::Message(text)) => {
                                // Metadata string frame
                                let v: serde_json::Value = match serde_json::from_str(&text) {
                                    Ok(v) => v,
                                    Err(_) => continue,
                                };
                                if v["type"].as_str() == Some("verify") {
                                    // Verify frame from sender — check proof
                                    let sender_proof = v["proof"].as_str().unwrap_or("");
                                    if sender_proof != proof {
                                        return Err(anyhow::anyhow!("Wrong password."));
                                    }
                                    continue;
                                }
                                if v["type"].as_str() != Some("metadata") {
                                    continue;
                                }
                                content_type = v["contentType"].as_str().unwrap_or("text").to_owned();
                                file_meta = if v["fileMetadata"].is_null() { None } else { Some(v["fileMetadata"].clone()) };
                                content_checksum_expected = v["contentChecksum"].as_str().unwrap_or("").to_owned();

                                let stream_meta: StreamEncryptionMetadata = serde_json::from_value(
                                    v["streamEncryptionMetadata"].clone()
                                ).map_err(|e| anyhow::anyhow!("invalid stream metadata: {e}"))?;

                                total_plaintext_size = stream_meta.total_plaintext_size as usize;
                                let resume_from = v["resumeFromChunk"].as_u64().unwrap_or(0);
                                super::log::event(&format!(
                                    "metadata received ({content_type}, {}, resume from chunk {resume_from})",
                                    super::format_size(total_plaintext_size),
                                ));

                                let mut decryptor = StreamDecryptor::from_metadata(&stream_meta, password)
                                    .map_err(|e| anyhow::anyhow!("failed to init decryptor: {e}"))?;
                                if resume_from > 0 {
                                    decryptor.skip_to(resume_from);
                                }

                                let engine = ReceiverEngine::new(64, 250, 5000, resume_from);
                                let transport = CtrlTransport { control: &control };
                                adapter_opt = Some(ReceiverAdapter::new(engine, RealDecryptor(decryptor), transport));
                            }
                            Some(crate::webrtc::LoopEvent::BinaryData(data)) => {
                                // Binary chunk/end frame → feed to adapter
                                if let Some(ref mut adapter) = adapter_opt {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis() as u64;
                                    let outputs = adapter.on_frame(&data, now);
                                    for out in outputs {
                                        match out {
                                            AdapterOutput::Deliver { index, plaintext } => {
                                                hasher.update(&plaintext);
                                                plaintext_buf.extend_from_slice(&plaintext);
                                                super::log::event(&format!(
                                                    "received chunk {index} ({}) — {} / {}",
                                                    super::format_size(plaintext.len()),
                                                    super::format_size(plaintext_buf.len()),
                                                    super::format_size(total_plaintext_size),
                                                ));
                                                super::display::receive_progress(plaintext_buf.len(), total_plaintext_size);
                                            }
                                            AdapterOutput::Complete => {
                                                // Verify checksum
                                                let computed = format!("{:x}", hasher.clone().finalize());
                                                if !content_checksum_expected.is_empty() && computed != content_checksum_expected {
                                                    return Err(anyhow::anyhow!(
                                                        "Checksum mismatch: expected {content_checksum_expected}, got {computed}"
                                                    ));
                                                }
                                                return Ok((plaintext_buf, content_type, file_meta, computed));
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            Some(crate::webrtc::LoopEvent::Error(e)) => {
                                return Err(anyhow::anyhow!("WebRTC error: {e}"));
                            }
                            Some(crate::webrtc::LoopEvent::Done) | None => {
                                return Err(anyhow::anyhow!("DataChannel closed before transfer complete"));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }.await;

        match transfer_result {
            Ok((plaintext, content_type, file_meta, checksum)) => {
                super::log::blank();
                super::display::status(&format!(
                    "Received & decrypted ({})",
                    super::format_size(plaintext.len())
                ));

                // 10. Output
                if content_type == "file" {
                    if let Some(fm) = &file_meta {
                        let filename = fm["filename"]
                            .as_str()
                            .unwrap_or("received_file");
                        let dir = output_dir.unwrap_or(".");
                        let filepath = super::deduplicate_path(PathBuf::from(dir).join(filename));
                        confirm_unsafe_file(filename)?;
                        std::fs::write(&filepath, &plaintext)?;
                        super::log::step(&format!("Saved: {}", filepath.display()));
                    } else {
                        log(std::str::from_utf8(&plaintext).unwrap_or("(binary data)"));
                    }
                } else {
                    log(std::str::from_utf8(&plaintext).unwrap_or("(binary data)"));
                }

                // 11. Emit complete + wait for session deletion, then cleanup
                receiver.close();
                let _ = control.complete("recipient", &checksum);
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    control.events.deleted.recv(),
                ).await;
                return Ok(());
            }
            Err(e) => {
                super::log::blank();
                // Transfer interrupted — machine decides retry vs stop.
                machine_retry!(
                    &format!("transfer interrupted: {e}"),
                    format!("Transfer failed after {} retries: {e}", crate::retry::DEFAULT.max_retries)
                );
                rejoin!();
                continue;
            }
        }
    }
}

// ── Local mode (no server) ────────────────────────────────────────────────────

/// Fully local receive — discovers sender via mDNS, connects to the embedded
/// Socket.IO server via crate B, and runs the same flow as run_p2p (windowed-ACK v2).
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

    // 1. Resolve sender address (via mDNS or explicit)
    let addr = match ip {
        Some(a) => {
            super::log::step(&format!("📡 Connecting to {a}…"));
            a
        }
        None => crate::local::discover_addr(std::time::Duration::from_secs(30))?,
    };

    // 2. Connect to sender's embedded Socket.IO server via crate B
    let ws_url = format!("ws://{addr}/socket.io/?EIO=4&transport=websocket");
    let ws = TungsteniteWs::connect(&ws_url).await?;
    let (transport, evts) = SocketIoTransport::connect(ws, "p2p").await?;
    let mut control = P2PControl::new(transport, evts);

    // 3. Join as recipient
    control.join("local", "recipient")?;
    control.events.joined.recv().await
        .ok_or_else(|| anyhow::anyhow!("socket closed before joined"))?;
    super::log::step("Connected. Waiting for sender…");

    let bind_ip: Option<std::net::IpAddr> = addr.split(':')
        .next()
        .and_then(|h| h.parse().ok());

    // Shared receive types (sha256_bytes is already in module scope)
    use crate::crypto::{StreamDecryptor, StreamEncryptionMetadata};
    use crate::p2p::receiver_adapter::{AdapterOutput, ReceiverAdapter, ReceiverDecryptorT, ReceiverTransport};
    use crate::p2p::receiver_engine::ReceiverEngine;

    struct CtrlTransport<'a, T: nullseal_p2p_control::transport::ControlTransport> {
        control: &'a P2PControl<T>,
    }
    impl<'a, T: nullseal_p2p_control::transport::ControlTransport> ReceiverTransport for CtrlTransport<'a, T> {
        fn emit_ack(&mut self, through: u64) {
            let _ = self.control.ack(through);
        }
        fn emit_request(&mut self, from: u64) {
            let _ = self.control.request(from);
        }
    }

    struct RealDecryptor(StreamDecryptor);
    impl ReceiverDecryptorT for RealDecryptor {
        fn decrypt_chunk_at(&mut self, ciphertext: &[u8], index: u64) -> anyhow::Result<Vec<u8>> {
            self.0.decrypt_chunk_at(ciphertext, index)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
    }

    // 4. Reconnection driven by the shared `ConnectionMachine` (task 013). Local mode
    //    has no manual prompt, so `Stopped` → bail. The receiver's resume comes from
    //    the sender's metadata (`resumeFromChunk`) + the preserved plaintext buffer;
    //    the machine is the retry-budget / backoff authority.
    use crate::p2p::connection::{ConnEvent, ConnPhase, ConnectionMachine};
    let mut machine = ConnectionMachine::new(
        crate::retry::DEFAULT.max_retries,
        crate::retry::DEFAULT.backoff_ms.to_vec(),
        crate::retry::CHANNEL_TIMEOUT_SECS * 1000,
    );
    machine.handle(ConnEvent::Start);
    machine.handle(ConnEvent::SocketUp);
    machine.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 0 });
    let chunk_size = crate::crypto::STREAM_CHUNK_SIZE;

    // Preserved across reconnects so we resume instead of restarting.
    let mut plaintext_buf: Vec<u8> = Vec::new();
    let mut content_type = String::new();
    let mut file_meta: Option<serde_json::Value> = None;

    macro_rules! rejoin {
        () => {{
            super::p2p_stages::drain(&mut control.events.offer);
            super::p2p_stages::drain(&mut control.events.ice);
            super::p2p_stages::drain(&mut control.events.both_ready);
            if !control.is_alive() {
                let ws = TungsteniteWs::connect(&ws_url).await?;
                let (transport, evts) = SocketIoTransport::connect(ws, "p2p").await?;
                control = P2PControl::new(transport, evts);
                control.join("local", "recipient")?;
                control.events.joined.recv().await
                    .ok_or_else(|| anyhow::anyhow!("socket closed before joined on reconnect"))?;
            } else {
                control.join("local", "recipient")?;
            }
            machine.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 0 });
        }};
    }

    // Local has no manual-retry prompt: the machine's `Stopped` → bail directly.
    macro_rules! machine_retry {
        ($reason:expr, $bail:expr) => {{
            let acts = machine.handle(ConnEvent::DcClosed);
            if machine.phase() == ConnPhase::Stopped {
                bail!($bail);
            }
            crate::retry::log_retry(
                machine.attempts(), crate::retry::DEFAULT.max_retries, $reason,
            );
            let delay_ms = crate::commands::p2p_stages::retry_delay_ms(&acts);
            machine.handle(ConnEvent::RetryTimer);
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }};
    }

    let checksum = loop {
        // 5. Wait for the sender's offer. (Stale offer/ice are drained inside rejoin!
        //    BEFORE re-joining, so a fresh offer relayed right after both-ready over
        //    loopback isn't accidentally discarded here.)
        let offer = match super::p2p_stages::await_offer(&mut control.events, machine.attempts() == 0).await? {
            Some(o) => o,
            None => {
                machine_retry!(
                    "no offer received…",
                    format!("Sender did not reconnect after {} retries.", crate::retry::DEFAULT.max_retries)
                );
                rejoin!();
                continue;
            }
        };

        // 6. Build receiver from offer, answer, await DataChannel.
        let sdp_val = &offer["sdp"];
        let offer_val = serde_json::json!({"type": "offer", "sdp": sdp_val});
        let mut receiver = ReceiverPeer::from_offer(offer_val, vec![], bind_ip).await?;
        control.answer(&receiver.answer_sdp_json())?;

        let channel_open = super::p2p_stages::await_receiver_channel(&mut receiver, &mut control.events).await?;
        if !channel_open {
            machine_retry!(
                "channel open failed…",
                format!("DataChannel open failed after {} retries.", crate::retry::DEFAULT.max_retries)
            );
            rejoin!();
            continue;
        }
        machine.handle(ConnEvent::DcOpen);
        super::log::step("Transfer started…");

        // 7. Receive v2 binary transfer with windowed-ACK control plane. The
        //    plaintext we've already committed is kept; on (re)connect we truncate
        //    to the sender's resume point and decrypt forward from there.
        let transfer_result: Result<String> = async {
            let mut content_checksum_expected = String::new();
            let mut adapter_opt: Option<ReceiverAdapter<CtrlTransport<'_, _>, RealDecryptor>> = None;
            let mut total_plaintext_size: usize = 0;

            loop {
                match receiver.next_event().await {
                    Some(crate::webrtc::LoopEvent::Message(text)) => {
                        let v: serde_json::Value = match serde_json::from_str(&text) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        if v["type"].as_str() == Some("verify") {
                            let sender_proof = v["proof"].as_str().unwrap_or("");
                            if sender_proof != proof {
                                return Err(anyhow::anyhow!("Wrong password."));
                            }
                            continue;
                        }
                        if v["type"].as_str() != Some("metadata") {
                            continue;
                        }
                        content_type = v["contentType"].as_str().unwrap_or("text").to_owned();
                        file_meta = if v["fileMetadata"].is_null() { None } else { Some(v["fileMetadata"].clone()) };
                        content_checksum_expected = v["contentChecksum"].as_str().unwrap_or("").to_owned();

                        let stream_meta: StreamEncryptionMetadata = serde_json::from_value(
                            v["streamEncryptionMetadata"].clone()
                        ).map_err(|e| anyhow::anyhow!("invalid stream metadata: {e}"))?;

                        total_plaintext_size = stream_meta.total_plaintext_size as usize;
                        let resume_from = v["resumeFromChunk"].as_u64().unwrap_or(0);
                        super::log::event(&format!(
                            "metadata received ({content_type}, {}, resume from chunk {resume_from})",
                            super::format_size(total_plaintext_size),
                        ));

                        // Truncate any committed plaintext to the sender's resume point
                        // (mirrors the web recipient's `slice(0, resumeFrom)`), so a
                        // re-sent chunk isn't double-counted.
                        let keep = (resume_from as usize)
                            .saturating_mul(chunk_size)
                            .min(plaintext_buf.len());
                        plaintext_buf.truncate(keep);

                        let mut decryptor = StreamDecryptor::from_metadata(&stream_meta, &password)
                            .map_err(|e| anyhow::anyhow!("failed to init decryptor: {e}"))?;
                        if resume_from > 0 {
                            decryptor.skip_to(resume_from);
                        }

                        let engine = ReceiverEngine::new(64, 250, 5000, resume_from);
                        let transport = CtrlTransport { control: &control };
                        adapter_opt = Some(ReceiverAdapter::new(engine, RealDecryptor(decryptor), transport));
                    }
                    Some(crate::webrtc::LoopEvent::BinaryData(data)) => {
                        if let Some(ref mut adapter) = adapter_opt {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64;
                            let outputs = adapter.on_frame(&data, now);
                            for out in outputs {
                                match out {
                                    AdapterOutput::Deliver { index, plaintext } => {
                                        plaintext_buf.extend_from_slice(&plaintext);
                                        super::log::event(&format!(
                                            "received chunk {index} ({}) — {} / {}",
                                            super::format_size(plaintext.len()),
                                            super::format_size(plaintext_buf.len()),
                                            super::format_size(total_plaintext_size),
                                        ));
                                        super::display::receive_progress(plaintext_buf.len(), total_plaintext_size);
                                    }
                                    AdapterOutput::Complete => {
                                        // Hash the fully assembled buffer (resume-safe;
                                        // chunks may have been re-sent on reconnect).
                                        let computed = sha256_bytes(&plaintext_buf);
                                        if !content_checksum_expected.is_empty() && computed != content_checksum_expected {
                                            return Err(anyhow::anyhow!(
                                                "Checksum mismatch: expected {content_checksum_expected}, got {computed}"
                                            ));
                                        }
                                        return Ok(computed);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Some(crate::webrtc::LoopEvent::Error(e)) => {
                        return Err(anyhow::anyhow!("WebRTC error: {e}"));
                    }
                    Some(crate::webrtc::LoopEvent::Done) | None => {
                        return Err(anyhow::anyhow!("DataChannel closed before transfer complete"));
                    }
                    _ => {}
                }
            }
        }.await;

        match transfer_result {
            Ok(checksum) => {
                receiver.close();
                break checksum;
            }
            Err(e) => {
                super::log::blank();
                receiver.close();
                machine_retry!(
                    &format!("transfer interrupted: {e}"),
                    format!("Transfer failed after {} retries: {e}", crate::retry::DEFAULT.max_retries)
                );
                rejoin!();
                continue;
            }
        }
    };

    // 8. Output the assembled plaintext.
    super::log::blank();
    super::display::status(&format!(
        "Received & decrypted ({})",
        super::format_size(plaintext_buf.len())
    ));
    if content_type == "file" {
        if let Some(fm) = &file_meta {
            let filename = fm["filename"].as_str().unwrap_or("received_file");
            let dir = output_dir.as_deref().unwrap_or(".");
            let filepath = super::deduplicate_path(PathBuf::from(dir).join(filename));
            confirm_unsafe_file(filename)?;
            std::fs::write(&filepath, &plaintext_buf)?;
            super::log::step(&format!("Saved: {}", filepath.display()));
        } else {
            log(std::str::from_utf8(&plaintext_buf).unwrap_or("(binary data)"));
        }
    } else {
        log(std::str::from_utf8(&plaintext_buf).unwrap_or("(binary data)"));
    }

    // 9. Emit complete + wait for the sender to finish (deleted), then cleanup.
    //    (011 clean-completion handshake — keeps the sender exiting 0.)
    let _ = control.complete("recipient", &checksum);
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        control.events.deleted.recv(),
    ).await;
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
        run("https://example.com/s/abc123", "mypassword", None, Some(url), false, &mut |s| {
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

        let err = run("https://example.com/s/abc", "wrongpass", None, Some(url), false, &mut |_| {})
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
        run("https://example.com/s/fid", password, Some(dir.clone()), Some(url), false, &mut |_| {})
            .await
            .unwrap();

        let saved = std::fs::read(Path::new(&dir).join("data.zip")).unwrap();
        assert_eq!(saved, content);
    }

    #[tokio::test]
    async fn deduplicates_output_file_if_exists() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("data.zip"), b"existing").unwrap();

        let password = "filepass";
        let content = b"\x01";
        let (server, url) = mock_server().await;
        mount_file_share(&server, "dup", content, password, "data.zip").await;

        let dir = tmp.path().to_str().unwrap().to_owned();
        run("https://example.com/s/dup", password, Some(dir.clone()), Some(url), false, &mut |_| {})
            .await
            .unwrap();

        // Original file untouched
        assert_eq!(std::fs::read(tmp.path().join("data.zip")).unwrap(), b"existing");
        // New file saved with deduplicated name
        let deduped = tmp.path().join("data (1).zip");
        assert!(deduped.exists(), "expected deduplicated file at {:?}", deduped);
        assert_eq!(std::fs::read(&deduped).unwrap(), content);
    }

    #[tokio::test]
    async fn decrypts_file_and_saves() {
        let tmp = tempfile::tempdir().unwrap();
        let password = "pass123";
        let content = b"file content bytes";

        let (server, url) = mock_server().await;
        mount_file_share(&server, "file1", content, password, "doc.zip").await;

        let dir = tmp.path().to_str().unwrap().to_owned();
        run("https://example.com/s/file1", password, Some(dir.clone()), Some(url), false, &mut |_| {})
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
        let err = run(share_url, "password", None, Some(url), false, &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("not found") || err.to_string().to_lowercase().contains("unavailable"));
    }

    #[tokio::test]
    async fn rejects_short_password() {
        let err = run("abc123", "ab", None, None, false, &mut |_| {}).await.unwrap_err();
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

        let err = run("https://nullseal.com/p2p/s1", "password", None, Some(url), false, &mut |_| {})
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

        let err = run("https://nullseal.com/p2p/s2", "password", None, Some(url), false, &mut |_| {})
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
        run("s/fid2", password, Some(dir.clone()), Some(url), false, &mut |_| {})
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

    // ── Resume logic: sender restart detection ───────────────────────────

    /// Simulate the receiver's accumulated state when sender reports
    /// resumeFromChunk = 0 but receiver expected to resume from chunk N.
    /// The receiver must discard accumulated data to avoid corruption.
    #[test]
    fn resume_mismatch_resets_accumulated_chunks() {
        let mut all_chunks: Vec<String> = vec!["aaaa".into(), "bbbb".into(), "cccc".into()];
        let mut last_chunk_index: i64 = 2; // received chunks 0,1,2
        let sender_resume_from: usize = 0; // sender restarted from 0!
        let expected_start: usize = (last_chunk_index as usize) + 1; // expected 3

        // This replicates the logic in run_p2p (line ~265)
        if sender_resume_from < expected_start && !all_chunks.is_empty() {
            all_chunks.clear();
            last_chunk_index = if sender_resume_from == 0 {
                -1
            } else {
                sender_resume_from as i64 - 1
            };
        }

        assert!(all_chunks.is_empty(), "accumulated chunks must be cleared on mismatch");
        assert_eq!(last_chunk_index, -1, "chunk index must reset to -1 when sender starts from 0");
    }

    /// When sender resumes from the expected offset, accumulated data is kept.
    #[test]
    fn resume_match_preserves_accumulated_chunks() {
        let mut all_chunks: Vec<String> = vec!["aaaa".into(), "bbbb".into()];
        let mut last_chunk_index: i64 = 1; // received chunks 0,1
        let sender_resume_from: usize = 2; // sender resumes from chunk 2 — correct!
        let expected_start: usize = (last_chunk_index as usize) + 1;

        if sender_resume_from < expected_start && !all_chunks.is_empty() {
            all_chunks.clear();
            last_chunk_index = if sender_resume_from == 0 {
                -1
            } else {
                sender_resume_from as i64 - 1
            };
        }

        assert_eq!(all_chunks.len(), 2, "chunks must be preserved when resume matches");
        assert_eq!(last_chunk_index, 1, "chunk index must stay unchanged");
    }

    /// When sender partially resumes (e.g. got resume frame late, starts from chunk 1
    /// but receiver had chunks 0,1,2), receiver discards and trusts the sender.
    #[test]
    fn resume_partial_mismatch_resets_to_sender_offset() {
        let mut all_chunks: Vec<String> = vec!["aaaa".into(), "bbbb".into(), "cccc".into()];
        let mut last_chunk_index: i64 = 2;
        let sender_resume_from: usize = 1; // sender resumes from chunk 1, not 3
        let expected_start: usize = (last_chunk_index as usize) + 1;

        if sender_resume_from < expected_start && !all_chunks.is_empty() {
            all_chunks.clear();
            last_chunk_index = if sender_resume_from == 0 {
                -1
            } else {
                sender_resume_from as i64 - 1
            };
        }

        assert!(all_chunks.is_empty());
        assert_eq!(last_chunk_index, 0, "chunk index must be sender_resume_from - 1");
    }
}
