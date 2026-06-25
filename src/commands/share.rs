use std::path::Path;

use anyhow::{bail, Result};

use crate::api::{ApiClient, CreateShareRequest, FileMetadata};
use crate::crypto::{encrypt_bytes, generate_challenge, sha256_hex};
use crate::webrtc::SenderPeer;
use nullseal_p2p_control::control::P2PControl;
use nullseal_p2p_control::transport::SocketIoTransport;
use nullseal_socketio::transport::TungsteniteWs;

const MIN_PASSWORD_LEN: usize = 3;
const SERVER_MAX_BYTES: u64 = 2 * 1024 * 1024; // 2 MB
const MAX_TEXT_LENGTH: usize = 100_000;
const MAX_TTL_SECS: u64 = 7 * 24 * 3600; // 7 days
const DEFAULT_TTL_SECS: u64 = 24 * 3600; // 24 hours

use super::SUPPORTED_EXTENSIONS;

fn server_url(server: Option<&str>) -> Result<String> {
    server
        .map(str::to_owned)
        .or_else(|| std::env::var("CLI_APPS_CORE_URL").ok())
        .or_else(|| option_env!("CLI_APPS_CORE_URL").map(str::to_owned))
        .ok_or_else(|| anyhow::anyhow!("CLI_APPS_CORE_URL environment variable is not set"))
}

fn user_url() -> Option<String> {
    std::env::var("CLI_APPS_USER_URL")
        .ok()
        .or_else(|| option_env!("CLI_APPS_USER_URL").map(str::to_owned))
}

fn file_extension(filename: &str) -> String {
    Path::new(filename)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default()
}

fn validate(content: &str, password: &str, mode: &str, content_type: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN {
        bail!("Password must be at least {MIN_PASSWORD_LEN} characters.");
    }
    if content_type == "file" {
        let name = Path::new(content)
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or("");
        let ext = file_extension(name);
        if mode != "p2p" {
            if !SUPPORTED_EXTENSIONS.contains(&ext.as_str()) {
                bail!("Unsupported file extension: {}", if ext.is_empty() { "(none)" } else { &ext });
            }
            let size = std::fs::metadata(content).map(|m| m.len()).unwrap_or(0);
            if size > SERVER_MAX_BYTES {
                bail!("File exceeds short-time upload limit (2 MB).");
            }
        }
    } else if content.trim().is_empty() {
        bail!("Content cannot be empty.");
    } else if content.len() > MAX_TEXT_LENGTH {
        bail!("Text must be {MAX_TEXT_LENGTH} characters or fewer.");
    }
    Ok(())
}

fn resolve_content_type(flag: &str) -> &'static str {
    match flag {
        "pwd" => "password",
        "file" => "file",
        _ => "text",
    }
}

struct ReadInput {
    bytes: Vec<u8>,
    file_metadata: Option<FileMetadata>,
}

fn read_input(content: &str, content_type: &str) -> Result<ReadInput> {
    if content_type == "file" {
        let p = Path::new(content);
        let bytes = std::fs::read(p)?;
        let filename = p.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let extension = file_extension(&filename);
        Ok(ReadInput {
            file_metadata: Some(FileMetadata {
                size: bytes.len() as u64,
                mime_type: "application/octet-stream".into(),
                extension,
                filename,
            }),
            bytes,
        })
    } else {
        Ok(ReadInput { bytes: content.as_bytes().to_vec(), file_metadata: None })
    }
}

/// Outer entry point called from main and tests.
/// Accepts `impl Into<String>` so tests can pass `&str` without `.to_string()`.
pub async fn run(
    content: impl Into<String>,
    password: impl Into<String>,
    mode: impl Into<String>,
    content_type_flag: impl Into<String>,
    server: Option<String>,
    ttl: Option<String>,
    one_time: bool,
    relay_only: bool,
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    run_inner(content, password, mode, content_type_flag, server, false, ttl, one_time, relay_only, output).await
}



/// Fully local transfer — no server needed.
/// Host starts an embedded Socket.IO relay, advertises via mDNS, connects as
/// sender via crate B, and runs the same flow as run_p2p (windowed-ACK v2).
pub async fn run_local(
    content: impl Into<String>,
    password: impl Into<String>,
    content_type_flag: impl Into<String>,
    bind_addr: Option<String>,
    _output: &mut dyn FnMut(&str),
) -> Result<()> {
    let content = content.into();
    let password = password.into();
    let content_type_flag = content_type_flag.into();

    // Validate (use p2p mode rules — no server size limit)
    validate(&content, &password, "p2p", &content_type_flag)?;

    let content_type = resolve_content_type(&content_type_flag);
    let ReadInput { bytes, file_metadata } = read_input(&content, content_type)?;

    // 1. Derive password proof + checksum
    let content_checksum = crate::crypto::sha256_bytes(&bytes);
    let proof = sha256_hex(&password);

    // 2. Parse bind address
    let local_ip = match &bind_addr {
        Some(a) if a.contains(':') => a.rsplitn(2, ':').last().unwrap().to_string(),
        Some(ip) => ip.clone(),
        None => crate::webrtc::discover_local_ip().to_string(),
    };

    // 3. Start embedded Socket.IO server
    let (addr, _server_handle) = crate::local_server::start(&local_ip).await?;
    let port = addr.port();

    // 4. Display + broadcast via mDNS
    super::display::print_local_share_result(&format!("{local_ip}:{port}"));
    let _broadcast_guard = crate::local::broadcast_addr(&local_ip, port)?;

    // 5. Connect to own server as sender via crate B
    let ws_url = format!("ws://{local_ip}:{port}/socket.io/?EIO=4&transport=websocket");
    let ws = nullseal_socketio::transport::TungsteniteWs::connect(&ws_url).await?;
    let (transport, evts) = SocketIoTransport::connect(ws, "p2p").await?;
    let mut control = P2PControl::new(transport, evts);

    // 6. Join as sender; capture the relay's resume checkpoint. (BUG-10 parity)
    control.join("local", "sender")?;
    let mut last_chunk_offset: u64 = {
        let j = control.events.joined.recv().await
            .ok_or_else(|| anyhow::anyhow!("socket closed before joined"))?;
        j.get("lastChunkOffset").and_then(|v| v.as_u64()).unwrap_or(0)
    };
    super::log::step("📡 Waiting for recipient…");

    let bind_ip: Option<std::net::IpAddr> = local_ip.parse().ok();
    let chunk_size = crate::crypto::STREAM_CHUNK_SIZE;
    let total_bytes = bytes.len();

    let meta_extra = serde_json::json!({
        "contentType": content_type,
        "fileMetadata": file_metadata.as_ref().map(|fm| serde_json::to_value(fm).unwrap()),
        "contentChecksum": &content_checksum,
    });

    use crate::p2p::sender_adapter::{SenderAdapter, SenderCipherT, SenderTransport};
    use crate::p2p::sender_engine::SenderEngine;

    struct LocalCipher(crate::crypto::StreamCipher);
    impl SenderCipherT for LocalCipher {
        fn metadata(&self) -> serde_json::Value {
            serde_json::to_value(self.0.metadata()).unwrap()
        }
        fn chunk_index(&self) -> u64 { self.0.chunk_index() }
        fn skip_to(&mut self, index: u64) { self.0.skip_to(index); }
        fn encrypt_chunk(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.0.encrypt_chunk(plaintext).map_err(|e| anyhow::anyhow!("{e}"))
        }
    }

    struct BufTransport {
        text_queue: Vec<String>,
        binary_queue: Vec<Vec<u8>>,
    }
    impl SenderTransport for BufTransport {
        fn send_text(&mut self, s: String) { self.text_queue.push(s); }
        fn send_binary(&mut self, b: Vec<u8>) { self.binary_queue.push(b); }
    }

    // Test-only mid-transfer drop injection (CLI analog of the web test's PC-close):
    // when NULLSEAL_TEST_DROP_AFTER_BYTES is set, force one DC drop after that many
    // bytes so the rejoin/resume path runs deterministically. Inert in production.
    let test_drop_after: Option<u64> = std::env::var("NULLSEAL_TEST_DROP_AFTER_BYTES")
        .ok()
        .and_then(|s| s.parse().ok());
    let mut test_drop_armed = test_drop_after.is_some();

    // 7. Reconnection driven by the shared `ConnectionMachine` (same pure model as
    //    online/web, task 013). Local mode has no interactive prompt, so on the
    //    machine's `Stopped` we bail directly. Resume point is the relay checkpoint
    //    (`last_chunk_offset`). (BUG-9/10)
    use crate::p2p::connection::{ConnEvent, ConnPhase, ConnectionMachine};
    let mut machine = ConnectionMachine::new(
        crate::retry::DEFAULT.max_retries,
        crate::retry::DEFAULT.backoff_ms.to_vec(),
        crate::retry::CHANNEL_TIMEOUT_SECS * 1000,
    );
    machine.handle(ConnEvent::Start);
    machine.handle(ConnEvent::SocketUp);
    machine.handle(ConnEvent::Joined { last_chunk_offset, generation: 0 });

    macro_rules! rejoin {
        () => {{
            super::p2p_stages::drain(&mut control.events.both_ready);
            super::p2p_stages::drain(&mut control.events.answer);
            super::p2p_stages::drain(&mut control.events.ice);
            super::p2p_stages::drain(&mut control.events.error);
            if !control.is_alive() {
                let ws = nullseal_socketio::transport::TungsteniteWs::connect(&ws_url).await?;
                let (transport, evts) = SocketIoTransport::connect(ws, "p2p").await?;
                control = P2PControl::new(transport, evts);
                control.join("local", "sender")?;
                let j = control.events.joined.recv().await
                    .ok_or_else(|| anyhow::anyhow!("socket closed before joined on reconnect"))?;
                last_chunk_offset = j.get("lastChunkOffset").and_then(|v| v.as_u64()).unwrap_or(last_chunk_offset);
                machine.handle(ConnEvent::Joined { last_chunk_offset, generation: 0 });
            } else {
                control.join("local", "sender")?;
                if let Some(j) = control.events.joined.recv().await {
                    last_chunk_offset = j.get("lastChunkOffset").and_then(|v| v.as_u64()).unwrap_or(last_chunk_offset);
                }
                machine.handle(ConnEvent::Joined { last_chunk_offset, generation: 0 });
            }
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

    loop {
        // 7a. Wait for the recipient to (re)join.
        let got_ready = super::p2p_stages::await_ready(&mut control.events, machine.attempts() == 0).await?;
        if !got_ready {
            machine_retry!(
                "recipient not ready…",
                format!("Recipient did not rejoin after {} retries.", crate::retry::DEFAULT.max_retries)
            );
            rejoin!();
            continue;
        }
        super::display::status("Recipient connected. Starting transfer…");

        // 7b. Fresh WebRTC sender peer + offer (no ICE servers for LAN).
        while control.events.answer.try_recv().is_ok() {}
        while control.events.ice.try_recv().is_ok() {}
        let mut sender = SenderPeer::new(vec![], bind_ip).await?;
        control.offer(&sender.offer_sdp_json())?;
        super::p2p_stages::await_answer(&sender, &mut control.events).await?;
        let channel_open = super::p2p_stages::await_sender_channel(&mut sender, &mut control.events).await?;
        if !channel_open {
            machine_retry!(
                "channel open failed…",
                format!("DataChannel open failed after {} retries.", crate::retry::DEFAULT.max_retries)
            );
            rejoin!();
            continue;
        }
        // DataChannel open → machine resets the retry budget.
        machine.handle(ConnEvent::DcOpen);

        // 7c. Resume point from the relay checkpoint (BUG-9/10).
        let start_chunk = last_chunk_offset;
        if start_chunk > 0 {
            super::log::step(&format!("↻ Resuming from chunk {start_chunk}"));
        }

        sender.send_verify(&proof)?;

        let cipher = crate::crypto::StreamCipher::new(&password, total_bytes as u64);
        let stream_meta = cipher.metadata();
        let total_chunks = stream_meta.total_chunks as u64;
        let engine = SenderEngine::new(total_chunks, 256);
        let transport = BufTransport { text_queue: Vec::new(), binary_queue: Vec::new() };
        let mut adapter = SenderAdapter::new(
            engine, LocalCipher(cipher), transport, &bytes, chunk_size, total_chunks, meta_extra.clone(),
        );
        adapter.start(start_chunk);

        let drop_at = if test_drop_armed { test_drop_after } else { None };

        // Drive the adapter: flush queued frames to WebRTC, consume ack/request.
        let send_result: Result<()> = async {
            loop {
                let texts: Vec<String> = adapter.transport_mut().text_queue.drain(..).collect();
                for t in texts {
                    sender.send_frame(t).await?;
                }
                let bins: Vec<Vec<u8>> = adapter.transport_mut().binary_queue.drain(..).collect();
                let bin_count = bins.len();
                for b in bins {
                    sender.send_binary(b).await?;
                }
                let sent_bytes = total_bytes.min(
                    (adapter.engine_sent_through().unwrap_or(0) as usize + 1) * chunk_size
                );
                if bin_count > 0 {
                    super::log::event(&format!(
                        "sent {bin_count} chunk(s) — {} / {}",
                        super::format_size(sent_bytes),
                        super::format_size(total_bytes),
                    ));
                    super::display::transfer_progress(sent_bytes, total_bytes);
                }

                // Test-only one-shot drop to exercise resume.
                if let Some(th) = drop_at {
                    if (sent_bytes as u64) >= th {
                        return Err(anyhow::anyhow!("test-induced drop"));
                    }
                }

                if adapter.is_finished() {
                    break;
                }

                tokio::select! {
                    biased;
                    val = control.events.ack.recv() => {
                        if let Some(v) = val {
                            let through = v["through"].as_u64().unwrap_or(0);
                            adapter.on_ack(through);
                        } else {
                            return Err(anyhow::anyhow!("control socket closed during transfer"));
                        }
                    }
                    val = control.events.request.recv() => {
                        if let Some(v) = val {
                            let from = v["from"].as_u64().unwrap_or(0);
                            adapter.on_request(from);
                        } else {
                            return Err(anyhow::anyhow!("control socket closed during transfer"));
                        }
                    }
                    val = control.events.complete.recv() => {
                        if val.is_some() {
                            adapter.complete();
                        }
                        break;
                    }
                    event = sender.next_event() => {
                        match event {
                            Some(crate::webrtc::LoopEvent::Error(e)) => {
                                return Err(anyhow::anyhow!("WebRTC error during transfer: {e}"));
                            }
                            Some(crate::webrtc::LoopEvent::Done) | None => {
                                return Err(anyhow::anyhow!("DataChannel closed during transfer"));
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(())
        }.await;

        if let Err(e) = send_result {
            if e.to_string().contains("test-induced drop") {
                test_drop_armed = false; // fire once
            }
            super::log::blank();
            // close_and_flush (awaited) guarantees the Close reaches the event loop
            // even when the cmd channel is full, so wait_closed can't hang.
            sender.close_and_flush().await;
            sender.wait_closed().await;
            machine_retry!(
                &format!("transfer interrupted: {e}"),
                format!("Transfer failed after {} retries: {e}", crate::retry::DEFAULT.max_retries)
            );
            rejoin!();
            continue;
        }

        // 8. Cleanup — wait for the receiver's complete (011 handshake) → exit 0.
        sender.close_and_flush().await;
        sender.wait_closed().await;
        super::log::blank();
        super::display::status("Transfer complete.");
        control.complete("sender", &content_checksum)?;
        return Ok(());
    }
}

async fn run_inner(
    content: impl Into<String>,
    password: impl Into<String>,
    mode: impl Into<String>,
    content_type_flag: impl Into<String>,
    server: Option<String>,
    local: bool,
    ttl: Option<String>,
    one_time: bool,
    relay_only: bool,
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    let content = content.into();
    let password = password.into();
    let mode: String = mode.into();
    let content_type_flag = content_type_flag.into();

    if local && mode != "p2p" {
        anyhow::bail!("--local requires --p2p");
    }

    validate(&content, &password, &mode, &content_type_flag)?;

    if mode == "p2p" {
        return run_p2p(content, password, content_type_flag, server, local, relay_only, output).await;
    }
    let ttl_secs = parse_ttl(ttl.as_deref())?;
    run_server(content, password, content_type_flag, server, ttl_secs, one_time, output).await
}

async fn run_server(
    content: String,
    password: String,
    content_type_flag: String,
    server: Option<String>,
    ttl_secs: u64,
    one_time: bool,
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    let client = ApiClient::new(server_url(server.as_deref())?);
    let content_type = resolve_content_type(&content_type_flag);
    let ReadInput { bytes, file_metadata } = read_input(&content, content_type)?;
    super::log::event(&format!("encrypting {} ({content_type})", super::format_size(bytes.len())));
    let spinner = super::display::Spinner::start(
        &format!("Encrypting {} …", super::format_size(bytes.len())),
    );
    let content_checksum = crate::crypto::sha256_bytes(&bytes);
    let result = encrypt_bytes(&bytes, &password);
    let challenge = generate_challenge(&password);
    drop(spinner);

    let total = result.encrypted_payload.len();
    let _ = output; // status now routed through the leveled logger
    super::log::step(&format!("Uploading {} bytes…", total));
    let resp = client
        .create_share(CreateShareRequest {
            content_type: content_type.into(),
            encrypted_payload: result.encrypted_payload,
            encryption_metadata: result.encryption_metadata,
            file_metadata,
            one_time_read: one_time,
            expires_at: expires_at(ttl_secs),
            challenge_plaintext: challenge.challenge_plaintext,
            encrypted_challenge: challenge.encrypted_challenge,
            challenge_metadata: challenge.challenge_metadata,
            content_checksum,
        })
        .await?;

    let share_url = match user_url() {
        Some(base) => format!("{}/s/{}", base.trim_end_matches('/'), resp.share_id),
        None => resp.share_url,
    };
    let manage_url = match user_url() {
        Some(base) => format!("{}/manage", base.trim_end_matches('/')),
        None => String::new(),
    };
    super::display::print_server_share_result(
        &resp.share_id,
        &share_url,
        &resp.owner_code,
        &manage_url,
    );
    Ok(())
}

async fn run_p2p(
    content: String,
    password: String,
    content_type_flag: String,
    server: Option<String>,
    local: bool,
    relay_only: bool,
    _output: &mut dyn FnMut(&str),
) -> Result<()> {
    let base = server_url(server.as_deref())?;
    let client = ApiClient::new(&base);
    let content_type = resolve_content_type(&content_type_flag);
    let ReadInput { bytes, file_metadata } = read_input(&content, content_type)?;

    // 1. Derive password proof + checksum (streaming: no upfront encryption)
    let content_checksum = crate::crypto::sha256_bytes(&bytes);
    let proof = sha256_hex(&password);

    // 2. Create P2P session on the server
    super::log::event("creating session");
    let session = client.create_p2p_session(&proof).await?;
    super::log::event(&format!("session created {}", session.session_id));
    let p2p_url = match user_url() {
        Some(base) => format!("{}/p2p/{}", base.trim_end_matches('/'), session.session_id),
        None => session.share_url,
    };
    super::display::print_p2p_share_result(&session.session_id, &p2p_url);

    // 2b. Broadcast URL on local network if -n local
    let _broadcast_guard = if local {
        Some(crate::local::broadcast(&p2p_url)?)
    } else {
        None
    };

    // 3. Fetch ICE servers
    let ice_servers = client.get_ice_servers().await.unwrap_or_default();

    // 4. Connect socket as sender
    let ws_url = TungsteniteWs::build_url(&base)?;
    super::log::event(&format!("connecting to {ws_url}"));
    let ws = TungsteniteWs::connect(&ws_url).await?;
    let (transport, evts) = SocketIoTransport::connect(ws, "p2p").await?;
    super::log::event("connected (socket)");
    let mut control = P2PControl::new(transport, evts);

    // 4b. Emit join
    control.join(&session.session_id, "sender")?;

    // 5. Wait for joined ack — capture the server's cumulative-ACK checkpoint so we
    //    resume (not restart) after a drop. (BUG-10)
    let mut last_chunk_offset: u64 = tokio::select! {
        biased;
        j = control.events.joined.recv() => {
            let j = j.ok_or_else(|| anyhow::anyhow!("socket closed before joined"))?;
            j.get("lastChunkOffset").and_then(|v| v.as_u64()).unwrap_or(0)
        }
        err = control.events.error.recv() => {
            bail!("signaling error before joined: {}", err.unwrap_or_else(|| "unknown".into()));
        }
    };

    // 6. Reconnection driven by the shared `ConnectionMachine` (same pure model as
    //    the web client, task 001/013). The machine owns the retry budget, backoff,
    //    fatal-vs-transient classification, and the resume checkpoint; this loop
    //    feeds it lifecycle events and executes its decisions.
    use crate::p2p::connection::{ConnEvent, ConnPhase, ConnectionMachine};
    let mut machine = ConnectionMachine::new(
        crate::retry::DEFAULT.max_retries,
        crate::retry::DEFAULT.backoff_ms.to_vec(),
        crate::retry::CHANNEL_TIMEOUT_SECS * 1000,
    );
    machine.handle(ConnEvent::Start);
    machine.handle(ConnEvent::SocketUp);
    machine.handle(ConnEvent::Joined { last_chunk_offset, generation: 0 });

    // Test-only one-shot mid-transfer drop (CLI analog of the web PC-close), so the
    // online resume path runs deterministically in e2e. Inert in production.
    let test_drop_after: Option<u64> = std::env::var("NULLSEAL_TEST_DROP_AFTER_BYTES")
        .ok()
        .and_then(|s| s.parse().ok());
    let mut test_drop_armed = test_drop_after.is_some();

    // Helper: reconnect socket if dead, then emit join
    macro_rules! rejoin {
        () => {{
            // Discard stale signaling from the previous round BEFORE re-joining so
            // the next `await_ready` blocks on the FRESH `both_ready` that THIS
            // re-join triggers. A leftover `both_ready` would otherwise make us
            // send an offer against a stale state → server `invalid_state`.
            super::p2p_stages::drain(&mut control.events.both_ready);
            super::p2p_stages::drain(&mut control.events.answer);
            super::p2p_stages::drain(&mut control.events.ice);
            // Clear stale errors (e.g. a `peer_timeout` from the previous round)
            // so the next `await_ready` doesn't immediately act on them.
            super::p2p_stages::drain(&mut control.events.error);
            if !control.is_alive() {
                let ws = TungsteniteWs::connect(&ws_url).await?;
                let (transport, evts) = SocketIoTransport::connect(ws, "p2p").await?;
                control = P2PControl::new(transport, evts);
                control.join(&session.session_id, "sender")?;
                // Wait for joined ack on new socket; refresh the resume checkpoint.
                let j = control.events.joined.recv().await
                    .ok_or_else(|| anyhow::anyhow!("socket closed before joined on reconnect"))?;
                last_chunk_offset = j.get("lastChunkOffset").and_then(|v| v.as_u64()).unwrap_or(last_chunk_offset);
                machine.handle(ConnEvent::SocketUp);
                machine.handle(ConnEvent::Joined { last_chunk_offset, generation: 0 });
            } else {
                control.join(&session.session_id, "sender")?;
                // Re-join on the live socket also emits a fresh `joined` — read it to
                // pick up the latest checkpoint before resuming.
                if let Some(j) = control.events.joined.recv().await {
                    last_chunk_offset = j.get("lastChunkOffset").and_then(|v| v.as_u64()).unwrap_or(last_chunk_offset);
                }
                machine.handle(ConnEvent::Joined { last_chunk_offset, generation: 0 });
            }
        }};
    }

    // Drive one failure through the machine: it decides retry-with-backoff vs
    // Stopped (manual prompt) vs Expired. Returns nothing; the caller `rejoin!`s
    // and `continue`s. `$reason` labels the retry; `$bail` is the give-up message.
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
        // 6a. Wait for ready (recipient has joined). First attempt (machine budget
        //     not yet spent) waits indefinitely; retries use the peer timeout.
        let got_ready = super::p2p_stages::await_ready(&mut control.events, machine.attempts() == 0).await?;

        if !got_ready {
            machine_retry!(
                "recipient not ready…",
                format!("Recipient did not rejoin after {} retries.", crate::retry::DEFAULT.max_retries)
            );
            rejoin!();
            continue;
        }
        super::display::status("Recipient connected. Starting transfer…");

        // 7. Create WebRTC sender peer + offer
        // Drain stale signaling events from previous rounds
        while control.events.answer.try_recv().is_ok() {}
        while control.events.ice.try_recv().is_ok() {}

        let mut sender = if relay_only {
            SenderPeer::new_relay_only(ice_servers.clone(), None).await?
        } else {
            SenderPeer::new(ice_servers.clone(), None).await?
        };
        control.offer(&sender.offer_sdp_json())?;

        // 8. Wait for answer + relay ICE candidates
        super::p2p_stages::await_answer(&sender, &mut control.events).await?;

        // 9. Wait for DataChannel open
        let channel_open = super::p2p_stages::await_sender_channel(&mut sender, &mut control.events).await?;

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

        // 10. Resume point = p2p:joined lastChunkOffset (server's cumulative-ACK
        //     checkpoint, refreshed by `rejoin!`). Equals the receiver's `resume_from`
        //     so the cipher nonce stays aligned. (BUG-10) The machine tracks the same
        //     value for its own budget logic, but `last_chunk_offset` is the I/O truth.
        let start_chunk = last_chunk_offset;
        if start_chunk > 0 {
            super::log::step(&format!("↻ Resuming from chunk {start_chunk}"));
        }

        // 11. Send verify + stream via SenderAdapter (v2 binary protocol)
        sender.send_verify(&proof)?;

        let cipher = crate::crypto::StreamCipher::new(&password, bytes.len() as u64);
        let stream_meta = cipher.metadata();
        let chunk_size = crate::crypto::STREAM_CHUNK_SIZE;
        let total_chunks = stream_meta.total_chunks as u64;

        // Build metadata extra fields (camelCase, matching web)
        let meta_extra = serde_json::json!({
            "contentType": content_type,
            "fileMetadata": file_metadata.as_ref().map(|fm| serde_json::to_value(fm).unwrap()),
            "contentChecksum": &content_checksum,
        });

        // Create the adapter with a collecting transport; we drive it
        // in a loop feeding ack/request from the socket.
        use crate::p2p::sender_adapter::{SenderAdapter, SenderCipherT, SenderTransport};
        use crate::p2p::sender_engine::SenderEngine;

        struct RealCipher(crate::crypto::StreamCipher);
        impl SenderCipherT for RealCipher {
            fn metadata(&self) -> serde_json::Value {
                serde_json::to_value(self.0.metadata()).unwrap()
            }
            fn chunk_index(&self) -> u64 { self.0.chunk_index() }
            fn skip_to(&mut self, index: u64) { self.0.skip_to(index); }
            fn encrypt_chunk(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
                self.0.encrypt_chunk(plaintext).map_err(|e| anyhow::anyhow!("{e}"))
            }
        }

        // Buffered transport: collects frames to be sent asynchronously
        struct BufTransport {
            text_queue: Vec<String>,
            binary_queue: Vec<Vec<u8>>,
        }
        impl SenderTransport for BufTransport {
            fn send_text(&mut self, s: String) { self.text_queue.push(s); }
            fn send_binary(&mut self, b: Vec<u8>) { self.binary_queue.push(b); }
        }

        let engine = SenderEngine::new(total_chunks, 256);
        let transport = BufTransport { text_queue: Vec::new(), binary_queue: Vec::new() };
        let real_cipher = RealCipher(cipher);
        let mut adapter = SenderAdapter::new(
            engine, real_cipher, transport, &bytes, chunk_size, total_chunks, meta_extra,
        );

        adapter.start(start_chunk);

        // Drive the adapter: flush queued frames to WebRTC, consume ack/request
        let total_bytes = bytes.len();
        let drop_at = if test_drop_armed { test_drop_after } else { None };
        let send_result: Result<()> = async {
            loop {
                // Flush text frames
                let texts: Vec<String> = adapter.transport_mut().text_queue.drain(..).collect();
                for t in texts {
                    sender.send_frame(t).await?;
                }
                // Flush binary frames
                let bins: Vec<Vec<u8>> = adapter.transport_mut().binary_queue.drain(..).collect();
                let bin_count = bins.len();
                for b in bins {
                    sender.send_binary(b).await?;
                }
                let sent_bytes = total_bytes.min(
                    (adapter.engine_sent_through().unwrap_or(0) as usize + 1) * chunk_size
                );
                if bin_count > 0 {
                    super::log::event(&format!(
                        "sent {bin_count} chunk(s) — {} / {}",
                        super::format_size(sent_bytes),
                        super::format_size(total_bytes),
                    ));
                    super::display::transfer_progress(sent_bytes, total_bytes);
                }

                // Test-only one-shot drop to exercise the resume path deterministically.
                if let Some(th) = drop_at {
                    if (sent_bytes as u64) >= th {
                        return Err(anyhow::anyhow!("test-induced drop"));
                    }
                }

                if adapter.is_finished() {
                    break;
                }

                // Wait for socket events (ack/request/complete) or DC errors
                tokio::select! {
                    biased;
                    val = control.events.ack.recv() => {
                        if let Some(v) = val {
                            let through = v["through"].as_u64().unwrap_or(0);
                            adapter.on_ack(through);
                        } else {
                            break; // socket closed
                        }
                    }
                    val = control.events.request.recv() => {
                        if let Some(v) = val {
                            let from = v["from"].as_u64().unwrap_or(0);
                            adapter.on_request(from);
                        } else {
                            break;
                        }
                    }
                    val = control.events.complete.recv() => {
                        if val.is_some() {
                            adapter.complete();
                        }
                        break;
                    }
                    event = sender.next_event() => {
                        match event {
                            Some(crate::webrtc::LoopEvent::Error(e)) => {
                                return Err(anyhow::anyhow!("WebRTC error during transfer: {e}"));
                            }
                            Some(crate::webrtc::LoopEvent::Done) | None => {
                                return Err(anyhow::anyhow!("DataChannel closed during transfer"));
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(())
        }.await;

        if let Err(e) = send_result {
            if e.to_string().contains("test-induced drop") {
                test_drop_armed = false; // fire once
            }
            super::log::blank();
            sender.close();
            sender.wait_closed().await;
            machine_retry!(
                &format!("transfer interrupted: {e}"),
                format!("Transfer failed after {} retries: {e}", crate::retry::DEFAULT.max_retries)
            );
            rejoin!();
            continue;
        }

        // 12. Wait for data to flush, then signal done + cleanup
        sender.close_and_flush().await;
        sender.wait_closed().await;

        super::log::blank();
        super::display::status("Transfer complete.");

        control.complete("sender", &content_checksum)?;
        control.delete()?;
        return Ok(());
    }
}

fn parse_ttl(ttl: Option<&str>) -> Result<u64> {
    let s = match ttl {
        Some(v) => v.trim(),
        None => return Ok(DEFAULT_TTL_SECS),
    };
    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86400u64)
    } else {
        bail!("Invalid TTL format: \"{s}\". Use e.g. 1h, 24h, 3d, 7d.");
    };
    let num: u64 = num_str.parse().map_err(|_| anyhow::anyhow!("Invalid TTL number: \"{num_str}\"."))?;
    if num == 0 {
        bail!("TTL must be at least 1h.");
    }
    let secs = num * multiplier;
    if secs > MAX_TTL_SECS {
        bail!("TTL cannot exceed 7 days (168h).");
    }
    Ok(secs)
}

fn expires_at(ttl_secs: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
        + ttl_secs;
    unix_to_iso(secs)
}

fn unix_to_iso(s: u64) -> String {
    let sec = (s % 60) as u8;
    let min = ((s / 60) % 60) as u8;
    let hour = ((s / 3600) % 24) as u8;
    let (y, mo, d) = days_to_ymd(s / 86400);
    format!("{y:04}-{mo:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u8, u8) {
    let mut year = 1970u64;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy { break; }
        days -= dy;
        year += 1;
    }
    let months = [31u8, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u8;
    for dm in months {
        if days < dm as u64 { break; }
        days -= dm as u64;
        month += 1;
    }
    (year, month, days as u8 + 1)
}

fn is_leap(y: u64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mock_server() -> (MockServer, String) {
        let server = MockServer::start().await;
        let url = server.uri();
        (server, url)
    }

    fn share_ok_body() -> serde_json::Value {
        serde_json::json!({
            "shareId": "s1",
            "shareUrl": "https://nullseal.com/s/s1",
            "ownerCode": "oc1",
            "expiresAt": "2099-01-01T00:00:00Z"
        })
    }

    #[tokio::test]
    async fn server_upload_logs_url_and_owner_code() {
        let (server, url) = mock_server().await;
        Mock::given(method("POST"))
            .and(path("/shares"))
            .respond_with(ResponseTemplate::new(200).set_body_json(share_ok_body()))
            .mount(&server)
            .await;

        // Rich display now goes to stderr; just verify the command succeeds
        run("hello", "password", "u", "txt", Some(url), None, true, false, &mut |_| {})
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sends_password_content_type_for_pwd() {
        let (server, url) = mock_server().await;
        Mock::given(method("POST"))
            .and(path("/shares"))
            .respond_with(ResponseTemplate::new(200).set_body_json(share_ok_body()))
            .mount(&server)
            .await;

        run("hunter2", "password", "u", "pwd", Some(url), None, true, false, &mut |_| {})
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["contentType"], "password");
    }

    #[tokio::test]
    async fn rejects_short_password() {
        let err = run("hi", "ab", "u", "txt", None, None, true, false, &mut |_| {}).await.unwrap_err();
        assert!(err.to_string().contains("Password"));
    }

    #[tokio::test]
    async fn rejects_empty_content() {
        let err = run("   ", "password", "u", "txt", None, None, true, false, &mut |_| {}).await.unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[tokio::test]
    async fn rejects_unsupported_extension() {
        let err = run("script.exe", "password", "u", "file", None, None, true, false, &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unsupported"));
    }

    #[tokio::test]
    async fn uploads_file_with_metadata() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::with_suffix(".pdf").unwrap();
        tmp.write_all(b"fake pdf").unwrap();
        let tmp_path = tmp.path().to_str().unwrap().to_owned();

        let (server, url) = mock_server().await;
        Mock::given(method("POST"))
            .and(path("/shares"))
            .respond_with(ResponseTemplate::new(200).set_body_json(share_ok_body()))
            .mount(&server)
            .await;

        run(tmp_path, "password", "u", "file", Some(url), None, true, false, &mut |_| {})
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["contentType"], "file");
        assert!(body["fileMetadata"]["filename"].as_str().unwrap().ends_with(".pdf"));
    }

    #[tokio::test]
    async fn propagates_api_error() {
        let (server, url) = mock_server().await;
        Mock::given(method("POST"))
            .and(path("/shares"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let err = run("hello", "password", "u", "txt", Some(url), None, true, false, &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Request failed"));
    }

    // ── validate ─────────────────────────────────────────────────────────

    #[test]
    fn validate_ok_text() {
        validate("hello", "password", "u", "txt").unwrap();
    }

    #[test]
    fn validate_rejects_too_long_text() {
        let long = "x".repeat(MAX_TEXT_LENGTH + 1);
        let err = validate(&long, "password", "u", "txt").unwrap_err();
        assert!(err.to_string().contains("characters"));
    }

    #[test]
    fn validate_p2p_allows_any_file_extension() {
        // In p2p mode, unsupported extensions should be allowed
        validate("script.exe", "password", "p2p", "file").unwrap();
    }

    #[test]
    fn validate_server_rejects_too_large_file() {
        use std::io::Write;
        // Write just over 2 MB to a temp file
        let mut tmp = tempfile::NamedTempFile::with_suffix(".pdf").unwrap();
        // Create a sparse-like file by seeking past 2MB+1
        let size = SERVER_MAX_BYTES + 1;
        tmp.as_file().set_len(size).unwrap();
        tmp.write_all(b"x").unwrap(); // force file creation
        let path = tmp.path().to_str().unwrap().to_owned();
        let err = validate(&path, "password", "u", "file").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("limit"));
    }

    // ── resolve_content_type ─────────────────────────────────────────────

    #[test]
    fn resolve_content_type_file() {
        assert_eq!(resolve_content_type("file"), "file");
    }

    #[test]
    fn resolve_content_type_pwd() {
        assert_eq!(resolve_content_type("pwd"), "password");
    }

    #[test]
    fn resolve_content_type_txt() {
        assert_eq!(resolve_content_type("txt"), "text");
    }

    #[test]
    fn resolve_content_type_unknown_defaults_to_text() {
        assert_eq!(resolve_content_type("xyz"), "text");
    }

    // ── file_extension ───────────────────────────────────────────────────

    #[test]
    fn file_extension_pdf() {
        assert_eq!(file_extension("doc.PDF"), ".pdf");
    }

    #[test]
    fn file_extension_none() {
        assert_eq!(file_extension("Makefile"), "");
    }

    #[test]
    fn file_extension_hidden_file() {
        assert_eq!(file_extension(".gitignore"), "");
    }

    // ── run_inner: mode validation ───────────────────────────────────────

    #[tokio::test]
    async fn run_inner_local_requires_p2p() {
        let err = run_inner("hello", "password", "u", "txt", None, true, None, true, false, &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().contains("--local requires --p2p"));
    }

    // ── server upload: content types ─────────────────────────────────────

    #[tokio::test]
    async fn server_upload_file_sends_file_content_type() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::with_suffix(".txt").unwrap();
        tmp.write_all(b"content").unwrap();
        let tmp_path = tmp.path().to_str().unwrap().to_owned();

        let (server, url) = mock_server().await;
        Mock::given(method("POST"))
            .and(path("/shares"))
            .respond_with(ResponseTemplate::new(200).set_body_json(share_ok_body()))
            .mount(&server)
            .await;

        run(tmp_path, "password", "u", "file", Some(url), None, true, false, &mut |_| {})
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["contentType"], "file");
    }

    #[tokio::test]
    async fn server_upload_text_sends_text_content_type() {
        let (server, url) = mock_server().await;
        Mock::given(method("POST"))
            .and(path("/shares"))
            .respond_with(ResponseTemplate::new(200).set_body_json(share_ok_body()))
            .mount(&server)
            .await;

        run("hello world", "password", "u", "txt", Some(url), None, true, false, &mut |_| {})
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["contentType"], "text");
    }

    // ── parse_ttl ────────────────────────────────────────────────────────

    #[test]
    fn parse_ttl_default_is_24h() {
        assert_eq!(parse_ttl(None).unwrap(), 24 * 3600);
    }

    #[test]
    fn parse_ttl_hours() {
        assert_eq!(parse_ttl(Some("1h")).unwrap(), 3600);
        assert_eq!(parse_ttl(Some("48h")).unwrap(), 48 * 3600);
        assert_eq!(parse_ttl(Some("168h")).unwrap(), 168 * 3600);
    }

    #[test]
    fn parse_ttl_days() {
        assert_eq!(parse_ttl(Some("1d")).unwrap(), 86400);
        assert_eq!(parse_ttl(Some("7d")).unwrap(), 7 * 86400);
    }

    #[test]
    fn parse_ttl_rejects_over_7d() {
        let err = parse_ttl(Some("8d")).unwrap_err();
        assert!(err.to_string().contains("7 days"));
        let err = parse_ttl(Some("169h")).unwrap_err();
        assert!(err.to_string().contains("7 days"));
    }

    #[test]
    fn parse_ttl_rejects_zero() {
        let err = parse_ttl(Some("0h")).unwrap_err();
        assert!(err.to_string().contains("at least"));
    }

    #[test]
    fn parse_ttl_rejects_invalid_format() {
        let err = parse_ttl(Some("24")).unwrap_err();
        assert!(err.to_string().contains("Invalid TTL format"));
        let err = parse_ttl(Some("abc")).unwrap_err();
        assert!(err.to_string().contains("Invalid TTL format"));
    }

    // ── one_time flag ────────────────────────────────────────────────────

    #[tokio::test]
    async fn server_upload_respects_one_time_false() {
        let (server, url) = mock_server().await;
        Mock::given(method("POST"))
            .and(path("/shares"))
            .respond_with(ResponseTemplate::new(200).set_body_json(share_ok_body()))
            .mount(&server)
            .await;

        run("hello", "password", "u", "txt", Some(url), None, false, false, &mut |_| {})
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["oneTimeRead"], false);
    }

    #[tokio::test]
    async fn server_upload_respects_custom_ttl() {
        let (server, url) = mock_server().await;
        Mock::given(method("POST"))
            .and(path("/shares"))
            .respond_with(ResponseTemplate::new(200).set_body_json(share_ok_body()))
            .mount(&server)
            .await;

        run("hello", "password", "u", "txt", Some(url), Some("1h".into()), true, false, &mut |_| {})
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        // expiresAt should be roughly 1h from now, not 7d
        let expires = body["expiresAt"].as_str().unwrap();
        assert!(!expires.is_empty());
    }
}
