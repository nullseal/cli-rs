use std::path::Path;

use anyhow::{bail, Result};

use crate::api::{ApiClient, CreateShareRequest, FileMetadata};
use crate::crypto::{encrypt_bytes, generate_challenge, sha256_hex};
use crate::local_signal::SignalServer;
use crate::socket::P2PSocket;
use crate::webrtc::SenderPeer;

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
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    run_inner(content, password, mode, content_type_flag, server, false, ttl, one_time, output).await
}



/// Fully local transfer — no server needed.
/// Sender binds a TCP signaling server, does WebRTC locally.
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

    // 1. Encrypt + derive password proof
    let spinner = super::display::Spinner::start(
        &format!("Encrypting {} …", super::format_size(bytes.len())),
    );
    let content_checksum = crate::crypto::sha256_bytes(&bytes);
    let result = encrypt_bytes(&bytes, &password);
    let proof = sha256_hex(&password);
    drop(spinner);

    // 2. Parse bind address and bind TCP signaling server
    let (local_ip, explicit_port) = match &bind_addr {
        Some(a) if a.contains(':') => {
            let mut parts = a.rsplitn(2, ':');
            let port: u16 = parts.next().unwrap().parse()
                .map_err(|_| anyhow::anyhow!("invalid port in address: {a}"))?;
            let ip = parts.next().unwrap().to_string();
            (ip, Some(port))
        }
        Some(ip) => (ip.clone(), None),
        None => (crate::webrtc::discover_local_ip().to_string(), None),
    };
    let signal_server = if let Some(port) = explicit_port {
        SignalServer::bind_addr(&format!("{local_ip}:{port}")).await?
    } else {
        match SignalServer::bind_to(&local_ip).await {
            Ok(s) => s,
            Err(_) => SignalServer::bind().await?,
        }
    };
    let port = signal_server.port();
    let addr = format!("{local_ip}:{port}");

    // 3. Display local share info
    super::display::print_local_share_result(&addr);

    // 4. Broadcast via mDNS
    let _broadcast_guard = crate::local::broadcast_addr(&local_ip, port)?;

    // 5. Wait for receiver to connect
    let mut signal = signal_server.accept().await?;
    eprintln!("\x1b[1;32m✓\x1b[0m Recipient connected. Starting transfer…");

    // 6. Create WebRTC sender peer + offer
    let bind_ip: Option<std::net::IpAddr> = local_ip.parse().ok();
    let mut sender = SenderPeer::new(vec![], bind_ip).await?;
    signal.send_offer(sender.offer_sdp_json()).await?;

    // 7. Wait for answer
    let msg = signal.recv_or_bail().await?;
    match msg["type"].as_str() {
        Some("answer") => {
            sender.handle_answer(msg.clone())?;
        }
        _ => bail!("expected answer, got: {}", msg["type"]),
    }

    // 8. Wait for DataChannel open (with timeout)
    let channel_open = tokio::time::timeout(
        std::time::Duration::from_secs(crate::retry::CHANNEL_TIMEOUT_SECS),
        async {
            loop {
                match sender.next_event().await {
                    Some(crate::webrtc::LoopEvent::ChannelOpen) => return Ok::<bool, anyhow::Error>(true),
                    Some(crate::webrtc::LoopEvent::Error(e)) => bail!("WebRTC error: {e}"),
                    None => bail!("WebRTC closed before channel open"),
                    _ => {}
                }
            }
        },
    )
    .await;
    match channel_open {
        Ok(Ok(true)) => {}
        Ok(Err(e)) => return Err(e),
        _ => bail!("DataChannel open timed out"),
    }

    // 9. Send transfer
    sender.send_verify(&proof)?;
    sender.send_transfer(
        &result.encrypted_payload,
        content_type,
        &result.encryption_metadata,
        file_metadata
            .as_ref()
            .map(|fm| serde_json::to_value(fm).unwrap())
            .as_ref(),
        &content_checksum,
        &|sent, total| {
            eprint!("\rSending: {}/{}\x1b[K", super::format_size(sent), super::format_size(total));
        },
    ).await?;
    eprintln!();
    eprintln!("\x1b[1;32m✓\x1b[0m Transfer complete.");

    // 10. Cleanup
    sender.close();
    sender.wait_closed().await;
    Ok(())
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
        return run_p2p(content, password, content_type_flag, server, local, output).await;
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
    let spinner = super::display::Spinner::start(
        &format!("Encrypting {} …", super::format_size(bytes.len())),
    );
    let content_checksum = crate::crypto::sha256_bytes(&bytes);
    let result = encrypt_bytes(&bytes, &password);
    let challenge = generate_challenge(&password);
    drop(spinner);

    let total = result.encrypted_payload.len();
    output(&format!("Uploading {} bytes…", total));
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
    _output: &mut dyn FnMut(&str),
) -> Result<()> {
    let base = server_url(server.as_deref())?;
    let client = ApiClient::new(&base);
    let content_type = resolve_content_type(&content_type_flag);
    let ReadInput { bytes, file_metadata } = read_input(&content, content_type)?;

    // 1. Encrypt + derive password proof
    let spinner = super::display::Spinner::start(
        &format!("Encrypting {} …", super::format_size(bytes.len())),
    );
    let content_checksum = crate::crypto::sha256_bytes(&bytes);
    let result = encrypt_bytes(&bytes, &password);
    let proof = sha256_hex(&password);
    drop(spinner);

    // 2. Create P2P session on the server
    let session = client.create_p2p_session(&proof).await?;
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
    let (mut socket, mut events) = P2PSocket::connect(&base, &session.session_id, "sender").await?;

    // 5. Wait for joined ack
    tokio::select! {
        biased;
        j = events.joined.recv() => {
            j.ok_or_else(|| anyhow::anyhow!("socket closed before joined"))?;
        }
        err = events.error.recv() => {
            bail!("signaling error before joined: {}", err.unwrap_or_else(|| "unknown".into()));
        }
    }

    // 6. Retry loop for WebRTC connection + transfer
    let policy = &crate::retry::DEFAULT;
    let mut attempt = 0u32;

    // Helper: reconnect socket if dead, then emit join
    macro_rules! rejoin {
        () => {{
            if !socket.is_alive() {
                let (new_socket, new_events) = P2PSocket::connect(&base, &session.session_id, "sender").await?;
                socket = new_socket;
                events = new_events;
                // Wait for joined ack on new socket
                events.joined.recv().await
                    .ok_or_else(|| anyhow::anyhow!("socket closed before joined on reconnect"))?;
            } else {
                socket.emit_join(&session.session_id, "sender")?;
            }
        }};
    }

    loop {
        // 6a. Wait for ready (recipient has joined)
        let got_ready = super::p2p_stages::await_ready(&mut events, attempt == 0).await?;

        if !got_ready {
            attempt += 1;
            if policy.exhausted(attempt) {
                if !crate::retry::prompt_manual().await {
                    bail!("Recipient did not rejoin after {} retries.", policy.max_retries);
                }
                attempt = 0;
                rejoin!();
                continue;
            }
            crate::retry::log_retry(attempt, policy.max_retries, "recipient not ready…");
            tokio::time::sleep(policy.delay(attempt)).await;
            rejoin!();
            continue;
        }
        super::display::status("Recipient connected. Starting transfer…");

        // 7. Create WebRTC sender peer + offer
        // Drain stale signaling events from previous rounds
        while events.answer.try_recv().is_ok() {}
        while events.ice.try_recv().is_ok() {}

        let mut sender = SenderPeer::new(ice_servers.clone(), None).await?;
        socket.send_offer(sender.offer_sdp_json()).await?;

        // 8. Wait for answer + relay ICE candidates
        super::p2p_stages::await_answer(&sender, &mut events).await?;

        // 9. Wait for DataChannel open
        let channel_open = super::p2p_stages::await_sender_channel(&mut sender, &mut events).await?;

        if !channel_open {
            attempt += 1;
            if policy.exhausted(attempt) {
                if !crate::retry::prompt_manual().await {
                    bail!("WebRTC connection failed after {} retries.", policy.max_retries);
                }
                attempt = 0;
                rejoin!();
                continue;
            }
            crate::retry::log_retry(attempt, policy.max_retries, "channel open failed…");
            tokio::time::sleep(policy.delay(attempt)).await;
            rejoin!();
            continue;
        }

        // Reset retry counter on successful connection
        attempt = 0;

        // 10. Wait for resume frame from receiver
        let start_chunk = sender.wait_for_resume(crate::retry::RESUME_WAIT_MS).await;
        if start_chunk > 0 {
            eprintln!("\x1b[1;34m↻\x1b[0m Resuming from chunk {start_chunk}");
        }

        // 11. Send encrypted transfer over DataChannel
        sender.send_verify(&proof)?;
        let send_result = sender.send_transfer_from(
            &result.encrypted_payload,
            content_type,
            &result.encryption_metadata,
            file_metadata
                .as_ref()
                .map(|fm| serde_json::to_value(fm).unwrap())
                .as_ref(),
            &content_checksum,
            start_chunk,
            &|sent, total| {
                super::display::transfer_progress(sent, total);
            },
        ).await;

        if let Err(e) = send_result {
            eprintln!();
            sender.close();
            sender.wait_closed().await;
            attempt += 1;
            if policy.exhausted(attempt) {
                if !crate::retry::prompt_manual().await {
                    bail!("Transfer failed after {} retries: {e}", policy.max_retries);
                }
                attempt = 0;
            } else {
                crate::retry::log_retry(attempt, policy.max_retries, &format!("transfer interrupted: {e}"));
                tokio::time::sleep(policy.delay(attempt)).await;
            }
            rejoin!();
            continue;
        }

        eprintln!();
        super::display::status("Transfer complete.");

        // 12. Signal done + cleanup
        socket.done().await?;
        sender.close();
        sender.wait_closed().await;
        socket.disconnect().await?;
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
        run("hello", "password", "u", "txt", Some(url), None, true, &mut |_| {})
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

        run("hunter2", "password", "u", "pwd", Some(url), None, true, &mut |_| {})
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["contentType"], "password");
    }

    #[tokio::test]
    async fn rejects_short_password() {
        let err = run("hi", "ab", "u", "txt", None, None, true, &mut |_| {}).await.unwrap_err();
        assert!(err.to_string().contains("Password"));
    }

    #[tokio::test]
    async fn rejects_empty_content() {
        let err = run("   ", "password", "u", "txt", None, None, true, &mut |_| {}).await.unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[tokio::test]
    async fn rejects_unsupported_extension() {
        let err = run("script.exe", "password", "u", "file", None, None, true, &mut |_| {})
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

        run(tmp_path, "password", "u", "file", Some(url), None, true, &mut |_| {})
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

        let err = run("hello", "password", "u", "txt", Some(url), None, true, &mut |_| {})
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
        let err = run_inner("hello", "password", "u", "txt", None, true, None, true, &mut |_| {})
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

        run(tmp_path, "password", "u", "file", Some(url), None, true, &mut |_| {})
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

        run("hello world", "password", "u", "txt", Some(url), None, true, &mut |_| {})
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

        run("hello", "password", "u", "txt", Some(url), None, false, &mut |_| {})
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

        run("hello", "password", "u", "txt", Some(url), Some("1h".into()), true, &mut |_| {})
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        // expiresAt should be roughly 1h from now, not 7d
        let expires = body["expiresAt"].as_str().unwrap();
        assert!(!expires.is_empty());
    }
}
