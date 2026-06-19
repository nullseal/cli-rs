use std::path::Path;

use anyhow::{bail, Result};

use crate::api::{ApiClient, CreateShareRequest, FileMetadata};
use crate::crypto::{encrypt_bytes, sha256_hex};
use crate::local_signal::SignalServer;
use crate::socket::P2PSocket;
use crate::webrtc::SenderPeer;

const MIN_PASSWORD_LEN: usize = 3;
const SERVER_MAX_BYTES: u64 = 2 * 1024 * 1024; // 2 MB
const MAX_TEXT_LENGTH: usize = 100_000;

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
                bail!("File exceeds server upload limit (2 MB).");
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
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    run_inner(content, password, mode, content_type_flag, server, false, output).await
}

/// Same as `run` but broadcasts the P2P URL on the local network via mDNS.
pub async fn run_with_local(
    content: impl Into<String>,
    password: impl Into<String>,
    mode: impl Into<String>,
    content_type_flag: impl Into<String>,
    server: Option<String>,
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    run_inner(content, password, mode, content_type_flag, server, true, output).await
}

/// Fully local transfer — no server needed.
/// Sender binds a TCP signaling server, does WebRTC locally.
pub async fn run_local(
    content: impl Into<String>,
    password: impl Into<String>,
    content_type_flag: impl Into<String>,
    bind_addr: Option<String>,
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    let content = content.into();
    let password = password.into();
    let content_type_flag = content_type_flag.into();

    // Validate (use p2p mode rules — no server size limit)
    validate(&content, &password, "p2p", &content_type_flag)?;

    let content_type = resolve_content_type(&content_type_flag);
    let ReadInput { bytes, file_metadata } = read_input(&content, content_type)?;

    // 1. Encrypt + derive password proof
    let result = encrypt_bytes(&bytes, &password);
    let proof = sha256_hex(&password);

    // 2. Bind TCP signaling server
    let local_ip = bind_addr.unwrap_or_else(|| {
        crate::webrtc::discover_local_ip().to_string()
    });
    let signal_server = match SignalServer::bind_to(&local_ip).await {
        Ok(s) => s,
        Err(_) => SignalServer::bind().await?,
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

    // 8. Wait for DataChannel open
    loop {
        match sender.next_event().await {
            Some(crate::webrtc::LoopEvent::ChannelOpen) => break,
            Some(crate::webrtc::LoopEvent::Error(e)) => bail!("WebRTC error: {e}"),
            None => bail!("WebRTC closed before channel open"),
            _ => {}
        }
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
        &|sent, total| {
            eprint!("\rSending: {}/{}\x1b[K", super::format_size(sent), super::format_size(total));
        },
    )?;
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
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    let content = content.into();
    let password = password.into();
    let mode: String = mode.into();
    let content_type_flag = content_type_flag.into();

    if local && mode != "p2p" {
        anyhow::bail!("-n local requires -m p2p");
    }

    validate(&content, &password, &mode, &content_type_flag)?;

    if mode == "p2p" {
        return run_p2p(content, password, content_type_flag, server, local, output).await;
    }
    run_server(content, password, content_type_flag, server, output).await
}

async fn run_server(
    content: String,
    password: String,
    content_type_flag: String,
    server: Option<String>,
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    let client = ApiClient::new(server_url(server.as_deref())?);
    let content_type = resolve_content_type(&content_type_flag);
    let ReadInput { bytes, file_metadata } = read_input(&content, content_type)?;
    let result = encrypt_bytes(&bytes, &password);

    let total = result.encrypted_payload.len();
    output(&format!("Uploading {} bytes…", total));
    let resp = client
        .create_share(CreateShareRequest {
            content_type: content_type.into(),
            encrypted_payload: result.encrypted_payload,
            encryption_metadata: result.encryption_metadata,
            file_metadata,
            one_time_read: true,
            expires_at: expires_at_7_days(),
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
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    let base = server_url(server.as_deref())?;
    let client = ApiClient::new(&base);
    let content_type = resolve_content_type(&content_type_flag);
    let ReadInput { bytes, file_metadata } = read_input(&content, content_type)?;

    // 1. Encrypt + derive password proof
    let result = encrypt_bytes(&bytes, &password);
    let proof = sha256_hex(&password);

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
    let (socket, mut events) = P2PSocket::connect(&base, &session.session_id, "sender").await?;

    // 5. Wait for joined ack (also watch for errors)
    tokio::select! {
        biased;
        j = events.joined.recv() => {
            j.ok_or_else(|| anyhow::anyhow!("socket closed before joined"))?;
        }
        err = events.error.recv() => {
            bail!("signaling error before joined: {}", err.unwrap_or_else(|| "unknown".into()));
        }
    }

    // 6. Wait for ready (recipient has joined)
    tokio::select! {
        biased;
        r = events.ready.recv() => {
            r.ok_or_else(|| anyhow::anyhow!("socket closed before ready — session may have expired"))?;
        }
        err = events.error.recv() => {
            bail!("signaling error while waiting for recipient: {}", err.unwrap_or_else(|| "unknown".into()));
        }
    }
    eprintln!("\x1b[1;32m✓\x1b[0m Recipient connected. Starting transfer…");

    // 7. Create WebRTC sender peer + offer
    let mut sender = SenderPeer::new(ice_servers, None).await?;
    socket.send_offer(sender.offer_sdp_json()).await?;

    // 8. Wait for answer + relay ICE candidates concurrently
    loop {
        tokio::select! {
            biased;
            answer = events.answer.recv() => {
                if let Some(sdp) = answer {
                    sender.handle_answer(sdp)?;
                    break;
                }
                bail!("socket closed before answer");
            }
            ice = events.ice.recv() => {
                if let Some(c) = ice {
                    sender.add_ice_candidate(c)?;
                }
            }
            err = events.error.recv() => {
                if let Some(code) = err {
                    bail!("signaling error: {code}");
                }
            }
        }
    }

    // 9. Continue relaying ICE candidates and wait for DataChannel open
    loop {
        tokio::select! {
            biased;
            event = sender.next_event() => {
                match event {
                    Some(crate::webrtc::LoopEvent::ChannelOpen) => break,
                    Some(crate::webrtc::LoopEvent::Error(e)) => bail!("WebRTC error: {e}"),
                    None => bail!("WebRTC closed before channel open"),
                    _ => {}
                }
            }
            ice = events.ice.recv() => {
                if let Some(c) = ice {
                    sender.add_ice_candidate(c)?;
                }
            }
        }
    }

    // 10. Send encrypted transfer over DataChannel
    sender.send_verify(&proof)?;
    sender.send_transfer(
        &result.encrypted_payload,
        content_type,
        &result.encryption_metadata,
        file_metadata
            .as_ref()
            .map(|fm| serde_json::to_value(fm).unwrap())
            .as_ref(),
        &|sent, total| {
            eprint!("\rSending: {}/{}\x1b[K", super::format_size(sent), super::format_size(total));
        },
    )?;
    eprintln!();
    eprintln!("\x1b[1;32m✓\x1b[0m Transfer complete.");

    // 11. Signal done + cleanup
    socket.done().await?;
    sender.close();
    sender.wait_closed().await;
    socket.disconnect().await?;
    Ok(())
}

fn expires_at_7_days() -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
        + 7 * 24 * 3600;
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
        run("hello", "password", "u", "txt", Some(url), &mut |_| {})
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

        run("hunter2", "password", "u", "pwd", Some(url), &mut |_| {})
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["contentType"], "password");
    }

    #[tokio::test]
    async fn rejects_short_password() {
        let err = run("hi", "ab", "u", "txt", None, &mut |_| {}).await.unwrap_err();
        assert!(err.to_string().contains("Password"));
    }

    #[tokio::test]
    async fn rejects_empty_content() {
        let err = run("   ", "password", "u", "txt", None, &mut |_| {}).await.unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[tokio::test]
    async fn rejects_unsupported_extension() {
        let err = run("script.exe", "password", "u", "file", None, &mut |_| {})
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

        run(tmp_path, "password", "u", "file", Some(url), &mut |_| {})
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

        let err = run("hello", "password", "u", "txt", Some(url), &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Request failed"));
    }
}
