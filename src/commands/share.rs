use std::path::Path;

use anyhow::{bail, Result};

use crate::api::{ApiClient, CreateShareRequest, FileMetadata};
use crate::crypto::{encrypt_bytes, generate_challenge, sha256_hex};
use crate::webrtc::SenderPeer;
use nullseal_p2p_control::control::P2PControl;
use nullseal_p2p_control::transport::SocketIoTransport;
use nullseal_socketio::transport::TungsteniteWs;

const MIN_PASSWORD_LEN: usize = 3;
/// Fallback upload limit when `GET /shares/config` is unavailable (task 056:
/// the backend is authoritative — see `fetch_server_limit`). 10 MB matches the
/// server default (base64 in one Mongo doc; do not raise further).
const SERVER_MAX_BYTES: u64 = 10 * 1024 * 1024;
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
    // Env files (.env, .env.local, .env.production …) have unbounded suffixes;
    // normalise them all to ".env" so a single allow-list entry covers the family
    // and the server (which only sees this extension, never the filename) can validate it.
    let base = Path::new(filename)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if base == ".env" || base.starts_with(".env.") {
        return ".env".to_string();
    }
    Path::new(filename)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default()
}

fn validate(content: &str, password: &str, mode: &str, content_type: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN {
        bail!("Password must be at least {MIN_PASSWORD_LEN} characters.");
    }
    if content_type == "zip" {
        // Folder share (task 051, amended: explicit `--zip`): the directory is
        // packed into a `.zip`, so the extension allow-list doesn't apply to the
        // directory's own name. Task 058 lifted 056's upload-only gate — `--zip`
        // is legal in every mode; upload keeps the backend size limit (enforced
        // in run_server), p2p/local stream through the DataChannel with no limit.
        if !Path::new(content).is_dir() {
            bail!("--zip requires a directory, but \"{content}\" is not one.");
        }
        return Ok(());
    }
    if content_type == "sync" {
        // Direct folder sync (task 058): no archive, so there is nothing a server
        // share could store — p2p/local only. Backstops the main.rs flag gate for
        // the library entry points.
        if mode != "p2p" {
            bail!("{SYNC_UPLOAD_ERROR}");
        }
        if !Path::new(content).is_dir() {
            bail!("--sync requires a directory, but \"{content}\" is not one.");
        }
        return Ok(());
    }
    if content_type == "file" {
        // A directory is never read as a plain file — folder shares are the
        // explicit `--zip` path (task 051 amendment).
        if Path::new(content).is_dir() {
            bail!(
                "\"{content}\" is a directory. Use `nullseal share {content} --zip` to pack and share it as a zip."
            );
        }
        let name = Path::new(content)
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or("");
        let ext = file_extension(name);
        if mode != "p2p" {
            // Empty extension = an extensionless file (Dockerfile, Makefile,
            // .gitignore, …) — allowed. Otherwise it must be on the allow-list.
            // The upload size limit is enforced in run_server against the
            // backend-driven limit (task 056), not here.
            if !ext.is_empty() && !SUPPORTED_EXTENSIONS.contains(&ext.as_str()) {
                bail!("Unsupported file extension: {ext}");
            }
        }
    } else if content.trim().is_empty() {
        bail!("Content cannot be empty.");
    } else if content.len() > MAX_TEXT_LENGTH {
        bail!("Text must be {MAX_TEXT_LENGTH} characters or fewer.");
    }
    Ok(())
}

/// Backend-driven upload size limit (task 056): ask the server for its effective
/// limit via `GET /shares/config`; fall back to the compiled-in constant when
/// the endpoint is unavailable (older server) or returns nonsense. The source
/// used is logged at verbose level. Shared with `manage` (replace path).
pub(crate) async fn fetch_server_limit(client: &ApiClient) -> u64 {
    match client.get_shares_config().await {
        Ok(cfg) if cfg.max_bytes > 0 => {
            super::log::event(&format!(
                "server limit {} (from /shares/config)",
                super::format_limit(cfg.max_bytes),
            ));
            cfg.max_bytes
        }
        _ => {
            super::log::event(&format!(
                "server limit {} (built-in fallback; /shares/config unavailable)",
                super::format_limit(SERVER_MAX_BYTES),
            ));
            SERVER_MAX_BYTES
        }
    }
}

fn resolve_content_type(flag: &str) -> &'static str {
    match flag {
        "pwd" => "password",
        // `zip` (explicit folder share, task 051 amendment) travels the wire as
        // an ordinary file share — the folder marker lives in FileMetadata.
        "file" | "zip" => "file",
        // `sync` (task 058) is NOT a stored payload: it never reaches
        // `read_input` / `create_share`, so it keeps its own value rather than
        // collapsing to "file" and accidentally taking a server-share path.
        "sync" => "sync",
        _ => "text",
    }
}

struct ReadInput {
    bytes: Vec<u8>,
    file_metadata: Option<FileMetadata>,
}

/// The gating error for `--sync` in upload mode (task 058): a server share
/// stores exactly one payload, so a multi-file transfer has nowhere to land.
pub const SYNC_UPLOAD_ERROR: &str = "--sync needs a direct connection (--p2p or --local): a server share stores exactly one payload. Use --zip to upload the folder as a single archive.";

/// Flag validation for the two folder modes, `--zip` (task 051) and `--sync`
/// (task 058). Rules:
/// - `--zip` and `--sync` are mutually exclusive strategies.
/// - Either flag conflicts with `--text` / `--pwd` and with a *different*
///   `-t/--type` value: a folder share is never a text/password/plain-file
///   share. The check is **value-aware** because `-t zip` / `-t sync` are the
///   flags' own aliases (merged into the booleans in `main.rs` before this runs),
///   so `--zip -t file` must still fail while `-t zip` must not.
/// - Either flag requires the content argument to be an existing directory.
/// - `--sync` requires `--p2p` / `--local` / `-a` — upload mode is an error
///   naming `--zip`. `--zip` itself is legal in **every** mode (task 058 lifted
///   056's upload-only gate).
/// - A directory argument WITHOUT either flag (bare, `--file`, or `-t file`) is
///   an error naming **both** options — never a silent fall-back to sharing the
///   path string as text. Explicit `--text` / `--pwd` / `-t txt` / `-t pwd` keep
///   their literal-string behavior exactly as before.
#[allow(clippy::too_many_arguments)]
pub fn validate_folder_flags(
    zip: bool,
    sync: bool,
    text: bool,
    pwd: bool,
    type_alias: Option<&str>,
    p2p: bool,
    local: bool,
    address: bool,
    content: &str,
) -> Result<()> {
    let is_dir = Path::new(content).is_dir();
    if zip && sync {
        bail!("--zip and --sync are mutually exclusive: --zip packs the folder into one archive, --sync transfers the files directly.");
    }
    if sync {
        // `-t sync` is the alias, so only a DIFFERENT -t value conflicts.
        if text || pwd || matches!(type_alias, Some(t) if t != "sync") {
            bail!("--sync cannot be combined with --text, --pwd or -t/--type (a folder sync is not a text, password or single-file share).");
        }
        if !p2p && !local && !address {
            bail!("{SYNC_UPLOAD_ERROR}");
        }
        if !is_dir {
            bail!("--sync requires a directory, but \"{content}\" is not one.");
        }
        return Ok(());
    }
    if zip {
        if text || pwd || matches!(type_alias, Some(t) if t != "zip") {
            bail!("--zip cannot be combined with --text, --pwd or -t/--type (a folder share is always a file share).");
        }
        if !is_dir {
            bail!("--zip requires a directory, but \"{content}\" is not one.");
        }
        return Ok(());
    }
    if is_dir && !text && !pwd && !matches!(type_alias, Some("txt") | Some("pwd")) {
        bail!(
            "\"{content}\" is a directory. Use `nullseal share {content} --zip` to send it as one archive, or `--sync` to transfer the files directly (--sync needs --p2p/--local)."
        );
    }
    Ok(())
}

/// `--exclude` filters the shared folder tree (task 052), so it is only
/// meaningful together with `--zip` or `--sync` (task 058). Reject it otherwise
/// instead of silently ignoring it.
pub fn validate_exclude_flag(zip: bool, sync: bool, excludes: &[String]) -> Result<()> {
    if !excludes.is_empty() && !zip && !sync {
        bail!("--exclude requires --zip or --sync (exclude patterns filter the shared folder).");
    }
    Ok(())
}

/// `--exclude-from <FILE>` has the same gate as `--exclude` (task 058).
pub fn validate_exclude_from_flag(zip: bool, sync: bool, files: &[String]) -> Result<()> {
    if !files.is_empty() && !zip && !sync {
        bail!("--exclude-from requires --zip or --sync (exclude patterns filter the shared folder).");
    }
    Ok(())
}

/// Resolve `--exclude-from <FILE>` (repeatable) plus `--exclude <PATTERN>`
/// (repeatable) into the single ordered pattern list `walker::walk` consumes.
///
/// **Precedence, lowest → highest:** `.nullsealignore` (applied by the walker
/// itself) → each `--exclude-from` file in argument order → `--exclude` patterns.
/// Order matters because gitignore negations are order-dependent; this preserves
/// task 052's rule that a CLI `--exclude` can override a `!negation` in the file.
///
/// A missing or unreadable file is a **hard error naming the path**: a typo must
/// never silently ship the files the user meant to exclude. (A malformed
/// *pattern* stays tolerated — that is gitignore's own lenient semantic, see
/// `walker`.) Paths resolve relative to the current working directory, like any
/// other CLI path argument — not relative to the shared folder.
///
/// Deliberately lives in the command layer: `walker::walk` stays a pure
/// filesystem-read module with no notion of pattern files, and
/// `archive::pack_with_excludes` shares it unchanged.
pub fn resolve_exclude_patterns(
    exclude_from: &[String],
    excludes: &[String],
) -> Result<Vec<String>> {
    let mut patterns = Vec::new();
    for file in exclude_from {
        let text = std::fs::read_to_string(file).map_err(|e| {
            anyhow::anyhow!("cannot read --exclude-from file \"{file}\": {e}")
        })?;
        // Comments and blank lines are handled by the `ignore` crate exactly as
        // in `.nullsealignore`, so lines pass through verbatim.
        patterns.extend(text.lines().map(str::to_owned));
    }
    patterns.extend(excludes.iter().cloned());
    Ok(patterns)
}

/// Pack a directory into a zip in the OS temp dir and present it to the rest of
/// the pipeline as an ordinary in-memory file named `<folder>.zip`. The temp
/// archive is removed as soon as its bytes are read (and on every error path,
/// via `NamedTempFile`'s drop). `FileMetadata.mimeType` carries the folder
/// marker (`archive::FOLDER_MIME`) so the recipient can auto-extract — a plain
/// user-sent `.zip` never carries it. Packing honors `.nullsealignore` at the
/// folder root plus the additive `--exclude` patterns (task 052).
fn read_folder(dir: &Path, excludes: &[String]) -> Result<ReadInput> {
    let canon = dir
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("cannot access folder \"{}\": {e}", dir.display()))?;
    let folder_name = canon
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "folder".to_string());

    let tmp = tempfile::Builder::new()
        .prefix("nullseal-pack-")
        .suffix(".zip")
        .tempfile()?;
    let summary = crate::archive::pack_with_excludes(&canon, tmp.path(), excludes)?;
    for link in &summary.skipped_symlinks {
        super::display::warn(&format!("Skipping symlink: {}", link.display()));
    }
    super::log::step(&format!(
        "Packing {folder_name} ({} files, {})…",
        summary.file_count,
        super::format_size(summary.total_bytes as usize),
    ));
    let bytes = std::fs::read(tmp.path())?;
    drop(tmp); // temp archive removed here (NamedTempFile)

    Ok(ReadInput {
        file_metadata: Some(FileMetadata {
            size: bytes.len() as u64,
            mime_type: crate::archive::FOLDER_MIME.into(),
            extension: ".zip".into(),
            filename: format!("{folder_name}.zip"),
        }),
        bytes,
    })
}

fn read_input(content: &str, content_type: &str, excludes: &[String]) -> Result<ReadInput> {
    if content_type == "file" {
        let p = Path::new(content);
        // Only the explicit `--zip` flag routes a directory here (validate
        // rejects a directory for plain `--file` shares — task 051 amendment).
        if p.is_dir() {
            return read_folder(p, excludes);
        }
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

/// Outer entry point called from tests (and any caller without `--exclude`
/// patterns). Accepts `impl Into<String>` so tests can pass `&str` without
/// `.to_string()`.
#[allow(dead_code)] // test entry point — main.rs dispatches via run_with_excludes
#[allow(clippy::too_many_arguments)]
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
    run_with_excludes(content, password, mode, content_type_flag, server, ttl, one_time, relay_only, &[], output).await
}

/// `run` + `--exclude` patterns (task 052) — the entry point main.rs uses.
/// `excludes` only affects folder (`--zip`) shares, where it filters the packed
/// tree additively to `.nullsealignore`.
#[allow(clippy::too_many_arguments)]
pub async fn run_with_excludes(
    content: impl Into<String>,
    password: impl Into<String>,
    mode: impl Into<String>,
    content_type_flag: impl Into<String>,
    server: Option<String>,
    ttl: Option<String>,
    one_time: bool,
    relay_only: bool,
    excludes: &[String],
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    run_inner(content, password, mode, content_type_flag, server, false, ttl, one_time, relay_only, excludes, output).await
}

/// Fully local transfer — no server needed (see `run_local_with_excludes`).
#[allow(dead_code)] // no-excludes convenience mirror of `run` — main.rs dispatches via run_local_with_excludes
pub async fn run_local(
    content: impl Into<String>,
    password: impl Into<String>,
    content_type_flag: impl Into<String>,
    bind_addr: Option<String>,
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    run_local_with_excludes(content, password, content_type_flag, bind_addr, &[], output).await
}

/// Fully local transfer — no server needed.
/// Host starts an embedded Socket.IO relay, advertises via mDNS, connects as
/// sender via crate B, and runs the same flow as run_p2p (windowed-ACK v2).
/// `excludes` (task 052) filters the packed tree of a `--zip` folder share.
pub async fn run_local_with_excludes(
    content: impl Into<String>,
    password: impl Into<String>,
    content_type_flag: impl Into<String>,
    bind_addr: Option<String>,
    excludes: &[String],
    _output: &mut dyn FnMut(&str),
) -> Result<()> {
    let content = content.into();
    let password = password.into();
    let content_type_flag = content_type_flag.into();

    // Validate (use p2p mode rules — no server size limit)
    validate(&content, &password, "p2p", &content_type_flag)?;

    if content_type_flag == "sync" {
        // Direct folder sync over the LAN (task 058) — the documented cron path.
        return run_sync_local(&content, &password, bind_addr, excludes).await;
    }

    let content_type = resolve_content_type(&content_type_flag);
    let ReadInput { bytes, file_metadata } = read_input(&content, content_type, excludes)?;

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

        // Tracks whether the recipient signalled completion (p2p:complete /
        // p2p:both-completed). Once set, a subsequent peer-disconnect / DC-close is
        // expected teardown, not an interruption → finish success, never retry.
        let mut recipient_done = false;

        // Monotonic "entire payload handed to the transport" latch (task 037). Set
        // once below when `engine_sent_through()+1 >= total_chunks`, and NEVER reset
        // within this attempt — a per-attempt scope (re-entered on rejoin/`continue`)
        // resets it to `false` on its own. See is_done! for why this must be a latch.
        let mut payload_fully_sent = false;

        // Single completion-decision shared by every disconnect/close site (task 034).
        // A recipient disconnect at/after a full send resolves to SUCCESS if ANY of:
        //   1. completion was already selected (`recipient_done`),
        //   2. the adapter finished (final ACK applied),
        //   3. a completion is pending now (drain `complete` / `both_completed`), or
        //   4. the entire payload was handed to the transport — the recipient (web +
        //      CLI) only disconnects after assembling+verifying the whole payload, so
        //      "all sent + peer gone = done" sidesteps the ACK/`complete` timing race.
        // (4) is read from the monotonic `payload_fully_sent` latch, NOT live from
        // `engine_sent_through()`: a late tail gap-repair `request` rewinds the
        // engine's `next` cursor, so the live value can momentarily dip below
        // `total_chunks` after a full send and falsely read as a mid-transfer drop.
        macro_rules! is_done {
            () => {
                recipient_done
                    || adapter.is_finished()
                    || control.events.complete.try_recv().is_ok()
                    || control.events.both_completed.try_recv().is_ok()
                    || payload_fully_sent
            };
        }

        // Drive the adapter: flush queued frames to WebRTC, consume ack/request.
        let send_result: Result<()> = async {
            loop {
                // Latch "fully sent" as soon as every chunk has been handed to the
                // transport — BEFORE the flush — so a send error or peer-disconnect
                // during the final flush (the recipient tearing down at completion) is
                // recognised as success, and a later gap-repair `request` that rewinds
                // engine.next can't regress the signal. Never reset within the attempt.
                // (Task 037)
                if adapter
                    .engine_sent_through()
                    .map(|t| t + 1 >= total_chunks)
                    .unwrap_or(false)
                {
                    payload_fully_sent = true;
                }

                let texts: Vec<String> = adapter.transport_mut().text_queue.drain(..).collect();
                for t in texts {
                    // Interruptible flush: race the blocking send against a
                    // peer-disconnect so a real drop aborts a stuck send promptly
                    // instead of waiting for the ICE timeout.
                    tokio::select! {
                        biased;
                        r = sender.send_frame(t) => {
                            if let Err(e) = r {
                                // The send loop closing right at completion (recipient
                                // tore down after assembling everything) is expected
                                // teardown, not a failure → success, no retry. (037)
                                if is_done!() {
                                    recipient_done = true;
                                    break;
                                }
                                return Err(e);
                            }
                        }
                        _ = control.events.peer_disconnected.recv() => {
                            // The recv future has fired and is dropped before this body
                            // runs, so the `try_recv`s inside is_done! are free to borrow
                            // the (disjoint) complete/both_completed channels.
                            if is_done!() {
                                recipient_done = true;
                                break;
                            }
                            super::log::step("Receiver disconnected — reconnecting…");
                            return Err(anyhow::anyhow!("receiver disconnected"));
                        }
                    }
                }
                let bins: Vec<Vec<u8>> = adapter.transport_mut().binary_queue.drain(..).collect();
                let bin_count = bins.len();
                for b in bins {
                    tokio::select! {
                        biased;
                        r = sender.send_binary(b) => {
                            if let Err(e) = r {
                                if is_done!() {
                                    recipient_done = true;
                                    break;
                                }
                                return Err(e);
                            }
                        }
                        _ = control.events.peer_disconnected.recv() => {
                            if is_done!() {
                                recipient_done = true;
                                break;
                            }
                            super::log::step("Receiver disconnected — reconnecting…");
                            return Err(anyhow::anyhow!("receiver disconnected"));
                        }
                    }
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
                            // Real progress after a (re)connect → reset the retry budget. (B1)
                            if machine.attempts() > 0 { machine.handle(ConnEvent::TransferProgress); }
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
                        recipient_done = true;
                        break;
                    }
                    _ = control.events.both_completed.recv() => {
                        // Server's definitive "both done" signal → terminal success.
                        adapter.complete();
                        recipient_done = true;
                        break;
                    }
                    _ = control.events.peer_disconnected.recv() => {
                        // The recipient disconnecting AFTER it has the full payload is
                        // expected teardown, not a failure → finish success, no retry.
                        if is_done!() {
                            break;
                        }
                        // Real mid-transfer drop — surface it at default level and
                        // fall into the retry/rejoin path.
                        super::log::step("Receiver disconnected — reconnecting…");
                        return Err(anyhow::anyhow!("receiver disconnected"));
                    }
                    event = sender.next_event() => {
                        match event {
                            Some(crate::webrtc::LoopEvent::Error(e)) => {
                                return Err(anyhow::anyhow!("WebRTC error during transfer: {e}"));
                            }
                            Some(crate::webrtc::LoopEvent::Done) | None => {
                                if is_done!() {
                                    break;
                                }
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
        super::display::status("Transfer complete.");
        control.complete("sender", &content_checksum)?;
        return Ok(());
    }
}

// ── direct folder sync (`share --sync`, task 058) ─────────────────────────────

/// Walk + hash the shared folder, warning about skipped symlinks (as 051).
fn scan_shared_folder(dir: &Path, excludes: &[String]) -> Result<(Vec<crate::transfer::protocol::FileEntry>, u64)> {
    let spinner = super::display::Spinner::start("Scanning the folder…");
    let (files, symlinks) = super::sync_flow::scan_source(dir, excludes)?;
    drop(spinner);
    for link in &symlinks {
        super::display::warn(&format!("Skipping symlink: {link}"));
    }
    let bytes: u64 = files.iter().map(|f| f.size).sum();
    super::log::step(&format!(
        "{} file(s), {} to compare",
        files.len(),
        super::format_size(bytes as usize)
    ));
    Ok((files, bytes))
}

/// Sender half of the in-channel sync handshake: `verify` + a `metadata` frame
/// declaring the sync mode and this direction's cipher, then the receiver's own
/// `syncMeta` answer (each direction has its own keyed stream, so nonces never
/// repeat). Returns the driven summary.
async fn sync_send_over_channel(
    sender: &mut SenderPeer,
    password: &str,
    proof: &str,
    source_dir: &Path,
    files: Vec<crate::transfer::protocol::FileEntry>,
) -> Result<super::sync_flow::SyncSummary> {
    use crate::crypto::StreamEncryptionMetadata;
    use super::sync_flow::{Sealer, SenderWire, Unsealer};

    sender.send_verify(proof)?;
    let sealer = Sealer::new(password);
    sender
        .send_frame(
            serde_json::json!({
                "type": "metadata",
                "contentType": "sync",
                "transferMode": "sync",
                "streamEncryptionMetadata": sealer.metadata(),
            })
            .to_string(),
        )
        .await?;

    // The receiver answers with its own stream metadata before any sealed frame
    // (the DataChannel is ordered, so this text frame always arrives first).
    let peer_meta: StreamEncryptionMetadata = loop {
        match sender.next_event().await {
            Some(crate::webrtc::LoopEvent::Message(text)) => {
                let v: serde_json::Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if v["type"].as_str() != Some("syncMeta") {
                    continue;
                }
                break serde_json::from_value(v["streamEncryptionMetadata"].clone())
                    .map_err(|e| anyhow::anyhow!("invalid sync metadata from the receiver: {e}"))?;
            }
            Some(crate::webrtc::LoopEvent::Error(e)) => bail!("WebRTC error during handshake: {e}"),
            Some(crate::webrtc::LoopEvent::Done) | None => {
                bail!("The receiver disconnected before the sync handshake finished.")
            }
            _ => continue,
        }
    };

    // The very same `sealer` whose metadata was just published — a fresh one
    // would carry a different salt/base_iv and the receiver could not decrypt.
    let mut wire =
        SenderWire { peer: sender, sealer, unsealer: Unsealer::new(&peer_meta, password)? };
    super::sync_flow::run_sender(&mut wire, source_dir, files, crate::crypto::STREAM_CHUNK_SIZE)
        .await
}

/// `share <dir> --sync --p2p` — direct folder sync over server-signaled P2P.
///
/// Single attempt by design (spec §7.3): there is no byte-level resume in the
/// multi-file path, a non-zero exit is what keeps cron sane, and the hash diff
/// makes the re-run near-free.
async fn run_sync_online(
    content: &str,
    password: &str,
    server: Option<String>,
    relay_only: bool,
    excludes: &[String],
) -> Result<()> {
    let source = Path::new(content)
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("cannot access folder \"{content}\": {e}"))?;
    let (files, _) = scan_shared_folder(&source, excludes)?;

    let base = server_url(server.as_deref())?;
    let client = ApiClient::new(&base);
    let proof = sha256_hex(password);

    // Task 057: `mode: "sync"` makes core mint /sync/<id>, which is how the
    // recipient's `get` routes to the sync receiver.
    super::log::event("creating sync session");
    let session = client
        .create_p2p_session_with_mode(&proof, "sync")
        .await
        .map_err(super::with_conn_hint)?;
    let sync_url = match user_url() {
        Some(base) => format!("{}/sync/{}", base.trim_end_matches('/'), session.session_id),
        None => session.share_url.clone(),
    };
    super::display::print_p2p_share_result(&session.session_id, &sync_url);

    let ice_servers = client.get_ice_servers().await.unwrap_or_default();
    let ws_url = TungsteniteWs::build_url(&base)?;
    let ws = TungsteniteWs::connect(&ws_url).await?;
    let (transport, evts) = SocketIoTransport::connect(ws, "p2p").await?;
    let mut control = P2PControl::new(transport, evts);
    control.join(&session.session_id, "sender")?;
    tokio::select! {
        biased;
        j = control.events.joined.recv() => {
            j.ok_or_else(|| anyhow::anyhow!("socket closed before joined"))?;
        }
        err = control.events.error.recv() => {
            bail!("signaling error before joined: {}", err.unwrap_or_else(|| "unknown".into()));
        }
    }

    if !super::p2p_stages::await_ready(&mut control.events, true).await? {
        bail!("The recipient did not join.");
    }
    super::display::status("Recipient connected. Starting sync…");

    let mut sender = if relay_only {
        SenderPeer::new_relay_only(ice_servers.clone(), None).await?
    } else {
        SenderPeer::new(ice_servers.clone(), None).await?
    };
    control.offer(&sender.offer_sdp_json())?;
    super::p2p_stages::await_answer(&sender, &mut control.events).await?;
    if !super::p2p_stages::await_sender_channel(&mut sender, &mut control.events).await? {
        bail!("DataChannel open failed.");
    }

    let summary = sync_send_over_channel(&mut sender, password, &proof, &source, files).await;
    sender.close_and_flush().await;
    sender.wait_closed().await;
    let summary = summary?;

    super::log::blank();
    super::display::status(&super::sync_flow::format_sender_summary(&source, &summary));
    // The server only relays the completion signal (it never compares the value),
    // so a per-run digest is enough to tear the session down cleanly.
    let _ = control.complete("sender", &sha256_hex(&format!("sync:{}", summary.bytes)));
    let _ = control.delete();
    Ok(())
}

/// `share <dir> --sync --local [-a host:port]` — direct folder sync over the LAN.
/// This is the documented unattended/cron path (`guides/setup.md`).
async fn run_sync_local(
    content: &str,
    password: &str,
    bind_addr: Option<String>,
    excludes: &[String],
) -> Result<()> {
    let source = Path::new(content)
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("cannot access folder \"{content}\": {e}"))?;
    let (files, _) = scan_shared_folder(&source, excludes)?;

    let proof = sha256_hex(password);
    let local_ip = match &bind_addr {
        Some(a) if a.contains(':') => a.rsplitn(2, ':').last().unwrap().to_string(),
        Some(ip) => ip.clone(),
        None => crate::webrtc::discover_local_ip().to_string(),
    };
    let (addr, _server_handle) = crate::local_server::start(&local_ip).await?;
    let port = addr.port();
    super::display::print_local_share_result(&format!("{local_ip}:{port}"));
    let _broadcast_guard = crate::local::broadcast_addr(&local_ip, port)?;

    let ws_url = format!("ws://{local_ip}:{port}/socket.io/?EIO=4&transport=websocket");
    let ws = TungsteniteWs::connect(&ws_url).await?;
    let (transport, evts) = SocketIoTransport::connect(ws, "p2p").await?;
    let mut control = P2PControl::new(transport, evts);
    control.join("local", "sender")?;
    control
        .events
        .joined
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("socket closed before joined"))?;
    super::log::step("📡 Waiting for recipient…");

    if !super::p2p_stages::await_ready(&mut control.events, true).await? {
        bail!("The recipient did not join.");
    }
    super::display::status("Recipient connected. Starting sync…");

    let bind_ip: Option<std::net::IpAddr> = local_ip.parse().ok();
    let mut sender = SenderPeer::new(vec![], bind_ip).await?;
    control.offer(&sender.offer_sdp_json())?;
    super::p2p_stages::await_answer(&sender, &mut control.events).await?;
    if !super::p2p_stages::await_sender_channel(&mut sender, &mut control.events).await? {
        bail!("DataChannel open failed.");
    }

    let summary = sync_send_over_channel(&mut sender, password, &proof, &source, files).await;
    sender.close_and_flush().await;
    sender.wait_closed().await;
    let summary = summary?;

    super::log::blank();
    super::display::status(&super::sync_flow::format_sender_summary(&source, &summary));
    let _ = control.complete("sender", &sha256_hex(&format!("sync:{}", summary.bytes)));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
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
    excludes: &[String],
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

    if content_type_flag == "sync" {
        // Direct folder sync (task 058) — its own flow: no single payload, no
        // windowed-ACK resume (a re-run is the resume story, spec §7.3).
        return run_sync_online(&content, &password, server, relay_only, excludes).await;
    }
    if mode == "p2p" {
        return run_p2p(content, password, content_type_flag, server, local, relay_only, excludes, output).await;
    }
    let ttl_secs = parse_ttl(ttl.as_deref())?;
    run_server(content, password, content_type_flag, server, ttl_secs, one_time, excludes, output).await
}

#[allow(clippy::too_many_arguments)]
async fn run_server(
    content: String,
    password: String,
    content_type_flag: String,
    server: Option<String>,
    ttl_secs: u64,
    one_time: bool,
    excludes: &[String],
    output: &mut dyn FnMut(&str),
) -> Result<()> {
    let client = ApiClient::new(server_url(server.as_deref())?);
    // Backend-driven limit (task 056): the server's effective maxBytes governs
    // every upload size check; the compiled-in constant is only a fallback.
    let server_limit = fetch_server_limit(&client).await;
    let content_type = resolve_content_type(&content_type_flag);
    let ReadInput { bytes, file_metadata } = read_input(&content, content_type, excludes)?;
    // The limit applies to the bytes actually uploaded: for folder shares that
    // is the PACKED archive (never the folder's raw total), for plain files the
    // file contents.
    if let Some(fm) = file_metadata.as_ref() {
        if bytes.len() as u64 > server_limit {
            let limit = super::format_limit(server_limit);
            if fm.mime_type == crate::archive::FOLDER_MIME {
                bail!("Folder archive exceeds the server upload limit ({limit}). Trim it with --exclude/.nullsealignore, or share a zip file you create yourself over --p2p/--local.");
            }
            bail!("File exceeds the server upload limit ({limit}).");
        }
    }
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
        .await
        .map_err(super::with_conn_hint)?;

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

#[allow(clippy::too_many_arguments)]
async fn run_p2p(
    content: String,
    password: String,
    content_type_flag: String,
    server: Option<String>,
    local: bool,
    relay_only: bool,
    excludes: &[String],
    _output: &mut dyn FnMut(&str),
) -> Result<()> {
    let base = server_url(server.as_deref())?;
    let client = ApiClient::new(&base);
    let content_type = resolve_content_type(&content_type_flag);
    let ReadInput { bytes, file_metadata } = read_input(&content, content_type, excludes)?;

    // 1. Derive password proof + checksum (streaming: no upfront encryption)
    let content_checksum = crate::crypto::sha256_bytes(&bytes);
    let proof = sha256_hex(&password);

    // 2. Create P2P session on the server
    super::log::event("creating session");
    let session = client.create_p2p_session(&proof).await.map_err(super::with_conn_hint)?;
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

        // Tracks whether the recipient signalled completion (p2p:complete /
        // p2p:both-completed). Once set, a subsequent peer-disconnect / DC-close is
        // expected teardown, not an interruption → finish success, never retry.
        let mut recipient_done = false;

        // Monotonic "entire payload handed to the transport" latch (task 037). Set
        // once below when `engine_sent_through()+1 >= total_chunks`, and NEVER reset
        // within this attempt — a per-attempt scope (re-entered on rejoin/`continue`)
        // resets it to `false` on its own. See is_done! for why this must be a latch.
        let mut payload_fully_sent = false;

        // Single completion-decision shared by every disconnect/close site (task 034).
        // A recipient disconnect at/after a full send resolves to SUCCESS if ANY of:
        //   1. completion was already selected (`recipient_done`),
        //   2. the adapter finished (final ACK applied),
        //   3. a completion is pending now (drain `complete` / `both_completed`), or
        //   4. the entire payload was handed to the transport — the recipient (web +
        //      CLI) only disconnects after assembling+verifying the whole payload, so
        //      "all sent + peer gone = done" sidesteps the ACK/`complete` timing race.
        // (4) is read from the monotonic `payload_fully_sent` latch, NOT live from
        // `engine_sent_through()`: a late tail gap-repair `request` rewinds the
        // engine's `next` cursor, so the live value can momentarily dip below
        // `total_chunks` after a full send and falsely read as a mid-transfer drop.
        macro_rules! is_done {
            () => {
                recipient_done
                    || adapter.is_finished()
                    || control.events.complete.try_recv().is_ok()
                    || control.events.both_completed.try_recv().is_ok()
                    || payload_fully_sent
            };
        }

        let send_result: Result<()> = async {
            loop {
                // Latch "fully sent" as soon as every chunk has been handed to the
                // transport — BEFORE the flush — so a send error or peer-disconnect
                // during the final flush (the recipient tearing down at completion) is
                // recognised as success, and a later gap-repair `request` that rewinds
                // engine.next can't regress the signal. Never reset within the attempt.
                // (Task 037)
                if adapter
                    .engine_sent_through()
                    .map(|t| t + 1 >= total_chunks)
                    .unwrap_or(false)
                {
                    payload_fully_sent = true;
                }

                // Flush text frames
                let texts: Vec<String> = adapter.transport_mut().text_queue.drain(..).collect();
                for t in texts {
                    // Interruptible flush: race the blocking send against a
                    // peer-disconnect so a real drop aborts a stuck send promptly
                    // instead of waiting for the ICE timeout.
                    tokio::select! {
                        biased;
                        r = sender.send_frame(t) => {
                            if let Err(e) = r {
                                // The send loop closing right at completion (recipient
                                // tore down after assembling everything) is expected
                                // teardown, not a failure → success, no retry. (037)
                                if is_done!() {
                                    recipient_done = true;
                                    break;
                                }
                                return Err(e);
                            }
                        }
                        _ = control.events.peer_disconnected.recv() => {
                            // The recv future has fired and is dropped before this body
                            // runs, so the `try_recv`s inside is_done! are free to borrow
                            // the (disjoint) complete/both_completed channels.
                            if is_done!() {
                                recipient_done = true;
                                break;
                            }
                            super::log::step("Receiver disconnected — reconnecting…");
                            return Err(anyhow::anyhow!("receiver disconnected"));
                        }
                    }
                }
                // Flush binary frames
                let bins: Vec<Vec<u8>> = adapter.transport_mut().binary_queue.drain(..).collect();
                let bin_count = bins.len();
                for b in bins {
                    tokio::select! {
                        biased;
                        r = sender.send_binary(b) => {
                            if let Err(e) = r {
                                if is_done!() {
                                    recipient_done = true;
                                    break;
                                }
                                return Err(e);
                            }
                        }
                        _ = control.events.peer_disconnected.recv() => {
                            if is_done!() {
                                recipient_done = true;
                                break;
                            }
                            super::log::step("Receiver disconnected — reconnecting…");
                            return Err(anyhow::anyhow!("receiver disconnected"));
                        }
                    }
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
                            // Real progress after a (re)connect → reset the retry budget. (B1)
                            if machine.attempts() > 0 { machine.handle(ConnEvent::TransferProgress); }
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
                        recipient_done = true;
                        break;
                    }
                    _ = control.events.both_completed.recv() => {
                        // Server's definitive "both done" signal → terminal success.
                        adapter.complete();
                        recipient_done = true;
                        break;
                    }
                    _ = control.events.peer_disconnected.recv() => {
                        // The recipient disconnecting AFTER it has the full payload is
                        // expected teardown, not a failure → finish success, no retry.
                        if is_done!() {
                            break;
                        }
                        // Real mid-transfer drop — surface it at default level and
                        // fall into the retry/rejoin path.
                        super::log::step("Receiver disconnected — reconnecting…");
                        return Err(anyhow::anyhow!("receiver disconnected"));
                    }
                    event = sender.next_event() => {
                        match event {
                            Some(crate::webrtc::LoopEvent::Error(e)) => {
                                return Err(anyhow::anyhow!("WebRTC error during transfer: {e}"));
                            }
                            Some(crate::webrtc::LoopEvent::Done) | None => {
                                if is_done!() {
                                    break;
                                }
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

        // The GET /shares/config probe precedes the POST → inspect the last request.
        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs.last().unwrap().body).unwrap();
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
        let body: serde_json::Value = serde_json::from_slice(&reqs.last().unwrap().body).unwrap();
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
        let msg = err.to_string();
        assert!(msg.contains("500"), "expected status in error, got: {msg}");
        assert!(msg.contains("/shares"), "expected url path in error, got: {msg}");
    }

    // ── folder shares (task 051) ─────────────────────────────────────────

    #[tokio::test]
    async fn folder_share_uploads_zip_with_folder_marker() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("myfolder");
        std::fs::create_dir_all(folder.join("sub")).unwrap();
        std::fs::write(folder.join("a.txt"), b"alpha").unwrap();
        std::fs::write(folder.join("sub/b.txt"), b"beta").unwrap();

        let (server, url) = mock_server().await;
        Mock::given(method("POST"))
            .and(path("/shares"))
            .respond_with(ResponseTemplate::new(200).set_body_json(share_ok_body()))
            .mount(&server)
            .await;

        run(folder.to_str().unwrap(), "password", "u", "zip", Some(url), None, true, false, &mut |_| {})
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        // reqs[0] is the GET /shares/config probe (404 → fallback); the create
        // POST is the last request.
        let body: serde_json::Value = serde_json::from_slice(&reqs.last().unwrap().body).unwrap();
        assert_eq!(body["contentType"], "file");
        // The shared artifact IS the zip (task 056): the displayed name is
        // <folder>.zip and the declared size is the ARCHIVE's byte count —
        // proven by the encrypted payload decoding to exactly size + the
        // 16-byte AES-GCM tag.
        assert_eq!(body["fileMetadata"]["filename"], "myfolder.zip");
        assert_eq!(body["fileMetadata"]["extension"], ".zip");
        assert_eq!(body["fileMetadata"]["mimeType"], crate::archive::FOLDER_MIME);
        let size = body["fileMetadata"]["size"].as_u64().unwrap() as usize;
        assert!(size > 0);
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let payload = B64.decode(body["encryptedPayload"].as_str().unwrap()).unwrap();
        assert_eq!(payload.len(), size + 16, "metadata size must be the packed archive's byte count");
    }

    #[test]
    fn validate_zip_allows_directory_even_with_unlisted_extension_in_name() {
        // "backup.old" would fail the file allow-list, but as a `--zip` directory
        // it is packed to .zip — validation must not reject it.
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("backup.old");
        std::fs::create_dir_all(&folder).unwrap();
        validate(folder.to_str().unwrap(), "password", "u", "zip").unwrap();
    }

    #[tokio::test]
    async fn folder_archive_over_upload_limit_is_rejected() {
        use rand::RngCore;
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("bigfolder");
        std::fs::create_dir_all(&folder).unwrap();
        // Incompressible payload so the packed archive stays > 10 MB.
        let mut data = vec![0u8; (SERVER_MAX_BYTES + 512 * 1024) as usize];
        rand::thread_rng().fill_bytes(&mut data);
        std::fs::write(folder.join("blob.bin"), &data).unwrap();

        // No /shares/config mock → 404 → the CLI falls back to the built-in
        // 10 MB constant, and the error names the effective limit dynamically.
        let (_server, url) = mock_server().await;
        let err = run(folder.to_str().unwrap(), "password", "u", "zip", Some(url), None, true, false, &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().contains("limit"), "unexpected error: {err}");
        assert!(err.to_string().contains("10 MB"), "expected fallback limit in error: {err}");
    }

    // ── backend-driven limit (task 056) ──────────────────────────────────

    #[tokio::test]
    async fn config_limit_overrides_fallback_and_is_named_in_error() {
        use rand::RngCore;
        // Server advertises a 1 MB limit via /shares/config → a ~2 MB
        // incompressible archive is rejected, naming "1 MB" (not 10 MB).
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("midfolder");
        std::fs::create_dir_all(&folder).unwrap();
        let mut data = vec![0u8; 2 * 1024 * 1024];
        rand::thread_rng().fill_bytes(&mut data);
        std::fs::write(folder.join("blob.bin"), &data).unwrap();

        let (server, url) = mock_server().await;
        Mock::given(method("GET"))
            .and(path("/shares/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "maxBytes": 1024 * 1024,
                "maxTtlDays": 7
            })))
            .mount(&server)
            .await;

        let err = run(folder.to_str().unwrap(), "password", "u", "zip", Some(url), None, true, false, &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().contains("1 MB"), "expected fetched limit in error: {err}");
    }

    #[tokio::test]
    async fn folder_limit_applies_to_packed_archive_not_raw_total() {
        // 1 MB of zeros deflates to ~1 KB: with a 64 KB server limit the RAW
        // total (1 MB) is over but the PACKED archive is under → the upload
        // must succeed, proving the check runs on the archive bytes.
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("zeros");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("zeros.bin"), vec![0u8; 1024 * 1024]).unwrap();

        let (server, url) = mock_server().await;
        Mock::given(method("GET"))
            .and(path("/shares/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "maxBytes": 64 * 1024,
                "maxTtlDays": 7
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/shares"))
            .respond_with(ResponseTemplate::new(200).set_body_json(share_ok_body()))
            .mount(&server)
            .await;

        run(folder.to_str().unwrap(), "password", "u", "zip", Some(url), None, true, false, &mut |_| {})
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs.last().unwrap().body).unwrap();
        let size = body["fileMetadata"]["size"].as_u64().unwrap();
        assert!(size > 0 && size <= 64 * 1024, "declared size must be the packed archive's: {size}");
    }

    #[tokio::test]
    async fn plain_file_over_config_limit_is_rejected() {
        use std::io::Write;
        // The fetched limit also governs plain --file uploads.
        let mut tmp = tempfile::NamedTempFile::with_suffix(".pdf").unwrap();
        tmp.write_all(&vec![b'x'; 2048]).unwrap();
        let tmp_path = tmp.path().to_str().unwrap().to_owned();

        let (server, url) = mock_server().await;
        Mock::given(method("GET"))
            .and(path("/shares/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "maxBytes": 1024,
                "maxTtlDays": 7
            })))
            .mount(&server)
            .await;

        let err = run(tmp_path, "password", "u", "file", Some(url), None, true, false, &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().contains("1 KB"), "expected fetched limit in error: {err}");
    }

    // ── ignore rules / --exclude (task 052) ──────────────────────────────

    #[test]
    fn exclude_flag_requires_a_folder_mode() {
        let pat = ["*.log".to_string()];
        let err = validate_exclude_flag(false, false, &pat).unwrap_err();
        assert!(err.to_string().contains("--zip or --sync"), "{err}");
        // With either folder mode (or with no patterns at all) it passes.
        validate_exclude_flag(true, false, &pat).unwrap();
        validate_exclude_flag(false, true, &pat).unwrap();
        validate_exclude_flag(false, false, &[]).unwrap();
    }

    // ── --exclude-from (task 058) ────────────────────────────────────────

    #[test]
    fn exclude_from_flag_requires_a_folder_mode() {
        let files = ["ignores.txt".to_string()];
        let err = validate_exclude_from_flag(false, false, &files).unwrap_err();
        assert!(err.to_string().contains("--zip or --sync"), "{err}");
        validate_exclude_from_flag(true, false, &files).unwrap();
        validate_exclude_from_flag(false, true, &files).unwrap();
        validate_exclude_from_flag(false, false, &[]).unwrap();
    }

    #[test]
    fn exclude_from_files_compose_in_order_before_cli_patterns() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.ignore");
        let b = dir.path().join("b.ignore");
        std::fs::write(&a, "# comment\n\n*.log\n").unwrap();
        std::fs::write(&b, "!keep.log\nbuild/\n").unwrap();

        let patterns = resolve_exclude_patterns(
            &[a.to_string_lossy().into_owned(), b.to_string_lossy().into_owned()],
            &["*.tmp".to_string()],
        )
        .unwrap();
        // Order is lowest → highest precedence: file 1, file 2, then --exclude.
        // Comments/blank lines pass through verbatim (the `ignore` crate skips them).
        assert_eq!(
            patterns,
            vec![
                "# comment".to_string(),
                "".to_string(),
                "*.log".to_string(),
                "!keep.log".to_string(),
                "build/".to_string(),
                "*.tmp".to_string(),
            ]
        );
    }

    #[test]
    fn exclude_from_patterns_take_effect_and_cli_exclude_still_wins() {
        // End-to-end through the shared walker: the file's patterns filter the
        // tree, and a later --exclude overrides a negation from the file
        // (the precedence 052's extra_exclude_overrides_a_file_negation relies on).
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("app.log"), b"l").unwrap();
        std::fs::write(ws.join("keep.log"), b"k").unwrap();
        std::fs::write(ws.join("main.rs"), b"m").unwrap();
        let ignores = dir.path().join("shared.ignore");
        std::fs::write(&ignores, "*.log\n!keep.log\n").unwrap();
        let from = vec![ignores.to_string_lossy().into_owned()];

        let patterns = resolve_exclude_patterns(&from, &[]).unwrap();
        let walk = crate::walker::walk(&ws, &patterns).unwrap();
        let files: Vec<&str> =
            walk.entries.iter().filter(|e| !e.is_dir).map(|e| e.rel_path.as_str()).collect();
        assert_eq!(files, vec!["keep.log", "main.rs"], "file patterns must apply");

        let patterns = resolve_exclude_patterns(&from, &["keep.log".to_string()]).unwrap();
        let walk = crate::walker::walk(&ws, &patterns).unwrap();
        let files: Vec<&str> =
            walk.entries.iter().filter(|e| !e.is_dir).map(|e| e.rel_path.as_str()).collect();
        assert_eq!(files, vec!["main.rs"], "--exclude must override the file's negation");
    }

    #[test]
    fn exclude_from_missing_file_is_a_hard_error_naming_the_path() {
        // A typo must never silently ship the files the user meant to exclude.
        let err = resolve_exclude_patterns(&["no/such/ignores.txt".to_string()], &[]).unwrap_err();
        assert!(err.to_string().contains("no/such/ignores.txt"), "{err}");
        assert!(err.to_string().contains("--exclude-from"), "{err}");
    }

    #[test]
    fn exclude_from_empty_file_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.ignore");
        std::fs::write(&empty, "").unwrap();
        assert!(resolve_exclude_patterns(&[empty.to_string_lossy().into_owned()], &[])
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn folder_share_excludes_reach_the_packed_zip() {
        use rand::RngCore;
        // A >10MB incompressible blob would trip the upload limit (see the test
        // above) — excluding it must let the share through, proving --exclude
        // patterns reach walker::walk inside pack on the --zip path.
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("ws");
        std::fs::create_dir_all(&folder).unwrap();
        let mut data = vec![0u8; (SERVER_MAX_BYTES + 512 * 1024) as usize];
        rand::thread_rng().fill_bytes(&mut data);
        std::fs::write(folder.join("blob.bin"), &data).unwrap();
        std::fs::write(folder.join("a.txt"), b"alpha").unwrap();

        let (server, url) = mock_server().await;
        Mock::given(method("POST"))
            .and(path("/shares"))
            .respond_with(ResponseTemplate::new(200).set_body_json(share_ok_body()))
            .mount(&server)
            .await;

        run_with_excludes(
            folder.to_str().unwrap(), "password", "u", "zip", Some(url), None, true, false,
            &["blob.bin".to_string()], &mut |_| {},
        )
        .await
        .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs.last().unwrap().body).unwrap();
        assert_eq!(body["fileMetadata"]["filename"], "ws.zip");
        // The packed archive must be tiny — the blob never entered it.
        assert!(
            body["fileMetadata"]["size"].as_u64().unwrap() < 10 * 1024,
            "excluded blob leaked into the archive"
        );
    }

    // ── folder-mode flag validation (task 051 --zip, task 058 --sync) ────

    #[test]
    fn folder_flags_accept_a_directory_in_both_spellings() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().to_str().unwrap();
        // --zip works in every mode now (task 058 lifted 056's upload-only gate).
        validate_folder_flags(true, false, false, false, None, false, false, false, p).unwrap();
        validate_folder_flags(true, false, false, false, Some("zip"), false, false, false, p).unwrap();
        // --sync needs a direct mode; both spellings behave identically.
        validate_folder_flags(false, true, false, false, None, true, false, false, p).unwrap();
        validate_folder_flags(false, true, false, false, Some("sync"), false, true, false, p).unwrap();
        validate_folder_flags(false, true, false, false, Some("sync"), false, false, true, p).unwrap();
    }

    #[test]
    fn folder_flags_reject_a_non_directory_in_both_spellings() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::with_suffix(".txt").unwrap();
        tmp.write_all(b"x").unwrap();
        let file = tmp.path().to_str().unwrap();
        for (zip, sync, alias, flag) in [
            (true, false, None, "--zip"),
            (true, false, Some("zip"), "--zip"),
            (false, true, None, "--sync"),
            (false, true, Some("sync"), "--sync"),
        ] {
            for content in [file, "no/such/path"] {
                let err =
                    validate_folder_flags(zip, sync, false, false, alias, true, false, false, content)
                        .unwrap_err();
                assert!(err.to_string().contains("directory"), "{err}");
                assert!(err.to_string().contains(flag), "{err}");
            }
        }
    }

    #[test]
    fn zip_and_sync_together_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().to_str().unwrap();
        let err =
            validate_folder_flags(true, true, false, false, None, true, false, false, p).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn folder_flags_conflict_with_the_other_type_flags_but_not_their_own_alias() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().to_str().unwrap();
        for (text, pwd, alias) in [
            (true, false, None),          // --text
            (false, true, None),          // --pwd
            (false, false, Some("txt")),  // -t txt
            (false, false, Some("file")), // -t file   (must still fail — 051 rule)
            (false, false, Some("pwd")),  // -t pwd
            (false, false, Some("sync")), // -t sync alongside --zip
        ] {
            let err = validate_folder_flags(true, false, text, pwd, alias, false, false, false, p)
                .unwrap_err();
            assert!(err.to_string().contains("--zip"), "{err}");
        }
        for (text, pwd, alias) in [
            (true, false, None),
            (false, true, None),
            (false, false, Some("txt")),
            (false, false, Some("file")),
            (false, false, Some("pwd")),
            (false, false, Some("zip")), // -t zip alongside --sync
        ] {
            let err = validate_folder_flags(false, true, text, pwd, alias, true, false, false, p)
                .unwrap_err();
            assert!(err.to_string().contains("--sync") || err.to_string().contains("--zip"), "{err}");
        }
        // The flag's OWN alias is redundant but harmless.
        validate_folder_flags(true, false, false, false, Some("zip"), false, false, false, p).unwrap();
        validate_folder_flags(false, true, false, false, Some("sync"), true, false, false, p).unwrap();
    }

    // ── --zip is legal in every mode (task 058 reversal of 056) ───────────

    #[test]
    fn zip_is_accepted_in_p2p_local_and_address_modes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().to_str().unwrap();
        for (p2p, local, address) in [
            (true, false, false),  // --zip --p2p
            (false, true, false),  // --zip --local
            (false, false, true),  // --zip -a <addr>
            (true, true, true),    // all combined
            (false, false, false), // --zip alone (upload)
        ] {
            validate_folder_flags(true, false, false, false, None, p2p, local, address, p)
                .unwrap_or_else(|e| panic!("--zip must be legal in every mode: {e}"));
        }
    }

    #[test]
    fn zip_over_p2p_passes_library_validation() {
        // Task 058: the p2p entry point no longer refuses folder shares — bytes
        // stream through the DataChannel and never reach the server's limit.
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("f");
        std::fs::create_dir_all(&folder).unwrap();
        validate(folder.to_str().unwrap(), "password", "p2p", "zip").unwrap();
    }

    // ── --sync mode gating (task 058) ────────────────────────────────────

    #[test]
    fn sync_in_upload_mode_is_rejected_naming_zip_in_both_spellings() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().to_str().unwrap();
        for alias in [None, Some("sync")] {
            let err = validate_folder_flags(false, true, false, false, alias, false, false, false, p)
                .unwrap_err();
            assert!(err.to_string().contains("--zip"), "the error must name the fix: {err}");
            assert!(err.to_string().contains("--p2p"), "{err}");
        }
    }

    #[tokio::test]
    async fn sync_over_upload_is_rejected_by_run() {
        // Library-level backstop for the main.rs flag gate.
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("f");
        std::fs::create_dir_all(&folder).unwrap();
        let err = run(folder.to_str().unwrap(), "password", "u", "sync", None, None, true, false, &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().contains("--sync needs a direct connection"), "{err}");
    }

    #[test]
    fn validate_sync_requires_a_directory() {
        let err = validate("not-a-dir.txt", "password", "p2p", "sync").unwrap_err();
        assert!(err.to_string().contains("--sync requires a directory"), "{err}");
        let dir = tempfile::tempdir().unwrap();
        validate(dir.path().to_str().unwrap(), "password", "p2p", "sync").unwrap();
    }

    #[test]
    fn directory_without_a_folder_flag_names_both_options() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().to_str().unwrap();
        // Bare argument (the old auto-promotion trigger) and file-typed shares.
        for alias in [None, Some("file")] {
            let err =
                validate_folder_flags(false, false, false, false, alias, false, false, false, p)
                    .unwrap_err();
            assert!(err.to_string().contains("--zip"), "expected --zip hint, got: {err}");
            assert!(err.to_string().contains("--sync"), "expected --sync hint, got: {err}");
        }
        // Explicit text/pwd keep the pre-051 literal-string behavior.
        validate_folder_flags(false, false, true, false, None, false, false, false, p).unwrap();
        validate_folder_flags(false, false, false, true, None, false, false, false, p).unwrap();
        validate_folder_flags(false, false, false, false, Some("txt"), false, false, false, p).unwrap();
        validate_folder_flags(false, false, false, false, Some("pwd"), false, false, false, p).unwrap();
        // Non-directory content never triggers the hint.
        validate_folder_flags(false, false, false, false, None, false, false, false, "plain text secret")
            .unwrap();
    }

    #[test]
    fn validate_file_type_rejects_directory_with_zip_hint() {
        let dir = tempfile::tempdir().unwrap();
        let err = validate(dir.path().to_str().unwrap(), "password", "u", "file").unwrap_err();
        assert!(err.to_string().contains("--zip"), "{err}");
    }

    #[test]
    fn validate_zip_type_rejects_non_directory() {
        let err = validate("not-a-dir.txt", "password", "u", "zip").unwrap_err();
        assert!(err.to_string().contains("directory"), "{err}");
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

    #[tokio::test]
    async fn server_upload_rejects_too_large_file() {
        use std::io::Write;
        // Task 056: the size check moved from validate() into run_server, where
        // the backend-driven limit is known. No /shares/config mock → fallback
        // 10 MB constant; a 10MB+1 file is rejected before any upload.
        let mut tmp = tempfile::NamedTempFile::with_suffix(".pdf").unwrap();
        let size = SERVER_MAX_BYTES + 1;
        tmp.as_file().set_len(size).unwrap();
        tmp.write_all(b"x").unwrap(); // force file creation
        let path = tmp.path().to_str().unwrap().to_owned();

        let (server, url) = mock_server().await;
        let err = run(path, "password", "u", "file", Some(url), None, true, false, &mut |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("limit"), "{err}");
        assert!(err.to_string().contains("10 MB"), "expected fallback limit in error: {err}");
        // Nothing was POSTed to /shares.
        let reqs = server.received_requests().await.unwrap();
        assert!(reqs.iter().all(|r| r.url.path() != "/shares"), "oversized file must not be uploaded");
    }

    // ── resolve_content_type ─────────────────────────────────────────────

    #[test]
    fn resolve_content_type_file() {
        assert_eq!(resolve_content_type("file"), "file");
    }

    #[test]
    fn resolve_content_type_zip_is_a_file_share() {
        assert_eq!(resolve_content_type("zip"), "file");
    }

    #[test]
    fn resolve_content_type_sync_is_not_a_stored_share() {
        // Must NOT collapse to "file": a synced folder has no single payload, so
        // it may never take a server-share path.
        assert_eq!(resolve_content_type("sync"), "sync");
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

    #[test]
    fn file_extension_env_dotfiles_normalise_to_env() {
        assert_eq!(file_extension(".env"), ".env");
        assert_eq!(file_extension(".env.local"), ".env");
        assert_eq!(file_extension(".env.production"), ".env");
        assert_eq!(file_extension("/path/to/.env.staging"), ".env");
        assert_eq!(file_extension(".ENV"), ".env");
    }

    #[test]
    fn supported_extensions_includes_env() {
        assert!(crate::commands::SUPPORTED_EXTENSIONS.contains(&".env"));
    }

    #[test]
    fn validate_upload_allows_env_file() {
        use std::io::Write;
        // A literal `.env.local` file must pass the upload-mode allow-list.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env.local");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"SECRET=1").unwrap();
        validate(path.to_str().unwrap(), "password", "u", "file").unwrap();
    }

    #[test]
    fn supported_extensions_includes_developer_and_cert_types() {
        for ext in [".js", ".ts", ".py", ".rs", ".sql", ".pem", ".crt", ".csr", ".pub", ".ipynb"] {
            assert!(
                crate::commands::SUPPORTED_EXTENSIONS.contains(&ext),
                "missing {ext}"
            );
        }
    }

    #[test]
    fn validate_upload_allows_source_and_extensionless_files() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        for name in ["main.rs", "Dockerfile", "Makefile", ".gitignore"] {
            let path = dir.path().join(name);
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"x").unwrap();
            validate(path.to_str().unwrap(), "password", "u", "file")
                .unwrap_or_else(|e| panic!("{name} should be allowed: {e}"));
        }
    }

    #[test]
    fn validate_upload_still_rejects_unknown_extension() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("malware.exe");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"x").unwrap();
        let err = validate(path.to_str().unwrap(), "password", "u", "file").unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unsupported"));
    }

    // ── run_inner: mode validation ───────────────────────────────────────

    #[tokio::test]
    async fn run_inner_local_requires_p2p() {
        let err = run_inner("hello", "password", "u", "txt", None, true, None, true, false, &[], &mut |_| {})
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
        let body: serde_json::Value = serde_json::from_slice(&reqs.last().unwrap().body).unwrap();
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
        let body: serde_json::Value = serde_json::from_slice(&reqs.last().unwrap().body).unwrap();
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
        let body: serde_json::Value = serde_json::from_slice(&reqs.last().unwrap().body).unwrap();
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
        let body: serde_json::Value = serde_json::from_slice(&reqs.last().unwrap().body).unwrap();
        // expiresAt should be roughly 1h from now, not 7d
        let expires = body["expiresAt"].as_str().unwrap();
        assert!(!expires.is_empty());
    }
}
