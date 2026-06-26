//! `nullseal check` — network/connectivity diagnostic.
//!
//! A read-mostly debug tool answering "sharing isn't working, why?". It runs an
//! ordered chain of probes against the resolved backend — config, DNS, TCP/TLS,
//! web, core API, **create-session**, signaling (WebSocket), STUN (UDP) and TURN
//! (relay) — collects a [`CheckResult`] for each, and reports the single most
//! fundamental failing layer as the *blocker*.
//!
//! Two targets:
//! - `check server` — the full chain incl. STUN/TURN.
//! - `check turn`   — the DNS + STUN + TURN subset ("is UDP/relay blocked?").
//!
//! Two output modes:
//! - **normal** — one verdict line + (on failure) the single blocker line.
//! - **verbose** (`--verbose`) — the full per-probe ✓/✗ checklist + IPs / URLs /
//!   STUN srflx / TURN relayed address / timings, then the same verdict.
//!
//! `--pipe` emits a compact `probe=ok|fail` form + a `blocker=…` line.
//!
//! The probes never abort on first failure (each is `tokio::time::timeout`-bounded
//! at [`PROBE_TIMEOUT`]); the runner always collects every result so the blocker
//! can be picked from the full picture. Diagnostics are **factual** — they report
//! the observed failure (DNS, TCP, TLS, HTTP status, WS/STUN/TURN timeout), never
//! "a VPN or firewall may be blocking…" speculation.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::api::{ApiClient, IceServer};
use nullseal_p2p_control::transport::SocketIoTransport;
use nullseal_socketio::transport::TungsteniteWs;
use nullseal_turn::allocate::{new_txn_id, Credentials};
use nullseal_turn::message::{Class, MessageBuilder, Method};

/// Per-probe timeout. A hung network can't block the whole run past this.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// UDP recv timeout for the STUN binding probe.
const STUN_RECV_TIMEOUT: Duration = Duration::from_secs(5);

// ── Layers ──────────────────────────────────────────────────────────────────

/// The ordered connectivity layers. The blocker is the **first** layer (in this
/// order) that has a failing probe — downstream failures are usually consequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Layer {
    Config,
    Dns,
    TcpTls,
    Web,
    CoreApi,
    Session,
    Signaling,
    Stun,
    Turn,
}

impl Layer {
    /// Short label used in the `Blocker: <layer> — …` line.
    pub fn label(self) -> &'static str {
        match self {
            Layer::Config => "Config",
            Layer::Dns => "DNS",
            Layer::TcpTls => "TCP/TLS",
            Layer::Web => "Web",
            Layer::CoreApi => "Core API",
            Layer::Session => "Session",
            Layer::Signaling => "Signaling",
            Layer::Stun => "STUN",
            Layer::Turn => "TURN",
        }
    }

    /// Whether this layer is *critical* — a failure here means the verdict is
    /// BLOCKED and the exit code is non-zero. The **core** server chain is critical;
    /// `Web` (the nullseal.com app) is informational — a web outage does NOT block
    /// session creation (the CLI uses the core API), so it's non-critical. STUN/TURN
    /// are surfaced as a P2P warning, not a hard "can't reach the server" failure.
    pub fn is_critical(self) -> bool {
        matches!(
            self,
            Layer::Config | Layer::Dns | Layer::TcpTls | Layer::CoreApi | Layer::Session | Layer::Signaling
        )
    }
}

// ── CheckResult ───────────────────────────────────────────────────────────────

/// The outcome of a single probe.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Which ordered layer this probe belongs to.
    pub layer: Layer,
    /// Human label (e.g. "DNS — core host").
    pub name: &'static str,
    /// Whether the probe succeeded.
    pub ok: bool,
    /// Factual detail — resolved IPs / srflx / relayed addr on success, or the
    /// observed failure (timeout / refused / HTTP status) on failure.
    pub detail: String,
    /// Wall-clock latency of the probe, if measured.
    pub latency_ms: Option<u64>,
}

impl CheckResult {
    fn ok(layer: Layer, name: &'static str, detail: impl Into<String>, latency_ms: Option<u64>) -> Self {
        Self { layer, name, ok: true, detail: detail.into(), latency_ms }
    }
    fn fail(layer: Layer, name: &'static str, detail: impl Into<String>, latency_ms: Option<u64>) -> Self {
        Self { layer, name, ok: false, detail: detail.into(), latency_ms }
    }
}

// ── Blocker / verdict (pure, unit-testable) ───────────────────────────────────

/// The verdict computed from the collected results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Everything (server chain + STUN/TURN) passed.
    Ok,
    /// The server chain is healthy but STUN/TURN failed — sessions can be
    /// created, but P2P will fall back to relay / may not connect.
    OkButP2pMayFail { blocker_line: String },
    /// A critical (server-chain) layer failed.
    Blocked { blocker_line: String },
}

impl Verdict {
    /// Exit code: 0 only when the critical checks pass; non-zero otherwise.
    pub fn exit_code(&self) -> i32 {
        match self {
            Verdict::Ok | Verdict::OkButP2pMayFail { .. } => 0,
            Verdict::Blocked { .. } => 1,
        }
    }
}

/// Format the single `Blocker:` line for a failing probe — `<layer> — <factual cause>`.
pub fn blocker_line(r: &CheckResult) -> String {
    format!("{} — {}", r.layer.label(), r.detail)
}

/// First failing probe whose layer matches `pred`, walked in layer order.
fn first_failing(results: &[CheckResult], pred: impl Fn(Layer) -> bool) -> Option<&CheckResult> {
    const ORDER: [Layer; 9] = [
        Layer::Config, Layer::Dns, Layer::TcpTls, Layer::Web,
        Layer::CoreApi, Layer::Session, Layer::Signaling, Layer::Stun, Layer::Turn,
    ];
    ORDER
        .iter()
        .filter(|l| pred(**l))
        .find_map(|&layer| results.iter().find(|r| r.layer == layer && !r.ok))
}

/// Compute the verdict from the collected probe results.
pub fn compute_verdict(results: &[CheckResult]) -> Verdict {
    // 1. First failing *critical* (core-chain) layer → BLOCKED.
    if let Some(r) = first_failing(results, |l| l.is_critical()) {
        return Verdict::Blocked { blocker_line: blocker_line(r) };
    }
    // 2. No critical failure, but STUN/TURN down → sessions can still be created,
    //    but P2P may fall back to relay / fail.
    if let Some(r) = first_failing(results, |l| matches!(l, Layer::Stun | Layer::Turn)) {
        return Verdict::OkButP2pMayFail { blocker_line: blocker_line(r) };
    }
    // 3. Otherwise OK. A Web-only failure (the nullseal.com app) is informational —
    //    shown in --verbose, but it never blocks "can I create a session?".
    Verdict::Ok
}

/// Exit code for the whole command. `check turn` is a focused reachability check —
/// a blocked TURN/STUN is a failure for it (non-zero); for `check server` the same
/// state stays "OK, but P2P may fail" (exit 0, sessions can still be created).
pub fn exit_for(target: Target, verdict: &Verdict) -> i32 {
    match (target, verdict) {
        (Target::Turn, Verdict::OkButP2pMayFail { .. }) => 1,
        _ => verdict.exit_code(),
    }
}

// ── Formatting (pure, unit-testable) ──────────────────────────────────────────

/// Which command we ran — only affects the headline label in normal mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Server,
    Turn,
}

/// Normal (default) output: just the verdict + (on failure) one blocker line.
pub fn format_normal(target: Target, verdict: &Verdict) -> String {
    match (target, verdict) {
        (Target::Server, Verdict::Ok) => "Server connectivity: OK".to_string(),
        (Target::Server, Verdict::OkButP2pMayFail { blocker_line }) => {
            format!("Server connectivity: OK, but P2P may fail\nBlocker: {blocker_line}")
        }
        (Target::Server, Verdict::Blocked { blocker_line }) => {
            format!("Server connectivity: BLOCKED\nBlocker: {blocker_line}")
        }
        (Target::Turn, Verdict::Ok) => "TURN/STUN: reachable".to_string(),
        (Target::Turn, Verdict::OkButP2pMayFail { blocker_line }) => {
            format!("TURN/STUN: blocked — {}", strip_layer_prefix(blocker_line))
        }
        (Target::Turn, Verdict::Blocked { blocker_line }) => {
            format!("TURN/STUN: blocked — {}", strip_layer_prefix(blocker_line))
        }
    }
}

/// For the `check turn` headline we already say "TURN/STUN"; drop the redundant
/// `STUN — ` / `TURN — ` layer prefix from the cause for that one line.
fn strip_layer_prefix(line: &str) -> String {
    line.split_once(" — ").map(|(_, rest)| rest.to_string()).unwrap_or_else(|| line.to_string())
}

/// Verbose output: the full ordered checklist + the verdict.
pub fn format_verbose(target: Target, results: &[CheckResult], verdict: &Verdict) -> String {
    let mut out = String::new();
    out.push_str("Connectivity diagnostic\n");
    for r in results {
        let mark = if r.ok { "✓" } else { "✗" };
        let timing = match r.latency_ms {
            Some(ms) => format!(" ({ms} ms)"),
            None => String::new(),
        };
        out.push_str(&format!("  {mark} [{}] {} — {}{timing}\n", r.layer.label(), r.name, r.detail));
    }
    out.push('\n');
    out.push_str(&format_normal(target, verdict));
    out
}

/// Pipe (`--pipe`) output: compact, machine-readable. One `probe=ok|fail` line
/// per result plus a final `blocker=…` line. Exit code is authoritative.
pub fn format_pipe(results: &[CheckResult], verdict: &Verdict) -> String {
    let mut out = String::new();
    for r in results {
        out.push_str(&format!("{}={}\n", probe_key(r.layer, r.name), if r.ok { "ok" } else { "fail" }));
    }
    let blocker = match verdict {
        Verdict::Ok => "none".to_string(),
        Verdict::OkButP2pMayFail { blocker_line } | Verdict::Blocked { blocker_line } => blocker_line.clone(),
    };
    out.push_str(&format!("blocker={blocker}"));
    out
}

/// Stable snake_case key for a probe in pipe mode (`dns_core`, `tcp_tls_core`, …).
fn probe_key(layer: Layer, name: &str) -> String {
    let layer_key = match layer {
        Layer::Config => "config",
        Layer::Dns => "dns",
        Layer::TcpTls => "tcp_tls",
        Layer::Web => "web",
        Layer::CoreApi => "core_api",
        Layer::Session => "session",
        Layer::Signaling => "signaling",
        Layer::Stun => "stun",
        Layer::Turn => "turn",
    };
    // Only DNS and TCP/TLS have >1 probe (core host vs web host); disambiguate
    // those with a suffix. All other layers have a single probe → bare key.
    let suffix = if matches!(layer, Layer::Dns | Layer::TcpTls) {
        if name.contains("web") || name.contains("Web") {
            "_web"
        } else if name.contains("core") || name.contains("Core") {
            "_core"
        } else {
            ""
        }
    } else {
        ""
    };
    format!("{layer_key}{suffix}")
}

// ── URL / host resolution (mirrors share.rs, no duplicated probe logic) ───────

/// Resolve the core API base the same way `share`/`get` do: `-s` → env →
/// compile-time fallback. Returns `Err` when nothing is set (which alone explains
/// "can't create a session").
fn resolve_core_url(server: Option<&str>) -> Result<String> {
    server
        .map(str::to_owned)
        .or_else(|| std::env::var("CLI_APPS_CORE_URL").ok())
        .or_else(|| option_env!("CLI_APPS_CORE_URL").map(str::to_owned))
        .ok_or_else(|| anyhow::anyhow!("CLI_APPS_CORE_URL environment variable is not set"))
}

/// Resolve the web base (`CLI_APPS_USER_URL`), same as `share`/`get`.
fn resolve_user_url() -> Option<String> {
    std::env::var("CLI_APPS_USER_URL")
        .ok()
        .or_else(|| option_env!("CLI_APPS_USER_URL").map(str::to_owned))
}

/// Extract `(host, port)` from a URL, defaulting the port from the scheme
/// (https/wss → 443, http/ws → 80).
pub fn host_port(url_str: &str) -> Result<(String, u16)> {
    let parsed = url::Url::parse(url_str)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host: {url_str}"))?
        .to_string();
    let port = parsed.port().unwrap_or(match parsed.scheme() {
        "https" | "wss" => 443,
        _ => 80,
    });
    Ok((host, port))
}

/// Parse a `stun:host:port` URI into `host:port` (port defaults to 3478).
fn parse_stun_uri(uri: &str) -> Option<String> {
    let stripped = uri.strip_prefix("stun:").or_else(|| uri.strip_prefix("stuns:")).unwrap_or(uri);
    let addr_part = stripped.split('?').next().unwrap_or(stripped);
    if addr_part.is_empty() {
        return None;
    }
    if addr_part.contains(':') {
        Some(addr_part.to_string())
    } else {
        Some(format!("{addr_part}:3478"))
    }
}

/// Pull the first `stun:` URI out of an ICE server config.
fn first_stun_uri(ice_servers: &[IceServer]) -> Option<String> {
    ice_servers.iter().find_map(|s| uris_of(s).into_iter().find(|u| u.starts_with("stun:") || u.starts_with("stuns:")))
}

/// Pull the first `turn:` server (uri + creds) out of an ICE server config.
fn first_turn(ice_servers: &[IceServer]) -> Option<(String, String, String)> {
    ice_servers.iter().find_map(|s| {
        let username = s.username.clone()?;
        let credential = s.credential.clone()?;
        let uri = uris_of(s).into_iter().find(|u| u.starts_with("turn:") || u.starts_with("turns:"))?;
        Some((uri, username, credential))
    })
}

/// Normalize an `IceServer.urls` (string or array) into a `Vec<String>`.
fn uris_of(s: &IceServer) -> Vec<String> {
    if let Some(u) = s.urls.as_str() {
        return vec![u.to_string()];
    }
    if let Some(arr) = s.urls.as_array() {
        return arr.iter().filter_map(|u| u.as_str().map(String::from)).collect();
    }
    Vec::new()
}

/// Whether the ICE config advertises any `turn:` server.
fn has_turn_entry(ice_servers: &[IceServer]) -> bool {
    ice_servers.iter().any(|s| uris_of(s).iter().any(|u| u.starts_with("turn:") || u.starts_with("turns:")))
}

// ── Probes (network I/O; each timeout-bounded) ────────────────────────────────

/// DNS-resolve `host:port`, returning the resolved IPs.
async fn probe_dns(layer: Layer, name: &'static str, host: &str, port: u16) -> CheckResult {
    let start = Instant::now();
    let target = format!("{host}:{port}");
    match timeout(PROBE_TIMEOUT, tokio::net::lookup_host(target.clone())).await {
        Ok(Ok(addrs)) => {
            let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            let ms = start.elapsed().as_millis() as u64;
            if ips.is_empty() {
                CheckResult::fail(layer, name, format!("cannot resolve {host} (no addresses)"), Some(ms))
            } else {
                CheckResult::ok(layer, name, format!("{host} → {}", ips.join(", ")), Some(ms))
            }
        }
        Ok(Err(e)) => CheckResult::fail(layer, name, format!("cannot resolve {host}: {e}"), Some(start.elapsed().as_millis() as u64)),
        Err(_) => CheckResult::fail(layer, name, format!("DNS lookup for {host} timed out"), Some(PROBE_TIMEOUT.as_millis() as u64)),
    }
}

/// TCP+TLS reachability: a HEAD to the URL root via reqwest (which does the TCP +
/// TLS handshake using the OS cert store). Any HTTP response — including 4xx —
/// proves the transport layer is up; only connect/timeout/TLS errors fail here.
async fn probe_tcp_tls(layer: Layer, name: &'static str, base_url: &str) -> CheckResult {
    let start = Instant::now();
    let client = reqwest::Client::new();
    let root = base_url.trim_end_matches('/').to_string();
    match timeout(PROBE_TIMEOUT, client.head(&root).send()).await {
        Ok(Ok(resp)) => CheckResult::ok(
            layer,
            name,
            format!("reachable (HTTP {})", resp.status().as_u16()),
            Some(start.elapsed().as_millis() as u64),
        ),
        Ok(Err(e)) => CheckResult::fail(layer, name, tcp_tls_cause(base_url, &e), Some(start.elapsed().as_millis() as u64)),
        Err(_) => CheckResult::fail(layer, name, format!("connection to {root} timed out"), Some(PROBE_TIMEOUT.as_millis() as u64)),
    }
}

/// Factual cause string for a reqwest transport failure (refused / TLS / other).
fn tcp_tls_cause(base_url: &str, e: &reqwest::Error) -> String {
    let host = host_port(base_url).map(|(h, p)| format!("{h}:{p}")).unwrap_or_else(|_| base_url.to_string());
    let msg = e.to_string();
    let low = msg.to_lowercase();
    if low.contains("refused") {
        format!("connection refused to {host}")
    } else if low.contains("certificate") || low.contains("tls") || low.contains("handshake") {
        format!("TLS error to {host}: {msg}")
    } else {
        format!("cannot reach {host}: {msg}")
    }
}

/// HTTP GET the web base `/` — expect 2xx/3xx.
async fn probe_web(base_url: &str) -> CheckResult {
    let layer = Layer::Web; // informational: web-app reachability, NON-critical (session creation uses the core API, not the web app)
    let name = "Web reachable (nullseal.com)";
    let start = Instant::now();
    let client = reqwest::Client::new();
    let root = base_url.trim_end_matches('/').to_string();
    match timeout(PROBE_TIMEOUT, client.get(&root).send()).await {
        Ok(Ok(resp)) => {
            let status = resp.status();
            let ms = start.elapsed().as_millis() as u64;
            if status.is_success() || status.is_redirection() {
                CheckResult::ok(layer, name, format!("HTTP {}", status.as_u16()), Some(ms))
            } else {
                CheckResult::fail(layer, name, format!("HTTP {} from web base", status.as_u16()), Some(ms))
            }
        }
        Ok(Err(e)) => CheckResult::fail(layer, name, tcp_tls_cause(base_url, &e), Some(start.elapsed().as_millis() as u64)),
        Err(_) => CheckResult::fail(layer, name, format!("web GET to {root} timed out"), Some(PROBE_TIMEOUT.as_millis() as u64)),
    }
}

/// Core API liveness: `GET /p2p/ice-servers`. Returns the parsed ICE servers on
/// success (the STUN/TURN probes reuse them) alongside the result.
async fn probe_core_api(client: &ApiClient) -> (CheckResult, Vec<IceServer>) {
    let name = "Core API (get ICE servers)";
    let start = Instant::now();
    match timeout(PROBE_TIMEOUT, client.get_ice_servers()).await {
        Ok(Ok(servers)) => {
            let ms = start.elapsed().as_millis() as u64;
            let turn = if has_turn_entry(&servers) { ", turn: present" } else { ", turn: none" };
            let detail = format!("{} ICE server(s){turn}", servers.len());
            (CheckResult::ok(Layer::CoreApi, name, detail, Some(ms)), servers)
        }
        Ok(Err(e)) => (
            CheckResult::fail(Layer::CoreApi, name, api_cause(&e), Some(start.elapsed().as_millis() as u64)),
            Vec::new(),
        ),
        Err(_) => (
            CheckResult::fail(Layer::CoreApi, name, "ICE-servers request timed out", Some(PROBE_TIMEOUT.as_millis() as u64)),
            Vec::new(),
        ),
    }
}

/// Create-session (headline): `POST /p2p/sessions`. The session auto-expires
/// (~30 min) — there is no delete endpoint, so we don't try to delete it.
async fn probe_session(client: &ApiClient) -> CheckResult {
    let name = "Create session";
    let start = Instant::now();
    // Throwaway proof — a 64-hex placeholder; the server only stores it.
    let proof = "0".repeat(64);
    match timeout(PROBE_TIMEOUT, client.create_p2p_session(&proof)).await {
        Ok(Ok(resp)) => {
            let ms = start.elapsed().as_millis() as u64;
            let sid = truncate_id(&resp.session_id);
            CheckResult::ok(Layer::Session, name, format!("session {sid} created (auto-expires ~30 min)"), Some(ms))
        }
        Ok(Err(e)) => CheckResult::fail(Layer::Session, name, api_cause(&e), Some(start.elapsed().as_millis() as u64)),
        Err(_) => CheckResult::fail(Layer::Session, name, "create-session request timed out", Some(PROBE_TIMEOUT.as_millis() as u64)),
    }
}

/// Factual cause from an `ApiError` (network vs request failed).
fn api_cause(e: &crate::api::ApiError) -> String {
    match e {
        crate::api::ApiError::Network(ne) => {
            let msg = ne.to_string();
            if let Some(status) = ne.status() {
                format!("HTTP {}", status.as_u16())
            } else if msg.to_lowercase().contains("refused") {
                "connection refused".to_string()
            } else {
                format!("network error: {msg}")
            }
        }
        other => other.to_string(),
    }
}

/// Truncate a session id for display (first 8 chars + …).
fn truncate_id(id: &str) -> String {
    if id.len() > 8 {
        format!("{}…", &id[..8])
    } else {
        id.to_string()
    }
}

/// Signaling: connect the Socket.IO `/p2p` namespace, confirm the CONNECT
/// handshake, then drop the transport (disconnect).
async fn probe_signaling(base_url: &str) -> CheckResult {
    let name = "Signaling (Socket.IO /p2p)";
    let start = Instant::now();
    let ws_url = match TungsteniteWs::build_url(base_url) {
        Ok(u) => u,
        Err(e) => return CheckResult::fail(Layer::Signaling, name, format!("bad WS URL: {e}"), None),
    };
    let connect = async {
        let ws = TungsteniteWs::connect(&ws_url).await?;
        let (transport, _evts) = SocketIoTransport::connect(ws, "p2p").await?;
        // Handshake confirmed by a successful connect; drop to disconnect.
        drop(transport);
        Ok::<(), anyhow::Error>(())
    };
    match timeout(PROBE_TIMEOUT, connect).await {
        Ok(Ok(())) => CheckResult::ok(Layer::Signaling, name, format!("handshake OK ({ws_url})"), Some(start.elapsed().as_millis() as u64)),
        Ok(Err(e)) => CheckResult::fail(Layer::Signaling, name, format!("WebSocket handshake failed: {e}"), Some(start.elapsed().as_millis() as u64)),
        Err(_) => CheckResult::fail(Layer::Signaling, name, "WebSocket handshake timed out", Some(PROBE_TIMEOUT.as_millis() as u64)),
    }
}

/// STUN Binding (UDP): send a Binding request to the first `stun:` server, expect
/// the server-reflexive (srflx) address back. No response ⇒ UDP egress filtered.
async fn probe_stun(ice_servers: &[IceServer]) -> CheckResult {
    let name = "STUN Binding (UDP)";
    let start = Instant::now();
    let uri = match first_stun_uri(ice_servers) {
        Some(u) => u,
        None => return CheckResult::fail(Layer::Stun, name, "no stun: server in ICE config", None),
    };
    let host_port = match parse_stun_uri(&uri) {
        Some(hp) => hp,
        None => return CheckResult::fail(Layer::Stun, name, format!("unparseable STUN URI: {uri}"), None),
    };
    let server: SocketAddr = match timeout(PROBE_TIMEOUT, tokio::net::lookup_host(&host_port)).await {
        Ok(Ok(mut it)) => match it.next() {
            Some(a) => a,
            None => return CheckResult::fail(Layer::Stun, name, format!("cannot resolve STUN host {host_port}"), None),
        },
        Ok(Err(e)) => return CheckResult::fail(Layer::Stun, name, format!("cannot resolve STUN host {host_port}: {e}"), None),
        Err(_) => return CheckResult::fail(Layer::Stun, name, format!("DNS for STUN host {host_port} timed out"), None),
    };

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => return CheckResult::fail(Layer::Stun, name, format!("UDP bind failed: {e}"), None),
    };
    let txn_id = new_txn_id();
    let req = MessageBuilder::new(Method::Binding, Class::Request, txn_id).build_with_fingerprint();
    if let Err(e) = socket.send_to(&req, server).await {
        return CheckResult::fail(Layer::Stun, name, format!("UDP send failed: {e}"), None);
    }
    let mut buf = [0u8; 2048];
    match timeout(STUN_RECV_TIMEOUT, socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _src))) => {
            let ms = start.elapsed().as_millis() as u64;
            match nullseal_turn::message::decode(&buf[..len]) {
                Some(msg) => {
                    let srflx = msg.attrs.iter().find_map(|a| match a {
                        nullseal_turn::attr::Attribute::XorMappedAddress(addr)
                        | nullseal_turn::attr::Attribute::MappedAddress(addr) => Some(*addr),
                        _ => None,
                    });
                    match srflx {
                        Some(addr) => CheckResult::ok(Layer::Stun, name, format!("srflx {addr} (via {uri})"), Some(ms)),
                        None => CheckResult::fail(Layer::Stun, name, "STUN response had no mapped address", Some(ms)),
                    }
                }
                None => CheckResult::fail(Layer::Stun, name, "malformed STUN response", Some(ms)),
            }
        }
        Ok(Err(e)) => CheckResult::fail(Layer::Stun, name, format!("UDP recv error: {e}"), Some(start.elapsed().as_millis() as u64)),
        Err(_) => CheckResult::fail(Layer::Stun, name, "no STUN response — UDP may be filtered", Some(STUN_RECV_TIMEOUT.as_millis() as u64)),
    }
}

/// TURN Allocate (UDP): drive a real allocate (long-term cred) against the first
/// `turn:` server and confirm a relayed address. Let the allocation expire (no refresh).
async fn probe_turn(ice_servers: &[IceServer]) -> CheckResult {
    let name = "TURN Allocate (UDP)";
    let start = Instant::now();
    let (uri, username, credential) = match first_turn(ice_servers) {
        Some(t) => t,
        None => return CheckResult::fail(Layer::Turn, name, "no turn: server (with credentials) in ICE config", None),
    };
    let server = match crate::webrtc::turn::parse_turn_uri(&uri) {
        Ok(a) => a,
        Err(e) => return CheckResult::fail(Layer::Turn, name, format!("unparseable TURN URI {uri}: {e}"), None),
    };
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => return CheckResult::fail(Layer::Turn, name, format!("UDP bind failed: {e}"), None),
    };
    let creds = Credentials { username, password: credential };
    match timeout(PROBE_TIMEOUT, crate::webrtc::turn::allocate(&socket, server, creds)).await {
        Ok(Ok(alloc)) => {
            let ms = start.elapsed().as_millis() as u64;
            CheckResult::ok(
                Layer::Turn,
                name,
                format!("relayed {} (srflx {}, via {uri}, expires ~{}s)", alloc.relayed, alloc.srflx, alloc.lifetime),
                Some(ms),
            )
        }
        Ok(Err(e)) => CheckResult::fail(Layer::Turn, name, turn_cause(&e), Some(start.elapsed().as_millis() as u64)),
        Err(_) => CheckResult::fail(Layer::Turn, name, "no allocate response (UDP relay blocked)", Some(PROBE_TIMEOUT.as_millis() as u64)),
    }
}

/// Factual cause from a TURN allocate failure (auth vs timeout vs other).
fn turn_cause(e: &anyhow::Error) -> String {
    let msg = e.to_string();
    let low = msg.to_lowercase();
    if low.contains("timed out") || low.contains("timeout") {
        "no allocate response (UDP relay blocked)".to_string()
    } else if low.contains("401") || low.contains("403") || low.contains("unauthor") {
        format!("auth failed: {msg}")
    } else {
        format!("allocate failed: {msg}")
    }
}

// ── Runner ────────────────────────────────────────────────────────────────────

/// Build the "resolved config" check (always first; never a blocker on its own
/// unless the core URL is unset).
fn config_result(core_url: &Result<String>, user_url: &Option<String>, ws_url: &Option<String>) -> CheckResult {
    let name = "Resolved config";
    match core_url {
        Ok(core) => {
            let web = user_url.clone().unwrap_or_else(|| "(CLI_APPS_USER_URL unset)".to_string());
            let ws = ws_url.clone().unwrap_or_else(|| "(n/a)".to_string());
            CheckResult::ok(Layer::Config, name, format!("core={core}  web={web}  ws={ws}"), None)
        }
        Err(e) => CheckResult::fail(Layer::Config, name, e.to_string(), None),
    }
}

/// Run all probes for `check server` (full chain) and return the ordered results.
pub async fn run_server_probes(server: Option<&str>) -> Vec<CheckResult> {
    let core_url = resolve_core_url(server);
    let user_url = resolve_user_url();
    let ws_url = core_url.as_ref().ok().and_then(|c| TungsteniteWs::build_url(c).ok());

    let mut results = vec![config_result(&core_url, &user_url, &ws_url)];

    // Without a core URL nothing downstream is meaningful — config is the blocker.
    let core = match &core_url {
        Ok(c) => c.clone(),
        Err(_) => return results,
    };

    // DNS — core host (and web host if configured).
    if let Ok((host, port)) = host_port(&core) {
        results.push(probe_dns(Layer::Dns, "DNS — core host", &host, port).await);
    }
    if let Some(web) = &user_url {
        if let Ok((host, port)) = host_port(web) {
            results.push(probe_dns(Layer::Dns, "DNS — web host", &host, port).await);
        }
    }

    // TCP/TLS — core (and web reachability).
    results.push(probe_tcp_tls(Layer::TcpTls, "TCP/TLS — core host", &core).await);
    if let Some(web) = &user_url {
        results.push(probe_web(web).await);
    }

    // Core API + session.
    let client = ApiClient::new(&core);
    let (api_result, ice_servers) = probe_core_api(&client).await;
    results.push(api_result);
    results.push(probe_session(&client).await);

    // Signaling.
    results.push(probe_signaling(&core).await);

    // STUN + TURN (reuse the ICE servers from the core-API probe).
    results.push(probe_stun(&ice_servers).await);
    results.push(probe_turn(&ice_servers).await);

    results
}

/// Run the `check turn` subset: DNS (core) + STUN + TURN. We still need the ICE
/// config from the core API to know which STUN/TURN servers to probe, so a core
/// failure surfaces factually (and as the blocker) here too.
pub async fn run_turn_probes(server: Option<&str>) -> Vec<CheckResult> {
    let core_url = resolve_core_url(server);
    let ws_url = core_url.as_ref().ok().and_then(|c| TungsteniteWs::build_url(c).ok());
    let mut results = vec![config_result(&core_url, &resolve_user_url(), &ws_url)];

    let core = match &core_url {
        Ok(c) => c.clone(),
        Err(_) => return results,
    };

    if let Ok((host, port)) = host_port(&core) {
        results.push(probe_dns(Layer::Dns, "DNS — core host", &host, port).await);
    }

    let client = ApiClient::new(&core);
    let (api_result, ice_servers) = probe_core_api(&client).await;
    results.push(api_result);

    results.push(probe_stun(&ice_servers).await);
    results.push(probe_turn(&ice_servers).await);
    results
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run `nullseal check <target>` and print the result in the active output mode.
/// Returns the process exit code (0 only when critical checks pass).
pub async fn run(target: Target, server: Option<String>) -> i32 {
    let results = match target {
        Target::Server => run_server_probes(server.as_deref()).await,
        Target::Turn => run_turn_probes(server.as_deref()).await,
    };
    let verdict = compute_verdict(&results);

    if super::log::is_pipe() {
        // Compact machine-readable form on stdout; exit code authoritative.
        println!("{}", format_pipe(&results, &verdict));
    } else if super::log::is_verbose() {
        eprintln!("{}", format_verbose(target, &results, &verdict));
    } else {
        eprintln!("{}", format_normal(target, &verdict));
    }

    exit_for(target, &verdict)
}

// ── Tests (pure; no network) ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(layer: Layer, name: &'static str) -> CheckResult {
        CheckResult::ok(layer, name, "fine", Some(10))
    }
    fn fail(layer: Layer, name: &'static str, detail: &str) -> CheckResult {
        CheckResult::fail(layer, name, detail.to_string(), Some(5000))
    }

    fn all_ok() -> Vec<CheckResult> {
        vec![
            ok(Layer::Config, "Resolved config"),
            ok(Layer::Dns, "DNS — core host"),
            ok(Layer::TcpTls, "TCP/TLS — core host"),
            ok(Layer::CoreApi, "Core API"),
            ok(Layer::Session, "Create session"),
            ok(Layer::Signaling, "Signaling"),
            ok(Layer::Stun, "STUN Binding"),
            ok(Layer::Turn, "TURN Allocate"),
        ]
    }

    // ── blocker / layer ordering (via compute_verdict) ───────────────────

    #[test]
    fn no_blocker_when_all_ok() {
        assert_eq!(compute_verdict(&all_ok()), Verdict::Ok);
    }

    #[test]
    fn picks_most_fundamental_failing_layer() {
        // DNS (critical) and TURN both fail → DNS (more fundamental) is the blocker.
        let mut r = all_ok();
        r[1] = fail(Layer::Dns, "DNS — core host", "cannot resolve core.nullseal.com");
        r[7] = fail(Layer::Turn, "TURN Allocate", "no allocate response");
        match compute_verdict(&r) {
            Verdict::Blocked { blocker_line } => assert!(blocker_line.starts_with("DNS")),
            other => panic!("expected Blocked(DNS), got {other:?}"),
        }
    }

    #[test]
    fn config_unset_is_the_blocker() {
        let r = vec![fail(Layer::Config, "Resolved config", "CLI_APPS_CORE_URL environment variable is not set")];
        match compute_verdict(&r) {
            Verdict::Blocked { blocker_line } => assert!(blocker_line.starts_with("Config")),
            other => panic!("expected Blocked(Config), got {other:?}"),
        }
    }

    #[test]
    fn tcp_failure_beats_session_failure() {
        let mut r = all_ok();
        r[2] = fail(Layer::TcpTls, "TCP/TLS — core host", "connection refused to core.nullseal.com:443");
        r[4] = fail(Layer::Session, "Create session", "HTTP 500");
        match compute_verdict(&r) {
            Verdict::Blocked { blocker_line } => assert!(blocker_line.starts_with("TCP/TLS")),
            other => panic!("expected Blocked(TCP/TLS), got {other:?}"),
        }
    }

    // ── verdict / exit-code decision ─────────────────────────────────────

    #[test]
    fn verdict_ok_exits_zero() {
        let v = compute_verdict(&all_ok());
        assert_eq!(v, Verdict::Ok);
        assert_eq!(v.exit_code(), 0);
    }

    // ── B1: web (nullseal.com) is informational, never a blocker ─────────────

    #[test]
    fn web_down_but_core_ok_is_verdict_ok() {
        // Web app unreachable, but the whole core chain + STUN/TURN pass → sessions
        // can be created, so the verdict is OK (web is informational, not a blocker).
        let mut r = all_ok();
        r.push(fail(Layer::Web, "Web reachable (nullseal.com)", "cannot reach nullseal.com:443"));
        let v = compute_verdict(&r);
        assert_eq!(v, Verdict::Ok);
        assert_eq!(exit_for(Target::Server, &v), 0);
    }

    #[test]
    fn critical_failure_after_web_still_blocks() {
        // Web fails AND a critical layer after it (CoreApi) fails → BLOCKED on the
        // critical layer, not silently OK because web came first in the order.
        let mut r = all_ok();
        r.push(fail(Layer::Web, "Web reachable (nullseal.com)", "cannot reach nullseal.com:443"));
        r[3] = fail(Layer::CoreApi, "Core API", "HTTP 503");
        match compute_verdict(&r) {
            Verdict::Blocked { blocker_line } => assert!(blocker_line.starts_with("Core API")),
            other => panic!("expected Blocked(Core API), got {other:?}"),
        }
    }

    // ── B2: `check turn` exit code on a blocked relay ────────────────────────

    #[test]
    fn check_turn_exits_nonzero_when_turn_blocked() {
        let v = Verdict::OkButP2pMayFail { blocker_line: "TURN — no allocate response".into() };
        assert_eq!(exit_for(Target::Turn, &v), 1, "check turn: blocked relay must fail");
        assert_eq!(exit_for(Target::Server, &v), 0, "check server: TURN blocked is only a P2P warning");
    }

    #[test]
    fn server_chain_failure_is_blocked_nonzero() {
        let mut r = all_ok();
        r[3] = fail(Layer::CoreApi, "Core API", "HTTP 403");
        let v = compute_verdict(&r);
        assert!(matches!(v, Verdict::Blocked { .. }));
        assert_ne!(v.exit_code(), 0);
    }

    #[test]
    fn turn_only_failure_is_ok_but_p2p_may_fail_exit_zero() {
        // Server chain healthy, only TURN fails → OK-but-P2P-may-fail, exit 0.
        let mut r = all_ok();
        r[7] = fail(Layer::Turn, "TURN Allocate", "no allocate response (UDP relay blocked)");
        let v = compute_verdict(&r);
        assert!(matches!(v, Verdict::OkButP2pMayFail { .. }));
        assert_eq!(v.exit_code(), 0);
    }

    #[test]
    fn stun_failure_alone_is_p2p_warning_not_blocked() {
        let mut r = all_ok();
        r[6] = fail(Layer::Stun, "STUN Binding", "no STUN response — UDP may be filtered");
        let v = compute_verdict(&r);
        assert!(matches!(v, Verdict::OkButP2pMayFail { .. }));
        assert_eq!(v.exit_code(), 0);
    }

    // ── blocker line is factual ──────────────────────────────────────────

    #[test]
    fn blocker_line_has_layer_and_cause() {
        let r = fail(Layer::TcpTls, "TCP/TLS — core host", "connection refused to core.nullseal.com:443");
        assert_eq!(blocker_line(&r), "TCP/TLS — connection refused to core.nullseal.com:443");
    }

    // ── formatting: normal ───────────────────────────────────────────────

    #[test]
    fn normal_ok_server() {
        assert_eq!(format_normal(Target::Server, &Verdict::Ok), "Server connectivity: OK");
    }

    #[test]
    fn normal_blocked_server_shows_single_blocker_no_checklist() {
        let v = Verdict::Blocked { blocker_line: "DNS — cannot resolve core.nullseal.com".to_string() };
        let out = format_normal(Target::Server, &v);
        assert!(out.contains("Server connectivity: BLOCKED"));
        assert!(out.contains("Blocker: DNS — cannot resolve core.nullseal.com"));
        // No per-probe checklist in normal mode.
        assert!(!out.contains('✓'));
        assert!(!out.contains('✗'));
    }

    #[test]
    fn normal_p2p_warning_surfaces_turn_blocker() {
        let v = Verdict::OkButP2pMayFail {
            blocker_line: "TURN — no allocate response (UDP relay blocked)".to_string(),
        };
        let out = format_normal(Target::Server, &v);
        assert!(out.contains("Server connectivity: OK, but P2P may fail"));
        assert!(out.contains("Blocker: TURN — no allocate response (UDP relay blocked)"));
    }

    #[test]
    fn normal_check_turn_reachable_and_blocked() {
        assert_eq!(format_normal(Target::Turn, &Verdict::Ok), "TURN/STUN: reachable");
        let v = Verdict::OkButP2pMayFail {
            blocker_line: "TURN — no allocate response (UDP relay blocked)".to_string(),
        };
        assert_eq!(format_normal(Target::Turn, &v), "TURN/STUN: blocked — no allocate response (UDP relay blocked)");
    }

    // ── formatting: verbose shows the full checklist ─────────────────────

    #[test]
    fn verbose_shows_every_probe_with_marks_then_verdict() {
        let mut r = all_ok();
        r[7] = fail(Layer::Turn, "TURN Allocate", "no allocate response (UDP relay blocked)");
        let v = compute_verdict(&r);
        let out = format_verbose(Target::Server, &r, &v);
        assert!(out.contains('✓'));
        assert!(out.contains('✗'));
        assert!(out.contains("[STUN]"));
        assert!(out.contains("[TURN]"));
        assert!(out.contains("Server connectivity: OK, but P2P may fail"));
    }

    // ── formatting: pipe ─────────────────────────────────────────────────

    #[test]
    fn pipe_emits_probe_lines_and_blocker() {
        let mut r = all_ok();
        r[3] = fail(Layer::CoreApi, "Core API", "HTTP 403");
        let v = compute_verdict(&r);
        let out = format_pipe(&r, &v);
        assert!(out.contains("core_api=fail"));
        assert!(out.contains("dns_core=ok"));
        assert!(out.contains("blocker=Core API — HTTP 403"));
    }

    #[test]
    fn pipe_blocker_none_when_all_ok() {
        let out = format_pipe(&all_ok(), &Verdict::Ok);
        assert!(out.contains("blocker=none"));
    }

    // ── host_port parsing ────────────────────────────────────────────────

    #[test]
    fn host_port_defaults_https_443() {
        assert_eq!(host_port("https://core.nullseal.com").unwrap(), ("core.nullseal.com".to_string(), 443));
    }

    #[test]
    fn host_port_explicit_port() {
        assert_eq!(host_port("http://127.0.0.1:9").unwrap(), ("127.0.0.1".to_string(), 9));
    }

    #[test]
    fn host_port_http_defaults_80() {
        assert_eq!(host_port("http://example.com").unwrap(), ("example.com".to_string(), 80));
    }

    // ── stun / turn URI helpers ──────────────────────────────────────────

    #[test]
    fn parse_stun_uri_adds_default_port() {
        assert_eq!(parse_stun_uri("stun:stun.l.google.com").as_deref(), Some("stun.l.google.com:3478"));
    }

    #[test]
    fn parse_stun_uri_keeps_explicit_port() {
        assert_eq!(parse_stun_uri("stun:127.0.0.1:3478").as_deref(), Some("127.0.0.1:3478"));
    }

    #[test]
    fn uris_of_handles_string_and_array() {
        let s = IceServer {
            urls: serde_json::json!("stun:127.0.0.1:3478"),
            username: None,
            credential: None,
        };
        assert_eq!(uris_of(&s), vec!["stun:127.0.0.1:3478".to_string()]);
        let a = IceServer {
            urls: serde_json::json!(["stun:127.0.0.1:3478", "turn:127.0.0.1:3478"]),
            username: Some("u".into()),
            credential: Some("p".into()),
        };
        assert_eq!(uris_of(&a).len(), 2);
        assert!(has_turn_entry(&[a]));
    }

    #[test]
    fn first_turn_requires_credentials() {
        // turn: present but no creds → not selected.
        let no_creds = IceServer { urls: serde_json::json!("turn:127.0.0.1:3478"), username: None, credential: None };
        assert!(first_turn(&[no_creds]).is_none());
        let with_creds = IceServer {
            urls: serde_json::json!("turn:127.0.0.1:3478"),
            username: Some("nullseal".into()),
            credential: Some("secret".into()),
        };
        let (uri, u, c) = first_turn(&[with_creds]).unwrap();
        assert_eq!(uri, "turn:127.0.0.1:3478");
        assert_eq!(u, "nullseal");
        assert_eq!(c, "secret");
    }
}
