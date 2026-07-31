//! TCP data transport for `share --sync --local` (task 062).
//!
//! LAN sync used to ride a WebRTC DataChannel, which needs UDP. On networks
//! where an endpoint agent blocks UDP (Zscaler and friends) ICE never leaves
//! `checking` and the run dies with `DataChannel open failed` — even with both
//! machines on the same subnet, where NAT traversal buys nothing in the first
//! place. So LAN sync moves its frames over a plain TCP socket instead.
//!
//! Nothing is lost by dropping DTLS: `sync_flow::Sealer` already AES-GCM-seals
//! every frame with the password-derived key **before** it reaches the
//! transport, so DTLS was a redundant second layer here.
//!
//! ## Framing — the thing a byte stream gets wrong
//!
//! A DataChannel is message-oriented: one `send_binary` arrives as exactly one
//! event. TCP has no message boundaries, so every sealed blob is length-prefixed:
//!
//! ```text
//! [len u32 BE][sealed bytes]
//! ```
//!
//! matching the `[tag u8][len u32 BE]` convention of `transfer::protocol`. Reads
//! go through `read_exact`, so a short read is reassembled rather than treated as
//! a frame, and two frames arriving in one segment decode as two frames. A bogus
//! length is rejected **before** the buffer is allocated, mirroring the
//! `MAX_FRAME_BYTES` guard in `transfer::protocol`.
//!
//! ## Authentication
//!
//! Any host on the LAN can open the data port, so the seal is the gate: a peer
//! without the password cannot produce a frame that unseals. The **first** unseal
//! failure is fatal — the wire poisons itself and the run aborts.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

use crate::crypto::StreamEncryptionMetadata;
use crate::transfer::protocol::{
    decode_message, encode_frame, Frame, FRAME_HEADER_LEN, MAX_FRAME_BYTES,
};

use super::sync_flow::{Sealer, Unsealer, Wire};

// ── Constants ─────────────────────────────────────────────────────────────────

/// `p2p:metadata.type` value announcing a LAN sync data port over signaling.
pub const ANNOUNCE_KIND: &str = "syncTcp";

/// First message on the data socket, so a stray LAN connection fails loudly
/// instead of being mistaken for the recipient.
const HANDSHAKE_MAGIC: &str = "nullseal-sync-tcp";
/// Data-transport version. Sync is unreleased and both ends ship together, so a
/// mismatch is a hard error rather than a negotiation.
const HANDSHAKE_VERSION: u64 = 1;

/// Length-prefix width, `u32` big-endian (the `transfer::protocol` convention).
const LEN_PREFIX_BYTES: usize = 4;

/// Sealing overhead on top of one encoded frame: `[frame index u64 BE]` plus the
/// AES-GCM tag.
const SEAL_OVERHEAD: usize = 8 + 16;

/// Hard upper bound on one length-prefixed message. Derived from the protocol's
/// own `MAX_FRAME_BYTES` guard so the two can never drift apart: anything larger
/// would be rejected by `decode_message` anyway, and we refuse to allocate for it.
pub const MAX_MESSAGE_BYTES: usize = MAX_FRAME_BYTES + FRAME_HEADER_LEN + SEAL_OVERHEAD;

// ── Signaling announcement (pure) ─────────────────────────────────────────────

/// The `p2p:metadata` payload the sender emits once its data listener is bound.
/// Signaling itself is unchanged — this rides the relay the two peers already use.
pub fn announce(host: &str, port: u16) -> Value {
    json!({
        "type": ANNOUNCE_KIND,
        "transferMode": "sync",
        "contentType": "sync",
        "host": host,
        "port": port,
    })
}

/// Is this relayed `p2p:metadata` a sync data-port announcement?
pub fn is_sync_announcement(payload: &Value) -> bool {
    payload["type"].as_str() == Some(ANNOUNCE_KIND)
}

/// Where the receiver should open the data connection.
///
/// The port always comes from the announcement. The host prefers the announced
/// address, but falls back to the address signaling is already running on — that
/// one is known-reachable, so a sender that announced something unusable still
/// works.
pub fn data_addr(signaling_addr: &str, payload: &Value) -> Result<String> {
    let port = payload["port"]
        .as_u64()
        .filter(|p| *p > 0 && *p <= u16::MAX as u64)
        .ok_or_else(|| anyhow!("The sender announced no usable sync data port."))?
        as u16;
    let host = payload["host"]
        .as_str()
        .filter(|h| h.parse::<IpAddr>().is_ok())
        .map(str::to_string)
        .unwrap_or_else(|| host_of(signaling_addr));
    Ok(join_host_port(&host, port))
}

/// Strip the `:port` from an `ip:port` (or bracketed IPv6) signaling address.
fn host_of(addr: &str) -> String {
    if let Some(end) = addr.rfind(']') {
        return addr[..=end].to_string();
    }
    match addr.rsplit_once(':') {
        Some((host, _)) => host.to_string(),
        None => addr.to_string(),
    }
}

/// `host:port`, bracketing a bare IPv6 literal.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

// ── Error text (pure, so the wording is testable) ─────────────────────────────

/// Shown when no peer opened the data connection in time. Names the one thing an
/// operator can act on — TCP reachability of the data port.
pub fn accept_timeout_error(port: u16, secs: u64) -> String {
    format!(
        "The recipient did not open the sync data connection on port {port} within {secs}s. \
         The two sides agreed over signaling, so the data port itself is being blocked — \
         check the local firewall or endpoint-protection agent for inbound TCP {port}."
    )
}

/// Shown when the receiver cannot reach the announced data port.
pub fn connect_error(addr: &str, cause: &str) -> String {
    format!(
        "Cannot reach the sender's sync data port at {addr}: {cause}. \
         Signaling succeeded, so the sender is up — check that TCP to {addr} is \
         permitted by the firewall or endpoint-protection agent on either host."
    )
}

/// Shown when the connection is accepted but the handshake never completes.
pub fn connect_timeout_error(addr: &str, secs: u64) -> String {
    format!(
        "No answer from the sync data port at {addr} within {secs}s — the connection \
         was not completed. Check the firewall or endpoint-protection agent on either host."
    )
}

/// The first sealed frame that does not decrypt means the peer does not hold the
/// password. It is fatal: there is no legitimate way to produce a bad frame.
pub fn wrong_password_error() -> String {
    "Wrong password — the peer's sealed frame could not be decrypted, so the sync was aborted."
        .to_string()
}

// ── Length-prefixed messages ──────────────────────────────────────────────────

/// Write one length-prefixed message. Prefix and payload go out in a single
/// `write_all` so a small control frame is never split across two segments for
/// no reason.
async fn write_message<W: AsyncWriteExt + Unpin>(w: &mut W, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_MESSAGE_BYTES {
        bail!(
            "refusing to send a {}-byte sync message (max {MAX_MESSAGE_BYTES})",
            payload.len()
        );
    }
    let mut out = Vec::with_capacity(LEN_PREFIX_BYTES + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    w.write_all(&out).await.context("cannot write to the sync data connection")?;
    w.flush().await.context("cannot flush the sync data connection")?;
    Ok(())
}

/// Read exactly one length-prefixed message.
///
/// `read_exact` is what makes this correct on a byte stream: a short read is
/// normal and gets reassembled, and only `len` bytes are consumed, so a second
/// message sharing the same segment stays intact for the next call.
async fn read_message<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; LEN_PREFIX_BYTES];
    r.read_exact(&mut len_buf)
        .await
        .context("the sync data connection closed before the transfer finished")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    // Guarded BEFORE the allocation: a bogus prefix must never make us reserve
    // gigabytes (same rule as `transfer::protocol`'s decode guard).
    if len > MAX_MESSAGE_BYTES {
        bail!("the peer announced a {len}-byte sync message (max {MAX_MESSAGE_BYTES}) — refusing it");
    }
    if len == 0 {
        bail!("the peer sent an empty sync message");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .await
        .context("the sync data connection closed mid-frame")?;
    Ok(buf)
}

// ── The wire ──────────────────────────────────────────────────────────────────

/// A [`Wire`] over a TCP socket: the same sealed frames the DataChannel carried,
/// length-prefixed so the byte stream keeps its message boundaries.
pub struct TcpWire {
    read: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
    sealer: Sealer,
    unsealer: Unsealer,
    /// Set on the first unseal failure — the run is over, and every later call
    /// fails with the same reason instead of reading more attacker-chosen bytes.
    poisoned: bool,
    peer: SocketAddr,
}

/// Never print the keys: only the peer and whether the wire is still usable.
impl std::fmt::Debug for TcpWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpWire")
            .field("peer", &self.peer)
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

impl TcpWire {
    /// The peer this wire is talking to (for the `--verbose` evidence line).
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Half-close so the peer sees EOF rather than a reset once we are done.
    pub async fn shutdown(&mut self) {
        let _ = self.write.shutdown().await;
    }
}

impl Wire for TcpWire {
    async fn send(&mut self, frame: &Frame) -> Result<()> {
        let sealed = self.sealer.seal(&encode_frame(frame)?)?;
        write_message(&mut self.write, &sealed).await
    }

    async fn recv(&mut self) -> Result<Frame> {
        if self.poisoned {
            bail!(wrong_password_error());
        }
        let sealed = read_message(&mut self.read).await?;
        let plaintext = match self.unsealer.unseal(&sealed) {
            Ok(p) => p,
            Err(_) => {
                self.poisoned = true;
                bail!(wrong_password_error());
            }
        };
        Ok(decode_message(&plaintext)?)
    }
}

// ── Establishing the connection ───────────────────────────────────────────────

/// Bind the sender's data listener on the same IP the relay already uses, so
/// `-a <ip>` and mDNS discovery keep working unchanged. Port 0 = ephemeral; the
/// caller announces whatever the OS handed out.
pub async fn bind_data_listener(ip: &str) -> Result<TcpListener> {
    let bind = join_host_port(ip, 0);
    TcpListener::bind(&bind)
        .await
        .with_context(|| format!("cannot bind the sync data listener on {bind}"))
}

/// The socket halves plus the peer's stream metadata, once the handshake passed.
type Handshaken = (BufReader<OwnedReadHalf>, OwnedWriteHalf, SocketAddr, StreamEncryptionMetadata);

/// Exchange stream-encryption metadata over one connection.
///
/// Both sides write their own metadata before reading the peer's — the messages
/// are small enough to fit the socket buffers, so this never deadlocks. Salt and
/// base IV are public parameters; the password never travels.
///
/// Takes the caller's already-derived metadata rather than a password on purpose:
/// key derivation is 250k PBKDF2 rounds, so a connection that turns out to be LAN
/// noise must not cost one (the accept loop would otherwise burn a derivation per
/// port scan).
async fn handshake(stream: TcpStream, our_meta: &StreamEncryptionMetadata) -> Result<Handshaken> {
    // Control frames are tiny and strictly ping-pong per file; Nagle would add a
    // round-trip delay to every one of them.
    let _ = stream.set_nodelay(true);
    let peer = stream.peer_addr().context("cannot read the sync peer address")?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let hello = serde_json::to_vec(&json!({
        "magic": HANDSHAKE_MAGIC,
        "version": HANDSHAKE_VERSION,
        "streamEncryptionMetadata": our_meta,
    }))?;
    write_message(&mut writer, &hello).await?;

    let peer_meta = parse_handshake(&read_message(&mut reader).await?)?;
    Ok((reader, writer, peer, peer_meta))
}

/// Assemble the wire once a handshake has passed. The second (and only other)
/// key derivation of the session happens here.
fn wire_from(handshaken: Handshaken, sealer: Sealer, password: &str) -> Result<TcpWire> {
    let (read, write, peer, peer_meta) = handshaken;
    Ok(TcpWire {
        read,
        write,
        sealer,
        unsealer: Unsealer::new(&peer_meta, password)?,
        poisoned: false,
        peer,
    })
}

/// Validate the peer's handshake message and extract its stream metadata. Pure,
/// so the rejection paths are unit-testable without a socket.
pub fn parse_handshake(bytes: &[u8]) -> Result<StreamEncryptionMetadata> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| anyhow!("the peer on the sync data port is not a NullSeal sync peer"))?;
    if value["magic"].as_str() != Some(HANDSHAKE_MAGIC) {
        bail!("the peer on the sync data port is not a NullSeal sync peer");
    }
    if value["version"].as_u64() != Some(HANDSHAKE_VERSION) {
        bail!(
            "sync data protocol version mismatch: the peer speaks v{}, this build speaks v{HANDSHAKE_VERSION}. Upgrade both sides.",
            value["version"].as_u64().unwrap_or(0)
        );
    }
    serde_json::from_value(value["streamEncryptionMetadata"].clone())
        .map_err(|e| anyhow!("the peer sent invalid sync encryption metadata: {e}"))
}

/// Sender side: accept **one** data connection, bounded by
/// [`crate::retry::SYNC_DATA_TIMEOUT_SECS`].
///
/// The listener is consumed and dropped on return, so any further connection is
/// refused for the rest of the session.
pub async fn accept_data(listener: TcpListener, password: &str) -> Result<TcpWire> {
    accept_data_within(
        listener,
        password,
        Duration::from_secs(crate::retry::SYNC_DATA_TIMEOUT_SECS),
    )
    .await
}

async fn accept_data_within(
    listener: TcpListener,
    password: &str,
    budget: Duration,
) -> Result<TcpWire> {
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    // Derived once, outside the loop: a rejected connection must cost no crypto,
    // and nothing sealed was ever emitted on one, so the sealer stays valid.
    let sealer = Sealer::new(password);
    let our_meta = sealer.metadata();
    super::log::event(&format!(
        "waiting up to {}s for the recipient's data connection on port {port}",
        budget.as_secs()
    ));
    let accepting = async {
        loop {
            let (stream, from) = listener
                .accept()
                .await
                .context("cannot accept on the sync data port")?;
            super::log::event(&format!("data connection accepted from {from}; exchanging keys"));
            match handshake(stream, &our_meta).await {
                Ok(handshaken) => return Ok::<Handshaken, anyhow::Error>(handshaken),
                Err(e) => {
                    // A LAN scanner or a stale process — drop it and keep
                    // listening, so noise cannot steal the recipient's slot.
                    super::log::event(&format!("ignoring {from} on the sync data port: {e}"));
                }
            }
        }
    };
    let handshaken = match tokio::time::timeout(budget, accepting).await {
        Ok(result) => result?,
        Err(_) => bail!(accept_timeout_error(port, budget.as_secs())),
    };
    wire_from(handshaken, sealer, password)
    // `listener` drops here: one data connection per session.
}

/// Receiver side: connect to the announced data port, bounded the same way.
pub async fn connect_data(addr: &str, password: &str) -> Result<TcpWire> {
    connect_data_within(
        addr,
        password,
        Duration::from_secs(crate::retry::SYNC_DATA_TIMEOUT_SECS),
    )
    .await
}

async fn connect_data_within(addr: &str, password: &str, budget: Duration) -> Result<TcpWire> {
    super::log::event(&format!("opening a TCP data connection to {addr}"));
    let stream = match tokio::time::timeout(budget, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => bail!(connect_error(addr, &e.to_string())),
        Err(_) => bail!(connect_timeout_error(addr, budget.as_secs())),
    };
    super::log::event("data connection open; exchanging keys");
    let sealer = Sealer::new(password);
    let handshaken = match tokio::time::timeout(budget, handshake(stream, &sealer.metadata())).await
    {
        Ok(result) => result?,
        Err(_) => bail!(connect_timeout_error(addr, budget.as_secs())),
    };
    wire_from(handshaken, sealer, password)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::protocol::{ControlFrame, TransferMode};

    // ── Announcement / addressing (pure) ─────────────────────────────────────

    #[test]
    fn the_announcement_is_recognisable_and_carries_the_port() {
        let ann = announce("192.168.1.20", 54321);
        assert!(is_sync_announcement(&ann));
        assert_eq!(ann["port"].as_u64(), Some(54321));
        assert_eq!(ann["transferMode"], "sync");
        // Anything else relayed on p2p:metadata must not be mistaken for it.
        assert!(!is_sync_announcement(&json!({"type": "metadata", "contentType": "file"})));
        assert!(!is_sync_announcement(&json!({})));
    }

    #[test]
    fn data_addr_prefers_the_announced_host_and_always_takes_the_port() {
        let ann = announce("192.168.1.20", 5000);
        assert_eq!(data_addr("192.168.1.20:7777", &ann).unwrap(), "192.168.1.20:5000");
        // A useless announced host falls back to the signaling host, which is
        // known-reachable — the port is still the announced one.
        let odd = json!({"type": ANNOUNCE_KIND, "host": "not-an-ip", "port": 5000});
        assert_eq!(data_addr("10.0.0.4:9999", &odd).unwrap(), "10.0.0.4:5000");
        let hostless = json!({"type": ANNOUNCE_KIND, "port": 5000});
        assert_eq!(data_addr("127.0.0.1:1234", &hostless).unwrap(), "127.0.0.1:5000");
    }

    #[test]
    fn data_addr_rejects_a_missing_or_impossible_port() {
        for bad in [json!({}), json!({"port": 0}), json!({"port": 70000}), json!({"port": "x"})] {
            assert!(data_addr("127.0.0.1:1", &bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn ipv6_hosts_stay_bracketed() {
        assert_eq!(join_host_port("fe80::1", 42), "[fe80::1]:42");
        assert_eq!(host_of("[fe80::1]:9000"), "[fe80::1]");
        assert_eq!(host_of("127.0.0.1:9000"), "127.0.0.1");
        assert_eq!(host_of("127.0.0.1"), "127.0.0.1");
    }

    // ── Handshake validation (pure) ──────────────────────────────────────────

    #[test]
    fn a_foreign_peer_is_rejected_by_the_handshake() {
        assert!(parse_handshake(b"GET / HTTP/1.1").is_err());
        assert!(parse_handshake(br#"{"magic":"something-else"}"#).is_err());
        let wrong_version = format!(
            r#"{{"magic":"{HANDSHAKE_MAGIC}","version":99,"streamEncryptionMetadata":{{}}}}"#
        );
        let err = parse_handshake(wrong_version.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("version mismatch"), "{err}");
    }

    // ── Framing over a real socket ───────────────────────────────────────────

    /// A connected localhost socket pair, split into "the reader under test" and
    /// "a raw writer we control byte by byte".
    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connecting = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        (connecting.await.unwrap(), server)
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[tokio::test]
    async fn a_message_split_across_reads_is_reassembled() {
        // The DataChannel→TCP hazard: one logical message arriving in pieces must
        // NOT be read as a short frame.
        let (mut client, server) = socket_pair().await;
        let mut server = BufReader::new(server);
        let payload = vec![0xAB; 40_000];
        let wire_bytes = framed(&payload);

        tokio::spawn(async move {
            // Deliberately split mid-length-prefix, then mid-payload.
            client.write_all(&wire_bytes[..2]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            client.write_all(&wire_bytes[2..9]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            client.write_all(&wire_bytes[9..20_000]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            client.write_all(&wire_bytes[20_000..]).await.unwrap();
            client.flush().await.unwrap();
        });

        assert_eq!(read_message(&mut server).await.unwrap(), payload);
    }

    #[tokio::test]
    async fn two_messages_in_one_segment_decode_as_two_messages() {
        // The mirror hazard: coalesced writes must not be read as one frame.
        let (mut client, server) = socket_pair().await;
        let mut server = BufReader::new(server);
        let mut both = framed(b"first frame");
        both.extend_from_slice(&framed(b"second frame"));
        client.write_all(&both).await.unwrap();
        client.flush().await.unwrap();

        assert_eq!(read_message(&mut server).await.unwrap(), b"first frame");
        assert_eq!(read_message(&mut server).await.unwrap(), b"second frame");
    }

    #[tokio::test]
    async fn an_oversized_length_is_rejected_before_anything_is_allocated() {
        let (mut client, server) = socket_pair().await;
        let mut server = BufReader::new(server);
        // 4 GiB announced, zero bytes ever sent: the guard must fire on the
        // prefix alone, not by trying to fill a 4 GiB buffer.
        client.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        client.flush().await.unwrap();

        let err = tokio::time::timeout(Duration::from_secs(5), read_message(&mut server))
            .await
            .expect("the guard must fire immediately, not block on a huge read")
            .expect_err("an oversized length must be refused");
        assert!(err.to_string().contains("refusing it"), "{err}");
    }

    #[tokio::test]
    async fn a_message_over_the_cap_is_refused_on_the_way_out_too() {
        let (mut client, _server) = socket_pair().await;
        let err = write_message(&mut client, &vec![0u8; MAX_MESSAGE_BYTES + 1])
            .await
            .expect_err("an oversized payload must not be written");
        assert!(err.to_string().contains("refusing to send"), "{err}");
    }

    #[tokio::test]
    async fn a_truncated_stream_is_a_clean_error_not_a_hang() {
        let (client, server) = socket_pair().await;
        let mut server = BufReader::new(server);
        drop(client);
        assert!(read_message(&mut server).await.is_err());
    }

    // ── The wire end to end (real sockets + real sealing) ────────────────────

    /// A connected `TcpWire` pair, established the way the CLI does it.
    async fn wire_pair(sender_pw: &str, receiver_pw: &str) -> (TcpWire, TcpWire) {
        let listener = bind_data_listener("127.0.0.1").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let pw = receiver_pw.to_string();
        let connecting = tokio::spawn(async move { connect_data(&addr, &pw).await });
        let accepted = accept_data(listener, sender_pw).await.unwrap();
        (accepted, connecting.await.unwrap().unwrap())
    }

    #[tokio::test]
    async fn frames_round_trip_in_both_directions_over_a_real_socket() {
        let (mut a, mut b) = wire_pair("tcp-wire-pass", "tcp-wire-pass").await;
        assert_eq!(a.peer_addr().ip().to_string(), "127.0.0.1");

        a.send(&Frame::Control(ControlFrame::Hello {
            proto_version: 1,
            mode: TransferMode::Sync,
        }))
        .await
        .unwrap();
        a.send(&Frame::Chunk(b"payload bytes".to_vec())).await.unwrap();

        assert!(matches!(
            b.recv().await.unwrap(),
            Frame::Control(ControlFrame::Hello { mode: TransferMode::Sync, .. })
        ));
        assert_eq!(b.recv().await.unwrap(), Frame::Chunk(b"payload bytes".to_vec()));

        // …and back the other way, proving each direction has its own keyed stream.
        b.send(&Frame::Control(ControlFrame::FileOk { path: "a.txt".into() })).await.unwrap();
        assert_eq!(
            a.recv().await.unwrap(),
            Frame::Control(ControlFrame::FileOk { path: "a.txt".into() })
        );
    }

    #[tokio::test]
    async fn a_multi_megabyte_payload_survives_the_byte_stream_intact() {
        // Small frames hide framing bugs; megabytes of chunks do not. This is the
        // shape a real file takes: many STREAM_CHUNK_SIZE chunks back to back.
        let (mut a, mut b) = wire_pair("tcp-bulk-pass", "tcp-bulk-pass").await;
        let chunk_size = crate::crypto::STREAM_CHUNK_SIZE;
        let total = 3 * 1024 * 1024;
        let chunks = total / chunk_size;

        let sending = tokio::spawn(async move {
            for i in 0..chunks {
                let body = vec![(i % 251) as u8; chunk_size];
                a.send(&Frame::Chunk(body)).await.unwrap();
            }
            a
        });

        let mut received = 0usize;
        for i in 0..chunks {
            match b.recv().await.unwrap() {
                Frame::Chunk(body) => {
                    assert_eq!(body.len(), chunk_size, "chunk {i} lost its boundary");
                    assert!(
                        body.iter().all(|byte| *byte == (i % 251) as u8),
                        "chunk {i} is corrupt — frames were mis-aligned"
                    );
                    received += body.len();
                }
                other => panic!("expected a chunk, got {other:?}"),
            }
        }
        assert_eq!(received, total);
        sending.await.unwrap();
    }

    #[tokio::test]
    async fn the_first_unseal_failure_is_fatal() {
        // Nothing on the LAN can produce a frame that unseals without the
        // password, so one bad frame ends the run — and stays ended.
        let (mut a, mut b) = wire_pair("the-real-password", "a-different-password").await;
        a.send(&Frame::Control(ControlFrame::Hello {
            proto_version: 1,
            mode: TransferMode::Sync,
        }))
        .await
        .unwrap();

        let err = b.recv().await.expect_err("a wrong password must not decode");
        assert_eq!(err.to_string(), wrong_password_error());
        // Poisoned: a second read fails without touching the socket again.
        let err = b.recv().await.expect_err("the wire stays dead");
        assert_eq!(err.to_string(), wrong_password_error());
    }

    // ── Bounded establishment ────────────────────────────────────────────────

    #[tokio::test]
    async fn accept_times_out_instead_of_waiting_forever() {
        let listener = bind_data_listener("127.0.0.1").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let err = accept_data_within(listener, "pw", Duration::from_millis(150))
            .await
            .expect_err("an absent recipient must time out, not hang");
        assert_eq!(err.to_string(), accept_timeout_error(port, 0));
        assert!(err.to_string().contains(&port.to_string()));
    }

    #[tokio::test]
    async fn connect_reports_an_unreachable_data_port() {
        // Bind then drop, so the port is (almost certainly) closed.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        let err = connect_data_within(&addr, "pw", Duration::from_secs(5))
            .await
            .expect_err("a closed port must be reported, not retried forever");
        assert!(err.to_string().contains(&addr), "{err}");
        assert!(err.to_string().contains("firewall"), "{err}");
    }

    /// Rejecting noise must also be *cheap*: the accept loop derives its key once
    /// up front, so a port scan costs no PBKDF2 and cannot eat the accept budget.
    #[tokio::test]
    async fn stray_lan_noise_does_not_steal_the_recipients_slot() {
        let listener = bind_data_listener("127.0.0.1").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let noise_addr = addr.clone();
        tokio::spawn(async move {
            // A port scanner: connects, says something that is not our handshake.
            if let Ok(mut junk) = TcpStream::connect(&noise_addr).await {
                let _ = junk.write_all(&framed(b"GET / HTTP/1.1")).await;
                let _ = junk.flush().await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let real = tokio::spawn(async move { connect_data(&addr, "slot-pass").await });
        let mut server = accept_data(listener, "slot-pass")
            .await
            .expect("the real recipient must still get through");
        let mut client = real.await.unwrap().unwrap();

        server.send(&Frame::Chunk(b"ok".to_vec())).await.unwrap();
        assert_eq!(client.recv().await.unwrap(), Frame::Chunk(b"ok".to_vec()));
    }

    #[tokio::test]
    async fn a_second_connection_is_refused_once_the_session_has_its_peer() {
        let listener = bind_data_listener("127.0.0.1").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let first_addr = addr.clone();
        let first = tokio::spawn(async move { connect_data(&first_addr, "one-peer").await });
        let _server = accept_data(listener, "one-peer").await.unwrap();
        let _first = first.await.unwrap().unwrap();

        // The listener is gone with `accept_data`, so nobody else gets in.
        let second = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await;
        assert!(
            matches!(second, Ok(Err(_))),
            "a second data connection must be refused, got {second:?}"
        );
    }
}
