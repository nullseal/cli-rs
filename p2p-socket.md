# P2P Transfer — Socket.IO & WebRTC Protocol

Complete reference for all stages of a nullseal P2P file transfer, covering both **online mode** (Socket.IO signaling server) and **local mode** (direct TCP signaling).

---

## Architecture Overview

```
┌────────┐       Socket.IO (/p2p)       ┌────────┐
│ Sender │ ◄────────────────────────────► │ Server │
└───┬────┘                                └───┬────┘
    │                                         │
    │  SDP offer/answer + ICE candidates      │
    │ ◄───────────────────────────────────────►│
    │                                         │
┌───┴────┐       Socket.IO (/p2p)       ┌────┴───┐
│  Peer  │ ◄────────────────────────────► │Recipnt │
└───┬────┘                                └───┬────┘
    │                                         │
    │       WebRTC DataChannel (SCTP/UDP)     │
    │ ◄──────────────────────────────────────►│
    └─────────────────────────────────────────┘
          Encrypted file transfer here
```

**Two signaling modes:**
1. **Online** — Socket.IO server at `/p2p` namespace relays SDP + ICE
2. **Local** — Direct TCP connection, newline-delimited JSON

Both modes use **WebRTC DataChannel** (`"nullseal-transfer"`, ordered, reliable) for the actual encrypted data transfer.

---

## 1. Socket.IO Transport Layer

### Connection

| Parameter | Value |
|-----------|-------|
| Protocol | Engine.IO v4 over WebSocket |
| URL | `ws(s)://<server>/socket.io/?EIO=4&transport=websocket` |
| Namespace | `/p2p` |
| Reconnection | Disabled (manual reconnect on failure) |

### Engine.IO Handshake

```
Server → Client:  0{"sid":"...","pingInterval":25000,"pingTimeout":20000,...}
Client → Server:  40/p2p,              (connect to /p2p namespace)
Server → Client:  40/p2p,{"sid":"..."}  (namespace connect ack)
```

### Keepalive

- Server sends `2` (ping) every `pingInterval` ms (25s)
- Client replies `3` (pong)
- If no server ping within `pingInterval + 5000ms` → connection considered dead

### Event Encoding

All events are encoded as: `42/p2p,["<eventName>", <payload>]`

Example: `42/p2p,["p2p:join",{"sessionId":"abc123","role":"sender"}]`

### Disconnect

- Client sends `41/p2p,` to leave namespace
- Server sending `41/p2p` means server kicked the client

---

## 2. Socket.IO Events Reference

| Event | Direction | Payload | Purpose |
|-------|-----------|---------|---------|
| `p2p:join` | Client → Server | `{ sessionId, role }` | Join the signaling room |
| `p2p:joined` | Server → Client | `()` | Confirm room join successful |
| `p2p:ready` | Server → Client | `()` | Other peer is in the room |
| `p2p:offer` | Client → Server → Client | `{ sdp: { type, sdp } }` | Relay SDP offer |
| `p2p:answer` | Client → Server → Client | `{ sdp: { type, sdp } }` | Relay SDP answer |
| `p2p:ice` | Client → Server → Client | `{ candidate: { candidate, ... } }` | Relay ICE candidate |
| `p2p:done` | Client → Server | `{}` | Transfer complete, cleanup session |
| `p2p:error` | Server → Client | `{ code: string }` | Error (e.g. `session_unavailable`) |

### Role values
- `"sender"` — the party sharing content
- `"recipient"` — the party receiving content

---

## 3. Online Mode — Sender Flow

### Pre-signaling (HTTP)

| Step | Action | Detail |
|------|--------|--------|
| 1 | **Encrypt** | `encrypt_bytes(plaintext, password)` → AES-256-GCM + PBKDF2 |
| 2 | **Derive proof** | `proof = sha256_hex(password)` |
| 3 | **Create session** | `POST /p2p` with `{ proof }` → `{ session_id, share_url }` |
| 4 | **Fetch ICE servers** | `GET /ice-servers` → STUN/TURN credentials |

### Signaling (Socket.IO)

| Step | Action | Detail |
|------|--------|--------|
| 5 | **Connect** | `P2PSocket::connect(base, session_id, "sender")` |
| 6 | **Emit join** | `p2p:join { sessionId, role: "sender" }` |
| 7 | **Wait `p2p:joined`** | Server confirms room entry |
| 8 | **Wait `p2p:ready`** | Recipient has joined the room |

### WebRTC Establishment

| Step | Action | Detail |
|------|--------|--------|
| 9 | **Create SenderPeer** | `SenderPeer::new(ice_servers)` — creates str0m `Rtc`, adds DataChannel `"nullseal-transfer"`, generates SDP offer |
| 10 | **Send offer** | `socket.send_offer(sdp)` → `p2p:offer` |
| 11 | **Receive answer** | Listen for `p2p:answer` → `sender.handle_answer(sdp)` |
| 12 | **Exchange ICE** | Relay `p2p:ice` candidates in both directions during connection |
| 13 | **Channel open** | DataChannel `"nullseal-transfer"` opens (10s timeout) |

### Data Transfer

| Step | Action | Detail |
|------|--------|--------|
| 14 | **Wait resume** | Wait up to 5s for receiver's `{ type: "resume", chunkIndex }` frame |
| 15 | **Send verify** | `{ type: "verify", proof: "<sha256>" }` |
| 16 | **Send metadata** | `{ type: "metadata", contentType, encryptionMetadata, fileMetadata, contentChecksum, totalSize, resumeFromChunk }` |
| 17 | **Send chunks** | `{ type: "chunk", data: "<utf8_slice>" }` × N (16 KB each) |
| 18 | **Send end** | `{ type: "end" }` |

### Completion

| Step | Action | Detail |
|------|--------|--------|
| 19 | **Flush** | `sender.close_and_flush()` — awaits all frames through mpsc channel |
| 20 | **Wait closed** | `sender.wait_closed()` — event loop drains SCTP + 3s grace |
| 21 | **Signal done** | `socket.done()` → `p2p:done` |
| 22 | **Disconnect** | `socket.disconnect()` → `41/p2p,` |

---

## 4. Online Mode — Receiver Flow

### Pre-signaling (HTTP)

| Step | Action | Detail |
|------|--------|--------|
| 1 | **Check session** | `GET /p2p/:id` → verify session exists and not expired |
| 2 | **Verify password** | `POST /p2p/:id/verify` with `{ proof: sha256_hex(password) }` |
| 3 | **Fetch ICE servers** | `GET /ice-servers` → STUN/TURN credentials |

### Signaling (Socket.IO)

| Step | Action | Detail |
|------|--------|--------|
| 4 | **Connect** | `P2PSocket::connect(base, session_id, "recipient")` |
| 5 | **Emit join** | `p2p:join { sessionId, role: "recipient" }` |
| 6 | **Wait `p2p:joined`** | Server confirms room entry |
| 7 | **Wait for offer** | Listen for `p2p:offer` (sender's SDP offer) |

### WebRTC Establishment

| Step | Action | Detail |
|------|--------|--------|
| 8 | **Create ReceiverPeer** | `ReceiverPeer::from_offer(offer, ice_servers)` — parses offer SDP, generates answer |
| 9 | **Send answer** | `socket.send_answer(sdp)` → `p2p:answer` |
| 10 | **Exchange ICE** | Relay `p2p:ice` candidates in both directions |
| 11 | **Channel open** | DataChannel opens (10s timeout) |

### Data Transfer

| Step | Action | Detail |
|------|--------|--------|
| 12 | **Send resume** | `receiver.send_resume(last_chunk_index)` — sends 3× for reliability |
| 13 | **Receive verify** | Validate `proof` matches expected → reject if wrong password |
| 14 | **Receive metadata** | Parse encryption params, total size, resume point |
| 15 | **Receive chunks** | Accumulate `chunk.data` strings, update progress |
| 16 | **Receive end** | All data received |

### Post-transfer

| Step | Action | Detail |
|------|--------|--------|
| 17 | **Reconstruct** | Concatenate all chunks (including from prior retry rounds) |
| 18 | **Decrypt** | `decrypt_bytes(payload, encryption_metadata, password)` |
| 19 | **Verify integrity** | `sha256_bytes(decrypted) == content_checksum` |
| 20 | **Output** | Save file to disk or print text to stdout |
| 21 | **Cleanup** | `receiver.close()` → `socket.disconnect()` |

---

## 5. DataChannel Frame Protocol

All frames are JSON strings sent over the ordered, reliable `"nullseal-transfer"` DataChannel.

### Frame Types

```
Sender → Receiver:  { "type": "verify",   "proof": "<sha256_hex(password)>" }
Sender → Receiver:  { "type": "metadata", ... }
Sender → Receiver:  { "type": "chunk",    "data": "<utf8_slice>" }  × N
Sender → Receiver:  { "type": "end" }
Receiver → Sender:  { "type": "resume",   "chunkIndex": <int> }
```

### Metadata Frame Fields

| Field | Type | Description |
|-------|------|-------------|
| `contentType` | `"text" \| "password" \| "file"` | Type of shared content |
| `encryptionMetadata` | `object` | `{ algorithm, kdf, iterations, salt, iv }` |
| `fileMetadata` | `object \| null` | `{ filename, size, mimeType, extension }` |
| `contentChecksum` | `string` | SHA-256 hex of the **plaintext** (integrity check) |
| `totalSize` | `number` | Total encrypted payload size in bytes |
| `resumeFromChunk` | `number` | Starting chunk index (0 if fresh, >0 if resuming) |

### Encryption Metadata

| Field | Value |
|-------|-------|
| `algorithm` | `"aes-256-gcm"` |
| `kdf` | `"pbkdf2"` |
| `iterations` | `100000` |
| `salt` | Base64 string |
| `iv` | Base64 string |

### Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `CHUNK_SIZE` | `16 * 1024` (16 KB) | Max bytes per chunk frame |
| `CMD_CHANNEL_CAPACITY` | `4` | Sender → event loop mpsc channel bound |
| `MAX_PENDING` | `24` | Event loop local SCTP write buffer |
| `MAX_DRAIN_PER_CYCLE` | `64` | Max frames written to SCTP per poll cycle |

### Backpressure Pipeline

```
send_frame().await  ──►  mpsc(4)  ──►  pending_sends(24)  ──►  str0m SCTP  ──►  UDP
      │                      │                │                      │
      │                      │                │                      │
   blocks if              blocks if        stops reading         kernel buffer
   channel full           full (4)         cmd_rx when full
```

Max sender-ahead: `(4 + 24) × 16 KB = 448 KB`

---

## 6. Retry & Resume Mechanism

### Retry Policy

| Parameter | Value |
|-----------|-------|
| Max auto-retries | 3 |
| Backoff delays | [1s, 2s, 4s] |
| Peer timeout (ready/offer) | 10s (first attempt: indefinite) |
| Channel open timeout | 10s |
| Resume wait timeout | 5s |

### Retry Triggers

| Event | Action |
|-------|--------|
| `p2p:ready` not received within 10s | Retry (reconnect socket if dead) |
| SDP offer not received within 10s | Retry (reconnect socket if dead) |
| DataChannel open timeout | Retry |
| ICE Disconnected (network switch) | Event loop exits → transfer error → retry |
| Transfer interrupted (SCTP error) | Retry with resume |
| All 3 auto-retries exhausted | Prompt manual retry or abort |

### Socket Reconnection

```
if !socket.is_alive() {
    (socket, events) = P2PSocket::connect(base, session_id, role);
    wait for p2p:joined;
} else {
    socket.emit_join(session_id, role);  // re-enter signaling room
}
// Drain stale offer/answer/ice events before new round
```

### Resume Protocol

**Receiver side:**
1. On DataChannel open → send `{ type: "resume", chunkIndex: last_received }` 3× (redundancy)
2. `chunkIndex = -1` means fresh start (no prior data)
3. `chunkIndex = N` means chunks 0..N are already received

**Sender side:**
1. Wait up to 5s for resume frame after channel open
2. If no resume arrives → start from chunk 0
3. Include `resumeFromChunk` in metadata so receiver knows the starting point
4. Skip already-sent chunks: `chunks.iter().skip(start_chunk)`

**Receiver validation:**
- If `sender's resumeFromChunk < receiver's expected_start` → sender restarted
- Discard all accumulated chunks and reset `last_chunk_index`

### State Across Retries

| State | Preserved across retries? |
|-------|--------------------------|
| Encrypted payload | Yes (computed once before retry loop) |
| Socket connection | Recreated if dead |
| SenderPeer / ReceiverPeer | New instance each attempt |
| ICE candidates | Fresh each attempt (stale ones drained) |
| Received chunks (receiver) | Yes — accumulated in `all_chunks: Vec<String>` |
| `last_chunk_index` (receiver) | Yes — incremented by chunks received each round |

---

## 7. Local Mode — Sender Flow

No Socket.IO server. Signaling via direct TCP.

| Step | Action | Detail |
|------|--------|--------|
| 1 | **Encrypt** | Same as online: AES-256-GCM + PBKDF2 |
| 2 | **Derive proof** | `proof = sha256_hex(password)` |
| 3 | **Bind TCP** | `SignalServer::bind_to(local_ip)` — ephemeral port on LAN interface |
| 4 | **Display address** | Print `192.168.x.x:PORT` for manual entry |
| 5 | **Broadcast mDNS** | `broadcast_addr(ip, port)` for auto-discovery |
| 6 | **Accept connection** | `signal_server.accept()` → `SignalChannel` (one client only) |
| 7 | **Create SenderPeer** | `SenderPeer::new([], Some(bind_ip))` — no TURN, host candidates only |
| 8 | **Send offer via TCP** | `signal.send_offer(sdp)` — newline-delimited JSON |
| 9 | **Receive answer via TCP** | `signal.recv_or_bail()` → `sender.handle_answer(answer)` |
| 10 | **Channel open** | Wait 10s for DataChannel to open |
| 11 | **Send verify** | `{ type: "verify", proof }` |
| 12 | **Send transfer** | metadata + chunks + end (same as online) |
| 13 | **Flush + close** | `close_and_flush()` → `wait_closed()` |

### Local TCP Signaling Protocol

```
Sender → Receiver:  {"type":"offer","sdp":{"type":"offer","sdp":"v=0\r\n..."}}  \n
Receiver → Sender:  {"type":"answer","sdp":{"type":"answer","sdp":"v=0\r\n..."}}  \n
```

- Transport: TCP, `\n`-delimited JSON
- No ICE candidate exchange needed (LAN host candidates embedded in SDP suffice)
- Single-shot connection (no retry loop — LAN assumed reliable)

---

## 8. Local Mode — Receiver Flow

| Step | Action | Detail |
|------|--------|--------|
| 1 | **Resolve address** | Explicit IP or mDNS discovery (30s timeout) |
| 2 | **Connect TCP** | `SignalClient::connect(addr)` |
| 3 | **Receive offer** | `signal.recv_or_bail()` → SDP offer |
| 4 | **Create ReceiverPeer** | `ReceiverPeer::from_offer(offer, [], Some(bind_ip))` |
| 5 | **Send answer via TCP** | `signal.send_answer(answer_sdp)` |
| 6 | **Channel open** | Wait 10s |
| 7 | **Receive transfer** | verify + metadata + chunks + end |
| 8 | **Decrypt** | `decrypt_bytes(payload, enc_meta, password)` |
| 9 | **Verify checksum** | `sha256_bytes(decrypted) == content_checksum` |
| 10 | **Output** | Save file or print text |

---

## 9. Key Differences: Online vs Local

| Aspect | Online | Local |
|--------|--------|-------|
| Signaling transport | Socket.IO WebSocket | Direct TCP |
| ICE servers | STUN + TURN | None (host candidates only) |
| ICE candidate exchange | Via `p2p:ice` events | Not needed |
| Session management | Server creates/tracks session | No server involved |
| Password verification | Server-side `POST /p2p/:id/verify` | DataChannel `verify` frame only |
| Retry/resume | Full retry loop with backoff | Single-shot (no retry) |
| Discovery | URL shared manually | mDNS auto-discovery on LAN |
| Resume support | Yes (multi-round accumulation) | No |
| NAT traversal | STUN/TURN | Not needed (same LAN) |

---

## 10. Event Loop Internals

The `event_loop::run()` function is the core of the WebRTC layer, driving str0m's sans-I/O state machine.

### Inputs
- **UDP socket** — raw network I/O
- **`cmd_rx`** — commands from peer layer (SendData, Close, AddIceCandidate, ApplyAnswer)
- **`event_tx`** — events back to peer layer (ChannelOpen, Message, Done, Error)

### Processing Loop

```
loop {
    1. Drain pending_sends → SCTP (up to MAX_DRAIN_PER_CYCLE)
    2. If closing && pending_sends empty → 3s grace period → return
    3. rtc.poll_output() →
       - Timeout → select { recv UDP, recv cmd, sleep(deadline) }
       - Transmit → send UDP packet
       - Event → dispatch (ChannelOpen, ChannelData, ChannelClose, IceDisconnected)
       - Error → emit Error event, return
}
```

### Critical Events

| str0m Event | Handler Action |
|-------------|---------------|
| `IceConnectionState::Disconnected` | Emit `LoopEvent::Error`, return immediately |
| `ChannelOpen(id, label)` | Set `channel_open = true`, emit `LoopEvent::ChannelOpen` |
| `ChannelData(data)` | UTF-8 decode → emit `LoopEvent::Message` |
| `ChannelClose(_)` | Emit `LoopEvent::Done`, return |

### Close Handling

When `LoopCmd::Close` arrives:
1. Drain all remaining `LoopCmd::SendData` from `cmd_rx` into `pending_sends`
2. Set `closing = true` (stop reading new commands)
3. Continue loop: flush `pending_sends` → SCTP → UDP
4. After all pending data flushed, wait 3s grace period for final SCTP ACKs
5. Return (task exits, `wait_closed()` resolves)

---

## 11. Sequence Diagrams

### Online Mode — Happy Path

```
Sender                    Server                   Receiver
  │                         │                         │
  │── POST /p2p ───────────►│                         │
  │◄── { session_id } ──────│                         │
  │                         │                         │
  │── WS connect ──────────►│                         │
  │── p2p:join(sender) ────►│                         │
  │◄── p2p:joined ──────────│                         │
  │                         │                         │
  │                         │◄── WS connect ──────────│
  │                         │◄── p2p:join(recipient) ─│
  │                         │──► p2p:joined ──────────│
  │                         │                         │
  │◄── p2p:ready ───────────│──► p2p:ready ──────────►│
  │                         │                         │
  │── p2p:offer ───────────►│──► p2p:offer ──────────►│
  │                         │                         │
  │                         │◄── p2p:answer ──────────│
  │◄── p2p:answer ──────────│                         │
  │                         │                         │
  │◄─── p2p:ice ───────────►│◄──── p2p:ice ─────────►│
  │         (bidirectional ICE candidate exchange)     │
  │                         │                         │
  ╞═══════ DataChannel "nullseal-transfer" opens ═════╡
  │                         │                         │
  │◄──────────── { resume, chunkIndex: -1 } ─────────│  (×3)
  │                         │                         │
  │──────────── { verify, proof } ───────────────────►│
  │──────────── { metadata, ... } ───────────────────►│
  │──────────── { chunk, data } ─────────────────────►│  (×N)
  │──────────── { end } ─────────────────────────────►│
  │                         │                         │
  │── p2p:done ────────────►│                         │
  │── disconnect ──────────►│                         │
  │                         │                         │
```

### Online Mode — Retry with Resume

```
Sender                    Server                   Receiver
  │                         │                         │
  ╞══════ DataChannel opens (round 1) ════════════════╡
  │◄──────── { resume, chunkIndex: -1 } ─────────────│
  │────── { verify } ───────────────────────────────►│
  │────── { metadata, resumeFromChunk: 0 } ─────────►│
  │────── { chunk[0] } ────────────────────────────►│
  │────── { chunk[1] } ────────────────────────────►│
  │────── { chunk[2] } ────────────────────────────►│
  ╞══════ ICE Disconnected (network switch) ══════════╡
  │                         │                         │
  │  [1s backoff]           │  [saves last_chunk=2]   │
  │                         │                         │
  │── reconnect socket ────►│                         │
  │── p2p:join(sender) ────►│                         │
  │◄── p2p:ready ───────────│                         │
  │                         │                         │
  ╞══════ DataChannel opens (round 2) ════════════════╡
  │◄──────── { resume, chunkIndex: 2 } ──────────────│
  │────── { verify } ───────────────────────────────►│
  │────── { metadata, resumeFromChunk: 3 } ─────────►│
  │────── { chunk[3] } ────────────────────────────►│
  │────── { chunk[4] } ────────────────────────────►│
  │────── { end } ─────────────────────────────────►│
  │                         │                         │
  │  Receiver: concat(chunk[0..2] + chunk[3..4])      │
  │            decrypt → verify checksum → save       │
```

### Local Mode

```
Sender                              Receiver
  │                                     │
  │── TCP listen (LAN IP:port) ─────────│
  │── mDNS broadcast ──────────────────►│  (auto-discovery)
  │                                     │
  │◄─────── TCP connect ───────────────│
  │                                     │
  │── {"type":"offer","sdp":...} ──────►│
  │◄── {"type":"answer","sdp":...} ─────│
  │                                     │
  ╞══════ DataChannel opens ════════════╡
  │                                     │
  │── { verify, proof } ───────────────►│
  │── { metadata, ... } ───────────────►│
  │── { chunk, data } ────────────────►│  (×N)
  │── { end } ─────────────────────────►│
  │                                     │
```
