# CLI P2P Retry Flow

> Comprehensive documentation of the retry and resume mechanism in the NullSeal CLI, covering both **global** (server-signaled WebRTC) and **local** (mDNS direct) P2P modes.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        Global P2P Mode                           │
│                                                                  │
│  Sender CLI ─── Socket.IO ──→ NullSeal Server ←── Socket.IO ─── Receiver CLI │
│       │                                                   │      │
│       └────────── WebRTC DataChannel (direct) ────────────┘      │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                        Local P2P Mode                            │
│                                                                  │
│  Sender CLI ─── TCP signaling ──→ Receiver CLI                   │
│       │                                    │                     │
│       └────── WebRTC DataChannel (LAN) ────┘                     │
└──────────────────────────────────────────────────────────────────┘
```

---

## Constants

| Constant | Value | Location |
|----------|-------|----------|
| `MAX_RETRIES` | 3 | `commands/share.rs`, `commands/get.rs` |
| `BACKOFF_MS` | [1000, 2000, 4000] | both sender/receiver |
| `READY_TIMEOUT_SECS` | 10 | sender (waiting for `p2p:ready`) |
| `OFFER_TIMEOUT_SECS` | 10 | receiver (waiting for offer) |
| `RESUME_WAIT_MS` | 2000 | sender (waiting for resume frame) |
| `CHUNK_SIZE` | 16384 (16 KB) | `webrtc.rs` |
| Channel open timeout | 10s | both (WebRTC ICE connection) |

---

## Global P2P — Sender Flow (`share.rs::run_p2p`)

### Sequence Diagram

```
Sender                    Server                   Receiver
  │                         │                         │
  ├── create_p2p_session ──→│                         │
  │←── session_id ──────────│                         │
  │                         │                         │
  ├── Socket.IO connect ───→│                         │
  │←── p2p:joined ─────────│                         │
  │                         │                         │
  │     [WAIT for recipient to join]                  │
  │                         │                         │
  │←── p2p:ready ──────────│←── recipient joins ─────┤
  │                         │                         │
  ├── SenderPeer::new() ───→│                         │
  ├── send_offer ──────────→│──── forward offer ─────→│
  │                         │←── answer ─────────────┤
  │←── answer ─────────────│                         │
  │                         │                         │
  │    [ICE candidates exchanged via server]          │
  │                         │                         │
  │──── DataChannel open ────────────────────────────│
  │                         │                         │
  │←── resume { chunkIndex } ────────────────────────│
  │                         │                         │
  ├── verify frame ─────────────────────────────────→│
  ├── metadata frame ───────────────────────────────→│
  ├── chunk[start..N] ─────────────────────────────→│
  ├── end frame ────────────────────────────────────→│
  │                         │                         │
  ├── socket.done() ───────→│                         │
  └── disconnect ──────────→│                         │
```

### Retry Decision Points

The sender has **three** places where retry triggers:

1. **`p2p:ready` timeout** (recipient not joining/re-joining within 10s)
2. **DataChannel open timeout** (ICE/DTLS failure within 10s)
3. *(No transfer-level retry on sender — once DataChannel is open, `send_transfer_from` is synchronous)*

### Retry Logic (Pseudocode)

```rust
let mut attempt = 0;
loop {
    // Wait for p2p:ready (recipient available)
    let got_ready = wait_ready(attempt == 0 ? infinite : 10s);
    
    if !got_ready {
        attempt += 1;
        if attempt > MAX_RETRIES {
            if !prompt_manual_retry() { bail! }
            attempt = 0;
            socket.emit_join(session_id, "sender");
            continue;
        }
        sleep(BACKOFF_MS[attempt - 1]);
        socket.emit_join(session_id, "sender");
        continue;
    }
    
    // Create WebRTC peer, exchange SDP
    let mut sender = SenderPeer::new(...);
    socket.send_offer(...);
    // ... wait for answer + ICE ...
    
    // Wait for DataChannel open (10s timeout)
    let channel_open = timeout(10s, wait_channel_open());
    
    if !channel_open {
        attempt += 1;
        if attempt > MAX_RETRIES {
            if !prompt_manual_retry() { bail! }
            attempt = 0;
            socket.emit_join(session_id, "sender");
            continue;
        }
        sleep(BACKOFF_MS[attempt - 1]);
        socket.emit_join(session_id, "sender");
        continue;
    }
    
    // SUCCESS — reset counter, send data
    attempt = 0;
    let start_chunk = sender.wait_for_resume(2000ms);
    sender.send_verify(&proof);
    sender.send_transfer_from(..., start_chunk, ...);
    break; // done
}
```

### Key Behaviors

- **First attempt**: waits indefinitely for `p2p:ready` (recipient hasn't joined yet)
- **Retry attempts**: wait max 10s for `p2p:ready`
- **Re-join on retry**: `socket.emit_join()` tells server we're re-joining, triggers fresh signaling round
- **Reset on success**: `attempt = 0` after DataChannel opens (independent of prior failures)
- **Resume support**: sender waits 2s for resume frame; if none arrives, sends from chunk 0

---

## Global P2P — Receiver Flow (`get.rs::run_p2p`)

### Sequence Diagram

```
Receiver                  Server                   Sender
  │                         │                         │
  ├── verify password ─────→│                         │
  │←── OK ─────────────────│                         │
  │                         │                         │
  ├── Socket.IO connect ───→│                         │
  │←── p2p:joined ─────────│                         │
  │                         │                         │
  │     [WAIT for sender's offer]                     │
  │                         │                         │
  │←── offer (SDP) ────────│←── forward offer ──────┤
  │                         │                         │
  ├── ReceiverPeer::from_offer() ────────────────────│
  ├── send_answer ─────────→│──── forward answer ───→│
  │                         │                         │
  │    [ICE candidates exchanged]                     │
  │                         │                         │
  │──── DataChannel open ────────────────────────────│
  │                         │                         │
  ├── resume { chunkIndex } ────────────────────────→│
  │                         │                         │
  │←── verify frame ────────────────────────────────┤
  │←── metadata frame ─────────────────────────────┤
  │←── chunk[start..N] ────────────────────────────┤
  │←── end frame ──────────────────────────────────┤
  │                         │                         │
  └── disconnect ──────────→│                         │
```

### Retry Decision Points

The receiver has **three** places where retry triggers:

1. **Offer timeout** (sender's offer not arriving within 10s on retry attempts)
2. **DataChannel open timeout** (ICE/DTLS failure within 10s)
3. **Transfer interrupted** (DataChannel closes mid-transfer — error from `receive_transfer`)

### Retry Logic (Pseudocode)

```rust
let mut attempt = 0;
let mut last_chunk_index: i64 = -1;
let mut all_chunks: Vec<String> = Vec::new();

loop {
    // Wait for SDP offer from sender
    let offer = wait_offer(attempt == 0 ? infinite : 10s);
    
    if offer.is_none() {
        attempt += 1;
        if attempt > MAX_RETRIES {
            if !prompt_manual_retry() { bail! }
            attempt = 0;
            socket.emit_join(session_id, "recipient");
            continue;
        }
        sleep(BACKOFF_MS[attempt - 1]);
        socket.emit_join(session_id, "recipient");
        continue;
    }
    
    // Create WebRTC peer, exchange SDP
    let mut receiver = ReceiverPeer::from_offer(offer, ...);
    socket.send_answer(...);
    
    // Wait for DataChannel open (10s timeout)
    let channel_open = timeout(10s, wait_channel_open());
    
    if !channel_open {
        attempt += 1;
        if attempt > MAX_RETRIES {
            if !prompt_manual_retry() { bail! }
            attempt = 0;
            socket.emit_join(session_id, "recipient");
            continue;
        }
        sleep(BACKOFF_MS[attempt - 1]);
        socket.emit_join(session_id, "recipient");
        continue;
    }
    
    // SUCCESS — reset counter
    attempt = 0;
    
    // Send resume frame
    receiver.send_resume(last_chunk_index);
    
    // Receive transfer
    match receiver.receive_transfer(...) {
        Ok(transfer) => {
            // Combine prior + current chunks, decrypt, output
            break; // done
        }
        Err(e) => {
            // Save partial chunks for resume
            last_chunk_index += round_chunks.len() as i64;
            all_chunks.extend(round_chunks);
            
            attempt += 1;
            if attempt > MAX_RETRIES {
                if !prompt_manual_retry() { bail! }
                attempt = 0;
            }
            sleep(BACKOFF_MS[attempt - 1]);
            socket.emit_join(session_id, "recipient");
            continue;
        }
    }
}
```

### Key Behaviors

- **First attempt**: waits indefinitely for offer (sender hasn't connected yet)
- **Retry attempts**: wait max 10s for offer
- **Partial resume**: `last_chunk_index` tracks how many chunks received across all rounds
- **Resume frame**: tells sender to skip already-delivered chunks
- **Full payload reconstruction**: `all_chunks.concat()` + current round's data
- **Integrity check**: SHA-256 checksum verified after full decryption

---

## Local P2P Mode — Current State

### Sender (`share.rs::run_local`)

**No retry mechanism.** Single attempt:
1. Bind TCP signaling server
2. Broadcast via mDNS
3. Accept one receiver connection
4. WebRTC handshake (offer/answer via TCP)
5. Wait for DataChannel open
6. Send transfer
7. Done

### Receiver (`get.rs::run_local`)

**No retry mechanism.** Single attempt:
1. Discover sender via mDNS (30s timeout)
2. Connect to sender's TCP signaling server
3. Receive offer, create peer, send answer
4. Wait for DataChannel open
5. Receive transfer
6. Done

### Gap Analysis: Local Mode

| Feature | Global P2P | Local P2P | Gap? |
|---------|-----------|-----------|------|
| Auto-retry on ICE failure | ✓ (3 attempts) | ✗ | **Yes** |
| Backoff delays | ✓ [1s,2s,4s] | ✗ | **Yes** |
| Manual retry prompt | ✓ (Enter/Ctrl+C) | ✗ | **Yes** |
| Resume transfer | ✓ (chunk-index) | ✗ | **Yes** |
| DataChannel open timeout | ✓ (10s) | ✗ (waits forever) | **Yes** |
| Offer/ready timeout | ✓ (10s on retry) | N/A (TCP direct) | N/A |

---

## Manual Retry (`prompt_manual_retry`)

After 3 auto-retries are exhausted, the CLI prompts interactively:

```
⚠ All automatic retries exhausted.
Press Enter to retry or Ctrl+C to quit…
```

- **Interactive terminal**: waits for Enter → retries (resets `attempt = 0`)
- **Non-interactive** (piped stdin): returns `false` → bails with error
- After manual retry: re-joins the socket session to trigger a fresh signaling round

---

## Resume Protocol

### Sender Side (`SenderPeer::wait_for_resume`)

After DataChannel opens, sender waits up to 2000ms for a `resume` frame:
- Receives `{ type: "resume", chunkIndex: N }` → sends from chunk `N+1`
- Timeout (no frame) → sends from chunk 0
- Error/Done event → sends from chunk 0

### Receiver Side (`ReceiverPeer::send_resume`)

After DataChannel opens, receiver immediately sends:
- First connection: `{ type: "resume", chunkIndex: -1 }` (start from beginning)
- Retry after partial: `{ type: "resume", chunkIndex: last_received_index }`

### Chunk Indexing

```
Encrypted payload (e.g., 50000 bytes, CHUNK_SIZE = 16384):
  chunk[0] = payload[0..16384]       (16384 bytes)
  chunk[1] = payload[16384..32768]   (16384 bytes)  
  chunk[2] = payload[32768..49152]   (16384 bytes)
  chunk[3] = payload[49152..50000]   (848 bytes, last chunk)

Resume from chunkIndex=1 means: send chunk[2], chunk[3], then "end"
```

---

## Comparison with Browser (User) Flow

| Aspect | Browser | CLI |
|--------|---------|-----|
| Auto-retry count | 3 | 3 |
| Backoff schedule | [1s, 2s, 4s] | [1s, 2s, 4s] |
| Manual retry | Button in UI | Enter key prompt |
| Resume protocol | Same chunk-index | Same chunk-index |
| CHUNK_SIZE | 16384 | 16384 |
| Ready/Offer timeout | Implicit via timer | 10s explicit |
| Generation guard | Yes (prevents stale) | N/A (single session) |
| Timer cleanup | clearRetryTimer() | N/A (no timers — async/await) |
| Local mode retry | N/A (browser-only) | **Not implemented** |
| Transfer interrupt retry | Yes (3 auto) | Yes (3 auto) |

### Parity Assessment

The CLI **global P2P mode** has full parity with the browser flow:
- ✅ 3 auto-retries with [1s, 2s, 4s] backoff
- ✅ Manual retry after exhaustion
- ✅ Resumable transfer (chunk-index protocol)
- ✅ 10s timeouts for ICE connection
- ✅ Re-join on retry for fresh signaling
- ✅ Reset attempt counter on success

The CLI **local mode** has **no retry** — this is acceptable for LAN (direct TCP signaling + local WebRTC is highly reliable), but could be improved for robustness.

---

## Error Recovery Matrix

| Failure | When | Recovery | Attempt Cost |
|---------|------|----------|--------------|
| `p2p:ready` timeout | Recipient not joining | Re-join socket, wait again | +1 attempt |
| Offer timeout | Sender not offering | Re-join socket, wait again | +1 attempt |
| ICE timeout | NAT traversal failed | New peer, re-join | +1 attempt |
| Answer not received | Signaling failure | Fatal (bail) | — |
| Socket error | Server disconnect | Fatal (bail) | — |
| Transfer interrupted | DataChannel closed mid-transfer | Save chunks, re-join | +1 attempt |
| Wrong password | Bad proof | Fatal (bail) | — |
| Session expired | Server-side timeout | Fatal (bail) | — |

---

## Implementation Plan: Local Mode Retry

### Priority: Low

Local mode operates on LAN where connections are highly reliable. However, for completeness:

### Proposed Changes

1. **Sender (`run_local`)**: Add retry loop around DataChannel open with 3 attempts
2. **Receiver (`run_local`)**: Add retry loop around offer wait + DataChannel open
3. **Resume support**: Add `send_resume`/`wait_for_resume` in local mode
4. **TCP reconnection**: Allow receiver to reconnect if TCP signal drops

### Complexity: Medium

The TCP signaling in local mode is stateful and one-shot (accept single connection). Adding retry requires:
- Signal server accepting multiple connections (or reconnection)
- Receiver re-discovering via mDNS on retry
- State preservation across attempts (partial chunks)

### Recommendation

Defer local mode retry unless users report reliability issues on LAN. The global P2P mode (which goes through the server for signaling) already handles all retry scenarios correctly.

---

## Test Coverage

### Unit Tests (inline in source)

- `commands/share.rs`: 15+ tests covering validation, server mode, P2P flow
- `commands/get.rs`: 11+ tests covering URL parsing, server mode, P2P flow
- `webrtc.rs`: IP detection, LAN detection, `is_private_lan_ip`

### E2E Tests (`e2e/tests/cli-retry.integration.spec.ts`)

- Sender exits correctly when no receiver connects
- Normal P2P transfer succeeds (happy path, no retry needed)

### Suggested Additional E2E Tests

1. **Receiver disconnects mid-transfer, reconnects** → verify resume
2. **ICE failure simulation** → verify 3 retries then manual prompt
3. **Manual retry acceptance** → verify continued transfer after Enter
4. **Large file resume** → verify chunk-index correctness after reconnect
