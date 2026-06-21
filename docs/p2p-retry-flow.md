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

All retry constants are centralized in `src/retry.rs`:

| Constant | Value | Location |
|----------|-------|----------|
| `DEFAULT.max_retries` | 3 | `retry.rs` |
| `DEFAULT.backoff_ms` | [1000, 2000, 4000] | `retry.rs` |
| `PEER_TIMEOUT_SECS` | 10 | `retry.rs` (sender: p2p:ready, receiver: offer) |
| `CHANNEL_TIMEOUT_SECS` | 10 | `retry.rs` (WebRTC ICE connection) |
| `RESUME_WAIT_MS` | 5000 | `retry.rs` (sender waits for resume frame) |
| `CHUNK_SIZE` | 16384 (16 KB) | `webrtc/mod.rs` |

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

The sender has **four** places where retry triggers:

1. **`p2p:ready` timeout** (recipient not joining/re-joining within 10s)
2. **DataChannel open timeout** (ICE/DTLS failure within 10s)
3. **Transfer failure** (`send_transfer_from` returns error — event loop closed, SCTP failure)
4. **Stale signaling flush** — before each new SDP exchange, stale `answer`/`ice` events from previous rounds are drained

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
    let start_chunk = sender.wait_for_resume(5000ms);
    sender.send_verify(&proof);
    let result = sender.send_transfer_from(..., start_chunk, ...).await;
    
    if result.is_err() {
        // Transfer interrupted — retry
        sender.close();
        sender.wait_closed();
        attempt += 1;
        // Same retry/prompt logic as above
        socket.emit_join(session_id, "sender");
        continue;
    }
    break; // done
}
```

### Key Behaviors

- **First attempt**: waits indefinitely for `p2p:ready` (recipient hasn't joined yet)
- **Retry attempts**: wait max 10s for `p2p:ready`
- **Re-join on retry**: `socket.emit_join()` tells server we're re-joining, triggers fresh signaling round
- **Stale event drain**: before creating a new SenderPeer, stale `answer`/`ice` events are flushed from channels to prevent feeding old SDP to the new peer
- **Reset on success**: `attempt = 0` after DataChannel opens (independent of prior failures)
- **Resume support**: sender waits 5s for resume frame; receiver sends it 3× for redundancy; if none arrives, sends from chunk 0
- **Transfer retry**: if `send_transfer_from` fails mid-transfer, the sender retries with backoff (recipient will send resume frame on reconnect)

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

**No retry mechanism.** Single attempt with timeout:
1. Bind TCP signaling server
2. Broadcast via mDNS
3. Accept one receiver connection
4. WebRTC handshake (offer/answer via TCP)
5. Wait for DataChannel open **(10s timeout)**
6. Send transfer
7. Done

### Receiver (`get.rs::run_local`)

**No retry mechanism.** Single attempt with timeout:
1. Discover sender via mDNS (30s timeout)
2. Connect to sender's TCP signaling server
3. Receive offer, create peer, send answer
4. Wait for DataChannel open **(10s timeout)**
5. Receive transfer
6. Done

### Gap Analysis: Local Mode

| Feature | Global P2P | Local P2P | Gap? |
|---------|-----------|-----------|------|
| Auto-retry on ICE failure | ✓ (3 attempts) | ✗ | **Yes** |
| Backoff delays | ✓ [1s,2s,4s] | ✗ | **Yes** |
| Manual retry prompt | ✓ (Enter/Ctrl+C) | ✗ | **Yes** |
| Resume transfer | ✓ (chunk-index) | ✗ | **Yes** |
| DataChannel open timeout | ✓ (10s) | ✓ (10s) | No |
| Offer/ready timeout | ✓ (10s on retry) | N/A (TCP direct) | N/A |

---

## Manual Retry (`retry::prompt_manual`)

After 3 auto-retries are exhausted, the CLI prompts interactively (from `src/retry.rs`):

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

After DataChannel opens, sender waits up to **5000ms** for a `resume` frame:
- Receives `{ type: "resume", chunkIndex: N }` → sends from chunk `N+1`
- Timeout (no frame) → sends from chunk 0
- Error/Done event → sends from chunk 0

The metadata frame includes `"resumeFromChunk": start_chunk` so the receiver
can detect whether the sender actually resumed or restarted from scratch.

### Receiver Side (`ReceiverPeer::send_resume`)

After DataChannel opens, receiver immediately sends the resume frame **3 times**
for redundancy (guards against TURN relay latency causing the first frame to
arrive after the sender's timeout):
- First connection: `{ type: "resume", chunkIndex: -1 }` (start from beginning)
- Retry after partial: `{ type: "resume", chunkIndex: last_received_index }`

**Important**: The receiver's event loop captures the incoming DataChannel ID on
`ChannelOpen` (since the receiver doesn't create the channel — the sender does).
Without this, `send_resume` frames would be queued in `pending_sends` but never
written to SCTP. Fixed in v0.15.3 by making `channel_id` mutable in `event_loop::run`.

### Sender-Restart Detection (Receiver)

After calling `receive_transfer`, the receiver checks the sender's
`resumeFromChunk` value from the metadata frame:
- If `resumeFromChunk < expected_start` AND accumulated chunks exist →
  the sender restarted (e.g. missed the resume frame). The receiver **discards
  all accumulated data** and resets `last_chunk_index` to avoid data corruption
  from concatenating duplicate chunks.
- If `resumeFromChunk >= expected_start` → resume is correct, accumulated
  data is preserved.

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

## Module Architecture

### Retry Module (`src/retry.rs`)

Centralizes all retry-related logic previously duplicated across `share.rs` and `get.rs`:
- `RetryPolicy` struct with `max_retries` and `backoff_ms`
- `DEFAULT` constant policy (3 retries, [1s,2s,4s])
- Timeout constants: `PEER_TIMEOUT_SECS`, `CHANNEL_TIMEOUT_SECS`, `RESUME_WAIT_MS`
- `prompt_manual()` — interactive retry prompt (moved from `commands/mod.rs`)
- `log_retry()` — ANSI-formatted retry status

### P2P Stages (`src/commands/p2p_stages.rs`)

Extracted connection stage helpers used by both sender and receiver:
- `await_ready()` — sender waits for `p2p:ready` (infinite or timeout)
- `await_offer()` — receiver waits for SDP offer (infinite or timeout)
- `await_answer()` — sender collects answer + relays ICE candidates
- `await_sender_channel()` — sender waits for DataChannel open + relays ICE
- `await_receiver_channel()` — receiver waits for DataChannel open + relays ICE

### WebRTC Module (`src/webrtc/`)

Split from monolithic `webrtc.rs` into:
- `mod.rs` — shared types, re-exports
- `net.rs` — IP discovery, UDP binding (11 tests)
- `event_loop.rs` — sans-I/O loop
- `sender.rs` — SenderPeer (5 tests)
- `receiver.rs` — ReceiverPeer

---

## Test Coverage

### Unit Tests (inline in source, 101 total)

- `retry.rs`: 3 tests (delay, clamp, exhaustion boundary)
- `commands/share.rs`: 15+ tests covering validation, server mode, P2P flow
- `commands/get.rs`: 15+ tests covering URL parsing, server mode, P2P flow
- `webrtc/net.rs`: 11 tests (IP detection, LAN detection, `is_private_lan_ip`)
- `webrtc/sender.rs`: 5 tests (resume, transfer_from)
- `commands/display.rs`: 7 tests (ANSI strip, display width, hline)
- `crypto.rs`: 4 tests (round-trip, cross-compat, wrong password)
- `api.rs`: 8+ tests (mock server HTTP flows)

### E2E Tests (`e2e/tests/cli-retry.integration.spec.ts`)

- Sender exits correctly when no receiver connects
- Normal P2P transfer succeeds (happy path, no retry needed)

### Suggested Additional E2E Tests

1. **Receiver disconnects mid-transfer, reconnects** → verify resume
2. **ICE failure simulation** → verify 3 retries then manual prompt
3. **Manual retry acceptance** → verify continued transfer after Enter
4. **Large file resume** → verify chunk-index correctness after reconnect
