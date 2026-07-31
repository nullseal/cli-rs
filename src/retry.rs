//! Shared retry policy for P2P transfers.
//!
//! Centralizes constants, backoff logic, and the manual retry prompt
//! used by both sender (`share.rs`) and receiver (`get.rs`).

/// Retry policy configuration. The backoff/exhaustion *logic* now lives in the
/// shared `ConnectionMachine` (task 013); this struct just carries the constants
/// (`max_retries`, `backoff_ms`) the machine is constructed from.
pub struct RetryPolicy {
    pub max_retries: u32,
    pub backoff_ms: &'static [u64],
}

/// Default policy: 3 auto-retries with [1s, 2s, 4s] backoff.
pub const DEFAULT: RetryPolicy = RetryPolicy {
    max_retries: 3,
    backoff_ms: &[1000, 2000, 4000],
};

/// Timeout waiting for `p2p:ready` or SDP offer on retry attempts.
pub const PEER_TIMEOUT_SECS: u64 = 10;

/// Timeout waiting for DataChannel to open (ICE + DTLS).
pub const CHANNEL_TIMEOUT_SECS: u64 = 10;

/// Timeout waiting for the recipient's SDP answer after our offer went out.
///
/// Deliberately more generous than `PEER_TIMEOUT_SECS`/`CHANNEL_TIMEOUT_SECS`:
/// by this point the recipient is already known to be present (`p2p:both-ready`
/// fired), and before it can answer it must bind a UDP socket and, online, wait
/// out a TURN allocation. What this bounds is the pathological case — the
/// recipient never negotiates at all — which previously hung the sender forever
/// with no output at any verbosity.
pub const ANSWER_TIMEOUT_SECS: u64 = 30;

/// Timeout for the `--sync --local` TCP data connection (task 062): the sender
/// waiting to `accept`, the receiver waiting to `connect` + finish the handshake.
///
/// By this point signaling has already succeeded, so the only thing left that can
/// stall is the data port itself (a firewall or endpoint agent dropping the SYN).
/// Bounded on purpose — an unbounded wait here would repeat bug B3 / task 060.
pub const SYNC_DATA_TIMEOUT_SECS: u64 = 30;

/// Prompt user to manually retry after auto-retries are exhausted.
/// Returns `true` if user wants to retry, `false` to abort.
/// In non-interactive mode (piped stdin), returns `false`.
pub async fn prompt_manual() -> bool {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return false;
    }
    // Pipe mode is machine-driven (stdin is not a TTY there anyway), but guard
    // explicitly so we never write the interactive prompt to a piped stderr.
    if crate::commands::log::is_pipe() {
        return false;
    }
    eprintln!("\x1b[1;33m\u{26a0}\x1b[0m The connection was not successful.");
    eprint!("Press Enter to retry or Ctrl+C to quit\u{2026} ");
    let mut buf = String::new();
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    use tokio::io::AsyncBufReadExt;
    match reader.read_line(&mut buf).await {
        Ok(0) | Err(_) => false,
        Ok(_) => {
            // Immediate feedback so a manual retry visibly does something (the web
            // shows "Reconnecting"); the next stage then waits for the peer.
            crate::commands::log::step("\x1b[1;34m\u{21bb}\x1b[0m Reconnecting\u{2026}");
            true
        }
    }
}

/// Log a retry attempt through the leveled logger (Normal + Verbose; suppressed
/// in Pipe). The reason is a verbose-ish detail, but the attempt count itself is
/// a Normal-mode signal, so the whole line goes at `attempt` level.
pub fn log_retry(attempt: u32, max: u32, reason: &str) {
    crate::commands::log::attempt(attempt, max, reason);
}

// Backoff/exhaustion logic moved to `crate::p2p::connection::ConnectionMachine`
// (task 013); its 11 unit tests cover the retry budget + backoff semantics.
