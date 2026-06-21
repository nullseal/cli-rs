//! Shared retry policy for P2P transfers.
//!
//! Centralizes constants, backoff logic, and the manual retry prompt
//! used by both sender (`share.rs`) and receiver (`get.rs`).

use std::time::Duration;

/// Retry policy configuration.
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

/// How long sender waits for a resume frame after DataChannel opens.
pub const RESUME_WAIT_MS: u64 = 5000;

impl RetryPolicy {
    /// Get the backoff delay for a given attempt (1-indexed).
    pub fn delay(&self, attempt: u32) -> Duration {
        let ms = self
            .backoff_ms
            .get((attempt - 1) as usize)
            .copied()
            .unwrap_or(*self.backoff_ms.last().unwrap_or(&4000));
        Duration::from_millis(ms)
    }

    /// Whether the attempt count has exceeded max retries.
    pub fn exhausted(&self, attempt: u32) -> bool {
        attempt > self.max_retries
    }
}

/// Prompt user to manually retry after auto-retries are exhausted.
/// Returns `true` if user wants to retry, `false` to abort.
/// In non-interactive mode (piped stdin), returns `false`.
pub async fn prompt_manual() -> bool {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprintln!("\x1b[1;33m\u{26a0}\x1b[0m All automatic retries exhausted.");
    eprintln!("\x1b[2m  Tip: A VPN or firewall may be blocking P2P traffic. Disable VPN or switch network.\x1b[0m");
    eprint!("Press Enter to retry or Ctrl+C to quit\u{2026} ");
    let mut buf = String::new();
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    use tokio::io::AsyncBufReadExt;
    match reader.read_line(&mut buf).await {
        Ok(0) | Err(_) => false,
        Ok(_) => true,
    }
}

/// Log a retry attempt to stderr with ANSI formatting.
pub fn log_retry(attempt: u32, max: u32, reason: &str) {
    eprintln!(
        "\x1b[1;33m⟳\x1b[0m Retrying ({attempt}/{max}) — {reason}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_returns_correct_backoff() {
        assert_eq!(DEFAULT.delay(1), Duration::from_millis(1000));
        assert_eq!(DEFAULT.delay(2), Duration::from_millis(2000));
        assert_eq!(DEFAULT.delay(3), Duration::from_millis(4000));
    }

    #[test]
    fn delay_clamps_to_last_on_overflow() {
        assert_eq!(DEFAULT.delay(10), Duration::from_millis(4000));
    }

    #[test]
    fn exhausted_boundary() {
        assert!(!DEFAULT.exhausted(1));
        assert!(!DEFAULT.exhausted(3));
        assert!(DEFAULT.exhausted(4));
    }

    #[test]
    fn resume_wait_exceeds_typical_turn_latency() {
        // Resume frame is sent 3 times for redundancy. The sender must wait
        // long enough to receive at least one copy even through a TURN relay.
        // Typical TURN RTT is 200-500ms; 5s gives ample margin.
        assert!(RESUME_WAIT_MS >= 5000);
    }
}
