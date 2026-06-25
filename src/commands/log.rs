//! Leveled logger for the CLI — three output modes (Pipe / Normal / Verbose).
//!
//! All human-facing status goes through this logger so a single verbosity knob
//! controls what reaches the terminal:
//!
//! - **Pipe** (`--pipe`): machine-friendly. The *only* thing emitted is the
//!   `result(...)` payload (received content for `get`, share URL for `share`)
//!   plus any pre-existing stderr contract (e.g. the share-result box). All
//!   `step`/`progress`/`attempt`/`event`/`error` calls are suppressed.
//! - **Normal** *(default)*: main milestones + progress bar + retry attempts +
//!   errors. What a human needs, not a firehose.
//! - **Verbose** (`--verbose`): everything Normal shows **plus** the full
//!   lifecycle/transport event stream (per-chunk KB/MB, error codes, …).
//!
//! The verbosity is a process-global set once in `main` (`init`), so the deep
//! retry loops in `share.rs`/`get.rs`/`p2p_stages.rs` can log without threading a
//! handle through every call. ANSI styling is suppressed automatically when the
//! target stream is not a TTY (piped output), independent of the mode.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicU8, Ordering};

/// Output verbosity, derived from the `--pipe` / `--verbose` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    /// `--pipe`: result only, no logs.
    Pipe,
    /// default: milestones + progress + attempts + errors.
    Normal,
    /// `--verbose`: Normal + the full event firehose.
    Verbose,
}

impl Verbosity {
    fn from_u8(v: u8) -> Verbosity {
        match v {
            0 => Verbosity::Pipe,
            2 => Verbosity::Verbose,
            _ => Verbosity::Normal,
        }
    }
    fn as_u8(self) -> u8 {
        match self {
            Verbosity::Pipe => 0,
            Verbosity::Normal => 1,
            Verbosity::Verbose => 2,
        }
    }
}

// Default to Normal until `init` is called (keeps unit tests / early errors sane).
static VERBOSITY: AtomicU8 = AtomicU8::new(1);

/// Set the process-global verbosity from the parsed flags. Call once in `main`.
pub fn init(verbosity: Verbosity) {
    VERBOSITY.store(verbosity.as_u8(), Ordering::Relaxed);
}

/// Current process-global verbosity.
pub fn verbosity() -> Verbosity {
    Verbosity::from_u8(VERBOSITY.load(Ordering::Relaxed))
}

/// Whether logs (anything but `result`) are suppressed — i.e. Pipe mode.
pub fn is_pipe() -> bool {
    verbosity() == Verbosity::Pipe
}

/// Whether the verbose event firehose is enabled.
pub fn is_verbose() -> bool {
    verbosity() == Verbosity::Verbose
}

/// Whether stderr is a TTY (drives ANSI styling for log streams).
pub fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal()
}

/// The piped result — the payload (`get`) or share URL (`share`).
/// Always written to **stdout**, in every mode. This is the only thing Pipe emits.
pub fn result(s: &str) {
    println!("{s}");
}

/// A blank separator line on stderr (cosmetic). Suppressed in Pipe so piped
/// stderr stays empty.
pub fn blank() {
    if is_pipe() {
        return;
    }
    eprintln!();
}

/// A main milestone (e.g. "Creating session…", "Transfer complete").
/// Shown in Normal + Verbose; suppressed in Pipe.
pub fn step(s: &str) {
    if is_pipe() {
        return;
    }
    eprintln!("{s}");
}

/// A retry attempt notice. Shown in Normal + Verbose; suppressed in Pipe.
pub fn attempt(n: u32, max: u32, reason: &str) {
    if is_pipe() {
        return;
    }
    if stderr_is_tty() {
        eprintln!("\x1b[1;33m⟳\x1b[0m Retrying ({n}/{max}) — {reason}");
    } else {
        eprintln!("Retrying ({n}/{max}) — {reason}");
    }
}

/// A lifecycle / transport event (the debug firehose). Verbose only.
pub fn event(s: &str) {
    if !is_verbose() {
        return;
    }
    if stderr_is_tty() {
        eprintln!("\x1b[2m·\x1b[0m {s}");
    } else {
        eprintln!("· {s}");
    }
}

/// An error message. Shown on stderr in Normal + Verbose; suppressed in Pipe
/// (Pipe signals failure via exit code only).
pub fn error(s: &str) {
    if is_pipe() {
        return;
    }
    if stderr_is_tty() {
        eprintln!("\x1b[1;31m✗\x1b[0m {s}");
    } else {
        eprintln!("✗ {s}");
    }
}

/// Inline send progress (overwrites the current line). Normal + Verbose.
/// No-op in Pipe; plain (no carriage-return rewrite) when stderr isn't a TTY.
pub fn progress_send(sent: usize, total: usize) {
    progress("Sending", sent, total);
}

/// Inline receive progress (overwrites the current line). Normal + Verbose.
pub fn progress_recv(received: usize, total: usize) {
    progress("Receiving", received, total);
}

fn progress(label: &str, done: usize, total: usize) {
    if is_pipe() {
        return;
    }
    let done = super::format_size(done);
    let total = super::format_size(total);
    let mut err = std::io::stderr();
    if stderr_is_tty() {
        // Overwrite the current line with the live counter.
        let _ = write!(err, "\r{label}: {done}/{total}\x1b[K");
        let _ = err.flush();
    } else {
        // Non-TTY: emit one line per update would flood; only emit at the end
        // (done == total) so piped logs stay readable without ANSI rewrites.
        if done == total {
            let _ = writeln!(err, "{label}: {done}/{total}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbosity_round_trips_through_u8() {
        for v in [Verbosity::Pipe, Verbosity::Normal, Verbosity::Verbose] {
            assert_eq!(Verbosity::from_u8(v.as_u8()), v);
        }
    }

    #[test]
    fn unknown_u8_defaults_to_normal() {
        assert_eq!(Verbosity::from_u8(99), Verbosity::Normal);
    }

    #[test]
    fn init_sets_and_reads_back() {
        init(Verbosity::Verbose);
        assert_eq!(verbosity(), Verbosity::Verbose);
        assert!(is_verbose());
        assert!(!is_pipe());

        init(Verbosity::Pipe);
        assert_eq!(verbosity(), Verbosity::Pipe);
        assert!(is_pipe());
        assert!(!is_verbose());

        // Restore default so other tests in the binary aren't affected.
        init(Verbosity::Normal);
        assert_eq!(verbosity(), Verbosity::Normal);
    }
}
