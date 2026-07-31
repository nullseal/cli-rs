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
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// The one left margin every human-facing line is written at (task 067).
///
/// `display.rs` has always indented its result boxes and status lines two
/// columns, while the `step`/`error`/`event` family started at column 0 — so a
/// real run had a ragged left edge with two competing columns. Everything a
/// human reads now hangs off this margin: steps, errors, warnings, retries,
/// verbose events, the progress counter and the spinner. Pipe mode is exempt by
/// construction — it emits only [`result`] on stdout, which never gets a margin.
pub const MARGIN: &str = "  ";

/// The step glyph. Every milestone carries one so the glyph column is uniform:
/// a bare line among prefixed ones reads as misaligned even at the right indent.
pub const GLYPH_STEP: &str = "›";

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

// True while a live (TTY, `\r`-rewritten) progress line is pending without a
// trailing newline. Any other stderr write must terminate it first so messages
// don't run on (e.g. "Sending: 25 MB/112 MBReceiver disconnected…"). (task 033)
static PROGRESS_ACTIVE: AtomicBool = AtomicBool::new(false);

/// If a live progress line is pending, end it with a newline before other output.
fn finish_progress() {
    if PROGRESS_ACTIVE.swap(false, Ordering::Relaxed) {
        eprintln!();
    }
}

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
    finish_progress();
    eprintln!();
}

/// A main milestone (e.g. "Creating session…", "Transfer complete").
/// Shown in Normal + Verbose; suppressed in Pipe.
///
/// Rendered at [`MARGIN`] with the [`GLYPH_STEP`] prefix. Call sites pass the
/// message only — never their own glyph — so the column stays uniform. (067)
pub fn step(s: &str) {
    step_glyph(GLYPH_STEP, s);
}

/// A milestone that carries a glyph other than `›` — `↻` for resume/reconnect,
/// `✓` for a completed sub-step. Same margin as [`step`]; only the glyph differs.
/// The `glyph` may embed its own ANSI styling.
pub fn step_glyph(glyph: &str, s: &str) {
    if is_pipe() {
        return;
    }
    finish_progress();
    eprintln!("{}", format_line(glyph, s));
}

/// Compose one human-facing line: margin, glyph, message. (Pure — for testing.)
fn format_line(glyph: &str, s: &str) -> String {
    format!("{MARGIN}{glyph} {s}")
}

/// Format the retry-attempt line. The technical `reason` is appended only in
/// Verbose; Normal shows a clean `Connection interrupted, retrying (n/max)`.
/// (Pure — for testing.)
fn format_attempt(n: u32, max: u32, reason: &str, verbose: bool) -> String {
    if verbose {
        format!("Connection interrupted, retrying ({n}/{max}) — {reason}")
    } else {
        format!("Connection interrupted, retrying ({n}/{max})")
    }
}

/// A retry attempt notice. Shown in Normal + Verbose; suppressed in Pipe.
/// The technical `reason` (e.g. "transfer interrupted: DataChannel closed…") is
/// only shown in **Verbose** — Normal stays a clean
/// `Connection interrupted, retrying (n/max)`.
///
/// Marked with `↻`, the same glyph as "Resuming from chunk N" — retry and resume
/// are two halves of one interrupted run, and `⟳`/`↻` were visually
/// indistinguishable at terminal size anyway. (task 066)
pub fn attempt(n: u32, max: u32, reason: &str) {
    if is_pipe() {
        return;
    }
    finish_progress();
    let line = format_attempt(n, max, reason, is_verbose());
    if stderr_is_tty() {
        eprintln!("{MARGIN}\x1b[1;33m↻\x1b[0m {line}");
    } else {
        eprintln!("{MARGIN}↻ {line}");
    }
}

/// A lifecycle / transport event (the debug firehose). Verbose only.
///
/// Shares the standard [`MARGIN`]: verbose lines interleave with the very
/// milestones they explain, so hanging them at column 0 would rebuild the exact
/// ragged edge 067 removed. The dim `·` glyph already sets them apart. (067)
pub fn event(s: &str) {
    if !is_verbose() {
        return;
    }
    finish_progress();
    if stderr_is_tty() {
        eprintln!("{MARGIN}\x1b[2m·\x1b[0m {s}");
    } else {
        eprintln!("{MARGIN}· {s}");
    }
}

/// An error message. Shown on stderr in Normal + Verbose; suppressed in Pipe
/// (Pipe signals failure via exit code only).
///
/// Shares the standard [`MARGIN`]. The bold-red `✗` carries the emphasis; two
/// columns of whitespace would not add any, and a flush-left error next to an
/// indented step reads as a layout bug rather than a warning. (067)
pub fn error(s: &str) {
    if is_pipe() {
        return;
    }
    finish_progress();
    if stderr_is_tty() {
        eprintln!("{MARGIN}\x1b[1;31m✗\x1b[0m {s}");
    } else {
        eprintln!("{MARGIN}✗ {s}");
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
        // Margin + step glyph, same as every milestone: a bare counter sitting
        // between two `›` lines reads as misaligned. (task 067)
        let _ = write!(err, "\r{MARGIN}{GLYPH_STEP} {label}: {done}/{total}\x1b[K");
        let _ = err.flush();
        // A live line is now pending (no trailing newline) — mark it so the next
        // non-progress write terminates it. On the final tick, end it here. (task 033)
        if done == total {
            let _ = writeln!(err);
            PROGRESS_ACTIVE.store(false, Ordering::Relaxed);
        } else {
            PROGRESS_ACTIVE.store(true, Ordering::Relaxed);
        }
    } else {
        // Non-TTY: emit one line per update would flood; only emit at the end
        // (done == total) so piped logs stay readable without ANSI rewrites.
        if done == total {
            let _ = writeln!(err, "{}", format_line(GLYPH_STEP, &format!("{label}: {done}/{total}")));
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
    fn attempt_reason_only_in_verbose() {
        // Normal: clean line, no technical reason. Verbose: full reason. (Task 030)
        assert_eq!(
            format_attempt(1, 3, "DataChannel closed", false),
            "Connection interrupted, retrying (1/3)"
        );
        assert_eq!(
            format_attempt(1, 3, "DataChannel closed", true),
            "Connection interrupted, retrying (1/3) — DataChannel closed"
        );
    }

    #[test]
    fn step_lines_carry_the_margin_and_step_glyph() {
        // Task 067: one left margin, one glyph column. A step never starts at
        // column 0 and never goes out bare.
        assert_eq!(format_line(GLYPH_STEP, "Finishing up…"), "  › Finishing up…");
        assert!(format_line(GLYPH_STEP, "x").starts_with(MARGIN));
    }

    #[test]
    fn every_glyph_shares_one_margin() {
        // ✓ / ↻ / ✗ / ⚠ / · all hang off the same two columns, so the glyph
        // column stays vertically aligned across a whole run.
        for glyph in [GLYPH_STEP, "✓", "↻", "✗", "⚠", "·"] {
            let line = format_line(glyph, "msg");
            assert!(line.starts_with(MARGIN), "{glyph} line must be indented");
            assert_eq!(
                line.chars().take_while(|c| *c == ' ').count(),
                MARGIN.len(),
                "{glyph} line must use exactly the standard margin"
            );
        }
    }

    #[test]
    fn margin_is_two_columns() {
        // display.rs boxes are drawn at this indent; the log column must match.
        assert_eq!(MARGIN, "  ");
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
