/// Rich terminal output for share results.

// ANSI color helpers
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

const BOX_H: &str = "─";
const BOX_TL: &str = "┌";
const BOX_TR: &str = "┐";
const BOX_BL: &str = "└";
const BOX_BR: &str = "┘";
const BOX_V: &str = "│";

fn hline(width: usize) -> String {
    BOX_H.repeat(width)
}

/// Visible column width of one char.
///
/// The old rule — "non-ASCII means width 2" — was only ever right because the
/// only non-ASCII the boxes carried were emoji. Task 066 replaced those with
/// narrow glyphs (`›`, `↻`, `…`, box drawing), which a terminal renders in
/// **one** column; counting them as two would over-pad every box line by one
/// column per glyph. So: genuinely wide characters (emoji, CJK, fullwidth
/// forms) are 2, everything else is 1.
fn char_width(c: char) -> usize {
    let cp = c as u32;
    let wide = matches!(cp,
        // East Asian Wide / Fullwidth
        0x1100..=0x115F        // Hangul Jamo
        | 0x2E80..=0x303E      // CJK radicals, Kangxi, CJK symbols & punctuation
        | 0x3041..=0x33FF      // Hiragana, Katakana, Bopomofo, CJK compatibility
        | 0x3400..=0x4DBF      // CJK unified ideographs ext A
        | 0x4E00..=0x9FFF      // CJK unified ideographs
        | 0xA000..=0xA4CF      // Yi
        | 0xAC00..=0xD7A3      // Hangul syllables
        | 0xF900..=0xFAFF      // CJK compatibility ideographs
        | 0xFE30..=0xFE6F      // CJK compatibility forms, small form variants
        | 0xFF00..=0xFF60      // Fullwidth forms
        | 0xFFE0..=0xFFE6      // Fullwidth signs
        // Emoji presentation (the ranges that default to a double-width cell)
        | 0x231A..=0x231B      // ⌚ ⌛
        | 0x23E9..=0x23F3      // ⏩ … ⏳
        | 0x25FD..=0x25FE
        | 0x2614..=0x2615
        | 0x2648..=0x2653
        | 0x267F | 0x2693 | 0x26A1
        | 0x26AA..=0x26AB
        | 0x26BD..=0x26BE
        | 0x26C4..=0x26C5
        | 0x26CE | 0x26D4 | 0x26EA
        | 0x26F2..=0x26F3
        | 0x26F5 | 0x26FA | 0x26FD
        | 0x2705
        | 0x270A..=0x270B
        | 0x2728 | 0x274C | 0x274E
        | 0x2753..=0x2755
        | 0x2757
        | 0x2795..=0x2797
        | 0x27B0 | 0x27BF
        | 0x2B1B..=0x2B1C
        | 0x2B50 | 0x2B55
        | 0x1F300..=0x1F64F    // symbols & pictographs, emoticons
        | 0x1F680..=0x1F6FF    // transport & map
        | 0x1F900..=0x1F9FF    // supplemental symbols & pictographs
        | 0x1FA70..=0x1FAFF    // symbols & pictographs extended-A
    );
    if wide {
        2
    } else {
        1
    }
}

/// Approximate visible column width of a string (see [`char_width`]).
fn display_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// Strip ANSI escape sequences for width calculation.
fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else if c == '\x1b' {
            in_escape = true;
        } else {
            out.push(c);
        }
    }
    out
}

fn boxed_section(title: &str, rows: &[(&str, &str)], width: usize) {
    let inner = width - 2;
    eprintln!("  {BOX_TL}{}{BOX_TR}", hline(inner));
    // title — account for emoji width
    let title_w = display_width(title);
    let pad = inner.saturating_sub(title_w + 1);
    eprintln!("  {BOX_V} {BOLD}{title}{RESET}{}{BOX_V}", " ".repeat(pad));
    eprintln!("  {BOX_V}{}{BOX_V}", hline(inner));
    // rows
    for (label, value) in rows {
        let plain_value = strip_ansi(value);
        let visible_len = label.len() + 3 + display_width(&plain_value);
        let pad = inner.saturating_sub(visible_len);
        eprintln!("  {BOX_V}  {DIM}{label}{RESET} {value}{}{BOX_V}", " ".repeat(pad));
    }
    eprintln!("  {BOX_BL}{}{BOX_BR}", hline(inner));
}

pub fn print_server_share_result(
    share_id: &str,
    share_url: &str,
    owner_code: &str,
    manage_url: &str,
) {
    let width = 60;
    eprintln!();
    eprintln!("  {GREEN}{BOLD}✓ Share created successfully{RESET}");
    eprintln!();

    boxed_section(
        "Share",
        &[
            ("ID:", share_id),
            ("URL:", share_url),
            ("CLI:", &format!("{CYAN}nullseal get s/{share_id}{RESET}")),
        ],
        width,
    );

    eprintln!();

    boxed_section(
        "Owner",
        &[
            ("Code:", owner_code),
            ("Manage:", manage_url),
        ],
        width,
    );

    eprintln!();
    print_qr(share_url);
}

pub fn print_p2p_share_result(session_id: &str, p2p_url: &str) {
    eprintln!();
    eprintln!("  {GREEN}{BOLD}✓ P2P session created{RESET}");
    eprintln!();

    let width = 60;
    boxed_section(
        "P2P Session",
        &[
            ("ID:", session_id),
            ("URL:", p2p_url),
            ("CLI:", &format!("{CYAN}nullseal get p2p/{session_id}{RESET}")),
        ],
        width,
    );

    eprintln!();
    print_qr(p2p_url);
    eprintln!();
    eprintln!("  {YELLOW}› Waiting for recipient…{RESET}");
}

pub fn print_local_share_result(addr: &str) {
    eprintln!();
    eprintln!("  {GREEN}{BOLD}✓ Local share ready{RESET}");
    eprintln!();

    let width = 60;
    boxed_section(
        "Local Transfer",
        &[
            ("Address:", addr),
            ("CLI:", &format!("{CYAN}nullseal get --local{RESET}")),
            ("Direct:", &format!("{CYAN}nullseal get --local -a {addr}{RESET}")),
        ],
        width,
    );

    eprintln!();
    eprintln!("  {YELLOW}› Waiting for recipient…{RESET}");
}

fn print_qr(url: &str) {
    eprintln!("  {DIM}QR Code:{RESET}");
    // qr2term prints to stdout; we want it on stderr
    // Use qr2term::generate_qr_string and print to stderr
    if let Ok(qr_string) = qr2term::generate_qr_string(url) {
        for line in qr_string.lines() {
            eprintln!("  {line}");
        }
    }
}

// ── Semantic status helpers ───────────────────────────────────────────────────

/// Print a success status message (a milestone). Routed through the leveled
/// logger: shown in Normal + Verbose, suppressed in Pipe.
pub fn status(msg: &str) {
    if super::log::is_pipe() {
        return;
    }
    if super::log::stderr_is_tty() {
        eprintln!("\x1b[1;32m✓\x1b[0m {msg}");
    } else {
        eprintln!("✓ {msg}");
    }
}

/// Print a warning message (a milestone). Suppressed in Pipe.
#[allow(dead_code)]
pub fn warn(msg: &str) {
    if super::log::is_pipe() {
        return;
    }
    if super::log::stderr_is_tty() {
        eprintln!("\x1b[1;33m⚠\x1b[0m {msg}");
    } else {
        eprintln!("⚠ {msg}");
    }
}

/// Print inline transfer progress (overwrites current line). Routed through the
/// logger so it's suppressed in Pipe and avoids ANSI on a non-TTY.
pub fn transfer_progress(sent: usize, total: usize) {
    super::log::progress_send(sent, total);
}

/// Print inline receive progress (overwrites current line).
pub fn receive_progress(received: usize, total: usize) {
    super::log::progress_recv(received, total);
}

/// A spinner that runs on a background thread, showing a message with animation.
/// Stops and clears the line when dropped.
pub struct Spinner {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Spinner {
    /// Start a spinner with the given message. The spinner runs until dropped.
    ///
    /// In Pipe mode (or when stderr isn't a TTY) the animation is suppressed — a
    /// spinner is meaningless to a machine consumer and would corrupt piped logs.
    pub fn start(msg: &str) -> Self {
        if super::log::is_pipe() || !super::log::stderr_is_tty() {
            return Self { stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)), handle: None };
        }
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = stop.clone();
        let msg = msg.to_owned();
        let handle = std::thread::spawn(move || {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut i = 0;
            while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                eprint!("\r\x1b[1;36m{}\x1b[0m {}\x1b[K", frames[i % frames.len()], msg);
                i += 1;
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
            eprint!("\r\x1b[K");
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ansi_removes_escape_codes() {
        let colored = format!("{CYAN}hello{RESET}");
        assert_eq!(strip_ansi(&colored), "hello");
    }

    #[test]
    fn strip_ansi_plain_text_unchanged() {
        assert_eq!(strip_ansi("hello world"), "hello world");
    }

    #[test]
    fn display_width_ascii() {
        assert_eq!(display_width("hello"), 5);
    }

    #[test]
    fn display_width_emoji() {
        // Genuinely wide chars still count as 2 columns.
        assert_eq!(display_width("📡"), 2);
        assert_eq!(display_width("⏳"), 2);
        assert_eq!(display_width("漢"), 2);
    }

    #[test]
    fn display_width_mixed() {
        assert_eq!(display_width("a📡b"), 4); // 1 + 2 + 1
    }

    #[test]
    fn display_width_narrow_glyphs_are_one_column() {
        // Task 066: the CLI's status glyphs are single-width. Counting them as 2
        // (the old "non-ASCII ⇒ wide" rule) over-padded every boxed line.
        for g in ["›", "↻", "✓", "✗", "⚠", "·", "…", "─", "│"] {
            assert_eq!(display_width(g), 1, "{g} must be one column");
        }
    }

    #[test]
    fn display_width_box_titles_are_plain_ascii() {
        // Titles carry no glyph any more, so their width is just their length.
        for t in ["Share", "Owner", "P2P Session", "Local Transfer"] {
            assert_eq!(display_width(t), t.len());
        }
    }

    #[test]
    fn hline_generates_correct_width() {
        assert_eq!(hline(5), "─────");
    }

    #[test]
    fn hline_zero_is_empty() {
        assert_eq!(hline(0), "");
    }
}
