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

/// Approximate visible column width: ASCII = 1, wide/emoji chars = 2.
fn display_width(s: &str) -> usize {
    s.chars()
        .map(|c| if c.is_ascii() { 1 } else { 2 })
        .sum()
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
        "📤 Share",
        &[
            ("ID:", share_id),
            ("URL:", share_url),
            ("CLI:", &format!("{CYAN}nullseal get s/{share_id}{RESET}")),
        ],
        width,
    );

    eprintln!();

    boxed_section(
        "🔐 Owner",
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
        "📡 P2P Session",
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
    eprintln!("  {YELLOW}⏳ Waiting for recipient…{RESET}");
}

pub fn print_local_share_result(addr: &str) {
    eprintln!();
    eprintln!("  {GREEN}{BOLD}✓ Local share ready{RESET}");
    eprintln!();

    let width = 60;
    boxed_section(
        "📡 Local Transfer",
        &[
            ("Address:", addr),
            ("CLI:", &format!("{CYAN}nullseal get --local{RESET}")),
            ("Direct:", &format!("{CYAN}nullseal get --local -a {addr}{RESET}")),
        ],
        width,
    );

    eprintln!();
    eprintln!("  {YELLOW}⏳ Waiting for recipient…{RESET}");
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
        // Non-ASCII chars counted as width 2
        assert_eq!(display_width("📡"), 2);
    }

    #[test]
    fn display_width_mixed() {
        assert_eq!(display_width("a📡b"), 4); // 1 + 2 + 1
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
