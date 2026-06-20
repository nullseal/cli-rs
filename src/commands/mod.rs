pub mod display;
pub mod get;
pub mod manage;
pub mod share;

pub const SUPPORTED_EXTENSIONS: &[&str] = &[
    // text & data
    ".txt", ".md", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".log", ".rtf", ".tex", ".srt",
    ".vtt", ".ics", ".vcf",
    // documents
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp", ".pages", ".numbers", ".key",
    // ebooks
    ".epub", ".mobi", ".azw", ".azw3", ".fb2", ".djvu",
    // images
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico",
    ".tiff", ".tif", ".heic", ".heif", ".avif", ".raw", ".cr2", ".nef",
    ".psd", ".ai", ".eps",
    // audio
    ".mp3", ".wav", ".ogg", ".m4a", ".flac", ".aac", ".wma", ".opus",
    ".aiff", ".mid", ".midi",
    // video
    ".mp4", ".mov", ".webm", ".mkv", ".avi", ".wmv", ".flv", ".m4v",
    ".3gp", ".mpg", ".mpeg", ".ts",
    // archives
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".zst",
    ".tgz", ".tbz2",
    // fonts
    ".ttf", ".otf", ".woff", ".woff2",
    // email
    ".eml", ".msg", ".mbox",
];

pub fn is_safe_extension(filename: &str) -> bool {
    let ext = std::path::Path::new(filename)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    SUPPORTED_EXTENSIONS.contains(&ext.as_str())
}

pub fn confirm_unsafe_file(filename: &str) -> anyhow::Result<()> {
    if is_safe_extension(filename) {
        return Ok(());
    }
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Ok(());
    }
    eprint!("Warning: \"{}\" has an uncommon extension. Save anyway? [y/N] ", filename);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !input.trim().eq_ignore_ascii_case("y") {
        anyhow::bail!("Aborted.");
    }
    Ok(())
}

pub fn format_size(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;
    let b = bytes as f64;
    if b >= TB {
        format!("{:.2} TB", b / TB)
    } else if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.2} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}