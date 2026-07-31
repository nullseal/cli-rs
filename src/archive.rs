//! Folder-share archiving (task 051): pure `pack`/`extract` helpers with no
//! transport knowledge. Pure-Rust `zip` (deflate via miniz_oxide) — no system
//! tools, nothing for the user to install. Packing sources its file list from
//! `walker::walk` (task 052), so `.nullsealignore` + `--exclude` patterns are
//! honored and excluded files never enter the archive.
//!
//! Security rules (spec §5):
//! - Zip-slip guarded: every entry name is validated (via `enclosed_name`)
//!   BEFORE anything is written, so a malicious archive produces no output.
//! - Symlinks are never followed and never packed (skipped, reported in the
//!   summary so the caller can warn on stderr); symlink entries inside an
//!   archive are never materialised on extract.
//! - An unreadable file while packing fails fast, naming the file.
//! - Unix modes are preserved via zip external attributes (ignored on Windows).

use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

/// Sentinel MIME type marking a NullSeal folder share inside the existing
/// `FileMetadata.mimeType` field. The CLI sends `application/octet-stream` for
/// every plain file (and browsers send `application/zip` for user zips), so this
/// value is only ever produced by folder packing — a plain user-sent `.zip` is
/// therefore never auto-extracted. Carried in an existing free-string field, so
/// core (`@IsString()` DTO) and web need no changes.
pub const FOLDER_MIME: &str = "application/x-nullseal-folder";

/// Result of packing a directory into a zip archive.
#[derive(Debug)]
pub struct PackSummary {
    /// Number of regular files written into the archive.
    pub file_count: usize,
    /// Sum of the (uncompressed) file sizes, in bytes.
    pub total_bytes: u64,
    /// Symlinks encountered and skipped (relative to the packed dir).
    pub skipped_symlinks: Vec<PathBuf>,
}

/// Result of extracting an archive.
#[derive(Debug)]
pub struct ExtractSummary {
    /// Number of regular files written.
    pub file_count: usize,
    /// Symlink entries found in the archive and skipped (never materialised).
    pub skipped_symlinks: Vec<PathBuf>,
    /// Relative, forward-slash paths of the files written — the source set
    /// `get --replace-delete` diffs the destination against (task 058).
    pub written: std::collections::BTreeSet<String>,
}

/// Pack `dir` into a zip archive at `dest` (deterministic, name-sorted walk;
/// honors `.nullsealignore` at `dir` — task 052). Entries are stored relative
/// to `dir` (no wrapper directory). Empty directories are preserved. Symlinks
/// are skipped (see `PackSummary`).
///
/// Test-only convenience wrapper: production callers (`share --zip`) always go
/// through `pack_with_excludes` so `--exclude` patterns are threaded through.
#[cfg(test)]
pub fn pack(dir: &Path, dest: &Path) -> Result<PackSummary> {
    pack_with_excludes(dir, dest, &[])
}

/// `pack` with additional gitignore-style exclude patterns (`share --exclude`),
/// additive to `.nullsealignore`. The file source is `walker::walk` (task 052),
/// so excluded files never enter the archive.
pub fn pack_with_excludes(
    dir: &Path,
    dest: &Path,
    extra_excludes: &[String],
) -> Result<PackSummary> {
    let walk = crate::walker::walk(dir, extra_excludes)?;
    let out = File::create(dest)
        .with_context(|| format!("cannot create archive at \"{}\"", dest.display()))?;
    let mut zip = ZipWriter::new(BufWriter::new(out));
    let mut summary = PackSummary {
        file_count: 0,
        total_bytes: 0,
        skipped_symlinks: walk.skipped_symlinks.iter().map(PathBuf::from).collect(),
    };

    for entry in &walk.entries {
        // Walker rel paths are forward-slash relative components (no `..`, no
        // absolutes), exactly what zip entry names must be.
        let path = dir.join(&entry.rel_path);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(entry.mode)
            .large_file(entry.size >= 0xFFFF_FFFF);

        if entry.is_dir {
            zip.add_directory(format!("{}/", entry.rel_path), options)
                .with_context(|| {
                    format!("failed to add directory \"{}\" to the archive", entry.rel_path)
                })?;
        } else {
            // Fail fast on an unreadable file, naming it (spec §5.3).
            let mut f = File::open(&path)
                .with_context(|| format!("cannot read file \"{}\" — packing aborted", path.display()))?;
            zip.start_file(entry.rel_path.as_str(), options)
                .with_context(|| format!("failed to add \"{}\" to the archive", entry.rel_path))?;
            std::io::copy(&mut f, &mut zip)
                .with_context(|| format!("cannot read file \"{}\" — packing aborted", path.display()))?;
            summary.file_count += 1;
            summary.total_bytes += entry.size;
        }
    }
    zip.finish().context("failed to finalise the archive")?;
    Ok(summary)
}

/// Extract the archive at `zip_path` into the directory `dest`.
///
/// - An existing `dest` is **merge-overwritten silently** (task 058, spec §3):
///   colliding files are replaced, non-colliding existing files are left in
///   place. The old refusal-on-existing-folder and its `--force` escape hatch
///   are both gone — `get --replace-delete` is what prunes extras.
/// - Every entry name is validated up front; any absolute or `..`-traversing
///   name aborts the whole extraction with nothing written (zip-slip guard).
/// - Symlink entries are skipped (reported in the summary), never created.
/// - On a mid-extract error, partial output is deleted: the whole `dest` if we
///   created it, otherwise every file this run wrote.
pub fn extract(zip_path: &Path, dest: &Path) -> Result<ExtractSummary> {
    let dest_existed = dest.exists();

    let file = File::open(zip_path)
        .with_context(|| format!("cannot open archive \"{}\"", zip_path.display()))?;
    let mut archive = ZipArchive::new(BufReader::new(file))
        .with_context(|| format!("\"{}\" is not a valid zip archive", zip_path.display()))?;

    // Pass 1 — validate every entry name BEFORE writing anything, so a
    // malicious archive fails with zero partial output (spec §5.1).
    for i in 0..archive.len() {
        let entry = archive.by_index_raw(i)?;
        if entry.enclosed_name().is_none() {
            bail!(
                "Unsafe path \"{}\" in archive — extraction aborted, nothing was written.",
                entry.name()
            );
        }
    }

    fs::create_dir_all(dest)
        .with_context(|| format!("cannot create destination \"{}\"", dest.display()))?;

    // Pass 2 — write, tracking what we create for error cleanup.
    let mut written: Vec<PathBuf> = Vec::new();
    let mut summary = ExtractSummary {
        file_count: 0,
        skipped_symlinks: Vec::new(),
        written: std::collections::BTreeSet::new(),
    };
    let result: Result<()> = (|| {
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let rel = entry
                .enclosed_name()
                .ok_or_else(|| anyhow::anyhow!("unsafe path in archive"))?;
            let out_path = dest.join(&rel);

            // Never materialise symlink entries (spec §5.2).
            if let Some(mode) = entry.unix_mode() {
                if mode & 0o170000 == 0o120000 {
                    summary.skipped_symlinks.push(rel.clone());
                    continue;
                }
            }

            if entry.is_dir() {
                fs::create_dir_all(&out_path)
                    .with_context(|| format!("cannot create \"{}\"", out_path.display()))?;
                continue;
            }

            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("cannot create \"{}\"", parent.display()))?;
            }
            let mut f = File::create(&out_path)
                .with_context(|| format!("cannot write \"{}\"", out_path.display()))?;
            std::io::copy(&mut entry, &mut f)
                .with_context(|| format!("cannot write \"{}\"", out_path.display()))?;
            written.push(out_path.clone());
            summary.written.insert(
                rel.components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/"),
            );

            #[cfg(unix)]
            if let Some(mode) = entry.unix_mode() {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&out_path, fs::Permissions::from_mode(mode & 0o777));
            }
            summary.file_count += 1;
        }
        Ok(())
    })();

    match result {
        Ok(()) => Ok(summary),
        Err(e) => {
            // Delete partial output (spec §5.1): remove the whole destination if
            // this run created it; in a force-merge, only remove what we wrote.
            if !dest_existed {
                let _ = fs::remove_dir_all(dest);
            } else {
                for p in written {
                    let _ = fs::remove_file(p);
                }
            }
            Err(e)
        }
    }
}

/// List entry names in an archive (test helper).
#[cfg(test)]
fn read_entry_names(zip_path: &Path) -> Result<Vec<String>> {
    let mut archive = ZipArchive::new(BufReader::new(File::open(zip_path)?))?;
    let mut names = Vec::new();
    for i in 0..archive.len() {
        names.push(archive.by_index_raw(i)?.name().to_owned());
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a small tree:
    ///   root/
    ///     a.txt            ("alpha")
    ///     sub/b.txt        ("beta")
    ///     sub/deep/c.txt   ("gamma")
    ///     empty/           (empty dir)
    ///     tệp-ünïcode.txt  ("unicode")
    fn build_tree(root: &Path) {
        fs::create_dir_all(root.join("sub/deep")).unwrap();
        fs::create_dir_all(root.join("empty")).unwrap();
        fs::write(root.join("a.txt"), b"alpha").unwrap();
        fs::write(root.join("sub/b.txt"), b"beta").unwrap();
        fs::write(root.join("sub/deep/c.txt"), b"gamma").unwrap();
        fs::write(root.join("t\u{1EC7}p-\u{FC}n\u{EF}code.txt"), b"unicode").unwrap();
    }

    #[test]
    fn pack_extract_round_trip_preserves_tree_and_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("myfolder");
        build_tree(&src);

        let zip_path = tmp.path().join("myfolder.zip");
        let summary = pack(&src, &zip_path).unwrap();
        assert_eq!(summary.file_count, 4);
        assert_eq!(summary.total_bytes, (5 + 4 + 5 + 7) as u64);
        assert!(summary.skipped_symlinks.is_empty());

        let dest = tmp.path().join("out");
        let ex = extract(&zip_path, &dest).unwrap();
        assert_eq!(ex.file_count, 4);
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(dest.join("sub/b.txt")).unwrap(), b"beta");
        assert_eq!(fs::read(dest.join("sub/deep/c.txt")).unwrap(), b"gamma");
        assert_eq!(
            fs::read(dest.join("t\u{1EC7}p-\u{FC}n\u{EF}code.txt")).unwrap(),
            b"unicode"
        );
        // Empty directory preserved.
        assert!(dest.join("empty").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn pack_extract_preserves_unix_modes() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("modes");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("script.sh"), b"#!/bin/sh\n").unwrap();
        fs::write(src.join("plain.txt"), b"x").unwrap();
        fs::set_permissions(src.join("script.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(src.join("plain.txt"), fs::Permissions::from_mode(0o600)).unwrap();

        let zip_path = tmp.path().join("modes.zip");
        pack(&src, &zip_path).unwrap();
        let dest = tmp.path().join("out");
        extract(&zip_path, &dest).unwrap();

        let m1 = fs::metadata(dest.join("script.sh")).unwrap().permissions().mode() & 0o777;
        let m2 = fs::metadata(dest.join("plain.txt")).unwrap().permissions().mode() & 0o777;
        assert_eq!(m1, 0o755, "executable bit must survive the round trip");
        assert_eq!(m2, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn pack_skips_symlinks_and_reports_them() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("links");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("real.txt"), b"real").unwrap();
        // A link to a file inside the tree AND a link escaping the tree — both skipped.
        std::os::unix::fs::symlink(src.join("real.txt"), src.join("inner-link")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", src.join("escape-link")).unwrap();

        let zip_path = tmp.path().join("links.zip");
        let summary = pack(&src, &zip_path).unwrap();
        assert_eq!(summary.file_count, 1, "only the real file is packed");
        let mut skipped: Vec<String> = summary
            .skipped_symlinks
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        skipped.sort();
        assert_eq!(skipped, vec!["escape-link".to_string(), "inner-link".to_string()]);

        // The archive itself must not contain the link names.
        let names = read_entry_names(&zip_path).unwrap();
        assert!(names.iter().all(|n| !n.contains("link")), "links must not be packed: {names:?}");
    }

    #[cfg(unix)]
    #[test]
    fn pack_fails_fast_on_unreadable_file_naming_it() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("locked");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("ok.txt"), b"fine").unwrap();
        fs::write(src.join("secret.txt"), b"locked").unwrap();
        fs::set_permissions(src.join("secret.txt"), fs::Permissions::from_mode(0o000)).unwrap();

        // Running as root ignores permission bits — the scenario can't be
        // reproduced there, so bow out (the leader's Mac runs unprivileged).
        if File::open(src.join("secret.txt")).is_ok() {
            fs::set_permissions(src.join("secret.txt"), fs::Permissions::from_mode(0o644)).unwrap();
            eprintln!("skipping unreadable-file test: running with root privileges");
            return;
        }

        let zip_path = tmp.path().join("locked.zip");
        let err = pack(&src, &zip_path).unwrap_err();
        assert!(
            format!("{err:#}").contains("secret.txt"),
            "error must name the unreadable file, got: {err:#}"
        );
        fs::set_permissions(src.join("secret.txt"), fs::Permissions::from_mode(0o644)).unwrap();
    }

    // ── ignore rules (task 052): pack sources files from walker::walk ────

    #[test]
    fn pack_honors_nullsealignore_excluded_files_never_enter_the_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("ws");
        fs::create_dir_all(src.join("node_modules/dep")).unwrap();
        fs::create_dir_all(src.join("src")).unwrap();
        fs::write(src.join("app.log"), b"log").unwrap();
        fs::write(src.join("keep.log"), b"keep").unwrap();
        fs::write(src.join("node_modules/dep/index.js"), b"js").unwrap();
        fs::write(src.join("src/main.rs"), b"fn main() {}").unwrap();
        fs::write(src.join(".nullsealignore"), b"node_modules/\n*.log\n!keep.log\n").unwrap();

        let zip_path = tmp.path().join("ws.zip");
        let summary = pack(&src, &zip_path).unwrap();
        // .nullsealignore + keep.log + src/main.rs
        assert_eq!(summary.file_count, 3);

        let names = read_entry_names(&zip_path).unwrap();
        assert!(!names.iter().any(|n| n.starts_with("node_modules")), "{names:?}");
        assert!(!names.contains(&"app.log".to_string()), "{names:?}");
        assert!(names.contains(&"keep.log".to_string()), "{names:?}");
        assert!(names.contains(&"src/main.rs".to_string()), "{names:?}");
        // The ignore file itself is packed like any file.
        assert!(names.contains(&".nullsealignore".to_string()), "{names:?}");
    }

    #[test]
    fn pack_with_excludes_is_additive_to_the_ignore_file() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("ws");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.txt"), b"a").unwrap();
        fs::write(src.join("b.tmp"), b"b").unwrap();
        fs::write(src.join("c.log"), b"c").unwrap();
        fs::write(src.join(".nullsealignore"), b"*.log\n").unwrap();

        let zip_path = tmp.path().join("ws.zip");
        let summary = pack_with_excludes(&src, &zip_path, &["*.tmp".to_string()]).unwrap();
        assert_eq!(summary.file_count, 2); // a.txt + .nullsealignore

        let names = read_entry_names(&zip_path).unwrap();
        assert!(names.contains(&"a.txt".to_string()), "{names:?}");
        assert!(!names.contains(&"b.tmp".to_string()), "excluded by --exclude: {names:?}");
        assert!(!names.contains(&"c.log".to_string()), "excluded by the file: {names:?}");
    }

    #[test]
    fn pack_without_ignore_file_or_excludes_packs_everything() {
        // Guards the 051 baseline: absent any ignore input, pack is unchanged.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("plain");
        build_tree(&src);

        let zip_path = tmp.path().join("plain.zip");
        let summary = pack(&src, &zip_path).unwrap();
        assert_eq!(summary.file_count, 4);
        let names = read_entry_names(&zip_path).unwrap();
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"sub/deep/c.txt".to_string()));
        assert!(names.contains(&"empty/".to_string()), "empty dir entry kept: {names:?}");
    }

    /// Hand-crafted zip containing a single STORED entry with the given name —
    /// independent of any writer-side name sanitising.
    fn crafted_zip(name: &str) -> Vec<u8> {
        let data = b"x";
        let name_b = name.as_bytes();
        let mut v: Vec<u8> = Vec::new();
        // Local file header
        v.extend_from_slice(&0x04034b50u32.to_le_bytes());
        v.extend_from_slice(&20u16.to_le_bytes()); // version needed
        v.extend_from_slice(&0u16.to_le_bytes()); // flags
        v.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        v.extend_from_slice(&0u16.to_le_bytes()); // mod time
        v.extend_from_slice(&0u16.to_le_bytes()); // mod date
        v.extend_from_slice(&0u32.to_le_bytes()); // crc (never read: name check aborts first)
        v.extend_from_slice(&(data.len() as u32).to_le_bytes()); // csize
        v.extend_from_slice(&(data.len() as u32).to_le_bytes()); // usize
        v.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // extra len
        v.extend_from_slice(name_b);
        v.extend_from_slice(data);
        let cd_offset = v.len() as u32;
        // Central directory
        v.extend_from_slice(&0x02014b50u32.to_le_bytes());
        v.extend_from_slice(&20u16.to_le_bytes()); // version made by
        v.extend_from_slice(&20u16.to_le_bytes()); // version needed
        v.extend_from_slice(&0u16.to_le_bytes()); // flags
        v.extend_from_slice(&0u16.to_le_bytes()); // method
        v.extend_from_slice(&0u16.to_le_bytes()); // time
        v.extend_from_slice(&0u16.to_le_bytes()); // date
        v.extend_from_slice(&0u32.to_le_bytes()); // crc
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // extra
        v.extend_from_slice(&0u16.to_le_bytes()); // comment
        v.extend_from_slice(&0u16.to_le_bytes()); // disk start
        v.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        v.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        v.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        v.extend_from_slice(name_b);
        let cd_size = v.len() as u32 - cd_offset;
        // End of central directory
        v.extend_from_slice(&0x06054b50u32.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // disk
        v.extend_from_slice(&0u16.to_le_bytes()); // cd disk
        v.extend_from_slice(&1u16.to_le_bytes()); // entries on disk
        v.extend_from_slice(&1u16.to_le_bytes()); // total entries
        v.extend_from_slice(&cd_size.to_le_bytes());
        v.extend_from_slice(&cd_offset.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // comment len
        v
    }

    #[test]
    fn extract_rejects_zip_slip_traversal_with_no_partial_output() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = tmp.path().join("evil.zip");
        let mut f = File::create(&zip_path).unwrap();
        f.write_all(&crafted_zip("../evil.txt")).unwrap();
        drop(f);

        let dest = tmp.path().join("out");
        let err = extract(&zip_path, &dest).unwrap_err();
        assert!(
            format!("{err:#}").to_lowercase().contains("unsafe path"),
            "unexpected error: {err:#}"
        );
        assert!(!dest.exists(), "no partial output may remain after a rejected extract");
        assert!(!tmp.path().join("evil.txt").exists(), "traversal target must not be created");
    }

    #[test]
    fn extract_rejects_absolute_path_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = tmp.path().join("abs.zip");
        fs::write(&zip_path, crafted_zip("/abs-evil.txt")).unwrap();

        let dest = tmp.path().join("out");
        let err = extract(&zip_path, &dest).unwrap_err();
        assert!(format!("{err:#}").to_lowercase().contains("unsafe path"));
        assert!(!dest.exists());
    }

    #[test]
    fn extract_skips_symlink_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = tmp.path().join("withlink.zip");
        {
            let mut zip = ZipWriter::new(BufWriter::new(File::create(&zip_path).unwrap()));
            let opts = SimpleFileOptions::default();
            zip.start_file("ok.txt", opts).unwrap();
            std::io::Write::write_all(&mut zip, b"fine").unwrap();
            zip.add_symlink("evil-link", "/etc/passwd", opts).unwrap();
            zip.finish().unwrap();
        }

        let dest = tmp.path().join("out");
        let summary = extract(&zip_path, &dest).unwrap();
        assert_eq!(summary.file_count, 1);
        assert_eq!(summary.skipped_symlinks, vec![PathBuf::from("evil-link")]);
        assert!(dest.join("ok.txt").exists());
        assert!(
            fs::symlink_metadata(dest.join("evil-link")).is_err(),
            "symlink entry must not be materialised"
        );
    }

    #[test]
    fn extract_into_an_existing_destination_merges_silently() {
        // Task 058 reversal: the old refusal (and the `--force` flag that waived
        // it) are gone — a populated destination is merge-overwritten without
        // complaint, and `get --replace-delete` is what prunes extras.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.txt"), b"new").unwrap();
        let zip_path = tmp.path().join("a.zip");
        pack(&src, &zip_path).unwrap();

        let dest = tmp.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("keep.txt"), b"keep").unwrap();

        let summary = extract(&zip_path, &dest).unwrap();
        assert_eq!(summary.file_count, 1);
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"new");
        assert_eq!(fs::read(dest.join("keep.txt")).unwrap(), b"keep", "extras are kept");
    }

    #[test]
    fn extract_reports_the_relative_paths_it_wrote() {
        // The `written` set is the source list `--replace-delete` diffs against.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("sub/deep")).unwrap();
        fs::create_dir_all(src.join("empty")).unwrap();
        fs::write(src.join("a.txt"), b"a").unwrap();
        fs::write(src.join("sub/deep/c.txt"), b"c").unwrap();
        let zip_path = tmp.path().join("w.zip");
        pack(&src, &zip_path).unwrap();

        let dest = tmp.path().join("dest");
        let summary = extract(&zip_path, &dest).unwrap();
        assert_eq!(
            summary.written.iter().cloned().collect::<Vec<_>>(),
            vec!["a.txt".to_string(), "sub/deep/c.txt".to_string()],
            "forward-slash relative file paths only (no directory entries)"
        );
    }

    #[test]
    fn extract_merges_overwriting_collisions_keeping_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("collide.txt"), b"from-archive").unwrap();
        fs::write(src.join("sub/new.txt"), b"brand-new").unwrap();
        let zip_path = tmp.path().join("m.zip");
        pack(&src, &zip_path).unwrap();

        let dest = tmp.path().join("dest");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("collide.txt"), b"old-local").unwrap();
        fs::write(dest.join("unrelated.txt"), b"mine").unwrap();

        extract(&zip_path, &dest).unwrap();
        // Colliding file overwritten…
        assert_eq!(fs::read(dest.join("collide.txt")).unwrap(), b"from-archive");
        // …new files added…
        assert_eq!(fs::read(dest.join("sub/new.txt")).unwrap(), b"brand-new");
        // …non-colliding existing files kept (merge, not wipe).
        assert_eq!(fs::read(dest.join("unrelated.txt")).unwrap(), b"mine");
    }
}
