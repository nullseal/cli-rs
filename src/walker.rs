//! Ignore rules + deterministic workspace walker (task 052, sync stage 1).
//!
//! `walk(root, extra_excludes)` lists a workspace's files and directories in a
//! deterministic order while honoring gitignore-style exclusions. It is a pure
//! filesystem-read module (no transport, no archive knowledge) shared by
//! `archive::pack` (`share --zip`) and `commands::sync_flow::scan_source`
//! (`share --sync`, task 058), so both folder modes filter identically.
//!
//! Rules (spec `docs/superpowers/specs/2026-07-29-folder-transfer-modes-design.md` §2):
//! - `.nullsealignore` at `root` is honored with full gitignore syntax
//!   (dir patterns `node_modules/`, globs `*.log`, negation `!keep.log`,
//!   anchored nested patterns `sub/build/`), via the pure-Rust `ignore` crate
//!   (ripgrep's engine).
//! - `extra_excludes` are additive: appended after the file's patterns, so they
//!   can also override a `!negation` in the file. The command layer builds this
//!   list in fixed precedence order — each `--exclude-from <FILE>`'s patterns in
//!   argument order, then the `--exclude` patterns (see
//!   `commands::share::resolve_exclude_patterns`). The walker itself never reads
//!   a pattern file: it stays a pure filesystem-read module.
//! - `.gitignore` is deliberately NOT honored — only our file governs. A
//!   workspace's git hygiene and its sync/pack contents are different concerns.
//! - Symlinks are never followed and never listed; non-excluded ones are
//!   collected in `skipped_symlinks` so callers can warn. (An explicitly
//!   excluded symlink is silently dropped like any excluded entry.)
//! - Every directory (including empty ones) yields an `is_dir` entry; an
//!   excluded directory is pruned whole — nothing inside it can re-appear
//!   (git semantics: no re-including inside an excluded directory).
//! - `rel_path` is relative to `root`, forward-slash separated on every
//!   platform. Entries are sorted by `rel_path` (byte order), which places a
//!   directory entry before everything inside it.
//! - `.nullsealignore` itself is an ordinary file: it is listed (and therefore
//!   synced/packed) unless a pattern excludes it.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use ignore::gitignore::{Gitignore, GitignoreBuilder};

/// Name of the ignore file honored at the workspace root.
pub const IGNORE_FILE_NAME: &str = ".nullsealignore";

/// One listed file or directory, relative to the walk root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkEntry {
    /// Path relative to the root, forward-slash separated (`sub/deep/c.txt`).
    pub rel_path: String,
    /// File size in bytes; always 0 for directories.
    pub size: u64,
    /// Unix permission bits (`& 0o777`); fixed 0o755/0o644 on non-unix.
    pub mode: u32,
    /// True for a directory entry (empty directories are included).
    pub is_dir: bool,
}

/// Result of walking a workspace.
#[derive(Debug)]
pub struct WalkSummary {
    /// All non-excluded files and directories, sorted by `rel_path`.
    pub entries: Vec<WalkEntry>,
    /// Non-excluded symlinks encountered (relative, forward-slash) — never
    /// followed, never listed in `entries`; callers warn about these.
    pub skipped_symlinks: Vec<String>,
}

/// Walk `root` deterministically, honoring `.nullsealignore` at `root` plus the
/// additive `extra_excludes` patterns. See the module docs for the full rules.
pub fn walk(root: &Path, extra_excludes: &[String]) -> Result<WalkSummary> {
    let matcher = build_matcher(root, extra_excludes)?;
    let mut summary = WalkSummary { entries: Vec::new(), skipped_symlinks: Vec::new() };
    walk_dir(root, "", &matcher, &mut summary)?;
    // The per-directory name sort already yields a deterministic DFS order;
    // the flat byte-order sort makes the contract independent of walk shape
    // (a directory sorts before everything under it, since "a" < "a/…").
    summary.entries.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    summary.skipped_symlinks.sort();
    Ok(summary)
}

/// Compile `.nullsealignore` (if present at `root`) + `extra_excludes` into one
/// gitignore matcher rooted at `root`. `.gitignore` is never read.
fn build_matcher(root: &Path, extra_excludes: &[String]) -> Result<Gitignore> {
    let mut builder = GitignoreBuilder::new(root);
    let ignore_file = root.join(IGNORE_FILE_NAME);
    if ignore_file.is_file() {
        if let Some(err) = builder.add(&ignore_file) {
            return Err(anyhow::Error::new(err))
                .with_context(|| format!("invalid pattern in \"{}\"", ignore_file.display()));
        }
    }
    // Additive: appended AFTER the file's lines, so a later --exclude wins over
    // an earlier !negation in the file (standard gitignore last-match-wins).
    for pattern in extra_excludes {
        builder
            .add_line(None, pattern)
            .with_context(|| format!("invalid --exclude pattern \"{pattern}\""))?;
    }
    builder.build().context("failed to compile ignore patterns")
}

fn walk_dir(
    dir: &Path,
    prefix: &str,
    matcher: &Gitignore,
    summary: &mut WalkSummary,
) -> Result<()> {
    // Deterministic walk: sort entries by name at every level.
    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("cannot read directory \"{}\"", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("cannot read directory \"{}\"", dir.display()))?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        // symlink_metadata never follows links — a symlink is detected as such
        // even when it points at a directory or outside the tree.
        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot stat \"{}\"", path.display()))?;
        let is_symlink = meta.file_type().is_symlink();
        let is_dir = !is_symlink && meta.is_dir();

        // Excluded → gone silently (a directory is pruned whole: nothing inside
        // an excluded directory can be re-included, matching git semantics).
        if matcher.matched(rel.as_str(), is_dir).is_ignore() {
            continue;
        }

        if is_symlink {
            // Never followed, never listed — collected so callers can warn.
            summary.skipped_symlinks.push(rel);
            continue;
        }

        if is_dir {
            summary.entries.push(WalkEntry {
                rel_path: rel.clone(),
                size: 0,
                mode: mode_of(&meta, true),
                is_dir: true,
            });
            walk_dir(&path, &rel, matcher, summary)?;
        } else {
            summary.entries.push(WalkEntry {
                rel_path: rel,
                size: meta.len(),
                mode: mode_of(&meta, false),
                is_dir: false,
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata, _is_dir: bool) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    // Strip setuid/setgid/sticky — only plain permission bits travel.
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata, is_dir: bool) -> u32 {
    if is_dir {
        0o755
    } else {
        0o644
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn rel_paths(summary: &WalkSummary) -> Vec<&str> {
        summary.entries.iter().map(|e| e.rel_path.as_str()).collect()
    }

    fn file_paths(summary: &WalkSummary) -> Vec<&str> {
        summary
            .entries
            .iter()
            .filter(|e| !e.is_dir)
            .map(|e| e.rel_path.as_str())
            .collect()
    }

    /// Workspace used by the pattern tests:
    ///   root/
    ///     .nullsealignore
    ///     app.log
    ///     keep.log
    ///     node_modules/dep/index.js
    ///     src/main.rs
    ///     src/debug.log
    ///     sub/build/out.bin
    ///     sub/other/data.txt
    fn build_workspace(root: &PathBuf, ignore_lines: &str) {
        fs::create_dir_all(root.join("node_modules/dep")).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("sub/build")).unwrap();
        fs::create_dir_all(root.join("sub/other")).unwrap();
        fs::write(root.join("app.log"), b"log").unwrap();
        fs::write(root.join("keep.log"), b"keep").unwrap();
        fs::write(root.join("node_modules/dep/index.js"), b"js").unwrap();
        fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();
        fs::write(root.join("src/debug.log"), b"dbg").unwrap();
        fs::write(root.join("sub/build/out.bin"), b"bin").unwrap();
        fs::write(root.join("sub/other/data.txt"), b"data").unwrap();
        if !ignore_lines.is_empty() {
            fs::write(root.join(IGNORE_FILE_NAME), ignore_lines).unwrap();
        }
    }

    #[test]
    fn pattern_basics_dir_glob_negation_and_nested() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        build_workspace(&root, "node_modules/\n*.log\n!keep.log\nsub/build/\n");

        let summary = walk(&root, &[]).unwrap();
        let files = file_paths(&summary);

        // Dir pattern prunes the whole subtree — no dir entry, no children.
        assert!(!rel_paths(&summary).iter().any(|p| p.starts_with("node_modules")));
        // Glob applies at every depth.
        assert!(!files.contains(&"app.log"));
        assert!(!files.contains(&"src/debug.log"));
        // Negation re-includes.
        assert!(files.contains(&"keep.log"));
        // Anchored nested dir pattern prunes only that subtree.
        assert!(!rel_paths(&summary).iter().any(|p| p.starts_with("sub/build")));
        assert!(files.contains(&"sub/other/data.txt"));
        // Untouched files survive; the ignore file itself is listed like any file.
        assert!(files.contains(&"src/main.rs"));
        assert!(files.contains(&IGNORE_FILE_NAME));
    }

    #[test]
    fn no_ignore_file_lists_the_full_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        build_workspace(&root, "");

        let summary = walk(&root, &[]).unwrap();
        assert_eq!(
            rel_paths(&summary),
            vec![
                "app.log",
                "keep.log",
                "node_modules",
                "node_modules/dep",
                "node_modules/dep/index.js",
                "src",
                "src/debug.log",
                "src/main.rs",
                "sub",
                "sub/build",
                "sub/build/out.bin",
                "sub/other",
                "sub/other/data.txt",
            ]
        );
    }

    #[test]
    fn extra_excludes_are_additive_to_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        build_workspace(&root, "*.log\n");
        fs::write(root.join("scratch.tmp"), b"tmp").unwrap();

        let summary = walk(&root, &["*.tmp".to_string(), "sub/".to_string()]).unwrap();
        let files = file_paths(&summary);
        // File pattern still applies…
        assert!(!files.contains(&"app.log"));
        // …and both extra patterns apply on top.
        assert!(!files.contains(&"scratch.tmp"));
        assert!(!rel_paths(&summary).iter().any(|p| p.starts_with("sub")));
        assert!(files.contains(&"src/main.rs"));
    }

    #[test]
    fn extra_exclude_overrides_a_file_negation() {
        // Last match wins: --exclude appended after the file can re-exclude
        // what the file's !negation re-included.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        build_workspace(&root, "*.log\n!keep.log\n");

        let summary = walk(&root, &["keep.log".to_string()]).unwrap();
        assert!(!file_paths(&summary).contains(&"keep.log"));
    }

    #[test]
    fn walk_is_deterministic_and_sorted() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        build_workspace(&root, "*.log\n!keep.log\n");

        let a = walk(&root, &[]).unwrap();
        let b = walk(&root, &[]).unwrap();
        assert_eq!(a.entries, b.entries, "two walks must produce identical entries");
        assert_eq!(a.skipped_symlinks, b.skipped_symlinks);

        let mut sorted = a.entries.clone();
        sorted.sort_by(|x, y| x.rel_path.cmp(&y.rel_path));
        assert_eq!(a.entries, sorted, "entries must be sorted by rel_path");
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_never_followed_and_are_collected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("real.txt"), b"real").unwrap();
        // A link inside the tree and a link escaping the tree — both skipped.
        std::os::unix::fs::symlink(root.join("real.txt"), root.join("inner-link")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", root.join("sub/escape-link")).unwrap();

        let summary = walk(&root, &[]).unwrap();
        assert_eq!(file_paths(&summary), vec!["real.txt"]);
        assert_eq!(
            summary.skipped_symlinks,
            vec!["inner-link".to_string(), "sub/escape-link".to_string()]
        );
    }

    #[test]
    fn empty_directories_are_included_as_dir_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(root.join("empty")).unwrap();
        fs::create_dir_all(root.join("sub/also-empty")).unwrap();
        fs::write(root.join("a.txt"), b"x").unwrap();

        let summary = walk(&root, &[]).unwrap();
        let dirs: Vec<&str> = summary
            .entries
            .iter()
            .filter(|e| e.is_dir)
            .map(|e| e.rel_path.as_str())
            .collect();
        assert_eq!(dirs, vec!["empty", "sub", "sub/also-empty"]);
        let empty = summary.entries.iter().find(|e| e.rel_path == "empty").unwrap();
        assert!(empty.is_dir);
        assert_eq!(empty.size, 0);
    }

    #[test]
    fn gitignore_is_not_honored() {
        // Explicit decision: only .nullsealignore governs — a .gitignore in the
        // workspace is packed/synced like any other file and filters nothing.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(".gitignore"), b"secret.txt\n").unwrap();
        fs::write(root.join("secret.txt"), b"still here").unwrap();

        let summary = walk(&root, &[]).unwrap();
        let files = file_paths(&summary);
        assert!(files.contains(&"secret.txt"), ".gitignore must not filter the walk");
        assert!(files.contains(&".gitignore"), ".gitignore is listed like any file");
    }

    #[test]
    fn nullsealignore_can_exclude_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(IGNORE_FILE_NAME), b".nullsealignore\n").unwrap();
        fs::write(root.join("a.txt"), b"x").unwrap();

        let summary = walk(&root, &[]).unwrap();
        assert_eq!(file_paths(&summary), vec!["a.txt"]);
    }

    #[test]
    fn entries_carry_size_and_forward_slash_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(root.join("sub/deep")).unwrap();
        fs::write(root.join("sub/deep/c.txt"), b"gamma").unwrap();

        let summary = walk(&root, &[]).unwrap();
        let c = summary.entries.iter().find(|e| e.rel_path == "sub/deep/c.txt").unwrap();
        assert!(!c.is_dir);
        assert_eq!(c.size, 5);
        assert!(
            summary.entries.iter().all(|e| !e.rel_path.contains('\\')),
            "rel paths must be forward-slash on every platform"
        );
    }

    #[cfg(unix)]
    #[test]
    fn entries_carry_unix_modes() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("script.sh"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(root.join("script.sh"), fs::Permissions::from_mode(0o755)).unwrap();

        let summary = walk(&root, &[]).unwrap();
        let s = summary.entries.iter().find(|e| e.rel_path == "script.sh").unwrap();
        assert_eq!(s.mode, 0o755);
    }

    #[test]
    fn malformed_pattern_is_tolerated_with_gitignore_leniency() {
        // gitignore semantics (the `ignore` crate, same engine git uses the rules
        // of): a malformed glob like the unclosed class "a[" is tolerated, not
        // fatal — verified against the real crate (add_line returns Ok). The
        // build_matcher error path still propagates anything add_line DOES
        // reject, naming the pattern. Leader ruling 2026-07-28 (Mac cargo run):
        // lenient is the engine's native semantic and keeps .nullsealignore and
        // --exclude behaviorally identical.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("afile.txt"), b"x").unwrap();

        let summary = walk(&root, &["a[".to_string()]).unwrap();
        assert!(
            summary.entries.iter().any(|e| e.rel_path == "afile.txt"),
            "a malformed pattern must not exclude anything or abort the walk"
        );
    }
}
