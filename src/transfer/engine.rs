//! Pure decision engines for the direct multi-file transfer (task 058).
//!
//! No I/O: the sender's plan is a function of two manifests, the receiver's
//! verdicts are functions of paths and hashes handed in by the caller. SHA-256
//! lives here because hashing bytes is arithmetic, not I/O — the *reading* of
//! those bytes happens in `commands::sync_flow`.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use super::protocol::{
    ControlFrame, FileEntry, PathHash, TransferError, TransferMode, MANIFEST_BATCH, PROTO_VERSION,
};

/// SHA-256 of `data` as lower-case hex (same encoding as `crypto::sha256_bytes`,
/// duplicated here so the pure module has no dependency on the crypto adapter).
/// One-shot counterpart of [`Hasher`], which the streaming file paths use.
#[allow(dead_code)]
pub fn sha256_hex_bytes(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// Streaming SHA-256 so a large file can be hashed without being buffered whole.
#[derive(Default)]
pub struct Hasher(Sha256);

impl Hasher {
    pub fn new() -> Self {
        Self(Sha256::new())
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    pub fn finish(self) -> String {
        format!("{:x}", self.0.finalize())
    }
}

/// Validate one incoming relative path, mirroring 051's zip-slip guard.
///
/// Rejects absolute paths, `..`, `.`, empty paths and empty components, nul
/// bytes, backslashes (a Windows separator would escape on POSIX and vice versa)
/// and Windows drive prefixes. A rejection aborts the whole run — a partial file
/// is never applied.
pub fn validate_rel_path(path: &str) -> Result<(), TransferError> {
    let bad = |reason: &str| {
        Err(TransferError::UnsafePath { path: path.to_string(), reason: reason.to_string() })
    };
    if path.is_empty() {
        return bad("empty path");
    }
    if path.contains('\0') {
        return bad("nul byte");
    }
    if path.contains('\\') {
        return bad("backslash");
    }
    if path.starts_with('/') {
        return bad("absolute path");
    }
    // C:, c:\… — a drive-qualified path is absolute on Windows.
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return bad("windows drive prefix");
    }
    for component in path.split('/') {
        match component {
            "" => return bad("empty path component"),
            "." => return bad("\".\" component"),
            ".." => return bad("\"..\" traversal"),
            _ => {}
        }
    }
    Ok(())
}

/// Shared hello check: the version must match exactly and the declared mode must
/// be the one this side is running. Used by sender and receiver alike.
pub fn check_hello(
    proto_version: u16,
    mode: TransferMode,
    expected: TransferMode,
) -> Result<(), TransferError> {
    if proto_version != PROTO_VERSION {
        return Err(TransferError::VersionMismatch { ours: PROTO_VERSION, theirs: proto_version });
    }
    if mode != expected {
        return Err(TransferError::ModeMismatch { expected, actual: mode });
    }
    Ok(())
}

/// Our own hello frame.
pub fn hello_frame(mode: TransferMode) -> ControlFrame {
    ControlFrame::Hello { proto_version: PROTO_VERSION, mode }
}

/// What the sender does after a `FileFail`: one retry per file, then abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailAction {
    Retry,
    Abort,
}

/// Sender side: owns the source manifest and derives the transfer plan from the
/// receiver's answer (equal hash → skipped; new/changed → sent; receiver-extra →
/// announced for pruning).
pub struct SenderEngine {
    manifest: Vec<FileEntry>,
    plan: Vec<FileEntry>,
    delete_paths: Vec<String>,
    skipped: usize,
    retried: BTreeSet<String>,
}

impl SenderEngine {
    /// `files` must be sorted+deduplicated by path (the walker guarantees both).
    pub fn new(files: Vec<FileEntry>) -> Self {
        Self {
            manifest: files,
            plan: Vec::new(),
            delete_paths: Vec::new(),
            skipped: 0,
            retried: BTreeSet::new(),
        }
    }

    /// The full source list, split into wire-sized batches. Always sent — even
    /// when the diff turns out empty — because `--replace-delete` cannot compute
    /// the prune set without it (spec §4).
    pub fn manifest_batches(&self) -> Vec<ControlFrame> {
        let total = self.manifest.len();
        if total == 0 {
            return vec![ControlFrame::Manifest { files: Vec::new(), more: false }];
        }
        let mut out = Vec::new();
        let mut sent = 0;
        for batch in self.manifest.chunks(MANIFEST_BATCH) {
            sent += batch.len();
            out.push(ControlFrame::Manifest { files: batch.to_vec(), more: sent < total });
        }
        out
    }

    /// Diff the receiver's `{path, hash}` list against the source manifest.
    pub fn on_manifest_ack(&mut self, remote: &[PathHash]) {
        let remote_map: BTreeMap<&str, &str> =
            remote.iter().map(|p| (p.path.as_str(), p.hash.as_str())).collect();
        let source: BTreeSet<&str> = self.manifest.iter().map(|f| f.path.as_str()).collect();

        self.plan.clear();
        self.skipped = 0;
        for entry in &self.manifest {
            match remote_map.get(entry.path.as_str()) {
                // Equal hash → skipped. This is the whole point of the mode: a
                // steady-state re-run transfers nothing.
                Some(hash) if *hash == entry.hash => self.skipped += 1,
                _ => self.plan.push(entry.clone()),
            }
        }
        self.delete_paths = remote
            .iter()
            .map(|p| p.path.clone())
            .filter(|p| !source.contains(p.as_str()))
            .collect();
        self.delete_paths.sort();
    }

    /// Files that must actually travel, in manifest order.
    pub fn plan(&self) -> &[FileEntry] {
        &self.plan
    }

    /// Destination files absent from the source (the receiver decides whether to
    /// act on them — see [`ReceiverEngine::delete_decision`]).
    pub fn delete_paths(&self) -> &[String] {
        &self.delete_paths
    }

    /// Files the receiver already had byte-identical.
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// Total bytes the plan will move.
    pub fn planned_bytes(&self) -> u64 {
        self.plan.iter().map(|f| f.size).sum()
    }

    /// One retry per file, then a typed abort.
    pub fn on_file_fail(&mut self, path: &str) -> FailAction {
        if self.retried.insert(path.to_string()) {
            FailAction::Retry
        } else {
            FailAction::Abort
        }
    }
}

/// Why a prune request was not carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepReason {
    /// The receiver was not invoked with `--replace-delete`.
    NotRequested,
    /// The sender's manifest was empty while the destination was not — almost
    /// certainly a wrong source directory (spec §4). `--yes` overrides.
    FatFingerGuard,
}

/// Outcome of a `Delete` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteDecision {
    /// Remove exactly these paths.
    Prune(Vec<String>),
    /// Leave `count` stale files in place, for this reason.
    Keep { count: usize, reason: KeepReason },
}

/// Receiver side: validates every incoming path, verifies every file hash, and
/// gates the prune set.
pub struct ReceiverEngine {
    local: Vec<PathHash>,
    allow_delete: bool,
    confirm_delete_all: bool,
    source: BTreeSet<String>,
    manifest_complete: bool,
}

impl ReceiverEngine {
    /// `local` is the destination's current `{path, hash}` list; `allow_delete`
    /// is `--replace-delete`; `confirm_delete_all` is `--yes` (bypasses the
    /// fat-finger guard only).
    pub fn new(local: Vec<PathHash>, allow_delete: bool, confirm_delete_all: bool) -> Self {
        Self {
            local,
            allow_delete,
            confirm_delete_all,
            source: BTreeSet::new(),
            manifest_complete: false,
        }
    }

    /// Version + mode negotiation from the sender's hello.
    pub fn on_hello(&self, proto_version: u16, mode: TransferMode) -> Result<(), TransferError> {
        check_hello(proto_version, mode, TransferMode::Sync)
    }

    /// Accumulate one manifest batch, validating every path up front.
    pub fn on_manifest(&mut self, files: &[FileEntry], more: bool) -> Result<(), TransferError> {
        for f in files {
            validate_rel_path(&f.path)?;
            self.source.insert(f.path.clone());
        }
        if !more {
            self.manifest_complete = true;
        }
        Ok(())
    }

    pub fn manifest_complete(&self) -> bool {
        self.manifest_complete
    }

    /// Number of files the sender declared.
    pub fn source_count(&self) -> usize {
        self.source.len()
    }

    /// Our answer to the manifest, in wire-sized batches.
    pub fn ack_batches(&self) -> Vec<ControlFrame> {
        let total = self.local.len();
        if total == 0 {
            return vec![ControlFrame::ManifestAck { files: Vec::new(), more: false }];
        }
        let mut out = Vec::new();
        let mut sent = 0;
        for batch in self.local.chunks(MANIFEST_BATCH) {
            sent += batch.len();
            out.push(ControlFrame::ManifestAck { files: batch.to_vec(), more: sent < total });
        }
        out
    }

    /// Validate a `FileBegin` path before a single byte is written.
    pub fn on_file_begin(&self, path: &str) -> Result<(), TransferError> {
        validate_rel_path(path)
    }

    /// Verify a finished file: `expected` from `FileEnd`, `actual` computed over
    /// the bytes received.
    pub fn verify(&self, path: &str, expected: &str, actual: &str) -> Result<(), TransferError> {
        if expected == actual {
            Ok(())
        } else {
            Err(TransferError::HashMismatch { path: path.to_string() })
        }
    }

    /// Gate the sender's prune set.
    ///
    /// - Not `--replace-delete` → keep everything (and the caller logs
    ///   "N stale files kept").
    /// - Empty source manifest + non-empty destination → refuse unless `--yes`.
    /// - Any unsafe path in the request aborts the run.
    pub fn delete_decision(&self, requested: &[String]) -> Result<DeleteDecision, TransferError> {
        for p in requested {
            validate_rel_path(p)?;
        }
        if !self.allow_delete {
            return Ok(DeleteDecision::Keep {
                count: requested.len(),
                reason: KeepReason::NotRequested,
            });
        }
        // Fat-finger guard: an empty source against a populated destination is
        // almost always a mistyped source directory, not a request to wipe.
        if self.source.is_empty() && !self.local.is_empty() && !self.confirm_delete_all {
            return Ok(DeleteDecision::Keep {
                count: requested.len(),
                reason: KeepReason::FatFingerGuard,
            });
        }
        Ok(DeleteDecision::Prune(requested.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, hash: &str) -> FileEntry {
        FileEntry { path: path.into(), size: 10, mode: 0o644, hash: hash.into() }
    }
    fn ph(path: &str, hash: &str) -> PathHash {
        PathHash { path: path.into(), hash: hash.into() }
    }
    fn plan_paths(e: &SenderEngine) -> Vec<&str> {
        e.plan().iter().map(|f| f.path.as_str()).collect()
    }

    // ── hashing ──────────────────────────────────────────────────────────

    #[test]
    fn sha256_matches_the_known_vector_and_the_streaming_hasher() {
        // echo -n "abc" | shasum -a 256
        let expect = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(sha256_hex_bytes(b"abc"), expect);
        let mut h = Hasher::new();
        h.update(b"a");
        h.update(b"bc");
        assert_eq!(h.finish(), expect, "streaming must equal one-shot");
    }

    // ── path validation ──────────────────────────────────────────────────

    #[test]
    fn safe_relative_paths_are_accepted() {
        for p in ["a.txt", "sub/b.txt", "sub/deep/c.bin", ".nullsealignore", "tệp.txt", "a..b/c"] {
            validate_rel_path(p).unwrap_or_else(|e| panic!("{p} should be safe: {e}"));
        }
    }

    #[test]
    fn every_unsafe_path_shape_is_rejected() {
        let cases = [
            ("", "empty path"),
            ("/etc/passwd", "absolute path"),
            ("../escape.txt", "\"..\" traversal"),
            ("sub/../../escape.txt", "\"..\" traversal"),
            ("..", "\"..\" traversal"),
            (".", "\".\" component"),
            ("./a.txt", "\".\" component"),
            ("sub//b.txt", "empty path component"),
            ("sub/", "empty path component"),
            ("a\0b", "nul byte"),
            ("sub\\evil.txt", "backslash"),
            ("C:/Windows/x.dll", "windows drive prefix"),
            ("c:evil", "windows drive prefix"),
        ];
        for (path, reason) in cases {
            match validate_rel_path(path) {
                Err(TransferError::UnsafePath { path: p, reason: r }) => {
                    assert_eq!(p, path);
                    assert_eq!(r, reason, "wrong reason for {path:?}");
                }
                other => panic!("{path:?} must be rejected, got {other:?}"),
            }
        }
    }

    // ── hello / version negotiation ──────────────────────────────────────

    #[test]
    fn hello_matches_on_same_version_and_mode() {
        check_hello(PROTO_VERSION, TransferMode::Sync, TransferMode::Sync).unwrap();
        assert_eq!(
            hello_frame(TransferMode::Sync),
            ControlFrame::Hello { proto_version: PROTO_VERSION, mode: TransferMode::Sync }
        );
    }

    #[test]
    fn version_mismatch_aborts_with_a_typed_error() {
        let err = check_hello(PROTO_VERSION + 1, TransferMode::Sync, TransferMode::Sync)
            .unwrap_err();
        assert_eq!(
            err,
            TransferError::VersionMismatch { ours: PROTO_VERSION, theirs: PROTO_VERSION + 1 }
        );
        assert!(err.to_string().contains("Update nullseal on both machines"), "{err}");
    }

    #[test]
    fn mode_mismatch_aborts_with_a_typed_error() {
        // A /sync/ link that reaches a plain file transfer: the hello wins and
        // the mismatch is reported, never guessed at.
        let err = check_hello(PROTO_VERSION, TransferMode::File, TransferMode::Sync).unwrap_err();
        assert_eq!(
            err,
            TransferError::ModeMismatch {
                expected: TransferMode::Sync,
                actual: TransferMode::File,
            }
        );
        let engine = ReceiverEngine::new(vec![], false, false);
        assert!(engine.on_hello(PROTO_VERSION, TransferMode::File).is_err());
        engine.on_hello(PROTO_VERSION, TransferMode::Sync).unwrap();
    }

    // ── the diff matrix ──────────────────────────────────────────────────

    #[test]
    fn diff_covers_new_changed_equal_and_receiver_extra() {
        let mut e = SenderEngine::new(vec![
            f("changed.txt", "h-new"),
            f("equal.txt", "h-same"),
            f("new.txt", "h-new2"),
        ]);
        e.on_manifest_ack(&[
            ph("changed.txt", "h-old"),
            ph("equal.txt", "h-same"),
            ph("stale.txt", "h-stale"),
        ]);
        assert_eq!(plan_paths(&e), vec!["changed.txt", "new.txt"]);
        assert_eq!(e.skipped(), 1);
        assert_eq!(e.delete_paths(), &["stale.txt".to_string()]);
        assert_eq!(e.planned_bytes(), 20);
    }

    #[test]
    fn unchanged_tree_transfers_nothing() {
        let files = vec![f("a.txt", "h1"), f("sub/b.txt", "h2")];
        let mut e = SenderEngine::new(files.clone());
        e.on_manifest_ack(&files.iter().map(|x| ph(&x.path, &x.hash)).collect::<Vec<_>>());
        assert!(e.plan().is_empty(), "an identical tree must plan zero transfers");
        assert_eq!(e.planned_bytes(), 0);
        assert_eq!(e.skipped(), 2);
        assert!(e.delete_paths().is_empty());
    }

    #[test]
    fn empty_receiver_transfers_everything() {
        let mut e = SenderEngine::new(vec![f("a", "h1"), f("b", "h2")]);
        e.on_manifest_ack(&[]);
        assert_eq!(plan_paths(&e), vec!["a", "b"]);
        assert_eq!(e.skipped(), 0);
    }

    #[test]
    fn empty_source_plans_nothing_and_prunes_everything() {
        let mut e = SenderEngine::new(vec![]);
        e.on_manifest_ack(&[ph("x", "h"), ph("y", "h")]);
        assert!(e.plan().is_empty());
        assert_eq!(e.delete_paths(), &["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn manifest_is_batched_and_always_sent() {
        // Empty manifest still produces exactly one terminal frame.
        let e = SenderEngine::new(vec![]);
        assert_eq!(
            e.manifest_batches(),
            vec![ControlFrame::Manifest { files: vec![], more: false }]
        );

        let files: Vec<FileEntry> =
            (0..MANIFEST_BATCH + 3).map(|i| f(&format!("f{i}"), "h")).collect();
        let batches = SenderEngine::new(files).manifest_batches();
        assert_eq!(batches.len(), 2);
        match (&batches[0], &batches[1]) {
            (
                ControlFrame::Manifest { files: a, more: true },
                ControlFrame::Manifest { files: b, more: false },
            ) => {
                assert_eq!(a.len(), MANIFEST_BATCH);
                assert_eq!(b.len(), 3);
            }
            other => panic!("unexpected batching: {other:?}"),
        }
    }

    #[test]
    fn manifest_ack_is_batched_the_same_way() {
        let local: Vec<PathHash> =
            (0..MANIFEST_BATCH + 1).map(|i| ph(&format!("f{i}"), "h")).collect();
        let e = ReceiverEngine::new(local, false, false);
        let batches = e.ack_batches();
        assert_eq!(batches.len(), 2);
        assert!(matches!(batches[0], ControlFrame::ManifestAck { more: true, .. }));
        assert!(matches!(batches[1], ControlFrame::ManifestAck { more: false, .. }));

        let empty = ReceiverEngine::new(vec![], false, false);
        assert_eq!(
            empty.ack_batches(),
            vec![ControlFrame::ManifestAck { files: vec![], more: false }]
        );
    }

    #[test]
    fn receiver_accumulates_batched_manifests_and_rejects_unsafe_paths() {
        let mut e = ReceiverEngine::new(vec![], false, false);
        e.on_manifest(&[f("a", "h")], true).unwrap();
        assert!(!e.manifest_complete());
        e.on_manifest(&[f("b", "h")], false).unwrap();
        assert!(e.manifest_complete());
        assert_eq!(e.source_count(), 2);

        let mut e = ReceiverEngine::new(vec![], false, false);
        let err = e.on_manifest(&[f("../evil", "h")], false).unwrap_err();
        assert!(matches!(err, TransferError::UnsafePath { .. }));
        assert!(!e.manifest_complete(), "a rejected manifest must not complete the run");
    }

    // ── per-file verification / retry ────────────────────────────────────

    #[test]
    fn hash_verification_accepts_equal_and_rejects_different() {
        let e = ReceiverEngine::new(vec![], false, false);
        e.verify("a.txt", "hash", "hash").unwrap();
        assert_eq!(
            e.verify("a.txt", "want", "got").unwrap_err(),
            TransferError::HashMismatch { path: "a.txt".into() }
        );
    }

    #[test]
    fn file_begin_validates_the_path() {
        let e = ReceiverEngine::new(vec![], false, false);
        e.on_file_begin("sub/ok.txt").unwrap();
        assert!(matches!(
            e.on_file_begin("/etc/passwd").unwrap_err(),
            TransferError::UnsafePath { .. }
        ));
    }

    #[test]
    fn a_failed_file_is_retried_once_then_aborts() {
        let mut e = SenderEngine::new(vec![f("a", "h")]);
        assert_eq!(e.on_file_fail("a"), FailAction::Retry);
        assert_eq!(e.on_file_fail("a"), FailAction::Abort);
        // The budget is per file.
        assert_eq!(e.on_file_fail("b"), FailAction::Retry);
    }

    // ── delete gating ────────────────────────────────────────────────────

    #[test]
    fn prune_only_happens_with_replace_delete() {
        let requested = vec!["stale.txt".to_string()];
        let off = ReceiverEngine::new(vec![ph("stale.txt", "h")], false, false);
        assert_eq!(
            off.delete_decision(&requested).unwrap(),
            DeleteDecision::Keep { count: 1, reason: KeepReason::NotRequested }
        );

        let mut on = ReceiverEngine::new(vec![ph("stale.txt", "h")], true, false);
        on.on_manifest(&[f("kept.txt", "h")], false).unwrap();
        assert_eq!(
            on.delete_decision(&requested).unwrap(),
            DeleteDecision::Prune(requested.clone())
        );
    }

    #[test]
    fn fat_finger_guard_refuses_to_wipe_on_an_empty_source() {
        let mut e = ReceiverEngine::new(vec![ph("mine.txt", "h")], true, false);
        e.on_manifest(&[], false).unwrap(); // sender's source was empty
        assert_eq!(
            e.delete_decision(&["mine.txt".to_string()]).unwrap(),
            DeleteDecision::Keep { count: 1, reason: KeepReason::FatFingerGuard }
        );

        // --yes overrides the guard…
        let mut yes = ReceiverEngine::new(vec![ph("mine.txt", "h")], true, true);
        yes.on_manifest(&[], false).unwrap();
        assert_eq!(
            yes.delete_decision(&["mine.txt".to_string()]).unwrap(),
            DeleteDecision::Prune(vec!["mine.txt".to_string()])
        );

        // …and an empty source against an empty destination is not a guard case.
        let mut empty_dest = ReceiverEngine::new(vec![], true, false);
        empty_dest.on_manifest(&[], false).unwrap();
        assert_eq!(empty_dest.delete_decision(&[]).unwrap(), DeleteDecision::Prune(vec![]));
    }

    #[test]
    fn an_unsafe_delete_path_aborts_even_without_replace_delete() {
        let e = ReceiverEngine::new(vec![], false, false);
        assert!(matches!(
            e.delete_decision(&["../../etc/passwd".to_string()]).unwrap_err(),
            TransferError::UnsafePath { .. }
        ));
    }

    // ── two-engine loopback (no I/O): the full converge → re-run story ────

    #[test]
    fn loopback_first_run_transfers_all_then_re_run_transfers_nothing() {
        let source = vec![f("a.txt", "h-a"), f("sub/b.txt", "h-b")];

        // Run 1 — empty destination.
        let mut sender = SenderEngine::new(source.clone());
        let mut receiver = ReceiverEngine::new(vec![], true, false);
        for batch in sender.manifest_batches() {
            if let ControlFrame::Manifest { files, more } = batch {
                receiver.on_manifest(&files, more).unwrap();
            }
        }
        let acks: Vec<PathHash> = receiver
            .ack_batches()
            .into_iter()
            .flat_map(|b| match b {
                ControlFrame::ManifestAck { files, .. } => files,
                _ => vec![],
            })
            .collect();
        sender.on_manifest_ack(&acks);
        assert_eq!(sender.plan().len(), 2);
        assert!(sender.delete_paths().is_empty());

        // Run 2 — destination now mirrors the source, plus one stale extra.
        let mut sender = SenderEngine::new(source.clone());
        let local: Vec<PathHash> = source
            .iter()
            .map(|x| ph(&x.path, &x.hash))
            .chain(std::iter::once(ph("stale.txt", "h-stale")))
            .collect();
        let mut receiver = ReceiverEngine::new(local, true, false);
        for batch in sender.manifest_batches() {
            if let ControlFrame::Manifest { files, more } = batch {
                receiver.on_manifest(&files, more).unwrap();
            }
        }
        let acks: Vec<PathHash> = receiver
            .ack_batches()
            .into_iter()
            .flat_map(|b| match b {
                ControlFrame::ManifestAck { files, .. } => files,
                _ => vec![],
            })
            .collect();
        sender.on_manifest_ack(&acks);
        assert!(sender.plan().is_empty(), "steady state must transfer nothing");
        assert_eq!(sender.planned_bytes(), 0, "zero bytes planned on a re-run");
        assert_eq!(sender.skipped(), 2);
        assert_eq!(
            receiver.delete_decision(sender.delete_paths()).unwrap(),
            DeleteDecision::Prune(vec!["stale.txt".to_string()])
        );
    }
}
