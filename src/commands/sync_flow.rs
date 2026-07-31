//! I/O half of the direct multi-file transfer (task 058): walk + hash the
//! source, stream files through a [`Wire`], write them atomically on the far
//! side, and prune what `--replace-delete` allows.
//!
//! Every protocol decision lives in the pure `crate::transfer` module — this
//! file only turns those decisions into filesystem and DataChannel calls. The
//! split is the same one the P2P v2 engines/adapters use.
//!
//! Frames ride the existing encrypted DataChannel as opaque payload: each frame
//! is length-prefixed by `transfer::protocol`, then sealed with the session's
//! `StreamCipher` (one keyed stream per direction, so nonces never repeat).

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::crypto::{StreamCipher, StreamDecryptor, StreamEncryptionMetadata};
use crate::transfer::engine::{
    hello_frame, DeleteDecision, Hasher, KeepReason, ReceiverEngine, SenderEngine,
};
use crate::transfer::protocol::{
    decode_message, encode_frame, ControlFrame, FileEntry, Frame, PathHash, TransferError,
    TransferMode,
};

/// Suffix of the temp file a received file occupies until its hash verifies.
/// An interrupted run therefore never leaves a truncated file under a real name.
pub const PART_SUFFIX: &str = ".nullseal-part";

/// Receiver-side flags.
#[derive(Clone, Copy, Default, Debug)]
pub struct SyncOptions {
    /// `--replace-delete`: prune destination files absent from the source.
    pub replace_delete: bool,
    /// `--yes`: bypass the empty-source fat-finger guard.
    pub confirm_all: bool,
}

/// What a finished run did — printed by both sides.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncSummary {
    pub files_sent: u64,
    pub bytes: u64,
    pub skipped: u64,
    pub deleted: u64,
    /// Stale destination files left in place (no `--replace-delete`, or the
    /// fat-finger guard fired).
    pub kept: u64,
    /// Files whose write replaced an existing file (receiver side only).
    pub overwritten: u64,
}

// ── Wire ──────────────────────────────────────────────────────────────────────

/// A bidirectional frame channel. Implemented over the real DataChannel peers
/// and over an in-memory pair in tests.
pub trait Wire {
    fn send(&mut self, frame: &Frame) -> impl std::future::Future<Output = Result<()>>;
    /// Next frame from the peer; `Err` when the channel closed or the peer sent
    /// something unparseable.
    fn recv(&mut self) -> impl std::future::Future<Output = Result<Frame>>;
}

/// Per-direction frame sealing: `[frame index u64 BE][AES-GCM ciphertext]`.
///
/// The index is explicit on the wire so decryption never depends on both sides
/// having counted the same number of messages.
pub struct Sealer {
    cipher: StreamCipher,
    index: u64,
}

impl Sealer {
    pub fn new(password: &str) -> Self {
        // total_plaintext_size is only used for the metadata's chunk bookkeeping,
        // which the sync path does not use — the nonce derivation is what matters.
        Self { cipher: StreamCipher::new(password, 0), index: 0 }
    }
    pub fn metadata(&self) -> StreamEncryptionMetadata {
        self.cipher.metadata()
    }
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.cipher.skip_to(self.index);
        let ct = self
            .cipher
            .encrypt_chunk(plaintext)
            .map_err(|e| anyhow::anyhow!("failed to encrypt a transfer frame: {e}"))?;
        let mut out = Vec::with_capacity(8 + ct.len());
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&ct);
        self.index += 1;
        Ok(out)
    }
}

/// The peer's [`Sealer`] counterpart.
pub struct Unsealer(StreamDecryptor);

impl Unsealer {
    pub fn new(meta: &StreamEncryptionMetadata, password: &str) -> Result<Self> {
        Ok(Self(
            StreamDecryptor::from_metadata(meta, password)
                .map_err(|e| anyhow::anyhow!("failed to init the transfer decryptor: {e}"))?,
        ))
    }
    pub fn unseal(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        if msg.len() < 8 {
            bail!("sealed transfer frame is truncated");
        }
        let mut idx = [0u8; 8];
        idx.copy_from_slice(&msg[..8]);
        let index = u64::from_be_bytes(idx);
        self.0
            .decrypt_chunk_at(&msg[8..], index)
            .map_err(|e| anyhow::anyhow!("cannot decrypt transfer frame {index}: {e}"))
    }
}

// ── source / destination scanning ─────────────────────────────────────────────

/// Walk + hash the shared folder. `patterns` is the fully-resolved exclude list
/// (`--exclude-from` files then `--exclude`, see `share::resolve_exclude_patterns`);
/// `.nullsealignore` at the folder root is applied by the walker itself.
///
/// Directories are not manifest entries — the receiver creates parents as needed.
/// Symlinks are skipped and returned so the caller can warn (as 051).
pub fn scan_source(dir: &Path, patterns: &[String]) -> Result<(Vec<FileEntry>, Vec<String>)> {
    let walk = crate::walker::walk(dir, patterns)?;
    let mut files = Vec::new();
    for entry in walk.entries.iter().filter(|e| !e.is_dir) {
        let path = dir.join(&entry.rel_path);
        let hash = hash_file(&path)?;
        files.push(FileEntry {
            path: entry.rel_path.clone(),
            size: entry.size,
            mode: entry.mode,
            hash,
        });
    }
    Ok((files, walk.skipped_symlinks))
}

/// Hash every file already in the destination tree.
///
/// Deliberately does **not** apply ignore rules: a mirror must see everything
/// that is really there, otherwise a `.nullsealignore` copied into the
/// destination would hide files and make them re-transfer on every run. Stale
/// `.nullseal-part` files and symlinks are ignored.
pub fn scan_dest(root: &Path) -> Result<Vec<PathHash>> {
    let mut out = Vec::new();
    if root.is_dir() {
        collect_dest(root, "", &mut out)?;
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn collect_dest(dir: &Path, prefix: &str, out: &mut Vec<PathHash>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("cannot read directory \"{}\"", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("cannot read directory \"{}\"", dir.display()))?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot stat \"{}\"", path.display()))?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_dest(&path, &rel, out)?;
        } else if !name.ends_with(PART_SUFFIX) {
            out.push(PathHash { path: rel, hash: hash_file(&path)? });
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String> {
    let mut f = BufReader::new(
        File::open(path).with_context(|| format!("cannot read \"{}\"", path.display()))?,
    );
    let mut hasher = Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("cannot read \"{}\"", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finish())
}

/// Remove leftover `*.nullseal-part` files from an interrupted run.
pub fn discard_stale_parts(root: &Path) -> Result<usize> {
    let mut removed = 0;
    if root.is_dir() {
        discard_parts_in(root, &mut removed)?;
    }
    Ok(removed)
}

fn discard_parts_in(dir: &Path, removed: &mut usize) -> Result<()> {
    for entry in fs::read_dir(dir)
        .with_context(|| format!("cannot read directory \"{}\"", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            discard_parts_in(&path, removed)?;
        } else if entry.file_name().to_string_lossy().ends_with(PART_SUFFIX) {
            fs::remove_file(&path)?;
            *removed += 1;
        }
    }
    Ok(())
}

// ── sender ────────────────────────────────────────────────────────────────────

/// Drive one whole send: hello → manifest → diff → the changed files → prune
/// announcement → done. Any failure returns `Err` (non-zero exit), which is the
/// documented cron story: re-running resumes, and the hash diff makes the repeat
/// near-free (spec §7.3).
pub async fn run_sender<W: Wire>(
    wire: &mut W,
    source_dir: &Path,
    files: Vec<FileEntry>,
    chunk_size: usize,
) -> Result<SyncSummary> {
    let mut engine = SenderEngine::new(files);

    wire.send(&Frame::Control(hello_frame(TransferMode::Sync))).await?;
    for batch in engine.manifest_batches() {
        wire.send(&Frame::Control(batch)).await?;
    }

    // Await the peer's hello + its complete file list.
    let mut acks: Vec<PathHash> = Vec::new();
    let (mut got_hello, mut got_ack) = (false, false);
    while !(got_hello && got_ack) {
        match wire.recv().await? {
            Frame::Control(ControlFrame::Hello { proto_version, mode }) => {
                if let Err(e) =
                    crate::transfer::engine::check_hello(proto_version, mode, TransferMode::Sync)
                {
                    abort(wire, &e.to_string()).await;
                    return Err(e.into());
                }
                got_hello = true;
            }
            Frame::Control(ControlFrame::ManifestAck { files, more }) => {
                acks.extend(files);
                got_ack = !more;
            }
            Frame::Control(ControlFrame::Abort { reason }) => {
                return Err(TransferError::PeerAbort(reason).into())
            }
            other => return Err(unexpected(&other, "hello/manifest ack")),
        }
    }

    engine.on_manifest_ack(&acks);
    let plan: Vec<FileEntry> = engine.plan().to_vec();
    let delete_paths: Vec<String> = engine.delete_paths().to_vec();
    super::log::step(&format!(
        "Syncing {} file(s) ({}); {} unchanged, {} stale on the receiver",
        plan.len(),
        super::format_size(engine.planned_bytes() as usize),
        engine.skipped(),
        delete_paths.len(),
    ));

    let mut summary = SyncSummary {
        skipped: engine.skipped() as u64,
        kept: delete_paths.len() as u64,
        ..Default::default()
    };

    for entry in &plan {
        loop {
            let sent = send_one_file(wire, source_dir, entry, chunk_size).await?;
            match wire.recv().await? {
                Frame::Control(ControlFrame::FileOk { .. }) => {
                    summary.files_sent += 1;
                    summary.bytes += sent;
                    super::display::transfer_progress(
                        summary.bytes as usize,
                        engine.planned_bytes() as usize,
                    );
                    break;
                }
                Frame::Control(ControlFrame::FileFail { path, reason }) => {
                    super::display::warn(&format!("Receiver rejected \"{path}\": {reason}"));
                    match engine.on_file_fail(&path) {
                        crate::transfer::engine::FailAction::Retry => {
                            super::log::step(&format!("Retrying \"{path}\"…"));
                            continue;
                        }
                        crate::transfer::engine::FailAction::Abort => {
                            let msg = format!("\"{path}\" failed twice: {reason}");
                            abort(wire, &msg).await;
                            bail!("Transfer aborted — {msg}");
                        }
                    }
                }
                Frame::Control(ControlFrame::Abort { reason }) => {
                    return Err(TransferError::PeerAbort(reason).into())
                }
                other => return Err(unexpected(&other, "file ack")),
            }
        }
    }

    if !delete_paths.is_empty() {
        wire.send(&Frame::Control(ControlFrame::Delete { paths: delete_paths })).await?;
    }
    wire.send(&Frame::Control(ControlFrame::Done {
        files_sent: summary.files_sent,
        bytes: summary.bytes,
        deleted: 0,
        skipped: summary.skipped,
    }))
    .await?;

    // The receiver's own Done carries what it actually deleted.
    loop {
        match wire.recv().await? {
            Frame::Control(ControlFrame::Done { deleted, .. }) => {
                summary.deleted = deleted;
                summary.kept = summary.kept.saturating_sub(deleted);
                break;
            }
            Frame::Control(ControlFrame::Abort { reason }) => {
                return Err(TransferError::PeerAbort(reason).into())
            }
            // A late FileOk (retry raced) is harmless — keep waiting for Done.
            Frame::Control(ControlFrame::FileOk { .. }) => continue,
            other => return Err(unexpected(&other, "done")),
        }
    }
    Ok(summary)
}

async fn send_one_file<W: Wire>(
    wire: &mut W,
    source_dir: &Path,
    entry: &FileEntry,
    chunk_size: usize,
) -> Result<u64> {
    let path = source_dir.join(&entry.path);
    let mut f = BufReader::new(
        File::open(&path).with_context(|| format!("cannot read \"{}\"", path.display()))?,
    );
    wire.send(&Frame::Control(ControlFrame::FileBegin {
        path: entry.path.clone(),
        size: entry.size,
        mode: entry.mode,
    }))
    .await?;

    let mut hasher = Hasher::new();
    let mut buf = vec![0u8; chunk_size];
    let mut total = 0u64;
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("cannot read \"{}\"", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
        wire.send(&Frame::Chunk(buf[..n].to_vec())).await?;
    }
    // The hash is recomputed while streaming rather than reused from the scan:
    // the file may have changed since it was walked, and the receiver must verify
    // what actually travelled.
    wire.send(&Frame::Control(ControlFrame::FileEnd { hash: hasher.finish() })).await?;
    Ok(total)
}

// ── receiver ──────────────────────────────────────────────────────────────────

/// One file being written to its `.nullseal-part` temp name.
struct PartFile {
    rel: String,
    part: PathBuf,
    target: PathBuf,
    file: File,
    hasher: Hasher,
    mode: u32,
    existed: bool,
}

/// Drive one whole receive into `dest_root`. Files are written to
/// `.nullseal-part` temp names and atomically renamed only after their hash
/// verifies; a populated destination is merge-overwritten silently (spec §3), and
/// extras are only removed with `--replace-delete`.
pub async fn run_receiver<W: Wire>(
    wire: &mut W,
    dest_root: &Path,
    opts: SyncOptions,
) -> Result<SyncSummary> {
    fs::create_dir_all(dest_root)
        .with_context(|| format!("cannot create destination \"{}\"", dest_root.display()))?;
    let stale = discard_stale_parts(dest_root)?;
    if stale > 0 {
        super::log::event(&format!("discarded {stale} stale .nullseal-part file(s)"));
    }
    let local = scan_dest(dest_root)?;
    let mut engine = ReceiverEngine::new(local, opts.replace_delete, opts.confirm_all);

    wire.send(&Frame::Control(hello_frame(TransferMode::Sync))).await?;

    let mut summary = SyncSummary::default();
    let mut current: Option<PartFile> = None;
    let mut acked = false;

    let result: Result<()> = async {
        loop {
            match wire.recv().await? {
                Frame::Control(ControlFrame::Hello { proto_version, mode }) => {
                    if let Err(e) = engine.on_hello(proto_version, mode) {
                        abort(wire, &e.to_string()).await;
                        return Err(e.into());
                    }
                }
                Frame::Control(ControlFrame::Manifest { files, more }) => {
                    if let Err(e) = engine.on_manifest(&files, more) {
                        abort(wire, &e.to_string()).await;
                        return Err(e.into());
                    }
                    if engine.manifest_complete() && !acked {
                        acked = true;
                        super::log::event(&format!(
                            "sender declared {} file(s)",
                            engine.source_count()
                        ));
                        for batch in engine.ack_batches() {
                            wire.send(&Frame::Control(batch)).await?;
                        }
                    }
                }
                Frame::Control(ControlFrame::FileBegin { path, size, mode }) => {
                    if let Err(e) = engine.on_file_begin(&path) {
                        abort(wire, &e.to_string()).await;
                        return Err(e.into());
                    }
                    let target = dest_root.join(&path);
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent).with_context(|| {
                            format!("cannot create \"{}\"", parent.display())
                        })?;
                    }
                    let part = with_part_suffix(&target);
                    let file = File::create(&part)
                        .with_context(|| format!("cannot write \"{}\"", part.display()))?;
                    super::log::event(&format!(
                        "receiving {path} ({})",
                        super::format_size(size as usize)
                    ));
                    current = Some(PartFile {
                        rel: path,
                        existed: target.exists(),
                        target,
                        part,
                        file,
                        hasher: Hasher::new(),
                        mode,
                    });
                }
                Frame::Chunk(bytes) => {
                    let Some(part) = current.as_mut() else {
                        let e = TransferError::Unexpected("file chunk before FileBegin".into());
                        abort(wire, &e.to_string()).await;
                        return Err(e.into());
                    };
                    part.file
                        .write_all(&bytes)
                        .with_context(|| format!("cannot write \"{}\"", part.part.display()))?;
                    part.hasher.update(&bytes);
                }
                Frame::Control(ControlFrame::FileEnd { hash }) => {
                    let Some(part) = current.take() else {
                        let e = TransferError::Unexpected("FileEnd before FileBegin".into());
                        abort(wire, &e.to_string()).await;
                        return Err(e.into());
                    };
                    match commit_part(&engine, part, &hash) {
                        Ok((rel, bytes, existed)) => {
                            summary.files_sent += 1;
                            summary.bytes += bytes;
                            if existed {
                                summary.overwritten += 1;
                            }
                            wire.send(&Frame::Control(ControlFrame::FileOk { path: rel })).await?;
                        }
                        Err((rel, reason)) => {
                            wire.send(&Frame::Control(ControlFrame::FileFail {
                                path: rel,
                                reason,
                            }))
                            .await?;
                        }
                    }
                }
                Frame::Control(ControlFrame::Delete { paths }) => {
                    match engine.delete_decision(&paths) {
                        Ok(DeleteDecision::Prune(list)) => {
                            summary.deleted = prune(dest_root, &list)? as u64;
                        }
                        Ok(DeleteDecision::Keep { count, reason }) => {
                            summary.kept = count as u64;
                            match reason {
                                KeepReason::NotRequested => super::log::step(&format!(
                                    "{count} stale file(s) kept (pass --replace-delete to mirror deletions)"
                                )),
                                KeepReason::FatFingerGuard => super::display::warn(&format!(
                                    "Refusing to delete {count} file(s): the sender's file list is empty while \"{}\" is not. Re-run with --yes if that is really intended.",
                                    dest_root.display()
                                )),
                            }
                        }
                        Err(e) => {
                            abort(wire, &e.to_string()).await;
                            return Err(e.into());
                        }
                    }
                }
                Frame::Control(ControlFrame::Done { skipped, .. }) => {
                    summary.skipped = skipped;
                    wire.send(&Frame::Control(ControlFrame::Done {
                        files_sent: summary.files_sent,
                        bytes: summary.bytes,
                        deleted: summary.deleted,
                        skipped: summary.skipped,
                    }))
                    .await?;
                    return Ok(());
                }
                Frame::Control(ControlFrame::Abort { reason }) => {
                    return Err(TransferError::PeerAbort(reason).into())
                }
                other => {
                    let e = TransferError::Unexpected(frame_label(&other));
                    abort(wire, &e.to_string()).await;
                    return Err(e.into());
                }
            }
        }
    }
    .await;

    // Never leave a truncated file behind under a real name, on any exit path.
    if let Some(part) = current.take() {
        drop(part.file);
        let _ = fs::remove_file(&part.part);
    }
    result?;
    Ok(summary)
}

/// Verify a finished part file and atomically move it into place.
/// `Err((rel, reason))` means the file was discarded and a `FileFail` is due.
fn commit_part(
    engine: &ReceiverEngine,
    part: PartFile,
    expected_hash: &str,
) -> std::result::Result<(String, u64, bool), (String, String)> {
    let PartFile { rel, part: part_path, target, file, hasher, mode, existed } = part;
    let bytes = file.metadata().map(|m| m.len()).unwrap_or(0);
    if let Err(e) = file.sync_all() {
        let _ = fs::remove_file(&part_path);
        return Err((rel, format!("cannot flush the received file: {e}")));
    }
    drop(file);

    let actual = hasher.finish();
    if let Err(e) = engine.verify(&rel, expected_hash, &actual) {
        let _ = fs::remove_file(&part_path);
        return Err((rel, e.to_string()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&part_path, fs::Permissions::from_mode(mode & 0o777));
    }
    #[cfg(not(unix))]
    let _ = mode;
    if let Err(e) = fs::rename(&part_path, &target) {
        let _ = fs::remove_file(&part_path);
        return Err((rel, format!("cannot move the file into place: {e}")));
    }
    Ok((rel, bytes, existed))
}

fn with_part_suffix(target: &Path) -> PathBuf {
    let mut name = target.file_name().unwrap_or_default().to_os_string();
    name.push(PART_SUFFIX);
    target.with_file_name(name)
}

/// Delete the pruned paths (files only; the caller has already gated this).
pub fn prune(root: &Path, paths: &[String]) -> Result<usize> {
    let mut deleted = 0;
    for rel in paths {
        let path = root.join(rel);
        match fs::remove_file(&path) {
            Ok(()) => {
                super::log::event(&format!("deleted {rel}"));
                deleted += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                super::display::warn(&format!("Cannot delete \"{}\": {e}", path.display()));
            }
        }
    }
    Ok(deleted)
}

/// `--replace-delete` on a **zip** folder share: after extraction, remove
/// destination files that the archive did not contain (spec §3).
pub fn prune_extras(dest: &Path, kept: &BTreeSet<String>) -> Result<usize> {
    let extras: Vec<String> = scan_dest(dest)?
        .into_iter()
        .map(|p| p.path)
        .filter(|p| !kept.contains(p))
        .collect();
    prune(dest, &extras)
}

// ── shared helpers ────────────────────────────────────────────────────────────

async fn abort<W: Wire>(wire: &mut W, reason: &str) {
    let _ = wire.send(&Frame::Control(ControlFrame::Abort { reason: reason.to_string() })).await;
}

fn frame_label(frame: &Frame) -> String {
    match frame {
        Frame::Chunk(b) => format!("unexpected {}-byte chunk", b.len()),
        Frame::Control(c) => format!("unexpected control frame {c:?}"),
    }
}

fn unexpected(frame: &Frame, expecting: &str) -> anyhow::Error {
    TransferError::Unexpected(format!("{} while expecting {expecting}", frame_label(frame))).into()
}

/// Format the mandatory run summary. Always names the destination — the only
/// mitigation for a mistyped `-o` now that a populated destination is accepted
/// silently (spec §3).
pub fn format_receiver_summary(dest: &Path, s: &SyncSummary) -> String {
    format!(
        "Synced into {} — {} written ({} overwritten), {} unchanged, {} deleted, {} stale kept",
        dest.display(),
        s.files_sent,
        s.overwritten,
        s.skipped,
        s.deleted,
        s.kept,
    )
}

/// Sender-side counterpart of [`format_receiver_summary`].
pub fn format_sender_summary(source: &Path, s: &SyncSummary) -> String {
    format!(
        "Synced {} — {} file(s) sent ({}), {} unchanged, {} deleted, {} stale kept",
        source.display(),
        s.files_sent,
        super::format_size(s.bytes as usize),
        s.skipped,
        s.deleted,
        s.kept,
    )
}

// ── real DataChannel wires ────────────────────────────────────────────────────

/// Sender-side wire over the WebRTC DataChannel.
pub struct SenderWire<'a> {
    pub peer: &'a mut crate::webrtc::SenderPeer,
    pub sealer: Sealer,
    pub unsealer: Unsealer,
}

impl Wire for SenderWire<'_> {
    async fn send(&mut self, frame: &Frame) -> Result<()> {
        let sealed = self.sealer.seal(&encode_frame(frame)?)?;
        self.peer.send_binary(sealed).await
    }
    async fn recv(&mut self) -> Result<Frame> {
        loop {
            match self.peer.next_event().await {
                Some(crate::webrtc::LoopEvent::BinaryData(data)) => {
                    return Ok(decode_message(&self.unsealer.unseal(&data)?)?)
                }
                Some(crate::webrtc::LoopEvent::Message(_)) => continue,
                Some(crate::webrtc::LoopEvent::Error(e)) => {
                    bail!("WebRTC error during transfer: {e}")
                }
                Some(crate::webrtc::LoopEvent::Done) | None => {
                    bail!("DataChannel closed before the transfer finished")
                }
                _ => continue,
            }
        }
    }
}

/// Receiver-side wire over the WebRTC DataChannel.
pub struct ReceiverWire<'a> {
    pub peer: &'a mut crate::webrtc::ReceiverPeer,
    pub sealer: Sealer,
    pub unsealer: Unsealer,
}

impl Wire for ReceiverWire<'_> {
    async fn send(&mut self, frame: &Frame) -> Result<()> {
        let sealed = self.sealer.seal(&encode_frame(frame)?)?;
        self.peer.send_binary(sealed).await
    }
    async fn recv(&mut self) -> Result<Frame> {
        loop {
            match self.peer.next_event().await {
                Some(crate::webrtc::LoopEvent::BinaryData(data)) => {
                    return Ok(decode_message(&self.unsealer.unseal(&data)?)?)
                }
                Some(crate::webrtc::LoopEvent::Message(_)) => continue,
                Some(crate::webrtc::LoopEvent::Error(e)) => {
                    bail!("WebRTC error during transfer: {e}")
                }
                Some(crate::webrtc::LoopEvent::Done) | None => {
                    bail!("DataChannel closed before the transfer finished")
                }
                _ => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

    /// In-memory wire pair. Frames go through the real `encode_frame` /
    /// `decode_message`, so framing is exercised; sealing is covered separately
    /// (it would cost two PBKDF2 derivations per test).
    struct Loopback {
        tx: UnboundedSender<Vec<u8>>,
        rx: UnboundedReceiver<Vec<u8>>,
        /// Bytes of file payload this side put on the wire — the assertion that
        /// a steady-state re-run moves nothing.
        chunk_bytes: Arc<AtomicU64>,
        chunk_frames: Arc<AtomicU64>,
    }

    fn loopback_pair() -> (Loopback, Loopback) {
        let (a_tx, b_rx) = unbounded_channel();
        let (b_tx, a_rx) = unbounded_channel();
        (
            Loopback {
                tx: a_tx,
                rx: a_rx,
                chunk_bytes: Arc::new(AtomicU64::new(0)),
                chunk_frames: Arc::new(AtomicU64::new(0)),
            },
            Loopback {
                tx: b_tx,
                rx: b_rx,
                chunk_bytes: Arc::new(AtomicU64::new(0)),
                chunk_frames: Arc::new(AtomicU64::new(0)),
            },
        )
    }

    impl Wire for Loopback {
        async fn send(&mut self, frame: &Frame) -> Result<()> {
            if let Frame::Chunk(b) = frame {
                self.chunk_bytes.fetch_add(b.len() as u64, Ordering::Relaxed);
                self.chunk_frames.fetch_add(1, Ordering::Relaxed);
            }
            let bytes = encode_frame(frame)?;
            self.tx.send(bytes).map_err(|_| anyhow::anyhow!("loopback closed"))
        }
        async fn recv(&mut self) -> Result<Frame> {
            match self.rx.recv().await {
                Some(bytes) => Ok(decode_message(&bytes)?),
                None => bail!("loopback closed"),
            }
        }
    }

    /// Run a whole sender+receiver session concurrently over a loopback pair.
    /// Returns both summaries plus the byte/frame counters the sender produced.
    async fn sync_once(
        source: &Path,
        dest: &Path,
        opts: SyncOptions,
    ) -> Result<(SyncSummary, SyncSummary, u64, u64)> {
        let (mut a, mut b) = loopback_pair();
        let bytes = a.chunk_bytes.clone();
        let frames = a.chunk_frames.clone();
        let (files, _) = scan_source(source, &[])?;
        let src = source.to_path_buf();
        let dst = dest.to_path_buf();
        let send = async move { run_sender(&mut a, &src, files, 16 * 1024).await };
        let recv = async move { run_receiver(&mut b, &dst, opts).await };
        let (s, r) = tokio::join!(send, recv);
        Ok((s?, r?, bytes.load(Ordering::Relaxed), frames.load(Ordering::Relaxed)))
    }

    fn write(path: &Path, body: &[u8]) {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn fixture(root: &Path) {
        write(&root.join("a.txt"), b"alpha");
        write(&root.join("sub/b.txt"), b"beta");
        write(&root.join("sub/deep/c.bin"), &vec![7u8; 40_000]);
    }

    #[tokio::test]
    async fn first_run_materialises_the_whole_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fixture(&src);

        let (s, r, bytes, _) = sync_once(&src, &dst, SyncOptions::default()).await.unwrap();
        assert_eq!(s.files_sent, 3);
        assert_eq!(r.files_sent, 3);
        assert_eq!(s.skipped, 0);
        assert_eq!(bytes, 5 + 4 + 40_000);
        assert_eq!(fs::read(dst.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(dst.join("sub/b.txt")).unwrap(), b"beta");
        assert_eq!(fs::read(dst.join("sub/deep/c.bin")).unwrap(), vec![7u8; 40_000]);
        // No temp files survive a clean run.
        assert!(scan_dest(&dst).unwrap().iter().all(|p| !p.path.ends_with(PART_SUFFIX)));
    }

    #[tokio::test]
    async fn re_run_over_an_unchanged_tree_transfers_zero_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fixture(&src);
        sync_once(&src, &dst, SyncOptions::default()).await.unwrap();

        // Second run: same tree on both sides.
        let (s, r, bytes, frames) = sync_once(&src, &dst, SyncOptions::default()).await.unwrap();
        assert_eq!(frames, 0, "no chunk frame may be sent for an unchanged tree");
        assert_eq!(bytes, 0, "no file bytes may cross the wire on a steady-state re-run");
        assert_eq!(s.files_sent, 0);
        assert_eq!(s.bytes, 0);
        assert_eq!(s.skipped, 3);
        assert_eq!(r.files_sent, 0);
        assert_eq!(r.overwritten, 0);
        // The destination is still intact.
        assert_eq!(fs::read(dst.join("sub/b.txt")).unwrap(), b"beta");
    }

    #[tokio::test]
    async fn only_changed_and_new_files_travel_on_a_re_run() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fixture(&src);
        sync_once(&src, &dst, SyncOptions::default()).await.unwrap();

        write(&src.join("sub/b.txt"), b"beta-changed");
        write(&src.join("new.txt"), b"n");
        let (s, r, bytes, _) = sync_once(&src, &dst, SyncOptions::default()).await.unwrap();
        assert_eq!(s.files_sent, 2, "only the changed + new file");
        assert_eq!(s.skipped, 2);
        assert_eq!(bytes, "beta-changed".len() as u64 + 1);
        assert_eq!(r.overwritten, 1, "the changed file replaced an existing one");
        assert_eq!(fs::read(dst.join("sub/b.txt")).unwrap(), b"beta-changed");
        assert_eq!(fs::read(dst.join("new.txt")).unwrap(), b"n");
    }

    #[tokio::test]
    async fn a_populated_destination_is_merge_overwritten_silently() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fixture(&src);
        write(&dst.join("a.txt"), b"mine-old");
        write(&dst.join("unrelated.txt"), b"keep me");

        let (_, r, _, _) = sync_once(&src, &dst, SyncOptions::default()).await.unwrap();
        assert_eq!(fs::read(dst.join("a.txt")).unwrap(), b"alpha", "collision overwritten");
        assert_eq!(
            fs::read(dst.join("unrelated.txt")).unwrap(),
            b"keep me",
            "extras are left alone without --replace-delete"
        );
        assert_eq!(r.kept, 1, "the stale extra is reported, not deleted");
        assert_eq!(r.overwritten, 1);
    }

    #[tokio::test]
    async fn replace_delete_prunes_destination_extras() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fixture(&src);
        write(&dst.join("stale.txt"), b"gone soon");
        write(&dst.join("old/deep.txt"), b"gone too");

        let opts = SyncOptions { replace_delete: true, confirm_all: false };
        let (s, r, _, _) = sync_once(&src, &dst, opts).await.unwrap();
        assert_eq!(r.deleted, 2);
        assert_eq!(s.deleted, 2, "the sender's summary reflects the receiver's deletions");
        assert!(!dst.join("stale.txt").exists());
        assert!(!dst.join("old/deep.txt").exists());
        assert!(dst.join("a.txt").exists());
    }

    #[tokio::test]
    async fn fat_finger_guard_keeps_files_when_the_source_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("empty-src");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(&src).unwrap();
        write(&dst.join("precious.txt"), b"do not delete");

        let opts = SyncOptions { replace_delete: true, confirm_all: false };
        let (_, r, _, _) = sync_once(&src, &dst, opts).await.unwrap();
        assert_eq!(r.deleted, 0);
        assert_eq!(r.kept, 1);
        assert_eq!(fs::read(dst.join("precious.txt")).unwrap(), b"do not delete");

        // --yes overrides the guard.
        let opts = SyncOptions { replace_delete: true, confirm_all: true };
        let (_, r, _, _) = sync_once(&src, &dst, opts).await.unwrap();
        assert_eq!(r.deleted, 1);
        assert!(!dst.join("precious.txt").exists());
    }

    #[tokio::test]
    async fn an_unsafe_path_aborts_the_run_with_nothing_written() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("dst");
        let (mut a, mut b) = loopback_pair();
        let dst2 = dst.clone();
        let recv = tokio::spawn(async move {
            run_receiver(&mut b, &dst2, SyncOptions::default()).await.map(|_| ())
        });

        a.send(&Frame::Control(hello_frame(TransferMode::Sync))).await.unwrap();
        a.send(&Frame::Control(ControlFrame::Manifest {
            files: vec![FileEntry {
                path: "../escape.txt".into(),
                size: 1,
                mode: 0o644,
                hash: "h".into(),
            }],
            more: false,
        }))
        .await
        .unwrap();

        let err = recv.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("unsafe path"), "{err}");
        assert!(!tmp.path().join("escape.txt").exists());
        assert!(scan_dest(&dst).unwrap().is_empty(), "nothing may be written");
        // …and the receiver told the peer why (after its own hello).
        let mut aborted = None;
        while let Ok(frame) = a.recv().await {
            if let Frame::Control(ControlFrame::Abort { reason }) = frame {
                aborted = Some(reason);
                break;
            }
        }
        let reason = aborted.expect("the receiver must send a typed abort");
        assert!(reason.contains("escape.txt"), "{reason}");
    }

    #[tokio::test]
    async fn a_version_mismatch_aborts_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("dst");
        let (mut a, mut b) = loopback_pair();
        let dst2 = dst.clone();
        let recv = tokio::spawn(async move {
            run_receiver(&mut b, &dst2, SyncOptions::default()).await.map(|_| ())
        });
        a.send(&Frame::Control(ControlFrame::Hello {
            proto_version: 99,
            mode: TransferMode::Sync,
        }))
        .await
        .unwrap();
        let err = recv.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("version mismatch"), "{err}");
    }

    #[tokio::test]
    async fn a_hash_mismatch_is_rejected_and_leaves_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("dst");
        let (mut a, mut b) = loopback_pair();
        let dst2 = dst.clone();
        let recv = tokio::spawn(async move { run_receiver(&mut b, &dst2, SyncOptions::default()).await });

        a.send(&Frame::Control(hello_frame(TransferMode::Sync))).await.unwrap();
        a.send(&Frame::Control(ControlFrame::Manifest { files: vec![], more: false }))
            .await
            .unwrap();
        // Drain the receiver's hello + ack.
        for _ in 0..2 {
            a.recv().await.unwrap();
        }
        a.send(&Frame::Control(ControlFrame::FileBegin {
            path: "corrupt.txt".into(),
            size: 3,
            mode: 0o644,
        }))
        .await
        .unwrap();
        a.send(&Frame::Chunk(b"abc".to_vec())).await.unwrap();
        a.send(&Frame::Control(ControlFrame::FileEnd { hash: "not-the-hash".into() }))
            .await
            .unwrap();
        match a.recv().await.unwrap() {
            Frame::Control(ControlFrame::FileFail { path, reason }) => {
                assert_eq!(path, "corrupt.txt");
                assert!(reason.contains("hash mismatch"), "{reason}");
            }
            other => panic!("expected FileFail, got {other:?}"),
        }
        assert!(!dst.join("corrupt.txt").exists(), "a failed file is never committed");
        assert!(
            !with_part_suffix(&dst.join("corrupt.txt")).exists(),
            "the temp part must be discarded"
        );

        a.send(&Frame::Control(ControlFrame::Done {
            files_sent: 0,
            bytes: 0,
            deleted: 0,
            skipped: 0,
        }))
        .await
        .unwrap();
        let summary = recv.await.unwrap().unwrap();
        assert_eq!(summary.files_sent, 0);
    }

    #[tokio::test]
    async fn stale_part_files_are_discarded_on_startup() {
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("dst");
        write(&dst.join("keep.txt"), b"k");
        write(&dst.join(format!("interrupted.txt{PART_SUFFIX}")), b"half");
        write(&dst.join(format!("sub/deep.bin{PART_SUFFIX}")), b"half");

        assert_eq!(discard_stale_parts(&dst).unwrap(), 2);
        assert!(!dst.join(format!("interrupted.txt{PART_SUFFIX}")).exists());
        assert!(dst.join("keep.txt").exists());
        // A stale part never counts as destination content for the diff.
        assert_eq!(
            scan_dest(&dst).unwrap().iter().map(|p| p.path.clone()).collect::<Vec<_>>(),
            vec!["keep.txt".to_string()]
        );
    }

    #[test]
    fn scan_source_hashes_files_skips_dirs_and_reports_excludes() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fixture(&src);
        fs::create_dir_all(src.join("emptydir")).unwrap();
        write(&src.join("skip.log"), b"noise");

        let (files, links) = scan_source(&src, &["*.log".to_string()]).unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["a.txt", "sub/b.txt", "sub/deep/c.bin"]);
        assert!(links.is_empty());
        let a = files.iter().find(|f| f.path == "a.txt").unwrap();
        assert_eq!(a.size, 5);
        assert_eq!(a.hash, crate::transfer::engine::sha256_hex_bytes(b"alpha"));
    }

    #[test]
    fn scan_dest_ignores_a_nullsealignore_in_the_destination() {
        // A mirror must see everything really present: an ignore file that
        // travelled with the sync must not hide destination files from the diff.
        let tmp = tempfile::tempdir().unwrap();
        let dst = tmp.path().join("dst");
        write(&dst.join(".nullsealignore"), b"*.log\n");
        write(&dst.join("app.log"), b"x");
        let paths: Vec<String> = scan_dest(&dst).unwrap().into_iter().map(|p| p.path).collect();
        assert_eq!(paths, vec![".nullsealignore".to_string(), "app.log".to_string()]);
    }

    #[test]
    fn sealed_frames_round_trip_and_reject_a_wrong_password() {
        let mut sealer = Sealer::new("sync-password");
        let meta = sealer.metadata();
        let f1 = sealer.seal(b"frame one").unwrap();
        let f2 = sealer.seal(b"frame two").unwrap();
        assert_ne!(&f1[8..], &f2[8..], "each frame gets its own nonce");
        assert_eq!(&f1[..8], &0u64.to_be_bytes());
        assert_eq!(&f2[..8], &1u64.to_be_bytes());

        let mut unsealer = Unsealer::new(&meta, "sync-password").unwrap();
        assert_eq!(unsealer.unseal(&f1).unwrap(), b"frame one");
        assert_eq!(unsealer.unseal(&f2).unwrap(), b"frame two");

        let mut wrong = Unsealer::new(&meta, "not-the-password").unwrap();
        assert!(wrong.unseal(&f1).is_err());
        // A truncated envelope is a clean error, never a panic.
        assert!(Unsealer::new(&meta, "sync-password").unwrap().unseal(&[0u8; 4]).is_err());
    }

    #[test]
    fn prune_extras_removes_only_what_the_archive_did_not_contain() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("proj");
        write(&dest.join("readme.txt"), b"r");
        write(&dest.join("sub/keep.txt"), b"k");
        write(&dest.join("stale.txt"), b"s");

        let kept: BTreeSet<String> =
            ["readme.txt".to_string(), "sub/keep.txt".to_string()].into_iter().collect();
        assert_eq!(prune_extras(&dest, &kept).unwrap(), 1);
        assert!(dest.join("readme.txt").exists());
        assert!(dest.join("sub/keep.txt").exists());
        assert!(!dest.join("stale.txt").exists());
    }

    #[test]
    fn summaries_name_the_destination_and_the_counts() {
        let s = SyncSummary {
            files_sent: 2,
            bytes: 2048,
            skipped: 5,
            deleted: 1,
            kept: 0,
            overwritten: 1,
        };
        let text = format_receiver_summary(Path::new("/tmp/mirror"), &s);
        assert!(text.contains("/tmp/mirror"), "{text}");
        assert!(text.contains("2 written (1 overwritten)"), "{text}");
        assert!(text.contains("5 unchanged"), "{text}");
        assert!(text.contains("1 deleted"), "{text}");
        let text = format_sender_summary(Path::new("/tmp/src"), &s);
        assert!(text.contains("/tmp/src") && text.contains("2 file(s) sent"), "{text}");
    }
}
