//! Versioned frame protocol for the direct multi-file transfer (task 058).
//!
//! Pure: encode/decode only — no I/O, no clocks. Frames ride as opaque payload
//! **inside** the existing encrypted DataChannel, so core and web never see them
//! and the cipher stays unaware of framing (spec §4).
//!
//! Wire format, one frame per DataChannel message:
//!
//! ```text
//! [tag u8][len u32 BE][payload len bytes]
//! ```
//!
//! - `tag 1` — control frame; payload is compact JSON of [`ControlFrame`]
//!   (internally tagged with `"t"`).
//! - `tag 2` — raw file bytes; payload is the chunk itself (never JSON, never
//!   base64 — the whole point of a binary channel).
//!
//! `len` is guarded by [`MAX_FRAME_BYTES`]: a bogus length can never make the
//! decoder allocate wildly, and an oversized encode is a typed error rather than
//! a frame the peer will reject mid-run.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Frame-protocol version. Bumped on any incompatible frame change; a mismatch
/// aborts the run cleanly on both sides (spec §4).
pub const PROTO_VERSION: u16 = 1;

/// Hard upper bound on one frame's payload. File chunks are
/// `crypto::STREAM_CHUNK_SIZE` (16 KB) and manifests are batched
/// ([`MANIFEST_BATCH`]), so 1 MiB is far above anything legitimate.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Manifest / manifest-ack entries per frame. A 100k-file workspace therefore
/// travels as ~200 bounded frames instead of one multi-megabyte message.
pub const MANIFEST_BATCH: usize = 512;

/// Bytes of framing overhead before the payload (`[tag u8][len u32]`).
pub const FRAME_HEADER_LEN: usize = 5;

const TAG_CONTROL: u8 = 1;
const TAG_CHUNK: u8 = 2;

/// What kind of transfer the peer declares in its hello frame.
///
/// **The hello frame is authoritative in every transport** (spec §3a): LAN mode
/// mints no URL, so this is how `get --local` knows it is receiving a folder
/// sync. A `/sync/<id>` URL is only a routing hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferMode {
    /// Direct per-file transfer (`share --sync`).
    Sync,
    /// Single-payload transfer (plain file / `--zip` archive).
    File,
}

impl std::fmt::Display for TransferMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferMode::Sync => write!(f, "sync"),
            TransferMode::File => write!(f, "file"),
        }
    }
}

/// One entry of the sender's manifest: the full post-ignore source file list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    /// Path relative to the shared folder, forward-slash separated.
    pub path: String,
    pub size: u64,
    /// Unix permission bits (`& 0o777`).
    pub mode: u32,
    /// SHA-256 of the file contents, lower-case hex.
    pub hash: String,
}

/// One entry of the receiver's answer: what it already holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathHash {
    pub path: String,
    pub hash: String,
}

/// Every control frame in the protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ControlFrame {
    /// Version + mode negotiation, sent first by **both** sides.
    ///
    /// `folder` is the **base name of the shared directory**, sent by the sender
    /// only (the receiver answers with `None`). It is the first thing on the
    /// wire because the receiver needs it before it touches the disk: the
    /// receiver's sync root is `<output_dir>/<folder>`, and nothing outside that
    /// root is ever read, written or deleted (task 064). The name is
    /// peer-controlled, so the receiver validates it as a single safe path
    /// component ([`crate::transfer::engine::validate_path_component`]) and
    /// aborts on violation.
    Hello {
        proto_version: u16,
        mode: TransferMode,
        #[serde(default)]
        folder: Option<String>,
    },
    /// A batch of the sender's file list; `more = true` means another batch
    /// follows. Sent even when nothing will transfer — `--replace-delete` cannot
    /// compute the prune set without the full source set.
    Manifest { files: Vec<FileEntry>, more: bool },
    /// A batch of the receiver's own `{path, hash}` list (same batching rule).
    ManifestAck { files: Vec<PathHash>, more: bool },
    /// Start of one file's bytes.
    FileBegin { path: String, size: u64, mode: u32 },
    /// End of one file's bytes, with the expected content hash.
    FileEnd { hash: String },
    /// Receiver verified the hash and committed the file.
    FileOk { path: String },
    /// Receiver rejected the file (hash mismatch, write error…).
    FileFail { path: String, reason: String },
    /// The prune set: destination files absent from the source.
    Delete { paths: Vec<String> },
    /// Run summary, sent by both sides.
    Done { files_sent: u64, bytes: u64, deleted: u64, skipped: u64 },
    /// Clean typed abort (version mismatch, unsafe path, repeated failure).
    Abort { reason: String },
}

/// A decoded frame: a control frame or a raw chunk of file bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Control(ControlFrame),
    Chunk(Vec<u8>),
}

/// Typed protocol failures. Every variant aborts the run — nothing partial is
/// ever applied (spec §4 receiver safety).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransferError {
    #[error("frame payload too large: {len} bytes (max {MAX_FRAME_BYTES})")]
    FrameTooLarge { len: usize },
    #[error("unknown frame tag {0}")]
    UnknownTag(u8),
    #[error("malformed control frame: {0}")]
    BadControl(String),
    #[error(
        "protocol version mismatch: the peer speaks v{theirs}, this CLI speaks v{ours}. \
         Update nullseal on both machines."
    )]
    VersionMismatch { ours: u16, theirs: u16 },
    #[error(
        "transfer mode mismatch: expected a {expected} transfer, the sender declared {actual}"
    )]
    ModeMismatch { expected: TransferMode, actual: TransferMode },
    #[error("unsafe path \"{path}\" ({reason}) — transfer aborted, nothing was applied")]
    UnsafePath { path: String, reason: String },
    #[error(
        "the sender's hello did not name the shared folder — nothing was written. \
         Update nullseal on the sending machine."
    )]
    MissingFolder,
    #[error("hash mismatch for \"{path}\"")]
    HashMismatch { path: String },
    #[error("unexpected frame: {0}")]
    Unexpected(String),
    #[error("the peer aborted the transfer: {0}")]
    PeerAbort(String),
}

/// Encode one frame to its wire bytes.
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, TransferError> {
    let (tag, payload) = match frame {
        Frame::Control(c) => (
            TAG_CONTROL,
            serde_json::to_vec(c).map_err(|e| TransferError::BadControl(e.to_string()))?,
        ),
        Frame::Chunk(bytes) => (TAG_CHUNK, bytes.clone()),
    };
    if payload.len() > MAX_FRAME_BYTES {
        return Err(TransferError::FrameTooLarge { len: payload.len() });
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.push(tag);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decode the first frame in `buf`.
///
/// Returns `Ok(None)` when the buffer holds only part of a frame (so a stream
/// consumer can wait for more), `Ok(Some((frame, consumed)))` on success, and a
/// typed error for an oversized length, an unknown tag or malformed JSON.
pub fn decode_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, TransferError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Ok(None);
    }
    let tag = buf[0];
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    // Guard BEFORE touching the buffer: a bogus length must never drive an
    // allocation or a huge read.
    if len > MAX_FRAME_BYTES {
        return Err(TransferError::FrameTooLarge { len });
    }
    // Reject an unknown tag even when the body is incomplete — the peer is not
    // speaking this protocol, so waiting for more bytes is pointless.
    if tag != TAG_CONTROL && tag != TAG_CHUNK {
        return Err(TransferError::UnknownTag(tag));
    }
    let end = FRAME_HEADER_LEN + len;
    if buf.len() < end {
        return Ok(None);
    }
    let payload = &buf[FRAME_HEADER_LEN..end];
    let frame = if tag == TAG_CONTROL {
        Frame::Control(
            serde_json::from_slice(payload)
                .map_err(|e| TransferError::BadControl(e.to_string()))?,
        )
    } else {
        Frame::Chunk(payload.to_vec())
    };
    Ok(Some((frame, end)))
}

/// Decode exactly one whole frame from a DataChannel message.
///
/// The DataChannel is message-oriented, so trailing bytes mean a corrupt or
/// hostile peer rather than pipelining.
pub fn decode_message(buf: &[u8]) -> Result<Frame, TransferError> {
    match decode_frame(buf)? {
        Some((frame, consumed)) if consumed == buf.len() => Ok(frame),
        Some((_, consumed)) => Err(TransferError::BadControl(format!(
            "{} trailing byte(s) after the frame",
            buf.len() - consumed
        ))),
        None => Err(TransferError::BadControl("truncated frame".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str) -> FileEntry {
        FileEntry { path: path.into(), size: 3, mode: 0o644, hash: "ab".repeat(32) }
    }

    fn round_trip(frame: Frame) {
        let bytes = encode_frame(&frame).unwrap();
        let decoded = decode_message(&bytes).unwrap();
        assert_eq!(decoded, frame, "frame must survive an encode/decode round trip");
    }

    #[test]
    fn every_control_frame_round_trips() {
        round_trip(Frame::Control(ControlFrame::Hello {
            proto_version: PROTO_VERSION,
            mode: TransferMode::Sync,
            folder: Some("proj".into()),
        }));
        round_trip(Frame::Control(ControlFrame::Hello {
            proto_version: 7,
            mode: TransferMode::File,
            folder: None,
        }));
        round_trip(Frame::Control(ControlFrame::Manifest {
            files: vec![entry("a.txt"), entry("sub/b.txt")],
            more: true,
        }));
        round_trip(Frame::Control(ControlFrame::ManifestAck {
            files: vec![PathHash { path: "a.txt".into(), hash: "cd".repeat(32) }],
            more: false,
        }));
        round_trip(Frame::Control(ControlFrame::FileBegin {
            path: "sub/b.txt".into(),
            size: 42,
            mode: 0o755,
        }));
        round_trip(Frame::Control(ControlFrame::FileEnd { hash: "ef".repeat(32) }));
        round_trip(Frame::Control(ControlFrame::FileOk { path: "a.txt".into() }));
        round_trip(Frame::Control(ControlFrame::FileFail {
            path: "a.txt".into(),
            reason: "hash mismatch".into(),
        }));
        round_trip(Frame::Control(ControlFrame::Delete {
            paths: vec!["stale.txt".into(), "old/x.bin".into()],
        }));
        round_trip(Frame::Control(ControlFrame::Done {
            files_sent: 3,
            bytes: 900,
            deleted: 1,
            skipped: 7,
        }));
        round_trip(Frame::Control(ControlFrame::Abort { reason: "boom".into() }));
    }

    #[test]
    fn chunk_frames_round_trip_including_empty_and_binary() {
        round_trip(Frame::Chunk(vec![]));
        round_trip(Frame::Chunk((0u8..=255).collect()));
        round_trip(Frame::Chunk(vec![0u8; 16 * 1024]));
    }

    #[test]
    fn wire_layout_is_tag_len_payload() {
        let bytes = encode_frame(&Frame::Chunk(vec![1, 2, 3])).unwrap();
        assert_eq!(bytes[0], TAG_CHUNK);
        assert_eq!(&bytes[1..5], &[0, 0, 0, 3]);
        assert_eq!(&bytes[5..], &[1, 2, 3]);

        let hello = encode_frame(&Frame::Control(ControlFrame::Hello {
            proto_version: 1,
            mode: TransferMode::Sync,
            folder: Some("proj".into()),
        }))
        .unwrap();
        assert_eq!(hello[0], TAG_CONTROL);
        let json = std::str::from_utf8(&hello[5..]).unwrap();
        assert!(json.contains("\"t\":\"hello\""), "internally tagged JSON: {json}");
        assert!(json.contains("\"mode\":\"sync\""), "{json}");
        assert!(json.contains("\"protoVersion\":1"), "{json}");
        assert!(json.contains("\"folder\":\"proj\""), "{json}");
    }

    #[test]
    fn a_hello_without_a_folder_decodes_as_none() {
        // The receiver's own hello carries no folder, and a peer that omits the
        // field entirely must decode rather than blow up — the *receiver* is what
        // refuses a folder-less sync hello, with a typed error.
        let mut bytes = vec![TAG_CONTROL];
        let payload = br#"{"t":"hello","protoVersion":1,"mode":"sync"}"#;
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        assert_eq!(
            decode_message(&bytes).unwrap(),
            Frame::Control(ControlFrame::Hello {
                proto_version: 1,
                mode: TransferMode::Sync,
                folder: None,
            })
        );
    }

    #[test]
    fn truncated_frame_is_incomplete_not_an_error() {
        let bytes = encode_frame(&Frame::Chunk(vec![9; 100])).unwrap();
        for cut in [0, 1, 4, FRAME_HEADER_LEN, FRAME_HEADER_LEN + 1, bytes.len() - 1] {
            assert_eq!(
                decode_frame(&bytes[..cut]).unwrap(),
                None,
                "a partial frame ({cut} bytes) must decode as incomplete"
            );
        }
        // …and decode_message treats a partial DataChannel message as malformed.
        assert!(matches!(
            decode_message(&bytes[..7]),
            Err(TransferError::BadControl(_))
        ));
    }

    #[test]
    fn oversized_length_is_rejected_without_allocating() {
        // A 5-byte header claiming 4 GB of payload: rejected on the header alone.
        let mut bogus = vec![TAG_CHUNK];
        bogus.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            decode_frame(&bogus),
            Err(TransferError::FrameTooLarge { len: u32::MAX as usize })
        );
        // Just over the guard is rejected too.
        let mut over = vec![TAG_CHUNK];
        over.extend_from_slice(&((MAX_FRAME_BYTES + 1) as u32).to_be_bytes());
        assert_eq!(
            decode_frame(&over),
            Err(TransferError::FrameTooLarge { len: MAX_FRAME_BYTES + 1 })
        );
    }

    #[test]
    fn encoding_an_oversized_chunk_is_a_typed_error() {
        let err = encode_frame(&Frame::Chunk(vec![0u8; MAX_FRAME_BYTES + 1])).unwrap_err();
        assert_eq!(err, TransferError::FrameTooLarge { len: MAX_FRAME_BYTES + 1 });
    }

    #[test]
    fn unknown_tag_is_rejected() {
        let mut frame = encode_frame(&Frame::Chunk(vec![1])).unwrap();
        frame[0] = 99;
        assert_eq!(decode_frame(&frame), Err(TransferError::UnknownTag(99)));
        // Even with a truncated body — a wrong tag is not a "wait for more".
        assert_eq!(decode_frame(&frame[..5]), Err(TransferError::UnknownTag(99)));
    }

    #[test]
    fn malformed_control_json_is_rejected() {
        let mut bytes = vec![TAG_CONTROL];
        let payload = b"{not json";
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        assert!(matches!(decode_frame(&bytes), Err(TransferError::BadControl(_))));

        // Valid JSON, unknown frame tag inside → still malformed.
        let mut bytes = vec![TAG_CONTROL];
        let payload = br#"{"t":"teleport","x":1}"#;
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        assert!(matches!(decode_frame(&bytes), Err(TransferError::BadControl(_))));
    }

    #[test]
    fn trailing_bytes_in_a_message_are_rejected() {
        let mut bytes = encode_frame(&Frame::Chunk(vec![1, 2])).unwrap();
        bytes.push(0xff);
        assert!(matches!(decode_message(&bytes), Err(TransferError::BadControl(_))));
    }

    #[test]
    fn decode_frame_reports_consumed_length_for_a_stream() {
        let mut stream = encode_frame(&Frame::Chunk(vec![1, 2, 3])).unwrap();
        stream.extend(encode_frame(&Frame::Control(ControlFrame::FileOk {
            path: "a".into(),
        }))
        .unwrap());
        let (first, consumed) = decode_frame(&stream).unwrap().unwrap();
        assert_eq!(first, Frame::Chunk(vec![1, 2, 3]));
        let (second, _) = decode_frame(&stream[consumed..]).unwrap().unwrap();
        assert_eq!(second, Frame::Control(ControlFrame::FileOk { path: "a".into() }));
    }

    #[test]
    fn mode_displays_as_the_wire_value() {
        assert_eq!(TransferMode::Sync.to_string(), "sync");
        assert_eq!(TransferMode::File.to_string(), "file");
    }
}
