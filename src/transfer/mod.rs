//! Direct (unzipped) multi-file transfer — `share --sync` / `get` on a
//! `/sync/<id>` link (task 058).
//!
//! **This module is pure and I/O-free by contract** (spec
//! `docs/superpowers/specs/2026-07-29-folder-transfer-modes-design.md` §4): no
//! `std::fs`, no `File`, no sockets (`tokio::net`), no clocks (`Instant` /
//! `SystemTime`), no randomness. File hashes and file lists are supplied by the
//! caller; every decision the protocol makes (what to send, what to skip, what
//! to prune, what to reject) is a pure function of the frames exchanged.
//!
//! The I/O half lives in `commands::sync_flow` (walk + hash + atomic writes +
//! DataChannel plumbing). Keeping the split grep-able is deliberate — task 053's
//! predecessor module was deleted for sitting unwired, and the leader greps this
//! directory for I/O leaks.
//!
//! - [`protocol`] — the versioned frame set and its `[tag][len][payload]` wire
//!   framing.
//! - [`engine`] — the sender's hash diff / plan, the receiver's path validation,
//!   hash verification and delete gating.

pub mod engine;
pub mod protocol;
