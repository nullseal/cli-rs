//! P2P transfer protocol v2 — pure, sans-I/O building blocks + data-plane adapters.
//! See docs/architecture/p2p-transfer-protocol.md and p2p-v2-implementation-plan.md.

pub mod codec;
pub mod connection;
pub mod receiver_adapter;
pub mod receiver_engine;
pub mod sender_adapter;
pub mod sender_engine;
