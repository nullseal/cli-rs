//! Transport-agnostic Socket.IO v4 client.
//!
//! Two modules:
//! - `proto`: pure encode/decode for Engine.IO + Socket.IO v4 text frames (no I/O).
//! - `client`: async driver generic over a `WsTransport` trait.
//!
//! Also provides `TungsteniteWs`, a real WebSocket transport using `tokio-tungstenite`.

pub mod proto;
pub mod client;
pub mod transport;
