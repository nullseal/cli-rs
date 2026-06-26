//! Transport-agnostic P2P control-plane crate for NullSeal signaling.
//!
//! Provides:
//! - `events`: typed event channels + inbound router
//! - `transport`: `ControlTransport` trait + Socket.IO impl
//! - `control`: `P2PControl` with typed emit API

pub mod events;
pub mod transport;
pub mod control;
