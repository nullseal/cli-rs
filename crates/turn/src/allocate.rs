//! Pure Allocate/auth state machine (sans-I/O).
//!
//! Feed it "datagram received" bytes, get "send this datagram" actions + terminal results.
//! No sockets, no timers — purely deterministic given the same inputs.

use std::net::SocketAddr;

use crate::attr::Attribute;
use crate::auth;
use crate::message::{self, Class, MessageBuilder, Method, StunMessage};

/// Credentials for TURN long-term auth.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// Result of a successful Allocate handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocated {
    pub relayed: SocketAddr,
    pub srflx: SocketAddr,
    pub lifetime: u32,
}

/// Actions emitted by the state machine.
#[derive(Debug, Clone)]
pub enum Action {
    /// Send this datagram to the TURN server.
    SendDatagram(Vec<u8>),
    /// Allocation succeeded.
    Allocated(Allocated),
    /// Allocation failed with an error.
    Error(AllocateError),
}

/// Errors from the allocate state machine.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AllocateError {
    #[error("server returned error {code}: {reason}")]
    ServerError { code: u16, reason: String },
    #[error("unexpected response")]
    Unexpected,
    #[error("max retries exceeded (stale nonce loop)")]
    MaxRetries,
}

/// Internal state of the Allocate handshake.
#[derive(Debug)]
#[allow(dead_code)]
enum State {
    /// Waiting for response to initial unauthenticated Allocate.
    AwaitingChallenge { txn_id: [u8; 12] },
    /// Waiting for response to authenticated Allocate.
    AwaitingAllocate { txn_id: [u8; 12], realm: String, nonce: String, key: [u8; 16] },
    /// Terminal.
    Done,
}

/// Pure Allocate state machine.
#[derive(Debug)]
pub struct AllocateMachine {
    creds: Credentials,
    state: State,
    stale_retries: u8,
}

const MAX_STALE_RETRIES: u8 = 3;

impl AllocateMachine {
    /// Create and start the machine. Returns the machine + the initial datagram to send.
    pub fn start(creds: Credentials, txn_id: [u8; 12]) -> (Self, Vec<u8>) {
        let msg = build_unauth_allocate(&txn_id);
        let machine = Self {
            creds,
            state: State::AwaitingChallenge { txn_id },
            stale_retries: 0,
        };
        (machine, msg)
    }

    /// Feed a received datagram. Returns zero or more actions.
    pub fn handle(&mut self, data: &[u8]) -> Vec<Action> {
        let parsed = match message::decode(data) {
            Some(m) => m,
            None => return vec![],
        };

        match &self.state {
            State::AwaitingChallenge { txn_id } => {
                if parsed.txn_id != *txn_id {
                    return vec![];
                }
                self.handle_challenge_response(parsed)
            }
            State::AwaitingAllocate { txn_id, .. } => {
                if parsed.txn_id != *txn_id {
                    return vec![];
                }
                self.handle_allocate_response(parsed)
            }
            State::Done => vec![],
        }
    }

    fn handle_challenge_response(&mut self, msg: StunMessage) -> Vec<Action> {
        // Expect a 401 error with REALM + NONCE
        if msg.class != Class::Error {
            self.state = State::Done;
            return vec![Action::Error(AllocateError::Unexpected)];
        }

        let mut realm = None;
        let mut nonce = None;
        let mut error_code = None;

        for attr in &msg.attrs {
            match attr {
                Attribute::Realm(r) => realm = Some(r.clone()),
                Attribute::Nonce(n) => nonce = Some(n.clone()),
                Attribute::ErrorCode { code, reason: _ } => error_code = Some(*code),
                _ => {}
            }
        }

        match error_code {
            Some(401) => {}
            Some(code) => {
                let reason = msg.attrs.iter().find_map(|a| {
                    if let Attribute::ErrorCode { reason, .. } = a { Some(reason.clone()) } else { None }
                }).unwrap_or_default();
                self.state = State::Done;
                return vec![Action::Error(AllocateError::ServerError { code, reason })];
            }
            None => {
                self.state = State::Done;
                return vec![Action::Error(AllocateError::Unexpected)];
            }
        }

        let realm = match realm {
            Some(r) => r,
            None => {
                self.state = State::Done;
                return vec![Action::Error(AllocateError::Unexpected)];
            }
        };
        let nonce = match nonce {
            Some(n) => n,
            None => {
                self.state = State::Done;
                return vec![Action::Error(AllocateError::Unexpected)];
            }
        };

        // Compute key and send authenticated Allocate
        let key = auth::long_term_key(&self.creds.username, &realm, &self.creds.password);
        let txn_id = generate_txn_id();
        let msg_bytes = build_auth_allocate(&txn_id, &self.creds.username, &realm, &nonce, &key);

        self.state = State::AwaitingAllocate { txn_id, realm, nonce, key };
        vec![Action::SendDatagram(msg_bytes)]
    }

    fn handle_allocate_response(&mut self, msg: StunMessage) -> Vec<Action> {
        match msg.class {
            Class::Success => {
                // Extract XOR-RELAYED-ADDRESS, XOR-MAPPED-ADDRESS, LIFETIME
                let mut relayed = None;
                let mut srflx = None;
                let mut lifetime = 600; // default

                for attr in &msg.attrs {
                    match attr {
                        Attribute::XorRelayedAddress(a) => relayed = Some(*a),
                        Attribute::XorMappedAddress(a) => srflx = Some(*a),
                        Attribute::Lifetime(l) => lifetime = *l,
                        _ => {}
                    }
                }

                self.state = State::Done;
                match (relayed, srflx) {
                    (Some(r), Some(s)) => {
                        vec![Action::Allocated(Allocated { relayed: r, srflx: s, lifetime })]
                    }
                    _ => vec![Action::Error(AllocateError::Unexpected)],
                }
            }
            Class::Error => {
                // Check for 438 Stale Nonce
                let mut error_code = None;
                let mut new_nonce = None;
                let mut realm = None;

                for attr in &msg.attrs {
                    match attr {
                        Attribute::ErrorCode { code, .. } => error_code = Some(*code),
                        Attribute::Nonce(n) => new_nonce = Some(n.clone()),
                        Attribute::Realm(r) => realm = Some(r.clone()),
                        _ => {}
                    }
                }

                if error_code == Some(438) {
                    // Stale nonce — retry with new nonce
                    self.stale_retries += 1;
                    if self.stale_retries > MAX_STALE_RETRIES {
                        self.state = State::Done;
                        return vec![Action::Error(AllocateError::MaxRetries)];
                    }

                    let nonce = new_nonce.unwrap_or_default();
                    let realm = realm.unwrap_or_else(|| {
                        if let State::AwaitingAllocate { realm: ref old_realm, .. } = self.state {
                            old_realm.clone()
                        } else {
                            String::new()
                        }
                    });
                    let key = auth::long_term_key(&self.creds.username, &realm, &self.creds.password);
                    let txn_id = generate_txn_id();
                    let msg_bytes = build_auth_allocate(&txn_id, &self.creds.username, &realm, &nonce, &key);
                    self.state = State::AwaitingAllocate { txn_id, realm, nonce, key };
                    return vec![Action::SendDatagram(msg_bytes)];
                }

                let reason = msg.attrs.iter().find_map(|a| {
                    if let Attribute::ErrorCode { code, reason } = a { Some(format!("{}: {}", code, reason)) } else { None }
                }).unwrap_or_else(|| "unknown error".to_string());

                self.state = State::Done;
                vec![Action::Error(AllocateError::ServerError {
                    code: error_code.unwrap_or(0),
                    reason,
                })]
            }
            _ => vec![],
        }
    }
}

/// Build an unauthenticated Allocate request.
fn build_unauth_allocate(txn_id: &[u8; 12]) -> Vec<u8> {
    let mut builder = MessageBuilder::new(Method::Allocate, Class::Request, *txn_id);
    builder.add_requested_transport(17); // UDP
    builder.add_software("nullseal");
    builder.build_with_fingerprint()
}

/// Build an authenticated Allocate request with MESSAGE-INTEGRITY + FINGERPRINT.
fn build_auth_allocate(
    txn_id: &[u8; 12],
    username: &str,
    realm: &str,
    nonce: &str,
    key: &[u8; 16],
) -> Vec<u8> {
    let mut builder = MessageBuilder::new(Method::Allocate, Class::Request, *txn_id);
    builder.add_requested_transport(17); // UDP
    builder.add_username(username);
    builder.add_realm(realm);
    builder.add_nonce(nonce);
    builder.build_with_integrity(key)
}

/// Encode a Refresh request (for use by task 008).
pub fn build_refresh(
    txn_id: &[u8; 12],
    username: &str,
    realm: &str,
    nonce: &str,
    key: &[u8; 16],
    lifetime: u32,
) -> Vec<u8> {
    let mut builder = MessageBuilder::new(Method::Refresh, Class::Request, *txn_id);
    builder.add_lifetime(lifetime);
    builder.add_username(username);
    builder.add_realm(realm);
    builder.add_nonce(nonce);
    builder.build_with_integrity(key)
}

/// Encode a CreatePermission request (for use by task 008).
pub fn build_create_permission(
    txn_id: &[u8; 12],
    username: &str,
    realm: &str,
    nonce: &str,
    key: &[u8; 16],
    peer_addr: &SocketAddr,
) -> Vec<u8> {
    let mut builder = MessageBuilder::new(Method::CreatePermission, Class::Request, *txn_id);
    builder.add_xor_peer_address(peer_addr);
    builder.add_username(username);
    builder.add_realm(realm);
    builder.add_nonce(nonce);
    builder.build_with_integrity(key)
}

/// Generate a random 12-byte transaction ID.
fn generate_txn_id() -> [u8; 12] {
    use rand::RngCore;
    let mut id = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Generate a random transaction ID (public, for tests/external use).
pub fn new_txn_id() -> [u8; 12] {
    generate_txn_id()
}
