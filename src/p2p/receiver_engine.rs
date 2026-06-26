//! P2P v2 receiver protocol engine — pure, sans-I/O.
//!
//! Tracks contiguous progress, decides when to ACK (batch boundary + timer),
//! when to request a resend (gap / stall), and when complete. Deals only in
//! chunk indices and an injected `now` (ms). Mirrors the web
#![allow(dead_code)] // library surface — mirrors web, exercised by #[cfg(test)]
//! `lib/p2p/receiver-engine.ts`.

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiverAction {
    Deliver { index: u64 },
    Ack { through: u64 },
    Request { from: u64 },
    Complete,
    Ignore,
}

pub struct ReceiverEngine {
    expected: u64,
    acked_through: i64, // -1 if none
    last_data_at: u64,
    last_control_at: u64,
    last_ack_at: u64,
    done: bool,
    batch: u64,
    ack_interval_ms: u64,
    stall_timeout_ms: u64,
}

impl ReceiverEngine {
    pub fn new(batch: u64, ack_interval_ms: u64, stall_timeout_ms: u64, resume_from: u64) -> Self {
        ReceiverEngine {
            expected: resume_from,
            acked_through: resume_from as i64 - 1,
            last_data_at: 0,
            last_control_at: 0,
            last_ack_at: 0,
            done: false,
            batch,
            ack_interval_ms,
            stall_timeout_ms,
        }
    }

    /// A chunk arrived (in arrival order).
    pub fn chunk(&mut self, index: u64, now: u64) -> Vec<ReceiverAction> {
        if self.done {
            return vec![];
        }
        if index < self.expected {
            return vec![ReceiverAction::Ignore]; // duplicate (e.g. resend)
        }
        if index > self.expected {
            return vec![ReceiverAction::Request { from: self.expected }]; // gap
        }
        let mut actions = vec![ReceiverAction::Deliver { index }];
        self.expected += 1;
        self.last_data_at = now;
        if self.expected % self.batch == 0 {
            actions.push(self.ack(now));
        }
        actions
    }

    /// Control-plane traffic seen — feeds stall detection.
    pub fn control_activity(&mut self, now: u64) {
        self.last_control_at = now;
    }

    /// Timer pulse. Emits a periodic ACK and/or a stall resend-request.
    pub fn tick(&mut self, now: u64) -> Vec<ReceiverAction> {
        if self.done {
            return vec![];
        }
        let mut actions = Vec::new();
        if (self.expected as i64 - 1) > self.acked_through
            && now.saturating_sub(self.last_ack_at) >= self.ack_interval_ms
        {
            actions.push(self.ack(now));
        }
        if self.last_control_at > 0
            && self.last_control_at >= self.last_data_at
            && now.saturating_sub(self.last_data_at) >= self.stall_timeout_ms
        {
            actions.push(ReceiverAction::Request { from: self.expected });
            self.last_data_at = now; // debounce
        }
        actions
    }

    /// `end` frame. Complete iff contiguous through `total`, else request the gap.
    pub fn end(&mut self, total: u64) -> Vec<ReceiverAction> {
        if self.done {
            return vec![];
        }
        if self.expected == total {
            self.done = true;
            vec![ReceiverAction::Complete]
        } else {
            vec![ReceiverAction::Request { from: self.expected }]
        }
    }

    fn ack(&mut self, now: u64) -> ReceiverAction {
        self.acked_through = self.expected as i64 - 1;
        self.last_ack_at = now;
        ReceiverAction::Ack { through: self.expected - 1 }
    }

    pub fn expected_index(&self) -> u64 {
        self.expected
    }
    pub fn is_complete(&self) -> bool {
        self.done
    }
}

#[cfg(test)]
mod tests {
    use super::ReceiverAction::*;
    use super::*;

    // (batch, ack_interval, stall_timeout, resume_from)
    fn eng(batch: u64) -> ReceiverEngine {
        ReceiverEngine::new(batch, 250, 5000, 0)
    }

    #[test]
    fn in_order_delivers_and_advances() {
        let mut e = eng(64);
        assert_eq!(e.chunk(0, 0), vec![Deliver { index: 0 }]);
        assert_eq!(e.chunk(1, 0), vec![Deliver { index: 1 }]);
        assert_eq!(e.expected_index(), 2);
    }

    #[test]
    fn acks_on_batch_boundary() {
        let mut e = eng(4);
        e.chunk(0, 0);
        e.chunk(1, 0);
        e.chunk(2, 0);
        assert_eq!(e.chunk(3, 0), vec![Deliver { index: 3 }, Ack { through: 3 }]);
    }

    #[test]
    fn duplicate_is_ignored() {
        let mut e = eng(64);
        e.chunk(0, 0);
        e.chunk(1, 0);
        assert_eq!(e.chunk(0, 0), vec![Ignore]);
        assert_eq!(e.expected_index(), 2);
    }

    #[test]
    fn gap_requests_missing() {
        let mut e = eng(64);
        e.chunk(0, 0);
        assert_eq!(e.chunk(5, 0), vec![Request { from: 1 }]);
    }

    #[test]
    fn periodic_ack_via_tick_once_per_new_data() {
        let mut e = eng(64);
        e.chunk(0, 0);
        e.chunk(1, 10);
        assert_eq!(e.tick(100), vec![]);
        assert_eq!(e.tick(300), vec![Ack { through: 1 }]);
        assert_eq!(e.tick(600), vec![]);
    }

    #[test]
    fn stall_requests_then_debounces() {
        let mut e = ReceiverEngine::new(64, 1_000_000, 5000, 0);
        e.chunk(0, 1000);
        e.control_activity(2000);
        assert_eq!(e.tick(3000), vec![]);
        assert_eq!(e.tick(6001), vec![Request { from: 1 }]);
        assert_eq!(e.tick(6500), vec![]);
    }

    #[test]
    fn no_spurious_stall_before_control() {
        let mut e = eng(64);
        assert_eq!(e.tick(10_000), vec![]);
    }

    #[test]
    fn end_completes_when_contiguous() {
        let mut e = eng(64);
        e.chunk(0, 0);
        e.chunk(1, 0);
        e.chunk(2, 0);
        assert_eq!(e.end(3), vec![Complete]);
        assert!(e.is_complete());
        assert_eq!(e.chunk(3, 0), vec![]);
    }

    #[test]
    fn end_with_missing_tail_requests() {
        let mut e = eng(64);
        e.chunk(0, 0);
        e.chunk(1, 0);
        assert_eq!(e.end(5), vec![Request { from: 2 }]);
        assert!(!e.is_complete());
    }

    #[test]
    fn resume_from_starts_at_checkpoint() {
        let mut e = ReceiverEngine::new(64, 250, 5000, 50);
        assert_eq!(e.expected_index(), 50);
        assert_eq!(e.chunk(50, 0), vec![Deliver { index: 50 }]);
        assert_eq!(e.chunk(49, 0), vec![Ignore]);
    }
}
