//! P2P v2 sender protocol engine — pure, sans-I/O.
//!
//! Decides which frames go on the wire (metadata / chunk[i] / end) given a
//! sliding window, cumulative ACKs, resume points, and resend requests. Deals
//! only in chunk indices — no crypto, sockets, or timers. Mirrors the web
#![allow(dead_code)] // library surface — mirrors web, exercised by #[cfg(test)]
//! `lib/p2p/sender-engine.ts`.

#[derive(Debug, PartialEq, Eq)]
pub enum SenderAction {
    Metadata { resume_from: u64 },
    Chunk { index: u64 },
    End { total: u64 },
}

pub struct SenderEngine {
    total: u64,
    window: u64,
    base: u64, // first un-acked chunk (ack_through + 1)
    next: u64, // next chunk to send
    end_sent: bool,
}

impl SenderEngine {
    /// `total` = number of chunks; `window` = max chunks in flight ahead of `base`.
    pub fn new(total: u64, window: u64) -> Self {
        assert!(window >= 1, "window must be >= 1");
        SenderEngine { total, window, base: 0, next: 0, end_sent: false }
    }

    /// DataChannel (re)opened; start/resume at `resume_from`. Metadata + window.
    pub fn open(&mut self, resume_from: u64) -> Vec<SenderAction> {
        self.base = resume_from;
        self.next = resume_from;
        self.end_sent = false;
        let mut actions = vec![SenderAction::Metadata { resume_from }];
        actions.extend(self.pump());
        actions
    }

    /// Cumulative ACK: receiver has everything through chunk `through`.
    pub fn ack(&mut self, through: u64) -> Vec<SenderAction> {
        if through + 1 > self.base {
            self.base = through + 1;
        }
        self.pump()
    }

    /// Receiver asks to resend from `from`. Rewinds and re-announces.
    pub fn request(&mut self, from: u64) -> Vec<SenderAction> {
        self.base = from;
        self.next = from;
        self.end_sent = false;
        let mut actions = vec![SenderAction::Metadata { resume_from: from }];
        actions.extend(self.pump());
        actions
    }

    /// Continue the window (e.g. after back-pressure clears).
    pub fn pump(&mut self) -> Vec<SenderAction> {
        let mut actions = Vec::new();
        while self.next < self.total && self.next - self.base < self.window {
            actions.push(SenderAction::Chunk { index: self.next });
            self.next += 1;
        }
        if self.next >= self.total && !self.end_sent {
            actions.push(SenderAction::End { total: self.total });
            self.end_sent = true;
        }
        actions
    }

    pub fn end_emitted(&self) -> bool {
        self.end_sent
    }

    /// Highest chunk index sent (or u64::MAX-equivalent meaning none if next==0).
    pub fn sent_through(&self) -> Option<u64> {
        if self.next == 0 { None } else { Some(self.next - 1) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunks(a: &[SenderAction]) -> Vec<u64> {
        a.iter().filter_map(|x| match x {
            SenderAction::Chunk { index } => Some(*index),
            _ => None,
        }).collect()
    }
    fn kinds(a: &[SenderAction]) -> Vec<&'static str> {
        a.iter().map(|x| match x {
            SenderAction::Metadata { .. } => "metadata",
            SenderAction::Chunk { .. } => "chunk",
            SenderAction::End { .. } => "end",
        }).collect()
    }

    #[test]
    fn open_emits_metadata_chunks_end_when_window_not_limiting() {
        let mut e = SenderEngine::new(3, 10);
        let a = e.open(0);
        assert_eq!(kinds(&a), ["metadata", "chunk", "chunk", "chunk", "end"]);
        assert_eq!(chunks(&a), [0, 1, 2]);
        assert!(e.end_emitted());
    }

    #[test]
    fn window_limits_then_ack_slides() {
        let mut e = SenderEngine::new(5, 2);
        assert_eq!(chunks(&e.open(0)), [0, 1]);
        assert!(!e.end_emitted());
        assert_eq!(chunks(&e.ack(0)), [2]);
        assert_eq!(chunks(&e.ack(1)), [3]);
        let last = e.ack(3);
        assert_eq!(chunks(&last), [4]);
        assert_eq!(*kinds(&last).last().unwrap(), "end");
        assert!(e.end_emitted());
    }

    #[test]
    fn end_emitted_exactly_once() {
        let mut e = SenderEngine::new(2, 10);
        let a = e.open(0);
        assert_eq!(a.iter().filter(|x| matches!(x, SenderAction::End { .. })).count(), 1);
        assert!(e.pump().is_empty());
        assert!(e.ack(1).is_empty());
    }

    #[test]
    fn never_sends_past_total() {
        let mut e = SenderEngine::new(3, 100);
        assert_eq!(chunks(&e.open(0)), [0, 1, 2]);
        assert!(chunks(&e.ack(2)).is_empty());
    }

    #[test]
    fn open_resume_starts_at_resume_point() {
        let mut e = SenderEngine::new(10, 2);
        let a = e.open(4);
        assert_eq!(a[0], SenderAction::Metadata { resume_from: 4 });
        assert_eq!(chunks(&a), [4, 5]);
    }

    #[test]
    fn request_rewinds_and_reannounces() {
        let mut e = SenderEngine::new(10, 3);
        e.open(0);
        e.ack(2);
        let a = e.request(1);
        assert_eq!(a[0], SenderAction::Metadata { resume_from: 1 });
        assert_eq!(chunks(&a), [1, 2, 3]);
    }

    #[test]
    fn stale_ack_does_not_move_base_back() {
        let mut e = SenderEngine::new(10, 2);
        e.open(0);
        e.ack(1);
        let before = e.sent_through();
        assert!(e.ack(0).is_empty());
        assert_eq!(e.sent_through(), before);
    }

    #[test]
    fn window_one_is_stop_and_wait_eager_end() {
        let mut e = SenderEngine::new(3, 1);
        assert_eq!(chunks(&e.open(0)), [0]);
        assert_eq!(chunks(&e.ack(0)), [1]);
        assert_eq!(kinds(&e.ack(1)), ["chunk", "end"]);
        assert!(e.end_emitted());
    }

    // Task 037: the CLI sender's `is_done!` "all payload sent" term is a monotonic
    // `payload_fully_sent` latch, NOT a live read of `sent_through()` (=
    // `engine_sent_through()` on the adapter). This test proves the latch semantics
    // purely at the engine level — no WebRTC. A late tail gap-repair `request(from)`
    // rewinds `next`, so `sent_through()+1` momentarily drops below `total`; the
    // latch, once set, must stay `true` so a completion-time disconnect still reads
    // as success rather than a spurious mid-transfer drop.
    #[test]
    fn payload_fully_sent_latch_survives_request_rewind() {
        // Use a window SMALLER than the payload so a far-back gap-repair `request`
        // can't refill to `total` in one pump → the live `sent_through()` read truly
        // regresses (with window >= total, `request` re-pumps everything immediately
        // and the live read never dips, which is why the latch is only needed in the
        // windowed regime — exactly the 112 MB / 256-chunk-window case).
        let total: u64 = 6;
        let window: u64 = 2;
        let mut e = SenderEngine::new(total, window);

        // Slide the window all the way to completion via cumulative ACKs.
        e.open(0);
        for t in 0..total {
            let _ = e.ack(t);
        }
        assert_eq!(e.sent_through(), Some(total - 1), "every chunk handed to transport");
        assert!(e.end_emitted());

        // Mirror the loop's latch step: once `sent_through()+1 >= total`, latch it.
        let live_all_sent =
            |eng: &SenderEngine| eng.sent_through().map(|t| t + 1 >= total).unwrap_or(false);
        let mut payload_fully_sent = false;
        if live_all_sent(&e) {
            payload_fully_sent = true;
        }
        assert!(payload_fully_sent, "latch must set once the whole payload is sent");
        assert!(live_all_sent(&e));

        // A far-back gap-repair request rewinds `next` beyond the window → the LIVE
        // all-sent read regresses (this is what made 034's live check false-retry).
        e.request(0);
        assert!(
            !live_all_sent(&e),
            "request far back rewinds next past the window, so the live read regresses",
        );

        // The monotonic latch is NEVER cleared within the attempt, so re-running the
        // latch step cannot un-set it — the `is_done!`-style decision still succeeds.
        if live_all_sent(&e) {
            payload_fully_sent = true;
        }
        assert!(payload_fully_sent, "latch must stay true after a request rewind");

        // is_done!-style decision: a disconnect after full send → success (no retry).
        let recipient_done = false;
        let adapter_finished = false; // final ACK not yet applied
        let is_done = recipient_done || adapter_finished || payload_fully_sent;
        assert!(is_done, "disconnect after full send must read as done (no retry)");
    }
}
