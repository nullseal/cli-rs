//! P2P v2 connection / reconnection state machine — pure, sans-I/O (spec §15).
//!
//! One peer's signaling lifecycle. Timers are injected: the machine emits
//! `ArmRetryTimer` / `ArmReconnectDeadline` and is fed `RetryTimer` /
//! `ReconnectDeadline` events. Mirrors the web `lib/p2p/connection-machine.ts`.
// Live since task 013: drives the retry budget / backoff / Stopped+Expired across
// all four CLI flows (share/get × online/local). This is the *complete* mirror of
// the web `connection-machine.ts`, so a few events/actions (e.g. BothReady→BuildPc,
// ArmReconnectDeadline) are exercised only by the unit tests below — the CLI feeds
// the budget-relevant subset. Keep `allow(dead_code)` for those mirror-completeness
// variants rather than diverging from the web model.
#![allow(dead_code)]

#[derive(Debug, Clone)]
pub enum ConnEvent {
    Start,
    SocketUp,
    SocketDown,
    SocketError,
    Joined { last_chunk_offset: u64, generation: u64 },
    BothReady { generation: u64 },
    PeerDisconnected,
    DcOpen,
    DcClosed,
    IceFailed,
    Error { code: String },
    ManualRetry,
    TransferProgress,
    TransferComplete,
    RetryTimer,
    ReconnectDeadline,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConnAction {
    Dial,
    Join,
    BuildPc { resume_from: u64 },
    ArmRetryTimer { delay_ms: u64 },
    ArmReconnectDeadline { delay_ms: u64 },
    Stopped,
    Expired,
    Completed,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConnPhase {
    Idle,
    Connecting,
    Waiting,
    Negotiating,
    Transferring,
    Reconnecting,
    Stopped,
    Completed,
    Expired,
}

fn fatal(code: &str) -> bool {
    matches!(
        code,
        "session_unavailable" | "session_deleted" | "evicted" | "invalid_payload"
    )
}

pub struct ConnectionMachine {
    phase: ConnPhase,
    socket_up: bool,
    pending_join: bool,
    attempt: u32,
    retry_scheduled: bool,
    timer_armed: bool,
    deadline_armed: bool,
    peer_ever_present: bool,
    resume_from: u64,
    generation: u64,
    max_retries: u32,
    backoff_ms: Vec<u64>,
    ice_timeout_ms: u64,
}

impl Default for ConnectionMachine {
    fn default() -> Self {
        ConnectionMachine::new(3, vec![1000, 2000, 4000], 10_000)
    }
}

impl ConnectionMachine {
    pub fn new(max_retries: u32, backoff_ms: Vec<u64>, ice_timeout_ms: u64) -> Self {
        ConnectionMachine {
            phase: ConnPhase::Idle,
            socket_up: false,
            pending_join: false,
            attempt: 0,
            retry_scheduled: false,
            timer_armed: false,
            deadline_armed: false,
            peer_ever_present: false,
            resume_from: 0,
            generation: 0,
            max_retries,
            backoff_ms,
            ice_timeout_ms,
        }
    }

    pub fn handle(&mut self, ev: ConnEvent) -> Vec<ConnAction> {
        match ev {
            ConnEvent::Start => {
                self.phase = ConnPhase::Connecting;
                self.pending_join = true;
                vec![ConnAction::Dial]
            }
            ConnEvent::SocketUp => {
                self.socket_up = true;
                if self.pending_join {
                    self.pending_join = false;
                    vec![ConnAction::Join]
                } else {
                    vec![]
                }
            }
            ConnEvent::SocketDown => {
                self.socket_up = false;
                self.schedule_retry()
            }
            ConnEvent::SocketError | ConnEvent::DcClosed | ConnEvent::IceFailed => self.schedule_retry(),
            ConnEvent::Joined { last_chunk_offset, generation } => {
                // A socket re-join is NOT a completed reconnect (no DataChannel yet).
                // KEEP the reconnect deadline armed so a reconnect that joins but never
                // reaches a live DataChannel still escalates; BothReady/DcOpen clear it on
                // a real recovery. (BUG-RECONNECT-STALL: was disarming → stuck at 1/3.)
                self.retry_scheduled = false;
                self.timer_armed = false;
                self.generation = generation;
                if last_chunk_offset > self.resume_from {
                    self.resume_from = last_chunk_offset;
                }
                if self.attempt == 0 {
                    self.phase = ConnPhase::Waiting;
                } else if !self.peer_ever_present {
                    // Pre-transfer reconnect: re-joined the socket but never had a peer
                    // (no BothReady), so we're legitimately back to WAITING — no
                    // DataChannel to time out. Disarm the deadline + reset the budget so
                    // a blip while waiting for the peer doesn't escalate to Stopped.
                    // (Bug 021-B) Active-session re-joins keep climbing (020/019).
                    self.phase = ConnPhase::Waiting;
                    self.deadline_armed = false;
                    self.attempt = 0;
                }
                vec![]
            }
            ConnEvent::BothReady { generation } => {
                self.generation = generation;
                self.peer_ever_present = true;
                self.deadline_armed = false;
                if self.phase == ConnPhase::Stopped {
                    self.attempt = 0;
                    self.retry_scheduled = false;
                }
                self.phase = ConnPhase::Negotiating;
                vec![ConnAction::BuildPc { resume_from: self.resume_from }]
            }
            ConnEvent::DcOpen => {
                // A reopened DataChannel is not proof the transfer recovered (a flapping
                // link re-opens then drops). Clear in-flight retry timers but KEEP the
                // attempt budget; it resets only on real progress (TransferProgress) or
                // a manual retry — so the counter climbs 1→2→3→stopped on a flapping
                // link instead of sticking at 1. (Bug B1, mirrors web)
                self.phase = ConnPhase::Transferring;
                // A DataChannel opened → a peer was definitely present. The CLI receiver
                // never dispatches BothReady, so without this its `peer_ever_present`
                // would stay false and the 021-B Joined branch would reset the attempt
                // to 0 on every rejoin (never climbing). (Bug 024-A)
                self.peer_ever_present = true;
                self.retry_scheduled = false;
                self.timer_armed = false;
                self.deadline_armed = false;
                vec![]
            }
            ConnEvent::TransferProgress => {
                // A chunk was actually ACKed/received after a (re)connect → genuine
                // recovery, so the next unrelated drop starts fresh at attempt 1.
                self.attempt = 0;
                self.retry_scheduled = false;
                vec![]
            }
            ConnEvent::PeerDisconnected => {
                // The OTHER peer dropped. Enter the retry climb (same as our own
                // SocketDown/DcClosed) so the attempt counter advances 1→2→3 and,
                // if the peer never returns, reaches Stopped → manual retry. A fast
                // reconnect clears it via BothReady/DcOpen and the budget resets on
                // the next TransferProgress. (BUG-020: previously just set phase=
                // Reconnecting and returned [] → counter frozen forever.)
                self.schedule_retry()
            }
            ConnEvent::Error { code } => {
                if fatal(&code) {
                    self.phase = ConnPhase::Expired;
                    vec![ConnAction::Expired]
                } else {
                    self.schedule_retry()
                }
            }
            ConnEvent::ManualRetry => self.manual_retry(),
            ConnEvent::TransferComplete => {
                self.phase = ConnPhase::Completed;
                vec![ConnAction::Completed]
            }
            ConnEvent::RetryTimer => self.on_retry_timer(),
            ConnEvent::ReconnectDeadline => {
                if !self.deadline_armed {
                    return vec![];
                }
                self.deadline_armed = false;
                if self.terminal() {
                    return vec![];
                }
                self.retry_scheduled = false;
                self.schedule_retry()
            }
        }
    }

    fn schedule_retry(&mut self) -> Vec<ConnAction> {
        if self.terminal() {
            return vec![];
        }
        if self.retry_scheduled {
            return self.arm_retry();
        }
        self.retry_scheduled = true;
        self.attempt += 1;
        if self.attempt > self.max_retries {
            self.retry_scheduled = false;
            self.timer_armed = false;
            self.deadline_armed = false;
            self.phase = ConnPhase::Stopped;
            return vec![ConnAction::Stopped];
        }
        self.phase = ConnPhase::Reconnecting;
        self.arm_retry()
    }

    fn arm_retry(&mut self) -> Vec<ConnAction> {
        if self.timer_armed {
            return vec![];
        }
        self.timer_armed = true;
        let idx = ((self.attempt.saturating_sub(1)) as usize).min(self.backoff_ms.len() - 1);
        vec![ConnAction::ArmRetryTimer { delay_ms: self.backoff_ms[idx] }]
    }

    fn on_retry_timer(&mut self) -> Vec<ConnAction> {
        if !self.timer_armed {
            return vec![];
        }
        self.timer_armed = false;
        if self.terminal() {
            return vec![];
        }
        let mut acts = Vec::new();
        self.pending_join = true;
        if !self.socket_up {
            acts.push(ConnAction::Dial);
        } else {
            self.pending_join = false;
            acts.push(ConnAction::Join);
        }
        // Arm the reconnect deadline only if one isn't already running. A re-dial must
        // NOT reset it — a fast-failing connect (offline → connect_error → SocketError →
        // retry timer every ~1s) would otherwise keep re-arming the deadline so it never
        // fires and the attempt never climbs. (Bug 021-A)
        if !self.deadline_armed {
            self.deadline_armed = true;
            acts.push(ConnAction::ArmReconnectDeadline { delay_ms: self.ice_timeout_ms });
        }
        acts
    }

    fn manual_retry(&mut self) -> Vec<ConnAction> {
        if self.phase == ConnPhase::Completed || self.phase == ConnPhase::Expired {
            return vec![];
        }
        self.attempt = 0;
        self.retry_scheduled = false;
        self.timer_armed = false;
        self.phase = ConnPhase::Reconnecting;
        let mut acts = Vec::new();
        self.pending_join = true;
        if self.socket_up {
            self.pending_join = false;
            acts.push(ConnAction::Join);
        } else {
            acts.push(ConnAction::Dial);
        }
        self.deadline_armed = true;
        acts.push(ConnAction::ArmReconnectDeadline { delay_ms: self.ice_timeout_ms });
        acts
    }

    fn terminal(&self) -> bool {
        self.phase == ConnPhase::Completed || self.phase == ConnPhase::Expired
    }

    pub fn phase(&self) -> ConnPhase {
        self.phase
    }
    pub fn attempts(&self) -> u32 {
        self.attempt
    }
    pub fn resume_point(&self) -> u64 {
        self.resume_from
    }
}

#[cfg(test)]
mod tests {
    use super::ConnAction::*;
    use super::*;

    fn kinds(a: &[ConnAction]) -> Vec<&'static str> {
        a.iter().map(|x| match x {
            Dial => "dial",
            Join => "join",
            BuildPc { .. } => "buildPc",
            ArmRetryTimer { .. } => "armRetryTimer",
            ArmReconnectDeadline { .. } => "armReconnectDeadline",
            Stopped => "stopped",
            Expired => "expired",
            Completed => "completed",
        }).collect()
    }

    fn run(m: &mut ConnectionMachine, evs: Vec<ConnEvent>) -> Vec<&'static str> {
        let mut out = Vec::new();
        for ev in evs {
            out.extend(kinds(&m.handle(ev)));
        }
        out
    }

    fn to_transferring(m: &mut ConnectionMachine) {
        m.handle(ConnEvent::Start);
        m.handle(ConnEvent::SocketUp);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 1 });
        m.handle(ConnEvent::BothReady { generation: 1 });
        m.handle(ConnEvent::DcOpen);
    }

    fn exhaust_to_stopped(m: &mut ConnectionMachine) -> Vec<ConnAction> {
        m.handle(ConnEvent::DcClosed);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::ReconnectDeadline);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::ReconnectDeadline);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::ReconnectDeadline)
    }

    #[test]
    fn happy_path() {
        let mut m = ConnectionMachine::default();
        assert_eq!(m.handle(ConnEvent::Start), vec![Dial]);
        assert_eq!(m.handle(ConnEvent::SocketUp), vec![Join]);
        assert_eq!(m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 1 }), vec![]);
        assert_eq!(m.phase(), ConnPhase::Waiting);
        assert_eq!(m.handle(ConnEvent::BothReady { generation: 1 }), vec![BuildPc { resume_from: 0 }]);
        m.handle(ConnEvent::DcOpen);
        assert_eq!(m.phase(), ConnPhase::Transferring);
    }

    #[test]
    fn b1_flapping_climbs_to_stopped_dcopen_does_not_reset() {
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        m.handle(ConnEvent::DcClosed);
        assert_eq!(m.attempts(), 1);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::DcOpen);
        assert_eq!(m.attempts(), 1, "DcOpen must NOT zero the budget");
        m.handle(ConnEvent::DcClosed);
        assert_eq!(m.attempts(), 2);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::DcOpen);
        m.handle(ConnEvent::DcClosed);
        assert_eq!(m.attempts(), 3);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::DcOpen);
        assert_eq!(kinds(&m.handle(ConnEvent::DcClosed)), vec!["stopped"]);
        assert_eq!(m.phase(), ConnPhase::Stopped);
    }

    #[test]
    fn b1_transfer_progress_resets_budget() {
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        m.handle(ConnEvent::DcClosed);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::DcOpen);
        assert_eq!(m.attempts(), 1);
        m.handle(ConnEvent::TransferProgress);
        assert_eq!(m.attempts(), 0, "real progress resets the budget");
        m.handle(ConnEvent::DcClosed);
        assert_eq!(m.attempts(), 1);
    }

    #[test]
    fn reconnect_stall_climbs_when_join_without_both_ready() {
        // A reconnect re-joins the socket but never reaches a DataChannel (no BothReady) —
        // the reconnect deadline must fire and climb the attempt (was stuck at 1 because
        // Joined disarmed the deadline). BUG-RECONNECT-STALL.
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        m.handle(ConnEvent::DcClosed);
        assert_eq!(m.attempts(), 1);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 2 });
        m.handle(ConnEvent::ReconnectDeadline);
        assert_eq!(m.attempts(), 2, "join-without-both-ready must climb to 2");
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 3 });
        m.handle(ConnEvent::ReconnectDeadline);
        assert_eq!(m.attempts(), 3);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 4 });
        assert_eq!(kinds(&m.handle(ConnEvent::ReconnectDeadline)), vec!["stopped"]);
    }

    #[test]
    fn reconnect_stall_guard_successful_reconnect_no_overcount() {
        // The inverse: a real recovery (joined → both-ready → dc-open) clears the deadline,
        // so a later deadline tick is a no-op (no spurious extra retry).
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        m.handle(ConnEvent::DcClosed);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 2 });
        m.handle(ConnEvent::BothReady { generation: 2 });
        m.handle(ConnEvent::DcOpen);
        assert_eq!(m.handle(ConnEvent::ReconnectDeadline), vec![]);
        assert_eq!(m.phase(), ConnPhase::Transferring);
    }

    #[test]
    fn auto_retry_succeeds_2nd_attempt() {
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        let acts = run(&mut m, vec![
            ConnEvent::DcClosed,
            ConnEvent::RetryTimer,
            ConnEvent::ReconnectDeadline,
            ConnEvent::RetryTimer,
            ConnEvent::Joined { last_chunk_offset: 50, generation: 2 },
            ConnEvent::BothReady { generation: 2 },
            ConnEvent::DcOpen,
        ]);
        assert!(!acts.contains(&"stopped"));
        assert!(acts.contains(&"buildPc"));
        assert_eq!(m.phase(), ConnPhase::Transferring);
    }

    #[test]
    fn resumes_from_checkpoint() {
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        m.handle(ConnEvent::DcClosed);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 4000, generation: 2 });
        assert_eq!(m.handle(ConnEvent::BothReady { generation: 2 }), vec![BuildPc { resume_from: 4000 }]);
    }

    #[test]
    fn manual_retry_first_time() {
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        assert_eq!(kinds(&exhaust_to_stopped(&mut m)), vec!["stopped"]);
        assert_eq!(m.phase(), ConnPhase::Stopped);
        let acts = run(&mut m, vec![
            ConnEvent::ManualRetry,
            ConnEvent::Joined { last_chunk_offset: 10, generation: 5 },
            ConnEvent::BothReady { generation: 5 },
            ConnEvent::DcOpen,
        ]);
        assert!(acts.contains(&"buildPc"));
        assert_eq!(m.phase(), ConnPhase::Transferring);
    }

    #[test]
    fn manual_retry_second_time() {
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        exhaust_to_stopped(&mut m); // stopped #1
        m.handle(ConnEvent::ManualRetry);
        m.handle(ConnEvent::ReconnectDeadline);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::ReconnectDeadline);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::ReconnectDeadline);
        m.handle(ConnEvent::RetryTimer);
        assert_eq!(kinds(&m.handle(ConnEvent::ReconnectDeadline)), vec!["stopped"]); // stopped #2
        let acts = run(&mut m, vec![
            ConnEvent::ManualRetry,
            ConnEvent::Joined { last_chunk_offset: 10, generation: 9 },
            ConnEvent::BothReady { generation: 9 },
            ConnEvent::DcOpen,
        ]);
        assert!(acts.contains(&"buildPc"));
        assert_eq!(m.phase(), ConnPhase::Transferring);
    }

    #[test]
    fn network_change_one_attempt_then_redial() {
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        m.handle(ConnEvent::SocketDown);
        assert_eq!(m.handle(ConnEvent::DcClosed), vec![]); // cluster dedup
        assert_eq!(m.attempts(), 1);
        assert_eq!(kinds(&m.handle(ConnEvent::RetryTimer)), vec!["dial", "armReconnectDeadline"]);
        m.handle(ConnEvent::ReconnectDeadline);
        assert_eq!(kinds(&m.handle(ConnEvent::RetryTimer)), vec!["dial", "armReconnectDeadline"]);
        let acts = run(&mut m, vec![
            ConnEvent::SocketUp,
            ConnEvent::Joined { last_chunk_offset: 4000, generation: 7 },
            ConnEvent::BothReady { generation: 7 },
            ConnEvent::DcOpen,
        ]);
        assert!(acts.contains(&"join"));
        assert_eq!(m.phase(), ConnPhase::Transferring);
    }

    #[test]
    fn clustered_failures_one_retry() {
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        m.handle(ConnEvent::SocketDown);
        m.handle(ConnEvent::SocketError);
        m.handle(ConnEvent::DcClosed);
        m.handle(ConnEvent::IceFailed);
        assert_eq!(m.attempts(), 1);
    }

    #[test]
    fn fatal_error_expires() {
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        assert_eq!(kinds(&m.handle(ConnEvent::Error { code: "session_deleted".into() })), vec!["expired"]);
        assert_eq!(m.phase(), ConnPhase::Expired);
        assert_eq!(m.handle(ConnEvent::ManualRetry), vec![]);
        assert_eq!(m.handle(ConnEvent::DcClosed), vec![]);
    }

    #[test]
    fn recoverable_error_retries() {
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        assert_eq!(kinds(&m.handle(ConnEvent::Error { code: "peer_timeout".into() })), vec!["armRetryTimer"]);
        assert_ne!(m.phase(), ConnPhase::Expired);
        assert_eq!(m.phase(), ConnPhase::Reconnecting);
    }

    #[test]
    fn transfer_complete_terminal() {
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        assert_eq!(kinds(&m.handle(ConnEvent::TransferComplete)), vec!["completed"]);
        assert_eq!(m.phase(), ConnPhase::Completed);
        assert_eq!(m.handle(ConnEvent::DcClosed), vec![]);
    }

    #[test]
    fn peer_disconnected_fast_reconnect_recovers() {
        // The peer drops but returns quickly: PeerDisconnected starts the climb
        // (attempt → 1, retry timer armed), but a BothReady → DcOpen recovers and
        // the first TransferProgress resets the budget. (BUG-020)
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        assert_eq!(kinds(&m.handle(ConnEvent::PeerDisconnected)), vec!["armRetryTimer"]);
        assert_eq!(m.phase(), ConnPhase::Reconnecting);
        assert_eq!(m.attempts(), 1, "peer-drop must enter the retry budget");
        m.handle(ConnEvent::RetryTimer);
        assert_eq!(kinds(&m.handle(ConnEvent::BothReady { generation: 3 })), vec!["buildPc"]);
        m.handle(ConnEvent::DcOpen);
        m.handle(ConnEvent::TransferProgress);
        assert_eq!(m.attempts(), 0, "real progress resets the budget");
        assert_eq!(m.phase(), ConnPhase::Transferring);
    }

    #[test]
    fn bug021a_fast_failing_offline_reconnect_still_climbs() {
        // Offline: dial fails instantly → SocketError → retry timer (~1s). The re-dial
        // must NOT re-arm the 10s deadline, or it never fires and the attempt sticks at 1.
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        m.handle(ConnEvent::SocketDown); // attempt 1, offline
        assert_eq!(m.attempts(), 1);
        assert_eq!(kinds(&m.handle(ConnEvent::RetryTimer)), vec!["dial", "armReconnectDeadline"]);
        for _ in 0..5 {
            m.handle(ConnEvent::SocketError); // dedup → re-arm retry timer only
            assert_eq!(kinds(&m.handle(ConnEvent::RetryTimer)), vec!["dial"], "redial must not re-arm deadline");
            assert_eq!(m.attempts(), 1, "still 1 until the deadline fires");
        }
        m.handle(ConnEvent::ReconnectDeadline);
        assert_eq!(m.attempts(), 2, "deadline fires once → climb");
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::ReconnectDeadline);
        assert_eq!(m.attempts(), 3);
        m.handle(ConnEvent::RetryTimer);
        assert_eq!(kinds(&m.handle(ConnEvent::ReconnectDeadline)), vec!["stopped"]);
    }

    #[test]
    fn bug021b_waiting_side_returns_to_waiting_after_blip() {
        // A side waiting for a peer (no BothReady) must not escalate on a transient
        // drop — on re-join it returns to Waiting with the budget reset.
        let mut m = ConnectionMachine::default();
        m.handle(ConnEvent::Start);
        m.handle(ConnEvent::SocketUp);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 1 });
        assert_eq!(m.phase(), ConnPhase::Waiting);
        m.handle(ConnEvent::SocketDown);
        assert_eq!(m.attempts(), 1);
        assert_eq!(m.phase(), ConnPhase::Reconnecting);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 2 });
        assert_eq!(m.phase(), ConnPhase::Waiting, "pre-peer re-join returns to waiting");
        assert_eq!(m.attempts(), 0, "budget reset, not escalating while waiting");
        assert_eq!(m.handle(ConnEvent::ReconnectDeadline), vec![], "stale deadline tick is a no-op");
    }

    #[test]
    fn bug021b_guard_peer_present_join_still_climbs() {
        // 019/020 unchanged: once a peer existed, a join-without-DataChannel keeps climbing.
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m); // peer_ever_present = true
        m.handle(ConnEvent::DcClosed);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 2 });
        assert_eq!(m.phase(), ConnPhase::Reconnecting, "active-session re-join stays reconnecting");
        m.handle(ConnEvent::ReconnectDeadline);
        assert_eq!(m.attempts(), 2, "still climbs (peer was present)");
    }

    #[test]
    fn receiver_without_bothready_climbs_via_dcopen() {
        // The CLI receiver flow never dispatches BothReady — it reaches a live
        // DataChannel via Start → SocketUp → Joined → DcOpen. DcOpen must set
        // peer_ever_present so a later rejoin-driven Joined while reconnecting keeps
        // climbing the budget (1→2→3→stopped) instead of the 021-B "pre-peer" branch
        // resetting the attempt to 0 every retry (the bug: stuck at 1). (Bug 024-A)
        let mut m = ConnectionMachine::default();
        m.handle(ConnEvent::Start);
        m.handle(ConnEvent::SocketUp);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 1 });
        m.handle(ConnEvent::DcOpen); // NO BothReady — receiver-only path
        assert_eq!(m.phase(), ConnPhase::Transferring);

        m.handle(ConnEvent::DcClosed);
        assert_eq!(m.attempts(), 1);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 2 }); // rejoin
        assert_eq!(m.phase(), ConnPhase::Reconnecting, "peer was present → stays reconnecting, not Waiting");
        assert_eq!(m.attempts(), 1, "rejoin must NOT reset the budget to 0");
        m.handle(ConnEvent::ReconnectDeadline);
        assert_eq!(m.attempts(), 2, "join-without-dc must climb to 2");

        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 3 });
        m.handle(ConnEvent::ReconnectDeadline);
        assert_eq!(m.attempts(), 3);

        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 4 });
        assert_eq!(kinds(&m.handle(ConnEvent::ReconnectDeadline)), vec!["stopped"]);
        assert_eq!(m.phase(), ConnPhase::Stopped);
    }

    #[test]
    fn peer_disconnected_stays_gone_climbs_to_stopped() {
        // The peer drops and never returns: the counter must climb 1→2→3 → stopped
        // → (manual retry), not freeze in Reconnecting. (BUG-020 — the user's report)
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        m.handle(ConnEvent::PeerDisconnected);
        assert_eq!(m.attempts(), 1);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 2 });
        m.handle(ConnEvent::ReconnectDeadline);
        assert_eq!(m.attempts(), 2, "peer still gone → climb to 2");
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 3 });
        m.handle(ConnEvent::ReconnectDeadline);
        assert_eq!(m.attempts(), 3);
        m.handle(ConnEvent::RetryTimer);
        m.handle(ConnEvent::Joined { last_chunk_offset: 0, generation: 4 });
        assert_eq!(kinds(&m.handle(ConnEvent::ReconnectDeadline)), vec!["stopped"]);
        assert_eq!(m.phase(), ConnPhase::Stopped);
    }
}
