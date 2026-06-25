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
                self.retry_scheduled = false;
                self.timer_armed = false;
                self.deadline_armed = false;
                self.generation = generation;
                if last_chunk_offset > self.resume_from {
                    self.resume_from = last_chunk_offset;
                }
                if self.attempt == 0 {
                    self.phase = ConnPhase::Waiting;
                }
                vec![]
            }
            ConnEvent::BothReady { generation } => {
                self.generation = generation;
                self.deadline_armed = false;
                if self.phase == ConnPhase::Stopped {
                    self.attempt = 0;
                    self.retry_scheduled = false;
                }
                self.phase = ConnPhase::Negotiating;
                vec![ConnAction::BuildPc { resume_from: self.resume_from }]
            }
            ConnEvent::DcOpen => {
                self.phase = ConnPhase::Transferring;
                self.attempt = 0;
                self.retry_scheduled = false;
                self.timer_armed = false;
                self.deadline_armed = false;
                vec![]
            }
            ConnEvent::PeerDisconnected => {
                if self.terminal() {
                    return vec![];
                }
                self.phase = ConnPhase::Reconnecting;
                vec![]
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
        self.deadline_armed = true;
        acts.push(ConnAction::ArmReconnectDeadline { delay_ms: self.ice_timeout_ms });
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
    fn peer_disconnected_waits() {
        let mut m = ConnectionMachine::default();
        to_transferring(&mut m);
        assert_eq!(m.handle(ConnEvent::PeerDisconnected), vec![]);
        assert_eq!(m.phase(), ConnPhase::Reconnecting);
        assert_eq!(m.attempts(), 0);
        assert_eq!(m.handle(ConnEvent::BothReady { generation: 3 }), vec![BuildPc { resume_from: 0 }]);
    }
}
