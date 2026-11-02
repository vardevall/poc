//! Local changes (vv-05 §3.2, §4.6): the platform's notifications settle into one change, which
//! the routes learn of, and a gathering round follows it.

use vardevall_proto::route::{ChangeAction, Families, Latency, Next, RoundId, Status};
use vardevall_proto::time::Instant;
use vardevall_proto::transport::Remote;

use vardevall_proto::discovery::candidate::{Candidate, MAX_CANDIDATES};
use vardevall_switch_proto::reflexive::Mapping;

use super::Node;
use crate::event::LogLevel;

fn describe(m: Option<Mapping>) -> String {
    match m {
        None => "no server".to_owned(),
        Some(Mapping::Punchable(a)) => format!("punchable {a}"),
        Some(Mapping::Symmetric) => "symmetric".to_owned(),
        Some(Mapping::Blocked) => "udp-blocked".to_owned(),
    }
}

impl Node {
    /// A platform notification: the addresses of `families` changed. The state that depends on
    /// them is out of date from now on, and the change settles once no further notification
    /// arrives for `CHANGE_SETTLE`.
    pub(super) fn on_local_change(&mut self, families: Families) {
        let now = self.clock.now().instant;
        self.changes.change(now, families);
        self.stun.reset();
        self.run_change_actions();
        self.refresh_hello();
        self.release_held_if_ready();
    }

    /// Runs the timers of the gathering: requests to resend, a retry after a silent round, a
    /// credential that ran out.
    pub(super) fn stun_timeout(&mut self, now: Instant) {
        for (to, data) in self.stun.handle_timeout(now, &mut self.rng) {
            self.send_to(to, &data);
        }
        if let Some(after) = self.stun.take_retry() {
            self.log(
                LogLevel::Debug,
                format!(
                    "STUN: retrying after {}s, no server answered",
                    after.as_secs()
                ),
            );
        }
        self.reflexive_done();
        self.stun.expire(now, self.udp.reach());
        if self.stun.next_doubt().is_some_and(|t| now >= t) {
            self.doubt_reflexive();
        }
    }

    /// Asks STUN again while a direct route that could win keeps failing: the node's mapping may
    /// have moved under a socket that kept sending. Without such a route the doubt
    /// ends.
    pub(super) fn doubt_reflexive(&mut self) {
        let families = self.failing_direct();
        if families.is_empty() {
            self.stun.trust();
            return;
        }
        let now = self.clock.now().instant;
        for (to, data) in self.stun.doubt(now, &mut self.rng, families) {
            self.send_to(to, &data);
        }
    }

    /// The families of the internet routes on the interface socket that failed and are still
    /// retried because they could win; LAN routes say nothing of the mapping.
    fn failing_direct(&self) -> Families {
        let mut families = Families::NONE;
        for peer in self.core.peers() {
            let Some(view) = self.core.peer_view(peer) else {
                continue;
            };
            for r in &view.routes {
                if let Remote::Addr(addr) = r.path.to
                    && r.path.via == self.media.udp
                    && r.class.latency == Latency::High
                    && r.status == Status::Failed
                    && matches!(r.next, Some(Next::Retry(_)))
                {
                    let family = if addr.is_ipv4() {
                        Families::V4
                    } else {
                        Families::V6
                    };
                    families = families.union(family);
                }
            }
        }
        families
    }

    /// Settles the change if the notifications stopped.
    pub(super) fn changes_timeout(&mut self) {
        let now = self.clock.now().instant;
        self.changes.handle_timeout(now);
        self.run_change_actions();
    }

    fn run_change_actions(&mut self) {
        while let Some(action) = self.changes.poll_action() {
            match action {
                ChangeAction::Settled => self.on_settled(),
                ChangeAction::StartRound { round, families } => {
                    self.start_round(round, families);
                }
                ChangeAction::CancelRound(round) => {
                    self.stun.cancel_round(round);
                }
            }
        }
    }

    /// The change settled: what does not survive it is redone and every route is verified
    /// again (vv-05 §4.6); the new candidates follow the gathering round.
    fn on_settled(&mut self) {
        let now = self.clock.now().instant;
        self.udp.rebind(now);
        self.flush_udp_log();
        for s in &mut self.sources {
            s.path_changed();
        }
        self.switches.path_changed();
        self.resolver.resolve_stun();
        self.turn.local_change();
        self.refresh_hello();
        self.release_held_if_ready();
        self.routes_local_change(self.changes.stale());
        self.log(LogLevel::Info, "local path changed".to_owned());
    }

    fn start_round(&mut self, round: RoundId, families: Families) {
        let now = self.clock.now().instant;
        for (to, data) in self.stun.restart(now, &mut self.rng, round, families) {
            self.send_to(to, &data);
        }
        if !self.stun.busy() {
            self.round_ended();
            self.refresh_hello();
            self.release_held_if_ready();
        }
    }

    /// Reports a finished round: the round `LocalChanges` waits for is complete, and the
    /// candidates follow the result.
    pub(super) fn reflexive_done(&mut self) {
        let Some(s) = self.stun.take_result() else {
            return;
        };
        self.log(
            LogLevel::Info,
            format!("STUN: ipv6 {}, ipv4 {}", describe(s.v6), describe(s.v4)),
        );
        self.round_ended();
        self.refresh_hello();
        self.release_held_if_ready();
    }

    /// The gathering round `LocalChanges` asked for ended, or there was nothing to gather.
    fn round_ended(&mut self) {
        if let Some(id) = self.stun.take_round() {
            self.changes.round_complete(id);
        }
    }

    /// Whether gathering is running or about to, after a local change (vv-05 §3.2).
    pub(super) fn gathering(&self) -> bool {
        self.stun.busy() || !self.changes.stale().is_empty()
    }

    /// Rebuilds the candidates of later handshakes from the STUN result and the allocation
    /// (vv-05 §2.2): no `punch` for a family that is `symmetric` or `udp-blocked` (§3.2), or
    /// whose result is out of date after a local change. Peers with a session get the change as
    /// a `cand` message (vv-05 §4.9).
    pub(super) fn refresh_hello(&mut self) {
        let candidates = self.own_candidates();
        let ready = self.turn.relayed().is_some();
        let now = self.clock.now();
        self.core
            .set_ready(now, &mut self.rng, self.media.turn, ready);
        self.core.set_own_candidates(now, &mut self.rng, candidates);
        self.drain();
    }

    /// The shared candidates of this node: `punch` from STUN, `relay` from the allocation; no
    /// `punch` of a family that a local change made stale (vv-05 §3.2).
    fn own_candidates(&self) -> Vec<Candidate> {
        let mut candidates = Vec::new();
        if let Some(s) = self.stun.snapshot() {
            for m in [s.v6, s.v4].into_iter().flatten() {
                if let Some(addr) = m.punch() {
                    candidates.push(Candidate::punch(addr).with_metered(self.local_metered));
                }
            }
        }
        if let Some(addr) = self.turn.relayed() {
            candidates.push(Candidate::relay(addr));
        }
        let mut candidates = self.changes.for_handshake(&candidates);
        candidates.truncate(MAX_CANDIDATES);
        candidates
    }

    /// The platform marked the interface as expensive or not (vv-05 §2.2).
    pub(super) fn on_metered(&mut self, metered: bool) {
        if self.local_metered == metered {
            return;
        }
        self.local_metered = metered;
        let now = self.clock.now();
        self.core.set_local_metered(now, &mut self.rng, metered);
        self.drain();
        self.refresh_hello();
    }

    /// A settled local change of `families`: their probed routes are verified again
    ///.
    fn routes_local_change(&mut self, families: Families) {
        let now = self.clock.now();
        self.core.local_change(now, &mut self.rng, families);
        self.drain();
    }
}
