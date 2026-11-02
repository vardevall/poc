//! Settling of local change notifications and the gathering rounds they trigger (vv-05 §3.2,
//! §4.6).
//!
//! [`LocalChanges`] belongs to the node, not to a peer. The caller reports every notification of
//! the platform with the address families it affects, runs the rounds it is told to start, and
//! reports a round's end. A burst of notifications is one change: it settles once no notification
//! has arrived for `CHANGE_SETTLE`, and only then does a round start and the node's routes learn of
//! the change.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use crate::discovery::candidate::{Candidate, label};
use crate::time::Instant;

/// Local change notifications this close to each other are one change (vv-05 §3.2).
pub const CHANGE_SETTLE: Duration = Duration::from_millis(250);

/// A set of address families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Families {
    /// IPv4.
    pub v4: bool,
    /// IPv6.
    pub v6: bool,
}

impl Families {
    /// Neither family.
    pub const NONE: Families = Families {
        v4: false,
        v6: false,
    };
    /// IPv4 only.
    pub const V4: Families = Families {
        v4: true,
        v6: false,
    };
    /// IPv6 only.
    pub const V6: Families = Families {
        v4: false,
        v6: true,
    };
    /// Both families.
    pub const BOTH: Families = Families { v4: true, v6: true };

    /// Whether neither family is in the set.
    pub const fn is_empty(self) -> bool {
        !self.v4 && !self.v6
    }

    /// The families in either set.
    pub const fn union(self, other: Families) -> Families {
        Families {
            v4: self.v4 || other.v4,
            v6: self.v6 || other.v6,
        }
    }

    /// Whether the family of `addr` is in the set.
    pub const fn contains(self, addr: &SocketAddr) -> bool {
        if addr.is_ipv4() { self.v4 } else { self.v6 }
    }
}

/// A gathering round, by the number [`LocalChanges`] gave it.
pub type RoundId = u64;

/// What the caller does for [`LocalChanges`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeAction {
    /// The change has settled: report it to the node
    /// ([`Node::local_change`](crate::node::Node::local_change)).
    Settled,
    /// Start a gathering round (vv-05 §3.1) for these families.
    StartRound {
        /// The round.
        round: RoundId,
        /// The families to gather for.
        families: Families,
    },
    /// Abandon a round that is running: a further change arrived.
    CancelRound(RoundId),
}

/// The state of local changes and gathering rounds of a node.
#[derive(Debug, Clone, Default)]
pub struct LocalChanges {
    settle: Duration,
    settle_at: Option<Instant>,
    stale: Families,
    running: Option<RoundId>,
    next_round: RoundId,
    actions: VecDeque<ChangeAction>,
}

impl LocalChanges {
    /// A tracker with the default `CHANGE_SETTLE`.
    pub fn new() -> Self {
        Self::with_settle(CHANGE_SETTLE)
    }

    /// A tracker with another settling time.
    pub fn with_settle(settle: Duration) -> Self {
        LocalChanges {
            settle,
            ..Default::default()
        }
    }

    /// Takes the next action.
    pub fn poll_action(&mut self) -> Option<ChangeAction> {
        self.actions.pop_front()
    }

    /// The platform reported a change that affects `families`. A round that is running is
    /// cancelled; the change settles `CHANGE_SETTLE` after the last notification.
    pub fn change(&mut self, now: Instant, families: Families) {
        if let Some(id) = self.running.take() {
            self.actions.push_back(ChangeAction::CancelRound(id));
        }
        self.stale = self.stale.union(families);
        self.settle_at = Some(now + self.settle);
    }

    /// The instant at which [`LocalChanges::handle_timeout`] has work.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.settle_at
    }

    /// Settles the change if no notification arrived for `CHANGE_SETTLE`: the node is
    /// told and a round starts for the families affected since the last completed round.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.settle_at.is_none_or(|t| t > now) {
            return;
        }
        self.settle_at = None;
        let id = self.next_round;
        self.next_round = id.saturating_add(1);
        self.running = Some(id);
        self.actions.push_back(ChangeAction::Settled);
        self.actions.push_back(ChangeAction::StartRound {
            round: id,
            families: self.stale,
        });
    }

    /// The round `round` completed. Returns whether it was the current round: a cancelled round's
    /// results are stale and the caller discards them.
    pub fn round_complete(&mut self, round: RoundId) -> bool {
        if self.running != Some(round) {
            return false;
        }
        self.running = None;
        self.stale = Families::NONE;
        true
    }

    /// The families whose `punch` candidates are out of date: a change happened and no round
    /// started after the latest one has completed (vv-05 §3.2).
    pub fn stale(&self) -> Families {
        self.stale
    }

    /// Removes the `punch` candidates of stale families from the candidates for a handshake. The
    /// new ones follow in a `cand` message as soon as the round completes (vv-05 §4.9).
    pub fn for_handshake(&self, candidates: &[Candidate]) -> Vec<Candidate> {
        candidates
            .iter()
            .filter(|c| !(c.label == label::PUNCH && self.stale.contains(&c.addr)))
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(ms: u64) -> Instant {
        Instant::from_millis(ms)
    }

    fn actions(c: &mut LocalChanges) -> Vec<ChangeAction> {
        std::iter::from_fn(|| c.poll_action()).collect()
    }

    #[test]
    fn a_burst_of_notifications_is_one_change() {
        let mut c = LocalChanges::new();
        for t in [0, 100, 300, 500] {
            c.change(at(t), Families::V4);
            c.handle_timeout(at(t));
        }
        assert!(actions(&mut c).is_empty());
        assert_eq!(c.poll_timeout(), Some(at(750)));
        c.handle_timeout(at(749));
        assert!(actions(&mut c).is_empty());
        c.handle_timeout(at(750));
        assert_eq!(
            actions(&mut c),
            [
                ChangeAction::Settled,
                ChangeAction::StartRound {
                    round: 0,
                    families: Families::V4
                }
            ]
        );
        assert_eq!(c.poll_timeout(), None);
    }

    #[test]
    fn a_change_during_a_round_cancels_it_and_a_new_round_follows_the_settle() {
        let mut c = LocalChanges::new();
        c.change(at(0), Families::V4);
        c.handle_timeout(at(250));
        actions(&mut c);
        c.change(at(400), Families::V6);
        assert_eq!(actions(&mut c), [ChangeAction::CancelRound(0)]);
        assert!(!c.round_complete(0), "the cancelled round is stale");
        assert_eq!(c.stale(), Families::BOTH);
        c.handle_timeout(at(650));
        assert_eq!(
            actions(&mut c),
            [
                ChangeAction::Settled,
                ChangeAction::StartRound {
                    round: 1,
                    families: Families::BOTH
                }
            ]
        );
        assert!(c.round_complete(1));
        assert_eq!(c.stale(), Families::NONE);
    }

    #[test]
    fn a_handshake_carries_no_punch_candidates_of_stale_families() {
        let mut c = LocalChanges::new();
        let cand = |make: fn(SocketAddr) -> Candidate, a: &str| make(a.parse().unwrap());
        let all = [
            cand(Candidate::punch, "203.0.113.1:1"),
            cand(Candidate::punch, "[2001:db8::1]:1"),
            cand(Candidate::relay, "198.51.100.4:2"),
        ];
        assert_eq!(c.for_handshake(&all), all);
        c.change(at(0), Families::V4);
        assert_eq!(c.for_handshake(&all), all[1..]);
        c.handle_timeout(at(250));
        assert_eq!(
            c.for_handshake(&all),
            all[1..],
            "still stale during the round"
        );
        assert!(c.round_complete(0));
        assert_eq!(c.for_handshake(&all), all);
    }
}
