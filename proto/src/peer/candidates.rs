//! The peer's shared candidates and the `cand`/`candack` exchange.
//!
//! [`Candidates`] outlives sessions: the peer's set from its latest handshake or `cand`, the
//! greatest `seq` accepted from it, and what this node last told it. [`Telling`] is a `cand` of
//! ours awaiting its `candack`; it lives in `Link::Up` and is dropped with the session.

use std::time::Duration;

use crate::discovery::candidate::{Candidate, MAX_CANDIDATES};
use crate::time::Instant;

/// What the node knows of the candidates it exchanges with one peer.
#[derive(Debug, Clone, Default)]
pub(crate) struct Candidates {
    /// The peer's shared candidates, at most [`MAX_CANDIDATES`].
    shared: Vec<Candidate>,
    /// The greatest `seq` of a `cand` accepted from the peer.
    accepted: Option<u64>,
    /// The `seq` of our latest `cand`.
    seq: u64,
    /// Our shared candidates as the peer last heard them, in a handshake or a `cand`.
    told: Vec<Candidate>,
}

/// A `cand` of ours that the peer has not acknowledged yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Telling {
    pub(crate) seq: u64,
    pub(crate) cand: Vec<Candidate>,
    /// When it goes out again.
    pub(crate) next: Instant,
    pub(crate) tries: u32,
}

impl Candidates {
    /// The peer's shared candidates.
    pub(crate) fn shared(&self) -> &[Candidate] {
        &self.shared
    }

    /// A handshake completed: `told` is what our payload carried, `theirs` what the peer's
    /// carried. A non-empty `theirs` replaces the peer's set without touching `accepted`.
    /// Returns whether the peer's set changed.
    pub(crate) fn handshake(&mut self, told: &[Candidate], theirs: &[Candidate]) -> bool {
        self.told = shared_only(told);
        if theirs.is_empty() {
            return false;
        }
        let theirs = shared_only(theirs);
        let changed = theirs != self.shared;
        self.shared = theirs;
        changed
    }

    /// Our shared candidates are `own` now: if they differ from `told`, a new `cand` with the
    /// next `seq`, due again one `rto` after `now`.
    pub(crate) fn tell(
        &mut self,
        now: Instant,
        rto: Duration,
        own: &[Candidate],
    ) -> Option<Telling> {
        let own = shared_only(own);
        if own == self.told {
            return None;
        }
        self.told = own.clone();
        self.seq = self.seq.saturating_add(1);
        Some(Telling {
            seq: self.seq,
            cand: own,
            next: now + rto,
            tries: 0,
        })
    }

    /// A `cand` arrived. A `seq` above `accepted` replaces the peer's set. Returns the `seq` to
    /// acknowledge (the greatest accepted, which an old `cand` also gets) and whether the set
    /// changed.
    pub(crate) fn receive(&mut self, seq: u64, cand: &[Candidate]) -> (u64, bool) {
        if let Some(accepted) = self.accepted.filter(|a| seq <= *a) {
            return (accepted, false);
        }
        self.accepted = Some(seq);
        let cand = shared_only(cand);
        let changed = cand != self.shared;
        self.shared = cand;
        (seq, changed)
    }

    /// A `candack` of `seq` arrived for `telling`. At or above its `seq`, `telling` is done. Above
    /// our own `seq`, the peer remembers a set of an earlier run of this node: `seq` jumps past
    /// it and the set is told again at once, as with [`Candidates::tell`]. Returns what is still
    /// to tell.
    pub(crate) fn acked(
        &mut self,
        now: Instant,
        rto: Duration,
        seq: u64,
        telling: Option<Telling>,
    ) -> Option<Telling> {
        if seq > self.seq {
            self.seq = seq.saturating_add(1);
            return Some(Telling {
                seq: self.seq,
                cand: self.told.clone(),
                next: now + rto,
                tries: 0,
            });
        }
        telling.filter(|t| seq < t.seq)
    }
}

impl Telling {
    /// After a send at `now`: the next one in `rto × 2^tries`, at most `keepalive_timeout`.
    pub(crate) fn sent(&mut self, now: Instant, rto: Duration, keepalive_timeout: Duration) {
        self.tries = self.tries.saturating_add(1);
        let backoff = rto * (1u32 << self.tries.min(8));
        self.next = now + backoff.min(keepalive_timeout);
    }
}

fn shared_only(list: &[Candidate]) -> Vec<Candidate> {
    list.iter()
        .filter(|c| c.shared)
        .copied()
        .take(MAX_CANDIDATES)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTO: Duration = Duration::from_millis(200);
    const KEEPALIVE: Duration = Duration::from_secs(10);

    fn at(ms: u64) -> Instant {
        Instant::from_millis(ms)
    }

    fn punch(port: u16) -> Candidate {
        Candidate::punch(format!("203.0.113.9:{port}").parse().unwrap())
    }

    fn lan(port: u16) -> Candidate {
        Candidate::lan(format!("192.168.1.5:{port}").parse().unwrap())
    }

    #[test]
    fn a_new_set_is_told_once_with_the_next_seq() {
        let mut c = Candidates::default();
        let t = c.tell(at(10), RTO, &[punch(1)]).unwrap();
        assert_eq!((t.seq, t.tries), (1, 0));
        assert_eq!(t.cand, vec![punch(1)]);
        assert_eq!(t.next, at(10) + RTO);
        assert_eq!(c.tell(at(20), RTO, &[punch(1)]), None);
        assert_eq!(c.tell(at(30), RTO, &[punch(1), punch(2)]).unwrap().seq, 2);
    }

    #[test]
    fn an_empty_set_is_not_told_but_a_withdrawn_one_is() {
        let mut c = Candidates::default();
        assert_eq!(c.tell(at(0), RTO, &[]), None);
        c.tell(at(0), RTO, &[punch(1)]).unwrap();
        let t = c.tell(at(1), RTO, &[]).unwrap();
        assert_eq!((t.seq, t.cand), (2, vec![]));
    }

    #[test]
    fn only_shared_candidates_are_told_and_at_most_max_candidates() {
        let mut c = Candidates::default();
        assert_eq!(c.tell(at(0), RTO, &[lan(1)]), None);
        let many: Vec<Candidate> = (1..=12).map(punch).collect();
        let t = c.tell(at(0), RTO, &[lan(1), many[0], many[1]]).unwrap();
        assert_eq!(t.cand, vec![punch(1), punch(2)]);
        let t = c.tell(at(1), RTO, &many).unwrap();
        assert_eq!(t.cand.len(), MAX_CANDIDATES);
    }

    #[test]
    fn a_telling_is_retried_at_rto_doubling_up_to_the_keepalive_timeout() {
        let mut c = Candidates::default();
        let mut t = c.tell(at(0), RTO, &[punch(1)]).unwrap();
        let mut gaps = Vec::new();
        let mut now = t.next;
        for _ in 0..8 {
            t.sent(now, RTO, KEEPALIVE);
            gaps.push(t.next - now);
            now = t.next;
        }
        let ms = |n| Duration::from_millis(n);
        assert_eq!(
            gaps,
            [
                ms(400),
                ms(800),
                ms(1600),
                ms(3200),
                ms(6400),
                KEEPALIVE,
                KEEPALIVE,
                KEEPALIVE
            ]
        );
    }

    #[test]
    fn an_acknowledgement_at_or_above_the_seq_ends_the_telling() {
        let mut c = Candidates::default();
        let t = c.tell(at(0), RTO, &[punch(1)]).unwrap();
        assert_eq!(c.acked(at(5), RTO, 1, Some(t.clone())), None);
        let t2 = c.tell(at(6), RTO, &[punch(2)]).unwrap();
        assert_eq!(c.acked(at(7), RTO, 2, Some(t2.clone())), None);
    }

    #[test]
    fn an_acknowledgement_below_the_seq_leaves_the_telling_going() {
        let mut c = Candidates::default();
        c.tell(at(0), RTO, &[punch(1)]).unwrap();
        let t2 = c.tell(at(6), RTO, &[punch(2)]).unwrap();
        assert_eq!(c.acked(at(7), RTO, 1, Some(t2.clone())), Some(t2));
    }

    #[test]
    fn an_acknowledgement_above_our_seq_makes_us_tell_again_past_it() {
        let mut c = Candidates::default();
        let t = c.tell(at(0), RTO, &[punch(1)]).unwrap();
        let again = c.acked(at(5), RTO, 7, Some(t)).unwrap();
        assert_eq!((again.seq, again.tries), (8, 0));
        assert_eq!(again.cand, vec![punch(1)]);
        assert_eq!(again.next, at(5) + RTO);
        assert_eq!(c.acked(at(6), RTO, 8, Some(again)), None);
        assert_eq!(c.tell(at(7), RTO, &[punch(1), punch(2)]).unwrap().seq, 9);
    }

    #[test]
    fn an_acknowledgement_above_our_seq_with_nothing_pending_tells_the_current_set() {
        let mut c = Candidates::default();
        let t = c.tell(at(0), RTO, &[punch(1)]).unwrap();
        assert_eq!(c.acked(at(1), RTO, 1, Some(t)), None);
        let again = c.acked(at(2), RTO, 4, None).unwrap();
        assert_eq!((again.seq, again.cand), (5, vec![punch(1)]));
    }

    #[test]
    fn a_cand_replaces_the_peers_set_and_reports_the_change() {
        let mut c = Candidates::default();
        assert_eq!(c.receive(1, &[punch(1), lan(2)]), (1, true));
        assert_eq!(c.shared(), [punch(1)]);
        assert_eq!(c.receive(2, &[punch(1)]), (2, false));
        assert_eq!(c.receive(3, &[punch(3)]), (3, true));
        assert_eq!(c.shared(), [punch(3)]);
    }

    #[test]
    fn an_old_cand_is_acknowledged_with_the_greatest_seq_and_changes_nothing() {
        let mut c = Candidates::default();
        c.receive(5, &[punch(5)]);
        assert_eq!(c.receive(3, &[punch(3)]), (5, false));
        assert_eq!(c.receive(5, &[punch(9)]), (5, false));
        assert_eq!(c.shared(), [punch(5)]);
    }

    #[test]
    fn the_first_cand_is_accepted_whatever_its_seq() {
        let mut c = Candidates::default();
        assert_eq!(c.receive(0, &[punch(1)]), (0, true));
    }

    #[test]
    fn a_handshake_replaces_the_peers_set_without_touching_the_accepted_seq() {
        let mut c = Candidates::default();
        c.receive(4, &[punch(4)]);
        assert!(c.handshake(&[], &[punch(8), lan(9)]));
        assert_eq!(c.shared(), [punch(8)]);
        assert!(!c.handshake(&[], &[punch(8)]));
        assert_eq!(c.receive(4, &[punch(4)]), (4, false));
        assert_eq!(c.receive(5, &[punch(5)]), (5, true));
    }

    #[test]
    fn a_handshake_without_candidates_keeps_the_peers_set() {
        let mut c = Candidates::default();
        c.receive(1, &[punch(1)]);
        assert!(!c.handshake(&[], &[]));
        assert_eq!(c.shared(), [punch(1)]);
    }

    #[test]
    fn what_the_handshake_told_is_not_told_again() {
        let mut c = Candidates::default();
        c.handshake(&[punch(1), lan(3)], &[]);
        assert_eq!(c.tell(at(0), RTO, &[punch(1)]), None);
        assert_eq!(c.tell(at(0), RTO, &[punch(2)]).unwrap().seq, 1);
    }
}
