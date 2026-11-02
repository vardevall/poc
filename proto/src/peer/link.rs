//! The sessions of one peer and the handshakes that make them.
//!
//! WireGuard's three slots become the variants of [`Link`]: a session exists only in the
//! state where it is valid, and an attempt carries the timers that belong to it.

use std::mem::take;

use crate::discovery::candidate::Candidate;
use crate::handshake::Initiator;
use crate::node::{PeerState, Reason};
use crate::peer::candidates::Telling;
use crate::route::paths::Paths;
use crate::session::Session;
use crate::time::Instant;
use crate::transport::Path;

/// Most messages 1 of one attempt kept awaiting an answer (retransmissions and the early
/// resend after a cookie use new indices).
pub(crate) const PENDING_LIMIT: usize = 4;

/// A handshake message in both framings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandshakeMessage {
    /// The two fragments, for [`crate::transport::Framing::Fragmented`] (vv-02 §5).
    pub(crate) fragments: [Vec<u8>; 2],
    /// Type byte and whole message, for [`crate::transport::Framing::Whole`] (vv-02 §1).
    pub(crate) whole: Vec<u8>,
}

/// One message 1 of ours awaiting its answer.
pub(crate) struct Sent {
    pub(crate) index: u32,
    pub(crate) initiator: Initiator,
    pub(crate) fragment_mac1: [[u8; 16]; 2],
    /// The candidates its payload carried.
    pub(crate) candidates: Vec<Candidate>,
    /// Sent at once after a cookie arrived, outside the retransmission schedule.
    pub(crate) early: bool,
    /// Whether a cookie for it already caused an early resend.
    pub(crate) early_used: bool,
}

/// An initiation of ours.
pub(crate) struct Attempt {
    pub(crate) started: Instant,
    /// Oldest first, at most [`PENDING_LIMIT`].
    pub(crate) sent: Vec<Sent>,
    /// The latest message 1, resent to targets found later (vv-05 §4.1).
    pub(crate) message: HandshakeMessage,
    pub(crate) retransmit_at: Instant,
    /// When the message also goes through the reporting transports, if direct targets were
    /// tried first (vv-05 §4.1, `FALLBACK_DELAY`).
    pub(crate) switch_at: Option<Instant>,
    /// Where message 1 went, for rule 4.1.4: the path message 2 arrives on is verified if
    /// message 1 went out on it.
    pub(crate) paths: Vec<Path>,
}

impl Attempt {
    fn indices(&self, keep: Option<u32>) -> impl Iterator<Item = u32> + '_ {
        self.sent
            .iter()
            .map(|s| s.index)
            .filter(move |i| Some(*i) != keep)
    }
}

/// A session we answered and that awaits its first authenticated frame (vv-02 §6.3).
pub(crate) struct Responded {
    pub(crate) session: Session,
    /// Position among all unconfirmed sessions of the node, oldest first.
    pub(crate) seq: u64,
    /// BLAKE3 of the message 1 answered.
    pub(crate) msg1: [u8; 32],
    /// Our message 2, sent again on any other path the same message 1 arrives on, instead of
    /// being dropped as a replay.
    pub(crate) msg2: HandshakeMessage,
    /// The candidates its payload carried.
    pub(crate) candidates: Vec<Candidate>,
    /// The candidates the initiator's message 1 carried.
    pub(crate) peer_candidates: Vec<Candidate>,
    /// Where the message 1 arrived, adopted as a route once confirmed.
    pub(crate) path: Path,
}

/// The link with a peer.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Link {
    /// No session and no attempt; `down` says why the last session ended, if one did.
    Idle { down: Option<Reason> },
    /// Our initiation is under way; `responded` holds a session for the peer's own
    /// simultaneous initiation.
    Connecting {
        attempt: Attempt,
        responded: Option<Responded>,
    },
    /// We answered the peer and await its first frame.
    Responding { responded: Responded },
    /// A session can carry data.
    Up {
        current: Session,
        /// The session `current` replaced, kept for frames still in flight.
        previous: Option<Session>,
        /// The peer's rekey that we answered.
        next: Option<Responded>,
        /// Our rekey.
        rekey: Option<Attempt>,
        /// When data was sent without anything authenticated coming back: an initiation is due
        /// at `KEEPALIVE_TIMEOUT + REKEY_TIMEOUT` after it (vv-02 §6.4).
        loss_at: Option<Instant>,
        /// Whether the last-minute rekey before `REJECT_AFTER_TIME` was started.
        lastminute: bool,
        /// The routes; built when the link comes up, kept across rekeys.
        paths: Paths,
        /// Our `cand` awaiting its `candack`.
        telling: Option<Telling>,
    },
}

impl Default for Link {
    fn default() -> Self {
        Link::Idle { down: None }
    }
}

/// Which session of a link a receiver index names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    Previous,
    Current,
    /// The unconfirmed session of [`Link::Responding`], [`Link::Up::next`] or
    /// [`Link::Connecting::responded`].
    Next,
}

impl Link {
    /// The attempt in progress, ours.
    pub(crate) fn attempt(&self) -> Option<&Attempt> {
        match self {
            Link::Connecting { attempt, .. } => Some(attempt),
            Link::Up { rekey, .. } => rekey.as_ref(),
            Link::Idle { .. } | Link::Responding { .. } => None,
        }
    }

    pub(crate) fn attempt_mut(&mut self) -> Option<&mut Attempt> {
        match self {
            Link::Connecting { attempt, .. } => Some(attempt),
            Link::Up { rekey, .. } => rekey.as_mut(),
            Link::Idle { .. } | Link::Responding { .. } => None,
        }
    }

    /// The unconfirmed session we answered.
    pub(crate) fn responded(&self) -> Option<&Responded> {
        match self {
            Link::Connecting { responded, .. } => responded.as_ref(),
            Link::Responding { responded } => Some(responded),
            Link::Up { next, .. } => next.as_ref(),
            Link::Idle { .. } => None,
        }
    }

    /// The state a peer is reported in; a pure function of the link.
    pub(crate) fn state(&self) -> PeerState {
        match self {
            Link::Idle { down: None } => PeerState::Idle,
            Link::Idle { down: Some(r) } => PeerState::Down(*r),
            Link::Connecting { .. } | Link::Responding { .. } => PeerState::Connecting,
            Link::Up { current, .. } => PeerState::Up {
                initiator: current.is_initiator(),
            },
        }
    }

    pub(crate) fn is_up(&self) -> bool {
        matches!(self, Link::Up { .. })
    }

    pub(crate) fn current(&self) -> Option<&Session> {
        match self {
            Link::Up { current, .. } => Some(current),
            _ => None,
        }
    }

    pub(crate) fn current_mut(&mut self) -> Option<&mut Session> {
        match self {
            Link::Up { current, .. } => Some(current),
            _ => None,
        }
    }

    /// The time at which unanswered data calls for a new initiation.
    pub(crate) fn loss_at(&self) -> Option<Instant> {
        match self {
            Link::Up { loss_at, .. } => *loss_at,
            _ => None,
        }
    }

    pub(crate) fn set_loss_at(&mut self, at: Option<Instant>) {
        if let Link::Up { loss_at, .. } = self {
            *loss_at = at;
        }
    }

    /// Every session held.
    pub(crate) fn sessions(&self) -> impl Iterator<Item = &Session> {
        let (previous, current) = match self {
            Link::Up {
                previous, current, ..
            } => (previous.as_ref(), Some(current)),
            _ => (None, None),
        };
        [previous, current, self.responded().map(|r| &r.session)]
            .into_iter()
            .flatten()
    }

    /// Every receiver index held: sessions and pending messages 1.
    pub(crate) fn indices(&self) -> Vec<u32> {
        self.sessions()
            .map(|s| s.local_index)
            .chain(self.attempt().into_iter().flat_map(|a| a.indices(None)))
            .collect()
    }

    pub(crate) fn slot_of(&self, local_index: u32) -> Option<Slot> {
        if self.current().is_some_and(|s| s.local_index == local_index) {
            return Some(Slot::Current);
        }
        if let Link::Up {
            previous: Some(p), ..
        } = self
            && p.local_index == local_index
        {
            return Some(Slot::Previous);
        }
        self.responded()
            .filter(|r| r.session.local_index == local_index)
            .map(|_| Slot::Next)
    }

    pub(crate) fn session_mut(&mut self, slot: Slot) -> Option<&mut Session> {
        match (slot, self) {
            (Slot::Current, Link::Up { current, .. }) => Some(current),
            (Slot::Previous, Link::Up { previous, .. }) => previous.as_mut(),
            (Slot::Next, Link::Up { next, .. }) => next.as_mut().map(|r| &mut r.session),
            (Slot::Next, Link::Responding { responded }) => Some(&mut responded.session),
            (
                Slot::Next,
                Link::Connecting {
                    responded: Some(r), ..
                },
            ) => Some(&mut r.session),
            _ => None,
        }
    }

    /// Promotes the unconfirmed session after its first authenticated frame: `Responding` and
    /// `Connecting { responded }` become `Up` (an attempt of ours goes on as the rekey),
    /// `Up { next }` rotates `current` into `previous`. `paths` builds the routes of a link that
    /// comes up; it is not called for a rotation, which keeps them.
    pub(crate) fn confirm(&mut self, paths: impl FnOnce(&Responded) -> Paths) -> Option<Confirmed> {
        match take(self) {
            Link::Responding { responded } => {
                let paths = paths(&responded);
                let (confirmed, session) = Confirmed::of(responded, Vec::new());
                *self = Link::Up {
                    current: session,
                    previous: None,
                    next: None,
                    rekey: None,
                    loss_at: None,
                    lastminute: false,
                    paths,
                    telling: None,
                };
                Some(confirmed)
            }
            Link::Connecting {
                attempt,
                responded: Some(responded),
            } => {
                let paths = paths(&responded);
                let (confirmed, session) = Confirmed::of(responded, Vec::new());
                *self = Link::Up {
                    current: session,
                    previous: None,
                    next: None,
                    rekey: Some(attempt),
                    loss_at: None,
                    lastminute: false,
                    paths,
                    telling: None,
                };
                Some(confirmed)
            }
            Link::Up {
                current,
                previous,
                next: Some(responded),
                rekey,
                loss_at,
                lastminute,
                paths,
                telling,
            } => {
                let freed = previous.iter().map(|s| s.local_index).collect();
                let (confirmed, session) = Confirmed::of(responded, freed);
                *self = Link::Up {
                    current: session,
                    previous: Some(current),
                    next: None,
                    rekey,
                    loss_at,
                    lastminute,
                    paths,
                    telling,
                };
                Some(confirmed)
            }
            other => {
                *self = other;
                None
            }
        }
    }

    /// Installs the session of a completed attempt of ours as `current`; the attempt's other
    /// messages 1 are dropped. `paths` builds the routes of a link that comes up; it is not called
    /// for a rekey, which keeps them. Returns the indices freed.
    pub(crate) fn complete(&mut self, session: Session, paths: impl FnOnce() -> Paths) -> Vec<u32> {
        let keep = session.local_index;
        match take(self) {
            Link::Connecting { attempt, responded } => {
                let freed = attempt.indices(Some(keep)).collect();
                *self = Link::Up {
                    current: session,
                    previous: None,
                    next: responded,
                    rekey: None,
                    loss_at: None,
                    lastminute: false,
                    paths: paths(),
                    telling: None,
                };
                freed
            }
            Link::Up {
                current,
                previous,
                next,
                rekey: Some(attempt),
                paths,
                telling,
                ..
            } => {
                let mut freed: Vec<u32> = attempt.indices(Some(keep)).collect();
                freed.extend(previous.map(|s| s.local_index));
                *self = Link::Up {
                    current: session,
                    previous: Some(current),
                    next,
                    rekey: None,
                    loss_at: None,
                    lastminute: false,
                    paths,
                    telling,
                };
                freed
            }
            other => {
                *self = other;
                vec![keep]
            }
        }
    }

    /// Installs an answered session, replacing an older unconfirmed one (whose index is freed)
    /// and dropping `previous` (vv-02 §6.4). Returns the indices freed.
    pub(crate) fn respond(&mut self, responded: Responded) -> Vec<u32> {
        match take(self) {
            Link::Idle { .. } => {
                *self = Link::Responding { responded };
                Vec::new()
            }
            Link::Responding { responded: old } => {
                *self = Link::Responding { responded };
                vec![old.session.local_index]
            }
            Link::Connecting {
                attempt,
                responded: old,
            } => {
                *self = Link::Connecting {
                    attempt,
                    responded: Some(responded),
                };
                old.iter().map(|r| r.session.local_index).collect()
            }
            Link::Up {
                current,
                previous,
                next,
                rekey,
                loss_at,
                lastminute,
                paths,
                telling,
            } => {
                let freed = previous
                    .iter()
                    .map(|s| s.local_index)
                    .chain(next.iter().map(|r| r.session.local_index))
                    .collect();
                *self = Link::Up {
                    current,
                    previous: None,
                    next: Some(responded),
                    rekey,
                    loss_at,
                    lastminute,
                    paths,
                    telling,
                };
                freed
            }
        }
    }

    /// Drops every session past `REJECT_AFTER_TIME`, falling back to the next state down.
    pub(crate) fn expire(&mut self, now: Instant) -> Expired {
        let mut out = Expired::default();
        let alive = |r: Option<Responded>, out: &mut Expired| match r {
            Some(r) if r.session.expired(now) => {
                out.freed.push(r.session.local_index);
                out.unconfirmed.push(r.seq);
                None
            }
            other => other,
        };
        match take(self) {
            Link::Idle { down } => *self = Link::Idle { down },
            Link::Responding { responded } => {
                *self = match alive(Some(responded), &mut out) {
                    Some(responded) => Link::Responding { responded },
                    None => Link::Idle { down: None },
                };
            }
            Link::Connecting { attempt, responded } => {
                let responded = alive(responded, &mut out);
                *self = Link::Connecting { attempt, responded };
            }
            Link::Up {
                current,
                previous,
                next,
                rekey,
                loss_at,
                lastminute,
                paths,
                telling,
            } => {
                let next = alive(next, &mut out);
                let previous = previous.filter(|s| {
                    let gone = s.expired(now);
                    if gone {
                        out.freed.push(s.local_index);
                    }
                    !gone
                });
                if current.expired(now) {
                    out.freed.push(current.local_index);
                    out.freed.extend(previous.map(|s| s.local_index));
                    *self = match (next, rekey) {
                        (Some(responded), Some(attempt)) => Link::Connecting {
                            attempt,
                            responded: Some(responded),
                        },
                        (Some(responded), None) => Link::Responding { responded },
                        (None, Some(attempt)) => Link::Connecting {
                            attempt,
                            responded: None,
                        },
                        (None, None) => Link::Idle {
                            down: Some(Reason::Idle),
                        },
                    };
                } else {
                    *self = Link::Up {
                        current,
                        previous,
                        next,
                        rekey,
                        loss_at,
                        lastminute,
                        paths,
                        telling,
                    };
                }
            }
        }
        out
    }

    /// Ends our attempt after `REKEY_ATTEMPT_TIME`; returns its indices.
    pub(crate) fn give_up(&mut self) -> Vec<u32> {
        match take(self) {
            Link::Connecting { attempt, responded } => {
                *self = match responded {
                    Some(responded) => Link::Responding { responded },
                    None => Link::Idle {
                        down: Some(Reason::Unreachable),
                    },
                };
                attempt.indices(None).collect()
            }
            Link::Up {
                current,
                previous,
                next,
                rekey: Some(attempt),
                loss_at,
                lastminute,
                paths,
                telling,
            } => {
                *self = Link::Up {
                    current,
                    previous,
                    next,
                    rekey: None,
                    loss_at,
                    lastminute,
                    paths,
                    telling,
                };
                attempt.indices(None).collect()
            }
            other => {
                *self = other;
                Vec::new()
            }
        }
    }

    /// Drops the unconfirmed session whose sequence number is `seq`; returns its index.
    pub(crate) fn drop_responded(&mut self, seq: u64) -> Option<u32> {
        if self.responded().is_none_or(|r| r.seq != seq) {
            return None;
        }
        match take(self) {
            Link::Responding { responded } => Some(responded.session.local_index),
            Link::Connecting { attempt, responded } => {
                let index = responded.map(|r| r.session.local_index);
                *self = Link::Connecting {
                    attempt,
                    responded: None,
                };
                index
            }
            Link::Up {
                current,
                previous,
                next,
                rekey,
                loss_at,
                lastminute,
                paths,
                telling,
            } => {
                let index = next.map(|r| r.session.local_index);
                *self = Link::Up {
                    current,
                    previous,
                    next: None,
                    rekey,
                    loss_at,
                    lastminute,
                    paths,
                    telling,
                };
                index
            }
            Link::Idle { down } => {
                *self = Link::Idle { down };
                None
            }
        }
    }

    /// The routes, while the link is up.
    pub(crate) fn paths(&self) -> Option<&Paths> {
        match self {
            Link::Up { paths, .. } => Some(paths),
            _ => None,
        }
    }

    pub(crate) fn paths_mut(&mut self) -> Option<&mut Paths> {
        match self {
            Link::Up { paths, .. } => Some(paths),
            _ => None,
        }
    }

    /// Our `cand` that awaits its `candack`.
    pub(crate) fn telling(&self) -> Option<&Telling> {
        match self {
            Link::Up { telling, .. } => telling.as_ref(),
            _ => None,
        }
    }

    pub(crate) fn telling_mut(&mut self) -> Option<&mut Telling> {
        match self {
            Link::Up { telling, .. } => telling.as_mut(),
            _ => None,
        }
    }

    /// Replaces the `cand` that awaits its `candack`.
    pub(crate) fn set_telling(&mut self, t: Option<Telling>) {
        if let Link::Up { telling, .. } = self {
            *telling = t;
        }
    }

    /// Drops everything, as when no route is left: the link goes to
    /// `Idle { down: Some(Unreachable) }`. Returns the indices freed and the sequence numbers of
    /// the unconfirmed sessions dropped.
    pub(crate) fn lose(&mut self) -> Lost {
        let indices = self.indices();
        let unconfirmed = self.responded().map(|r| r.seq).into_iter().collect();
        *self = Link::Idle {
            down: Some(Reason::Unreachable),
        };
        Lost {
            freed: indices,
            unconfirmed,
        }
    }

    /// Whether the last-minute rekey was started.
    pub(crate) fn lastminute(&self) -> bool {
        matches!(
            self,
            Link::Up {
                lastminute: true,
                ..
            }
        )
    }

    pub(crate) fn set_lastminute(&mut self) {
        if let Link::Up { lastminute, .. } = self {
            *lastminute = true;
        }
    }
}

impl Confirmed {
    fn of(r: Responded, freed: Vec<u32>) -> (Confirmed, Session) {
        (Confirmed { freed, seq: r.seq }, r.session)
    }
}

/// What [`Link::confirm`] changed.
pub(crate) struct Confirmed {
    pub(crate) freed: Vec<u32>,
    pub(crate) seq: u64,
}

/// What [`Link::lose`] dropped.
pub(crate) struct Lost {
    pub(crate) freed: Vec<u32>,
    pub(crate) unconfirmed: Vec<u64>,
}

/// What [`Link::expire`] dropped.
#[derive(Default)]
pub(crate) struct Expired {
    pub(crate) freed: Vec<u32>,
    pub(crate) unconfirmed: Vec<u64>,
}
