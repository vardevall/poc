//! Packets held while candidates are prepared (vv-05 §3.1, §4.2).
//!
//! [`Held`] is the queue and its deadline; the methods of [`Node`] here decide when a handshake
//! must wait for fresh STUN results or a relay and when the packets go on.

use std::collections::VecDeque;
use std::time::Duration;

use vardevall_proto::keys::NodePublic;
use vardevall_proto::time::Instant;

use super::Node;

/// Longest a packet waits for fresh candidates or a relay before its handshake starts anyway.
const HOLD_MAX: Duration = Duration::from_millis(1500);
/// Packets held at most while candidates are gathered.
const HELD_PACKETS: usize = 64;

/// The packets held and when the first of them stops waiting.
#[derive(Default)]
pub(super) struct Held {
    packets: VecDeque<(NodePublic, Vec<u8>)>,
    until: Option<Instant>,
}

impl Held {
    /// Queues a packet for `peer`; the queue is bounded and drops what does not fit.
    pub(super) fn hold(&mut self, now: Instant, peer: NodePublic, packet: Vec<u8>) {
        if self.packets.len() < HELD_PACKETS {
            self.packets.push_back((peer, packet));
        }
        self.until.get_or_insert(now + HOLD_MAX);
    }

    /// Whether `peer` has packets waiting, which later ones must queue behind.
    pub(super) fn holds(&self, peer: &NodePublic) -> bool {
        self.packets.iter().any(|(p, _)| p == peer)
    }

    /// Takes every packet, in arrival order.
    pub(super) fn release(&mut self) -> VecDeque<(NodePublic, Vec<u8>)> {
        self.until = None;
        std::mem::take(&mut self.packets)
    }

    /// When the first packet stops waiting.
    pub(super) fn poll_timeout(&self) -> Option<Instant> {
        self.until
    }

    /// Takes the packets once the first has waited `HOLD_MAX`.
    pub(super) fn handle_timeout(&mut self, now: Instant) -> VecDeque<(NodePublic, Vec<u8>)> {
        if self.until.is_some_and(|t| now >= t) {
            self.release()
        } else {
            VecDeque::new()
        }
    }
}

impl Node {
    /// Whether handshakes towards `peer` must wait for fresh candidates or a relay, which this
    /// starts (vv-05 §3.1, §4.2): only a handshake that goes through a switch needs them.
    pub(super) fn needs_prep(&mut self, peer: &NodePublic) -> bool {
        if !self.core.awaits_reporting_path(peer) {
            return false;
        }
        let now = self.clock.now().instant;
        let mut wait = false;
        if self.stun.has_servers() {
            for (to, data) in self.stun.refresh(now, &mut self.rng) {
                self.send_to(to, &data);
            }
            wait |= self.gathering();
        }
        if self.relay_first() {
            wait |= !self.ensure_relay();
        }
        wait
    }

    /// Whether handshakes go through a relay from the start (vv-05 §4.2 step 2, §4.4).
    fn relay_first(&self) -> bool {
        self.turn
            .relay_first(self.stun.snapshot().is_some_and(|s| s.unpunchable()))
    }

    fn prep_pending(&self) -> bool {
        self.gathering() || (self.relay_first() && self.turn.pending())
    }

    /// Hands the held packets on once nothing is being prepared any more.
    pub(super) fn release_held_if_ready(&mut self) {
        if !self.prep_pending() {
            self.release_held();
        }
    }

    /// Hands the held packets to the core.
    fn release_held(&mut self) {
        let packets = self.held.release();
        self.send_held(packets);
    }

    fn send_held(&mut self, packets: VecDeque<(NodePublic, Vec<u8>)>) {
        for (peer, packet) in packets {
            self.send_to_core(peer, &packet);
        }
    }

    /// Runs the deadline of the held packets.
    pub(super) fn held_timeout(&mut self, now: Instant) {
        let packets = self.held.handle_timeout(now);
        self.send_held(packets);
    }
}
