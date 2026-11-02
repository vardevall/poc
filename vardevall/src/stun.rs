//! `Stun`: gathering of `punch` candidates and the servers to ask (vv-05 §3.1).
//!
//! It performs no I/O: the datagrams it returns go out through [`crate::udp::Udp`], and what
//! arrives from the STUN servers is passed in.

use std::net::SocketAddr;
use std::time::Duration;

use rand_core::CryptoRng;
use vardevall_proto::route::{Families, RoundId};
use vardevall_proto::time::Instant;
use vardevall_switch_proto::origin::Origin;
use vardevall_switch_proto::reflexive::{Reflexive, Snapshot, Transmit};
use vardevall_switch_proto::stun::Message;
use vardevall_switch_proto::stun_servers::StunServers;

use crate::udp::Reach;

/// The gathering and the servers it asks.
#[derive(Default)]
pub(crate) struct Stun {
    reflexive: Reflexive,
    servers: StunServers,
    /// The gathering round that `LocalChanges` asked for and is waiting on.
    round: Option<RoundId>,
}

impl Stun {
    /// The STUN servers of `origin` arrived; `required` says they answer only requests with a
    /// credential (vv-04 §3.4, §4.7). Call [`Stun::update`] next.
    pub(crate) fn set_servers(&mut self, origin: Origin, servers: Vec<SocketAddr>, required: bool) {
        self.servers.set(origin, servers, required);
    }

    /// Drops the servers of `origin`. Call [`Stun::update`] next.
    pub(crate) fn forget(&mut self, origin: Origin) {
        self.servers.set(origin, Vec::new(), false);
    }

    /// The credential of `origin` arrived or was renewed (vv-04 §4.7). Call [`Stun::update`] next.
    pub(crate) fn set_credential(
        &mut self,
        now: Instant,
        origin: Origin,
        username: String,
        key: Vec<u8>,
        ttl: Option<Duration>,
    ) {
        self.servers.set_credential(now, origin, username, key, ttl);
    }

    /// Hands the servers that can be asked now to the gathering (vv-05 §3.1); returns whether
    /// they differ from before.
    pub(crate) fn update(&mut self, now: Instant, reach: Reach) -> bool {
        let servers = self.servers.servers(now, |a| reach.contains(a));
        self.reflexive.set_servers(servers)
    }

    /// Hands the servers to the gathering again once a credential ran out.
    pub(crate) fn expire(&mut self, now: Instant, reach: Reach) {
        if self.servers.next_expiry().is_some_and(|t| now >= t) {
            self.update(now, reach);
        }
    }

    /// Whether any STUN server is known.
    pub(crate) fn has_servers(&self) -> bool {
        self.reflexive.has_servers()
    }

    /// The newest finished result.
    pub(crate) fn snapshot(&self) -> Option<&Snapshot> {
        self.reflexive.snapshot()
    }

    /// Whether a round is running.
    pub(crate) fn busy(&self) -> bool {
        self.reflexive.busy()
    }

    /// Starts a round of Binding requests unless one is running (vv-05 §3.1).
    pub(crate) fn start(&mut self, now: Instant, rng: &mut impl CryptoRng) -> Vec<Transmit> {
        self.reflexive.start(now, rng)
    }

    /// Starts a round for the families whose result is out of date.
    pub(crate) fn refresh(&mut self, now: Instant, rng: &mut impl CryptoRng) -> Vec<Transmit> {
        self.reflexive.refresh(now, rng)
    }

    /// Starts the round `round` that `LocalChanges` asked for, for `families` (vv-05 §3.2).
    pub(crate) fn restart(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        round: RoundId,
        families: Families,
    ) -> Vec<Transmit> {
        self.round = Some(round);
        self.reflexive.restart(now, rng, families)
    }

    /// A direct route over `families` keeps failing: their mappings are asked again once the
    /// backoff of the doubt allows it.
    pub(crate) fn doubt(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        families: Families,
    ) -> Vec<Transmit> {
        self.reflexive.doubt(now, rng, families)
    }

    /// When a standing doubt may ask again.
    pub(crate) fn next_doubt(&self) -> Option<Instant> {
        self.reflexive.next_doubt()
    }

    /// No direct route fails any more.
    pub(crate) fn trust(&mut self) {
        self.reflexive.trust();
    }

    /// The round `LocalChanges` waits for ended, or there was nothing to gather.
    pub(crate) fn take_round(&mut self) -> Option<RoundId> {
        self.round.take()
    }

    /// Abandons `round` if it is the one running.
    pub(crate) fn cancel_round(&mut self, round: RoundId) {
        if self.round == Some(round) {
            self.round = None;
            self.reflexive.cancel();
        }
    }

    /// A local change: the running round is abandoned and the backoff of retries starts over;
    /// the results stay until a round replaces them (vv-05 §3.2).
    pub(crate) fn reset(&mut self) {
        self.reflexive.reset();
    }

    /// Records a datagram sent from the interface socket to `to`, which keeps the mapping of
    /// its family alive.
    pub(crate) fn sent(&mut self, now: Instant, to: SocketAddr) {
        self.reflexive.sent(now, to);
    }

    /// Feeds a STUN message from the interface socket to the gathering; `raw` is its bytes.
    pub(crate) fn handle(&mut self, now: Instant, from: SocketAddr, msg: &Message, raw: &[u8]) {
        self.reflexive.handle(now, from, msg, raw);
    }

    /// The result of a round that just finished.
    pub(crate) fn take_result(&mut self) -> Option<Snapshot> {
        self.reflexive.take_result()
    }

    /// The delay of the retry that started since the last call.
    pub(crate) fn take_retry(&mut self) -> Option<Duration> {
        self.reflexive.take_retry()
    }

    /// The earliest time the gathering, a doubt or a credential needs attention.
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        [
            self.reflexive.poll_timeout(),
            self.reflexive.next_doubt(),
            self.servers.next_expiry(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Runs the timers of the gathering; returns the requests to send.
    pub(crate) fn handle_timeout(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
    ) -> Vec<Transmit> {
        self.reflexive.handle_timeout(now, rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::rng::os_rng;

    fn addr() -> SocketAddr {
        "192.0.2.1:3478".parse().unwrap()
    }

    #[test]
    fn a_new_server_list_changes_the_gathering_once() {
        let mut s = Stun::default();
        let now = Instant::from_millis(0);
        s.set_servers(Origin::Config(0), vec![addr()], false);
        assert!(s.update(now, Reach::new(true)));
        assert!(!s.update(now, Reach::new(true)));
        assert!(s.has_servers());
    }

    #[test]
    fn a_round_of_a_local_change_is_taken_once_or_cancelled() {
        let mut s = Stun::default();
        let mut rng = os_rng();
        let now = Instant::from_millis(0);
        s.set_servers(Origin::Config(0), vec![addr()], false);
        s.update(now, Reach::new(true));
        assert_eq!(s.restart(now, &mut rng, 7, Families::BOTH).len(), 1);
        assert!(s.busy());
        s.cancel_round(8);
        assert!(s.busy());
        s.cancel_round(7);
        assert!(!s.busy());
        assert_eq!(s.take_round(), None);
        s.restart(now, &mut rng, 9, Families::BOTH);
        assert_eq!(s.take_round(), Some(9));
        assert_eq!(s.take_round(), None);
    }

    #[test]
    fn a_credential_that_ran_out_takes_its_servers_from_the_gathering() {
        let mut s = Stun::default();
        let t0 = Instant::from_millis(0);
        s.set_servers(Origin::Config(0), vec![addr()], true);
        s.set_credential(
            t0,
            Origin::Config(0),
            "u".to_owned(),
            b"k".to_vec(),
            Some(Duration::from_secs(5)),
        );
        assert!(s.update(t0, Reach::new(true)));
        let until = t0 + Duration::from_secs(5);
        assert_eq!(s.poll_timeout(), Some(until));
        s.expire(until, Reach::new(true));
        assert!(!s.has_servers());
        assert_eq!(s.poll_timeout(), None);
    }
}
