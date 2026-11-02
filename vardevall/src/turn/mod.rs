//! `Turn`: the TURN allocation, its TLS link and the offers it is made from (vv-05 §3.3, §4.4).
//!
//! The allocation is [`vardevall_switch_proto::turn::TurnAllocation`]; the server and
//! credentials come from [`TurnOffers`]. It performs no I/O of its own over UDP: the datagrams
//! for the interface socket wait for [`Turn::take_datagrams`], what happened for
//! [`Turn::take_events`].

mod stream;

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::task::{Context, Poll};
use std::time::Duration;

use rand_core::CryptoRng;
use vardevall_proto::handshake::message::MAX_FRAGMENT;
use vardevall_proto::route::{Band, Latency, RouteClass};
use vardevall_proto::time::Instant;
use vardevall_proto::transport::{Framing, Medium, Reachability, Remote};
use vardevall_switch_proto::origin::Origin;
use vardevall_switch_proto::turn::{
    Credentials, Failure, Handled, Server, TurnAllocation, TurnOffer, TurnTransport,
};
use vardevall_switch_proto::turn_offers::TurnOffers;

use self::stream::Link;
pub(crate) use self::stream::LinkEvent;
use crate::net::mark::SocketMark;
use crate::udp::Reach;
use crate::view::Relay;

/// The TURN allocation: brought up on demand, metered, and reaches no local candidate.
pub(crate) struct TurnMedium;

impl Medium for TurnMedium {
    fn name(&self) -> &str {
        "turn"
    }

    fn class(&self) -> RouteClass {
        RouteClass {
            band: Band::High,
            latency: Latency::High,
            metered: true,
        }
    }

    fn reaches(&self, to: &Remote, local: bool) -> bool {
        matches!(to, Remote::Addr(_)) && !local
    }

    fn reachability(&self) -> Reachability {
        Reachability::Probe
    }

    fn framing(&self) -> Framing {
        Framing::Fragmented { max: MAX_FRAGMENT }
    }

    fn on_demand(&self) -> bool {
        true
    }
}

/// Something that happened to the allocation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Event {
    /// The relayed address is usable.
    Allocated(SocketAddr),
    /// The allocation ended or could not be made; [`Turn::lost`] says what to do next.
    Lost(Failure),
    /// A peer sent data to the relayed address; `from` is the peer's address as the server saw it.
    Data { from: SocketAddr, payload: Vec<u8> },
}

/// What follows the loss of an allocation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Lost {
    /// The origin whose credentials the server rejected: ask it for fresh ones.
    pub refresh: Option<Origin>,
    /// The next server is a TLS one after a UDP one failed: try it at once.
    pub retry: bool,
}

/// The allocation and what it is made from.
pub(crate) struct Turn {
    offers: TurnOffers,
    client: Option<TurnAllocation>,
    /// The TLS connection of `client`, if it uses one.
    link: Option<Link>,
    fallback_delay: Duration,
    mark: SocketMark,
    datagrams: Vec<(SocketAddr, Vec<u8>)>,
    events: VecDeque<Event>,
}

impl Turn {
    /// A TURN client with no offers; `fallback_delay` is the node's.
    pub(crate) fn new(fallback_delay: Duration, mark: SocketMark) -> Self {
        Turn {
            mark,
            offers: TurnOffers::default(),
            client: None,
            link: None,
            fallback_delay,
            datagrams: Vec::new(),
            events: VecDeque::new(),
        }
    }

    /// Stores the credentials of `origin` (vv-04 §4.4, §4.5); returns whether it is the first
    /// offer from that origin.
    pub(crate) fn offer(&mut self, origin: Origin, offer: TurnOffer) -> bool {
        self.offers.insert(origin, offer)
    }

    /// Drops the offer of `origin`; an allocation made from it lives until it ends.
    pub(crate) fn forget(&mut self, origin: Origin) {
        self.offers.remove(origin);
    }

    /// The volume stated by the offer an allocation is made from.
    pub(crate) fn bytes(&self) -> Option<u64> {
        self.offers.bytes()
    }

    /// Whether any origin offered TURN credentials.
    pub(crate) fn offered(&self) -> bool {
        !self.offers.is_empty()
    }

    /// The relayed address, once the allocation exists.
    pub(crate) fn relayed(&self) -> Option<SocketAddr> {
        self.client.as_ref().and_then(TurnAllocation::relayed)
    }

    /// Whether an allocation is being made.
    pub(crate) fn pending(&self) -> bool {
        self.client
            .as_ref()
            .is_some_and(|c| c.active() && c.relayed().is_none())
    }

    /// Whether handshakes go through a relay from the start: `fallback_delay = 0` or
    /// no family can punch (vv-05 §4.2 step 2).
    pub(crate) fn relay_first(&self, unpunchable: bool) -> bool {
        self.offered() && (self.fallback_delay.is_zero() || unpunchable)
    }

    /// The address of the TURN server if the allocation talks to it over the interface socket.
    pub(crate) fn udp_server(&self) -> Option<SocketAddr> {
        self.client
            .as_ref()
            .filter(|c| !c.is_stream())
            .map(TurnAllocation::server)
    }

    /// The allocation as the view shows it.
    pub(crate) fn relay(&self) -> Option<Relay> {
        self.client.as_ref().and_then(|c| {
            c.relayed().map(|addr| Relay {
                addr,
                server: c.server(),
                tls: c.is_stream(),
            })
        })
    }

    /// A client for `server`, with the connection it needs.
    fn make_client(&mut self, server: &Server, creds: Credentials) -> TurnAllocation {
        match &server.transport {
            TurnTransport::Udp => {
                self.link = None;
                TurnAllocation::new(server.addr, creds)
            }
            TurnTransport::Tls { host, auth } => {
                self.link = Some(Link::connect(
                    server.addr,
                    host.clone(),
                    auth.clone(),
                    self.mark,
                ));
                TurnAllocation::new_stream(server.addr, creds)
            }
        }
    }

    /// Makes sure an allocation exists or is being made; returns whether it is usable now
    /// (vv-05 §3.3).
    pub(crate) fn ensure(&mut self, now: Instant, rng: &mut impl CryptoRng, reach: Reach) -> bool {
        let Some((server, creds)) = self.offers.select(|a| reach.contains(a)) else {
            return false;
        };
        let existing = self.client.as_ref().map(|c| {
            (
                c.server() == server.addr && c.is_stream() == server.is_stream(),
                c.active(),
            )
        });
        match existing {
            Some((true, _)) => {
                if let Some(c) = self.client.as_mut() {
                    c.set_credentials(creds);
                }
            }
            Some((false, false)) | None => {
                let client = self.make_client(&server, creds);
                self.client = Some(client);
            }
            Some((false, true)) => {}
        }
        let Some(c) = self.client.as_mut() else {
            return false;
        };
        if !c.active() {
            c.allocate(now, rng);
        }
        let up = c.relayed().is_some();
        self.pump();
        up
    }

    /// The node no longer needs the allocation.
    pub(crate) fn release(&mut self, now: Instant, rng: &mut impl CryptoRng) {
        if let Some(c) = self.client.as_mut() {
            c.release(now, rng);
        }
        self.pump();
    }

    /// What does not survive a settled local change is redone: the allocation over UDP is bound
    /// to the old address (vv-05 §4.6), and the order of TURN servers starts over.
    pub(crate) fn local_change(&mut self) {
        self.offers.reset();
        if let Some(c) = self.client.as_mut() {
            c.reset();
        }
    }

    /// Sends `data` to `to` through the allocation, if there is one.
    pub(crate) fn send(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        to: SocketAddr,
        data: &[u8],
    ) -> bool {
        let Some(c) = self.client.as_mut() else {
            return false;
        };
        let sent = c.send(now, rng, to, data);
        self.pump();
        sent
    }

    /// Creates permissions for the addresses of a peer's candidates (vv-05 §3.3).
    pub(crate) fn permit(&mut self, now: Instant, rng: &mut impl CryptoRng, addrs: &[SocketAddr]) {
        let ips: Vec<IpAddr> = addrs.iter().map(SocketAddr::ip).collect();
        if let Some(c) = self.client.as_mut() {
            c.permit(now, rng, &ips);
        }
        self.pump();
    }

    /// Feeds a datagram of the TURN server to the allocation; `false` if it is not one of its
    /// messages.
    pub(crate) fn handle_datagram(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        buf: &[u8],
    ) -> bool {
        let Some(c) = self.client.as_mut() else {
            return false;
        };
        match c.handle_datagram(now, rng, buf) {
            Handled::Data { peer, payload } => {
                self.events.push_back(Event::Data {
                    from: peer,
                    payload,
                });
            }
            Handled::Consumed => self.pump(),
            Handled::Unknown => return false,
        }
        true
    }

    /// Something happened on the TLS connection.
    pub(crate) fn handle_link(&mut self, now: Instant, rng: &mut impl CryptoRng, event: LinkEvent) {
        match event {
            LinkEvent::Frame(frame) => {
                if !self.handle_datagram(now, rng, &frame) {
                    self.pump();
                }
            }
            LinkEvent::Closed => {
                self.link = None;
                if let Some(c) = self.client.as_mut().filter(|c| c.is_stream()) {
                    c.connection_lost();
                }
                self.pump();
            }
        }
    }

    /// Polls the TLS connection, if there is one.
    pub(crate) fn poll_link(&mut self, cx: &mut Context<'_>) -> Poll<LinkEvent> {
        match self.link.as_mut() {
            Some(l) => l.poll_event(cx),
            None => Poll::Pending,
        }
    }

    /// The server just tried failed with `failure` (vv-04 §2.3): the next try uses the next
    /// server, and what the node does about it is in the result.
    pub(crate) fn lost(&mut self, failure: Failure, reach: Reach) -> Lost {
        let was_stream = self.client.as_ref().is_some_and(TurnAllocation::is_stream);
        if matches!(failure, Failure::Timeout | Failure::Rejected(_)) {
            self.offers
                .next_server(failure == Failure::Timeout, |a| reach.contains(a));
        }
        let refresh = if failure == Failure::Unauthorized {
            self.offers.best_origin()
        } else {
            None
        };
        let next_is_stream = self
            .offers
            .select(|a| reach.contains(a))
            .is_some_and(|(s, _)| s.is_stream());
        Lost {
            refresh,
            retry: next_is_stream && !was_stream && failure != Failure::Unauthorized,
        }
    }

    /// The earliest time the allocation needs attention.
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        self.client.as_ref().and_then(TurnAllocation::poll_timeout)
    }

    /// Runs the timers of the allocation.
    pub(crate) fn handle_timeout(&mut self, now: Instant, rng: &mut impl CryptoRng) {
        if let Some(c) = self.client.as_mut() {
            c.handle_timeout(now, rng);
        }
        self.pump();
    }

    /// Moves what the allocation queued to the TLS link or to [`Turn::take_datagrams`], and its
    /// events to [`Turn::take_events`].
    fn pump(&mut self) {
        let Some(c) = self.client.as_mut() else {
            return;
        };
        let server = c.server();
        while let Some(d) = c.poll_transmit() {
            match &self.link {
                Some(link) => {
                    link.send(d);
                }
                None => self.datagrams.push((server, d)),
            }
        }
        while let Some(e) = c.poll_event() {
            self.events.push_back(match e {
                vardevall_switch_proto::turn::Event::Allocated(a) => Event::Allocated(a),
                vardevall_switch_proto::turn::Event::Lost(f) => Event::Lost(f),
            });
        }
    }

    /// Drops the connection once the allocation has nothing left to say.
    pub(crate) fn close_idle_link(&mut self) {
        if self
            .client
            .as_ref()
            .is_some_and(|c| !c.active() && c.poll_timeout().is_none())
        {
            self.link = None;
        }
    }

    /// The datagrams for the TURN server, to send from the interface socket.
    pub(crate) fn take_datagrams(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        std::mem::take(&mut self.datagrams)
    }

    /// What happened since the last call.
    pub(crate) fn take_events(&mut self) -> VecDeque<Event> {
        std::mem::take(&mut self.events)
    }
}

#[cfg(test)]
mod tests {
    use vardevall_switch_proto::address::SwitchAuth;

    use super::*;
    use crate::net::rng::os_rng;

    fn offer(servers: Vec<Server>) -> TurnOffer {
        TurnOffer {
            servers,
            username: "u".to_owned(),
            password: "p".to_owned(),
            ttl: Duration::from_secs(60),
            bits_per_second: None,
            bytes: None,
            realm: None,
            nonce: None,
            priority: 0,
        }
    }

    fn udp(addr: &str) -> Server {
        Server::udp(addr.parse().unwrap())
    }

    fn tls(addr: &str) -> Server {
        Server {
            addr: addr.parse().unwrap(),
            transport: TurnTransport::Tls {
                host: "turn.example".to_owned(),
                auth: SwitchAuth::Web {
                    extra_roots: Vec::new(),
                },
            },
        }
    }

    fn addr(s: &str) -> Remote {
        Remote::Addr(s.parse().unwrap())
    }

    #[test]
    fn the_medium_is_metered_and_reaches_no_local_candidate() {
        assert!(TurnMedium.class().metered);
        assert!(TurnMedium.reaches(&addr("192.168.1.5:1"), false));
        assert!(!TurnMedium.reaches(&addr("192.168.1.5:1"), true));
        assert!(!TurnMedium.reaches(&Remote::Peer([1; 32].into()), false));
    }

    #[test]
    fn without_an_offer_there_is_no_allocation() {
        let mut t = Turn::new(Duration::from_secs(3), SocketMark::NONE);
        let mut rng = os_rng();
        assert!(!t.offered());
        assert!(!t.ensure(Instant::ZERO, &mut rng, Reach::new(true)));
        assert!(t.take_datagrams().is_empty());
        assert!(!t.relay_first(true));
    }

    #[test]
    fn an_offer_starts_an_allocation_towards_its_server() {
        let mut t = Turn::new(Duration::from_secs(3), SocketMark::NONE);
        let mut rng = os_rng();
        let origin = Origin::Config(0);
        assert!(t.offer(origin, offer(vec![udp("192.0.2.1:3478")])));
        assert!(!t.offer(origin, offer(vec![udp("192.0.2.1:3478")])));
        assert!(t.relay_first(true));
        assert!(!t.relay_first(false));
        assert!(!t.ensure(Instant::ZERO, &mut rng, Reach::new(true)));
        let out = t.take_datagrams();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "192.0.2.1:3478".parse().unwrap());
        assert_eq!(t.udp_server(), Some(out[0].0));
        assert!(t.pending());
        assert!(t.relayed().is_none());
    }

    #[test]
    fn a_timed_out_udp_server_is_followed_by_the_tls_one_at_once() {
        let mut t = Turn::new(Duration::from_secs(3), SocketMark::NONE);
        let mut rng = os_rng();
        t.offer(
            Origin::Config(0),
            offer(vec![udp("192.0.2.1:3478"), tls("192.0.2.1:443")]),
        );
        t.ensure(Instant::ZERO, &mut rng, Reach::new(true));
        let lost = t.lost(Failure::Timeout, Reach::new(true));
        assert_eq!(
            lost,
            Lost {
                refresh: None,
                retry: true
            }
        );
    }

    #[test]
    fn rejected_credentials_are_asked_of_their_origin() {
        let mut t = Turn::new(Duration::from_secs(3), SocketMark::NONE);
        let mut rng = os_rng();
        t.offer(Origin::Config(2), offer(vec![udp("192.0.2.1:3478")]));
        t.ensure(Instant::ZERO, &mut rng, Reach::new(true));
        let lost = t.lost(Failure::Unauthorized, Reach::new(true));
        assert_eq!(
            lost,
            Lost {
                refresh: Some(Origin::Config(2)),
                retry: false
            }
        );
    }
}
