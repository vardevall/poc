//! One peer: its handshakes and sessions ([`link`]), its routes ([`crate::route::paths`]), the
//! candidates found for it ([`book`]) and exchanged with it ([`candidates`]) and the packets
//! waiting for it.
//!
//! A [`Peer`] never stores what the node owns; every call borrows it through a [`Ctx`].

mod book;
mod candidates;
mod link;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::addr::OverlayAddrs;
use crate::discovery::candidate::Candidate;
use crate::error::PeerError;
use crate::handshake::cookie::COOKIE_LIFETIME;
use crate::handshake::message::{self, CookieReply, MIN_MESSAGE2, MessageNumber, TYPE_MSG2};
use crate::handshake::payload::{self, Hello, MAX_PAYLOAD_1, MAX_PAYLOAD_2, PADDED_PAYLOAD_1};
use crate::handshake::{Initiator, LocalKeys, Responder};
use crate::ip::exit::{ExitOffer, ExitPeer, Serving};
use crate::ip::site::Site;
use crate::ip::source::Source;
use crate::keys::{NodePublic, PairPsk};
use crate::meter::Meter;
use crate::node::peers::Indices;
use crate::node::{Event, Output, PeerState, RouteView, Services, Settings, queue_transmit};
use crate::plane::frame::{self, FrameHeader};
use crate::route::paths::{Delivery, Do, NAT_KEEPALIVE, Origin, Paths, Spec};
use crate::route::rtt::INITIAL_RTO;
use crate::route::{self, Control, DeliveryClass, Families, Latency, RouteInfo, encode_control};
use crate::session::{
    REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME, REKEY_ATTEMPT_TIME,
    REKEY_JITTER_MAX_MS, REKEY_TIMEOUT, Session,
};
use crate::time::{Instant, Now};
use crate::transport::{Framing, Path, Reachability, Remote, TransportId, Transports};

use book::Book;
pub use book::{Found, Group, MAX_TARGETS};
use candidates::Candidates;
use link::{Attempt, HandshakeMessage, Link, PENDING_LIMIT, Responded, Sent, Slot};

/// Messages 1 per second accepted from one initiator key (vv-02 §4.3).
pub(crate) const MSG1_RATE: u32 = 50;
/// Packets queued while no session or no fitting route exists (vv-05 §4.3).
pub(crate) const QUEUE_LIMIT: usize = 64;

/// How a peer is accepted (vv-00 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Configured by key.
    Key,
    /// Accepted as a member of the network.
    Member,
}

/// Everything a peer borrows from the node for one call.
pub(crate) struct Ctx<'a, R> {
    pub(crate) now: Now,
    pub(crate) rng: &'a mut R,
    pub(crate) keys: &'a LocalKeys,
    pub(crate) settings: &'a Settings,
    pub(crate) transports: &'a mut Transports,
    /// The candidates this node shares.
    pub(crate) own: &'a [Candidate],
    /// The exit this node offers to peers held by key, with the IPv4 addresses it gave.
    pub(crate) exit: Option<Serving<'a>>,
    pub(crate) local_metered: bool,
    pub(crate) indices: &'a mut Indices,
    pub(crate) services: &'a mut Services,
    pub(crate) out: &'a mut VecDeque<Output>,
}

impl<R: CryptoRng> Ctx<'_, R> {
    /// Queues a datagram; data and control on an on-demand transport keep it in use.
    pub(crate) fn transmit(&mut self, path: Path, data: Vec<u8>, signal: bool) {
        self.mark_use(path);
        self.transmit_probe(path, data, signal);
    }

    /// Queues a datagram that does not count as use of an on-demand transport.
    pub(crate) fn transmit_probe(&mut self, path: Path, data: Vec<u8>, signal: bool) {
        queue_transmit(self.transports, self.out, path, data, signal);
    }

    pub(crate) fn mark_use(&mut self, path: Path) {
        let now = self.now.instant;
        if let Some(e) = self.transports.get_mut(path.via)
            && e.medium.on_demand()
        {
            e.last_use = Some(now);
        }
    }

    pub(crate) fn event(&mut self, e: crate::node::Event) {
        self.out.push_back(Output::Event(e));
    }
}

/// A token bucket allowing [`MSG1_RATE`] events per second.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RateLimiter {
    tat: Instant,
}

impl RateLimiter {
    pub(crate) const fn new() -> Self {
        RateLimiter { tat: Instant::ZERO }
    }

    pub(crate) fn allow(&mut self, now: Instant) -> bool {
        let interval = Duration::from_secs(1) / MSG1_RATE;
        let tat = self.tat.max(now) + interval;
        if tat - now > interval * MSG1_RATE {
            return false;
        }
        self.tat = tat;
        true
    }
}

/// A cookie received from the peer (vv-02 §4.2).
pub(crate) struct StoredCookie {
    pub(crate) value: Zeroizing<[u8; 32]>,
    pub(crate) received_at: Instant,
}

/// Handshake state that outlives every session: keys derived for the peer, replay protection
/// of its messages 1, the rate of ours.
pub(crate) struct Handshakes {
    pub(crate) mac1_out: Zeroizing<[u8; 32]>,
    pub(crate) cookie_key: Zeroizing<[u8; 32]>,
    pub(crate) cookie: Option<StoredCookie>,
    /// The timestamp of the last message 1 accepted from the peer.
    pub(crate) last_ts: Option<u64>,
    /// The timestamp of our last message 1.
    pub(crate) own_ts: u64,
    pub(crate) rate: RateLimiter,
    /// When our last message 1 of a new attempt went out (`REKEY_TIMEOUT` rate limit).
    pub(crate) last_initiation: Option<Instant>,
}

impl Handshakes {
    pub(crate) fn valid_cookie(&self, now: Instant) -> Option<[u8; 32]> {
        self.cookie
            .as_ref()
            .filter(|c| now < c.received_at + COOKIE_LIFETIME)
            .map(|c| *c.value)
    }
}

/// An initiation held back by the `REKEY_TIMEOUT` rate limit, and why it is wanted; when it is
/// due it goes ahead only if the reason still holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Retry {
    pub(crate) at: Instant,
    pub(crate) why: Why,
}

/// Why an initiation is wanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Why {
    /// Packets are queued: goes ahead if the queue is not empty.
    Queued,
    /// Data went out and nothing came back: goes ahead.
    Loss,
    /// An exit is in use and this peer's offer or session is wanted: goes ahead if the link is
    /// not up.
    Exit,
}

/// A packet waiting for a session or for a route that meets its class.
pub(crate) struct Queued {
    pub(crate) class: DeliveryClass,
    pub(crate) packet: Vec<u8>,
}

/// A snapshot of one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerView {
    /// How the peer is trusted.
    pub trust: Trust,
    /// What the link is doing.
    pub link: PeerState,
    /// Whether a responder-side session awaits its first authenticated frame.
    pub unconfirmed: bool,
    /// Messages 1 awaiting an answer.
    pub pending: usize,
    /// Packets queued.
    pub queued: usize,
    /// The active route.
    pub active: Option<RouteView>,
    /// Whether the active route does not meet the class it was asked for by the last packet.
    pub degraded: bool,
    /// Every route; empty while the link is not up.
    pub routes: Vec<RouteInfo>,
    /// The candidates the peer shared.
    pub shared: Vec<Candidate>,
    /// The candidates the caller's sources found.
    pub found: Vec<Candidate>,
    /// The addresses a direct handshake attempt goes to.
    pub targets: Vec<SocketAddr>,
    /// The reporting transports on which the peer is reachable.
    pub reporting: Vec<TransportId>,
    /// Whether a probing episode is running.
    pub probing: bool,
    /// Whether a fallback to the switch path or a relay is pending.
    pub fallback: bool,
    /// The retransmission timeout of the active route.
    pub rto: Duration,
    /// The source address of our pings as the peer's latest pong reported it.
    pub observed: Option<SocketAddr>,
    /// The last exit offer received; kept while the link is down.
    pub exit: Option<ExitOffer>,
}

/// One peer.
pub(crate) struct Peer {
    key: NodePublic,
    trust: Trust,
    psk: PairPsk,
    addrs: OverlayAddrs,
    hs: Handshakes,
    link: Link,
    /// The last offer received, replaced by the next handshake that completes.
    offer: Option<ExitOffer>,
    /// While an exit of this peer's site is in use: when the next keepalive is due
    ///.
    hold: Option<Instant>,
    /// An initiation held back by the `REKEY_TIMEOUT` rate limit.
    retry: Option<Retry>,
    candidates: Candidates,
    /// The source address of our pings as the latest pong reported it.
    observed: Option<SocketAddr>,
    book: Book,
    queue: VecDeque<Queued>,
    /// The class of the last packet sent, for [`PeerView::degraded`].
    class: Option<DeliveryClass>,
    /// The state last reported in [`Event::Peer`].
    reported: PeerState,
    /// The route last reported in [`Event::Active`].
    reported_route: Option<RouteView>,
    last_used: Instant,
}

/// Whether an initiation was made.
enum Initiation {
    Started,
    Pending,
    Limited(Instant),
}

/// A message to send on `path` in the framing of its transport.
fn send_message<R: CryptoRng>(ctx: &mut Ctx<'_, R>, path: Path, m: &HandshakeMessage) {
    match ctx.transports.framing(path.via) {
        Some(Framing::Fragmented { .. }) => {
            for f in &m.fragments {
                ctx.transmit(path, f.clone(), true);
            }
        }
        Some(Framing::Whole) => ctx.transmit(path, m.whole.clone(), true),
        None => {}
    }
}

/// Whether two reported routes are the same route; what they carried does not count.
fn same_route(a: Option<RouteView>, b: Option<RouteView>) -> bool {
    let plain = |r: Option<RouteView>| {
        r.map(|r| RouteView {
            meter: Meter::default(),
            ..r
        })
    };
    plain(a) == plain(b)
}

fn jitter<R: CryptoRng>(rng: &mut R) -> Duration {
    Duration::from_millis(u64::from(rng.next_u32()) % (REKEY_JITTER_MAX_MS + 1))
}

impl Peer {
    pub(crate) fn new(
        key: NodePublic,
        trust: Trust,
        psk: PairPsk,
        keys: &LocalKeys,
        settings: &Settings,
        now: Instant,
    ) -> Self {
        Peer {
            key,
            trust,
            psk,
            addrs: OverlayAddrs::derive(&settings.network_id, &key),
            hs: Handshakes {
                mac1_out: keys.network().mac1_key(&key),
                cookie_key: keys.network().cookie_key(&key),
                cookie: None,
                last_ts: None,
                own_ts: 0,
                rate: RateLimiter::new(),
                last_initiation: None,
            },
            link: Link::default(),
            offer: None,
            hold: None,
            retry: None,
            candidates: Candidates::default(),
            observed: None,
            book: Book::default(),
            queue: VecDeque::new(),
            class: None,
            reported: PeerState::Idle,
            reported_route: None,
            last_used: now,
        }
    }

    pub(crate) fn key(&self) -> &NodePublic {
        &self.key
    }

    pub(crate) fn trust(&self) -> Trust {
        self.trust
    }

    /// The offer made to this peer: only a peer held by key gets one.
    fn offer_for_peer(&self, own: Option<Serving<'_>>) -> Option<ExitOffer> {
        own.filter(|_| self.trust == Trust::Key)
            .map(|o| o.offer_for(&self.key))
    }

    /// The offer a handshake brought, if this peer is held by key.
    fn accepted_offer(&self, offer: Option<ExitOffer>) -> Option<ExitOffer> {
        offer.filter(|_| self.trust == Trust::Key)
    }

    /// The offer of the latest handshake that made a session in use; kept while the link is down
    ///.
    pub(crate) fn exit_offer(&self) -> Option<&ExitOffer> {
        self.offer.as_ref()
    }

    /// What the source check of this peer's IP packets needs.
    fn ip_source<'a, R>(&'a self, ctx: &'a Ctx<'_, R>) -> Source<'a> {
        Source {
            network_id: &ctx.settings.network_id,
            own: ctx.keys.public(),
            peer: &self.key,
            peer_addrs: &self.addrs,
            held_by_key: self.trust == Trust::Key,
            serving: ctx.exit,
            offer: self.exit_offer(),
        }
    }

    /// What the choice of an exit needs to know of this peer, if it offered one.
    pub(crate) fn exit_peer(&self) -> Option<ExitPeer> {
        let offer = self.exit_offer()?.clone();
        Some(ExitPeer {
            offer,
            live: self.link.is_up(),
            metered: self.route_active().map(|a| a.class.metered),
            srtt: self.link.paths().and_then(Paths::active_srtt),
        })
    }

    pub(crate) fn set_trust(&mut self, trust: Trust, psk: PairPsk) {
        self.trust = trust;
        self.psk = psk;
    }

    pub(crate) fn addrs(&self) -> &OverlayAddrs {
        &self.addrs
    }

    pub(crate) fn last_used(&self) -> Instant {
        self.last_used
    }

    /// No session, no handshake, nothing queued: a member in this state may be evicted.
    pub(crate) fn is_idle(&self) -> bool {
        matches!(self.link, Link::Idle { .. }) && self.queue.is_empty()
    }

    /// Whether a message 1 of the peer was ever accepted.
    pub(crate) fn ever_heard(&self) -> bool {
        self.hs.last_ts.is_some()
    }

    /// Every receiver index the peer holds, for [`crate::node::peers::Peers::remove`].
    pub(crate) fn indices(&self) -> Vec<u32> {
        self.link.indices()
    }

    /// The sequence number of the unconfirmed session, if any.
    pub(crate) fn unconfirmed_seq(&self) -> Option<u64> {
        self.link.responded().map(|r| r.seq)
    }

    /// Drops the unconfirmed responder session whose sequence number is `seq`; returns its
    /// index.
    pub(crate) fn drop_unconfirmed(&mut self, seq: u64) -> Option<u32> {
        self.link.drop_responded(seq)
    }

    /// The retransmission timeout of the active route; `INITIAL_RTO` while the link is not up.
    pub(crate) fn rto(&self) -> Duration {
        self.link.paths().map_or(INITIAL_RTO, Paths::rto)
    }

    /// The active route, for ordering the providers of a service.
    pub(crate) fn route_active(&self) -> Option<route::Active> {
        self.link.paths().and_then(Paths::active)
    }

    fn arm_loss<R: CryptoRng>(&mut self, ctx: &Ctx<'_, R>) {
        if self.link.is_up() && self.link.loss_at().is_none() {
            self.link.set_loss_at(Some(
                ctx.now.instant + ctx.settings.keepalive_timeout + REKEY_TIMEOUT,
            ));
        }
    }

    fn schedule(&mut self, at: Instant, why: Why) {
        if !matches!(self.retry, Some(Retry { why: Why::Loss, .. })) {
            self.retry = Some(Retry { at, why });
        }
    }

    fn initiate<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) -> Initiation {
        if self.link.attempt().is_some() {
            return Initiation::Pending;
        }
        if let Some(t) = self.hs.last_initiation {
            let allowed = t + REKEY_TIMEOUT;
            if ctx.now.instant < allowed {
                return Initiation::Limited(allowed);
            }
        }
        self.send_initiation(ctx, false);
        Initiation::Started
    }

    /// Sends a packet, or queues it and starts a handshake. With a session but no
    /// route that fits it only queues: unanswered data arms the loss timer once it is sent.
    pub(crate) fn send<R: CryptoRng>(
        &mut self,
        ctx: &mut Ctx<'_, R>,
        class: DeliveryClass,
        packet: &[u8],
    ) -> Result<(), PeerError> {
        self.last_used = ctx.now.instant;
        self.class = Some(class);
        let usable = self
            .link
            .current()
            .is_some_and(|s| s.can_send(ctx.now.instant));
        if usable {
            if self.send_data(ctx, &class, packet) {
                self.maybe_rekey(ctx);
                self.pump(ctx);
            } else {
                self.enqueue(class, packet);
                self.maybe_rekey(ctx);
            }
            return Ok(());
        }
        self.enqueue(class, packet);
        self.connect(ctx, Why::Queued);
        Ok(())
    }

    fn enqueue(&mut self, class: DeliveryClass, packet: &[u8]) {
        if self.queue.len() >= QUEUE_LIMIT {
            self.queue.pop_front();
        }
        self.queue.push_back(Queued {
            class,
            packet: packet.to_vec(),
        });
    }

    /// Seals `packet` and sends it on the route for `class`; `false` if it must wait.
    fn send_data<R: CryptoRng>(
        &mut self,
        ctx: &mut Ctx<'_, R>,
        class: &DeliveryClass,
        packet: &[u8],
    ) -> bool {
        let now = ctx.now.instant;
        let cfg = ctx.settings.routes;
        let Some(Delivery::Route(path) | Delivery::Degraded(path)) =
            self.link.paths().map(|p| p.route_for(class))
        else {
            return false;
        };
        let mtu = ctx.settings.mtu;
        let Some(session) = self.link.current_mut().filter(|s| s.can_send(now)) else {
            return false;
        };
        let (_, data) = session.seal(&frame::pad(packet, mtu));
        let len = data.len();
        ctx.transmit(path, data, false);
        if let Some(paths) = self.link.paths_mut() {
            paths.count_sent(path, len);
            paths.on_sent(now, &cfg, path, true);
        }
        self.arm_loss(ctx);
        true
    }

    fn maybe_rekey<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        let now = ctx.now.instant;
        let rekey = self.link.current().is_some_and(|s| {
            s.send_counter() >= REKEY_AFTER_MESSAGES
                || (s.initiator && now >= s.created + REKEY_AFTER_TIME)
        });
        if rekey {
            let _ = self.initiate(ctx);
        }
    }

    /// Sends the queue on the routes that now fit; returns whether anything went out.
    fn flush<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) -> bool {
        let now = ctx.now.instant;
        if self.queue.is_empty() || !self.link.current().is_some_and(|s| s.can_send(now)) {
            return false;
        }
        let mut sent = false;
        for q in std::mem::take(&mut self.queue) {
            if self.send_data(ctx, &q.class, &q.packet) {
                sent = true;
            } else {
                self.queue.push_back(q);
            }
        }
        sent
    }

    /// Seals `control` in the current session; `None` if it cannot send.
    fn seal_control<R: CryptoRng>(
        &mut self,
        ctx: &mut Ctx<'_, R>,
        control: &Control,
    ) -> Option<Vec<u8>> {
        let now = ctx.now.instant;
        let session = self.link.current_mut().filter(|s| s.can_send(now))?;
        let (_, data) = session.seal(&encode_control(control));
        self.maybe_rekey(ctx);
        Some(data)
    }

    /// Sends a ping or pong on `path`; it does not count as use of an on-demand transport.
    fn send_probe<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>, path: Path, control: &Control) {
        if let Some(data) = self.seal_control(ctx, control) {
            let len = data.len();
            ctx.transmit_probe(path, data, true);
            if let Some(paths) = self.link.paths_mut() {
                paths.count_sent(path, len);
            }
        }
    }

    /// Sends a control message that is not a probe on `path`.
    fn send_control_on<R: CryptoRng>(
        &mut self,
        ctx: &mut Ctx<'_, R>,
        path: Path,
        control: &Control,
        signal: bool,
    ) {
        let now = ctx.now.instant;
        let cfg = ctx.settings.routes;
        if let Some(data) = self.seal_control(ctx, control) {
            let len = data.len();
            ctx.transmit(path, data, signal);
            if let Some(paths) = self.link.paths_mut() {
                paths.count_sent(path, len);
                paths.on_sent(now, &cfg, path, false);
            }
        }
    }

    /// Sends a `cand`, `svc` or `svcack` on every reported route and the active route
    ///.
    fn send_control_paths<R: CryptoRng>(
        &mut self,
        ctx: &mut Ctx<'_, R>,
        control: &Control,
        signal: bool,
    ) {
        let to = self
            .link
            .paths()
            .map(Paths::control_paths)
            .unwrap_or_default();
        for path in to {
            self.send_control_on(ctx, path, control, signal);
        }
    }

    /// Sends our `cand` that awaits its `candack`.
    fn send_telling<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        let Some(t) = self.link.telling() else {
            return;
        };
        let control = Control::Cand {
            seq: t.seq,
            cand: t.cand.clone(),
        };
        self.send_control_paths(ctx, &control, true);
    }

    /// Tells the peer our shared candidates if they differ from what it last heard.
    fn tell<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        if !self.link.is_up() {
            return;
        }
        let rto = self.rto();
        if let Some(t) = self.candidates.tell(ctx.now.instant, rto, ctx.own) {
            self.link.set_telling(Some(t));
            self.send_telling(ctx);
        }
    }

    /// Takes an offer the host remembered across a restart: only for a peer held
    /// by key whose link is not up and that has no offer yet. Returns whether it was taken.
    pub(crate) fn remember_offer(&mut self, site: Site) -> bool {
        if self.trust != Trust::Key || self.link.is_up() || self.offer.is_some() {
            return false;
        }
        self.offer = Some(ExitOffer { site, ipv4: None });
        true
    }

    /// Whether this peer is held by key and its remembered offer names `site`.
    pub(crate) fn offers_site(&self, site: &Site) -> bool {
        self.trust == Trust::Key && self.offer.as_ref().is_some_and(|o| o.site == *site)
    }

    /// Whether the peer is kept connected for an exit in use.
    pub(crate) fn is_held(&self) -> bool {
        self.hold.is_some()
    }

    /// Starts or stops keeping the link up for an exit in use: while held, a keepalive goes out
    /// each [`NAT_KEEPALIVE`] and a link that is down is initiated again.
    pub(crate) fn set_held<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>, held: bool) {
        match (held, self.hold) {
            (true, None) => {
                self.hold = Some(ctx.now.instant + NAT_KEEPALIVE);
                self.reach(ctx);
            }
            (false, Some(_)) => self.hold = None,
            _ => {}
        }
    }

    /// Initiates toward a peer held by key whose link is not up, so that its offer becomes known
    ///.
    pub(crate) fn reach<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        if self.trust == Trust::Key && !self.link.is_up() {
            self.connect(ctx, Why::Exit);
        }
    }

    /// Sends an empty frame on the active route, as data goes: it shows the route to the peer
    /// and the session to its owner.
    fn keepalive<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        let now = ctx.now.instant;
        let cfg = ctx.settings.routes;
        let Some(path) = self.route_active().map(|a| a.path) else {
            return;
        };
        let Some(session) = self.link.current_mut().filter(|s| s.can_send(now)) else {
            return;
        };
        let (_, data) = session.seal(&[]);
        let len = data.len();
        ctx.transmit(path, data, true);
        if let Some(paths) = self.link.paths_mut() {
            paths.count_sent(path, len);
            paths.on_sent(now, &cfg, path, true);
        }
        self.maybe_rekey(ctx);
    }

    /// Starts a handshake unless one is pending; a rate-limited one is kept in `retry`.
    pub(crate) fn connect<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>, why: Why) {
        match self.initiate(ctx) {
            Initiation::Limited(at) => self.schedule(at, why),
            Initiation::Started | Initiation::Pending => self.retry = None,
        }
    }

    fn send_initiation<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>, early: bool) {
        let now = ctx.now;
        let index = ctx.indices.alloc(ctx.rng, self.key);
        let ts = now.unix_nanos.max(self.hs.own_ts.saturating_add(1));
        self.hs.own_ts = ts;
        let hello = Hello {
            candidates: ctx.own.to_vec(),
            exit: self.offer_for_peer(ctx.exit),
        };
        let pad = if self.trust == Trust::Key {
            PADDED_PAYLOAD_1
        } else {
            0
        };
        let (body, carried) = payload::encode_msg1_padded(ts, &hello, MAX_PAYLOAD_1, pad);
        let candidates = hello.candidates[..carried].to_vec();
        let Ok((initiator, message1)) =
            Initiator::start(ctx.rng, ctx.keys, &self.key, index, &body)
        else {
            ctx.indices.free(index);
            return;
        };
        let cookie = self.hs.valid_cookie(now.instant);
        let Ok(fragments) = message::fragment_message(
            &message1,
            MessageNumber::One,
            index,
            &self.hs.mac1_out,
            cookie.as_ref(),
        ) else {
            ctx.indices.free(index);
            return;
        };
        let mac1 = |f: &[u8]| -> [u8; 16] {
            let mut m = [0u8; 16];
            m.copy_from_slice(&f[f.len() - 32..f.len() - 16]);
            m
        };
        let fragment_mac1 = [mac1(&fragments[0]), mac1(&fragments[1])];
        let mut whole = Vec::with_capacity(1 + message1.len());
        whole.push(message::TYPE_MSG1);
        whole.extend_from_slice(&message1);
        let message = HandshakeMessage { fragments, whole };
        let sent = Sent {
            index,
            initiator,
            fragment_mac1,
            candidates,
            early,
            early_used: false,
        };
        let retransmit_at = now.instant + REKEY_TIMEOUT + jitter(ctx.rng);
        match self.link.attempt_mut() {
            Some(a) => {
                if a.sent.len() >= PENDING_LIMIT {
                    let old = a.sent.remove(0);
                    ctx.indices.free(old.index);
                }
                a.sent.push(sent);
                a.message = message;
                a.retransmit_at = retransmit_at;
            }
            None => {
                let attempt = Attempt {
                    started: now.instant,
                    sent: vec![sent],
                    message,
                    retransmit_at,
                    switch_at: None,
                    paths: Vec::new(),
                };
                self.link = match std::mem::take(&mut self.link) {
                    Link::Idle { .. } => Link::Connecting {
                        attempt,
                        responded: None,
                    },
                    Link::Responding { responded } => Link::Connecting {
                        attempt,
                        responded: Some(responded),
                    },
                    Link::Up {
                        current,
                        previous,
                        next,
                        loss_at,
                        lastminute,
                        paths,
                        telling,
                        ..
                    } => Link::Up {
                        current,
                        previous,
                        next,
                        rekey: Some(attempt),
                        loss_at,
                        lastminute,
                        paths,
                        telling,
                    },
                    connecting @ Link::Connecting { .. } => connecting,
                };
            }
        }
        if !early {
            self.hs.last_initiation = Some(now.instant);
        }
        ctx.event(Event::Initiation { peer: self.key });
        self.fan_out(ctx);
    }

    /// Sends the latest message 1 on the active route if it is probed, to every address of the
    /// direct targets and the peer's shared candidates that a ready probed transport reaches,
    /// and, when no such path exists or the attempt is older than `fallback_delay`, through every
    /// reporting transport that reaches the peer. Every path is recorded in the
    /// attempt.
    fn fan_out<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        let Some(attempt) = self.link.attempt() else {
            return;
        };
        let message = attempt.message.clone();
        let started = attempt.started;
        let mut paths: Vec<Path> = Vec::new();
        if let Some(a) = self.link.paths().and_then(Paths::active)
            && ctx
                .transports
                .get(a.path.via)
                .is_some_and(|e| e.medium.reachability() == Reachability::Probe)
        {
            paths.push(a.path);
        }
        let targets: Vec<Candidate> = self
            .book
            .targets()
            .into_iter()
            .chain(self.candidates.shared().iter().copied())
            .collect();
        for c in targets {
            let to = Remote::Addr(c.addr);
            for (via, e) in ctx.transports.iter() {
                let path = Path { via, to };
                if e.usable()
                    && !e.medium.on_demand()
                    && e.medium.reachability() == Reachability::Probe
                    && e.medium.reaches(&to, c.local)
                    && !paths.contains(&path)
                {
                    paths.push(path);
                }
            }
        }
        for p in &paths {
            send_message(ctx, *p, &message);
        }
        let reporting: Vec<Path> = ctx
            .transports
            .reporting(&self.key)
            .map(|via| Path {
                via,
                to: Remote::Peer(self.key),
            })
            .collect();
        let has_reporting = !reporting.is_empty();
        let due_at = started + ctx.settings.routes.fallback_delay;
        let send_now = has_reporting && (paths.is_empty() || ctx.now.instant >= due_at);
        if send_now {
            for p in &reporting {
                send_message(ctx, *p, &message);
            }
            paths.extend(reporting);
        }
        if let Some(a) = self.link.attempt_mut() {
            for p in paths {
                if !a.paths.contains(&p) {
                    a.paths.push(p);
                }
            }
            if has_reporting {
                a.switch_at = (!send_now).then_some(due_at);
            }
        }
    }

    /// Sends the pending message 1 again, to targets or transports found since.
    pub(crate) fn resend<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        if matches!(self.link, Link::Connecting { .. }) {
            self.fan_out(ctx);
        }
    }

    /// A message 1 from this peer, already read by `responder`, that arrived on `path`; `raw`
    /// is the whole message.
    pub(crate) fn on_message1<R: CryptoRng>(
        &mut self,
        ctx: &mut Ctx<'_, R>,
        path: Path,
        raw: &[u8],
        responder: Responder,
    ) {
        let now = ctx.now.instant;
        let Ok((ts, hello)) = payload::decode_msg1(responder.payload()) else {
            return;
        };
        let hash = *blake3::hash(raw).as_bytes();
        if let Some(r) = self.link.responded()
            && r.msg1 == hash
        {
            if r.path != path && self.hs.rate.allow(now) {
                let m = r.msg2.clone();
                send_message(ctx, path, &m);
            }
            return;
        }
        if !self.hs.rate.allow(now) || self.hs.last_ts.is_some_and(|last| ts <= last) {
            return;
        }
        self.hs.last_ts = Some(ts);
        self.last_used = now;

        let Some(framing) = ctx.transports.framing(path.via) else {
            return;
        };
        let reply_limit = match framing {
            Framing::Whole => MAX_PAYLOAD_2,
            Framing::Fragmented { .. } => raw.len().saturating_sub(MIN_MESSAGE2).min(MAX_PAYLOAD_2),
        };
        let own = Hello {
            candidates: ctx.own.to_vec(),
            exit: self.offer_for_peer(ctx.exit),
        };
        let (body, carried) = payload::encode_msg2_counted(&own, reply_limit);
        let own_carried = own.candidates[..carried].to_vec();
        let sender_index = ctx.indices.alloc(ctx.rng, self.key);
        let initiator_index = responder.initiator_index();
        let Ok((message2, completed)) = responder.respond(ctx.rng, &self.psk, sender_index, &body)
        else {
            ctx.indices.free(sender_index);
            return;
        };
        let cookie = self.hs.valid_cookie(now);
        let Ok(fragments) = message::fragment_message(
            &message2,
            MessageNumber::Two,
            sender_index,
            &self.hs.mac1_out,
            cookie.as_ref(),
        ) else {
            ctx.indices.free(sender_index);
            return;
        };
        let mut whole = Vec::with_capacity(1 + message2.len());
        whole.push(TYPE_MSG2);
        whole.extend_from_slice(&message2);
        let msg2 = HandshakeMessage { fragments, whole };
        send_message(ctx, path, &msg2);

        let mut session = Session::new(&completed.keys, false, sender_index, initiator_index, now);
        session.offer = self.accepted_offer(hello.exit);
        if let Some(old) = self.link.responded() {
            ctx.indices.drop_unconfirmed(old.seq);
        }
        let seq = ctx.indices.push_unconfirmed(self.key);
        let freed = self.link.respond(Responded {
            session,
            seq,
            msg1: hash,
            msg2,
            candidates: own_carried,
            peer_candidates: hello.candidates,
            path,
        });
        for i in freed {
            ctx.indices.free(i);
        }
    }

    /// A message 2 answering one of our indices.
    pub(crate) fn on_message2<R: CryptoRng>(
        &mut self,
        ctx: &mut Ctx<'_, R>,
        path: Path,
        raw: &[u8],
    ) {
        let now = ctx.now.instant;
        let Ok(m) = message::parse_message2(raw) else {
            return;
        };
        let Some(sent) = self
            .link
            .attempt()
            .and_then(|a| a.sent.iter().find(|s| s.index == m.receiver_index))
        else {
            return;
        };
        let Ok((completed, remote_index)) = sent.initiator.finish(ctx.keys, &self.psk, raw) else {
            return;
        };
        let (index, own_carried) = (sent.index, sent.candidates.clone());
        let Ok(reply) = payload::decode_msg2(&completed.payload) else {
            for i in self.link.give_up() {
                ctx.indices.free(i);
            }
            return;
        };
        self.retry = None;
        self.last_used = now;
        let mut session = Session::new(&completed.keys, true, index, remote_index, now);
        session.offer = self.accepted_offer(reply.exit);
        let verified = self
            .link
            .attempt()
            .is_some_and(|a| a.paths.contains(&path))
            .then_some(path);
        let entered = !self.link.is_up();
        let changed = self.candidates.handshake(&own_carried, &reply.candidates);
        let cfg = ctx.settings.routes;
        let known = Known {
            key: &self.key,
            book: &self.book,
            candidates: &self.candidates,
            transports: ctx.transports,
            local_metered: ctx.local_metered,
        };
        let freed = self
            .link
            .complete(session, || known.paths(now, &cfg, &[path], verified));
        for i in freed {
            ctx.indices.free(i);
        }
        self.session_up(ctx, entered, changed);
    }

    /// A cookie reply answering one of our indices.
    pub(crate) fn on_cookie<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>, reply: &CookieReply) {
        let Some(sent) = self
            .link
            .attempt_mut()
            .and_then(|a| a.sent.iter_mut().find(|x| x.index == reply.receiver_index))
        else {
            return;
        };
        let cookie = reply
            .open(&self.hs.cookie_key, &sent.fragment_mac1[0])
            .or_else(|| reply.open(&self.hs.cookie_key, &sent.fragment_mac1[1]));
        let Some(cookie) = cookie else { return };
        self.hs.cookie = Some(StoredCookie {
            value: Zeroizing::new(cookie),
            received_at: ctx.now.instant,
        });
        if !sent.early && !sent.early_used {
            sent.early_used = true;
            self.send_initiation(ctx, true);
        }
    }

    /// The link came up or rekeyed: the shared candidates of the handshake are in; `entered`:
    /// the link was not up before, so its routes were just built. The initiator's when message
    /// 2 arrives, the responder's when its first frame does.
    fn session_up<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>, entered: bool, changed: bool) {
        let now = ctx.now.instant;
        self.offer = self.link.current().and_then(|s| s.offer.clone());
        if changed {
            ctx.event(Event::Candidates {
                peer: self.key,
                candidates: self.candidates.shared().to_vec(),
            });
        }
        if !entered {
            self.sync_paths(ctx);
        }
        self.tell(ctx);
        let rto = self.rto();
        ctx.services.book.session_up(now, &self.key, |_| rto);
        ctx.services.dirty = true;
        self.pump(ctx);
    }

    /// The link left `Up`: the service book forgets the session.
    fn session_down<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        ctx.services.book.session_down(ctx.now.instant, &self.key);
        ctx.services.dirty = true;
        if self.hold.is_some() {
            self.connect(ctx, Why::Exit);
        }
    }

    /// What a frame this peer sealed carries, for the simulator's trace.
    #[cfg(feature = "sim")]
    pub(crate) fn describe_sent(&self, header: &FrameHeader, data: &[u8]) -> Option<&'static str> {
        let plaintext = self
            .link
            .sessions()
            .find_map(|s| s.open_sent(header, data))?;
        Some(match plaintext.first() {
            None => "keepalive",
            Some(&route::control::CONTROL_MARKER) => match route::parse_control(&plaintext) {
                Some(Control::Ping { .. }) => "ping",
                Some(Control::Pong { .. }) => "pong",
                Some(Control::Cand { .. }) => "cand",
                Some(Control::CandAck { .. }) => "candack",
                Some(Control::Svc { .. }) => "svc",
                Some(Control::SvcAck { .. }) => "svcack",
                None => "control?",
            },
            Some(_) => "data",
        })
    }

    /// The routes the transports and candidates make for this peer, plus `learned` paths whose
    /// transport still reaches them.
    #[cfg(test)]
    pub(crate) fn specs(
        &self,
        transports: &Transports,
        local_metered: bool,
        learned: &[Path],
    ) -> Vec<Spec> {
        Known {
            key: &self.key,
            book: &self.book,
            candidates: &self.candidates,
            transports,
            local_metered,
        }
        .specs(learned)
    }

    /// The routes changed their set or their class: `Paths` takes the new specs.
    fn sync_paths<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        let Some(paths) = self.link.paths() else {
            return;
        };
        let learned: Vec<Path> = paths.learned().collect();
        let specs = Known {
            key: &self.key,
            book: &self.book,
            candidates: &self.candidates,
            transports: ctx.transports,
            local_metered: ctx.local_metered,
        }
        .specs(&learned);
        let (now, cfg) = (ctx.now.instant, ctx.settings.routes);
        if let Some(paths) = self.link.paths_mut() {
            paths.sync(now, &cfg, &specs);
        }
    }

    /// The spec `Paths` needs for a frame from `path`: any route it knows, or a learned route
    /// if `path` is an address on a probed transport. None on a transport that is
    /// not usable: the frame is handled, but makes no route and moves none.
    fn frame_spec<R: CryptoRng>(&self, ctx: &Ctx<'_, R>, path: Path) -> Option<Spec> {
        let e = ctx.transports.get(path.via).filter(|e| e.usable())?;
        let known = self.link.paths().is_some_and(|p| p.knows(&path));
        let learnable =
            matches!(path.to, Remote::Addr(_)) && e.medium.reachability() == Reachability::Probe;
        if !known && !learnable {
            return None;
        }
        let mut class = e.medium.class();
        class.metered |= ctx.local_metered;
        Some(Spec {
            path,
            class,
            label: "learned",
            origin: Origin::Learned,
        })
    }

    /// A data frame for one of our sessions.
    pub(crate) fn on_frame<R: CryptoRng>(
        &mut self,
        ctx: &mut Ctx<'_, R>,
        path: Path,
        header: &FrameHeader,
        data: &[u8],
    ) -> Delivered {
        enum Body {
            Keepalive,
            Data(Vec<u8>),
            Control(Control),
            Skip,
        }
        let now = ctx.now.instant;
        let cfg = ctx.settings.routes;
        let Some(slot) = self.link.slot_of(header.receiver_index) else {
            return Delivered::Nothing;
        };
        let Some(session) = self.link.session_mut(slot) else {
            return Delivered::Nothing;
        };
        if session.expired(now) || !session.window.check(header.counter) {
            return Delivered::Nothing;
        }
        let Ok(plaintext) = session.open(header, data) else {
            return Delivered::Nothing;
        };
        let newest = session.window.is_newest(header.counter);
        session.window.update(header.counter);
        let initiator = session.initiator;
        let created = session.created;

        let mut confirmed = false;
        if slot == Slot::Next
            && let Some(r) = self.link.responded()
        {
            let (told, theirs, hs_path) = (r.candidates.clone(), r.peer_candidates.clone(), r.path);
            let changed = self.candidates.handshake(&told, &theirs);
            let entered = !self.link.is_up();
            let known = Known {
                key: &self.key,
                book: &self.book,
                candidates: &self.candidates,
                transports: ctx.transports,
                local_metered: ctx.local_metered,
            };
            if let Some(c) = self
                .link
                .confirm(|_| known.paths(now, &cfg, &[hs_path, path], None))
            {
                for i in c.freed {
                    ctx.indices.free(i);
                }
                ctx.indices.drop_unconfirmed(c.seq);
                self.session_up(ctx, entered, changed);
                confirmed = true;
            }
        }
        self.last_used = now;
        self.link.set_loss_at(None);
        if matches!(self.retry, Some(Retry { why: Why::Loss, .. })) {
            self.retry = None;
        }

        let body = if plaintext.is_empty() {
            Body::Keepalive
        } else if plaintext[0] == route::control::CONTROL_MARKER {
            match route::parse_control(&plaintext) {
                Some(c) => Body::Control(c),
                None => Body::Skip,
            }
        } else {
            let Some(packet) = self.ip_source(ctx).accept(&plaintext) else {
                return Delivered::Nothing;
            };
            Body::Data(packet.to_vec())
        };

        if !matches!(body, Body::Skip) {
            if self.link.paths().and_then(Paths::active).map(|a| a.path) == Some(path) {
                ctx.mark_use(path);
            }
            let mut live = false;
            if let Some(paths) = self.link.paths_mut() {
                paths.on_rx(now, path);
                live = paths.hear(created);
            }
            let spec = self.frame_spec(ctx, path);
            match &body {
                Body::Keepalive | Body::Skip => {}
                Body::Data(_) => {
                    if let Some(spec) = spec
                        && let Some(paths) = self.link.paths_mut()
                    {
                        paths.on_data(now, &cfg, spec, newest && live);
                    }
                }
                Body::Control(Control::Ping { txid }) => match spec {
                    Some(spec) => {
                        if let Some(paths) = self.link.paths_mut() {
                            paths.on_ping(now, &cfg, spec, *txid);
                        }
                    }
                    None => {
                        let pong = Control::Pong {
                            txid: *txid,
                            observed: None,
                        };
                        self.send_probe(ctx, path, &pong);
                    }
                },
                Body::Control(Control::Pong { txid, observed }) => {
                    if observed.is_some() {
                        self.observed = *observed;
                    }
                    if let Some(paths) = self.link.paths_mut() {
                        paths.on_pong(now, &cfg, path, *txid);
                    }
                }
                Body::Control(Control::Cand { seq, cand }) => {
                    let (ack, changed) = self.candidates.receive(*seq, cand);
                    let ack = Control::CandAck { seq: ack };
                    self.send_control_on(ctx, path, &ack, true);
                    if changed {
                        ctx.event(Event::Candidates {
                            peer: self.key,
                            candidates: self.candidates.shared().to_vec(),
                        });
                        self.sync_paths(ctx);
                    }
                }
                Body::Control(Control::CandAck { seq }) => {
                    let rto = self.rto();
                    let before = self.link.telling().cloned();
                    let after = self.candidates.acked(now, rto, *seq, before.clone());
                    let fresh = after
                        .as_ref()
                        .is_some_and(|t| before.as_ref().is_none_or(|b| b.seq != t.seq));
                    self.link.set_telling(after);
                    if fresh {
                        self.send_telling(ctx);
                    }
                }
                Body::Control(Control::Svc { .. } | Control::SvcAck { .. }) => {}
            }
            if let Some(paths) = self.link.paths_mut() {
                paths.count_received(path, data.len());
            }
            self.pump(ctx);
        }

        if self
            .link
            .current()
            .is_some_and(|s| s.local_index == header.receiver_index)
            && initiator
            && !self.link.lastminute()
            && now
                >= created
                    + REJECT_AFTER_TIME
                        .saturating_sub(ctx.settings.keepalive_timeout + REKEY_TIMEOUT)
        {
            self.link.set_lastminute();
            let _ = self.initiate(ctx);
        }
        if confirmed {
            self.pump(ctx);
        }
        match body {
            Body::Data(p) => Delivered::Packet(p),
            Body::Control(c @ (Control::Svc { .. } | Control::SvcAck { .. })) => {
                Delivered::Service(c)
            }
            _ => Delivered::Nothing,
        }
    }

    /// Runs the peer's timers.
    pub(crate) fn handle_timeout<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        let now = ctx.now.instant;
        let cfg = ctx.settings.routes;
        let was_up = self.link.is_up();
        let expired = self.link.expire(now);
        for i in expired.freed {
            ctx.indices.free(i);
        }
        for s in expired.unconfirmed {
            ctx.indices.drop_unconfirmed(s);
        }
        if was_up && !self.link.is_up() {
            self.session_down(ctx);
        }

        if self.link.loss_at().is_some_and(|t| t <= now) {
            self.link.set_loss_at(None);
            if let Initiation::Limited(at) = self.initiate(ctx) {
                self.schedule(at, Why::Loss);
            }
        }
        if let Some(r) = self.retry.filter(|r| r.at <= now) {
            self.retry = None;
            let go = match r.why {
                Why::Queued => !self.queue.is_empty(),
                Why::Loss => true,
                Why::Exit => !self.link.is_up(),
            };
            if go && let Initiation::Limited(at) = self.initiate(ctx) {
                self.schedule(at, r.why);
            }
        }
        if let Some(a) = self.link.attempt()
            && a.retransmit_at <= now
        {
            if now >= a.started + REKEY_ATTEMPT_TIME {
                let connecting = matches!(self.link, Link::Connecting { .. });
                for i in self.link.give_up() {
                    ctx.indices.free(i);
                }
                if connecting {
                    self.queue.clear();
                }
            } else {
                self.send_initiation(ctx, false);
            }
        }
        if let Some(a) = self.link.attempt_mut()
            && a.switch_at.is_some_and(|t| t <= now)
        {
            a.switch_at = None;
            let message = a.message.clone();
            let reporting: Vec<Path> = ctx
                .transports
                .reporting(&self.key)
                .map(|via| Path {
                    via,
                    to: Remote::Peer(self.key),
                })
                .collect();
            for p in &reporting {
                send_message(ctx, *p, &message);
            }
            if let Some(a) = self.link.attempt_mut() {
                for p in reporting {
                    if !a.paths.contains(&p) {
                        a.paths.push(p);
                    }
                }
            }
        }
        if let Some(paths) = self.link.paths_mut() {
            paths.handle_timeout(now, &cfg);
        }
        if self.hold.is_some_and(|at| at <= now) {
            self.hold = Some(now + NAT_KEEPALIVE);
            if self.link.is_up() {
                self.keepalive(ctx);
            } else {
                self.connect(ctx, Why::Exit);
            }
        }
        if self.link.telling().is_some_and(|t| t.next <= now) {
            self.send_telling(ctx);
            let rto = self.rto();
            let keepalive = ctx.settings.keepalive_timeout;
            if let Some(t) = self.link.telling_mut() {
                t.sent(now, rto, keepalive);
            }
        }
        self.pump(ctx);
    }

    /// The earliest instant at which `handle_timeout` has work for this peer.
    pub(crate) fn poll_timeout(&self, cfg: &route::Config) -> Option<Instant> {
        let attempt = self.link.attempt();
        self.link
            .sessions()
            .map(Session::expires_at)
            .chain(self.link.loss_at())
            .chain(self.retry.map(|r| r.at))
            .chain(attempt.map(|a| a.retransmit_at))
            .chain(attempt.and_then(|a| a.switch_at))
            .chain(self.link.paths().and_then(|p| p.poll_timeout(cfg)))
            .chain(self.link.telling().map(|t| t.next))
            .chain(self.hold)
            .min()
    }

    /// Replaces the candidates of one source group; returns whether the set changed.
    pub(crate) fn set_candidates<R: CryptoRng>(
        &mut self,
        ctx: &mut Ctx<'_, R>,
        group: Group,
        found: Found,
    ) -> bool {
        let changed = self.book.apply(group, found);
        if changed {
            self.sync_paths(ctx);
            self.pump(ctx);
            self.resend(ctx);
        }
        changed
    }

    /// The transports, their readiness or the peer's reachability on them changed.
    pub(crate) fn transports_changed<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        self.sync_paths(ctx);
        self.pump(ctx);
    }

    /// The node's shared candidates changed.
    pub(crate) fn own_candidates_changed<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        self.tell(ctx);
        self.pump(ctx);
    }

    /// The local network became metered or stopped being metered.
    pub(crate) fn local_metered_changed<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        self.sync_paths(ctx);
        self.pump(ctx);
    }

    /// A settled local change of `families`: their probed routes are verified again
    ///.
    pub(crate) fn local_change<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>, families: Families) {
        let (now, cfg) = (ctx.now.instant, ctx.settings.routes);
        if let Some(paths) = self.link.paths_mut() {
            paths.local_change(now, &cfg, families);
        }
        self.pump(ctx);
    }

    /// Sends a service message on every reported route and the active route, as a `cand` goes.
    pub(crate) fn send_control<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>, control: &Control) {
        self.send_control_paths(ctx, control, false);
    }

    /// Carries out what `Paths` says to do, then sends the queue if a route is active
    ///.
    fn pump<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        loop {
            let Some(action) = self.link.paths_mut().and_then(Paths::poll) else {
                if self.flush(ctx) {
                    continue;
                }
                return;
            };
            match action {
                Do::Ping { path, txid } => self.send_probe(ctx, path, &Control::Ping { txid }),
                Do::Pong {
                    path,
                    txid,
                    observed,
                } => self.send_probe(ctx, path, &Control::Pong { txid, observed }),
                Do::Demand => {
                    let now = ctx.now.instant;
                    let vias: Vec<TransportId> = ctx
                        .transports
                        .iter()
                        .filter(|(_, e)| e.medium.on_demand() && !e.ready && !e.exhausted())
                        .map(|(via, _)| via)
                        .collect();
                    for via in vias {
                        if let Some(e) = ctx.transports.get_mut(via) {
                            e.last_use = Some(now);
                            e.demanded = true;
                        }
                        ctx.out.push_back(Output::Demand { via, on: true });
                    }
                }
                Do::Failed(path) => {
                    if let Remote::Addr(addr) = path.to
                        && ctx
                            .transports
                            .get(path.via)
                            .is_some_and(|e| !e.medium.on_demand())
                    {
                        ctx.event(Event::RouteFailed {
                            peer: self.key,
                            addr,
                        });
                    }
                }
                Do::Lost => self.lose(ctx),
            }
        }
    }

    /// No route is left: the session is dropped, and a new handshake starts if
    /// packets are waiting.
    fn lose<R: CryptoRng>(&mut self, ctx: &mut Ctx<'_, R>) {
        let lost = self.link.lose();
        for i in lost.freed {
            ctx.indices.free(i);
        }
        for s in lost.unconfirmed {
            ctx.indices.drop_unconfirmed(s);
        }
        self.session_down(ctx);
        if !self.queue.is_empty() {
            self.connect(ctx, Why::Queued);
        }
    }

    /// The route to report: the active route while the link is up.
    fn route_view(&self) -> Option<RouteView> {
        let a = self.route_active()?;
        Some(RouteView {
            path: a.path,
            class: a.class,
            label: a.label,
            verified: a.verified,
            meter: a.meter,
        })
    }

    /// What changed since the state and the route were last reported; marks them reported.
    pub(crate) fn take_changes(&mut self) -> (Option<PeerState>, Option<Option<RouteView>>) {
        let state = self.link.state();
        let route = self.route_view();
        let state = (state != self.reported).then(|| {
            self.reported = state;
            state
        });
        let route = (!same_route(route, self.reported_route)).then(|| {
            self.reported_route = route;
            route
        });
        (state, route)
    }

    pub(crate) fn has_link(&self) -> bool {
        !matches!(self.link, Link::Idle { .. })
    }

    /// Whether a first handshake has an address to go to directly.
    pub(crate) fn has_targets(&self) -> bool {
        !self.book.targets().is_empty() || !self.candidates.shared().is_empty()
    }

    pub(crate) fn view(&self, transports: &Transports) -> PeerView {
        let active = self.route_view();
        let paths = self.link.paths();
        PeerView {
            trust: self.trust,
            link: self.link.state(),
            unconfirmed: self.link.responded().is_some(),
            pending: self.link.attempt().map_or(0, |a| a.sent.len()),
            queued: self.queue.len(),
            active,
            degraded: active.is_some()
                && self.class.is_some_and(|c| {
                    paths.is_some_and(|p| matches!(p.route_for(&c), Delivery::Degraded(_)))
                }),
            routes: paths.map(Paths::routes).unwrap_or_default(),
            shared: self.candidates.shared().to_vec(),
            found: self.book.candidates(),
            targets: self.book.targets().iter().map(|c| c.addr).collect(),
            reporting: transports.reporting(&self.key).collect(),
            probing: paths.is_some_and(Paths::probing),
            fallback: paths.is_some_and(Paths::fallback),
            rto: self.rto(),
            observed: self.observed,
            exit: self.exit_offer().cloned(),
        }
    }
}

/// What a peer knows of its routes, borrowed from the fields that make their specs.
struct Known<'a> {
    key: &'a NodePublic,
    book: &'a Book,
    candidates: &'a Candidates,
    transports: &'a Transports,
    local_metered: bool,
}

impl Known<'_> {
    /// The specs: a route per reported transport that reaches the peer, per
    /// pair of a candidate and a ready probed transport that reaches it, and per learned path
    /// whose transport still reaches it and that no candidate covers. Reported routes come first
    /// so that the route cap never cuts one; the candidates follow in preference order: the
    /// local sources' in the order they found them, then the peer's in the order it listed them;
    /// learned paths come last.
    fn specs(&self, learned: &[Path]) -> Vec<Spec> {
        let mut out: Vec<Spec> = Vec::new();
        let mut add = |spec: Spec| {
            if !out.iter().any(|s| s.path == spec.path) {
                out.push(spec);
            }
        };
        let probed = |via: TransportId, to: &Remote, local: bool| {
            self.transports.get(via).filter(|e| {
                e.usable()
                    && e.medium.reachability() == Reachability::Probe
                    && e.medium.reaches(to, local)
            })
        };
        for via in self.transports.reporting(self.key) {
            if let Some(spec) = self.reported(via) {
                add(spec);
            }
        }
        let found = self.book.candidates();
        for c in found.iter().chain(self.candidates.shared()) {
            let to = Remote::Addr(c.addr);
            for (via, e) in self.transports.iter() {
                if probed(via, &to, c.local).is_none() {
                    continue;
                }
                let mut class = e.medium.class();
                if c.local {
                    class.latency = Latency::Low;
                }
                class.metered |= c.metered || self.local_metered;
                add(Spec {
                    path: Path { via, to },
                    class,
                    label: c.label,
                    origin: Origin::Candidate,
                });
            }
        }
        for path in learned {
            if let Some(e) = probed(path.via, &path.to, false) {
                let mut class = e.medium.class();
                class.metered |= self.local_metered;
                add(Spec {
                    path: *path,
                    class,
                    label: "learned",
                    origin: Origin::Learned,
                });
            }
        }
        out
    }

    /// The spec of the reported route over `via`.
    fn reported(&self, via: TransportId) -> Option<Spec> {
        let to = Remote::Peer(*self.key);
        let e = self.transports.get(via)?;
        let mut class = e.medium.class();
        class.metered |= self.local_metered;
        Some(Spec {
            path: Path { via, to },
            class,
            label: "switch",
            origin: Origin::Reported,
        })
    }

    /// The routes of a link that came up: the specs, the `handshake` paths (where message 1 or
    /// 2 and the first frame arrived) as learned routes, or reported ones on a ready reported
    /// transport, if nothing covers them, and message 2's path `verified` if message 1 went out
    /// on it.
    fn paths(
        &self,
        now: Instant,
        cfg: &route::Config,
        handshake: &[Path],
        verified: Option<Path>,
    ) -> Paths {
        let mut specs = self.specs(handshake);
        for path in handshake {
            if specs.iter().any(|s| s.path == *path) || path.to != Remote::Peer(*self.key) {
                continue;
            }
            if self
                .transports
                .get(path.via)
                .is_some_and(|e| e.usable() && e.medium.reachability() == Reachability::Reported)
                && let Some(spec) = self.reported(path.via)
            {
                specs.insert(0, spec);
            }
        }
        Paths::new(now, cfg, &specs, verified)
    }
}

/// What an authenticated frame carried that the node hands on: packets go to the caller,
/// service messages to the [`crate::ip::service::ServiceBook`].
pub(crate) enum Delivered {
    Nothing,
    Packet(Vec<u8>),
    Service(Control),
}

#[cfg(test)]
impl Peer {
    /// Installs an unconfirmed responder session, as answering a message 1 does.
    pub(crate) fn install_unconfirmed(&mut self, indices: &mut Indices, session: Session) {
        if let Some(old) = self.link.responded() {
            indices.drop_unconfirmed(old.seq);
        }
        let seq = indices.push_unconfirmed(self.key);
        indices.record(session.local_index, self.key);
        let responded = Responded {
            session,
            seq,
            msg1: [0; 32],
            msg2: HandshakeMessage {
                fragments: [Vec::new(), Vec::new()],
                whole: Vec::new(),
            },
            candidates: Vec::new(),
            peer_candidates: Vec::new(),
            path: Path {
                via: TransportId(0),
                to: Remote::Peer(self.key),
            },
        };
        for i in self.link.respond(responded) {
            indices.free(i);
        }
    }

    pub(crate) fn has_unconfirmed(&self) -> bool {
        self.link.responded().is_some()
    }

    pub(crate) fn has_session(&self) -> bool {
        self.link.is_up()
    }

    /// Makes `theirs` the peer's shared candidates, as a handshake does.
    pub(crate) fn share(&mut self, theirs: &[Candidate]) {
        self.candidates.handshake(&[], theirs);
    }
}
