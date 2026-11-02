//! The sans-IO node: every peer, its handshakes, sessions and routes, over the caller's
//! transports.
//!
//! The caller registers transports, feeds datagrams with [`Node::handle_datagram`], time with
//! [`Node::handle_timeout`] and application packets with [`Node::send`], and carries out the
//! [`Output`]s it drains with [`Node::poll_output`]. [`Node::poll_timeout`] says when
//! `handle_timeout` must next be called.

pub(crate) mod peers;

use std::collections::{BTreeSet, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rand_core::CryptoRng;

use crate::addr::OverlayAddrs;
use crate::discovery::candidate::Candidate;
use crate::error::PeerError;
use crate::handshake::cookie::CookieJar;
use crate::handshake::message::{self, MAX_FRAGMENT, MessageNumber};
use crate::handshake::reassembly::{self, Reassembly};
use crate::handshake::{LocalKeys, Responder};
use crate::ip::exit::{Change, ExitServe, ExitUse, Exits, SiteView};
use crate::ip::service::{Proto, Provider, Service, ServiceAction, ServiceBook};
use crate::ip::site::{Site, site_addr};
use crate::keys::{NetworkId, NetworkSecret, NodePublic, NodeSecret, PairPsk};
use crate::meter::{Budget, Level, Meter};
use crate::peer::{Ctx, Delivered, Found, Group, Peer, PeerView};
use crate::plane::frame::DEFAULT_MTU;
use crate::route::{self, DeliveryClass, Families, RouteClass};
use crate::session::KEEPALIVE_TIMEOUT;
use crate::time::{Instant, Now};
use crate::transport::{
    DEMAND_IDLE, Entry, Framing, Medium, Path, Remote, TransportId, Transports,
};

pub use crate::peer::Trust;
pub(crate) use peers::Peers;
use peers::UNCONFIRMED_LIMIT;

/// Handshake datagrams per second above which the node is under load (vv-02 §4.2).
pub const DEFAULT_LOAD_THRESHOLD: u32 = 256;

/// How long a use of an exit waits for one of the site's known exits before it initiates toward
/// every peer held by key.
pub const EXIT_SEARCH: Duration = Duration::from_secs(5);

/// Node settings.
pub struct Config {
    /// The node's private key.
    pub secret: NodeSecret,
    /// The network secret.
    pub network_secret: NetworkSecret,
    /// The network ID; defaults to `net_pk` (vv-01 §4.3).
    pub network_id: Option<NetworkId>,
    /// Accept any member of the network (vv-02 §4.4).
    pub accept_members: bool,
    /// The interface MTU (vv-03 §3.4).
    pub mtu: usize,
    /// `KEEPALIVE_TIMEOUT`; larger values are clamped to [`KEEPALIVE_TIMEOUT`] (vv-02 §6.4).
    pub keepalive_timeout: Duration,
    /// Handshake datagrams per second that mark the node as under load.
    pub load_threshold: u32,
    /// Settings of the routes of every peer; their `keepalive_timeout` is the node's.
    pub routes: route::Config,
    /// The exit this node offers to the peers it holds by key.
    pub exit: Option<ExitServe>,
}

impl Config {
    /// Default settings: key trust only, MTU 1280.
    pub fn new(secret: NodeSecret, network_secret: NetworkSecret) -> Self {
        Config {
            secret,
            network_secret,
            network_id: None,
            accept_members: false,
            mtu: DEFAULT_MTU,
            keepalive_timeout: KEEPALIVE_TIMEOUT,
            load_threshold: DEFAULT_LOAD_THRESHOLD,
            routes: route::Config::default(),
            exit: None,
        }
    }
}

/// A key-trusted peer entry (vv-07 `[[peer]]`).
#[derive(Clone)]
pub struct PeerConfig {
    /// The peer's public key.
    pub public: NodePublic,
    /// The pair PSK, or `zeros(32)` (vv-02 §2.1).
    pub psk: PairPsk,
}

impl PeerConfig {
    /// A peer without pair PSK.
    pub fn new(public: NodePublic) -> Self {
        PeerConfig {
            public,
            psk: PairPsk::none(),
        }
    }
}

/// An action for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send `data` on `path`.
    Transmit {
        /// Where.
        path: Path,
        /// The datagram.
        data: Vec<u8>,
        /// Handshake, keepalive or control rather than application data; a transport that paces
        /// data lets it through (vv-04 §3.4 `forward_limits`).
        signal: bool,
    },
    /// Bring an on-demand transport up (`on`) or let it go; it reports back with
    /// [`Node::set_ready`].
    Demand {
        /// The transport.
        via: TransportId,
        /// Whether it is wanted.
        on: bool,
    },
    /// Tell the caller something happened.
    Event(Event),
}

/// Why a peer went down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The session reached `REJECT_AFTER_TIME` with nothing sent or received, so no rekey replaced
    /// it: not a failure.
    Idle,
    /// No answer within `REKEY_ATTEMPT_TIME`; queued packets were dropped (vv-02 §6.4): the
    /// failure.
    Unreachable,
}

/// The connection state of a peer, as reported in [`Event::Peer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// No session and no handshake yet.
    Idle,
    /// A handshake is under way and no session can carry data yet.
    Connecting,
    /// A session can carry data.
    Up {
        /// Whether this node initiated the handshake that brought it up.
        initiator: bool,
    },
    /// The last session ended or the handshake gave up.
    Down(Reason),
}

/// The active route of a peer, for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteView {
    /// The path.
    pub path: Path,
    /// Its class: the medium's, low latency for a local candidate, metered if the candidate or
    /// the local network is.
    pub class: RouteClass,
    /// For views and logs: the candidate's label, `"learned"` or `"switch"`.
    pub label: &'static str,
    /// Whether a pong verified it or a transport reports it; `false` while it is active only
    /// because the peer roamed to it.
    pub verified: bool,
    /// What the route has carried when the view was made; it does not take part in deciding
    /// whether the route changed.
    pub meter: Meter,
}

/// A transport and what `proto` holds about it, from [`Node::transports`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportView {
    /// The transport.
    pub id: TransportId,
    /// The medium's name.
    pub name: String,
    /// The medium's own class.
    pub class: RouteClass,
    /// Whether the caller says it is up.
    pub ready: bool,
    /// Whether routes and messages may use it: ready, and its budget not exhausted.
    pub usable: bool,
    /// Every datagram sent and received on it.
    pub meter: Meter,
    /// What it may still carry, if a volume was stated.
    pub budget: Option<Budget>,
}

impl TransportView {
    fn of(id: TransportId, e: &Entry) -> Self {
        TransportView {
            id,
            name: e.medium.name().to_owned(),
            class: e.medium.class(),
            ready: e.ready,
            usable: e.usable(),
            meter: e.meter,
            budget: e.budget,
        }
    }
}

/// A notification for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A peer was created, configured or found by member trust. Its state starts as
    /// [`PeerState::Idle`].
    Added {
        /// The peer.
        peer: NodePublic,
        /// How it is trusted.
        trust: Trust,
    },
    /// A peer was removed, explicitly or because an idle member was evicted.
    Removed {
        /// The peer.
        peer: NodePublic,
    },
    /// The connection state of `peer` changed; reported once per change.
    Peer {
        /// The peer.
        peer: NodePublic,
        /// Its state.
        state: PeerState,
    },
    /// An authenticated IPv6 packet arrived (vv-03 §3.2).
    Packet {
        /// The peer.
        peer: NodePublic,
        /// The packet without padding.
        packet: Vec<u8>,
    },
    /// The active route of `peer` changed; `None` while the peer is not up. It follows the
    /// [`Event::Peer`] of the same step: the link comes up, then it has a route.
    Active {
        /// The peer.
        peer: NodePublic,
        /// The route, if any.
        route: Option<RouteView>,
    },
    /// The sites that some peer has offered, live or not, are now `sites`.
    /// Reported when the set changes, before the [`Event::Exit`] of the same step.
    Sites {
        /// The sites, in order.
        sites: Vec<Site>,
    },
    /// The offers remembered, live or not, are now `offers`: what the host keeps
    /// across restarts and gives back with [`Node::remember`].
    Remembered {
        /// Each peer and the site it offered, by key.
        offers: Vec<(NodePublic, Site)>,
    },
    /// The exit chosen for `site` is now `via`, or the IPv4 address it gives this node changed;
    /// `None` once the site has no live exit. Reported once per change, after the
    /// [`Event::Peer`] and [`Event::Active`] of the same step.
    Exit {
        /// The site.
        site: Site,
        /// The exit.
        via: Option<NodePublic>,
        /// The IPv4 address the exit gives this node; `None` without an exit or
        /// when it does not carry IPv4.
        ipv4: Option<Ipv4Addr>,
    },
    /// The exit this node serves gave `peer` the IPv4 address `ipv4`, or freed it (`None`), so
    /// that IPv4 for that address goes to the peer.
    ExitClient {
        /// The peer.
        peer: NodePublic,
        /// Its address.
        ipv4: Option<Ipv4Addr>,
    },
    /// Two sites with different names have the same id, so neither is used or offered
    ///. Reported once while it lasts.
    ExitCollision {
        /// The first site, in site order.
        first: Site,
        /// The second.
        second: Site,
    },
    /// Message 1 to `peer` went out: candidate sources may look the peer up again.
    Initiation {
        /// The peer.
        peer: NodePublic,
    },
    /// The peer's shared candidates changed (vv-05 §4.9); a TURN transport permits their
    /// addresses.
    Candidates {
        /// The peer.
        peer: NodePublic,
        /// The candidates.
        candidates: Vec<Candidate>,
    },
    /// A direct route to `addr` failed or went unanswered for a whole probing episode
    /// (vv-05 §4.9): a source holding fallbacks for it may offer the next one.
    RouteFailed {
        /// The peer.
        peer: NodePublic,
        /// The address of the route.
        addr: SocketAddr,
    },
    /// The services of some peer changed; [`Node::providers`] has the new answer.
    Services,
    /// The budget of transport `via` was set (`Some`) or removed (`None`), or crossed into a
    /// lower [`Level`].
    Budget {
        /// The transport.
        via: TransportId,
        /// The budget as it stands.
        budget: Option<Budget>,
    },
}

/// Sizes of the node's tables, for monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Peers held, configured and member.
    pub peers: usize,
    /// Session and pending-handshake indices in use.
    pub indices: usize,
    /// Partially received handshake messages.
    pub reassembly: usize,
}

/// Settings every peer reads, borrowed into [`crate::peer::Ctx`].
pub(crate) struct Settings {
    pub(crate) network_id: NetworkId,
    pub(crate) accept_members: bool,
    pub(crate) mtu: usize,
    pub(crate) keepalive_timeout: Duration,
    pub(crate) load_threshold: u32,
    pub(crate) routes: route::Config,
}

/// Handshake datagrams in the current one-second window.
#[derive(Default)]
pub(crate) struct LoadMeter {
    window_start: Option<Instant>,
    count: u32,
}

impl LoadMeter {
    pub(crate) fn record(&mut self, now: Instant) {
        match self.window_start {
            Some(s) if now < s + Duration::from_secs(1) => {
                self.count = self.count.saturating_add(1)
            }
            _ => {
                self.window_start = Some(now);
                self.count = 1;
            }
        }
    }

    pub(crate) fn rate(&self, now: Instant) -> u32 {
        match self.window_start {
            Some(s) if now < s + Duration::from_secs(1) => self.count,
            _ => 0,
        }
    }
}

/// The service book and whether it changed since [`Event::Services`] was last emitted.
pub(crate) struct Services {
    pub(crate) book: ServiceBook,
    pub(crate) dirty: bool,
}

/// Most peers one transport reports as reachable.
const MAX_REACHABLE: usize = 1024;

/// All state of one node.
pub struct Node {
    keys: LocalKeys,
    own_addrs: OverlayAddrs,
    settings: Settings,
    cookies: CookieJar,
    reassembly: Reassembly<Path>,
    load: LoadMeter,
    transports: Transports,
    peers: Peers,
    exits: Exits,
    /// The exit the host makes this network carry, if any.
    using: Option<ExitUse>,
    /// While a use waits for a live exit: when it initiates toward every peer held by key
    ///.
    search: Option<Instant>,
    /// The candidates this node shares in handshakes and `cand` messages.
    own: Vec<Candidate>,
    local_metered: bool,
    services: Services,
    /// Peers touched since the last time their state and route were compared with what was
    /// reported.
    touched: BTreeSet<NodePublic>,
    out: VecDeque<Output>,
}

/// Runs `$body` with the peer `$key` as `$p` and a [`Ctx`] as `$ctx`; `None` if there is no
/// such peer. The peer is marked as touched.
macro_rules! on_peer {
    ($s:expr, $now:expr, $rng:expr, $key:expr, $p:ident, $ctx:ident => $body:expr) => {{
        let key: NodePublic = *$key;
        match $s.peers.split(&key) {
            Some(($p, indices)) => {
                $s.touched.insert(key);
                let mut $ctx = Ctx {
                    now: $now,
                    rng: &mut *$rng,
                    keys: &$s.keys,
                    settings: &$s.settings,
                    transports: &mut $s.transports,
                    own: &$s.own,
                    exit: $s.exits.serving(),
                    local_metered: $s.local_metered,
                    indices,
                    services: &mut $s.services,
                    out: &mut $s.out,
                };
                Some($body)
            }
            None => None,
        }
    }};
}

/// Queues a datagram: the one place every `Output::Transmit` is made, charging the meter and
/// the budget of its transport. Nothing is queued on a transport whose budget is exhausted
///.
pub(crate) fn queue_transmit(
    transports: &mut Transports,
    out: &mut VecDeque<Output>,
    path: Path,
    data: Vec<u8>,
    signal: bool,
) {
    if transports.get(path.via).is_some_and(Entry::exhausted) {
        return;
    }
    let level = transports.charge_sent(path.via, data.len());
    out.push_back(Output::Transmit { path, data, signal });
    report_level(transports, out, path.via, level);
}

/// Queues [`Event::Budget`] if a charge crossed into a level.
fn report_level(
    transports: &Transports,
    out: &mut VecDeque<Output>,
    via: TransportId,
    level: Option<Level>,
) {
    if level.is_some() {
        let budget = transports.get(via).and_then(|e| e.budget);
        out.push_back(Output::Event(Event::Budget { via, budget }));
    }
}

fn source_bytes(path: &Path) -> Option<Vec<u8>> {
    let Remote::Addr(addr) = path.to else {
        return None;
    };
    let mut v = match addr.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };
    v.extend_from_slice(&addr.port().to_be_bytes());
    Some(v)
}

impl Node {
    /// A node with no peers and no transports.
    pub fn new<R: CryptoRng>(config: Config, now: Now, rng: &mut R) -> Self {
        let keys = LocalKeys::new(config.secret, config.network_secret);
        let network_id = config
            .network_id
            .unwrap_or_else(|| keys.network().default_network_id());
        let own_addrs = OverlayAddrs::derive(&network_id, keys.public());
        let keepalive_timeout = config.keepalive_timeout.min(KEEPALIVE_TIMEOUT);
        let services = Services {
            book: ServiceBook::new(*keys.public(), keepalive_timeout),
            dirty: false,
        };
        Node {
            own_addrs,
            settings: Settings {
                network_id,
                accept_members: config.accept_members,
                mtu: config.mtu,
                keepalive_timeout,
                load_threshold: config.load_threshold,
                routes: route::Config {
                    keepalive_timeout,
                    ..config.routes
                },
            },
            cookies: CookieJar::new(rng, now.instant),
            reassembly: Reassembly::new(),
            load: LoadMeter::default(),
            transports: Transports::default(),
            peers: Peers::default(),
            exits: Exits::new(network_id, config.exit),
            using: None,
            search: None,
            own: Vec::new(),
            local_metered: false,
            services,
            touched: BTreeSet::new(),
            out: VecDeque::new(),
            keys,
        }
    }

    /// This node's public key.
    pub fn public(&self) -> &NodePublic {
        self.keys.public()
    }

    /// This node's overlay addresses (vv-06 §2.1).
    pub fn overlay_addrs(&self) -> &OverlayAddrs {
        &self.own_addrs
    }

    /// The network ID in use.
    pub fn network_id(&self) -> &NetworkId {
        &self.settings.network_id
    }

    /// Registers a transport. An on-demand one starts not ready; a
    /// [`crate::transport::Reachability::Reported`] one starts ready with no peer reachable.
    pub fn add_transport(&mut self, medium: Arc<dyn Medium>) -> TransportId {
        self.transports.add(medium)
    }

    /// Forgets a transport and every route on it.
    pub fn remove_transport<R: CryptoRng>(&mut self, now: Now, rng: &mut R, via: TransportId) {
        if self.transports.remove(via).is_some() {
            self.transports_changed(now, rng);
        }
    }

    /// A [`crate::transport::Reachability::Reported`] transport says whether `peer` is
    /// reachable on it; returns whether that changed. A member that is reachable becomes a peer
    /// if member trust is on.
    pub fn set_reachable<R: CryptoRng>(
        &mut self,
        now: Now,
        rng: &mut R,
        via: TransportId,
        peer: &NodePublic,
        reachable: bool,
    ) -> bool {
        let Some(e) = self.transports.get_mut(via) else {
            return false;
        };
        let changed = if reachable {
            !e.reachable.contains(peer)
                && e.reachable.len() < MAX_REACHABLE
                && e.reachable.insert(*peer)
        } else {
            e.reachable.remove(peer)
        };
        if !changed {
            return false;
        }
        if reachable {
            let _ = self.ensure_peer(peer, now.instant);
        }
        on_peer!(self, now, rng, peer, p, ctx => {
            p.transports_changed(&mut ctx);
            p.resend(&mut ctx);
        });
        self.finish(now, rng);
        true
    }

    /// A transport became usable or stopped being usable (an allocation was made or lost, a
    /// switch registered or disconnected).
    pub fn set_ready<R: CryptoRng>(
        &mut self,
        now: Now,
        rng: &mut R,
        via: TransportId,
        ready: bool,
    ) {
        let Some(e) = self.transports.get_mut(via) else {
            return;
        };
        if e.ready == ready {
            return;
        }
        e.ready = ready;
        if ready {
            e.last_use = Some(now.instant);
        } else {
            e.demanded = false;
        }
        self.transports_changed(now, rng);
    }

    /// Replaces the budget of `via`, or removes it; reported with [`Event::Budget`]. A budget
    /// that arrives exhausted makes the transport unusable at once, a fresh one makes it usable
    /// again.
    pub fn set_budget<R: CryptoRng>(
        &mut self,
        now: Now,
        rng: &mut R,
        via: TransportId,
        budget: Option<Budget>,
    ) {
        let Some(e) = self.transports.get_mut(via) else {
            return;
        };
        let was = e.usable();
        e.budget = budget;
        let usable = e.usable();
        self.out
            .push_back(Output::Event(Event::Budget { via, budget }));
        if was != usable {
            self.transports_changed(now, rng);
        } else {
            self.finish(now, rng);
        }
    }

    /// Every transport, in registration order.
    pub fn transports(&self) -> Vec<TransportView> {
        self.transports
            .iter()
            .map(|(id, e)| TransportView::of(id, e))
            .collect()
    }

    /// One transport.
    pub fn transport(&self, via: TransportId) -> Option<TransportView> {
        self.transports.get(via).map(|e| TransportView::of(via, e))
    }

    fn transports_changed<R: CryptoRng>(&mut self, now: Now, rng: &mut R) {
        self.refresh_routes(now, rng);
        self.finish(now, rng);
    }

    /// Every peer takes stock of the transports it may use.
    fn refresh_routes<R: CryptoRng>(&mut self, now: Now, rng: &mut R) {
        let keys: Vec<NodePublic> = self.peers.keys().copied().collect();
        for key in keys {
            on_peer!(self, now, rng, &key, p, ctx => p.transports_changed(&mut ctx));
        }
    }

    /// Replaces the exit this node offers; peers held by key hear it at their next handshake
    ///. An exit that carries IPv4 gives every peer held by key its address.
    pub fn set_exit<R: CryptoRng>(&mut self, now: Now, rng: &mut R, offer: Option<ExitServe>) {
        self.exits.set_own(offer);
        let keys: Vec<NodePublic> = self.peers.keys().copied().collect();
        for key in keys {
            self.assign_ipv4(key);
        }
        self.finish(now, rng);
    }

    /// Gives `peer` an IPv4 address if this node's exit carries IPv4 and the peer is held by key
    ///.
    fn assign_ipv4(&mut self, peer: NodePublic) {
        let keyed = self
            .peers
            .get(&peer)
            .is_some_and(|p| p.trust() == Trust::Key);
        if !keyed || !self.exits.serves_ipv4() {
            return;
        }
        if let Some(ipv4) = self.exits.assign_ipv4(peer) {
            self.out.push_back(Output::Event(Event::ExitClient {
                peer,
                ipv4: Some(ipv4),
            }));
        }
    }

    /// The IPv4 address this node's exit gave `peer`.
    pub fn exit_client_ipv4(&self, peer: &NodePublic) -> Option<Ipv4Addr> {
        self.exits.ipv4_of(peer)
    }

    /// Gives back the offers the host kept from [`Event::Remembered`]. Each one of
    /// a peer held by key that has no offer yet is remembered as if its link had gone down.
    pub fn remember<R: CryptoRng>(&mut self, now: Now, rng: &mut R, offers: &[(NodePublic, Site)]) {
        for (key, site) in offers {
            if let Some(p) = self.peers.get_mut(key)
                && p.remember_offer(site.clone())
            {
                self.touched.insert(*key);
            }
        }
        self.finish(now, rng);
    }

    /// Says whether an exit is in use and which site. While it is, the node keeps its exits'
    /// sessions alive: every peer whose offer names the site in use gets a
    /// keepalive each [`crate::route::NAT_KEEPALIVE`], is initiated toward when the use starts
    /// and again when its link goes down. When the use starts and no peer is known to offer the
    /// site, or when [`EXIT_SEARCH`] later the site still has no live exit, the node initiates
    /// once toward every peer held by key whose link is not up, so that their offers are known.
    /// All of it stops when the use ends.
    pub fn set_exit_use<R: CryptoRng>(&mut self, now: Now, rng: &mut R, using: Option<ExitUse>) {
        let started = self.using.is_none() && using.is_some();
        self.using = using;
        if self.using.is_none() {
            self.search = None;
        }
        if started {
            self.search = Some(now.instant + EXIT_SEARCH);
            let known = self
                .site_in_use()
                .is_some_and(|site| self.peers.values().any(|p| p.offers_site(&site)));
            if !known {
                self.reach_all(now, rng);
            }
        }
        let keys: Vec<NodePublic> = self.peers.keys().copied().collect();
        self.sync_held(now, rng, &keys);
        self.finish(now, rng);
    }

    /// Initiates toward every peer held by key whose link is not up.
    fn reach_all<R: CryptoRng>(&mut self, now: Now, rng: &mut R) {
        let keys: Vec<NodePublic> = self.peers.keys().copied().collect();
        for key in keys {
            on_peer!(self, now, rng, &key, p, ctx => p.reach(&mut ctx));
        }
    }

    /// Whether the site in use has a live exit.
    fn exit_live(&self) -> bool {
        self.site_in_use()
            .is_some_and(|site| self.exits.chosen(&site).is_some())
    }

    /// The site in use: the one the host picked, else the network's only site.
    fn site_in_use(&self) -> Option<Site> {
        self.exits.in_use(self.using.as_ref()?)
    }

    /// Brings the peers in `keys` in line with the use: a peer offering the site in use is kept
    /// connected, every other is not. Returns whether any peer changed.
    fn sync_held<R: CryptoRng>(&mut self, now: Now, rng: &mut R, keys: &[NodePublic]) -> bool {
        let site = self.site_in_use();
        let mut changed = false;
        for key in keys {
            let Some(p) = self.peers.get(key) else {
                continue;
            };
            let held = site.as_ref().is_some_and(|s| p.offers_site(s));
            if held != p.is_held() {
                changed = true;
                on_peer!(self, now, rng, key, p, ctx => p.set_held(&mut ctx, held));
            }
        }
        changed
    }

    /// The sites that some peer has offered, live or not, with the exit chosen for each that has
    /// one.
    pub fn sites(&self) -> Vec<SiteView> {
        self.exits.sites()
    }

    /// The network's only site: the one that every offer remembered names, live or not. A host
    /// that uses an exit without picking a site uses this one.
    pub fn only_site(&self) -> Option<Site> {
        self.exits.only_site()
    }

    /// The exit chosen for `site`.
    pub fn exit_for(&self, site: &Site) -> Option<NodePublic> {
        self.exits.chosen(site)
    }

    /// This node's address in `site`.
    pub fn site_addr(&self, site: &Site) -> Ipv6Addr {
        site_addr(&self.settings.network_id, site, self.keys.public())
    }

    /// Enables or disables member trust; disabling removes member peers.
    pub fn set_accept_members(&mut self, accept: bool) {
        self.settings.accept_members = accept;
        if !accept {
            let members: Vec<NodePublic> = self
                .peers
                .keys()
                .filter(|k| {
                    self.peers
                        .get(k)
                        .is_some_and(|p| p.trust() == Trust::Member)
                })
                .copied()
                .collect();
            for m in members {
                self.peers.remove(&m);
            }
            let peers = &self.peers;
            self.services.book.retain_accepted(|k| peers.contains(k));
            self.services.dirty = true;
        }
    }

    /// Adds or updates a key-trusted peer.
    pub fn add_peer(&mut self, config: PeerConfig, now: Instant) {
        if config.public == *self.keys.public() {
            return;
        }
        match self.peers.get_mut(&config.public) {
            Some(p) => p.set_trust(Trust::Key, config.psk),
            None => {
                let peer = Peer::new(
                    config.public,
                    Trust::Key,
                    config.psk,
                    &self.keys,
                    &self.settings,
                    now,
                );
                self.peers.insert(peer);
            }
        }
        self.assign_ipv4(config.public);
        self.flush_events();
    }

    fn ensure_peer(&mut self, peer: &NodePublic, now: Instant) -> Result<(), PeerError> {
        if self.peers.contains(peer) {
            return Ok(());
        }
        if !self.settings.accept_members || peer == self.keys.public() {
            return Err(PeerError::Unknown);
        }
        let p = Peer::new(
            *peer,
            Trust::Member,
            PairPsk::none(),
            &self.keys,
            &self.settings,
            now,
        );
        self.peers.insert(p);
        Ok(())
    }

    /// Removes a peer, every session and pending handshake with it, and its services.
    pub fn remove_peer(&mut self, peer: &NodePublic) {
        self.peers.remove(peer);
        if self.exits.release_ipv4(peer).is_some() {
            self.out.push_back(Output::Event(Event::ExitClient {
                peer: *peer,
                ipv4: None,
            }));
        }
        self.services.book.forget(peer);
        self.services.dirty = true;
        self.flush_events();
    }

    /// Replaces the candidates one source `group` knows for `peer`; an empty [`Found`] withdraws
    /// the group. A member peer is created if member trust is on. Returns whether the peer's
    /// candidates changed.
    pub fn set_candidates<R: CryptoRng>(
        &mut self,
        now: Now,
        rng: &mut R,
        peer: &NodePublic,
        group: Group,
        found: Found,
    ) -> Result<bool, PeerError> {
        if !self.peers.contains(peer) {
            if found.offered.is_empty() && found.spare.is_empty() {
                return Ok(false);
            }
            self.ensure_peer(peer, now.instant)?;
        }
        let changed =
            on_peer!(self, now, rng, peer, p, ctx => p.set_candidates(&mut ctx, group, found))
                .unwrap_or(false);
        self.finish(now, rng);
        Ok(changed)
    }

    /// Replaces the candidates this node shares: later handshakes carry them and peers with a
    /// session get a `cand` message when they differ (vv-05 §4.9).
    pub fn set_own_candidates<R: CryptoRng>(
        &mut self,
        now: Now,
        rng: &mut R,
        candidates: Vec<Candidate>,
    ) {
        self.own = candidates;
        let keys: Vec<NodePublic> = self.peers.keys().copied().collect();
        for key in keys {
            on_peer!(self, now, rng, &key, p, ctx => p.own_candidates_changed(&mut ctx));
        }
        self.finish(now, rng);
    }

    /// The platform marked the local network as metered or not (vv-05 §2.2).
    pub fn set_local_metered<R: CryptoRng>(&mut self, now: Now, rng: &mut R, metered: bool) {
        if self.local_metered == metered {
            return;
        }
        self.local_metered = metered;
        let keys: Vec<NodePublic> = self.peers.keys().copied().collect();
        for key in keys {
            on_peer!(self, now, rng, &key, p, ctx => p.local_metered_changed(&mut ctx));
        }
        self.finish(now, rng);
    }

    /// A settled local change of the address `families`: every probed route of those families
    /// is verified again.
    pub fn local_change<R: CryptoRng>(&mut self, now: Now, rng: &mut R, families: Families) {
        let keys: Vec<NodePublic> = self.peers.keys().copied().collect();
        for key in keys {
            on_peer!(self, now, rng, &key, p, ctx => p.local_change(&mut ctx, families));
        }
        self.finish(now, rng);
    }

    /// Sends an IPv6 packet of delivery class `class` to `peer`, queueing it and starting a
    /// handshake if needed.
    pub fn send<R: CryptoRng>(
        &mut self,
        now: Now,
        rng: &mut R,
        peer: &NodePublic,
        class: DeliveryClass,
        packet: &[u8],
    ) -> Result<(), PeerError> {
        if packet.len() > self.settings.mtu {
            return Err(PeerError::TooLarge);
        }
        self.ensure_peer(peer, now.instant)?;
        let r = on_peer!(self, now, rng, peer, p, ctx => p.send(&mut ctx, class, packet))
            .unwrap_or(Err(PeerError::Unknown));
        self.finish(now, rng);
        r
    }

    /// Processes one datagram that arrived on `path`.
    pub fn handle_datagram<R: CryptoRng>(
        &mut self,
        now: Now,
        rng: &mut R,
        path: Path,
        data: &[u8],
    ) {
        let level = self.transports.charge_received(path.via, data.len());
        report_level(&self.transports, &mut self.out, path.via, level);
        let Some(framing) = self.transports.framing(path.via) else {
            return;
        };
        self.cookies.rotate(rng, now.instant);
        if let Some(&first) = data.first() {
            let whole = framing == Framing::Whole;
            match first {
                message::TYPE_MSG1_FRAG0..=message::TYPE_MSG2_FRAG1 if !whole => {
                    self.handle_fragment(now, rng, path, data)
                }
                message::TYPE_COOKIE if !whole => self.handle_cookie_reply(now, rng, data),
                message::TYPE_DATA => self.handle_frame(now, rng, path, data),
                message::TYPE_MSG1 if whole => {
                    self.load.record(now.instant);
                    self.handle_message1(now, rng, path, &data[1..]);
                }
                message::TYPE_MSG2 if whole => {
                    self.load.record(now.instant);
                    self.handle_message2(now, rng, path, &data[1..]);
                }
                _ => {}
            }
        }
        self.finish(now, rng);
    }

    fn under_load(&self, now: Instant) -> bool {
        self.reassembly.len() * 2 > reassembly::MAX_ENTRIES
            || self.peers.indices.unconfirmed_len() >= UNCONFIRMED_LIMIT
            || self.load.rate(now) >= self.settings.load_threshold
    }

    fn handle_fragment<R: CryptoRng>(&mut self, now: Now, rng: &mut R, path: Path, data: &[u8]) {
        if data.len() > MAX_FRAGMENT {
            return;
        }
        let Ok(fragment) = message::parse_fragment(data) else {
            return;
        };
        if !fragment.mac1_valid(self.keys.mac1_key_in()) {
            return;
        }
        self.load.record(now.instant);
        if self.under_load(now.instant) {
            let Some(source) = source_bytes(&path) else {
                return;
            };
            if !self.cookies.mac2_valid(&fragment, &source) {
                let mut nonce = [0u8; 24];
                rng.fill_bytes(&mut nonce);
                let cookie = self.cookies.cookie(&source);
                let reply = message::build_cookie_reply(
                    fragment.sender_index,
                    &nonce,
                    self.keys.cookie_key_own(),
                    &cookie,
                    &fragment.mac1,
                );
                queue_transmit(
                    &mut self.transports,
                    &mut self.out,
                    path,
                    reply.to_vec(),
                    true,
                );
                return;
            }
        }
        self.reassembly.expire(now.instant);
        let Some(whole) = self.reassembly.insert(
            now.instant,
            path,
            fragment.message_number,
            fragment.sender_index,
            fragment.index,
            fragment.data,
        ) else {
            return;
        };
        match fragment.message_number {
            MessageNumber::One => self.handle_message1(now, rng, path, &whole),
            MessageNumber::Two => self.handle_message2(now, rng, path, &whole),
        }
    }

    fn handle_message1<R: CryptoRng>(&mut self, now: Now, rng: &mut R, path: Path, message: &[u8]) {
        let Ok(responder) = Responder::read(&self.keys, message) else {
            return;
        };
        let initiator = *responder.initiator();
        if initiator == *self.keys.public() {
            return;
        }
        if self.ensure_peer(&initiator, now.instant).is_err() {
            return;
        }
        on_peer!(self, now, rng, &initiator, p, ctx => p.on_message1(&mut ctx, path, message, responder));
        self.peers.drop_idle_member(&initiator);
        let evicted = self.peers.enforce_unconfirmed_limit();
        self.touched.extend(evicted);
    }

    fn handle_message2<R: CryptoRng>(&mut self, now: Now, rng: &mut R, path: Path, message: &[u8]) {
        let Ok(m) = message::parse_message2(message) else {
            return;
        };
        let Some(peer) = self.peers.by_index(m.receiver_index) else {
            return;
        };
        if !message::verify_mac1(message, self.keys.mac1_key_in()) {
            return;
        }
        on_peer!(self, now, rng, &peer, p, ctx => p.on_message2(&mut ctx, path, message));
    }

    fn handle_cookie_reply<R: CryptoRng>(&mut self, now: Now, rng: &mut R, data: &[u8]) {
        let Ok(reply) = message::parse_cookie_reply(data) else {
            return;
        };
        let Some(peer) = self.peers.by_index(reply.receiver_index) else {
            return;
        };
        on_peer!(self, now, rng, &peer, p, ctx => p.on_cookie(&mut ctx, &reply));
    }

    fn handle_frame<R: CryptoRng>(&mut self, now: Now, rng: &mut R, path: Path, data: &[u8]) {
        let Ok(header) = crate::plane::frame::parse_header(data) else {
            return;
        };
        let Some(peer) = self.peers.by_index(header.receiver_index) else {
            return;
        };
        let delivered =
            on_peer!(self, now, rng, &peer, p, ctx => p.on_frame(&mut ctx, path, &header, data));
        match delivered {
            Some(Delivered::Packet(packet)) => {
                self.out
                    .push_back(Output::Event(Event::Packet { peer, packet }));
            }
            Some(Delivered::Service(control)) => {
                let peers = &self.peers;
                self.services
                    .book
                    .handle_control(now.instant, &peer, &control, |k| {
                        peers.get(k).map_or(Duration::from_secs(1), Peer::rto)
                    });
                self.services.dirty = true;
            }
            Some(Delivered::Nothing) | None => {}
        }
    }

    /// Runs every timer that is due at `now`.
    pub fn handle_timeout<R: CryptoRng>(&mut self, now: Now, rng: &mut R) {
        self.reassembly.expire(now.instant);
        self.cookies.rotate(rng, now.instant);
        if self.search.is_some_and(|t| t <= now.instant) {
            self.search = None;
            if !self.exit_live() {
                self.reach_all(now, rng);
            }
        }
        let keys: Vec<NodePublic> = self.peers.keys().copied().collect();
        for key in keys {
            on_peer!(self, now, rng, &key, p, ctx => p.handle_timeout(&mut ctx));
        }
        if self
            .services
            .book
            .poll_timeout()
            .is_some_and(|t| t <= now.instant)
        {
            let peers = &self.peers;
            self.services.book.handle_timeout(now.instant, |k| {
                peers.get(k).map_or(Duration::from_secs(1), Peer::rto)
            });
            self.services.dirty = true;
        }
        let idle: Vec<TransportId> = self
            .transports
            .iter()
            .filter(|(_, e)| {
                e.ready
                    && e.medium.on_demand()
                    && e.last_use
                        .is_some_and(|t| now.instant.saturating_duration_since(t) >= DEMAND_IDLE)
            })
            .map(|(id, _)| id)
            .collect();
        for via in idle {
            if let Some(e) = self.transports.get_mut(via) {
                e.demanded = false;
                e.last_use = None;
            }
            self.out.push_back(Output::Demand { via, on: false });
        }
        self.finish(now, rng);
    }

    /// Takes the next pending output.
    pub fn poll_output(&mut self) -> Option<Output> {
        self.out.pop_front()
    }

    /// The earliest time at which [`Node::handle_timeout`] has work.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let demand = self
            .transports
            .iter()
            .filter(|(_, e)| e.ready && e.medium.on_demand())
            .filter_map(|(_, e)| e.last_use.map(|t| t + DEMAND_IDLE));
        self.peers
            .values()
            .filter_map(|p| p.poll_timeout(&self.settings.routes))
            .chain(self.reassembly.next_expiry())
            .chain(self.services.book.poll_timeout())
            .chain(demand)
            .chain(self.search)
            .min()
    }

    /// Hands on what the entry point left: service messages to send, creations and removals of
    /// peers, and the differences between each touched peer and what was reported of it.
    fn finish<R: CryptoRng>(&mut self, now: Now, rng: &mut R) {
        loop {
            loop {
                while let Some(ServiceAction::Send { peer, control }) =
                    self.services.book.poll_action()
                {
                    on_peer!(self, now, rng, &peer, p, ctx => p.send_control(&mut ctx, &control));
                }
                if !self.transports.take_ran_out() {
                    break;
                }
                self.refresh_routes(now, rng);
            }
            self.flush_events();
            let touched = std::mem::take(&mut self.touched);
            for key in &touched {
                let Some(p) = self.peers.get_mut(key) else {
                    continue;
                };
                let (state, route) = p.take_changes();
                if let Some(state) = state {
                    self.out
                        .push_back(Output::Event(Event::Peer { peer: *key, state }));
                }
                if let Some(route) = route {
                    self.out
                        .push_back(Output::Event(Event::Active { peer: *key, route }));
                }
                self.exits.observe(*key, p.exit_peer());
            }
            let mut sites_changed = false;
            for change in self.exits.update() {
                sites_changed |= matches!(change, Change::Sites { .. });
                self.out.push_back(Output::Event(match change {
                    Change::Sites { sites } => Event::Sites { sites },
                    Change::Remembered { offers } => Event::Remembered { offers },
                    Change::Exit { site, via, ipv4 } => Event::Exit { site, via, ipv4 },
                    Change::Collision { first, second } => Event::ExitCollision { first, second },
                }));
            }
            if self.using.is_none() {
                break;
            }
            let keys: Vec<NodePublic> = if sites_changed {
                self.peers.keys().copied().collect()
            } else {
                touched.into_iter().collect()
            };
            if !self.sync_held(now, rng, &keys) {
                break;
            }
        }
        if std::mem::take(&mut self.services.dirty) {
            self.out.push_back(Output::Event(Event::Services));
        }
    }

    fn flush_events(&mut self) {
        for e in std::mem::take(&mut self.peers.events) {
            if let Event::Removed { peer } = &e {
                self.exits.observe(*peer, None);
            }
            self.out.push_back(Output::Event(e));
        }
    }

    /// The peer whose overlay address is `addr` (vv-06 §3.1).
    pub fn peer_for_address(&self, addr: &Ipv6Addr) -> Option<NodePublic> {
        let octets = addr.octets();
        let iid: [u8; 8] = octets[8..].try_into().ok()?;
        if iid == self.own_addrs.iid || crate::addr::is_reserved_iid(&iid) {
            return None;
        }
        self.peers
            .by_iid(&iid)
            .filter(|p| p.addrs().contains(addr))
            .map(|p| *p.key())
    }

    /// The peers held, configured and member.
    pub fn peers(&self) -> impl Iterator<Item = &NodePublic> {
        self.peers.keys()
    }

    /// A snapshot of one peer.
    pub fn peer_view(&self, peer: &NodePublic) -> Option<PeerView> {
        self.peers.get(peer).map(|p| p.view(&self.transports))
    }

    /// Whether a first handshake with `peer` would go out only on reporting transports: it has no
    /// link, no direct address to try and is reachable on one.
    pub fn awaits_reporting_path(&self, peer: &NodePublic) -> bool {
        let idle = self
            .peers
            .get(peer)
            .is_none_or(|p| !p.has_link() && !p.has_targets());
        idle && self.transports.reporting(peer).next().is_some()
    }

    /// What a datagram this node sent carries, by its type byte and, for a frame, its plaintext.
    #[cfg(feature = "sim")]
    pub fn describe(&self, data: &[u8]) -> &'static str {
        match data.first() {
            Some(&(message::TYPE_MSG1 | message::TYPE_MSG1_FRAG0 | message::TYPE_MSG1_FRAG1)) => {
                "msg1"
            }
            Some(&(message::TYPE_MSG2 | message::TYPE_MSG2_FRAG0 | message::TYPE_MSG2_FRAG1)) => {
                "msg2"
            }
            Some(&message::TYPE_COOKIE) => "cookie",
            Some(&message::TYPE_DATA) => crate::plane::frame::parse_header(data)
                .ok()
                .and_then(|h| self.peers.values().find_map(|p| p.describe_sent(&h, data)))
                .unwrap_or("frame"),
            _ => "other",
        }
    }

    /// The sizes of the node's tables.
    pub fn stats(&self) -> Stats {
        Stats {
            peers: self.peers.len(),
            indices: self.peers.indices.len(),
            reassembly: self.reassembly.len(),
        }
    }

    /// Replaces the services this node announces (vve-14).
    pub fn set_services<R: CryptoRng>(&mut self, now: Now, rng: &mut R, want: Vec<Service>) {
        let stale: Vec<String> = self
            .services
            .book
            .own()
            .iter()
            .filter(|s| !want.contains(s))
            .map(|s| s.name().to_owned())
            .collect();
        let peers = &self.peers;
        let rto = |k: &NodePublic| peers.get(k).map_or(Duration::from_secs(1), Peer::rto);
        for name in stale {
            self.services.book.withdraw(now.instant, &name, rto);
        }
        for s in want {
            let _ = self.services.book.announce(now.instant, s, rto);
        }
        self.services.dirty = true;
        self.finish(now, rng);
    }

    /// The services this node announces.
    pub fn services(&self) -> &[Service] {
        self.services.book.own()
    }

    /// The providers of service `name`, of any transport protocol or of `proto` only.
    pub fn providers(&self, name: &str, proto: Option<Proto>) -> Vec<Provider> {
        let active = |k: &NodePublic| self.peers.get(k).and_then(Peer::route_active);
        match proto {
            None => self.services.book.providers(name, active),
            Some(p) => self.services.book.providers_for(name, p, active),
        }
    }

    /// The service names that this node or any peer announces.
    pub fn service_names(&self) -> Vec<String> {
        let mut names: BTreeSet<String> = self
            .services
            .book
            .own()
            .iter()
            .map(|s| s.name().to_owned())
            .collect();
        for peer in self.peers.keys() {
            if let Some((list, _)) = self.services.book.peer_services(peer) {
                names.extend(list.iter().map(|s| s.name().to_owned()));
            }
        }
        names.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::peers::{MEMBER_CACHE, MEMBER_SLACK};
    use super::*;
    use crate::handshake::SessionKeys;
    use crate::keys::PairPsk;
    use crate::route::{Band, Latency, RouteClass};
    use crate::session::{REJECT_AFTER_TIME, Session};
    use crate::transport::Reachability;

    struct Fixed(u64);

    impl rand_core::TryRng for Fixed {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            Ok((self.0 >> 32) as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from(self.try_next_u32()?) << 32 | u64::from(self.try_next_u32()?))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for c in dst.chunks_mut(4) {
                let v = self.try_next_u32()?.to_le_bytes();
                c.copy_from_slice(&v[..c.len()]);
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for Fixed {}

    struct Udp;

    impl Medium for Udp {
        fn name(&self) -> &str {
            "udp"
        }
        fn class(&self) -> RouteClass {
            RouteClass {
                band: Band::High,
                latency: Latency::High,
                metered: false,
            }
        }
        fn reaches(&self, to: &Remote, _: bool) -> bool {
            matches!(to, Remote::Addr(_))
        }
        fn reachability(&self) -> Reachability {
            Reachability::Probe
        }
        fn framing(&self) -> Framing {
            Framing::Fragmented { max: 1200 }
        }
        fn on_demand(&self) -> bool {
            false
        }
    }

    struct Turn;

    impl Medium for Turn {
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
            Framing::Fragmented { max: 1200 }
        }
        fn on_demand(&self) -> bool {
            true
        }
    }

    struct Switch;

    impl Medium for Switch {
        fn name(&self) -> &str {
            "switch"
        }
        fn class(&self) -> RouteClass {
            RouteClass {
                band: Band::Low,
                latency: Latency::High,
                metered: true,
            }
        }
        fn reaches(&self, to: &Remote, _: bool) -> bool {
            matches!(to, Remote::Peer(_))
        }
        fn reachability(&self) -> Reachability {
            Reachability::Reported
        }
        fn framing(&self) -> Framing {
            Framing::Whole
        }
        fn on_demand(&self) -> bool {
            false
        }
    }

    fn node() -> (Node, Fixed) {
        let mut rng = Fixed(1);
        let mut cfg = Config::new(
            NodeSecret::generate(&mut rng),
            NetworkSecret::from_bytes([3; 32]),
        );
        cfg.accept_members = true;
        let n = Node::new(cfg, Now::new(Instant::ZERO, 0), &mut rng);
        (n, rng)
    }

    fn member_at(n: &mut Node, key: NodePublic, at: Instant) {
        let p = Peer::new(
            key,
            Trust::Member,
            PairPsk::none(),
            &n.keys,
            &n.settings,
            at,
        );
        n.peers.insert(p);
    }

    fn member(n: &mut Node, k: u16) -> NodePublic {
        let mut b = [0u8; 32];
        b[..2].copy_from_slice(&k.to_le_bytes());
        let key = NodePublic::from_bytes(b);
        member_at(n, key, Instant::ZERO);
        key
    }

    fn unconfirmed_session(index: u32) -> Session {
        let keys = SessionKeys::from_noise_keys([1; 32], [2; 32]);
        Session::new(&keys, false, index, 9, Instant::ZERO)
    }

    fn install(n: &mut Node, key: &NodePublic, index: u32) {
        let (p, idx) = n.peers.split(key).unwrap();
        p.install_unconfirmed(idx, unconfirmed_session(index));
        n.peers.enforce_unconfirmed_limit();
    }

    fn cand(make: fn(SocketAddr) -> Candidate, addr: &str) -> Candidate {
        make(addr.parse().unwrap())
    }

    fn offered(list: Vec<Candidate>) -> Found {
        Found {
            offered: list,
            spare: Vec::new(),
        }
    }

    fn path(via: TransportId, addr: &str) -> Path {
        Path {
            via,
            to: Remote::Addr(addr.parse().unwrap()),
        }
    }

    fn specs_of(
        n: &Node,
        key: &NodePublic,
        metered: bool,
        learned: &[Path],
    ) -> Vec<(Path, &'static str, bool)> {
        n.peers
            .get(key)
            .unwrap()
            .specs(&n.transports, metered, learned)
            .into_iter()
            .map(|s| (s.path, s.label, s.class.metered))
            .collect()
    }

    #[test]
    fn specs_pair_found_then_shared_candidates_with_every_ready_probed_transport_once() {
        let (mut n, mut rng) = node();
        let udp = n.add_transport(Arc::new(Udp));
        let key = member(&mut n, 1);
        let now = Now::new(Instant::ZERO, 0);
        let g = Group {
            source: "static",
            name: String::new(),
        };
        n.set_candidates(
            now,
            &mut rng,
            &key,
            g,
            offered(vec![
                cand(Candidate::lan, "192.168.1.5:1"),
                cand(Candidate::punch, "203.0.113.9:2"),
            ]),
        )
        .unwrap();
        n.peers.get_mut(&key).unwrap().share(&[
            cand(Candidate::punch, "203.0.113.9:2"),
            cand(Candidate::punch, "203.0.113.9:3"),
        ]);
        assert_eq!(
            specs_of(&n, &key, false, &[]),
            [
                (path(udp, "192.168.1.5:1"), "lan", false),
                (path(udp, "203.0.113.9:2"), "punch", false),
                (path(udp, "203.0.113.9:3"), "punch", false),
            ]
        );
    }

    #[test]
    fn specs_list_the_local_sources_in_the_order_they_found_the_addresses_then_the_peers_then_learned()
     {
        let (mut n, mut rng) = node();
        let udp = n.add_transport(Arc::new(Udp));
        let key = member(&mut n, 1);
        let now = Now::new(Instant::ZERO, 0);
        let group = |source, name: &str| Group {
            source,
            name: name.to_owned(),
        };
        n.set_candidates(
            now,
            &mut rng,
            &key,
            group("static", ""),
            offered(vec![
                cand(Candidate::static_, "198.51.100.1:1"),
                cand(Candidate::punch, "203.0.113.9:7"),
            ]),
        )
        .unwrap();
        n.set_candidates(
            now,
            &mut rng,
            &key,
            group("mdns", "a"),
            offered(vec![
                cand(Candidate::lan, "192.168.1.9:1"),
                cand(Candidate::lan, "192.168.1.5:1"),
            ]),
        )
        .unwrap();
        n.peers.get_mut(&key).unwrap().share(&[
            cand(Candidate::punch, "203.0.113.9:30"),
            cand(Candidate::punch, "203.0.113.9:20"),
            cand(Candidate::lan, "192.168.1.5:1"),
        ]);
        let learned = [path(udp, "203.0.113.77:9")];
        let order: Vec<Path> = specs_of(&n, &key, false, &learned)
            .into_iter()
            .map(|s| s.0)
            .collect();
        assert_eq!(
            order,
            [
                path(udp, "198.51.100.1:1"),
                path(udp, "203.0.113.9:7"),
                path(udp, "192.168.1.9:1"),
                path(udp, "192.168.1.5:1"),
                path(udp, "203.0.113.9:30"),
                path(udp, "203.0.113.9:20"),
                path(udp, "203.0.113.77:9"),
            ]
        );
    }

    #[test]
    fn specs_use_an_on_demand_transport_only_while_it_is_ready() {
        let (mut n, mut rng) = node();
        let udp = n.add_transport(Arc::new(Udp));
        let turn = n.add_transport(Arc::new(Turn));
        let key = member(&mut n, 1);
        n.peers.get_mut(&key).unwrap().share(&[
            cand(Candidate::punch, "203.0.113.9:2"),
            cand(Candidate::lan, "10.0.0.7:5"),
        ]);
        assert_eq!(
            specs_of(&n, &key, false, &[]),
            [(path(udp, "203.0.113.9:2"), "punch", false)]
        );
        n.set_ready(Now::new(Instant::ZERO, 0), &mut rng, turn, true);
        assert_eq!(
            specs_of(&n, &key, false, &[]),
            [
                (path(udp, "203.0.113.9:2"), "punch", false),
                (path(turn, "203.0.113.9:2"), "punch", true),
            ],
            "a TURN route is metered and does not reach the LAN address"
        );
    }

    #[test]
    fn an_exhausted_budget_makes_a_transport_unusable_until_a_fresh_one_is_set() {
        use crate::meter::BudgetSource;
        let (mut n, mut rng) = node();
        let now = Now::new(Instant::ZERO, 0);
        let udp = n.add_transport(Arc::new(Udp));
        let sw = n.add_transport(Arc::new(Switch));
        let key = member(&mut n, 1);
        n.peers
            .get_mut(&key)
            .unwrap()
            .share(&[cand(Candidate::punch, "203.0.113.9:2")]);
        n.set_reachable(now, &mut rng, sw, &key, true);
        let spent = Budget {
            remaining: 0,
            ..Budget::new(10, BudgetSource::Reported, false)
        };
        n.set_budget(now, &mut rng, udp, Some(spent));
        assert!(
            specs_of(&n, &key, false, &[])
                .iter()
                .all(|s| s.0.via != udp),
            "no route on the exhausted transport"
        );
        assert_eq!(n.transports.reporting(&key).count(), 1);
        n.set_budget(now, &mut rng, sw, Some(spent));
        assert_eq!(n.transports.reporting(&key).count(), 0);
        let views = n.transports();
        assert_eq!(
            views
                .iter()
                .map(|v| (v.ready, v.usable))
                .collect::<Vec<_>>(),
            [(true, false), (true, false)]
        );
        n.set_budget(
            now,
            &mut rng,
            sw,
            Some(Budget::new(10, BudgetSource::Reported, false)),
        );
        assert_eq!(n.transports.reporting(&key).count(), 1);
        assert!(n.transports()[1].usable);
        let events: Vec<_> = std::iter::from_fn(|| n.poll_output())
            .filter_map(|o| match o {
                Output::Event(Event::Budget { via, budget }) => {
                    Some((via, budget.map(|b| b.level())))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            events,
            [
                (udp, Some(Level::Exhausted)),
                (sw, Some(Level::Exhausted)),
                (sw, Some(Level::Plenty)),
            ]
        );
        n.set_budget(now, &mut rng, sw, None);
        assert!(matches!(
            n.poll_output(),
            Some(Output::Event(Event::Budget { budget: None, .. }))
        ));
    }

    #[test]
    fn a_datagram_that_exhausts_a_received_budget_makes_the_transport_unusable() {
        use crate::meter::BudgetSource;
        let (mut n, mut rng) = node();
        let now = Now::new(Instant::ZERO, 0);
        let turn = n.add_transport(Arc::new(Turn));
        let e = n.transports.get(turn).unwrap();
        assert!(!e.ready && !e.usable() && !e.exhausted());
        n.set_ready(now, &mut rng, turn, true);
        n.set_budget(
            now,
            &mut rng,
            turn,
            Some(Budget::new(100, BudgetSource::Relay, true)),
        );
        assert!(n.transports.get(turn).unwrap().usable());
        n.handle_datagram(now, &mut rng, path(turn, "203.0.113.9:2"), &[0xff; 100]);
        let t = n.transports()[0].clone();
        assert_eq!((t.meter.received, t.usable), (100, false));
        assert_eq!(t.budget.unwrap().level(), Level::Exhausted);
    }

    #[test]
    fn every_datagram_is_charged_before_it_is_read_and_a_budget_charges_received_bytes_if_it_says_so()
     {
        use crate::meter::BudgetSource;
        let (mut n, mut rng) = node();
        let now = Now::new(Instant::ZERO, 0);
        let udp = n.add_transport(Arc::new(Udp));
        let sw = n.add_transport(Arc::new(Switch));
        n.set_budget(
            now,
            &mut rng,
            udp,
            Some(Budget::new(1000, BudgetSource::Relay, true)),
        );
        n.set_budget(
            now,
            &mut rng,
            sw,
            Some(Budget::new(1000, BudgetSource::Reported, false)),
        );
        let peer = member(&mut n, 1);
        n.handle_datagram(now, &mut rng, path(udp, "203.0.113.9:2"), &[0xff; 40]);
        let from = Path {
            via: sw,
            to: Remote::Peer(peer),
        };
        n.handle_datagram(now, &mut rng, from, &[0xff; 30]);
        let v = n.transports();
        assert_eq!(v[0].meter.received, 40);
        assert_eq!(v[0].budget.unwrap().remaining, 960);
        assert_eq!(v[1].meter.received, 30);
        assert_eq!(v[1].budget.unwrap().remaining, 1000);
    }

    #[test]
    fn a_route_class_comes_from_the_transport_and_the_source_never_from_the_address() {
        use crate::route::Latency::{High, Low};
        let (mut n, mut rng) = node();
        let udp = n.add_transport(Arc::new(Udp));
        let turn = n.add_transport(Arc::new(Turn));
        n.set_ready(Now::new(Instant::ZERO, 0), &mut rng, turn, true);
        let key = member(&mut n, 1);
        let g = Group {
            source: "static",
            name: String::new(),
        };
        n.set_candidates(
            Now::new(Instant::ZERO, 0),
            &mut rng,
            &key,
            g,
            offered(vec![
                cand(Candidate::lan, "[2001:db8::5]:1"),
                cand(Candidate::lan, "192.168.1.5:1"),
                cand(Candidate::same_host, "127.0.0.1:1"),
                cand(Candidate::static_, "10.0.0.7:1"),
                cand(Candidate::static_, "203.0.113.9:1"),
            ]),
        )
        .unwrap();
        n.peers
            .get_mut(&key)
            .unwrap()
            .share(&[cand(Candidate::punch, "10.0.0.8:2")]);
        let learned = [path(udp, "192.168.1.77:9")];
        let latency: Vec<_> = n
            .peers
            .get(&key)
            .unwrap()
            .specs(&n.transports, false, &learned)
            .into_iter()
            .map(|s| (s.path, s.label, s.class.latency, s.class.metered))
            .collect();
        assert_eq!(
            latency,
            [
                (path(udp, "[2001:db8::5]:1"), "lan", Low, false),
                (path(udp, "192.168.1.5:1"), "lan", Low, false),
                (path(udp, "127.0.0.1:1"), "local", Low, false),
                (path(udp, "10.0.0.7:1"), "static", High, false),
                (path(turn, "10.0.0.7:1"), "static", High, true),
                (path(udp, "203.0.113.9:1"), "static", High, false),
                (path(turn, "203.0.113.9:1"), "static", High, true),
                (path(udp, "10.0.0.8:2"), "punch", High, false),
                (path(turn, "10.0.0.8:2"), "punch", High, true),
                (path(udp, "192.168.1.77:9"), "learned", High, false),
            ],
            "a lan candidate is low latency on UDP and has no TURN route, whatever its address"
        );
    }

    #[test]
    fn specs_are_metered_when_the_candidate_or_the_local_network_is() {
        let (mut n, _) = node();
        let udp = n.add_transport(Arc::new(Udp));
        let key = member(&mut n, 1);
        n.peers.get_mut(&key).unwrap().share(&[
            cand(Candidate::punch, "203.0.113.9:2"),
            cand(Candidate::relay, "198.51.100.4:7"),
        ]);
        assert_eq!(
            specs_of(&n, &key, false, &[]),
            [
                (path(udp, "203.0.113.9:2"), "punch", false),
                (path(udp, "198.51.100.4:7"), "relay", true),
            ]
        );
        assert!(specs_of(&n, &key, true, &[]).iter().all(|s| s.2));
    }

    #[test]
    fn specs_list_learned_paths_unless_a_candidate_covers_them_or_the_transport_no_longer_reaches()
    {
        let (mut n, mut rng) = node();
        let udp = n.add_transport(Arc::new(Udp));
        let turn = n.add_transport(Arc::new(Turn));
        let key = member(&mut n, 1);
        n.peers
            .get_mut(&key)
            .unwrap()
            .share(&[cand(Candidate::punch, "203.0.113.9:2")]);
        let learned = [
            path(udp, "203.0.113.9:2"),
            path(udp, "203.0.113.77:9"),
            path(turn, "203.0.113.78:9"),
        ];
        assert_eq!(
            specs_of(&n, &key, false, &learned),
            [
                (path(udp, "203.0.113.9:2"), "punch", false),
                (path(udp, "203.0.113.77:9"), "learned", false),
            ],
            "the TURN transport is not ready"
        );
        n.set_ready(Now::new(Instant::ZERO, 0), &mut rng, turn, true);
        let all = specs_of(&n, &key, false, &learned);
        assert_eq!(all.len(), 4);
        assert_eq!(all[3], (path(turn, "203.0.113.78:9"), "learned", true));
        n.remove_transport(Now::new(Instant::ZERO, 0), &mut rng, udp);
        assert_eq!(
            specs_of(&n, &key, false, &learned),
            [
                (path(turn, "203.0.113.9:2"), "punch", true),
                (path(turn, "203.0.113.78:9"), "learned", true),
            ]
        );
    }

    #[test]
    fn specs_have_a_reported_route_while_the_peer_is_reachable_on_the_switch() {
        let (mut n, mut rng) = node();
        let now = Now::new(Instant::ZERO, 0);
        let sw = n.add_transport(Arc::new(Switch));
        let key = member(&mut n, 1);
        assert!(specs_of(&n, &key, false, &[]).is_empty());
        n.set_reachable(now, &mut rng, sw, &key, true);
        let to = Path {
            via: sw,
            to: Remote::Peer(key),
        };
        assert_eq!(specs_of(&n, &key, false, &[]), [(to, "switch", true)]);
        n.set_reachable(now, &mut rng, sw, &key, false);
        assert!(specs_of(&n, &key, false, &[]).is_empty());
    }

    #[test]
    fn idle_members_are_evicted_but_peers_with_sessions_are_kept() {
        let (mut n, mut rng) = node();
        let keep = NodePublic::from_bytes([1; 32]);
        member_at(&mut n, keep, Instant::ZERO);
        install(&mut n, &keep, 5);
        for i in 0..(MEMBER_CACHE as u64 + 300) {
            let mut k = [0u8; 32];
            rand_core::Rng::fill_bytes(&mut rng, &mut k);
            k[0] = (i & 0xff) as u8;
            k[1] = (i >> 8) as u8;
            member_at(
                &mut n,
                NodePublic::from_bytes(k),
                Instant::from_millis(i + 1),
            );
        }
        assert!(
            n.peers.len() <= MEMBER_CACHE + MEMBER_SLACK,
            "{}",
            n.peers.len()
        );
        assert!(
            n.peers.contains(&keep),
            "the entry with an unconfirmed session stays"
        );
        let removed = n
            .peers
            .events
            .iter()
            .filter(|e| matches!(e, Event::Removed { .. }))
            .count();
        assert!(removed > 0);
    }

    #[test]
    fn keepalive_timeout_is_clamped_to_the_default() {
        let mut rng = Fixed(1);
        let mut cfg = Config::new(
            NodeSecret::generate(&mut rng),
            NetworkSecret::from_bytes([3; 32]),
        );
        cfg.keepalive_timeout = Duration::from_secs(60);
        let n = Node::new(cfg, Now::new(Instant::ZERO, 0), &mut rng);
        assert_eq!(n.settings.keepalive_timeout, KEEPALIVE_TIMEOUT);
        let mut cfg = Config::new(
            NodeSecret::generate(&mut rng),
            NetworkSecret::from_bytes([3; 32]),
        );
        cfg.keepalive_timeout = Duration::from_secs(4);
        let n = Node::new(cfg, Now::new(Instant::ZERO, 0), &mut rng);
        assert_eq!(n.settings.keepalive_timeout, Duration::from_secs(4));
        assert_eq!(n.settings.routes.keepalive_timeout, Duration::from_secs(4));
    }

    #[test]
    fn unconfirmed_entries_are_bounded_oldest_first_and_count_as_load() {
        let (mut n, _) = node();
        let limit = UNCONFIRMED_LIMIT as u16;
        let keys: Vec<NodePublic> = (0..limit + 3).map(|k| member(&mut n, k)).collect();
        for (i, key) in keys.iter().take(UNCONFIRMED_LIMIT - 1).enumerate() {
            install(&mut n, key, i as u32 + 1);
        }
        assert!(!n.under_load(Instant::ZERO));
        let last = UNCONFIRMED_LIMIT - 1;
        install(&mut n, &keys[last], last as u32 + 1);
        assert_eq!(n.peers.indices.unconfirmed_len(), UNCONFIRMED_LIMIT);
        assert!(n.under_load(Instant::ZERO), "the bound is reached");

        install(&mut n, &keys[last + 1], last as u32 + 2);
        assert_eq!(n.peers.indices.unconfirmed_len(), UNCONFIRMED_LIMIT);
        assert!(
            !n.peers.get(&keys[0]).unwrap().has_unconfirmed(),
            "the oldest was evicted"
        );
        assert!(n.peers.by_index(1).is_none());
        assert!(n.peers.get(&keys[1]).unwrap().has_unconfirmed());
        assert!(n.under_load(Instant::ZERO));

        install(&mut n, &keys[1], 5000);
        assert_eq!(
            n.peers.indices.unconfirmed_len(),
            UNCONFIRMED_LIMIT,
            "replacing adds none"
        );
        assert!(n.peers.get(&keys[2]).unwrap().has_unconfirmed());

        n.peers.remove(&keys[3]);
        assert_eq!(n.peers.indices.unconfirmed_len(), UNCONFIRMED_LIMIT - 1);
        assert!(!n.under_load(Instant::ZERO));
    }

    #[test]
    fn confirming_or_expiring_frees_an_unconfirmed_entry() {
        let (mut n, mut rng) = node();
        let udp = n.add_transport(Arc::new(Udp));
        let a = member(&mut n, 1);
        let b = member(&mut n, 2);
        install(&mut n, &a, 11);
        install(&mut n, &b, 12);
        assert_eq!(n.peers.indices.unconfirmed_len(), 2);

        let keys = SessionKeys::from_noise_keys([1; 32], [2; 32]);
        let mut initiator_side = Session::new(&keys, true, 9, 11, Instant::ZERO);
        let (_, frame) = initiator_side.seal(&[]);
        let path = Path {
            via: udp,
            to: Remote::Addr("192.0.2.1:1".parse().unwrap()),
        };
        n.handle_datagram(Now::new(Instant::ZERO, 0), &mut rng, path, &frame);
        let pa = n.peers.get(&a).unwrap();
        assert!(pa.has_session() && !pa.has_unconfirmed());
        assert_eq!(n.peers.indices.unconfirmed_len(), 1);

        let later = Instant::ZERO + REJECT_AFTER_TIME;
        n.handle_timeout(Now::new(later, 0), &mut rng);
        assert_eq!(n.peers.indices.unconfirmed_len(), 0);
    }

    #[test]
    fn key_trusted_peers_are_never_evicted() {
        let (mut n, mut rng) = node();
        let key = NodePublic::from_bytes([9; 32]);
        n.add_peer(PeerConfig::new(key), Instant::ZERO);
        for i in 0..(MEMBER_CACHE as u64 + 50) {
            let mut k = [0u8; 32];
            rand_core::Rng::fill_bytes(&mut rng, &mut k);
            member_at(&mut n, NodePublic::from_bytes(k), Instant::from_millis(i));
        }
        assert!(n.peers.contains(&key));
    }

    #[test]
    fn an_evicted_unconfirmed_session_is_reported_as_idle_again() {
        let (mut n, mut rng) = node();
        let now = Now::new(Instant::ZERO, 0);
        let first = member(&mut n, 0);
        install(&mut n, &first, 1);
        n.touched.insert(first);
        n.finish(now, &mut rng);
        let others: Vec<NodePublic> = (1..=UNCONFIRMED_LIMIT as u16)
            .map(|k| member(&mut n, k))
            .collect();
        for (i, key) in others.iter().enumerate() {
            install(&mut n, key, i as u32 + 2);
        }
        n.touched.insert(first);
        n.finish(now, &mut rng);
        assert!(!n.peers.get(&first).unwrap().has_unconfirmed());
        let states: Vec<PeerState> = std::iter::from_fn(|| n.poll_output())
            .filter_map(|o| match o {
                Output::Event(Event::Peer { peer, state }) if peer == first => Some(state),
                _ => None,
            })
            .collect();
        assert_eq!(states, vec![PeerState::Connecting, PeerState::Idle]);
    }
}
