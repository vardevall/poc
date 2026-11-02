//! Whole [`Node`]s on a simulated network: virtual time, a seeded RNG, NATs, links, one switch
//! and one TURN server. A run repeats exactly for a given seed.
//!
//! A scenario builds a topology, introduces peers, runs, and then reads what happened: every
//! datagram is a [`Hop`] in [`Sim::hops`], every event of a node is in [`Sim::events`], and each
//! node answers [`Node::peer_view`].

mod media;
mod net;
mod rng;

use std::collections::BinaryHeap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub use media::{MediumKind, SimMedium};
pub use net::{End, Fate, LinkConfig, NatConfig, NatKind};
pub use rng::SimRng;

use crate::discovery::candidate::Candidate;
use crate::ip::exit::{ExitServe, ExitUse};
use crate::ip::site::Site;
use crate::keys::{NetworkSecret, NodePublic, NodeSecret};
use crate::meter::Budget;
use crate::node::{Config, Event, Node, Output, PeerConfig, PeerState, RouteView};
use crate::peer::{Found, Group};
use crate::route::{DeliveryClass, Families};
use crate::time::{Instant, Now};
use crate::transport::{Path, Remote, TransportId};
use net::{Arrival, Net};

/// The port of every host socket and of the TURN server.
pub const PORT: u16 = 51820;
/// The site of public addresses.
pub const INTERNET: SiteId = SiteId(0);
/// `Now::unix_nanos` at instant zero.
const UNIX_BASE: u64 = 1_789_300_000_000_000_000;
/// Most steps one [`Sim::run`] may take at a single instant before it is taken for a timer loop.
const STEPS_PER_INSTANT: usize = 10_000;
/// Bytes of an IPv6 header.
const IPV6_HEADER: usize = 40;

/// A host of the simulation, in order of [`Sim::host`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostId(pub usize);

/// A site, in order of [`Sim::site`]; [`INTERNET`] is the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SiteId(pub usize);

/// A periodic sender of packets, from [`Sim::stream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub usize);

/// One datagram, recorded when it is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    /// When it was sent.
    pub at: Instant,
    /// The sending end.
    pub from: End,
    /// The receiving end, [`End::Nowhere`] if the destination resolved to none.
    pub to: End,
    /// The transport it went on.
    pub medium: MediumKind,
    /// Socket addresses, as the sender sees them; `None` on the switch.
    pub src: Option<SocketAddr>,
    /// The destination address, as the sender addressed it; `None` on the switch.
    pub dst: Option<SocketAddr>,
    /// Its length in bytes.
    pub len: usize,
    /// `Output::Transmit::signal` of the datagram, or `true` for the TURN server's leg of it.
    pub signal: bool,
    /// What became of it.
    pub fate: Fate,
    /// What it carries, from [`Node::describe`] of the node that sealed it.
    pub what: &'static str,
}

/// Where a host's allocation on the TURN server is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Allocation {
    None,
    /// Asked for; ready at this instant. `client` is the host's address as the server sees it.
    Pending {
        ready: Instant,
        client: SocketAddr,
    },
    Up {
        relayed: SocketAddr,
        client: SocketAddr,
    },
}

struct Host {
    node: Node,
    rng: SimRng,
    udp: TransportId,
    /// The switch transport and the link to the switch, once registered.
    switch: Option<(TransportId, LinkConfig)>,
    turn: Option<TransportId>,
    allocation: Allocation,
    /// The own candidates last given to the node.
    own: Vec<Candidate>,
    events: Vec<(Instant, Event)>,
    /// What the TURN server still relays for the host's allocation, both directions, if a budget
    /// was given (the server's `account`).
    turn_left: Option<u64>,
    /// What the switch still forwards from the host in this session, if a budget was given.
    switch_left: Option<u64>,
}

/// Charges `len` bytes to `left` if they fit; whether they may pass.
fn take(left: &mut Option<u64>, len: usize) -> bool {
    match left {
        Some(l) if (len as u64) > *l => false,
        Some(l) => {
            *l -= len as u64;
            true
        }
        None => true,
    }
}

/// What is in flight, ordered by `due` then by when it was queued.
enum Flight {
    /// A datagram reaching a host on one of its transports.
    Datagram {
        to: HostId,
        path: Path,
        data: Vec<u8>,
    },
    /// A datagram reaching the TURN server: from the owner of an allocation, to be sent on from
    /// the relayed address to `onward`; or on a relayed address (`onward` is `None`), to be
    /// passed to its owner.
    Turn {
        owner: HostId,
        arrival: net::Arrival,
        onward: Option<SocketAddr>,
        data: Vec<u8>,
    },
    /// A packet of a stream is due.
    Stream(StreamId),
    /// A pending allocation completes.
    Allocated(HostId),
    /// A host's binding request after a NAT rebind is answered: it gathers its candidates again.
    Regather(HostId),
}

struct Queued {
    due: Instant,
    seq: u64,
    flight: Flight,
}

struct Stream {
    from: HostId,
    to: HostId,
    every: Duration,
    class: DeliveryClass,
    len: usize,
    on: bool,
    /// Whether a [`Flight::Stream`] of it is queued.
    armed: bool,
}

/// The simulation.
pub struct Sim {
    now: Instant,
    rng: SimRng,
    network: NetworkSecret,
    net: Net,
    hosts: Vec<Host>,
    switch_up: bool,
    turn_up: bool,
    /// Whether the servers enforce the budgets given with [`Sim::set_budget`].
    enforce: bool,
    streams: Vec<Stream>,
    queue: BinaryHeap<Queued>,
    seq: u64,
    hops: Vec<Hop>,
    /// `Output::Demand`s, by host.
    demands: Vec<(Instant, HostId, bool)>,
    /// Pairs of hosts that trust each other, smaller first.
    pairs: Vec<(HostId, HostId)>,
    step_at: Instant,
    steps: usize,
}

impl Sim {
    /// An empty simulation whose internet core adds `uplink` each way to public addresses.
    pub fn new(seed: u64, uplink: LinkConfig) -> Self {
        let mut rng = SimRng::new(seed);
        let network = NetworkSecret::generate(&mut rng);
        Sim {
            now: Instant::ZERO,
            rng,
            network,
            net: Net::new(uplink),
            hosts: Vec::new(),
            switch_up: true,
            turn_up: true,
            enforce: true,
            streams: Vec::new(),
            queue: BinaryHeap::new(),
            seq: 0,
            hops: Vec::new(),
            demands: Vec::new(),
            pairs: Vec::new(),
            step_at: Instant::ZERO,
            steps: 0,
        }
    }

    /// A LAN behind `nat` (`None`: a LAN of public addresses).
    pub fn site(&mut self, nat: Option<NatConfig>, uplink: LinkConfig, lan: LinkConfig) -> SiteId {
        self.net.add_site(nat, uplink, lan)
    }

    /// A host with one interface at `ip` on `site`, its UDP transport registered. `configure`
    /// adjusts the node's [`Config`] before the node is made.
    pub fn host(
        &mut self,
        site: SiteId,
        ip: IpAddr,
        configure: impl FnOnce(&mut Config),
    ) -> HostId {
        let id = HostId(self.hosts.len());
        let mut rng = self.rng.fork();
        let secret = NodeSecret::generate(&mut rng);
        let mut config = Config::new(secret, self.network.clone());
        configure(&mut config);
        let mut node = Node::new(config, self.now_struct(), &mut rng);
        let udp = node.add_transport(Arc::new(SimMedium(MediumKind::Udp)));
        self.net.add_iface(id, site, ip);
        self.hosts.push(Host {
            node,
            rng,
            udp,
            switch: None,
            turn: None,
            allocation: Allocation::None,
            own: Vec::new(),
            events: Vec::new(),
            turn_left: None,
            switch_left: None,
        });
        self.refresh_own(id);
        id
    }

    /// Another interface of `host`; it comes after the existing ones in preference.
    pub fn add_iface(&mut self, host: HostId, site: SiteId, ip: IpAddr) {
        self.net.add_iface(host, site, ip);
        self.refresh_own(host);
    }

    /// Brings an interface up or down; the node gets [`Node::local_change`] and new own
    /// candidates.
    pub fn set_iface(&mut self, host: HostId, ip: IpAddr, up: bool) {
        assert!(
            self.net.set_iface(host, ip, up),
            "host {} has no interface at {ip}",
            host.0
        );
        self.refresh_own(host);
        let now = self.now_struct();
        let h = &mut self.hosts[host.0];
        let families = if ip.is_ipv4() {
            Families::V4
        } else {
            Families::V6
        };
        h.node.local_change(now, &mut h.rng, families);
    }

    /// Marks the interface of `host` at `ip` as metered or not: the candidates gathered on it
    /// carry the flag (vv-05 §2.2).
    pub fn set_metered(&mut self, host: HostId, ip: IpAddr, metered: bool) {
        let iface = self.net.ifaces[host.0].iter_mut().find(|i| i.ip == ip);
        assert!(iface.is_some(), "host {} has no interface at {ip}", host.0);
        if let Some(i) = iface {
            i.metered = metered;
        }
        self.refresh_own(host);
    }

    /// `a` and `b` trust each other's keys.
    pub fn peer(&mut self, a: HostId, b: HostId) {
        let now = self.now;
        for (x, y) in [(a, b), (b, a)] {
            let key = self.public(y);
            self.hosts[x.0].node.add_peer(PeerConfig::new(key), now);
        }
        let pair = (a.min(b), a.max(b));
        if !self.pairs.contains(&pair) {
            self.pairs.push(pair);
        }
        self.announce(a, b);
    }

    /// `a` trusts `b`'s key; `b` does not know `a` and takes it as a member if its config says
    /// so.
    pub fn trust(&mut self, a: HostId, b: HostId) {
        let key = self.public(b);
        let now = self.now;
        self.hosts[a.0].node.add_peer(PeerConfig::new(key), now);
    }

    /// `host` offers `offer` to the peers it holds by key from its next handshake on.
    pub fn set_exit(&mut self, host: HostId, offer: Option<ExitServe>) {
        let now = self.now_struct();
        let h = &mut self.hosts[host.0];
        h.node.set_exit(now, &mut h.rng, offer);
    }

    /// `host` takes back the offers its host remembered.
    pub fn remember(&mut self, host: HostId, offers: &[(NodePublic, Site)]) {
        let now = self.now_struct();
        let h = &mut self.hosts[host.0];
        h.node.remember(now, &mut h.rng, offers);
    }

    /// `host` starts or stops using an exit.
    pub fn use_exit(&mut self, host: HostId, using: Option<ExitUse>) {
        let now = self.now_struct();
        let h = &mut self.hosts[host.0];
        h.node.set_exit_use(now, &mut h.rng, using);
    }

    /// `a`'s candidates for `b` from one source group, as an address book would give them.
    pub fn know(&mut self, a: HostId, b: HostId, offered: Vec<Candidate>) {
        let key = self.public(b);
        let now = self.now_struct();
        let group = Group {
            source: "static",
            name: String::new(),
        };
        let found = Found {
            offered,
            spare: Vec::new(),
        };
        let h = &mut self.hosts[a.0];
        h.node
            .set_candidates(now, &mut h.rng, &key, group, found)
            .expect("know: the hosts must be peers");
    }

    /// The candidates `host` gathers, as a host on no common link would hold them: the
    /// addresses of its interfaces on the open internet (`static`, internet class), its
    /// reflexive address unless behind a symmetric NAT, and its relayed address. An address
    /// behind a NAT is no use to a host elsewhere, and a host on the same link finds it with
    /// [`Candidate::lan`], which the scenario builds itself.
    pub fn candidates_of(&mut self, host: HostId) -> Vec<Candidate> {
        let now = self.now;
        let ifaces: Vec<(SocketAddr, bool, SiteId)> = self.net.ifaces[host.0]
            .iter()
            .filter(|i| i.up)
            .map(|i| (SocketAddr::new(i.ip, PORT), i.metered, i.site))
            .collect();
        let addrs: Vec<(SocketAddr, bool)> = ifaces.iter().map(|(a, m, _)| (*a, *m)).collect();
        let mut out: Vec<Candidate> = ifaces
            .iter()
            .filter(|(_, _, site)| *site == INTERNET)
            .map(|(a, metered, _)| Candidate::static_(*a).with_metered(*metered))
            .collect();
        for (a, metered) in &addrs {
            if let Some(r) = self.net.reflexive(now, host, *a) {
                out.push(Candidate::punch(r).with_metered(*metered));
            }
        }
        if let Allocation::Up { relayed, .. } = self.hosts[host.0].allocation {
            out.push(Candidate::relay(relayed));
        }
        out
    }

    /// Registers `host` with the switch over `link`: a switch transport, ready while the switch
    /// is up, on which every registered peer of the host is reachable.
    pub fn register(&mut self, host: HostId, link: LinkConfig) {
        if let Some((_, l)) = self.hosts[host.0].switch.as_mut() {
            *l = link;
            return;
        }
        let now = self.now_struct();
        let up = self.switch_up;
        let h = &mut self.hosts[host.0];
        let tid = h
            .node
            .add_transport(Arc::new(SimMedium(MediumKind::Switch)));
        if !up {
            h.node.set_ready(now, &mut h.rng, tid, false);
        }
        h.switch = Some((tid, link));
        let pairs = self.pairs.clone();
        for (x, y) in pairs {
            if x == host || y == host {
                self.announce(x, y);
            }
        }
    }

    /// The switch goes down or comes back: transports not ready, datagrams on it dropped.
    pub fn set_switch(&mut self, up: bool) {
        self.switch_up = up;
        let now = self.now_struct();
        for h in &mut self.hosts {
            if let Some((tid, _)) = h.switch {
                h.node.set_ready(now, &mut h.rng, tid, up);
            }
        }
    }

    /// The TURN server at `ip`, `link` from the internet core each way.
    pub fn turn_server(&mut self, ip: IpAddr, link: LinkConfig) {
        self.net.turn = Some((ip, link));
    }

    /// Gives `host` an on-demand TURN transport. An `Output::Demand { on: true }` allocates after
    /// one round trip to the server (`set_ready`, the relayed candidate added); `on: false`
    /// releases at once.
    pub fn enable_turn(&mut self, host: HostId) {
        let h = &mut self.hosts[host.0];
        if h.turn.is_none() {
            h.turn = Some(h.node.add_transport(Arc::new(SimMedium(MediumKind::Turn))));
        }
    }

    /// Gives `host`'s transport for `medium` a budget, or removes it. The simulated servers
    /// enforce the same volume as the real ones: the TURN server stops relaying for the host's
    /// allocation once the payload of both directions used it up, the switch stops forwarding
    /// what the host sends once its session used it up. A new budget is a new credential or
    /// session. `Udp` has no server.
    pub fn set_budget(&mut self, host: HostId, medium: MediumKind, budget: Option<Budget>) {
        let via = self
            .transport(host, medium)
            .unwrap_or_else(|| panic!("host {} has no {medium:?} transport", host.0));
        let now = self.now_struct();
        let h = &mut self.hosts[host.0];
        let left = budget.map(|b| b.remaining);
        match medium {
            MediumKind::Turn => h.turn_left = left,
            MediumKind::Switch => h.switch_left = left,
            MediumKind::Udp => {}
        }
        h.node.set_budget(now, &mut h.rng, via, budget);
    }

    /// Whether the servers enforce budgets (they do from the start). Switched off, they keep
    /// carrying after a volume is used up, as a lenient or late server would.
    pub fn enforce_budgets(&mut self, on: bool) {
        self.enforce = on;
    }

    /// The TURN server goes down or comes back; allocations are lost when it goes down.
    pub fn set_turn(&mut self, up: bool) {
        if self.turn_up == up {
            return;
        }
        self.turn_up = up;
        if !up {
            for i in 0..self.hosts.len() {
                self.release(HostId(i));
            }
        }
    }

    /// See [`Net::block`](net::Net::block).
    pub fn block(&mut self, from: End, to: End, on: bool) {
        self.net.block(from, to, on);
    }

    /// The NAT of `site` rebinds; the hosts behind it learn their new reflexive addresses one
    /// STUN round trip later, as a refresh would, and then get new own candidates.
    pub fn rebind(&mut self, site: SiteId) {
        self.rebind_quietly(site);
        let due = self.now + self.net.stun_round_trip(site);
        for i in 0..self.hosts.len() {
            if self.net.ifaces[i].iter().any(|f| f.up && f.site == site) {
                self.queue_at(due, Flight::Regather(HostId(i)));
            }
        }
    }

    /// The NAT of `site` rebinds and the hosts behind it keep the own candidates they had,
    /// until [`Sim::regather`].
    pub fn rebind_quietly(&mut self, site: SiteId) {
        self.net.rebind(site);
    }

    /// `host` gathers its own candidates again and tells its peers if they changed.
    pub fn regather(&mut self, host: HostId) {
        self.refresh_own(host);
    }

    /// From `from` to `to`, a packet of `len` bytes every `every` in `class`, starting now.
    pub fn stream(
        &mut self,
        from: HostId,
        to: HostId,
        every: Duration,
        class: DeliveryClass,
        len: usize,
    ) -> StreamId {
        let id = StreamId(self.streams.len());
        self.streams.push(Stream {
            from,
            to,
            every,
            class,
            len,
            on: true,
            armed: true,
        });
        self.queue_at(self.now, Flight::Stream(id));
        id
    }

    /// Starts or stops a stream; a started one sends at once.
    pub fn set_stream(&mut self, stream: StreamId, on: bool) {
        let s = &mut self.streams[stream.0];
        s.on = on;
        if on && !s.armed {
            s.armed = true;
            self.queue_at(self.now, Flight::Stream(stream));
        }
    }

    /// Sends one packet from `from` to `to` now: `payload` behind an IPv6 header.
    pub fn send(&mut self, from: HostId, to: HostId, class: DeliveryClass, payload: &[u8]) {
        let packet = self.packet(from, to, payload);
        self.send_packet(from, to, class, &packet);
    }

    /// Runs for `d`: delivers what is due, runs every node's timers, carries out every output,
    /// in instant order. Panics if a node's timer is still due after its `handle_timeout`.
    pub fn run(&mut self, d: Duration) {
        let end = self.now + d;
        self.drain();
        while let Some(t) = self.next_instant(end) {
            self.instant(t);
        }
        self.now = end;
    }

    /// Runs until `done` holds, checked after each instant, or `limit` passes; returns whether
    /// it held.
    pub fn run_until(&mut self, limit: Duration, mut done: impl FnMut(&Sim) -> bool) -> bool {
        let end = self.now + limit;
        self.drain();
        loop {
            if done(self) {
                return true;
            }
            let Some(t) = self.next_instant(end) else {
                self.now = end;
                return done(self);
            };
            self.instant(t);
        }
    }

    /// The current instant.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// The node of `host`.
    pub fn node(&self, host: HostId) -> &Node {
        &self.hosts[host.0].node
    }

    /// The public key of `host`.
    pub fn public(&self, host: HostId) -> NodePublic {
        *self.hosts[host.0].node.public()
    }

    /// The transport of `host` for `medium`, once it has one.
    pub fn transport(&self, host: HostId, medium: MediumKind) -> Option<TransportId> {
        let h = &self.hosts[host.0];
        match medium {
            MediumKind::Udp => Some(h.udp),
            MediumKind::Turn => h.turn,
            MediumKind::Switch => h.switch.map(|s| s.0),
        }
    }

    /// The overlay address of `host`.
    pub fn overlay(&self, host: HostId) -> Ipv6Addr {
        self.hosts[host.0].node.overlay_addrs().ula
    }

    /// The socket address of the first up interface of `host`.
    pub fn addr(&self, host: HostId) -> SocketAddr {
        let i = self.net.ifaces[host.0]
            .iter()
            .find(|i| i.up)
            .unwrap_or_else(|| panic!("host {} has no interface up", host.0));
        SocketAddr::new(i.ip, PORT)
    }

    /// Every datagram sent so far, in the order it was sent.
    pub fn hops(&self) -> &[Hop] {
        &self.hops
    }

    /// The events `host`'s node produced, with the instants.
    pub fn events(&self, host: HostId) -> &[(Instant, Event)] {
        &self.hosts[host.0].events
    }

    /// Every `Output::Demand` of every node, with the instant and the host.
    pub fn demands(&self) -> &[(Instant, HostId, bool)] {
        &self.demands
    }

    /// The states `host` reported for `peer`, in order.
    pub fn states(&self, host: HostId, peer: HostId) -> Vec<(Instant, PeerState)> {
        let key = self.public(peer);
        self.events(host)
            .iter()
            .filter_map(|(t, e)| match e {
                Event::Peer { peer: p, state } if *p == key => Some((*t, *state)),
                _ => None,
            })
            .collect()
    }

    /// The routes `host` reported for `peer`, in order.
    pub fn routes(&self, host: HostId, peer: HostId) -> Vec<(Instant, Option<RouteView>)> {
        let key = self.public(peer);
        self.events(host)
            .iter()
            .filter_map(|(t, e)| match e {
                Event::Active { peer: p, route } if *p == key => Some((*t, *route)),
                _ => None,
            })
            .collect()
    }

    /// When packets from `from` arrived at `host`.
    pub fn arrivals(&self, host: HostId, from: HostId) -> Vec<Instant> {
        let key = self.public(from);
        self.events(host)
            .iter()
            .filter_map(|(t, e)| match e {
                Event::Packet { peer, .. } if *peer == key => Some(*t),
                _ => None,
            })
            .collect()
    }

    /// The longest time in `[start, end]` without an arrival at `host` from `from`.
    pub fn gap(&self, host: HostId, from: HostId, start: Instant, end: Instant) -> Duration {
        let mut last = start;
        let mut worst = Duration::ZERO;
        for t in self.arrivals(host, from) {
            if t < start || t > end {
                continue;
            }
            worst = worst.max(t - last);
            last = t;
        }
        worst.max(end - last)
    }

    /// `host`'s active route to `peer` now.
    pub fn active(&self, host: HostId, peer: HostId) -> Option<RouteView> {
        self.node(host)
            .peer_view(&self.public(peer))
            .and_then(|v| v.active)
    }

    /// The run so far as JSON, for a viewer: the hosts, every hop and every event that is a state,
    /// a route or a demand. Times are in microseconds.
    pub fn trace(&self) -> String {
        use std::fmt::Write;
        let us = |t: Instant| t.as_duration().as_micros();
        let end = |e: End| match e {
            End::Host(h) => format!("\"{}\"", host_name(h)),
            End::Turn => "\"turn\"".to_owned(),
            End::Switch => "\"switch\"".to_owned(),
            End::Nowhere => "\"nowhere\"".to_owned(),
        };
        let addr = |a: Option<SocketAddr>| a.map_or("null".to_owned(), |a| format!("\"{a}\""));
        let mut out = String::from("{\"hosts\":[");
        for (i, _) in self.hosts.iter().enumerate() {
            let addrs: Vec<String> = self.net.ifaces[i]
                .iter()
                .map(|f| format!("\"{}\"", f.ip))
                .collect();
            let _ = write!(
                out,
                "{}{{\"name\":\"{}\",\"addrs\":[{}]}}",
                if i > 0 { "," } else { "" },
                host_name(HostId(i)),
                addrs.join(",")
            );
        }
        out.push_str("],\"hops\":[");
        for (i, h) in self.hops.iter().enumerate() {
            let (fate, arrive) = match h.fate {
                Fate::Delivered(t) => ("delivered", us(t).to_string()),
                f => (fate_name(f), "null".to_owned()),
            };
            let _ = write!(
                out,
                "{}[{},{},{},\"{:?}\",{},{},{},\"{}\",\"{}\",{}]",
                if i > 0 { "," } else { "" },
                us(h.at),
                end(h.from),
                end(h.to),
                h.medium,
                addr(h.src),
                addr(h.dst),
                h.len,
                h.what,
                fate,
                arrive
            );
        }
        out.push_str("],\"events\":[");
        let mut first = true;
        for (i, host) in self.hosts.iter().enumerate() {
            let me = HostId(i);
            let name_of = |k: &NodePublic| {
                (0..self.hosts.len())
                    .find(|j| self.hosts[*j].node.public() == k)
                    .map_or_else(|| "?".to_owned(), |j| host_name(HostId(j)))
            };
            for (t, e) in &host.events {
                let (peer, what) = match e {
                    Event::Peer { peer, state } => (peer, format!("\"state\",\"{state:?}\"")),
                    Event::Active { peer, route } => {
                        let r = route.map_or("null".to_owned(), |r| {
                            let via = [MediumKind::Udp, MediumKind::Turn, MediumKind::Switch]
                                .into_iter()
                                .find(|m| self.transport(me, *m) == Some(r.path.via))
                                .map_or_else(|| "?".to_owned(), |m| format!("{m:?}"));
                            let to = match r.path.to {
                                Remote::Addr(a) => a.to_string(),
                                Remote::Peer(_) => "peer".to_owned(),
                            };
                            format!(
                                "{{\"via\":\"{via}\",\"to\":\"{to}\",\"label\":\"{}\",\"band\":\"{:?}\",\"latency\":\"{:?}\",\"metered\":{},\"verified\":{}}}",
                                r.label,
                                r.class.band,
                                r.class.latency,
                                r.class.metered,
                                r.verified
                            )
                        });
                        (peer, format!("\"route\",{r}"))
                    }
                    _ => continue,
                };
                let _ = write!(
                    out,
                    "{}[{},\"{}\",\"{}\",{}]",
                    if first { "" } else { "," },
                    us(*t),
                    host_name(me),
                    name_of(peer),
                    what
                );
                first = false;
            }
        }
        out.push_str("],\"demands\":[");
        for (i, (t, h, on)) in self.demands.iter().enumerate() {
            let _ = write!(
                out,
                "{}[{},\"{}\",{}]",
                if i > 0 { "," } else { "" },
                us(*t),
                host_name(*h),
                on
            );
        }
        let _ = write!(out, "],\"end\":{}}}", us(self.now));
        out
    }

    fn now_struct(&self) -> Now {
        Now::new(
            self.now,
            UNIX_BASE + self.now.as_duration().as_nanos() as u64,
        )
    }

    fn queue_at(&mut self, due: Instant, flight: Flight) {
        self.seq += 1;
        self.queue.push(Queued {
            due,
            seq: self.seq,
            flight,
        });
    }

    /// Gives the node of `host` the shared candidates it gathers now, if they changed.
    fn refresh_own(&mut self, host: HostId) {
        let own: Vec<Candidate> = self
            .candidates_of(host)
            .into_iter()
            .filter(|c| c.shared)
            .collect();
        if own == self.hosts[host.0].own {
            return;
        }
        self.hosts[host.0].own = own.clone();
        let now = self.now_struct();
        let h = &mut self.hosts[host.0];
        h.node.set_own_candidates(now, &mut h.rng, own);
    }

    /// Reports `a` and `b` reachable to each other if both are registered.
    fn announce(&mut self, a: HostId, b: HostId) {
        let (Some((ta, _)), Some((tb, _))) = (self.hosts[a.0].switch, self.hosts[b.0].switch)
        else {
            return;
        };
        let now = self.now_struct();
        let (ka, kb) = (self.public(a), self.public(b));
        let h = &mut self.hosts[a.0];
        h.node.set_reachable(now, &mut h.rng, ta, &kb, true);
        let h = &mut self.hosts[b.0];
        h.node.set_reachable(now, &mut h.rng, tb, &ka, true);
    }

    fn packet(&self, from: HostId, to: HostId, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        p.extend_from_slice(&[59, 64]);
        p.extend_from_slice(&self.overlay(from).octets());
        p.extend_from_slice(&self.overlay(to).octets());
        p.extend_from_slice(payload);
        p
    }

    fn send_packet(&mut self, from: HostId, to: HostId, class: DeliveryClass, packet: &[u8]) {
        let key = self.public(to);
        let now = self.now_struct();
        let h = &mut self.hosts[from.0];
        h.node
            .send(now, &mut h.rng, &key, class, packet)
            .expect("send");
    }

    /// The next instant at which something happens, no later than `end`.
    fn next_instant(&self, end: Instant) -> Option<Instant> {
        let timers = self.hosts.iter().filter_map(|h| h.node.poll_timeout());
        let next = self
            .queue
            .peek()
            .map(|q| q.due)
            .into_iter()
            .chain(timers)
            .min()?;
        Some(next.max(self.now)).filter(|t| *t <= end)
    }

    /// One instant: what is due, every node's timers, every output.
    fn instant(&mut self, t: Instant) {
        if t == self.step_at {
            self.steps += 1;
        } else {
            self.step_at = t;
            self.steps = 1;
        }
        assert!(
            self.steps <= STEPS_PER_INSTANT,
            "more than {STEPS_PER_INSTANT} steps at {t:?}: a timer loop"
        );
        self.now = t;
        while self.queue.peek().is_some_and(|q| q.due <= t) {
            if let Some(q) = self.queue.pop() {
                self.deliver(q.flight);
            }
        }
        let now = self.now_struct();
        for (i, h) in self.hosts.iter_mut().enumerate() {
            h.node.handle_timeout(now, &mut h.rng);
            if let Some(p) = h.node.poll_timeout()
                && p <= t
            {
                panic!(
                    "host {i}: a timer due at {p:?} is still pending at {t:?} after handle_timeout"
                );
            }
        }
        self.drain();
    }

    fn deliver(&mut self, flight: Flight) {
        match flight {
            Flight::Datagram { to, path, data } => {
                let on_switch = self.hosts[to.0].switch.is_some_and(|s| s.0 == path.via);
                if on_switch && !self.switch_up {
                    return;
                }
                let now = self.now_struct();
                let h = &mut self.hosts[to.0];
                h.node.handle_datagram(now, &mut h.rng, path, &data);
            }
            Flight::Turn {
                owner,
                arrival,
                onward,
                data,
            } => self.at_turn(owner, arrival, onward, data),
            Flight::Stream(id) => {
                let s = &mut self.streams[id.0];
                s.armed = false;
                if !s.on {
                    return;
                }
                let (from, to, class, len, every) = (s.from, s.to, s.class, s.len, s.every);
                s.armed = true;
                let payload = vec![0u8; len.saturating_sub(IPV6_HEADER)];
                let packet = self.packet(from, to, &payload);
                self.send_packet(from, to, class, &packet);
                self.queue_at(self.now + every, Flight::Stream(id));
            }
            Flight::Allocated(host) => self.allocated(host),
            Flight::Regather(host) => self.regather(host),
        }
    }

    /// Carries out every output of every node until none is left.
    fn drain(&mut self) {
        loop {
            let mut any = false;
            for i in 0..self.hosts.len() {
                while let Some(out) = self.hosts[i].node.poll_output() {
                    any = true;
                    self.output(HostId(i), out);
                }
            }
            if !any {
                return;
            }
        }
    }

    fn output(&mut self, host: HostId, out: Output) {
        match out {
            Output::Transmit { path, data, signal } => self.transmit(host, path, data, signal),
            Output::Demand { via, on } => {
                self.demands.push((self.now, host, on));
                self.demand(host, via, on);
            }
            Output::Event(e) => self.hosts[host.0].events.push((self.now, e)),
        }
    }

    fn transmit(&mut self, host: HostId, path: Path, data: Vec<u8>, signal: bool) {
        let h = &self.hosts[host.0];
        let medium = if path.via == h.udp {
            MediumKind::Udp
        } else if h.turn == Some(path.via) {
            MediumKind::Turn
        } else if h.switch.is_some_and(|s| s.0 == path.via) {
            MediumKind::Switch
        } else {
            return;
        };
        match (medium, path.to) {
            (MediumKind::Udp, Remote::Addr(dst)) => {
                let Some(src) = self.net.source(host, dst) else {
                    self.hop(
                        End::Host(host),
                        End::Nowhere,
                        medium,
                        None,
                        Some(dst),
                        &data,
                        signal,
                        Fate::NoRoute,
                    );
                    return;
                };
                if let Some(a) = self.wire(End::Host(host), src, dst, medium, signal, &data) {
                    self.route(a, data);
                }
            }
            (MediumKind::Turn, Remote::Addr(dst)) => self.turn_in(host, dst, data, signal),
            (MediumKind::Switch, Remote::Peer(key)) => self.switch_hop(host, key, data, signal),
            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn hop(
        &mut self,
        from: End,
        to: End,
        medium: MediumKind,
        src: Option<SocketAddr>,
        dst: Option<SocketAddr>,
        data: &[u8],
        signal: bool,
        fate: Fate,
    ) {
        let sender = match from {
            End::Host(h) => Some(h.0),
            _ => None,
        };
        let what = sender
            .into_iter()
            .chain(0..self.hosts.len())
            .map(|i| self.hosts[i].node.describe(data))
            .find(|w| *w != "frame")
            .unwrap_or("frame");
        self.hops.push(Hop {
            at: self.now,
            from,
            to,
            medium,
            src,
            dst,
            len: data.len(),
            signal,
            fate,
            what,
        });
    }

    /// Sends a datagram over the network, records the hop and returns the arrival if it gets
    /// there.
    fn wire(
        &mut self,
        from: End,
        src: SocketAddr,
        dst: SocketAddr,
        medium: MediumKind,
        signal: bool,
        data: &[u8],
    ) -> Option<Arrival> {
        let sent = self.net.send(self.now, &mut self.rng, from, src, dst);
        let sent = match sent {
            Ok(a) if a.to == End::Turn && !self.turn_up => Err(Fate::Down),
            other => other,
        };
        match sent {
            Ok(a) => {
                self.hop(
                    from,
                    a.to,
                    medium,
                    Some(src),
                    Some(dst),
                    data,
                    signal,
                    Fate::Delivered(a.due),
                );
                Some(a)
            }
            Err(fate) => {
                let to = self.net.destination(from, src, dst).unwrap_or(End::Nowhere);
                self.hop(from, to, medium, Some(src), Some(dst), data, signal, fate);
                None
            }
        }
    }

    /// Hands an arrival to its receiver: a host socket, or a relayed address of the TURN server.
    fn route(&mut self, a: Arrival, data: Vec<u8>) {
        match a.to {
            End::Host(h) => {
                let path = Path {
                    via: self.hosts[h.0].udp,
                    to: Remote::Addr(a.from),
                };
                self.queue_at(a.due, Flight::Datagram { to: h, path, data });
            }
            End::Turn if a.at.port() != PORT => {
                if let Some(&owner) = self.net.relayed.get(&a.at.port()) {
                    self.queue_at(
                        a.due,
                        Flight::Turn {
                            owner,
                            arrival: a,
                            onward: None,
                            data,
                        },
                    );
                }
            }
            _ => {}
        }
    }

    /// A node sends `data` to `dst` through its allocation: first to the server.
    fn turn_in(&mut self, host: HostId, dst: SocketAddr, data: Vec<u8>, signal: bool) {
        let server = self.net.turn.map(|(ip, _)| SocketAddr::new(ip, PORT));
        let src = server.and_then(|s| self.net.source(host, s));
        let (Some(server), Some(src), Allocation::Up { .. }) =
            (server, src, self.hosts[host.0].allocation)
        else {
            self.hop(
                End::Host(host),
                End::Turn,
                MediumKind::Turn,
                None,
                Some(dst),
                &data,
                signal,
                Fate::Down,
            );
            return;
        };
        if let Some(a) = self.wire(
            End::Host(host),
            src,
            server,
            MediumKind::Turn,
            signal,
            &data,
        ) {
            self.queue_at(
                a.due,
                Flight::Turn {
                    owner: host,
                    arrival: a,
                    onward: Some(dst),
                    data,
                },
            );
        }
    }

    /// A datagram reaches the TURN server: sent on from the relayed address, or passed to the
    /// owner of the relayed address.
    fn at_turn(
        &mut self,
        owner: HostId,
        arrival: Arrival,
        onward: Option<SocketAddr>,
        data: Vec<u8>,
    ) {
        let Some((ip, _)) = self.net.turn else {
            return;
        };
        let Allocation::Up { relayed, client } = self.hosts[owner.0].allocation else {
            return;
        };
        if !self.turn_up {
            return;
        }
        let left = &mut self.hosts[owner.0].turn_left;
        if self.enforce && !take(left, data.len()) {
            return;
        }
        match onward {
            Some(dst) => {
                self.hosts[owner.0].allocation = Allocation::Up {
                    relayed,
                    client: arrival.from,
                };
                if let Some(a) = self.wire(End::Turn, relayed, dst, MediumKind::Turn, true, &data) {
                    self.route(a, data);
                }
            }
            None => {
                if relayed != arrival.at {
                    return;
                }
                let Some(via) = self.hosts[owner.0].turn else {
                    return;
                };
                let server = SocketAddr::new(ip, PORT);
                if let Some(a) = self.wire(End::Turn, server, client, MediumKind::Turn, true, &data)
                    && a.to == End::Host(owner)
                {
                    let path = Path {
                        via,
                        to: Remote::Addr(arrival.from),
                    };
                    self.queue_at(
                        a.due,
                        Flight::Datagram {
                            to: owner,
                            path,
                            data,
                        },
                    );
                }
            }
        }
    }

    /// A node sends `data` to `key` through the switch.
    fn switch_hop(&mut self, from: HostId, key: NodePublic, data: Vec<u8>, signal: bool) {
        let to = (0..self.hosts.len())
            .map(HostId)
            .find(|h| self.public(*h) == key);
        let Some(to) = to else {
            self.hop(
                End::Host(from),
                End::Nowhere,
                MediumKind::Switch,
                None,
                None,
                &data,
                signal,
                Fate::NoRoute,
            );
            return;
        };
        let (a, b) = (self.hosts[from.0].switch, self.hosts[to.0].switch);
        let fate = match (a, b) {
            (Some((_, la)), Some((tb, lb))) if self.switch_up => {
                let left = &mut self.hosts[from.0].switch_left;
                let over = self.enforce && !take(left, data.len());
                if over
                    || self.net.blocked.contains(&(End::Host(from), End::Switch))
                    || self.net.blocked.contains(&(End::Switch, End::Host(to)))
                {
                    Err(Fate::Blocked)
                } else {
                    Net::cross(self.now, &mut self.rng, la)
                        .and_then(|t| Net::cross(t, &mut self.rng, lb))
                        .map(|due| (due, tb))
                }
            }
            _ => Err(Fate::Down),
        };
        match fate {
            Ok((due, tb)) => {
                self.hop(
                    End::Host(from),
                    End::Host(to),
                    MediumKind::Switch,
                    None,
                    None,
                    &data,
                    signal,
                    Fate::Delivered(due),
                );
                let path = Path {
                    via: tb,
                    to: Remote::Peer(self.public(from)),
                };
                self.queue_at(due, Flight::Datagram { to, path, data });
            }
            Err(fate) => {
                self.hop(
                    End::Host(from),
                    End::Host(to),
                    MediumKind::Switch,
                    None,
                    None,
                    &data,
                    signal,
                    fate,
                );
            }
        }
    }

    /// A node asked for or let go of an on-demand transport.
    fn demand(&mut self, host: HostId, via: TransportId, on: bool) {
        if self.hosts[host.0].turn != Some(via) {
            return;
        }
        if !on {
            self.release(host);
            return;
        }
        if self.hosts[host.0].allocation != Allocation::None || !self.turn_up {
            return;
        }
        let Some((ip, _)) = self.net.turn else {
            return;
        };
        let server = SocketAddr::new(ip, PORT);
        let Some(src) = self.net.source(host, server) else {
            return;
        };
        let Ok(request) = self
            .net
            .send(self.now, &mut self.rng, End::Host(host), src, server)
        else {
            return;
        };
        let Ok(response) =
            self.net
                .send(request.due, &mut self.rng, End::Turn, server, request.from)
        else {
            return;
        };
        self.hosts[host.0].allocation = Allocation::Pending {
            ready: response.due,
            client: request.from,
        };
        self.queue_at(response.due, Flight::Allocated(host));
    }

    /// An allocation completes: the transport is ready and the relayed address a candidate.
    fn allocated(&mut self, host: HostId) {
        let Allocation::Pending { ready, client } = self.hosts[host.0].allocation else {
            return;
        };
        if ready != self.now || !self.turn_up {
            return;
        }
        let Some(relayed) = self.net.allocate(host) else {
            self.hosts[host.0].allocation = Allocation::None;
            return;
        };
        self.hosts[host.0].allocation = Allocation::Up { relayed, client };
        if let Some(via) = self.hosts[host.0].turn {
            let now = self.now_struct();
            let h = &mut self.hosts[host.0];
            h.node.set_ready(now, &mut h.rng, via, true);
        }
        self.refresh_own(host);
    }

    /// Drops the allocation of `host`.
    fn release(&mut self, host: HostId) {
        let was = std::mem::replace(&mut self.hosts[host.0].allocation, Allocation::None);
        let Allocation::Up { relayed, .. } = was else {
            return;
        };
        self.net.release(relayed);
        if let Some(via) = self.hosts[host.0].turn {
            let now = self.now_struct();
            let h = &mut self.hosts[host.0];
            h.node.set_ready(now, &mut h.rng, via, false);
        }
        self.refresh_own(host);
    }
}

impl PartialEq for Queued {
    fn eq(&self, o: &Self) -> bool {
        (self.due, self.seq) == (o.due, o.seq)
    }
}

impl Eq for Queued {}

impl PartialOrd for Queued {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

impl Ord for Queued {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (o.due, o.seq).cmp(&(self.due, self.seq))
    }
}

/// `A`, `B`, … for the trace.
fn host_name(h: HostId) -> String {
    char::from_u32(u32::from(b'A') + h.0 as u32).map_or_else(|| format!("H{}", h.0), String::from)
}

fn fate_name(f: Fate) -> &'static str {
    match f {
        Fate::Delivered(_) => "delivered",
        Fate::Lost => "lost",
        Fate::Blocked => "blocked",
        Fate::Filtered => "filtered",
        Fate::NoRoute => "noroute",
        Fate::Down => "down",
    }
}
