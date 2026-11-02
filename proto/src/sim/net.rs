//! Addressing, NATs and links of the simulation: where a datagram sent from one address to
//! another arrives, from which address it seems to come, and when.
//!
//! Every host socket and the TURN server listen on [`super::PORT`]; relayed addresses are ports of
//! the TURN server's address.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::rng::SimRng;
use super::{HostId, INTERNET, PORT, SiteId};
use crate::time::Instant;

/// The first port a NAT hands out.
const FIRST_NAT_PORT: u16 = 4000;
/// The first relayed port of the TURN server.
const FIRST_RELAYED_PORT: u16 = 49152;

/// How a NAT maps and filters (RFC 4787 terms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatKind {
    /// Endpoint-independent mapping and filtering.
    Open,
    /// Endpoint-independent mapping; only replies from an address and port the mapping sent to
    /// pass.
    PortRestricted,
    /// A mapping per destination; filtering as `PortRestricted`.
    Symmetric,
}

/// A NAT in front of a site.
#[derive(Debug, Clone, Copy)]
pub struct NatConfig {
    /// How it maps and filters.
    pub kind: NatKind,
    /// The public address.
    pub public: IpAddr,
    /// Whether a datagram from inside to the NAT's own public address is turned back inside.
    pub hairpin: bool,
    /// A mapping that sent nothing for this long is dropped.
    pub timeout: Duration,
}

impl NatConfig {
    /// A NAT of `kind` at `public`, without hairpinning and with a 120 s mapping timeout.
    pub fn new(kind: NatKind, public: IpAddr) -> Self {
        NatConfig {
            kind,
            public,
            hairpin: false,
            timeout: Duration::from_secs(120),
        }
    }
}

/// One direction of a link.
#[derive(Debug, Clone, Copy)]
pub struct LinkConfig {
    /// The fixed delay.
    pub latency: Duration,
    /// Added uniformly at random in `0..=jitter`; datagrams can overtake each other.
    pub jitter: Duration,
    /// Probability that a datagram is lost.
    pub loss: f64,
}

impl LinkConfig {
    /// A lossless link with a fixed delay.
    pub const fn latency(latency: Duration) -> Self {
        LinkConfig {
            latency,
            jitter: Duration::ZERO,
            loss: 0.0,
        }
    }
}

/// An endpoint of a hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum End {
    /// A host.
    Host(HostId),
    /// The TURN server, or one of its relayed addresses.
    Turn,
    /// The switch.
    Switch,
    /// No endpoint: the destination of a datagram that resolved to nothing.
    Nowhere,
}

/// What became of a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// Arrives at this instant.
    Delivered(Instant),
    /// Lost on a link.
    Lost,
    /// Dropped by [`Net::block`].
    Blocked,
    /// Dropped by a NAT's filter, or by a NAT without hairpinning.
    Filtered,
    /// No host, NAT mapping or relayed address has the destination.
    NoRoute,
    /// The switch or TURN server is down, or the sender is not registered with it.
    Down,
}

/// Where a delivered datagram ends up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrival {
    /// The receiving end.
    pub to: End,
    /// The address the receiver sees as the source.
    pub from: SocketAddr,
    /// The receiver's address it was sent to: a host socket, or a relayed address at
    /// [`End::Turn`].
    pub at: SocketAddr,
    /// When it arrives.
    pub due: Instant,
}

/// A network interface of a host.
#[derive(Debug, Clone, Copy)]
pub(super) struct Iface {
    pub(super) site: SiteId,
    pub(super) ip: IpAddr,
    pub(super) up: bool,
    /// Whether the candidates gathered on it are metered.
    pub(super) metered: bool,
}

/// A site: the internet (no NAT) or a LAN behind a NAT.
pub(super) struct Site {
    pub(super) nat: Option<Nat>,
    /// Between the site and the internet core, each way.
    pub(super) uplink: LinkConfig,
    /// Between two hosts of the site.
    pub(super) lan: LinkConfig,
}

pub(super) struct Nat {
    pub(super) config: NatConfig,
    /// By inside address, and destination for [`NatKind::Symmetric`].
    pub(super) mappings: HashMap<(SocketAddr, Option<SocketAddr>), Mapping>,
    pub(super) next_port: u16,
}

impl Nat {
    fn expire(&mut self, now: Instant) {
        let timeout = self.config.timeout;
        self.mappings
            .retain(|_, m| now.saturating_duration_since(m.last_out) <= timeout);
    }

    /// The inside address behind `port`, if the filter lets a datagram from `seen` through.
    fn admit(&self, port: u16, seen: SocketAddr) -> Result<SocketAddr, Fate> {
        let (key, mapping) = self
            .mappings
            .iter()
            .find(|(_, m)| m.port == port)
            .ok_or(Fate::NoRoute)?;
        match self.config.kind {
            NatKind::Open => Ok(key.0),
            NatKind::PortRestricted | NatKind::Symmetric => {
                if mapping.sent_to.contains(&seen) {
                    Ok(key.0)
                } else {
                    Err(Fate::Filtered)
                }
            }
        }
    }

    /// The inside address behind `port`, regardless of the filter.
    fn inside(&self, port: u16) -> Option<SocketAddr> {
        self.mappings
            .iter()
            .find(|(_, m)| m.port == port)
            .map(|(k, _)| k.0)
    }

    fn map(&mut self, now: Instant, inside: SocketAddr, dst: SocketAddr) -> SocketAddr {
        self.expire(now);
        let key = (
            inside,
            (self.config.kind == NatKind::Symmetric).then_some(dst),
        );
        let next = &mut self.next_port;
        let mapping = self.mappings.entry(key).or_insert_with(|| {
            let port = *next;
            *next = if port == u16::MAX {
                FIRST_NAT_PORT
            } else {
                port + 1
            };
            Mapping {
                port,
                last_out: now,
                sent_to: HashSet::new(),
            }
        });
        mapping.last_out = now;
        mapping.sent_to.insert(dst);
        SocketAddr::new(self.config.public, mapping.port)
    }
}

pub(super) struct Mapping {
    pub(super) port: u16,
    pub(super) last_out: Instant,
    /// Destinations it sent to, for the filter.
    pub(super) sent_to: HashSet<SocketAddr>,
}

/// Where a destination address leads, before any NAT state is consulted.
enum Dest {
    /// A host interface on the sender's own site.
    Lan(HostId),
    /// The sender's own NAT.
    Hairpin,
    /// Another site's NAT.
    Nat(SiteId),
    /// A host interface on a site without a NAT.
    Public(HostId, SiteId),
    /// The TURN server or one of its relayed addresses.
    Turn,
    Nowhere,
}

/// The network.
pub(super) struct Net {
    pub(super) sites: Vec<Site>,
    /// By host.
    pub(super) ifaces: Vec<Vec<Iface>>,
    pub(super) turn: Option<(IpAddr, LinkConfig)>,
    /// Relayed ports of the TURN server, by owner.
    pub(super) relayed: HashMap<u16, HostId>,
    pub(super) blocked: HashSet<(End, End)>,
    next_relayed: u16,
}

impl Net {
    /// The internet, as site 0, with `uplink` to every public address.
    pub(super) fn new(uplink: LinkConfig) -> Self {
        Net {
            sites: vec![Site {
                nat: None,
                uplink,
                lan: LinkConfig::latency(Duration::ZERO),
            }],
            ifaces: Vec::new(),
            turn: None,
            relayed: HashMap::new(),
            blocked: HashSet::new(),
            next_relayed: FIRST_RELAYED_PORT,
        }
    }

    pub(super) fn add_site(
        &mut self,
        nat: Option<NatConfig>,
        uplink: LinkConfig,
        lan: LinkConfig,
    ) -> SiteId {
        self.sites.push(Site {
            nat: nat.map(|config| Nat {
                config,
                mappings: HashMap::new(),
                next_port: FIRST_NAT_PORT,
            }),
            uplink,
            lan,
        });
        SiteId(self.sites.len() - 1)
    }

    pub(super) fn add_iface(&mut self, host: HostId, site: SiteId, ip: IpAddr) {
        while self.ifaces.len() <= host.0 {
            self.ifaces.push(Vec::new());
        }
        self.ifaces[host.0].push(Iface {
            site,
            ip,
            up: true,
            metered: false,
        });
    }

    /// Brings the interface of `host` at `ip` up or down; false if it has none.
    pub(super) fn set_iface(&mut self, host: HostId, ip: IpAddr, up: bool) -> bool {
        let Some(i) = self
            .ifaces
            .get_mut(host.0)
            .and_then(|v| v.iter_mut().find(|i| i.ip == ip))
        else {
            return false;
        };
        i.up = up;
        true
    }

    /// The host with an up interface at `ip` on `site`.
    fn host_at(&self, site: SiteId, ip: IpAddr) -> Option<HostId> {
        self.ifaces.iter().enumerate().find_map(|(h, v)| {
            v.iter()
                .any(|i| i.up && i.site == site && i.ip == ip)
                .then_some(HostId(h))
        })
    }

    /// The source a host uses towards `to`: the first up interface on the same site as `to`, else
    /// the first up interface; an interface of the family of `to` goes first.
    pub(super) fn source(&self, host: HostId, to: SocketAddr) -> Option<SocketAddr> {
        let up: Vec<&Iface> = self.ifaces.get(host.0)?.iter().filter(|i| i.up).collect();
        let same_site: Vec<&Iface> = up
            .iter()
            .copied()
            .filter(|i| self.host_at(i.site, to.ip()).is_some())
            .collect();
        let pool = if same_site.is_empty() {
            &up
        } else {
            &same_site
        };
        let pick = pool
            .iter()
            .find(|i| i.ip.is_ipv4() == to.is_ipv4())
            .or(pool.first())?;
        Some(SocketAddr::new(pick.ip, PORT))
    }

    /// Drops every datagram on hops from `from` to `to` while `on`; the other direction is not
    /// affected.
    pub(super) fn block(&mut self, from: End, to: End, on: bool) {
        if on {
            self.blocked.insert((from, to));
        } else {
            self.blocked.remove(&(from, to));
        }
    }

    /// Every mapping of the site's NAT is dropped: the next datagrams get new ports.
    pub(super) fn rebind(&mut self, site: SiteId) {
        if let Some(nat) = self.sites[site.0].nat.as_mut() {
            nat.mappings.clear();
        }
    }

    /// The round trip of a binding request from a host of `site` to a STUN server on the
    /// internet: its LAN and its uplink, there and back.
    pub(super) fn stun_round_trip(&self, site: SiteId) -> Duration {
        let s = &self.sites[site.0];
        2 * (s.lan.latency + s.uplink.latency)
    }

    /// A relayed address for `owner`; `None` if there is no TURN server or no port is left.
    pub(super) fn allocate(&mut self, owner: HostId) -> Option<SocketAddr> {
        let (ip, _) = self.turn?;
        let port = self.next_relayed;
        self.next_relayed = self.next_relayed.checked_add(1)?;
        self.relayed.insert(port, owner);
        Some(SocketAddr::new(ip, port))
    }

    /// Frees the relayed address `addr`.
    pub(super) fn release(&mut self, addr: SocketAddr) {
        self.relayed.remove(&addr.port());
    }

    fn site_of(&self, host: HostId, ip: IpAddr) -> Option<SiteId> {
        self.ifaces
            .get(host.0)?
            .iter()
            .find(|i| i.ip == ip)
            .map(|i| i.site)
    }

    fn classify(&self, src_site: Option<SiteId>, dst: SocketAddr) -> Dest {
        if let Some(s) = src_site {
            if s != INTERNET
                && let Some(h) = self.host_at(s, dst.ip())
            {
                return if dst.port() == PORT {
                    Dest::Lan(h)
                } else {
                    Dest::Nowhere
                };
            }
            if self.sites[s.0]
                .nat
                .as_ref()
                .is_some_and(|n| n.config.public == dst.ip())
            {
                return Dest::Hairpin;
            }
        }
        for (i, site) in self.sites.iter().enumerate() {
            if site
                .nat
                .as_ref()
                .is_some_and(|n| n.config.public == dst.ip())
            {
                return Dest::Nat(SiteId(i));
            }
        }
        for (h, v) in self.ifaces.iter().enumerate() {
            for i in v {
                if i.up && i.ip == dst.ip() && self.sites[i.site.0].nat.is_none() {
                    return if dst.port() == PORT {
                        Dest::Public(HostId(h), i.site)
                    } else {
                        Dest::Nowhere
                    };
                }
            }
        }
        match self.turn {
            Some((ip, _)) if ip == dst.ip() => Dest::Turn,
            _ => Dest::Nowhere,
        }
    }

    fn end_of(&self, src_site: Option<SiteId>, dest: &Dest, dst: SocketAddr) -> Option<End> {
        match dest {
            Dest::Lan(h) | Dest::Public(h, _) => Some(End::Host(*h)),
            Dest::Hairpin => {
                let s = src_site?;
                let inside = self.sites[s.0].nat.as_ref()?.inside(dst.port())?;
                self.host_at(s, inside.ip()).map(End::Host)
            }
            Dest::Nat(s) => {
                let inside = self.sites[s.0].nat.as_ref()?.inside(dst.port())?;
                self.host_at(*s, inside.ip()).map(End::Host)
            }
            Dest::Turn => Some(End::Turn),
            Dest::Nowhere => None,
        }
    }

    /// The end `dst` resolves to for a datagram from `src`, if any.
    pub(super) fn destination(&self, from: End, src: SocketAddr, dst: SocketAddr) -> Option<End> {
        let src_site = self.source_site(from, src).ok()?;
        let dest = self.classify(src_site, dst);
        self.end_of(src_site, &dest, dst)
    }

    fn source_site(&self, from: End, src: SocketAddr) -> Result<Option<SiteId>, Fate> {
        match from {
            End::Host(h) => self.site_of(h, src.ip()).map(Some).ok_or(Fate::NoRoute),
            End::Turn => Ok(None),
            End::Switch | End::Nowhere => Err(Fate::NoRoute),
        }
    }

    /// Sends a datagram from `src` (an address of `from`) to `dst`: through the source's NAT,
    /// across the internet or the LAN, through the destination's NAT. Creates and refreshes
    /// mappings, applies filters, hairpinning, blocks, loss, latency and jitter.
    pub(super) fn send(
        &mut self,
        now: Instant,
        rng: &mut SimRng,
        from: End,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<Arrival, Fate> {
        let src_site = self.source_site(from, src)?;
        let dest = self.classify(src_site, dst);
        if let Some(to) = self.end_of(src_site, &dest, dst)
            && self.blocked.contains(&(from, to))
        {
            return Err(Fate::Blocked);
        }
        let mut seen = src;
        if let Some(s) = src_site
            && !matches!(dest, Dest::Lan(_))
            && let Some(nat) = self.sites[s.0].nat.as_mut()
        {
            seen = nat.map(now, src, dst);
        }
        let turn_link = self.turn.map(|(_, l)| l);
        let src_link = match src_site {
            Some(s) => self.sites[s.0].uplink,
            None => turn_link.ok_or(Fate::NoRoute)?,
        };
        match dest {
            Dest::Lan(h) => {
                let s = src_site.ok_or(Fate::NoRoute)?;
                let due = Net::chain(now, rng, &[self.sites[s.0].lan])?;
                Ok(Arrival {
                    to: End::Host(h),
                    from: seen,
                    at: dst,
                    due,
                })
            }
            Dest::Hairpin => {
                let s = src_site.ok_or(Fate::NoRoute)?;
                let nat = self.sites[s.0].nat.as_mut().ok_or(Fate::NoRoute)?;
                if !nat.config.hairpin {
                    return Err(Fate::Filtered);
                }
                nat.expire(now);
                let inside = nat.admit(dst.port(), seen)?;
                let h = self.host_at(s, inside.ip()).ok_or(Fate::NoRoute)?;
                let due = Net::chain(now, rng, &[self.sites[s.0].lan])?;
                Ok(Arrival {
                    to: End::Host(h),
                    from: seen,
                    at: inside,
                    due,
                })
            }
            Dest::Nat(s) => {
                let nat = self.sites[s.0].nat.as_mut().ok_or(Fate::NoRoute)?;
                nat.expire(now);
                let inside = nat.admit(dst.port(), seen)?;
                let h = self.host_at(s, inside.ip()).ok_or(Fate::NoRoute)?;
                let due = Net::chain(now, rng, &[src_link, self.sites[s.0].uplink])?;
                Ok(Arrival {
                    to: End::Host(h),
                    from: seen,
                    at: inside,
                    due,
                })
            }
            Dest::Public(h, s) => {
                let due = Net::chain(now, rng, &[src_link, self.sites[s.0].uplink])?;
                Ok(Arrival {
                    to: End::Host(h),
                    from: seen,
                    at: dst,
                    due,
                })
            }
            Dest::Turn => {
                if dst.port() != PORT && !self.relayed.contains_key(&dst.port()) {
                    return Err(Fate::NoRoute);
                }
                let link = turn_link.ok_or(Fate::NoRoute)?;
                let due = Net::chain(now, rng, &[src_link, link])?;
                Ok(Arrival {
                    to: End::Turn,
                    from: seen,
                    at: dst,
                    due,
                })
            }
            Dest::Nowhere => Err(Fate::NoRoute),
        }
    }

    /// The address a STUN server on the internet would see for `src`, an address of `host`,
    /// creating the mapping as the binding request would; `None` behind a symmetric NAT, or if
    /// the NAT is of another address family.
    pub(super) fn reflexive(
        &mut self,
        now: Instant,
        host: HostId,
        src: SocketAddr,
    ) -> Option<SocketAddr> {
        let site = self.site_of(host, src.ip())?;
        let Some(nat) = self.sites[site.0].nat.as_mut() else {
            return Some(src);
        };
        if nat.config.kind == NatKind::Symmetric || nat.config.public.is_ipv4() != src.is_ipv4() {
            return None;
        }
        nat.expire(now);
        let key = (src, None);
        let next = &mut nat.next_port;
        let mapping = nat.mappings.entry(key).or_insert_with(|| {
            let port = *next;
            *next = if port == u16::MAX {
                FIRST_NAT_PORT
            } else {
                port + 1
            };
            Mapping {
                port,
                last_out: now,
                sent_to: HashSet::new(),
            }
        });
        mapping.last_out = now;
        Some(SocketAddr::new(nat.config.public, mapping.port))
    }

    /// Crosses `links` in turn.
    fn chain(now: Instant, rng: &mut SimRng, links: &[LinkConfig]) -> Result<Instant, Fate> {
        links.iter().try_fold(now, |at, l| Net::cross(at, rng, *l))
    }

    /// Lost or delayed on `link`, with jitter.
    pub(super) fn cross(now: Instant, rng: &mut SimRng, link: LinkConfig) -> Result<Instant, Fate> {
        if rng.chance(link.loss) {
            return Err(Fate::Lost);
        }
        let jitter = if link.jitter.is_zero() {
            Duration::ZERO
        } else {
            Duration::from_nanos(rng.below(link.jitter.as_nanos() as u64 + 1))
        };
        Ok(now + link.latency + jitter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn t(ms: u64) -> Instant {
        Instant::from_millis(ms)
    }

    fn link(ms: u64) -> LinkConfig {
        LinkConfig::latency(Duration::from_millis(ms))
    }

    struct World {
        net: Net,
        rng: SimRng,
        /// 10.0.0.2 behind NAT 1.1.1.1.
        a: HostId,
        /// 10.0.0.3 on A's site.
        a2: HostId,
        /// 192.168.1.5 behind NAT 2.2.2.2.
        b: HostId,
        /// 9.9.9.9 on the internet.
        c: HostId,
        site_a: SiteId,
    }

    fn world(a: NatKind, b: NatKind) -> World {
        let mut net = Net::new(link(10));
        let site_a = net.add_site(Some(NatConfig::new(a, ip("1.1.1.1"))), link(5), link(1));
        let site_b = net.add_site(Some(NatConfig::new(b, ip("2.2.2.2"))), link(7), link(1));
        let hosts = [
            (HostId(0), site_a, "10.0.0.2"),
            (HostId(1), site_a, "10.0.0.3"),
            (HostId(2), site_b, "192.168.1.5"),
            (HostId(3), INTERNET, "9.9.9.9"),
        ];
        for (h, s, i) in hosts {
            net.add_iface(h, s, ip(i));
        }
        World {
            net,
            rng: SimRng::new(1),
            a: HostId(0),
            a2: HostId(1),
            b: HostId(2),
            c: HostId(3),
            site_a,
        }
    }

    impl World {
        fn send(&mut self, now: u64, from: HostId, src: &str, dst: &str) -> Result<Arrival, Fate> {
            self.net
                .send(t(now), &mut self.rng, End::Host(from), sa(src), sa(dst))
        }
    }

    const A: &str = "10.0.0.2:51820";
    const A2: &str = "10.0.0.3:51820";
    const B: &str = "192.168.1.5:51820";
    const C: &str = "9.9.9.9:51820";

    #[test]
    fn an_open_nat_maps_once_and_lets_anyone_in() {
        let mut w = world(NatKind::Open, NatKind::Open);
        let out = w.send(0, w.a, A, C).unwrap();
        assert_eq!(out.to, End::Host(w.c));
        assert_eq!(out.from.ip(), ip("1.1.1.1"));
        assert_eq!(out.due, t(15));
        let mapped = out.from;
        let again = w.send(1, w.a, A, "2.2.2.2:4000");
        assert_eq!(again, Err(Fate::NoRoute), "B has no mapping yet");
        let other = w.send(2, w.a, A, C).unwrap();
        assert_eq!(other.from, mapped, "one mapping for every destination");
        let reply = w
            .net
            .send(t(3), &mut w.rng, End::Host(w.c), sa(C), mapped)
            .unwrap();
        assert_eq!(reply.to, End::Host(w.a));
        assert_eq!(reply.at, sa(A));
        assert_eq!(reply.from, sa(C));
        assert_eq!(reply.due, t(3 + 10 + 5));
        let unknown = sa("8.8.8.8:51820");
        assert_eq!(
            w.send(4, w.a, A, &unknown.to_string()),
            Err(Fate::NoRoute),
            "no host there"
        );
    }

    #[test]
    fn a_port_restricted_nat_lets_in_only_who_was_sent_to() {
        let mut w = world(NatKind::PortRestricted, NatKind::PortRestricted);
        let mapped = w.send(0, w.a, A, C).unwrap().from;
        let from_b_side = w
            .net
            .reflexive(t(0), w.b, sa(B))
            .expect("B is behind a mapping NAT");
        let stranger = w.net.send(t(1), &mut w.rng, End::Host(w.b), sa(B), mapped);
        assert_eq!(stranger, Err(Fate::Filtered));
        let again = w.send(2, w.a, A, &from_b_side.to_string()).unwrap();
        assert_eq!(again.from, mapped, "same mapping for every destination");
        let reply = w
            .net
            .send(t(3), &mut w.rng, End::Host(w.b), sa(B), mapped)
            .unwrap();
        assert_eq!(reply.to, End::Host(w.a));
        assert_eq!(reply.at, sa(A));
        assert_eq!(reply.from, from_b_side);
        assert_eq!(
            w.send(3, w.a, A, "9.9.9.9:1000"),
            Err(Fate::NoRoute),
            "not the port of a host socket"
        );
        let c_reply = w
            .net
            .send(t(4), &mut w.rng, End::Host(w.c), sa(C), mapped)
            .unwrap();
        assert_eq!(c_reply.to, End::Host(w.a), "C was sent to");
    }

    #[test]
    fn a_symmetric_nat_maps_per_destination() {
        let mut w = world(NatKind::Symmetric, NatKind::Open);
        let to_c = w.send(0, w.a, A, C).unwrap().from;
        let b_public = w.net.reflexive(t(0), w.b, sa(B)).unwrap();
        let to_b = w.send(1, w.a, A, &b_public.to_string()).unwrap().from;
        assert_ne!(to_c, to_b);
        assert_eq!(to_c.ip(), to_b.ip());
        assert_eq!(
            w.net.reflexive(t(2), w.a, sa(A)),
            None,
            "a binding request gets no endpoint-independent address"
        );
        let wrong = w.net.send(t(3), &mut w.rng, End::Host(w.c), sa(C), to_b);
        assert_eq!(
            wrong,
            Err(Fate::Filtered),
            "C was not sent to from that mapping"
        );
        let right = w
            .net
            .send(t(4), &mut w.rng, End::Host(w.c), sa(C), to_c)
            .unwrap();
        assert_eq!(right.at, sa(A));
        assert_eq!(
            w.net
                .send(t(5), &mut w.rng, End::Host(w.b), sa(B), to_b)
                .unwrap()
                .at,
            sa(A)
        );
    }

    #[test]
    fn a_host_without_a_nat_reflects_itself() {
        let mut w = world(NatKind::Open, NatKind::Open);
        assert_eq!(w.net.reflexive(t(0), w.c, sa(C)), Some(sa(C)));
        let mapped = w.net.reflexive(t(0), w.a, sa(A)).unwrap();
        assert_eq!(mapped.ip(), ip("1.1.1.1"));
        assert_eq!(w.net.reflexive(t(1), w.a, sa(A)), Some(mapped));
    }

    #[test]
    fn hairpinning_turns_a_datagram_back_inside_or_drops_it() {
        let mut w = world(NatKind::Open, NatKind::Open);
        let a_pub = w.net.reflexive(t(0), w.a, sa(A)).unwrap();
        let a2_pub = w.net.reflexive(t(0), w.a2, sa(A2)).unwrap();
        assert_eq!(
            w.send(1, w.a, A, &a2_pub.to_string()),
            Err(Fate::Filtered),
            "off by default"
        );
        let site = w.site_a;
        w.net.sites[site.0].nat.as_mut().unwrap().config.hairpin = true;
        let got = w.send(2, w.a, A, &a2_pub.to_string()).unwrap();
        assert_eq!(got.to, End::Host(w.a2));
        assert_eq!(got.at, sa(A2));
        assert_eq!(got.from, a_pub, "seen from its public address");
        assert_eq!(got.due, t(3), "one LAN crossing");
    }

    #[test]
    fn a_hairpin_obeys_the_filter_of_a_restricting_nat() {
        let mut w = world(NatKind::PortRestricted, NatKind::Open);
        let site = w.site_a;
        w.net.sites[site.0].nat.as_mut().unwrap().config.hairpin = true;
        let a_pub = w.net.reflexive(t(0), w.a, sa(A)).unwrap();
        let a2_pub = w.net.reflexive(t(0), w.a2, sa(A2)).unwrap();
        assert_eq!(w.send(1, w.a, A, &a2_pub.to_string()), Err(Fate::Filtered));
        let back = w
            .net
            .send(t(2), &mut w.rng, End::Host(w.a2), sa(A2), a_pub)
            .map(|a| a.to);
        assert_eq!(
            back,
            Ok(End::Host(w.a)),
            "A2 now sends to A's public address"
        );
    }

    #[test]
    fn rebinding_gives_new_ports() {
        let mut w = world(NatKind::PortRestricted, NatKind::Open);
        let first = w.send(0, w.a, A, C).unwrap().from;
        let site = w.site_a;
        w.net.rebind(site);
        let reply = w.net.send(t(1), &mut w.rng, End::Host(w.c), sa(C), first);
        assert_eq!(reply, Err(Fate::NoRoute), "the old port is gone");
        let second = w.send(2, w.a, A, C).unwrap().from;
        assert_eq!(first.ip(), second.ip());
        assert_ne!(first.port(), second.port());
        assert_eq!(w.net.reflexive(t(3), w.a, sa(A)), Some(second));
    }

    #[test]
    fn a_mapping_times_out_after_silence() {
        let mut w = world(NatKind::Open, NatKind::Open);
        let site = w.site_a;
        w.net.sites[site.0].nat.as_mut().unwrap().config.timeout = Duration::from_secs(10);
        let first = w.send(0, w.a, A, C).unwrap().from;
        w.send(9_000, w.a, A, C).unwrap();
        let alive = w
            .net
            .send(t(18_000), &mut w.rng, End::Host(w.c), sa(C), first);
        assert!(alive.is_ok(), "refreshed by the send at 9 s");
        let dead = w
            .net
            .send(t(30_000), &mut w.rng, End::Host(w.c), sa(C), first);
        assert_eq!(dead, Err(Fate::NoRoute));
        let second = w.send(30_001, w.a, A, C).unwrap().from;
        assert_ne!(first.port(), second.port());
    }

    #[test]
    fn the_lan_is_reached_without_the_nat() {
        let mut w = world(NatKind::Symmetric, NatKind::Open);
        let got = w.send(0, w.a, A, A2).unwrap();
        assert_eq!(got.to, End::Host(w.a2));
        assert_eq!(got.from, sa(A), "no translation");
        assert_eq!(got.at, sa(A2));
        assert_eq!(got.due, t(1), "the site's LAN link, once");
        let site = w.site_a;
        assert!(
            w.net.sites[site.0]
                .nat
                .as_ref()
                .unwrap()
                .mappings
                .is_empty(),
            "the NAT saw nothing"
        );
    }

    #[test]
    fn a_block_is_one_directional() {
        let mut w = world(NatKind::Open, NatKind::Open);
        w.net.block(End::Host(w.a), End::Host(w.c), true);
        assert_eq!(w.send(0, w.a, A, C), Err(Fate::Blocked));
        let site = w.site_a;
        assert!(
            w.net.sites[site.0]
                .nat
                .as_ref()
                .unwrap()
                .mappings
                .is_empty(),
            "a blocked datagram creates no mapping"
        );
        let reply = w
            .net
            .send(t(1), &mut w.rng, End::Host(w.c), sa(C), sa("1.1.1.1:4000"));
        assert_eq!(
            reply,
            Err(Fate::NoRoute),
            "the other way is not blocked, just unmapped"
        );
        w.net.block(End::Host(w.a), End::Host(w.c), false);
        assert!(w.send(2, w.a, A, C).is_ok());
    }

    #[test]
    fn full_loss_drops_everything_and_jitter_reorders() {
        let mut w = world(NatKind::Open, NatKind::Open);
        w.net.sites[INTERNET.0].uplink.loss = 1.0;
        for i in 0..20 {
            assert_eq!(w.send(i, w.a, A, C), Err(Fate::Lost));
        }
        w.net.sites[INTERNET.0].uplink.loss = 0.0;
        w.net.sites[INTERNET.0].uplink.jitter = Duration::from_millis(50);
        let dues: Vec<Instant> = (0..30).map(|i| w.send(i, w.a, A, C).unwrap().due).collect();
        assert!(
            dues.windows(2).any(|p| p[1] < p[0]),
            "a later datagram overtakes an earlier one"
        );
        assert!(dues.iter().all(|d| *d >= t(5 + 10)));
    }

    #[test]
    fn the_turn_server_and_its_relayed_addresses() {
        let mut w = world(NatKind::PortRestricted, NatKind::Open);
        w.net.turn = Some((ip("198.51.100.1"), link(3)));
        let relayed = w.net.allocate(w.c).unwrap();
        let server = sa("198.51.100.1:51820");
        let to_server = w.send(0, w.a, A, &server.to_string()).unwrap();
        assert_eq!(to_server.to, End::Turn);
        assert_eq!(to_server.due, t(5 + 3));
        let mapped = to_server.from;
        let to_relayed = w.send(1, w.a, A, &relayed.to_string()).unwrap();
        assert_eq!((to_relayed.to, to_relayed.at), (End::Turn, relayed));
        assert_eq!(
            w.send(2, w.a, A, "198.51.100.1:9"),
            Err(Fate::NoRoute),
            "no such relayed port"
        );
        let back = w
            .net
            .send(t(3), &mut w.rng, End::Turn, server, mapped)
            .unwrap();
        assert_eq!(back.to, End::Host(w.a));
        assert_eq!(back.due, t(3 + 3 + 5));
        w.net.release(relayed);
        assert_eq!(w.send(4, w.a, A, &relayed.to_string()), Err(Fate::NoRoute));
    }

    #[test]
    fn a_hop_to_a_down_interface_goes_nowhere() {
        let mut w = world(NatKind::Open, NatKind::Open);
        assert!(w.net.set_iface(w.c, ip("9.9.9.9"), false));
        assert_eq!(w.send(0, w.a, A, C), Err(Fate::NoRoute));
        assert_eq!(w.net.source(w.c, sa(A)), None);
    }
}
