//! Announcement, window rotation and matching, independent of the transport (vv-09 §2), and the
//! choice of one LAN route per peer and interface (vv-09 §2.3).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use rand_core::CryptoRng;
use vardevall_proto::discovery::candidate::Candidate;
use vardevall_proto::discovery::mdns::{self, Announcement, TagTable, WINDOW_SECONDS};
use vardevall_proto::keys::crypto::XNONCE_LEN;
use vardevall_proto::keys::{NetworkSecret, NodePublic};

use super::{Found, MdnsEvent, MdnsRequest, SERVICE_TYPE};
use crate::candidates::{MDNS_SOURCE as SOURCE, SourceKey, Update};

/// Most browse results kept; later ones are ignored until others are lost.
const MAX_INSTANCES: usize = 256;

/// How long an instance reported lost stays offered. The advertisement of a device without
/// network (an iPhone) is withdrawn and announced again every few seconds, and acting on each
/// loss would flip the route between the LAN and the internet.
pub(crate) const LOST_HOLD_SECONDS: u64 = 10;

/// The addresses of one announcement on one local interface, best first, and the one offered
/// to the controller.
struct Offer {
    ranked: Vec<Candidate>,
    offered: usize,
}

impl Offer {
    fn offered(&self) -> Candidate {
        self.ranked[self.offered]
    }
}

/// A resolved announcement: the peer and, per local interface, its addresses.
struct Lan {
    peer: NodePublic,
    port: u16,
    ifaces: BTreeMap<u32, Offer>,
    /// When the transport reported the instance lost, while it is still offered.
    lost_at: Option<u64>,
    /// The candidates and spares last handed out.
    reported: Option<(Vec<Candidate>, Vec<Candidate>)>,
}

/// The state of mDNS discovery for one interface.
pub(crate) struct Discovery {
    network: NetworkSecret,
    node: NodePublic,
    port: u16,
    accept_members: bool,
    peers: Vec<NodePublic>,
    table: TagTable,
    registered: Option<Announcement>,
    host_addrs: Vec<IpAddr>,
    resolved: HashMap<String, Lan>,
    requests: VecDeque<MdnsRequest>,
    updates: VecDeque<Update>,
}

fn nonce<R: CryptoRng>(rng: &mut R) -> [u8; XNONCE_LEN] {
    let mut n = [0u8; XNONCE_LEN];
    rng.fill_bytes(&mut n);
    n
}

fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// Position of an address in the order of vv-09 §2.3: IPv6 link-local, IPv6 unique-local, any
/// other IPv6, IPv4.
fn rank(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V6(a) if is_link_local_v6(a) => 0,
        IpAddr::V6(a) if a.segments()[0] & 0xfe00 == 0xfc00 => 1,
        IpAddr::V6(_) => 2,
        IpAddr::V4(_) => 3,
    }
}

/// The addresses of an announcement, best first. A link-local address is usable only when
/// `scoped`, that is, when the interface it arrived on is known.
fn ranked(addrs: &[IpAddr], scoped: bool) -> Vec<IpAddr> {
    let mut list: Vec<IpAddr> = addrs
        .iter()
        .filter(|ip| scoped || !matches!(ip, IpAddr::V6(a) if is_link_local_v6(a)))
        .copied()
        .collect();
    list.sort_by_key(|ip| (rank(ip), *ip));
    list.dedup();
    list
}

impl Discovery {
    /// Prepares discovery of the key-trusted `peers` at `unix_seconds`.
    pub(crate) fn new(
        network: NetworkSecret,
        node: NodePublic,
        port: u16,
        accept_members: bool,
        peers: Vec<NodePublic>,
        unix_seconds: u64,
    ) -> Self {
        let table = TagTable::new(&network, &peers, accept_members, unix_seconds);
        Discovery {
            network,
            node,
            port,
            accept_members,
            peers,
            table,
            registered: None,
            host_addrs: Vec::new(),
            resolved: HashMap::new(),
            requests: VecDeque::new(),
            updates: VecDeque::new(),
        }
    }

    /// Replaces the key-trusted peers announcements are matched to.
    pub(crate) fn set_peers(&mut self, peers: Vec<NodePublic>, unix_seconds: u64) {
        self.peers = peers;
        self.table = TagTable::new(
            &self.network,
            &self.peers,
            self.accept_members,
            unix_seconds,
        );
    }

    /// Sets the addresses of this host, used to recognise same-host announcements (vv-09 §2.2).
    pub(crate) fn set_host_addrs(&mut self, addrs: Vec<IpAddr>) {
        self.host_addrs = addrs;
    }

    /// Announces this node and starts browsing.
    pub(crate) fn start<R: CryptoRng>(&mut self, unix_seconds: u64, rng: &mut R) {
        self.register(unix_seconds, rng);
        self.requests.push_back(MdnsRequest::Browse);
    }

    fn register<R: CryptoRng>(&mut self, unix_seconds: u64, rng: &mut R) {
        let a = Announcement::new(
            &self.network,
            &self.node,
            unix_seconds,
            &nonce(rng),
            self.port,
        );
        self.requests.push_back(register_request(&a));
        self.registered = Some(a);
    }

    /// Rotates the announcement and tag tables if the window changed.
    pub(crate) fn tick<R: CryptoRng>(&mut self, unix_seconds: u64, rng: &mut R) {
        self.expire(unix_seconds);
        let current = mdns::window(unix_seconds);
        let Some(old) = &self.registered else { return };
        if old.window == current {
            return;
        }
        self.requests.push_back(MdnsRequest::Unregister {
            instance: old.instance(),
        });
        self.table = TagTable::new(
            &self.network,
            &self.peers,
            self.accept_members,
            unix_seconds,
        );
        self.register(unix_seconds, rng);
    }

    /// Time until the next window starts or a lost instance's hold ends, whichever is first.
    pub(crate) fn next_tick_in(&self, unix_seconds: u64) -> Duration {
        let mut next = (mdns::window(unix_seconds) + 1) * WINDOW_SECONDS;
        let hold_ends = self
            .resolved
            .values()
            .filter_map(|l| l.lost_at)
            .map(|at| at + LOST_HOLD_SECONDS)
            .min();
        if let Some(end) = hold_ends {
            next = next.min(end.max(unix_seconds + 1));
        }
        Duration::from_secs(next - unix_seconds)
    }

    fn expire(&mut self, unix_seconds: u64) {
        let due: Vec<String> = self
            .resolved
            .iter()
            .filter(|(_, l)| {
                l.lost_at
                    .is_some_and(|at| at + LOST_HOLD_SECONDS <= unix_seconds)
            })
            .map(|(i, _)| i.clone())
            .collect();
        for instance in due {
            if let Some(lan) = self.resolved.remove(&instance) {
                self.updates.push_back(Update {
                    peer: lan.peer,
                    source: SourceKey::Discovery {
                        source: SOURCE,
                        group: instance,
                    },
                    candidates: Vec::new(),
                    spare: Vec::new(),
                });
            }
        }
    }

    /// Announces again after an address change (vv-09 §2.1).
    pub(crate) fn refresh<R: CryptoRng>(&mut self, unix_seconds: u64, rng: &mut R) {
        if self.registered.is_some() {
            self.register(unix_seconds, rng);
        }
    }

    /// Withdraws the announcement and stops browsing.
    pub(crate) fn stop(&mut self) {
        if let Some(a) = self.registered.take() {
            self.requests.push_back(MdnsRequest::Unregister {
                instance: a.instance(),
            });
            self.requests.push_back(MdnsRequest::StopBrowse);
        }
    }

    /// Takes the next request for the transport.
    pub(crate) fn pop_request(&mut self) -> Option<MdnsRequest> {
        self.requests.pop_front()
    }

    /// Takes the next candidate update.
    pub(crate) fn pop_update(&mut self) -> Option<Update> {
        self.updates.pop_front()
    }

    /// Processes a browse result.
    ///
    /// A loss keeps the instance offered for [`LOST_HOLD_SECONDS`]; [`Self::tick`] ends the hold.
    pub(crate) fn event(&mut self, event: MdnsEvent, unix_seconds: u64) {
        self.expire(unix_seconds);
        match event {
            MdnsEvent::Found(f) => self.found(f),
            MdnsEvent::Lost { instance } => {
                if let Some(lan) = self.resolved.get_mut(&instance) {
                    lan.lost_at.get_or_insert(unix_seconds);
                }
            }
        }
    }

    fn found(&mut self, f: Found) {
        if self
            .registered
            .as_ref()
            .is_some_and(|a| a.instance() == f.instance)
        {
            return;
        }
        let strings: Vec<String> = f.txt.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let Some(tags) = mdns::parse_txt(&strings) else {
            return;
        };
        let Some(m) = self.table.matches(&tags) else {
            return;
        };
        let peer = *m.node();
        if peer == self.node {
            return;
        }
        if !self.resolved.contains_key(&f.instance) && self.resolved.len() >= MAX_INSTANCES {
            return;
        }
        let ranked = self.rank_candidates(&f);
        let lan = self.resolved.entry(f.instance.clone()).or_insert(Lan {
            peer,
            port: f.port,
            ifaces: BTreeMap::new(),
            lost_at: None,
            reported: None,
        });
        lan.peer = peer;
        lan.port = f.port;
        let returned = lan.lost_at.take().is_some();
        if returned {
            lan.ifaces.clear();
        }
        match ranked {
            None => {
                lan.ifaces.remove(&f.ifindex);
            }
            Some(list) => {
                let offered = lan.ifaces.get(&f.ifindex).and_then(|o| {
                    let current = o.offered().addr;
                    list.iter().position(|c| c.addr == current)
                });
                lan.ifaces.insert(
                    f.ifindex,
                    Offer {
                        ranked: list,
                        offered: offered.unwrap_or(0),
                    },
                );
            }
        }
        self.push_update(&f.instance, returned);
    }

    /// The candidates for the addresses of `f`, best first: one per address, or, when the
    /// announcement comes from this host, `local` candidates at the loopback of the families of
    /// those addresses, the family of the best one first (vv-09 §2.2 step 4).
    fn rank_candidates(&self, f: &Found) -> Option<Vec<Candidate>> {
        if f.addrs.iter().any(|ip| self.host_addrs.contains(ip)) {
            let mut out: Vec<Candidate> = Vec::new();
            for ip in &ranked(&f.addrs, true) {
                let loopback: IpAddr = match ip {
                    IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
                    IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
                };
                let c = Candidate::same_host(SocketAddr::new(loopback, f.port));
                if !out.contains(&c) {
                    out.push(c);
                }
            }
            return (!out.is_empty()).then_some(out);
        }
        let addrs = ranked(&f.addrs, f.ifindex != 0);
        if addrs.is_empty() {
            return None;
        }
        Some(
            addrs
                .into_iter()
                .map(|ip| {
                    let addr = match ip {
                        IpAddr::V6(v6) if is_link_local_v6(&v6) => {
                            SocketAddr::V6(SocketAddrV6::new(v6, f.port, 0, f.ifindex))
                        }
                        ip => SocketAddr::new(ip, f.port),
                    };
                    Candidate::lan(addr)
                })
                .collect(),
        )
    }

    /// Queues the update for `instance`: the offered address of every interface, and the others
    /// as spares.
    /// With `unless_same`, nothing is queued when it equals what was last handed out.
    fn push_update(&mut self, instance: &str, unless_same: bool) {
        let Some(lan) = self.resolved.get_mut(instance) else {
            return;
        };
        let mut candidates: Vec<Candidate> = Vec::new();
        let mut spare: Vec<Candidate> = Vec::new();
        for o in lan.ifaces.values() {
            let c = o.offered();
            if !candidates.contains(&c) {
                candidates.push(c);
            }
        }
        for o in lan.ifaces.values() {
            for (i, c) in o.ranked.iter().enumerate() {
                if i != o.offered && !candidates.contains(c) && !spare.contains(c) {
                    spare.push(*c);
                }
            }
        }
        let now = (candidates, spare);
        if unless_same && lan.reported.as_ref() == Some(&now) {
            return;
        }
        let (candidates, spare) = now.clone();
        lan.reported = Some(now);
        self.updates.push_back(Update {
            peer: lan.peer,
            source: SourceKey::Discovery {
                source: SOURCE,
                group: instance.to_owned(),
            },
            candidates,
            spare,
        });
    }

    /// The route to `addr` of `peer` failed (vv-05 §4.9): of the interfaces that offered it, the
    /// next address is offered.
    pub(crate) fn route_failed(&mut self, peer: &NodePublic, addr: SocketAddr) {
        let mut changed: Vec<String> = Vec::new();
        for (instance, lan) in &mut self.resolved {
            if lan.peer != *peer {
                continue;
            }
            let mut moved = false;
            for o in lan.ifaces.values_mut() {
                if o.ranked.len() > 1 && o.offered().addr == addr {
                    o.offered = (o.offered + 1) % o.ranked.len();
                    moved = true;
                }
            }
            if moved {
                changed.push(instance.clone());
            }
        }
        for instance in changed {
            self.push_update(&instance, false);
        }
    }
}

fn register_request(a: &Announcement) -> MdnsRequest {
    let txt = a
        .txt_strings()
        .into_iter()
        .map(|s| match s.split_once('=') {
            Some((k, v)) => (k.to_owned(), v.to_owned()),
            None => (s, String::new()),
        })
        .collect();
    MdnsRequest::Register {
        instance: a.instance(),
        service_type: SERVICE_TYPE.to_owned(),
        port: a.port,
        txt,
    }
}

#[cfg(test)]
mod tests {
    use vardevall_proto::discovery::candidate::label;
    use vardevall_proto::keys::NodeSecret;

    use super::*;
    use crate::net::rng::os_rng;

    const NOW: u64 = 1_789_300_000;

    struct Side {
        secret: NodeSecret,
        d: Discovery,
    }

    fn side(net: &NetworkSecret, peers: &[NodePublic], members: bool, port: u16) -> Side {
        let secret = NodeSecret::generate(&mut os_rng());
        let d = Discovery::new(
            net.clone(),
            secret.public(),
            port,
            members,
            peers.to_vec(),
            NOW,
        );
        Side { secret, d }
    }

    fn announce(s: &mut Side) -> Found {
        s.d.start(NOW, &mut os_rng());
        let Some(MdnsRequest::Register {
            instance,
            port,
            txt,
            service_type,
        }) = s.d.pop_request()
        else {
            panic!("no register");
        };
        assert_eq!(service_type, SERVICE_TYPE);
        assert_eq!(s.d.pop_request(), Some(MdnsRequest::Browse));
        assert_eq!(
            txt.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            ["v", "n", "k", "p"]
        );
        Found {
            instance,
            txt,
            port,
            addrs: vec!["192.168.1.9".parse().unwrap()],
            ifindex: 4,
        }
    }

    #[test]
    fn matches_configured_peer() {
        let net = NetworkSecret::generate(&mut os_rng());
        let mut a = side(&net, &[], false, 1111);
        let mut b = side(&net, &[a.secret.public()], false, 2222);
        let found = announce(&mut a);
        b.d.event(MdnsEvent::Found(found.clone()), NOW);
        let u = b.d.pop_update().unwrap();
        assert_eq!(u.peer, a.secret.public());
        assert_eq!(u.candidates.len(), 1);
        assert_eq!(u.candidates[0].label, label::LAN);
        assert_eq!(u.candidates[0].addr, "192.168.1.9:1111".parse().unwrap());
        b.d.event(
            MdnsEvent::Lost {
                instance: found.instance,
            },
            NOW,
        );
        assert!(b.d.pop_update().is_none());
        b.d.tick(NOW + LOST_HOLD_SECONDS, &mut os_rng());
        assert!(b.d.pop_update().unwrap().candidates.is_empty());
    }

    #[test]
    fn member_only_with_accept_members() {
        let net = NetworkSecret::generate(&mut os_rng());
        let mut a = side(&net, &[], false, 1111);
        let found = announce(&mut a);
        let mut strict = side(&net, &[], false, 2222);
        strict.d.event(MdnsEvent::Found(found.clone()), NOW);
        assert!(strict.d.pop_update().is_none());
        let mut open = side(&net, &[], true, 2222);
        open.d.event(MdnsEvent::Found(found), NOW);
        let u = open.d.pop_update().unwrap();
        assert_eq!(u.peer, a.secret.public());
    }

    #[test]
    fn ignores_other_networks_and_self() {
        let net = NetworkSecret::generate(&mut os_rng());
        let other = NetworkSecret::generate(&mut os_rng());
        let mut a = side(&other, &[], false, 1111);
        let mut b = side(&net, &[a.secret.public()], true, 2222);
        let found = announce(&mut a);
        b.d.event(MdnsEvent::Found(found), NOW);
        assert!(b.d.pop_update().is_none());
        let own = announce(&mut b);
        b.d.event(MdnsEvent::Found(own), NOW);
        assert!(b.d.pop_update().is_none());
    }

    #[test]
    fn own_addresses_become_local_loopback() {
        let net = NetworkSecret::generate(&mut os_rng());
        let mut a = side(&net, &[], false, 1111);
        let mut b = side(&net, &[a.secret.public()], false, 2222);
        b.d.set_host_addrs(vec!["192.168.1.9".parse().unwrap()]);
        let found = announce(&mut a);
        b.d.event(MdnsEvent::Found(found), NOW);
        let u = b.d.pop_update().unwrap();
        assert_eq!(u.candidates[0].label, label::LOCAL);
        assert_eq!(u.candidates[0].addr, "127.0.0.1:1111".parse().unwrap());
    }

    #[test]
    fn link_local_needs_scope() {
        let net = NetworkSecret::generate(&mut os_rng());
        let mut a = side(&net, &[], false, 1111);
        let mut b = side(&net, &[a.secret.public()], false, 2222);
        let mut found = announce(&mut a);
        found.addrs = vec!["fe80::1".parse().unwrap()];
        found.ifindex = 0;
        b.d.event(MdnsEvent::Found(found.clone()), NOW);
        assert!(b.d.pop_update().unwrap().candidates.is_empty());
        found.ifindex = 7;
        b.d.event(MdnsEvent::Found(found), NOW);
        let u = b.d.pop_update().unwrap();
        let SocketAddr::V6(v6) = u.candidates[0].addr else {
            panic!()
        };
        assert_eq!(v6.scope_id(), 7);
    }

    fn lan_pair() -> (Side, Side, Found) {
        let net = NetworkSecret::generate(&mut os_rng());
        let mut a = side(&net, &[], false, 1111);
        let b = side(&net, &[a.secret.public()], false, 2222);
        let found = announce(&mut a);
        (a, b, found)
    }

    fn addrs(u: &Update) -> Vec<String> {
        u.candidates.iter().map(|c| c.addr.to_string()).collect()
    }

    fn spare(u: &Update) -> Vec<String> {
        u.spare.iter().map(|c| c.addr.to_string()).collect()
    }

    const LAN: [&str; 5] = [
        "192.168.1.9",
        "2001:db8::9",
        "fd00::9",
        "fe80::9",
        "fd00::1",
    ];

    fn lan() -> Vec<IpAddr> {
        LAN.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn offers_the_best_address_of_an_interface_and_keeps_the_rest_as_spares() {
        let (_a, mut b, mut found) = lan_pair();
        found.addrs = lan();
        found.ifindex = 7;
        b.d.event(MdnsEvent::Found(found), NOW);
        let u = b.d.pop_update().unwrap();
        assert_eq!(addrs(&u), ["[fe80::9%7]:1111"]);
        assert_eq!(
            spare(&u),
            [
                "[fd00::1]:1111",
                "[fd00::9]:1111",
                "[2001:db8::9]:1111",
                "192.168.1.9:1111"
            ]
        );
        assert!(u.candidates.iter().all(|c| c.label == label::LAN));
    }

    #[test]
    fn without_an_interface_link_local_addresses_are_not_usable() {
        let (_a, mut b, mut found) = lan_pair();
        found.addrs = lan();
        found.ifindex = 0;
        b.d.event(MdnsEvent::Found(found), NOW);
        let u = b.d.pop_update().unwrap();
        assert_eq!(addrs(&u), ["[fd00::1]:1111"]);
        assert_eq!(
            spare(&u),
            ["[fd00::9]:1111", "[2001:db8::9]:1111", "192.168.1.9:1111"]
        );
    }

    #[test]
    fn a_failed_route_offers_the_next_address_and_wraps() {
        let (a, mut b, mut found) = lan_pair();
        let peer = a.secret.public();
        found.addrs = vec!["192.168.1.9".parse().unwrap(), "fd00::9".parse().unwrap()];
        b.d.event(MdnsEvent::Found(found), NOW);
        let first = b.d.pop_update().unwrap();
        assert_eq!(addrs(&first), ["[fd00::9]:1111"]);
        b.d.route_failed(&peer, "192.168.1.9:1111".parse().unwrap());
        assert!(b.d.pop_update().is_none(), "only the offered route counts");
        b.d.route_failed(&peer, "[fd00::9]:1111".parse().unwrap());
        let second = b.d.pop_update().unwrap();
        assert_eq!(addrs(&second), ["192.168.1.9:1111"]);
        assert_eq!(spare(&second), ["[fd00::9]:1111"]);
        b.d.route_failed(&peer, "192.168.1.9:1111".parse().unwrap());
        assert_eq!(addrs(&b.d.pop_update().unwrap()), ["[fd00::9]:1111"]);
        let stranger = NodePublic::from_bytes([9; 32]);
        b.d.route_failed(&stranger, "[fd00::9]:1111".parse().unwrap());
        assert!(b.d.pop_update().is_none());
    }

    #[test]
    fn a_single_address_has_no_next_one() {
        let (a, mut b, found) = lan_pair();
        b.d.event(MdnsEvent::Found(found), NOW);
        let _ = b.d.pop_update().unwrap();
        b.d.route_failed(&a.secret.public(), "192.168.1.9:1111".parse().unwrap());
        assert!(b.d.pop_update().is_none());
    }

    #[test]
    fn the_offer_stays_while_its_address_is_announced() {
        let (_a, mut b, mut found) = lan_pair();
        b.d.event(MdnsEvent::Found(found.clone()), NOW);
        assert_eq!(addrs(&b.d.pop_update().unwrap()), ["192.168.1.9:1111"]);
        found.addrs.push("fd00::9".parse().unwrap());
        b.d.event(MdnsEvent::Found(found.clone()), NOW);
        let u = b.d.pop_update().unwrap();
        assert_eq!(addrs(&u), ["192.168.1.9:1111"], "no switch to a better one");
        assert_eq!(spare(&u), ["[fd00::9]:1111"]);
        found.addrs = vec!["fd00::9".parse().unwrap()];
        b.d.event(MdnsEvent::Found(found), NOW);
        assert_eq!(addrs(&b.d.pop_update().unwrap()), ["[fd00::9]:1111"]);
    }

    #[test]
    fn each_interface_gets_one_route() {
        let (_a, mut b, mut found) = lan_pair();
        found.addrs = vec!["192.168.1.9".parse().unwrap(), "fd00::9".parse().unwrap()];
        found.ifindex = 4;
        b.d.event(MdnsEvent::Found(found.clone()), NOW);
        found.addrs = vec!["10.1.1.9".parse().unwrap()];
        found.ifindex = 9;
        b.d.event(MdnsEvent::Found(found), NOW);
        let _ = b.d.pop_update().unwrap();
        let u = b.d.pop_update().unwrap();
        assert_eq!(addrs(&u), ["[fd00::9]:1111", "10.1.1.9:1111"]);
        assert_eq!(spare(&u), ["192.168.1.9:1111"]);
    }

    #[test]
    fn a_match_on_this_host_uses_the_loopback_of_the_best_family() {
        let (_a, mut b, mut found) = lan_pair();
        b.d.set_host_addrs(vec![
            "192.168.1.9".parse().unwrap(),
            "fd00::9".parse().unwrap(),
        ]);
        found.addrs = vec!["192.168.1.9".parse().unwrap(), "fd00::9".parse().unwrap()];
        b.d.event(MdnsEvent::Found(found.clone()), NOW);
        let u = b.d.pop_update().unwrap();
        assert_eq!(addrs(&u), ["[::1]:1111"]);
        assert_eq!(spare(&u), ["127.0.0.1:1111"]);
        assert!(
            u.candidates
                .iter()
                .chain(&u.spare)
                .all(|c| c.label == label::LOCAL)
        );
        found.addrs = vec!["192.168.1.9".parse().unwrap()];
        b.d.event(MdnsEvent::Found(found), NOW);
        let u = b.d.pop_update().unwrap();
        assert_eq!(addrs(&u), ["127.0.0.1:1111"]);
        assert!(u.spare.is_empty());
    }

    fn lost(found: &Found) -> MdnsEvent {
        MdnsEvent::Lost {
            instance: found.instance.clone(),
        }
    }

    #[test]
    fn a_flap_shorter_than_the_hold_changes_nothing() {
        let (_a, mut b, found) = lan_pair();
        b.d.event(MdnsEvent::Found(found.clone()), NOW);
        assert_eq!(addrs(&b.d.pop_update().unwrap()), ["192.168.1.9:1111"]);
        b.d.event(lost(&found), NOW + 1);
        b.d.tick(NOW + 1 + LOST_HOLD_SECONDS - 1, &mut os_rng());
        assert!(b.d.pop_update().is_none());
        b.d.event(MdnsEvent::Found(found.clone()), NOW + LOST_HOLD_SECONDS - 1);
        assert!(b.d.pop_update().is_none());
        b.d.tick(NOW + 5 * LOST_HOLD_SECONDS, &mut os_rng());
        assert!(b.d.pop_update().is_none(), "the hold ended with the return");
        b.d.event(lost(&found), NOW + 6 * LOST_HOLD_SECONDS);
        b.d.event(lost(&found), NOW + 6 * LOST_HOLD_SECONDS + 5);
        b.d.tick(NOW + 7 * LOST_HOLD_SECONDS - 1, &mut os_rng());
        assert!(b.d.pop_update().is_none(), "a second loss does not extend");
        b.d.tick(NOW + 7 * LOST_HOLD_SECONDS, &mut os_rng());
        assert!(b.d.pop_update().unwrap().candidates.is_empty());
    }

    #[test]
    fn a_loss_longer_than_the_hold_withdraws_once() {
        let (a, mut b, found) = lan_pair();
        b.d.event(MdnsEvent::Found(found.clone()), NOW);
        let _ = b.d.pop_update().unwrap();
        b.d.event(lost(&found), NOW);
        b.d.tick(NOW + LOST_HOLD_SECONDS - 1, &mut os_rng());
        assert!(b.d.pop_update().is_none());
        b.d.tick(NOW + LOST_HOLD_SECONDS, &mut os_rng());
        let u = b.d.pop_update().unwrap();
        assert_eq!(u.peer, a.secret.public());
        assert!(u.candidates.is_empty() && u.spare.is_empty());
        b.d.tick(NOW + 2 * LOST_HOLD_SECONDS, &mut os_rng());
        assert!(b.d.pop_update().is_none());
        b.d.event(lost(&found), NOW + 2 * LOST_HOLD_SECONDS);
        assert!(b.d.pop_update().is_none(), "an unknown instance is ignored");
        assert_eq!(
            b.d.next_tick_in(NOW),
            Duration::from_secs((mdns::window(NOW) + 1) * WINDOW_SECONDS - NOW)
        );
    }

    #[test]
    fn a_return_with_a_new_address_updates_at_once() {
        let (_a, mut b, mut found) = lan_pair();
        b.d.event(MdnsEvent::Found(found.clone()), NOW);
        let _ = b.d.pop_update().unwrap();
        b.d.event(lost(&found), NOW + 2);
        found.addrs = vec!["192.168.1.20".parse().unwrap()];
        b.d.event(MdnsEvent::Found(found.clone()), NOW + 4);
        let u = b.d.pop_update().unwrap();
        assert_eq!(addrs(&u), ["192.168.1.20:1111"]);
        assert!(u.spare.is_empty());
        b.d.tick(NOW + 2 + LOST_HOLD_SECONDS, &mut os_rng());
        assert!(b.d.pop_update().is_none());
    }

    #[test]
    fn the_hold_is_a_deadline_of_the_tick() {
        let (_a, mut b, found) = lan_pair();
        b.d.start(NOW, &mut os_rng());
        b.d.event(MdnsEvent::Found(found.clone()), NOW);
        let window = b.d.next_tick_in(NOW);
        b.d.event(lost(&found), NOW);
        let wait = b.d.next_tick_in(NOW + 3);
        assert_eq!(
            wait,
            window
                .saturating_sub(Duration::from_secs(3))
                .min(Duration::from_secs(LOST_HOLD_SECONDS - 3))
        );
        assert!(wait >= Duration::from_secs(1));
    }

    #[test]
    fn rotates_per_window() {
        let net = NetworkSecret::generate(&mut os_rng());
        let mut a = side(&net, &[], false, 1111);
        let first = announce(&mut a);
        a.d.tick(NOW + 10, &mut os_rng());
        assert!(a.d.pop_request().is_none());
        a.d.tick(NOW + WINDOW_SECONDS, &mut os_rng());
        assert_eq!(
            a.d.pop_request(),
            Some(MdnsRequest::Unregister {
                instance: first.instance.clone()
            })
        );
        let Some(MdnsRequest::Register { instance, .. }) = a.d.pop_request() else {
            panic!()
        };
        assert_ne!(instance, first.instance);
        assert!(a.d.next_tick_in(NOW) <= Duration::from_secs(WINDOW_SECONDS));
    }
}
