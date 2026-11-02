//! Exit nodes: the offer a handshake carries and the choice among the exits of a site
//!.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::handshake::payload::REPLY_PAYLOAD_2;
use crate::ip::site::{Site, site_id};
use crate::json::{self, Value};
use crate::keys::{NetworkId, NodePublic, crypto, ctx};

/// Most bytes of an encoded offer: what a message 2 answering a padded message 1 carries, less
/// the braces and the `exit` member name around the offer.
pub const MAX_OFFER_LEN: usize = REPLY_PAYLOAD_2 - "{\"exit\":}".len();

/// The IPv4 range of an exit's clients: `198.18.0.0/15`, outside the private
/// ranges of §15.4 and outside carrier-grade NAT, as address and prefix length.
pub const IPV4_POOL: (Ipv4Addr, u8) = (Ipv4Addr::new(198, 18, 0, 0), 15);
/// The exit's own address in [`IPV4_POOL`], on its host's device.
pub const EXIT_IPV4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);

/// The pool's addresses, its first client address and how many clients it holds: from
/// `198.18.0.2` to `198.19.255.254`.
const POOL_SIZE: u32 = 1 << 17;
const FIRST_CLIENT: u32 = 2;
const CLIENTS: u32 = POOL_SIZE - 3;

/// Whether `addr` is in [`IPV4_POOL`].
pub fn in_ipv4_pool(addr: Ipv4Addr) -> bool {
    u32::from(addr) >> 17 == u32::from(IPV4_POOL.0) >> 17
}

/// Whether `addr` is one an exit gives a client: in [`IPV4_POOL`], neither its first nor its
/// last address nor [`EXIT_IPV4`].
pub fn is_client_ipv4(addr: Ipv4Addr) -> bool {
    let n = u32::from(addr).wrapping_sub(u32::from(IPV4_POOL.0));
    (FIRST_CLIENT..POOL_SIZE - 1).contains(&n)
}

/// The IPv4 address an exit gives `node` unless another client holds it: the
/// same at every exit of the network, so a node configures it before any exit is live.
pub fn home_ipv4(network_id: &NetworkId, node: &NodePublic) -> Ipv4Addr {
    let h = u32::from_be_bytes(crypto::kdf(
        ctx::EXIT_IPV4,
        &[network_id.as_bytes(), node.as_bytes()],
    ));
    Ipv4Addr::from(u32::from(IPV4_POOL.0) + FIRST_CLIENT + h % CLIENTS)
}

/// The host's choice to send traffic outside the overlay through this network.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExitUse {
    /// The site to use; `None` is the network's only site, the one that every offer received
    /// names, live or not, and with several sites there is no exit until one is picked.
    pub site: Option<Site>,
}

impl ExitUse {
    /// The site this use names among the `known` ones: the one the host picked, else the only one
    ///. The node and the router of a host both resolve it with this.
    pub fn resolve<'a>(&'a self, known: impl IntoIterator<Item = &'a Site>) -> Option<&'a Site> {
        match &self.site {
            Some(site) => Some(site),
            None => only_site(known),
        }
    }
}

/// The only site among `sites`, ignoring repeats; `None` for none or for several.
pub fn only_site<'a>(sites: impl IntoIterator<Item = &'a Site>) -> Option<&'a Site> {
    let mut sites: BTreeSet<&Site> = sites.into_iter().collect();
    let only = sites.pop_first()?;
    sites.is_empty().then_some(only)
}

/// The exit chosen for a site and the IPv4 address its offer gives this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chosen {
    /// The exit.
    pub peer: NodePublic,
    /// This node's IPv4 address from the exit's offer; `None`: it does not carry IPv4
    ///.
    pub ipv4: Option<Ipv4Addr>,
}

/// The exit this node serves: its site and whether it carries IPv4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitServe {
    /// The site it serves.
    pub site: Site,
    /// Whether it carries IPv4, giving each client an address of [`IPV4_POOL`].
    pub ipv4: bool,
}

/// What an exit offers one peer. It carries every destination outside the
/// overlay except the private ones of §15.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitOffer {
    /// The site it serves.
    pub site: Site,
    /// The IPv4 address it gives the peer; `None`: it does not carry IPv4.
    pub ipv4: Option<Ipv4Addr>,
}

impl ExitOffer {
    /// The size in bytes of the offer as the `exit` member of a handshake payload.
    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    /// The offer as the `exit` member of a handshake payload.
    pub(crate) fn encode(&self) -> String {
        let mut s = String::from("{\"site\":");
        json::write_string(&mut s, &self.site.to_string());
        if let Some(a) = self.ipv4 {
            s.push_str(",\"ipv4\":");
            json::write_string(&mut s, &a.to_string());
        }
        s.push('}');
        s
    }

    /// The offer in an `exit` member, or `None` if it does not parse; an address that is not a
    /// client address of [`IPV4_POOL`] does not.
    pub(crate) fn decode(v: &Value) -> Option<ExitOffer> {
        let site = v.get("site")?.as_str()?.parse().ok()?;
        let ipv4 = match v.get("ipv4") {
            None => None,
            Some(a) => {
                let a: Ipv4Addr = a.as_str()?.parse().ok()?;
                if !is_client_ipv4(a) {
                    return None;
                }
                Some(a)
            }
        };
        Some(ExitOffer { site, ipv4 })
    }
}

/// The IPv4 addresses an exit has given: each peer its home address, or the next
/// free one after it, kept while the process runs.
#[derive(Debug, Default)]
pub struct Ipv4Pool {
    by_peer: BTreeMap<NodePublic, Ipv4Addr>,
    by_addr: BTreeMap<Ipv4Addr, NodePublic>,
}

impl Ipv4Pool {
    /// The address of `peer`, given now if it has none; `None` once the pool is full.
    pub fn assign(&mut self, network_id: &NetworkId, peer: NodePublic) -> Option<Ipv4Addr> {
        if let Some(a) = self.by_peer.get(&peer) {
            return Some(*a);
        }
        if self.by_peer.len() >= CLIENTS as usize {
            return None;
        }
        let base = u32::from(IPV4_POOL.0) + FIRST_CLIENT;
        let home = u32::from(home_ipv4(network_id, &peer)) - base;
        let addr = (0..CLIENTS)
            .map(|i| Ipv4Addr::from(base + (home + i) % CLIENTS))
            .find(|a| !self.by_addr.contains_key(a))?;
        self.by_peer.insert(peer, addr);
        self.by_addr.insert(addr, peer);
        Some(addr)
    }

    /// Frees the address of `peer`.
    pub fn release(&mut self, peer: &NodePublic) -> Option<Ipv4Addr> {
        let a = self.by_peer.remove(peer)?;
        self.by_addr.remove(&a);
        Some(a)
    }

    /// The address given to `peer`.
    pub fn addr_of(&self, peer: &NodePublic) -> Option<Ipv4Addr> {
        self.by_peer.get(peer).copied()
    }

    /// The peer holding `addr`.
    pub fn holder(&self, addr: Ipv4Addr) -> Option<NodePublic> {
        self.by_addr.get(&addr).copied()
    }
}

/// The exit this node serves with the addresses it gave, as a peer makes its offer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Serving<'a> {
    pub(crate) serve: &'a ExitServe,
    pub(crate) pool: &'a Ipv4Pool,
}

impl Serving<'_> {
    /// The offer made to `peer`.
    pub(crate) fn offer_for(&self, peer: &NodePublic) -> ExitOffer {
        ExitOffer {
            site: self.serve.site.clone(),
            ipv4: self.ipv4_of(peer),
        }
    }

    /// The address given to `peer`, if this exit carries IPv4.
    pub(crate) fn ipv4_of(&self, peer: &NodePublic) -> Option<Ipv4Addr> {
        self.serve.ipv4.then(|| self.pool.addr_of(peer)).flatten()
    }
}

/// What the choice of an exit needs to know of a peer that offered one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitPeer {
    /// The last offer the peer made, kept while its link is down.
    pub offer: ExitOffer,
    /// Whether the peer's link is up: only such a peer can be chosen.
    pub live: bool,
    /// Whether the active route is metered; `None` without an active route.
    pub metered: Option<bool>,
    /// The smoothed round-trip time of the active route, once it has one.
    pub srtt: Option<Duration>,
}

impl ExitPeer {
    /// Smaller is better: a route before none, an unmetered one before a metered one, then the
    /// shorter round trip, a measured one before an unmeasured one.
    fn rank(&self) -> (bool, bool, Duration) {
        (
            self.metered.is_none(),
            self.metered.unwrap_or(true),
            self.srtt.unwrap_or(Duration::MAX),
        )
    }
}

/// A peer that offers a site, for views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SitePeer {
    /// The peer.
    pub peer: NodePublic,
    /// Whether its link is up; if not, the offer is remembered.
    pub live: bool,
}

/// A site and the peers that offer it, for views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteView {
    /// The site.
    pub site: Site,
    /// The peers offering it, by key.
    pub peers: Vec<SitePeer>,
    /// The live exit the node uses, if the site has one.
    pub chosen: Option<NodePublic>,
}

/// A difference between what [`Exits`] holds and what it last reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The sites known from the offers received, live or not, are now `sites`.
    Sites {
        /// The sites, in order.
        sites: Vec<Site>,
    },
    /// The offers remembered, live or not, are now `offers`: each peer with the site it offered
    ///.
    Remembered {
        /// The peers and their sites, by key.
        offers: Vec<(NodePublic, Site)>,
    },
    /// The chosen exit of `site`, or the IPv4 address it gives this node, is now `via` and
    /// `ipv4`; `None`: the site has none left.
    Exit {
        /// The site.
        site: Site,
        /// The exit.
        via: Option<NodePublic>,
        /// The IPv4 address the exit's offer gives this node; `None` without an
        /// exit or when it does not carry IPv4.
        ipv4: Option<Ipv4Addr>,
    },
    /// Two sites with different names have the same id: both are ignored.
    Collision {
        /// The first, in site order.
        first: Site,
        /// The second.
        second: Site,
    },
}

/// The exits of a node: the offers of its peers, the choice among them and its own offer
///.
///
/// Pure state: the caller says what each peer offers and asks for the changes.
#[derive(Debug)]
pub struct Exits {
    network_id: NetworkId,
    own: Option<ExitServe>,
    pool: Ipv4Pool,
    peers: BTreeMap<NodePublic, ExitPeer>,
    chosen: BTreeMap<Site, NodePublic>,
    reported: BTreeMap<Site, Chosen>,
    reported_sites: BTreeSet<Site>,
    reported_offers: BTreeMap<NodePublic, Site>,
    collisions: BTreeSet<(Site, Site)>,
    reported_collisions: BTreeSet<(Site, Site)>,
    changed: bool,
}

impl Exits {
    /// No peers offer anything; `own` is the exit this node serves.
    pub fn new(network_id: NetworkId, own: Option<ExitServe>) -> Self {
        Exits {
            network_id,
            own,
            pool: Ipv4Pool::default(),
            peers: BTreeMap::new(),
            chosen: BTreeMap::new(),
            reported: BTreeMap::new(),
            reported_sites: BTreeSet::new(),
            reported_offers: BTreeMap::new(),
            collisions: BTreeSet::new(),
            reported_collisions: BTreeSet::new(),
            changed: false,
        }
    }

    /// Replaces the exit this node serves.
    pub fn set_own(&mut self, own: Option<ExitServe>) {
        self.changed = true;
        self.own = own;
    }

    /// The exit to offer now: the configured one, unless its site collides with one received.
    pub fn offer(&self) -> Option<&ExitServe> {
        self.own.as_ref().filter(|o| {
            !self
                .collisions
                .iter()
                .any(|(a, b)| *a == o.site || *b == o.site)
        })
    }

    /// The exit to offer now with the addresses it gave.
    pub(crate) fn serving(&self) -> Option<Serving<'_>> {
        Some(Serving {
            serve: self.offer()?,
            pool: &self.pool,
        })
    }

    /// Whether this node serves an exit that carries IPv4, whatever the collisions.
    pub fn serves_ipv4(&self) -> bool {
        self.own.as_ref().is_some_and(|o| o.ipv4)
    }

    /// Gives `peer` an IPv4 address if it has none; `Some` only when one was
    /// given now.
    pub fn assign_ipv4(&mut self, peer: NodePublic) -> Option<Ipv4Addr> {
        if self.pool.addr_of(&peer).is_some() {
            return None;
        }
        self.pool.assign(&self.network_id, peer)
    }

    /// Frees the IPv4 address of `peer`.
    pub fn release_ipv4(&mut self, peer: &NodePublic) -> Option<Ipv4Addr> {
        self.pool.release(peer)
    }

    /// The IPv4 address given to `peer`.
    pub fn ipv4_of(&self, peer: &NodePublic) -> Option<Ipv4Addr> {
        self.pool.addr_of(peer)
    }

    /// What `peer` last offered and whether its link is up, or `None` if it offered nothing or
    /// is gone.
    pub fn observe(&mut self, peer: NodePublic, state: Option<ExitPeer>) {
        match state {
            Some(s) if self.peers.get(&peer) != Some(&s) => {
                self.peers.insert(peer, s);
                self.changed = true;
            }
            Some(_) => {}
            None => self.changed |= self.peers.remove(&peer).is_some(),
        }
    }

    /// Chooses again where the choice is not sticky and returns what differs from the last call.
    pub fn update(&mut self) -> Vec<Change> {
        if !std::mem::take(&mut self.changed) {
            return Vec::new();
        }
        self.collisions = self.find_collisions();
        let mut live: BTreeMap<&Site, Vec<(&NodePublic, &ExitPeer)>> = BTreeMap::new();
        for (key, p) in &self.peers {
            if p.live && !self.is_ignored(&p.offer.site) {
                live.entry(&p.offer.site).or_default().push((key, p));
            }
        }
        let mut chosen = BTreeMap::new();
        for (site, peers) in live {
            let keep = self
                .chosen
                .get(site)
                .filter(|c| peers.iter().any(|(k, _)| k == c));
            let pick = match keep {
                Some(c) => Some(*c),
                None => peers
                    .iter()
                    .min_by_key(|(k, p)| (p.rank(), **k))
                    .map(|(k, _)| **k),
            };
            if let Some(pick) = pick {
                chosen.insert(site.clone(), pick);
            }
        }
        self.chosen = chosen;

        let mut changes = Vec::new();
        let known = self.known();
        if known != self.reported_sites {
            changes.push(Change::Sites {
                sites: known.iter().cloned().collect(),
            });
            self.reported_sites = known;
        }
        let offers: BTreeMap<NodePublic, Site> = self
            .peers
            .iter()
            .map(|(k, p)| (*k, p.offer.site.clone()))
            .collect();
        if offers != self.reported_offers {
            changes.push(Change::Remembered {
                offers: offers.iter().map(|(k, s)| (*k, s.clone())).collect(),
            });
            self.reported_offers = offers;
        }
        let sites: BTreeSet<Site> = self
            .chosen
            .keys()
            .chain(self.reported.keys())
            .cloned()
            .collect();
        for site in sites {
            let now = self.chosen.get(&site).map(|k| Chosen {
                peer: *k,
                ipv4: self.peers.get(k).and_then(|p| p.offer.ipv4),
            });
            if now == self.reported.get(&site).copied() {
                continue;
            }
            changes.push(Change::Exit {
                site: site.clone(),
                via: now.map(|c| c.peer),
                ipv4: now.and_then(|c| c.ipv4),
            });
            match now {
                Some(k) => self.reported.insert(site, k),
                None => self.reported.remove(&site),
            };
        }
        for (first, second) in self.collisions.difference(&self.reported_collisions) {
            changes.push(Change::Collision {
                first: first.clone(),
                second: second.clone(),
            });
        }
        self.reported_collisions = self.collisions.clone();
        changes
    }

    /// The sites some peer has offered, live or not, without the ignored ones.
    fn known(&self) -> BTreeSet<Site> {
        self.peers
            .values()
            .map(|p| &p.offer.site)
            .filter(|s| !self.is_ignored(s))
            .cloned()
            .collect()
    }

    /// The sites some peer has offered, live or not, in site order.
    pub fn sites(&self) -> Vec<SiteView> {
        self.known()
            .into_iter()
            .map(|site| SiteView {
                chosen: self.chosen.get(&site).copied(),
                peers: self
                    .peers
                    .iter()
                    .filter(|(_, p)| p.offer.site == site)
                    .map(|(k, p)| SitePeer {
                        peer: *k,
                        live: p.live,
                    })
                    .collect(),
                site,
            })
            .collect()
    }

    /// The network's only site: the one that every offer remembered names, live or not.
    pub fn only_site(&self) -> Option<Site> {
        only_site(&self.known()).cloned()
    }

    /// The site `using` names: the one picked, else the network's only site.
    pub(crate) fn in_use(&self, using: &ExitUse) -> Option<Site> {
        using.resolve(&self.known()).cloned()
    }

    /// The exit chosen for `site`.
    pub fn chosen(&self, site: &Site) -> Option<NodePublic> {
        self.chosen.get(site).copied()
    }

    fn is_ignored(&self, site: &Site) -> bool {
        self.collisions.iter().any(|(a, b)| a == site || b == site)
    }

    /// Pairs of sites, among the offers received and the node's own, that share an id.
    fn find_collisions(&self) -> BTreeSet<(Site, Site)> {
        let mut by_id: BTreeMap<u16, BTreeSet<&Site>> = BTreeMap::new();
        let sites = self
            .peers
            .values()
            .map(|p| &p.offer.site)
            .chain(self.own.iter().map(|o| &o.site));
        for site in sites {
            by_id
                .entry(site_id(&self.network_id, site))
                .or_default()
                .insert(site);
        }
        let mut out = BTreeSet::new();
        for sites in by_id.values() {
            for (i, a) in sites.iter().enumerate() {
                for b in sites.iter().skip(i + 1) {
                    out.insert(((*a).clone(), (*b).clone()));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> NodePublic {
        NodePublic::from_bytes([n; 32])
    }

    fn offer(site: &str) -> ExitOffer {
        ExitOffer {
            site: site.parse().unwrap(),
            ipv4: None,
        }
    }

    fn peer(site: &str, metered: bool, ms: Option<u64>) -> ExitPeer {
        ExitPeer {
            offer: offer(site),
            live: true,
            metered: Some(metered),
            srtt: ms.map(Duration::from_millis),
        }
    }

    fn down(site: &str) -> ExitPeer {
        ExitPeer {
            live: false,
            metered: None,
            srtt: None,
            ..peer(site, false, None)
        }
    }

    /// The changes of the choice, without those of the known sites and offers.
    fn upd(e: &mut Exits) -> Vec<Change> {
        let mut all = e.update();
        all.retain(|c| !matches!(c, Change::Sites { .. } | Change::Remembered { .. }));
        all
    }

    fn exits() -> Exits {
        Exits::new(NetworkId::from_bytes([2; 32]), None)
    }

    fn via(site: &str, k: Option<u8>) -> Change {
        Change::Exit {
            site: site.parse().unwrap(),
            via: k.map(key),
            ipv4: None,
        }
    }

    #[test]
    fn the_unmetered_class_comes_first_then_the_shortest_round_trip_then_the_smaller_key() {
        let mut e = exits();
        e.observe(key(1), Some(peer("it", true, Some(5))));
        e.observe(key(2), Some(peer("it", false, Some(80))));
        e.observe(key(3), Some(peer("it", false, Some(20))));
        e.observe(key(4), Some(peer("it", false, Some(20))));
        e.observe(
            key(5),
            Some(ExitPeer {
                metered: None,
                ..peer("it", false, Some(1))
            }),
        );
        assert_eq!(upd(&mut e), [via("it", Some(3))]);
        assert_eq!(upd(&mut e), [], "reported once");
    }

    #[test]
    fn a_change_of_the_address_the_chosen_exit_gives_is_reported_with_the_same_exit() {
        let mut e = exits();
        e.observe(key(1), Some(peer("it", false, Some(5))));
        assert_eq!(upd(&mut e), [via("it", Some(1))]);
        let addr = Ipv4Addr::new(198, 18, 7, 9);
        let mut with = peer("it", false, Some(5));
        with.offer.ipv4 = Some(addr);
        e.observe(key(1), Some(with));
        assert_eq!(
            upd(&mut e),
            [Change::Exit {
                site: "it".parse().unwrap(),
                via: Some(key(1)),
                ipv4: Some(addr)
            }]
        );
        e.observe(key(1), Some(down("it")));
        assert_eq!(upd(&mut e), [via("it", None)]);
    }

    #[test]
    fn the_remembered_offers_are_reported_when_they_change_not_when_a_link_does() {
        let mut e = exits();
        let remembered = |e: &mut Exits| {
            e.update().into_iter().find_map(|c| match c {
                Change::Remembered { offers } => Some(offers),
                _ => None,
            })
        };
        e.observe(key(2), Some(peer("it/home", false, Some(5))));
        e.observe(key(1), Some(peer("de", false, Some(5))));
        assert_eq!(
            remembered(&mut e),
            Some(vec![
                (key(1), "de".parse().unwrap()),
                (key(2), "it/home".parse().unwrap())
            ])
        );
        e.observe(key(1), Some(down("de")));
        assert_eq!(remembered(&mut e), None);
        e.observe(key(1), None);
        assert_eq!(
            remembered(&mut e),
            Some(vec![(key(2), "it/home".parse().unwrap())])
        );
    }

    #[test]
    fn an_unmeasured_exit_ranks_after_a_measured_one() {
        let mut e = exits();
        e.observe(key(1), Some(peer("it", false, None)));
        e.observe(key(2), Some(peer("it", false, Some(900))));
        assert_eq!(upd(&mut e), [via("it", Some(2))]);
    }

    #[test]
    fn the_choice_sticks_while_the_chosen_exit_is_live() {
        let mut e = exits();
        e.observe(key(2), Some(peer("it", true, Some(50))));
        assert_eq!(upd(&mut e), [via("it", Some(2))]);
        e.observe(key(1), Some(peer("it", false, Some(5))));
        assert_eq!(upd(&mut e), []);
        e.observe(key(2), Some(peer("it", true, Some(500))));
        assert_eq!(upd(&mut e), []);
        e.observe(key(2), Some(down("it")));
        assert_eq!(upd(&mut e), [via("it", Some(1))]);
        e.observe(key(2), Some(peer("it", true, Some(1))));
        assert_eq!(upd(&mut e), [], "it does not move back");
        e.observe(key(1), Some(down("it")));
        assert_eq!(upd(&mut e), [via("it", Some(2))]);
        e.observe(key(2), Some(down("it")));
        assert_eq!(upd(&mut e), [via("it", None)]);
        assert_eq!(upd(&mut e), []);
        let sites = e.sites();
        assert_eq!(sites.len(), 1, "the site is still known");
        assert_eq!(sites[0].chosen, None);
        assert!(sites[0].peers.iter().all(|p| !p.live));
    }

    #[test]
    fn sites_are_chosen_apart() {
        let mut e = exits();
        e.observe(key(1), Some(peer("it/home", false, Some(10))));
        e.observe(key(2), Some(peer("de", false, Some(10))));
        e.observe(key(3), Some(peer("it/home", false, Some(5))));
        assert_eq!(upd(&mut e), [via("de", Some(2)), via("it/home", Some(3))]);
        let sites = e.sites();
        assert_eq!(sites.len(), 2);
        let keys: Vec<_> = sites[1].peers.iter().map(|p| p.peer).collect();
        assert_eq!(keys, [key(1), key(3)]);
        assert_eq!(sites[1].chosen, Some(key(3)));
        e.observe(key(2), Some(down("de")));
        assert_eq!(upd(&mut e), [via("de", None)]);
    }

    #[test]
    fn the_only_site_counts_the_sites_whose_exits_are_down() {
        let mut e = exits();
        assert_eq!(e.only_site(), None);
        e.observe(key(1), Some(peer("it/home", false, Some(10))));
        e.observe(key(2), Some(peer("de", false, Some(10))));
        assert_eq!(e.only_site(), None);
        assert_eq!(upd(&mut e), [via("de", Some(2)), via("it/home", Some(1))]);
        e.observe(key(2), Some(down("de")));
        assert_eq!(upd(&mut e), [via("de", None)]);
        assert_eq!(e.only_site(), None, "the second site is remembered");
        e.observe(key(2), None);
        e.update();
        assert_eq!(e.only_site(), Some("it/home".parse().unwrap()));
    }

    #[test]
    fn the_known_sites_are_reported_when_they_change() {
        let sites = |names: &[&str]| Change::Sites {
            sites: names.iter().map(|n| n.parse().unwrap()).collect(),
        };
        let mut e = exits();
        e.observe(key(1), Some(peer("it/home", false, Some(10))));
        assert_eq!(e.update()[0], sites(&["it/home"]));
        e.observe(key(2), Some(peer("de", false, Some(10))));
        assert_eq!(e.update()[0], sites(&["de", "it/home"]));
        e.observe(key(2), Some(down("de")));
        assert!(
            e.update()
                .iter()
                .all(|c| !matches!(c, Change::Sites { .. })),
            "a link going down changes no site"
        );
        e.observe(key(2), None);
        assert_eq!(e.update()[0], sites(&["it/home"]));
    }

    /// Two different names whose site ids are equal, found by search.
    fn colliding_sites(network_id: &NetworkId) -> (Site, Site) {
        let mut seen: BTreeMap<u16, Site> = BTreeMap::new();
        for i in 0..100_000u32 {
            let site: Site = format!("it/n{i}").parse().unwrap();
            if let Some(other) = seen.insert(site_id(network_id, &site), site.clone()) {
                return (other, site);
            }
        }
        unreachable!("65535 ids")
    }

    #[test]
    fn colliding_sites_are_both_ignored_and_reported_once() {
        let nid = NetworkId::from_bytes([2; 32]);
        let (a, b) = colliding_sites(&nid);
        let mut e = Exits::new(nid, None);
        e.observe(key(1), Some(peer(&a.to_string(), false, Some(10))));
        e.observe(key(3), Some(peer("de", false, Some(10))));
        assert_eq!(
            upd(&mut e),
            [via("de", Some(3)), via(&a.to_string(), Some(1))]
        );
        e.observe(key(2), Some(peer(&b.to_string(), false, Some(10))));
        assert_eq!(
            upd(&mut e),
            [
                via(&a.to_string(), None),
                Change::Collision {
                    first: a.clone().min(b.clone()),
                    second: a.clone().max(b.clone())
                }
            ]
        );
        assert_eq!(upd(&mut e), []);
        assert_eq!(e.sites().len(), 1);
        e.observe(key(2), None);
        assert_eq!(upd(&mut e), [via(&a.to_string(), Some(1))]);
    }

    #[test]
    fn an_offer_whose_site_collides_with_one_received_is_withdrawn() {
        let nid = NetworkId::from_bytes([2; 32]);
        let (a, b) = colliding_sites(&nid);
        let own = ExitServe {
            site: a.clone(),
            ipv4: true,
        };
        let mut e = Exits::new(nid, Some(own.clone()));
        assert_eq!(e.offer(), Some(&own), "nothing received yet");
        e.observe(key(1), Some(peer(&a.to_string(), false, Some(10))));
        upd(&mut e);
        assert_eq!(e.offer(), Some(&own), "the same site is no collision");
        e.observe(key(2), Some(peer(&b.to_string(), false, Some(10))));
        upd(&mut e);
        assert_eq!(e.offer(), None);
        e.observe(key(2), None);
        upd(&mut e);
        assert_eq!(e.offer(), Some(&own));
    }

    #[test]
    fn the_longest_offer_fits_the_reply_of_a_padded_message_1() {
        let longest = ExitOffer {
            site: format!("de/{}", "a".repeat(31)).parse().unwrap(),
            ipv4: Some(Ipv4Addr::new(198, 19, 255, 254)),
        };
        let len = longest.encode().len();
        assert!(len <= MAX_OFFER_LEN, "{len} > {MAX_OFFER_LEN}");
    }

    #[test]
    fn an_offered_address_must_be_a_client_address_of_the_pool() {
        let parse = |a: &str| {
            let text = format!(r#"{{"site":"it","ipv4":"{a}"}}"#);
            ExitOffer::decode(&json::parse(text.as_bytes()).unwrap())
        };
        assert_eq!(
            parse("198.18.0.2").and_then(|o| o.ipv4),
            Some(Ipv4Addr::new(198, 18, 0, 2))
        );
        assert!(parse("198.19.255.254").is_some());
        for bad in [
            "198.18.0.0",
            "198.18.0.1",
            "198.19.255.255",
            "198.20.0.2",
            "10.0.0.2",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
        let none = ExitOffer::decode(&json::parse(br#"{"site":"it"}"#).unwrap()).unwrap();
        assert_eq!(none.ipv4, None);
    }

    #[test]
    fn the_pool_gives_the_home_address_then_the_next_free_one_and_keeps_them() {
        let nid = NetworkId::from_bytes([2; 32]);
        let mut pool = Ipv4Pool::default();
        let a = pool.assign(&nid, key(1)).unwrap();
        assert_eq!(a, home_ipv4(&nid, &key(1)));
        assert!(is_client_ipv4(a));
        assert_eq!(pool.assign(&nid, key(1)), Some(a), "kept");
        assert_eq!(pool.holder(a), Some(key(1)));
        let (b, c) = (key(2), key(3));
        pool.by_addr.insert(home_ipv4(&nid, &b), c);
        let next = pool.assign(&nid, b).unwrap();
        assert_ne!(next, home_ipv4(&nid, &b), "taken, so the next one");
        assert!(is_client_ipv4(next));
        assert_eq!(pool.release(&key(1)), Some(a));
        assert_eq!(pool.holder(a), None);
    }

    #[test]
    fn the_search_for_a_free_address_wraps_inside_the_client_range() {
        let base = u32::from(IPV4_POOL.0) + FIRST_CLIENT;
        assert_eq!(
            Ipv4Addr::from(base + CLIENTS - 1),
            Ipv4Addr::new(198, 19, 255, 254)
        );
        let nid = NetworkId::from_bytes([2; 32]);
        let peer = (0..=255u8)
            .map(key)
            .find(|k| u32::from(home_ipv4(&nid, k)) != base)
            .unwrap();
        let home = u32::from(home_ipv4(&nid, &peer)) - base;
        let mut pool = Ipv4Pool::default();
        for i in home..CLIENTS {
            pool.by_addr.insert(Ipv4Addr::from(base + i), key(0));
        }
        assert_eq!(pool.assign(&nid, peer), Some(Ipv4Addr::from(base)));
    }

    #[test]
    fn a_use_names_the_site_picked_or_the_only_one_known() {
        let sites: Vec<Site> = ["it/home", "de"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let picked = ExitUse {
            site: Some(sites[1].clone()),
        };
        assert_eq!(picked.resolve(&sites[..1]), Some(&sites[1]));
        let any = ExitUse::default();
        assert_eq!(any.resolve(&sites[..1]), Some(&sites[0]));
        assert_eq!(any.resolve([&sites[0], &sites[0]]), Some(&sites[0]));
        assert_eq!(any.resolve(&sites), None, "two sites need a pick");
        assert_eq!(any.resolve(&[]), None);
    }
}
