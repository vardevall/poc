//! Routing of packets between the tunnel and the peers (vv-06 §3).

mod exit;
pub mod ndp;

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use vardevall_proto::addr::{self, OverlayAddrs};
use vardevall_proto::ip::exit::{EXIT_IPV4, ExitServe};
use vardevall_proto::ip::private::{self, Refusal, is_global};
use vardevall_proto::ip::site::{self, Site};
use vardevall_proto::keys::{NetworkId, NodePublic};

use crate::packet::{self, HEADER_LEN, Header, MIN_MTU, icmp, v4};

use exit::ExitState;
pub use exit::{Chosen, ExitUse};

/// ICMPv6 Destination Unreachable codes used (RFC 4443 §3.1).
const CODE_NO_ROUTE: u8 = 0;
const CODE_PROHIBITED: u8 = 1;
const CODE_ADDRESS_UNREACHABLE: u8 = 3;

/// What to do with a packet read from the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Send on the session with this peer (vv-06 §3.1).
    Unicast(NodePublic),
    /// Send to each of these peers (vv-06 §3.3).
    Multicast(Vec<NodePublic>),
    /// Write this packet back to the tunnel: an ICMP error, a Neighbor Advertisement, or a
    /// packet for the node's own address that the OS sent into the tunnel (macOS and iOS do).
    Reply(Vec<u8>),
    /// Discard.
    Drop,
}

/// What to do with a packet received from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    /// Write this packet to the tunnel.
    Deliver(Vec<u8>),
    /// Send this ICMP error back to the peer that sent the packet.
    Return(Vec<u8>),
    /// Discard.
    Drop,
}

/// Why a peer cannot be added to the routing table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// It is this node.
    Own,
    /// Its interface identifier equals this node's or another peer's (vv-06 §2.2).
    Collision,
    /// Its interface identifier is in a reserved range (vv-06 §2.2).
    Reserved,
}

/// The routing table of one interface.
pub struct Router {
    own_key: NodePublic,
    own: OverlayAddrs,
    network_id: NetworkId,
    prefix: [u8; 8],
    peers: HashMap<[u8; 8], NodePublic>,
    live: HashSet<NodePublic>,
    keyed: HashSet<NodePublic>,
    exit: ExitState,
    /// The IPv4 addresses the exit this node serves gave its peers.
    clients: HashMap<Ipv4Addr, NodePublic>,
    ipv6_uplink: bool,
    synthetic_ndp: bool,
}

const LINK_LOCAL_PREFIX: [u8; 8] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0];

impl Router {
    /// A router for a layer-3 device.
    pub fn new(network_id: NetworkId, own: NodePublic) -> Self {
        Router {
            own_key: own,
            own: OverlayAddrs::derive(&network_id, &own),
            network_id,
            prefix: addr::ula_prefix(&network_id),
            peers: HashMap::new(),
            live: HashSet::new(),
            keyed: HashSet::new(),
            exit: ExitState::default(),
            clients: HashMap::new(),
            ipv6_uplink: true,
            synthetic_ndp: false,
        }
    }

    /// Answers Neighbor Solicitations for known peers, for layer-2 devices (vv-06 §3.2).
    pub fn with_synthetic_ndp(mut self) -> Self {
        self.synthetic_ndp = true;
        self
    }

    /// The node's own addresses.
    pub fn own_addrs(&self) -> &OverlayAddrs {
        &self.own
    }

    /// Adds an accepted peer.
    pub fn add_peer(&mut self, key: NodePublic) -> Result<(), Rejected> {
        if key == self.own_key {
            return Err(Rejected::Own);
        }
        let iid = addr::iid(&self.network_id, &key);
        if iid == self.own.iid {
            return Err(Rejected::Collision);
        }
        if addr::is_reserved_iid(&iid) {
            return Err(Rejected::Reserved);
        }
        match self.peers.get(&iid) {
            Some(k) if *k == key => Ok(()),
            Some(_) => Err(Rejected::Collision),
            None => {
                self.peers.insert(iid, key);
                Ok(())
            }
        }
    }

    /// Removes a peer and the IPv4 address it had from this node's exit.
    pub fn remove_peer(&mut self, key: &NodePublic) {
        let iid = addr::iid(&self.network_id, key);
        if self.peers.get(&iid) == Some(key) {
            self.peers.remove(&iid);
        }
        self.live.remove(key);
        self.keyed.remove(key);
        self.clients.retain(|_, k| k != key);
    }

    /// Records whether a session carrying the `tun` plane is up (vv-06 §3.3).
    pub fn set_live(&mut self, key: NodePublic, live: bool) {
        if live {
            self.live.insert(key);
        } else {
            self.live.remove(&key);
        }
    }

    /// Marks a peer as held by key, the only kind that may use or serve an exit.
    pub fn set_keyed(&mut self, key: NodePublic) {
        self.keyed.insert(key);
    }

    /// The exit this node serves, if any.
    pub fn set_serving(&mut self, serving: Option<ExitServe>) {
        self.exit.set_serving(serving);
    }

    /// The IPv4 address the exit this node serves gave `peer`, or `None` once freed
    ///: IPv4 from the host to it goes to the peer.
    pub fn set_exit_client(&mut self, peer: NodePublic, ipv4: Option<Ipv4Addr>) {
        self.clients.retain(|_, k| *k != peer);
        if let Some(a) = ipv4 {
            self.clients.insert(a, peer);
        }
    }

    /// Whether traffic outside the overlay goes through this network's exit.
    pub fn set_exit_use(&mut self, using: Option<ExitUse>) {
        self.exit.set_use(using);
    }

    /// Whether the host of the exit this node serves has an IPv6 route to the internet; on by
    /// default and kept across changes of the offer. While it has not, a packet
    /// from a peer to a global IPv6 destination outside the overlay is answered with "no route"
    /// instead of being delivered to the host.
    pub fn set_ipv6_uplink(&mut self, on: bool) {
        self.ipv6_uplink = on;
    }

    /// Whether the exit this node serves has an IPv6 uplink.
    pub fn ipv6_uplink(&self) -> bool {
        self.ipv6_uplink
    }

    /// The sites that some peer has offered, live or not.
    pub fn set_known_sites(&mut self, sites: impl IntoIterator<Item = Site>) {
        self.exit.set_known(sites);
    }

    /// The exit chosen for `site`, or `None` once it has none.
    pub fn set_exit_peer(&mut self, site: Site, via: Option<Chosen>) {
        self.exit.set_chosen(site, via);
    }

    /// The site in use and the exit chosen for it, with the IPv4 address it gives this node.
    pub fn exit_chosen(&self) -> Option<(&Site, Chosen)> {
        self.exit.used().map(|(site, c)| (site, *c))
    }

    /// The site in use and the exit that carries it.
    pub fn exit_in_use(&self) -> Option<(&Site, NodePublic)> {
        self.exit.used().map(|(site, c)| (site, c.peer))
    }

    /// The accepted peer owning `addr`, if any (vv-06 §3.1).
    pub fn peer_for(&self, addr: &Ipv6Addr) -> Option<NodePublic> {
        let o = addr.octets();
        if o[..8] != self.prefix && o[..8] != LINK_LOCAL_PREFIX {
            return None;
        }
        let iid: [u8; 8] = o[8..].try_into().ok()?;
        self.peers.get(&iid).copied()
    }

    /// The peer held by key that owns `addr` in the site this node serves.
    fn served_peer(&self, addr: &Ipv6Addr) -> Option<NodePublic> {
        let serving = self.exit.serving()?;
        let o = addr.octets();
        if o[..8] != site::site_prefix(&self.network_id, &serving.site) {
            return None;
        }
        let iid: [u8; 8] = o[8..].try_into().ok()?;
        self.peers
            .get(&iid)
            .copied()
            .filter(|k| self.keyed.contains(k))
    }

    /// Whether `addr` is inside the network's `/48` or is link-local on the overlay.
    fn in_overlay(&self, addr: &Ipv6Addr) -> bool {
        let o = addr.octets();
        o[..6] == self.prefix[..6] || o[..8] == LINK_LOCAL_PREFIX
    }

    /// This node's address in `site`.
    pub fn site_addr(&self, site: &Site) -> Ipv6Addr {
        site::site_addr(&self.network_id, site, &self.own_key)
    }

    /// Whether `addr` is this node's address in the site in use.
    fn is_own_site_addr(&self, addr: &Ipv6Addr) -> bool {
        self.exit
            .used()
            .is_some_and(|(site, _)| *addr == self.site_addr(site))
    }

    /// Decides what to do with an IP packet read from the tunnel (vv-06 §3); the
    /// version nibble tells the family.
    ///
    /// A unicast IPv6 destination outside the overlay goes to the exit in use, if there is one.
    /// IPv4 goes to the exit in use from the address it gave this node, and to a client of this
    /// node's exit for that client's address.
    pub fn route(&self, packet: &[u8]) -> Route {
        if packet.first().is_some_and(|b| b >> 4 == 4) {
            return self.route_v4(packet);
        }
        let Some(h) = packet::parse(packet) else {
            return Route::Drop;
        };
        if h.dst.octets()[0] == 0xff {
            return self.route_multicast(packet, &h);
        }
        if self.own.contains(&h.dst) || self.is_own_site_addr(&h.dst) {
            return Route::Reply(packet::with_checksum(packet));
        }
        if self.in_overlay(&h.dst) {
            return match self.peer_for(&h.dst).or_else(|| self.served_peer(&h.dst)) {
                Some(p) => Route::Unicast(p),
                None => unreachable_reply(&self.own, packet, &h, CODE_ADDRESS_UNREACHABLE),
            };
        }
        if is_global(&h.dst)
            && let Some((_, exit)) = self.exit.used()
        {
            return Route::Unicast(exit.peer);
        }
        unreachable_reply(&self.own, packet, &h, CODE_NO_ROUTE)
    }

    fn route_multicast(&self, packet: &[u8], h: &Header) -> Route {
        let kind = packet::icmpv6_type(packet, h);
        if let Some(k) = kind {
            if k == icmp::NEIGHBOR_SOLICITATION && self.synthetic_ndp {
                let known =
                    |a: &Ipv6Addr| self.peer_for(a).map(|k| addr::iid(&self.network_id, &k));
                return ndp::answer(packet, h, known).map_or(Route::Drop, Route::Reply);
            }
            if icmp::is_link_local_control(k) {
                return Route::Drop;
            }
        }
        if h.dst.octets()[1] & 0x0f != 2 {
            return Route::Drop;
        }
        let mut peers: Vec<NodePublic> = self.live.iter().copied().collect();
        peers.sort();
        if peers.is_empty() {
            Route::Drop
        } else {
            Route::Multicast(peers)
        }
    }

    /// An IPv4 packet read from the tunnel: from the address the exit in use gave
    /// this node, it goes to that exit as it is; to a client address of the exit this node
    /// serves, to that client. Any other is dropped.
    fn route_v4(&self, packet: &[u8]) -> Route {
        let Some((src, dst)) = v4::addrs(packet) else {
            return Route::Drop;
        };
        if let Some((_, exit)) = self.exit.used()
            && exit.ipv4 == Some(src)
        {
            return Route::Unicast(exit.peer);
        }
        if self.exit.serving().is_some_and(|s| s.ipv4)
            && let Some(peer) = self.clients.get(&dst)
        {
            return Route::Unicast(*peer);
        }
        Route::Drop
    }

    /// What to do with a packet received from `from`: neither neighbour discovery nor MLD
    /// crosses the overlay (vv-06 §3.3), and the source must be one `from` may use
    ///:
    ///
    /// - one of its overlay addresses, whatever the destination;
    /// - any, if `from` is the exit in use and the packet is for this node's address in that
    ///   site, or, for IPv4, for the address that exit gave this node;
    /// - its address in the site this node serves, or for IPv4 the address this node gave it, if
    ///   it is held by key. A refused destination outside the overlay is answered
    ///   with "administratively prohibited". While the exit has no IPv6 uplink
    ///   ([`Router::set_ipv6_uplink`]) a global IPv6 destination is answered with "no route".
    pub fn inbound(&mut self, from: &NodePublic, packet: &[u8]) -> Inbound {
        if packet.first().is_some_and(|b| b >> 4 == 4) {
            return self.inbound_v4(from, packet);
        }
        let Some(h) = packet::parse(packet) else {
            return Inbound::Drop;
        };
        if packet::icmpv6_type(packet, &h).is_some_and(icmp::is_link_local_control) {
            return Inbound::Drop;
        }
        let deliver = || Inbound::Deliver(packet.to_vec());
        if OverlayAddrs::derive(&self.network_id, from).contains(&h.src) {
            return deliver();
        }
        if let Some((site, exit)) = self.exit.used()
            && exit.peer == *from
            && h.dst == self.site_addr(site)
        {
            return deliver();
        }
        let Some(serving) = self.exit.serving() else {
            return Inbound::Drop;
        };
        if h.src != site::site_addr(&self.network_id, &serving.site, from)
            || !self.keyed.contains(from)
        {
            return Inbound::Drop;
        }
        let error = |code| {
            icmp_error(&self.own, packet, &h, icmp::DEST_UNREACHABLE, code, [0; 4])
                .map_or(Inbound::Drop, Inbound::Return)
        };
        if self.in_overlay(&h.dst) {
            return deliver();
        }
        match private::refusal_v6(&h.dst, self.ipv6_uplink) {
            Some(Refusal::Prohibited) => error(CODE_PROHIBITED),
            Some(Refusal::NoRoute) => error(CODE_NO_ROUTE),
            None => deliver(),
        }
    }

    /// An IPv4 packet received from `from`.
    fn inbound_v4(&self, from: &NodePublic, packet: &[u8]) -> Inbound {
        let Some((src, dst)) = v4::addrs(packet) else {
            return Inbound::Drop;
        };
        if let Some((_, exit)) = self.exit.used()
            && exit.peer == *from
            && exit.ipv4 == Some(dst)
        {
            return Inbound::Deliver(packet.to_vec());
        }
        let serves = self.exit.serving().is_some_and(|s| s.ipv4);
        if !serves || self.clients.get(&src) != Some(from) || !self.keyed.contains(from) {
            return Inbound::Drop;
        }
        if private::refuses_v4(dst) {
            return v4::error(
                EXIT_IPV4,
                v4::DEST_UNREACHABLE,
                v4::ADMIN_PROHIBITED,
                packet,
            )
            .map_or(Inbound::Drop, Inbound::Return);
        }
        Inbound::Deliver(packet.to_vec())
    }
}

fn unreachable_reply(own: &OverlayAddrs, packet: &[u8], h: &Header, code: u8) -> Route {
    icmp_error(own, packet, h, icmp::DEST_UNREACHABLE, code, [0; 4])
        .map_or(Route::Drop, Route::Reply)
}

/// An ICMPv6 error from the node's overlay address to the source of `packet`, which quotes it,
/// or `None` where none may be sent: the source is unspecified or multicast, or the packet is an
/// ICMPv6 error itself (RFC 4443 §2.4).
fn icmp_error(
    own: &OverlayAddrs,
    packet: &[u8],
    h: &Header,
    kind: u8,
    code: u8,
    rest: [u8; 4],
) -> Option<Vec<u8>> {
    let src = h.src.octets();
    let silent = h.src.is_unspecified()
        || src[0] == 0xff
        || packet::icmpv6_type(packet, h).is_some_and(|k| k < 128);
    if silent {
        return None;
    }
    let keep = packet.len().min(MIN_MTU - HEADER_LEN - 8);
    let mut body = rest.to_vec();
    body.extend_from_slice(&packet[..keep]);
    Some(packet::build_icmpv6(
        &own.ula, &h.src, kind, code, &body, 64,
    ))
}

#[cfg(test)]
mod tests;
