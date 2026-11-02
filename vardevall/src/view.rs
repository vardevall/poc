//! What the node believes about its own reachability and each peer's paths, for status displays.
//!
//! Everything here is inferred locally: the NAT classes come from this node's STUN round
//! (vv-05 §3.2), the peer's from the candidates of its latest handshake, and the route from where
//! frames to the peer go now (vv-05 §4).

use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::time::Instant;
use vardevall_proto::discovery::candidate::{Candidate, label};
use vardevall_proto::ip::exit::SitePeer;
use vardevall_proto::ip::site::Site;
use vardevall_proto::keys::NodePublic;
use vardevall_proto::meter::{Budget, Meter};
use vardevall_proto::node::PeerState;
use vardevall_proto::route::{Latency, RouteClass, Status};

use crate::event::SwitchState;
use crate::switch::SwitchId;

/// Shortest time between two [`crate::NodeEvent::View`]s.
pub const VIEW_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Shortest time between two [`crate::NodeEvent::View`]s that differ only in meters, remaining
/// budgets and the value of round-trip times.
pub const METER_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// The classification of one address family of this node (vv-05 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nat {
    /// No STUN round finished for the family yet.
    Unknown,
    /// The mapping is reusable; the address is the `punch` candidate.
    Punchable(SocketAddr),
    /// Two servers saw different ports: punching cannot succeed.
    Symmetric,
    /// No STUN server answered.
    Blocked,
}

/// What the peer's candidates say about its NAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerNat {
    /// The peer shared no `punch` or `relay` candidate.
    Unknown,
    /// The peer shared a `punch` candidate.
    Punchable,
    /// The peer shared only a `relay` candidate: it is symmetric, UDP-blocked or relay-first.
    RelayOnly,
}

/// This node's TURN allocation (vv-05 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relay {
    /// The relayed address.
    pub addr: SocketAddr,
    /// The TURN server.
    pub server: SocketAddr,
    /// Whether the client reaches the server over TLS rather than UDP.
    pub tls: bool,
}

/// One configured switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch {
    /// The switch, in configuration order.
    pub id: SwitchId,
    /// `host:port`.
    pub address: String,
    /// The registration.
    pub state: SwitchState,
    /// `"http3"`, `"http2"` or `"http1"` once a connection was made.
    pub transport: Option<&'static str>,
    /// While disconnected, when the next attempt starts (vv-04 §4.6).
    pub retry_at: Option<Instant>,
}

/// This node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Local {
    /// IPv6.
    pub v6: Nat,
    /// IPv4.
    pub v4: Nat,
    /// The allocation, if one exists.
    pub relay: Option<Relay>,
    /// The switches.
    pub switches: Vec<Switch>,
    /// Every transport, in registration order, with what it carried and what it may still carry
    ///.
    pub transports: Vec<Transport>,
}

/// A transport of this node: `"udp"`, `"turn"` or a switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transport {
    /// Its name; a switch is named by its address.
    pub name: String,
    /// Whether routes and messages may use it: up, and its budget not exhausted.
    pub usable: bool,
    /// Every datagram sent and received on it.
    pub meter: Meter,
    /// What it may still carry, if a volume was stated.
    pub budget: Option<Budget>,
}

/// Where tunnel frames to a peer go now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Straight to the peer on the local network: a route of low latency.
    Lan(SocketAddr),
    /// Straight to the peer's public address, through the NATs on both sides.
    Internet(SocketAddr),
    /// To the peer's TURN relayed address; metered on the peer's side.
    PeerRelay(SocketAddr),
    /// Through this node's TURN allocation to this address of the peer; metered here.
    OwnRelay(SocketAddr),
    /// Through this switch (vv-05 §4.7); metered.
    Switch(SwitchId),
}

impl Route {
    /// The route to a peer's `addr`: through our own relay if `own_relay`, to the peer's relay if
    /// its candidate is labelled `relay`, on the LAN if the route's latency is low, else the
    /// internet. The address plays no part.
    pub fn to_addr(addr: SocketAddr, own_relay: bool, label: &str, class: RouteClass) -> Route {
        if own_relay {
            Route::OwnRelay(addr)
        } else if label == label::RELAY {
            Route::PeerRelay(addr)
        } else if class.latency == Latency::Low {
            Route::Lan(addr)
        } else {
            Route::Internet(addr)
        }
    }

    /// Whether the traffic passes a relay or switch that counts it.
    pub fn metered(&self) -> bool {
        matches!(
            self,
            Route::PeerRelay(_) | Route::OwnRelay(_) | Route::Switch(_)
        )
    }
}

/// One route of a link: an entry of the trace of the paths the node knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRoute {
    /// Where it goes, classified as the active route is.
    pub route: Route,
    /// What the node knows of it.
    pub status: Status,
    /// The smoothed round-trip time of its pings, to the millisecond, if any was answered.
    pub rtt: Option<Duration>,
    /// Whether data goes on it now.
    pub active: bool,
    /// Whether it passes a relay or switch that counts it, or the candidate or local network is
    /// metered.
    pub metered: bool,
    /// While it is failed, its next ping or when it is forgotten.
    pub next: Option<RouteNext>,
}

/// What a failed route waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteNext {
    /// One more ping then, since it could still carry data.
    Retry(Instant),
    /// It was learned from the peer's frames and is dropped then.
    Forget(Instant),
}

/// One peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// The peer.
    pub peer: NodePublic,
    /// The state of the link.
    pub state: PeerState,
    /// Where data goes, if the link is up and has a route.
    pub route: Option<Route>,
    /// Whether the route is metered at either end or by its kind, as the controller ranks it
    /// (vv-05 §2.2, §4.8).
    pub metered: bool,
    /// Whether the route does not meet the delivery class of the `tun` plane (vv-05 §4.7).
    pub degraded: bool,
    /// What the peer's shared candidates say about its NAT.
    pub nat: PeerNat,
    /// The peer's candidates: shared ones from its latest handshake, then the address book's.
    pub candidates: Vec<Candidate>,
    /// The switches where the peer is online.
    pub switches: Vec<SwitchId>,
    /// Whether the peer's candidates are being probed (vv-05 §4.3).
    pub probing: bool,
    /// Whether a relay fallback is pending or under way (vv-05 §4.4).
    pub fallback: bool,
    /// What the active route has carried; `None` without one.
    pub meter: Option<Meter>,
    /// The smoothed round-trip time of the active route, to the millisecond.
    pub rtt: Option<Duration>,
    /// Every route of the link in rank order; empty while the link is not up.
    pub routes: Vec<PeerRoute>,
}

/// A site that some peer has offered, live or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSite {
    /// The site.
    pub site: Site,
    /// The peers offering it, by key; one whose link is down is shown as not live.
    pub peers: Vec<SitePeer>,
    /// The exit in use; `None` while no peer offering the site is live.
    pub chosen: Option<NodePublic>,
    /// This node's address in the site.
    pub addr: Ipv6Addr,
}

/// The whole picture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    /// This node.
    pub local: Local,
    /// The peers, by key.
    pub peers: Vec<Peer>,
    /// The sites some peer has offered, in site order.
    pub sites: Vec<ExitSite>,
}

impl PeerNat {
    /// The inference from a peer's shared candidates.
    pub fn from_candidates(candidates: &[Candidate]) -> Self {
        let has = |l| candidates.iter().any(|c| c.label == l);
        if has(label::PUNCH) {
            PeerNat::Punchable
        } else if has(label::RELAY) {
            PeerNat::RelayOnly
        } else {
            PeerNat::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use vardevall_proto::route::Band;

    use super::*;

    #[test]
    fn a_route_to_an_address_is_shaped_by_its_class_and_label_never_by_the_address() {
        let a: SocketAddr = "[2001:db8::5]:1".parse().unwrap();
        let low = RouteClass {
            band: Band::High,
            latency: Latency::Low,
            metered: false,
        };
        let high = RouteClass {
            latency: Latency::High,
            ..low
        };
        assert_eq!(Route::to_addr(a, false, "lan", low), Route::Lan(a));
        assert_eq!(
            Route::to_addr(a, false, "learned", high),
            Route::Internet(a)
        );
        let private: SocketAddr = "192.168.1.5:1".parse().unwrap();
        assert_eq!(
            Route::to_addr(private, false, "static", high),
            Route::Internet(private)
        );
        assert_eq!(Route::to_addr(a, false, "relay", high), Route::PeerRelay(a));
        assert_eq!(Route::to_addr(a, true, "punch", high), Route::OwnRelay(a));
    }

    #[test]
    fn peer_nat_from_candidates() {
        let punch = Candidate::punch("193.205.81.9:51820".parse().unwrap());
        let relay = Candidate::relay("84.46.243.47:49297".parse().unwrap());
        assert_eq!(PeerNat::from_candidates(&[]), PeerNat::Unknown);
        assert_eq!(
            PeerNat::from_candidates(&[relay, punch]),
            PeerNat::Punchable
        );
        assert_eq!(PeerNat::from_candidates(&[relay]), PeerNat::RelayOnly);
    }

    #[test]
    fn metered_routes() {
        let a: SocketAddr = "84.46.243.47:49297".parse().unwrap();
        assert!(Route::OwnRelay(a).metered());
        assert!(Route::PeerRelay(a).metered());
        assert!(Route::Switch(SwitchId(0)).metered());
        assert!(!Route::Internet(a).metered());
        assert!(!Route::Lan(a).metered());
    }
}
