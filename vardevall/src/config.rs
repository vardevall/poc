//! Settings of a node (vv-07 §3).

use std::net::SocketAddr;
use std::time::Duration;

use vardevall_proto::ip::exit::ExitServe;
use vardevall_proto::ip::service::Service;
use vardevall_proto::keys::NodePublic;
use vardevall_proto::keys::{NetworkId, NetworkSecret, NodeSecret, PairPsk};
use vardevall_proto::route::DeliveryClass;

pub use vardevall_switch_proto::address::{AddressError, SwitchAuth, SwitchSpec};

use crate::candidates::CandidateSource;
use crate::mdns::MdnsRequestSink;
use crate::net::mark::SocketMark;

/// Where a peer's `endpoint` points (vv-07 §3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// An IP address and port.
    Addr(SocketAddr),
    /// A DNS name looked up with A and AAAA.
    Host {
        /// The name.
        host: String,
        /// The port.
        port: u16,
    },
    /// A name without a port, resolved through SRV records of `_vardevall._udp.<name>`, whose
    /// targets are then looked up with A and AAAA.
    Srv(String),
}

/// A key-trusted peer (vv-07 `[[peer]]`).
#[derive(Clone)]
pub struct PeerSpec {
    /// The peer's public key.
    pub public: NodePublic,
    /// The pair PSK (vv-02 §2.1).
    pub psk: Option<PairPsk>,
    /// `static` candidates.
    pub endpoints: Vec<Endpoint>,
    /// Whether the endpoints are known to be on this link: their candidates are `local`, so LAN
    /// class, and TURN never carries them.
    pub endpoints_local: bool,
}

/// A TURN server with its own credentials, used in addition to those the switches issue and
/// preferred over them by default (vv-07 §3.4, vv-05 §3.3).
#[derive(Clone)]
pub struct TurnSpec {
    /// `turn:` URIs of one provider; only UDP ones are used.
    pub urls: Vec<String>,
    /// The long-term credential username.
    pub username: String,
    /// The long-term credential password.
    pub credential: String,
    /// Higher is tried first; switch-issued TURN counts as 0.
    pub priority: i32,
}

impl PartialEq for TurnSpec {
    fn eq(&self, other: &Self) -> bool {
        self.urls == other.urls
            && self.username == other.username
            && self.credential == other.credential
            && self.priority == other.priority
    }
}

impl PeerSpec {
    /// Whether `other` has the same pair PSK, none counting as the zero key.
    pub fn same_psk(&self, other: &PeerSpec) -> bool {
        let psk = |p: &PeerSpec| p.psk.as_ref().map_or([0u8; 32], |k| *k.as_bytes());
        vardevall_proto::keys::crypto::ct_eq(&psk(self), &psk(other))
    }

    /// Whether `other` describes the same peer in the same way: key, pair PSK, endpoints and
    /// whether they are local.
    pub fn same_as(&self, other: &PeerSpec) -> bool {
        self.public == other.public
            && self.same_psk(other)
            && self.endpoints == other.endpoints
            && self.endpoints_local == other.endpoints_local
    }
}

/// What a running node takes in place of the settings it started with:
/// the key-trusted peers, the exit it serves and the STUN and TURN servers of the
/// configuration. Peers whose entry did not change keep their sessions.
pub struct LiveUpdate {
    /// All key-trusted peers.
    pub peers: Vec<PeerSpec>,
    /// The exit this node offers.
    pub exit: Option<ExitServe>,
    /// STUN servers in addition to the switches'.
    pub stun: Vec<StunSpec>,
    /// TURN servers configured by the user.
    pub turn: Vec<TurnSpec>,
}

/// A STUN server of the configuration, used in addition to those of the switches (vv-05 §3.1,
/// vv-07 §3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunSpec {
    /// `stun:` URIs of one provider; `stuns:` ones are not used.
    pub urls: Vec<String>,
    /// The short-term credential username (RFC 8489 §9.1), if the server asks for one.
    pub username: Option<String>,
    /// The short-term credential password.
    pub credential: Option<String>,
}

/// Whether a switch may carry data at all (vv-05 §4.7, vv-07 §3.2).
///
/// Handshakes and control messages go through a switch in either case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SwitchPath {
    /// A switch is the last route, for traffic whose delivery class allows it.
    #[default]
    On,
    /// A switch carries no data.
    Off,
}

/// How mDNS runs (vv-09).
pub enum MdnsMode {
    /// No mDNS.
    Off,
    /// The engine's own multicast sockets.
    Builtin(BuiltinMdns),
    /// A platform service; requests go to the sink and results come in through
    /// [`crate::Handle::mdns_event`].
    External(Box<dyn MdnsRequestSink>),
}

/// Settings of the built-in mDNS transport.
#[derive(Debug, Clone, Default)]
pub struct BuiltinMdns {
    /// Interface names to use; `None` selects every physical interface.
    pub interfaces: Option<Vec<String>>,
    /// Interface names never to use, such as the overlay interface.
    pub exclude: Vec<String>,
}

/// Everything a node needs to run.
pub struct NodeConfig {
    /// The node key.
    pub secret: NodeSecret,
    /// The network secret.
    pub network_secret: NetworkSecret,
    /// The network ID; defaults to the network public key.
    pub network_id: Option<NetworkId>,
    /// The UDP port, or 0 for a random one.
    pub listen_port: u16,
    /// The inner MTU (vv-03 §3.4).
    pub mtu: usize,
    /// Accept any member of the network (vv-02 §4.4).
    pub accept_members: bool,
    /// mDNS settings.
    pub mdns: MdnsMode,
    /// Key-trusted peers.
    pub peers: Vec<PeerSpec>,
    /// Switches to register with (vv-04 §4.6).
    pub switches: Vec<SwitchSpec>,
    /// TURN servers configured by the user.
    pub turn: Vec<TurnSpec>,
    /// Whether a switch may carry data.
    pub switch_path: SwitchPath,
    /// The delivery class of the `tun` plane (vv-05 §4.7).
    pub tun_class: DeliveryClass,
    /// The interval at which an unmetered active route is pinged while data goes out on it and
    /// nothing comes back on it; `None` is [`vardevall_proto::route::DETECT_TIMEOUT`]. A metered
    /// route is pinged every `KEEPALIVE_TIMEOUT`.
    pub detect_timeout: Option<Duration>,
    /// `FALLBACK_DELAY`: how long the direct routes get before a metered route is used; zero
    /// relays first. The default is [`vardevall_proto::route::FALLBACK_DELAY`].
    pub fallback_delay: Duration,
    /// STUN servers in addition to those of the switches (vv-05 §3.1).
    pub stun: Vec<StunSpec>,
    /// Services announced from the start (vve-14 §2.1); more come from [`crate::Handle::announce`].
    pub services: Vec<Service>,
    /// Resolvers for the SRV lookups of `endpoint` entries without a port (vv-07 §3.5); empty
    /// uses those the system lists in `/etc/resolv.conf`, and none where it has none.
    pub dns_servers: Vec<SocketAddr>,
    /// Whether the node itself watches the host's addresses for changes (vv-05 §4.6); an
    /// embedder with a platform path monitor reports them through
    /// [`crate::Handle::path_changed`] instead.
    pub watch_network: bool,
    /// Interfaces the watch on the host's addresses leaves out, such as the tunnel's own device.
    pub watch_exclude: Vec<String>,
    /// Local discovery sources in addition to mDNS (vv-05 §2.3), such as a same-host registry.
    pub discovery: Vec<Box<dyn CandidateSource>>,
    /// The exit this node offers to the peers it holds by key.
    pub exit: Option<ExitServe>,
    /// The firewall mark of every socket the node opens, for a host that routes its default
    /// traffic into the tunnel. Needs Linux and the `fwmark` feature, else
    /// [`Node::new`](crate::Node::new) refuses it. The mDNS sockets and the lookups of host names
    /// carry it; a name only the system knows is still looked up by the system's resolver.
    pub socket_mark: SocketMark,
}
