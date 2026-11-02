//! Events for the embedder and their JSON form (`vv_event_cb`).

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;
use vardevall::view::{Route, View};
use vardevall::{Budget, LogLevel, PeerState, SwitchState, Trust};
use vardevall_proto::ip::site::Site;
use vardevall_proto::keys::NodePublic;

/// The state of the whole tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Status {
    /// The engine runs and listens on this UDP port.
    Started {
        /// The bound port.
        listen_port: u16,
    },
    /// The engine stopped.
    Stopped,
}

/// How a switch is authenticated (vv-04 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchKind {
    /// A pinned address: the switch is known by its key.
    Pinned,
    /// A web address: the switch is known by its host name in the Web PKI.
    Web,
}

impl SwitchKind {
    /// `"pinned"` or `"web"`.
    pub const fn name(self) -> &'static str {
        match self {
            SwitchKind::Pinned => "pinned",
            SwitchKind::Web => "web",
        }
    }
}

/// Something the embedder may want to show or log.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// The tunnel started or stopped.
    Status(Status),
    /// A peer was configured or found by member trust.
    Added {
        /// The peer's key.
        key: NodePublic,
        /// The peer's overlay `ula`.
        addr: Ipv6Addr,
        /// The configured name, if any.
        name: Option<String>,
        /// How the peer is trusted.
        trust: Trust,
    },
    /// A peer was removed or evicted.
    Removed {
        /// The peer's key.
        key: NodePublic,
        /// The peer's overlay `ula`.
        addr: Ipv6Addr,
        /// The configured name, if any.
        name: Option<String>,
    },
    /// The link to a peer changed state.
    Peer {
        /// The peer's key.
        key: NodePublic,
        /// The peer's overlay `ula`.
        addr: Ipv6Addr,
        /// The configured name, if any.
        name: Option<String>,
        /// What happened.
        state: PeerState,
    },
    /// The route to a peer changed; `None` while the link is not up.
    Route {
        /// The peer's key.
        key: NodePublic,
        /// The peer's overlay `ula`.
        addr: Ipv6Addr,
        /// The configured name, if any.
        name: Option<String>,
        /// The route, if any.
        route: Option<Route>,
    },
    /// The exit chosen for a site changed; `None` once the site has no live exit
    ///.
    Exit {
        /// The site.
        site: Site,
        /// The exit's key.
        via: Option<NodePublic>,
        /// This node's address in the site.
        addr: Ipv6Addr,
        /// The IPv4 address the exit gives this node; `None` without an exit or
        /// when it does not carry IPv4.
        ipv4: Option<Ipv4Addr>,
    },
    /// The offers remembered changed: the host keeps them and gives them back
    /// after a start with [`Tunnel::remember_exits`](super::Tunnel::remember_exits).
    Exits {
        /// Each peer and the site it offered.
        offers: Vec<(NodePublic, Site)>,
    },
    /// A switch changed state (vv-04 §4.6).
    Switch {
        /// `host:port` of the switch.
        address: String,
        /// Whether the address is pinned or a web address.
        kind: SwitchKind,
        /// What happened.
        state: SwitchState,
    },
    /// The budget of a transport was set, removed, crossed a level or ran out.
    Budget {
        /// The transport's name.
        transport: String,
        /// The budget as it stands, if the transport has one.
        budget: Option<Budget>,
    },
    /// What the node believes about its paths (`vardevall::view`).
    View {
        /// The view.
        view: View,
        /// The overlay `ula` and configured name of each entry of `view.peers`, in order.
        peers: Vec<(Ipv6Addr, Option<String>)>,
        /// The kind of each switch of `view.local.switches`, in order.
        switches: Vec<SwitchKind>,
        /// The site in use and its exit, when the host uses this network's exit and the choice is
        /// made.
        exit: Option<(Site, NodePublic)>,
    },
    /// A log line.
    Log {
        /// Severity.
        level: LogLevel,
        /// Text.
        message: String,
    },
}

impl Event {
    /// The JSON object `{"type":"status"|"added"|"removed"|"peer"|"route"|"exit"|"exits"|
    /// "switch"|"budget"|"view"|"log","network":"<network>", ...}` of vardevall.h.
    pub fn to_json(&self, network: &str) -> String {
        super::json::render(network, self)
    }
}
