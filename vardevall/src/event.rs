//! Notifications from the engine to its embedder.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use vardevall_proto::ip::site::Site;
use vardevall_proto::keys::NodePublic;
use vardevall_proto::meter::Budget;
use vardevall_proto::node::{PeerState, Trust};

use crate::switch::SwitchId;
use crate::view::Route;

/// Severity of a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Detail for debugging.
    Debug,
    /// Normal operation.
    Info,
    /// Something is wrong but the node continues.
    Warn,
    /// An operation failed.
    Error,
}

/// The state of the node itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The node runs and listens on this local address.
    Started {
        /// The bound socket address.
        listen: SocketAddr,
    },
    /// The node stopped.
    Stopped,
}

pub use vardevall_switch_proto::session::{SwitchFailure, SwitchState};

/// What the engine reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    /// The node started or stopped.
    Status(Status),
    /// A peer was configured or found by member trust.
    Added {
        /// The peer.
        peer: NodePublic,
        /// How it is trusted.
        trust: Trust,
    },
    /// A peer was removed, explicitly or evicted as an idle member.
    Removed {
        /// The peer.
        peer: NodePublic,
    },
    /// The link to a peer changed state; reported once per change.
    Peer {
        /// The peer.
        peer: NodePublic,
        /// The new state.
        state: PeerState,
    },
    /// The route that carries data to a peer changed; `None` while the link is not up
    ///. It follows the [`NodeEvent::Peer`] of the same change.
    Route {
        /// The peer.
        peer: NodePublic,
        /// The route, if any.
        route: Option<Route>,
    },
    /// The sites that some peer has offered, live or not, changed. It precedes
    /// the [`NodeEvent::Exit`] of the same change.
    Sites {
        /// The sites, in order.
        sites: Vec<Site>,
    },
    /// The offers remembered, live or not, changed: each peer and the site it
    /// offered, for the embedder to keep across restarts and give back with
    /// [`Handle::remember_exits`](crate::Handle::remember_exits).
    Remembered {
        /// The peers and their sites, by key.
        offers: Vec<(NodePublic, Site)>,
    },
    /// The exit chosen for a site, or the IPv4 address it gives this node, changed; `None` once
    /// the site has no live exit. It follows the [`NodeEvent::Peer`] and
    /// [`NodeEvent::Route`] of the same change.
    Exit {
        /// The site.
        site: Site,
        /// The exit.
        via: Option<NodePublic>,
        /// This node's address in the site.
        addr: Ipv6Addr,
        /// The IPv4 address the exit gives this node; `None` without an exit or
        /// when it does not carry IPv4.
        ipv4: Option<Ipv4Addr>,
    },
    /// The exit this node serves gave `peer` an IPv4 address, or freed it.
    ExitClient {
        /// The peer.
        peer: NodePublic,
        /// Its address; `None` once freed.
        ipv4: Option<Ipv4Addr>,
    },
    /// A switch changed state.
    Switch {
        /// The switch, in configuration order.
        id: SwitchId,
        /// `host:port` of the switch.
        address: String,
        /// The new state.
        state: SwitchState,
    },
    /// An IPv6 packet arrived from a peer (vv-03 §3.2).
    Packet {
        /// The peer.
        peer: NodePublic,
        /// The packet.
        packet: Vec<u8>,
    },
    /// The budget of a transport was set (`Some`) or removed (`None`), or crossed into a lower
    /// level or ran out. An exhausted transport is unusable until a fresh budget
    /// arrives.
    Budget {
        /// The transport's name: `"udp"`, `"turn"` or the address of a switch.
        transport: String,
        /// The budget as it stands.
        budget: Option<Budget>,
    },
    /// What the node believes about its paths changed; sent at most every
    /// [`VIEW_INTERVAL`](crate::view::VIEW_INTERVAL), and only when it differs from the last one.
    /// A change in meters and remaining budgets alone counts only every
    /// [`METER_INTERVAL`](crate::view::METER_INTERVAL).
    View(crate::view::View),
    /// A log line.
    Log {
        /// Its severity.
        level: LogLevel,
        /// The text.
        message: String,
    },
}

/// Receives the engine's events on the engine task; it must not block.
pub trait EventSink: Send {
    /// Handles one event.
    fn event(&mut self, event: NodeEvent);
}

impl<F: FnMut(NodeEvent) + Send> EventSink for F {
    fn event(&mut self, event: NodeEvent) {
        self(event)
    }
}
