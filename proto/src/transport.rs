//! Transports as `proto` sees them: identifiers, paths and the [`Medium`] description
//!.
//!
//! `proto` knows no concrete transport. The caller registers each one with
//! [`crate::node::Node::add_transport`] and gets a [`TransportId`] back; datagrams come in and go
//! out on a [`Path`].

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::keys::NodePublic;
use crate::meter::{Budget, Level, Meter};
use crate::route::RouteClass;
use crate::time::Instant;

/// An on-demand transport that carried no data for this long is let go (vv-05 §3.3).
pub const DEMAND_IDLE: Duration = Duration::from_secs(60);

/// A registered transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransportId(pub u16);

/// The far end of a path on a transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Remote {
    /// A transport address: UDP, or the peer address of a TURN allocation.
    Addr(SocketAddr),
    /// A peer by key, for transports that address peers themselves (a switch).
    Peer(NodePublic),
}

/// Where a datagram came from or goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Path {
    /// The transport.
    pub via: TransportId,
    /// The far end.
    pub to: Remote,
}

impl Path {
    /// The transport address of the far end, if it has one.
    pub const fn addr(&self) -> Option<SocketAddr> {
        match self.to {
            Remote::Addr(a) => Some(a),
            Remote::Peer(_) => None,
        }
    }
}

/// How `proto` learns whether a peer is reachable on a transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    /// Routes are verified by probing.
    Probe,
    /// The transport reports it with [`crate::node::Node::set_reachable`] (a switch, from
    /// presence).
    Reported,
}

/// How handshake messages travel on a transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// Split into fragments of at most `max` bytes, with mac1 and cookies.
    Fragmented {
        /// Largest datagram.
        max: usize,
    },
    /// Whole messages without mac1; only for transports that authenticate senders themselves.
    Whole,
}

/// What `proto` needs to know about a transport.
pub trait Medium: Send + Sync {
    /// A short name for views and logs.
    fn name(&self) -> &str;
    /// The transport's own class: what a path over it is before its candidate says more.
    fn class(&self) -> RouteClass;
    /// Whether the transport can send to `to` at all; `local` says the candidate was found on
    /// this link or host, which a relay cannot reach. Learned paths pass `false`.
    fn reaches(&self, to: &Remote, local: bool) -> bool;
    /// How reachability is learnt.
    fn reachability(&self) -> Reachability;
    /// How handshake messages are framed.
    fn framing(&self) -> Framing;
    /// Whether the transport costs something to bring up, so `proto` asks for it with
    /// [`crate::node::Output::Demand`].
    fn on_demand(&self) -> bool;
}

/// One registered transport and the facts `proto` holds about it.
pub(crate) struct Entry {
    pub(crate) medium: Arc<dyn Medium>,
    /// Usable now; an on-demand transport starts not ready.
    pub(crate) ready: bool,
    /// Whether `proto` currently wants the on-demand transport up.
    pub(crate) demanded: bool,
    /// When the on-demand transport last carried data or was asked for; probes do not count.
    /// `None` while ready means its release was asked for.
    pub(crate) last_use: Option<Instant>,
    /// Peers reported reachable, for [`Reachability::Reported`] transports.
    pub(crate) reachable: HashSet<NodePublic>,
    /// Every datagram sent and received on it.
    pub(crate) meter: Meter,
    /// What it may still carry, if a volume was stated.
    pub(crate) budget: Option<Budget>,
}

impl Entry {
    /// Whether routes and messages may use it: ready, and its budget not exhausted.
    pub(crate) fn usable(&self) -> bool {
        self.ready && !self.exhausted()
    }

    /// Whether its budget is spent.
    pub(crate) fn exhausted(&self) -> bool {
        self.budget.is_some_and(|b| b.exhausted())
    }
}

/// The registered transports, in registration order.
#[derive(Default)]
pub(crate) struct Transports {
    entries: BTreeMap<TransportId, Entry>,
    next: u16,
    /// A budget ran out since the node last took stock of its routes.
    ran_out: bool,
}

impl Transports {
    /// Registers a transport; an on-demand one starts not ready.
    pub(crate) fn add(&mut self, medium: Arc<dyn Medium>) -> TransportId {
        let id = TransportId(self.next);
        self.next = self.next.wrapping_add(1);
        let ready = !medium.on_demand();
        self.entries.insert(
            id,
            Entry {
                medium,
                ready,
                demanded: false,
                last_use: None,
                reachable: HashSet::new(),
                meter: Meter::default(),
                budget: None,
            },
        );
        id
    }

    pub(crate) fn remove(&mut self, id: TransportId) -> Option<Entry> {
        self.entries.remove(&id)
    }

    pub(crate) fn get(&self, id: TransportId) -> Option<&Entry> {
        self.entries.get(&id)
    }

    pub(crate) fn get_mut(&mut self, id: TransportId) -> Option<&mut Entry> {
        self.entries.get_mut(&id)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (TransportId, &Entry)> {
        self.entries.iter().map(|(k, v)| (*k, v))
    }

    /// The framing of `id`, or `None` for an unknown transport.
    pub(crate) fn framing(&self, id: TransportId) -> Option<Framing> {
        self.get(id).map(|e| e.medium.framing())
    }

    /// Counts a datagram of `len` bytes sent on `via`; returns the level its budget crossed into.
    pub(crate) fn charge_sent(&mut self, via: TransportId, len: usize) -> Option<Level> {
        let e = self.entries.get_mut(&via)?;
        e.meter.add_sent(len);
        let level = e.budget.as_mut().and_then(|b| b.spend(len));
        self.ran_out |= level == Some(Level::Exhausted);
        level
    }

    /// Counts a datagram of `len` bytes received on `via`, against the budget too if it charges
    /// received bytes; returns the level it crossed into.
    pub(crate) fn charge_received(&mut self, via: TransportId, len: usize) -> Option<Level> {
        let e = self.entries.get_mut(&via)?;
        e.meter.add_received(len);
        let level = e
            .budget
            .as_mut()
            .filter(|b| b.received)
            .and_then(|b| b.spend(len));
        self.ran_out |= level == Some(Level::Exhausted);
        level
    }

    /// Whether a budget ran out since the last call.
    pub(crate) fn take_ran_out(&mut self) -> bool {
        std::mem::take(&mut self.ran_out)
    }

    /// The usable [`Reachability::Reported`] transports on which `peer` is reachable, in
    /// registration order.
    pub(crate) fn reporting<'a>(
        &'a self,
        peer: &'a NodePublic,
    ) -> impl Iterator<Item = TransportId> + 'a {
        self.iter()
            .filter(move |(_, e)| {
                e.usable()
                    && e.medium.reachability() == Reachability::Reported
                    && e.reachable.contains(peer)
            })
            .map(|(id, _)| id)
    }
}
