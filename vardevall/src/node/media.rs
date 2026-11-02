//! The built-in transports as `proto` sees them.

use vardevall_proto::route::{Band, Latency, RouteClass};
use vardevall_proto::transport::{Framing, Medium, Reachability, Remote, TransportId};

use crate::switch::SwitchId;

/// One switch: whole messages to peers by key, reachability from presence.
pub(super) struct SwitchMedium {
    name: String,
}

impl SwitchMedium {
    pub(super) fn new(name: String) -> Self {
        SwitchMedium { name }
    }
}

impl Medium for SwitchMedium {
    fn name(&self) -> &str {
        &self.name
    }

    fn class(&self) -> RouteClass {
        RouteClass {
            band: Band::Low,
            latency: Latency::High,
            metered: true,
        }
    }

    fn reaches(&self, to: &Remote, _: bool) -> bool {
        matches!(to, Remote::Peer(_))
    }

    fn reachability(&self) -> Reachability {
        Reachability::Reported
    }

    fn framing(&self) -> Framing {
        Framing::Whole
    }

    fn on_demand(&self) -> bool {
        false
    }
}

/// The transports the engine registered with `proto`.
pub(super) struct Media {
    pub(super) udp: TransportId,
    pub(super) turn: TransportId,
    /// Indexed by [`SwitchId`].
    pub(super) switches: Vec<TransportId>,
}

impl Media {
    /// The transport of switch `id`.
    pub(super) fn switch(&self, id: SwitchId) -> Option<TransportId> {
        self.switches.get(id.0 as usize).copied()
    }

    /// The switch behind transport `via`.
    pub(super) fn switch_id(&self, via: TransportId) -> Option<SwitchId> {
        self.switches
            .iter()
            .position(|t| *t == via)
            .and_then(|i| u32::try_from(i).ok())
            .map(SwitchId)
    }
}
