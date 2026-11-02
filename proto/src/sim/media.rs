//! The simulated transports as `proto` sees them; the same shapes as the lib's built-ins.

use crate::handshake::message::MAX_FRAGMENT;
use crate::route::{Band, Latency, RouteClass};
use crate::transport::{Framing, Medium, Reachability, Remote};

/// Which simulated transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediumKind {
    /// The host's UDP socket.
    Udp,
    /// The host's allocation on the TURN server, on demand.
    Turn,
    /// The host's registration with the switch.
    Switch,
}

/// A [`Medium`] of the simulation.
#[derive(Debug, Clone, Copy)]
pub struct SimMedium(pub MediumKind);

impl Medium for SimMedium {
    fn name(&self) -> &str {
        match self.0 {
            MediumKind::Udp => "udp",
            MediumKind::Turn => "turn",
            MediumKind::Switch => "switch",
        }
    }

    fn class(&self) -> RouteClass {
        let (band, latency, metered) = match self.0 {
            MediumKind::Udp => (Band::High, Latency::High, false),
            MediumKind::Turn => (Band::High, Latency::High, true),
            MediumKind::Switch => (Band::Low, Latency::High, true),
        };
        RouteClass {
            band,
            latency,
            metered,
        }
    }

    fn reaches(&self, to: &Remote, local: bool) -> bool {
        match (self.0, to) {
            (MediumKind::Udp, Remote::Addr(_)) => true,
            (MediumKind::Turn, Remote::Addr(_)) => !local,
            (MediumKind::Switch, Remote::Peer(_)) => true,
            _ => false,
        }
    }

    fn reachability(&self) -> Reachability {
        match self.0 {
            MediumKind::Switch => Reachability::Reported,
            MediumKind::Udp | MediumKind::Turn => Reachability::Probe,
        }
    }

    fn framing(&self) -> Framing {
        match self.0 {
            MediumKind::Switch => Framing::Whole,
            MediumKind::Udp | MediumKind::Turn => Framing::Fragmented { max: MAX_FRAGMENT },
        }
    }

    fn on_demand(&self) -> bool {
        self.0 == MediumKind::Turn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Remote {
        Remote::Addr(s.parse().unwrap())
    }

    #[test]
    fn the_media_have_their_own_class_whatever_the_address() {
        let class = |m: MediumKind| SimMedium(m).class();
        assert_eq!(
            (
                class(MediumKind::Udp).latency,
                class(MediumKind::Udp).metered
            ),
            (Latency::High, false)
        );
        assert!(class(MediumKind::Turn).metered);
    }

    #[test]
    fn turn_does_not_reach_a_local_candidate() {
        let turn = SimMedium(MediumKind::Turn);
        assert!(turn.reaches(&addr("203.0.113.9:1"), false));
        assert!(turn.reaches(&addr("10.0.0.2:1"), false));
        assert!(!turn.reaches(&addr("203.0.113.9:1"), true));
        assert!(SimMedium(MediumKind::Udp).reaches(&addr("10.0.0.2:1"), true));
    }

    #[test]
    fn the_switch_is_low_band_and_metered() {
        let c = SimMedium(MediumKind::Switch).class();
        assert_eq!((c.band, c.metered), (Band::Low, true));
    }
}
