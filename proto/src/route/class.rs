//! Route classes and the delivery classes of traffic.

/// Nominal bandwidth of a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Band {
    /// Low bandwidth, such as the switch path or Bluetooth LE.
    Low,
    /// High bandwidth.
    High,
}

/// Nominal latency of a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Latency {
    /// High latency; a later variant is better.
    High,
    /// Low latency.
    Low,
}

/// The class of a route: what the medium says it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteClass {
    /// Nominal bandwidth.
    pub band: Band,
    /// Nominal latency.
    pub latency: Latency,
    /// Whether traffic on the route is counted or limited.
    pub metered: bool,
}

/// The bandwidth traffic asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WantBand {
    /// Any bandwidth.
    Any,
    /// High bandwidth.
    High,
}

/// The latency traffic asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WantLatency {
    /// Any latency.
    Any,
    /// Low latency.
    Low,
}

/// What a flow of traffic needs from a route, and whether it may do with less (vv-05 §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryClass {
    /// The bandwidth asked for.
    pub band: WantBand,
    /// The latency asked for.
    pub latency: WantLatency,
    /// Whether the traffic is sent on a route that does not meet the class.
    pub degrade: bool,
}

impl Default for DeliveryClass {
    fn default() -> Self {
        DeliveryClass {
            band: WantBand::High,
            latency: WantLatency::Any,
            degrade: false,
        }
    }
}

impl DeliveryClass {
    /// Whether a route of class `c` meets the class: its band and latency are at least those
    /// asked.
    pub fn met_by(&self, c: &RouteClass) -> bool {
        let band = match self.band {
            WantBand::Any => true,
            WantBand::High => c.band == Band::High,
        };
        let latency = match self.latency {
            WantLatency::Any => true,
            WantLatency::Low => c.latency == Latency::Low,
        };
        band && latency
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn class(band: Band, latency: Latency, metered: bool) -> RouteClass {
        RouteClass {
            band,
            latency,
            metered,
        }
    }

    const INTERNET: RouteClass = class(Band::High, Latency::High, false);
    const LAN: RouteClass = class(Band::High, Latency::Low, false);
    const RELAY: RouteClass = class(Band::High, Latency::High, true);
    const SWITCH: RouteClass = class(Band::Low, Latency::High, true);

    #[test]
    fn the_default_class_excludes_the_low_band() {
        let c = DeliveryClass::default();
        assert!(c.met_by(&INTERNET));
        assert!(c.met_by(&LAN));
        assert!(c.met_by(&RELAY));
        assert!(!c.met_by(&SWITCH));
    }

    #[test]
    fn any_band_accepts_the_low_band_and_low_latency_excludes_high() {
        let any = DeliveryClass {
            band: WantBand::Any,
            ..DeliveryClass::default()
        };
        assert!(any.met_by(&SWITCH));
        let low = DeliveryClass {
            latency: WantLatency::Low,
            ..DeliveryClass::default()
        };
        assert!(low.met_by(&LAN));
        assert!(!low.met_by(&INTERNET));
    }
}
