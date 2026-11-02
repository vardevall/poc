//! Destinations an exit does not carry.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ip::exit::IPV4_POOL;

/// The private IPv4 ranges a client keeps off the exit, as address and
/// prefix length.
pub const PRIVATE_V4: [(Ipv4Addr, u8); 4] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
];

/// The IPv4 ranges an exit refuses: [`PRIVATE_V4`], loopback, the "this network" block, the
/// exit's own pool, multicast and the reserved block above it.
const REFUSED_V4: [(Ipv4Addr, u8); 9] = [
    PRIVATE_V4[0],
    PRIVATE_V4[1],
    PRIVATE_V4[2],
    PRIVATE_V4[3],
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    IPV4_POOL,
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// Unique-local and link-local IPv6, as address and prefix length.
const REFUSED_V6: [(Ipv6Addr, u8); 2] = [
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
];

/// Whether an exit refuses the IPv4 destination `dst`.
pub fn refuses_v4(dst: Ipv4Addr) -> bool {
    REFUSED_V4
        .iter()
        .any(|(net, len)| u32::from(dst) >> (32 - len) == u32::from(*net) >> (32 - len))
}

/// Whether an exit refuses the IPv6 destination `dst`, outside the overlay.
pub fn refuses_v6(dst: &Ipv6Addr) -> bool {
    REFUSED_V6
        .iter()
        .any(|(net, len)| u128::from(*dst) >> (128 - len) == u128::from(*net) >> (128 - len))
}

/// Whether an exit could carry a packet to `addr`: not unspecified, loopback or link-local.
pub fn is_global(addr: &Ipv6Addr) -> bool {
    let o = addr.octets();
    let link_local = o[0] == 0xfe && o[1] & 0xc0 == 0x80;
    !(addr.is_unspecified() || addr.is_loopback() || link_local)
}

/// Why an exit does not carry an IPv6 destination outside the overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A private destination: administratively prohibited.
    Prohibited,
    /// No route: not a global destination, or the exit has no IPv6 uplink.
    NoRoute,
}

/// What an exit does with an IPv6 packet for `dst`, outside the overlay and the site: `None`
/// carries it. `uplink` is whether the host has an IPv6 route to the
/// internet.
pub fn refusal_v6(dst: &Ipv6Addr, uplink: bool) -> Option<Refusal> {
    if refuses_v6(dst) {
        Some(Refusal::Prohibited)
    } else if !uplink || !is_global(dst) {
        Some(Refusal::NoRoute)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ipv6_is_prohibited_and_what_has_no_uplink_has_no_route() {
        let ula: Ipv6Addr = "fd00::1".parse().unwrap();
        let global: Ipv6Addr = "2606:4700::1111".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        assert_eq!(refusal_v6(&ula, true), Some(Refusal::Prohibited));
        assert_eq!(refusal_v6(&link_local, true), Some(Refusal::Prohibited));
        assert_eq!(refusal_v6(&global, true), None);
        assert_eq!(refusal_v6(&global, false), Some(Refusal::NoRoute));
        assert_eq!(
            refusal_v6(&Ipv6Addr::LOCALHOST, true),
            Some(Refusal::NoRoute)
        );
    }

    #[test]
    fn the_refused_ipv4_ranges_include_the_pool_and_leave_the_internet() {
        assert!(refuses_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(refuses_v4(Ipv4Addr::new(198, 18, 0, 9)));
        assert!(refuses_v4(Ipv4Addr::new(239, 1, 1, 1)));
        assert!(!refuses_v4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!refuses_v4(Ipv4Addr::new(1, 1, 1, 1)));
    }
}
