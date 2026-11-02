//! Synthetic Neighbor Advertisements for layer-2 tunnel devices (vv-06 §3.2).
//!
//! Layer-3 devices (macOS `utun`, Linux `tun`, Apple packet tunnels) need no neighbour
//! discovery, so the router uses this module only when constructed for a layer-2 device.

use std::net::Ipv6Addr;

use crate::packet::{self, HEADER_LEN, Header, icmp};

/// A link-layer address derived from an interface identifier: locally administered, unicast.
pub fn synthetic_mac(iid: &[u8; 8]) -> [u8; 6] {
    [0x02, iid[0], iid[1], iid[2], iid[3], iid[4]]
}

/// The Neighbor Advertisement answering a Neighbor Solicitation in `packet`, if the target is an
/// address for which `known` returns its interface identifier (RFC 4861 §7).
///
/// Solicitations from the unspecified address are duplicate address detection, which vv-06 §2.1
/// disables; they get no answer.
pub fn answer<F>(packet: &[u8], header: &Header, known: F) -> Option<Vec<u8>>
where
    F: Fn(&Ipv6Addr) -> Option<[u8; 8]>,
{
    if header.next != packet::ICMPV6 || header.hop_limit != 255 || header.src.is_unspecified() {
        return None;
    }
    let msg = packet.get(HEADER_LEN..HEADER_LEN + header.payload_len)?;
    if msg.len() < 24 || msg[0] != icmp::NEIGHBOR_SOLICITATION || msg[1] != 0 {
        return None;
    }
    if packet::checksum(&header.src, &header.dst, packet::ICMPV6, msg) != 0 {
        return None;
    }
    let target: [u8; 16] = msg[8..24].try_into().ok()?;
    let target = Ipv6Addr::from(target);
    let iid = known(&target)?;
    let mut body = Vec::with_capacity(28);
    body.extend_from_slice(&[0x60, 0, 0, 0]);
    body.extend_from_slice(&target.octets());
    body.extend_from_slice(&[2, 1]);
    body.extend_from_slice(&synthetic_mac(&iid));
    Some(packet::build_icmpv6(
        &target,
        &header.src,
        icmp::NEIGHBOR_ADVERTISEMENT,
        0,
        &body,
        255,
    ))
}

#[cfg(test)]
pub(crate) fn solicitation(src: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
    let mut sol = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0];
    sol[13..16].copy_from_slice(&target.octets()[13..16]);
    let dst = Ipv6Addr::from(sol);
    let mut body = vec![0, 0, 0, 0];
    body.extend_from_slice(&target.octets());
    packet::build_icmpv6(&src, &dst, icmp::NEIGHBOR_SOLICITATION, 0, &body, 255)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn answers_for_known_targets_only() {
        let target = a("fd00::6d0a:8bf2:5ecf:91dd");
        let iid = [0x6d, 0x0a, 0x8b, 0xf2, 0x5e, 0xcf, 0x91, 0xdd];
        let ns = solicitation(a("fd00::1"), target);
        let h = packet::parse(&ns).unwrap();
        let na = answer(&ns, &h, |t| (*t == target).then_some(iid)).unwrap();
        let nh = packet::parse(&na).unwrap();
        assert_eq!(nh.src, target);
        assert_eq!(nh.dst, a("fd00::1"));
        assert_eq!(nh.hop_limit, 255);
        let msg = &na[HEADER_LEN..];
        assert_eq!(msg[0], icmp::NEIGHBOR_ADVERTISEMENT);
        assert_eq!(msg[4], 0x60);
        assert_eq!(&msg[8..24], &target.octets());
        assert_eq!(&msg[24..26], &[2, 1]);
        assert_eq!(&msg[26..32], &synthetic_mac(&iid));
        assert_eq!(packet::checksum(&nh.src, &nh.dst, packet::ICMPV6, msg), 0);
        assert!(answer(&ns, &h, |_| None).is_none());
    }

    #[test]
    fn ignores_duplicate_address_detection() {
        let target = a("fd00::2");
        let ns = solicitation(Ipv6Addr::UNSPECIFIED, target);
        let h = packet::parse(&ns).unwrap();
        assert!(answer(&ns, &h, |_| Some([0; 8])).is_none());
    }

    #[test]
    fn requires_hop_limit_255() {
        let target = a("fd00::2");
        let mut ns = solicitation(a("fd00::1"), target);
        ns[7] = 64;
        let h = packet::parse(&ns).unwrap();
        assert!(answer(&ns, &h, |_| Some([0; 8])).is_none());
    }
}
