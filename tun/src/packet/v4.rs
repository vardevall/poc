//! IPv4 packets as an exit carries them: their addresses and the ICMPv4 errors the
//! router sends (RFC 792, RFC 1812).

use std::net::Ipv4Addr;

use super::sum;

/// Length of the IPv4 header without options.
pub const HEADER_LEN: usize = 20;
/// Protocol number of ICMPv4.
pub const ICMPV4: u8 = 1;

/// ICMPv4 Destination Unreachable.
pub const DEST_UNREACHABLE: u8 = 3;
/// Communication administratively prohibited (of Destination Unreachable, RFC 1812 §5.2.7.1).
pub const ADMIN_PROHIBITED: u8 = 13;

/// Most bytes of the offending packet an error quotes: with the headers, 576 bytes in all.
const QUOTE: usize = 576 - HEADER_LEN - 8;

fn checksum(data: &[u8]) -> u16 {
    let mut acc = sum(data, 0);
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The source and destination of a well-formed IPv4 packet, fragment or not.
pub fn addrs(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < HEADER_LEN || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if ihl < HEADER_LEN || total < ihl || total > packet.len() {
        return None;
    }
    let p = packet;
    Some((
        Ipv4Addr::new(p[12], p[13], p[14], p[15]),
        Ipv4Addr::new(p[16], p[17], p[18], p[19]),
    ))
}

/// An ICMPv4 error from `src` to the source of `offending`, or `None` where none may be sent:
/// the offending packet is malformed, a later fragment, an ICMP error itself, or not from a
/// unicast address.
pub fn error(src: Ipv4Addr, kind: u8, code: u8, offending: &[u8]) -> Option<Vec<u8>> {
    let (from, _) = addrs(offending)?;
    let ihl = usize::from(offending[0] & 0x0f) * 4;
    let later_fragment = u16::from_be_bytes([offending[6], offending[7]]) & 0x1fff != 0;
    let is_error = offending[9] == ICMPV4
        && offending
            .get(ihl)
            .is_some_and(|t| matches!(t, 3 | 4 | 5 | 11 | 12));
    if later_fragment
        || is_error
        || from.is_unspecified()
        || from.is_broadcast()
        || from.is_multicast()
        || from.is_loopback()
    {
        return None;
    }
    let mut m = vec![kind, code, 0, 0, 0, 0, 0, 0];
    m.extend_from_slice(&offending[..offending.len().min(QUOTE)]);
    let c = checksum(&m);
    m[2..4].copy_from_slice(&c.to_be_bytes());
    let total = u16::try_from(HEADER_LEN + m.len()).unwrap_or(u16::MAX);
    let mut p = Vec::with_capacity(HEADER_LEN + m.len());
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 64, ICMPV4, 0, 0]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&from.octets());
    let c = checksum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(&m);
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0];
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&[0, 53, 0, 53, 0, 8, 0, 0]);
        p
    }

    #[test]
    fn an_error_goes_back_to_the_source_quoting_the_packet_with_valid_checksums() {
        let from = Ipv4Addr::new(198, 18, 3, 4);
        let p = udp(from, Ipv4Addr::new(192, 168, 1, 1));
        let e = error(
            Ipv4Addr::new(198, 18, 0, 1),
            DEST_UNREACHABLE,
            ADMIN_PROHIBITED,
            &p,
        )
        .unwrap();
        assert_eq!(addrs(&e), Some((Ipv4Addr::new(198, 18, 0, 1), from)));
        assert_eq!(checksum(&e[..HEADER_LEN]), 0);
        assert_eq!(checksum(&e[HEADER_LEN..]), 0);
        assert_eq!(&e[HEADER_LEN..HEADER_LEN + 2], &[3, 13]);
        assert_eq!(&e[HEADER_LEN + 8..], &p[..]);
    }

    #[test]
    fn no_error_answers_an_error_a_later_fragment_or_a_multicast_source() {
        let to = Ipv4Addr::new(1, 1, 1, 1);
        let own = Ipv4Addr::new(198, 18, 0, 1);
        let mut frag = udp(Ipv4Addr::new(198, 18, 3, 4), to);
        frag[7] = 1;
        assert_eq!(error(own, 3, 13, &frag), None);
        let multicast = udp(Ipv4Addr::new(224, 0, 0, 1), to);
        assert_eq!(error(own, 3, 13, &multicast), None);
        let first = udp(Ipv4Addr::new(198, 18, 3, 4), to);
        let e = error(own, 3, 13, &first).unwrap();
        assert_eq!(error(own, 3, 13, &e), None);
        assert_eq!(addrs(&first[..19]), None);
    }
}
