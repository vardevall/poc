//! IPv6, UDP and ICMPv6 packets as read from and written to the tunnel (vv-03 §3.2, vv-06 §3).
//!
//! Only what the router, NDP and DNS responder need: header parsing, extension-header walking
//! and construction of replies with correct checksums. [`v4`] has what an exit's IPv4 needs.

pub mod v4;

use std::net::Ipv6Addr;

/// Length of the IPv6 header.
pub const HEADER_LEN: usize = 40;
/// The IPv6 minimum MTU; replies never exceed it.
pub const MIN_MTU: usize = 1280;

/// Next-header value of TCP.
pub const TCP: u8 = 6;
/// Next-header value of UDP.
pub const UDP: u8 = 17;
/// Next-header value of ICMPv6.
pub const ICMPV6: u8 = 58;

/// The fixed IPv6 header fields the engine uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Next header of the fixed header.
    pub next: u8,
    /// Hop limit.
    pub hop_limit: u8,
    /// Source address.
    pub src: Ipv6Addr,
    /// Destination address.
    pub dst: Ipv6Addr,
    /// Payload length announced by the header.
    pub payload_len: usize,
}

/// Parses the fixed header; `None` unless the packet is IPv6 and at least as long as it claims.
pub fn parse(packet: &[u8]) -> Option<Header> {
    if packet.len() < HEADER_LEN || packet[0] >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if HEADER_LEN + payload_len > packet.len() {
        return None;
    }
    let addr = |at: usize| -> Option<Ipv6Addr> {
        let b: [u8; 16] = packet[at..at + 16].try_into().ok()?;
        Some(Ipv6Addr::from(b))
    };
    Some(Header {
        next: packet[6],
        hop_limit: packet[7],
        src: addr(8)?,
        dst: addr(24)?,
        payload_len,
    })
}

/// The upper-layer protocol and the offset of its header, skipping extension headers.
pub fn upper_layer(packet: &[u8], header: &Header) -> Option<(u8, usize)> {
    let end = HEADER_LEN + header.payload_len;
    let mut next = header.next;
    let mut at = HEADER_LEN;
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let b = packet.get(at..at + 2)?;
                let len = (usize::from(b[1]) + 1) * 8;
                next = b[0];
                at += len;
            }
            44 => {
                let b = packet.get(at..at + 8)?;
                next = b[0];
                at += 8;
            }
            _ => return (at <= end).then_some((next, at)),
        }
        if at > end {
            return None;
        }
    }
    None
}

fn sum(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        acc += u32::from(*last) << 8;
    }
    acc
}

/// The Internet checksum of the pseudo-header and `payload` (RFC 8200 §8.1).
pub fn checksum(src: &Ipv6Addr, dst: &Ipv6Addr, next: u8, payload: &[u8]) -> u16 {
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut acc = sum(&src.octets(), 0);
    acc = sum(&dst.octets(), acc);
    acc = sum(&len.to_be_bytes(), acc);
    acc += u32::from(next);
    acc = sum(payload, acc);
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// `packet` with its TCP or UDP checksum computed. The OS may leave it unset on traffic it
/// expected to loop back locally; other packets are returned unchanged.
pub fn with_checksum(packet: &[u8]) -> Vec<u8> {
    let mut p = packet.to_vec();
    let Some(h) = parse(packet) else {
        return p;
    };
    let (next, at, field) = match upper_layer(packet, &h) {
        Some((TCP, at)) => (TCP, at, at + 16),
        Some((UDP, at)) => (UDP, at, at + 6),
        _ => return p,
    };
    let end = HEADER_LEN + h.payload_len;
    if field + 2 > end {
        return p;
    }
    p[field..field + 2].fill(0);
    let mut c = checksum(&h.src, &h.dst, next, &p[at..end]);
    if c == 0 && next == UDP {
        c = 0xffff;
    }
    p[field..field + 2].copy_from_slice(&c.to_be_bytes());
    p
}

/// Builds an IPv6 packet around `payload` with hop limit `hop_limit`.
pub fn build(src: &Ipv6Addr, dst: &Ipv6Addr, next: u8, hop_limit: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(HEADER_LEN + payload.len());
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(
        &u16::try_from(payload.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    p.push(next);
    p.push(hop_limit);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

/// A parsed UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp<'a> {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// The payload.
    pub payload: &'a [u8],
}

/// Parses the UDP datagram of a packet whose upper layer is UDP, verifying its length and, if
/// `verify_checksum` is set, its checksum.
///
/// Operating systems that offload checksums hand the tunnel packets of local origin with a
/// partial checksum, so such packets are parsed without verification.
pub fn parse_udp<'a>(packet: &'a [u8], header: &Header, verify_checksum: bool) -> Option<Udp<'a>> {
    let (proto, at) = upper_layer(packet, header)?;
    if proto != UDP {
        return None;
    }
    let end = HEADER_LEN + header.payload_len;
    let dgram = packet.get(at..end)?;
    if dgram.len() < 8 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([dgram[4], dgram[5]]));
    if len < 8 || len > dgram.len() {
        return None;
    }
    let dgram = &dgram[..len];
    if verify_checksum && checksum(&header.src, &header.dst, UDP, dgram) != 0 {
        return None;
    }
    Some(Udp {
        src_port: u16::from_be_bytes([dgram[0], dgram[1]]),
        dst_port: u16::from_be_bytes([dgram[2], dgram[3]]),
        payload: &dgram[8..],
    })
}

/// Builds an IPv6 packet carrying a UDP datagram.
pub fn build_udp(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut d = Vec::with_capacity(len);
    d.extend_from_slice(&src_port.to_be_bytes());
    d.extend_from_slice(&dst_port.to_be_bytes());
    d.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(payload);
    let mut c = checksum(src, dst, UDP, &d);
    if c == 0 {
        c = 0xffff;
    }
    d[6..8].copy_from_slice(&c.to_be_bytes());
    build(src, dst, UDP, 64, &d)
}

/// Builds an IPv6 packet carrying an ICMPv6 message of `kind`, `code` and `body` (the four bytes
/// after the checksum onwards).
pub fn build_icmpv6(
    src: &Ipv6Addr,
    dst: &Ipv6Addr,
    kind: u8,
    code: u8,
    body: &[u8],
    hop_limit: u8,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + body.len());
    m.extend_from_slice(&[kind, code, 0, 0]);
    m.extend_from_slice(body);
    let c = checksum(src, dst, ICMPV6, &m);
    m[2..4].copy_from_slice(&c.to_be_bytes());
    build(src, dst, ICMPV6, hop_limit, &m)
}

/// ICMPv6 message types the router distinguishes.
pub mod icmp {
    /// Destination Unreachable (RFC 4443 §3.1).
    pub const DEST_UNREACHABLE: u8 = 1;
    /// Packet Too Big (RFC 4443 §3.2).
    pub const PACKET_TOO_BIG: u8 = 2;
    /// Time Exceeded (RFC 4443 §3.3).
    pub const TIME_EXCEEDED: u8 = 3;
    /// MLD query (RFC 2710).
    pub const MLD_QUERY: u8 = 130;
    /// MLD report (RFC 2710).
    pub const MLD_REPORT: u8 = 131;
    /// MLD done (RFC 2710).
    pub const MLD_DONE: u8 = 132;
    /// Router Solicitation.
    pub const ROUTER_SOLICITATION: u8 = 133;
    /// Router Advertisement.
    pub const ROUTER_ADVERTISEMENT: u8 = 134;
    /// Neighbor Solicitation.
    pub const NEIGHBOR_SOLICITATION: u8 = 135;
    /// Neighbor Advertisement.
    pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
    /// Redirect.
    pub const REDIRECT: u8 = 137;
    /// MLDv2 report (RFC 3810).
    pub const MLDV2_REPORT: u8 = 143;

    /// Whether `kind` is Neighbour Discovery (133–137) or MLD (130, 131, 143); vv-06 §3.3.
    ///
    /// MLD done (132) is included because it belongs with MLD and must never leave the host.
    pub const fn is_link_local_control(kind: u8) -> bool {
        matches!(kind, 130..=137 | 143)
    }
}

/// The ICMPv6 type of a packet, if its upper layer is ICMPv6.
pub fn icmpv6_type(packet: &[u8], header: &Header) -> Option<u8> {
    let (proto, at) = upper_layer(packet, header)?;
    (proto == ICMPV6).then(|| packet.get(at).copied()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn udp_round_trip_has_valid_checksum() {
        let p = build_udp(&a("fd00::1"), &a("fd00::2"), 4000, 53, b"query");
        let h = parse(&p).unwrap();
        let u = parse_udp(&p, &h, true).unwrap();
        assert_eq!(
            (u.src_port, u.dst_port, u.payload),
            (4000, 53, &b"query"[..])
        );
        let mut bad = p.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(parse_udp(&bad, &parse(&bad).unwrap(), true).is_none());
        assert!(parse_udp(&bad, &parse(&bad).unwrap(), false).is_some());
    }

    #[test]
    fn rejects_non_ipv6_and_truncated() {
        assert!(parse(&[0x45; 40]).is_none());
        let p = build(&a("::1"), &a("::2"), 59, 64, &[1, 2, 3, 4]);
        assert!(parse(&p[..p.len() - 1]).is_none());
        assert!(parse(&p).is_some());
    }

    #[test]
    fn walks_hop_by_hop_to_icmpv6() {
        let mut payload = vec![ICMPV6, 0, 5, 2, 0, 0, 1, 0];
        payload.extend_from_slice(&[icmp::MLDV2_REPORT, 0, 0, 0]);
        let p = build(&a("fe80::1"), &a("ff02::16"), 0, 1, &payload);
        let h = parse(&p).unwrap();
        assert_eq!(icmpv6_type(&p, &h), Some(143));
    }

    #[test]
    fn fills_in_a_missing_udp_checksum() {
        let good = build_udp(&a("fd00::1"), &a("fd00::1"), 1000, 53, b"query");
        let mut bare = good.clone();
        bare[HEADER_LEN + 6..HEADER_LEN + 8].fill(0x55);
        assert_eq!(with_checksum(&bare), good);
        let other = build(&a("::1"), &a("::2"), 59, 64, &[1, 2, 3]);
        assert_eq!(with_checksum(&other), other);
    }

    #[test]
    fn checksum_known_value() {
        let m = build_icmpv6(&a("fe80::1"), &a("fe80::2"), 128, 0, &[0, 1, 0, 1], 64);
        let h = parse(&m).unwrap();
        assert_eq!(checksum(&h.src, &h.dst, ICMPV6, &m[HEADER_LEN..]), 0);
    }
}
