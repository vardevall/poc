//! Answering DNS queries found in the packet stream of the tunnel (vv-06 §4.4), for platforms
//! where the resolver cannot bind a socket on the overlay address.

use std::net::Ipv6Addr;

use vardevall_proto::addr::OverlayAddrs;

use crate::packet;

/// The DNS port.
const DNS_PORT: u16 = 53;

/// A DNS query addressed to the node's own overlay address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The client.
    pub client: Ipv6Addr,
    /// The address the client queried: the node's `ula` or `link_local`.
    pub server: Ipv6Addr,
    /// The client's port.
    pub client_port: u16,
    /// The DNS message.
    pub message: Vec<u8>,
}

/// Extracts a query to UDP port 53 of the node's own overlay addresses.
pub fn intercept(packet: &[u8], own: &OverlayAddrs) -> Option<Query> {
    query_to(packet, |dst| own.contains(dst))
}

/// Extracts a query to UDP port 53 of `addr`, an address of the overlay that is not the node's own
///: a host that delivers packets for its own addresses locally sends its queries
/// there instead.
pub fn intercept_at(packet: &[u8], addr: &Ipv6Addr) -> Option<Query> {
    query_to(packet, |dst| dst == addr)
}

fn query_to(packet: &[u8], wanted: impl Fn(&Ipv6Addr) -> bool) -> Option<Query> {
    let h = packet::parse(packet)?;
    if !wanted(&h.dst) || h.next != packet::UDP {
        return None;
    }
    let u = packet::parse_udp(packet, &h, false)?;
    (u.dst_port == DNS_PORT).then(|| Query {
        client: h.src,
        server: h.dst,
        client_port: u.src_port,
        message: u.payload.to_vec(),
    })
}

/// The IPv6 packet carrying `message` back to the client of `query`.
pub fn reply_packet(query: &Query, message: &[u8]) -> Vec<u8> {
    packet::build_udp(
        &query.server,
        &query.client,
        DNS_PORT,
        query.client_port,
        message,
    )
}
