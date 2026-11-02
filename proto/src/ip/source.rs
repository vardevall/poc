//! The source check of the IP packets a peer sends.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::addr::OverlayAddrs;
use crate::ip::exit::{ExitOffer, Serving};
use crate::ip::site::site_addr;
use crate::keys::{NetworkId, NodePublic};
use crate::plane::frame;

/// What the check of one peer's packets needs to know.
pub(crate) struct Source<'a> {
    pub(crate) network_id: &'a NetworkId,
    /// This node's key.
    pub(crate) own: &'a NodePublic,
    pub(crate) peer: &'a NodePublic,
    pub(crate) peer_addrs: &'a OverlayAddrs,
    /// Whether the peer is held by key: only such a peer serves or uses an exit.
    pub(crate) held_by_key: bool,
    /// The exit this node serves, with the addresses it gave.
    pub(crate) serving: Option<Serving<'a>>,
    /// The exit the peer offers.
    pub(crate) offer: Option<&'a ExitOffer>,
}

impl Source<'_> {
    /// The IP packet in `plaintext`, stripped of its padding, if the peer may send it
    ///: its source is one of the peer's overlay addresses, or the site traffic of
    /// [`Source::site_traffic`] or [`Source::ipv4_traffic`].
    pub(crate) fn accept<'p>(&self, plaintext: &'p [u8]) -> Option<&'p [u8]> {
        let packet = frame::unpad(plaintext).ok()?;
        let allowed = match ipv6_source(packet) {
            Some(src) => self.peer_addrs.contains(&src) || self.site_traffic(packet, &src),
            None => self.ipv4_traffic(packet),
        };
        allowed.then_some(packet)
    }

    /// Whether an IPv6 packet whose source is not the peer's overlay address may still come from
    /// it: a peer held by key sends from its address in the site this node serves, and the exit
    /// it offers sends anything to this node's address in that site.
    fn site_traffic(&self, packet: &[u8], src: &Ipv6Addr) -> bool {
        if !self.held_by_key {
            return false;
        }
        let serves = self
            .serving
            .is_some_and(|o| *src == site_addr(self.network_id, &o.serve.site, self.peer));
        serves
            || self.offer.is_some_and(|o| {
                ipv6_destination(packet) == Some(site_addr(self.network_id, &o.site, self.own))
            })
    }

    /// Whether an IPv4 packet may come from this peer: from the address this node's exit gave it,
    /// or, from the exit it offers, to the address that offer gives this node.
    fn ipv4_traffic(&self, packet: &[u8]) -> bool {
        if !self.held_by_key {
            return false;
        }
        let Some((src, dst)) = ipv4_addrs(packet) else {
            return false;
        };
        let from_client = self
            .serving
            .and_then(|o| o.ipv4_of(self.peer))
            .is_some_and(|a| a == src);
        from_client || self.offer.and_then(|o| o.ipv4).is_some_and(|a| a == dst)
    }
}

/// The source address of an IPv6 packet that passed [`frame::unpad`]; `None` for IPv4.
pub fn ipv6_source(packet: &[u8]) -> Option<Ipv6Addr> {
    if packet.first()? >> 4 != 6 {
        return None;
    }
    let src: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
    Some(Ipv6Addr::from(src))
}

/// The destination address of an IPv6 packet that passed [`frame::unpad`]; `None` for IPv4.
pub fn ipv6_destination(packet: &[u8]) -> Option<Ipv6Addr> {
    if packet.first()? >> 4 != 6 {
        return None;
    }
    let dst: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
    Some(Ipv6Addr::from(dst))
}

/// The source and destination of an IPv4 packet that passed [`frame::unpad`]; `None` for IPv6.
pub fn ipv4_addrs(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.first()? >> 4 != 4 {
        return None;
    }
    let src: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
    let dst: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
    Some((Ipv4Addr::from(src), Ipv4Addr::from(dst)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_addresses_of_an_ipv4_packet_are_read_and_it_has_no_ipv6_source() {
        let mut p = [0u8; 48];
        p[0] = 0x45;
        p[3] = 28;
        p[12..16].copy_from_slice(&[198, 18, 0, 7]);
        p[16..20].copy_from_slice(&[1, 1, 1, 1]);
        let packet = frame::unpad(&p).unwrap();
        assert_eq!(ipv6_source(packet), None);
        assert_eq!(
            ipv4_addrs(packet),
            Some((Ipv4Addr::new(198, 18, 0, 7), Ipv4Addr::new(1, 1, 1, 1)))
        );
    }
}
