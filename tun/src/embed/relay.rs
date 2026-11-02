//! Relaying the host's queries to the exit's resolver through the engine's own packet path
//!.
//!
//! An OS socket of the tunnel's own process may not enter the tunnel (Apple), so the query is a
//! UDP packet built here, from a port of [`PORTS`], that the router sends to the exit like any
//! packet read from the host. The reply is recognised among the packets delivered to the host.

use std::net::Ipv6Addr;
use std::ops::Range;
use std::time::Instant;

use crate::dns::{self, ATTEMPT_TIMEOUT, MAX_IN_FLIGHT, Query};
use crate::packet;

/// Source ports of the engine's own queries, one for each query in flight. They are below the
/// ephemeral ranges of Linux (from 32768) and Apple (from 49152), so that a host application
/// querying the exit's resolver itself does not use them.
pub(super) const PORTS: Range<u16> = 5300..5300 + MAX_IN_FLIGHT as u16;

const DNS_PORT: u16 = 53;

struct Pending {
    id: u16,
    via: Ipv6Addr,
    client: Query,
    deadline: Instant,
}

/// The relays waiting for a reply, at most one for each port of [`PORTS`].
pub(super) struct Relays {
    slots: [Option<Pending>; MAX_IN_FLIGHT],
}

impl Relays {
    pub(super) fn new() -> Self {
        Relays {
            slots: std::array::from_fn(|_| None),
        }
    }

    fn expire(&mut self, now: Instant) {
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|p| p.deadline <= now) {
                *slot = None;
            }
        }
    }

    /// Takes a port for relaying `query`, the host's `client` message, to `via`; `None` if all
    /// are in use or the message has no header.
    pub(super) fn start(
        &mut self,
        now: Instant,
        via: Ipv6Addr,
        client: &Query,
        query: &[u8],
    ) -> Option<u16> {
        self.expire(now);
        let id = u16::from_be_bytes([*query.first()?, *query.get(1)?]);
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.is_none())?;
        *slot = Some(Pending {
            id,
            via,
            client: client.clone(),
            deadline: now + ATTEMPT_TIMEOUT,
        });
        Some(PORTS.start + index as u16)
    }

    /// Frees `port` when its query could not be sent.
    pub(super) fn cancel(&mut self, port: u16) {
        if let Some(slot) = port
            .checked_sub(PORTS.start)
            .and_then(|i| self.slots.get_mut(usize::from(i)))
        {
            *slot = None;
        }
    }

    /// If `packet`, delivered for this node's `own` address, is the reply to a pending relay,
    /// completes it and returns the packet that answers the host's query.
    pub(super) fn finish(
        &mut self,
        now: Instant,
        own: &Ipv6Addr,
        packet: &[u8],
    ) -> Option<Vec<u8>> {
        self.expire(now);
        let h = packet::parse(packet)?;
        if h.next != packet::UDP || h.dst != *own {
            return None;
        }
        let u = packet::parse_udp(packet, &h, false)?;
        if u.src_port != DNS_PORT || !PORTS.contains(&u.dst_port) || u.payload.len() < 12 {
            return None;
        }
        let slot = &mut self.slots[usize::from(u.dst_port - PORTS.start)];
        let p = slot.as_ref()?;
        if p.via != h.src
            || p.id != u16::from_be_bytes([u.payload[0], u.payload[1]])
            || u.payload[2] & 0x80 == 0
        {
            return None;
        }
        let reply = dns::reply_packet(&p.client, u.payload);
        *slot = None;
        Some(reply)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const OWN: &str = "fd00::1";
    const EXIT: &str = "fd00::2";

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn message(id: u16, response: bool) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend_from_slice(&[if response { 0x80 } else { 0 }, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        m
    }

    fn client(port: u16) -> Query {
        Query {
            client: addr("fd00::99"),
            server: addr(OWN),
            client_port: port,
            message: message(7, false),
        }
    }

    fn reply(port: u16, id: u16) -> Vec<u8> {
        packet::build_udp(&addr(EXIT), &addr(OWN), DNS_PORT, port, &message(id, true))
    }

    #[test]
    fn a_reply_completes_the_relay_it_answers() {
        let now = Instant::now();
        let mut r = Relays::new();
        let q = client(4000);
        let port = r.start(now, addr(EXIT), &q, &message(7, false)).unwrap();
        assert!(PORTS.contains(&port));
        let done = r.finish(now, &addr(OWN), &reply(port, 7)).unwrap();
        let h = packet::parse(&done).unwrap();
        let u = packet::parse_udp(&done, &h, true).unwrap();
        assert_eq!((h.src, h.dst), (addr(OWN), addr("fd00::99")));
        assert_eq!((u.src_port, u.dst_port), (DNS_PORT, 4000));
        assert_eq!(u.payload, message(7, true));
        assert!(r.finish(now, &addr(OWN), &reply(port, 7)).is_none());
    }

    #[test]
    fn a_reply_that_matches_nothing_is_not_taken() {
        let now = Instant::now();
        let mut r = Relays::new();
        let port = r
            .start(now, addr(EXIT), &client(4000), &message(7, false))
            .unwrap();
        let other_port = reply(port + 1, 7);
        let other_id = reply(port, 8);
        let other_source = packet::build_udp(
            &addr("fd00::3"),
            &addr(OWN),
            DNS_PORT,
            port,
            &message(7, true),
        );
        let not_from_53 = packet::build_udp(&addr(EXIT), &addr(OWN), 5353, port, &message(7, true));
        let a_query =
            packet::build_udp(&addr(EXIT), &addr(OWN), DNS_PORT, port, &message(7, false));
        for p in [other_port, other_id, other_source, not_from_53, a_query] {
            assert!(r.finish(now, &addr(OWN), &p).is_none());
        }
        assert!(r.finish(now, &addr(OWN), &reply(port, 7)).is_some());
    }

    #[test]
    fn at_most_the_limit_are_pending_and_a_timeout_frees_a_slot() {
        let now = Instant::now();
        let mut r = Relays::new();
        let q = client(4000);
        let ports: Vec<u16> = (0..MAX_IN_FLIGHT)
            .map(|i| {
                r.start(
                    now + Duration::from_millis(i as u64),
                    addr(EXIT),
                    &q,
                    &message(i as u16, false),
                )
                .unwrap()
            })
            .collect();
        let mut sorted = ports.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), MAX_IN_FLIGHT);
        let late = now + Duration::from_millis(20);
        assert!(r.start(late, addr(EXIT), &q, &message(99, false)).is_none());
        let later = now + ATTEMPT_TIMEOUT;
        assert_eq!(
            r.start(later, addr(EXIT), &q, &message(99, false)),
            Some(ports[0]),
            "only the first has timed out"
        );
        assert!(r.finish(later, &addr(OWN), &reply(ports[0], 0)).is_none());
    }

    #[test]
    fn a_cancelled_port_is_free_again() {
        let now = Instant::now();
        let mut r = Relays::new();
        let q = client(4000);
        let port = r.start(now, addr(EXIT), &q, &message(1, false)).unwrap();
        r.cancel(port);
        assert_eq!(r.start(now, addr(EXIT), &q, &message(2, false)), Some(port));
        assert!(r.start(now, addr(EXIT), &q, &[1]).is_none());
    }
}
