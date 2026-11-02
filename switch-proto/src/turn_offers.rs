//! The TURN credentials on offer and the choice of server among them (vv-05 §3.3).

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::net::SocketAddr;

use crate::origin::Origin;
use crate::turn::{Credentials, Server, TurnOffer};

/// The offers by origin, and which of the best offer's servers is tried.
#[derive(Debug, Default)]
pub struct TurnOffers {
    offers: BTreeMap<Origin, TurnOffer>,
    choice: usize,
}

impl TurnOffers {
    /// Stores the offer of `origin`, replacing an earlier one; returns whether it is the first
    /// from that origin.
    pub fn insert(&mut self, origin: Origin, offer: TurnOffer) -> bool {
        self.offers.insert(origin, offer).is_none()
    }

    /// Drops the offer of `origin`.
    pub fn remove(&mut self, origin: Origin) -> Option<TurnOffer> {
        self.offers.remove(&origin)
    }

    /// Whether there is any offer.
    pub fn is_empty(&self) -> bool {
        self.offers.is_empty()
    }

    /// The origin of the best offer: the highest priority (vv-07 §3.4), then the highest
    /// advertised rate, then the earliest origin. An offer that states no rate ranks after those
    /// that do (vv-05 §3.3 leaves this to local policy).
    pub fn best_origin(&self) -> Option<Origin> {
        self.offers
            .iter()
            .min_by_key(|(origin, o)| {
                (
                    Reverse(o.priority),
                    Reverse(o.bits_per_second.unwrap_or(0)),
                    **origin,
                )
            })
            .map(|(origin, _)| *origin)
    }

    /// The volume the best offer states, which is the offer an allocation is made from
    ///.
    pub fn bytes(&self) -> Option<u64> {
        self.best().and_then(|o| o.bytes)
    }

    fn best(&self) -> Option<&TurnOffer> {
        self.best_origin().and_then(|o| self.offers.get(&o))
    }

    fn usable(offer: &TurnOffer, reachable: &impl Fn(SocketAddr) -> bool) -> Vec<Server> {
        offer
            .servers
            .iter()
            .filter(|s| s.is_stream() || reachable(s.addr))
            .cloned()
            .collect()
    }

    /// The server to try and the credentials of the best offer. `reachable` says which
    /// addresses the interface socket can send to; a stream server needs no such address.
    pub fn select(&self, reachable: impl Fn(SocketAddr) -> bool) -> Option<(Server, Credentials)> {
        let offer = self.best()?;
        let usable = Self::usable(offer, &reachable);
        let server = usable.get(self.choice % usable.len().max(1))?.clone();
        Some((
            server,
            Credentials {
                username: offer.username.clone(),
                password: offer.password.clone(),
                realm: offer.realm.clone(),
                nonce: offer.nonce.clone(),
            },
        ))
    }

    /// The server just tried failed: take the next one. A UDP server that did not answer makes
    /// the rest of the UDP servers unlikely to, so the next try is the first TLS server, if any
    /// (UDP before TLS, vv-04 §2.3).
    pub fn next_server(&mut self, timed_out: bool, reachable: impl Fn(SocketAddr) -> bool) {
        let current = self
            .select(&reachable)
            .map(|(s, _)| s)
            .filter(|s| !s.is_stream());
        let first_stream = self.best().and_then(|o| {
            Self::usable(o, &reachable)
                .iter()
                .position(Server::is_stream)
        });
        self.choice = match (current, first_stream) {
            (Some(_), Some(i)) if timed_out && i > self.choice => i,
            _ => self.choice + 1,
        };
    }

    /// Starts the order of servers over, after a local change (vv-05 §4.6).
    pub fn reset(&mut self) {
        self.choice = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::address::SwitchAuth;
    use crate::origin::SwitchId;
    use crate::turn::TurnTransport;

    fn offer(server: &str, priority: i32, bits: Option<u64>) -> TurnOffer {
        TurnOffer {
            servers: vec![Server::udp(server.parse().unwrap())],
            username: format!("u-{server}"),
            password: "p".to_owned(),
            ttl: Duration::from_secs(60),
            bits_per_second: bits,
            bytes: None,
            realm: None,
            nonce: None,
            priority,
        }
    }

    fn any(_: SocketAddr) -> bool {
        true
    }

    fn chosen(offers: &TurnOffers) -> String {
        offers.select(any).unwrap().0.addr.to_string()
    }

    fn switch(i: u32) -> Origin {
        Origin::Switch(SwitchId(i))
    }

    #[test]
    fn offers_are_picked_by_priority_then_rate_then_order() {
        let mut o = TurnOffers::default();
        assert!(o.select(any).is_none());
        o.insert(switch(0), offer("192.0.2.1:3478", 0, None));
        o.insert(switch(1), offer("192.0.2.2:3478", 0, Some(1000)));
        assert_eq!(chosen(&o), "192.0.2.2:3478");
        o.insert(switch(2), offer("192.0.2.3:3478", 0, Some(1000)));
        assert_eq!(chosen(&o), "192.0.2.2:3478");
        o.insert(Origin::Config(0), offer("192.0.2.9:3478", 1, None));
        assert_eq!(chosen(&o), "192.0.2.9:3478");
        o.insert(Origin::Config(1), offer("192.0.2.8:3478", 0, None));
        assert_eq!(chosen(&o), "192.0.2.9:3478");
        assert_eq!(o.best_origin(), Some(Origin::Config(0)));
    }

    #[test]
    fn a_tie_goes_to_the_earliest_switch_then_the_earliest_configured_entry() {
        let mut o = TurnOffers::default();
        o.insert(Origin::Config(1), offer("192.0.2.4:3478", 0, None));
        o.insert(Origin::Config(0), offer("192.0.2.3:3478", 0, None));
        assert_eq!(o.best_origin(), Some(Origin::Config(0)));
        o.insert(switch(5), offer("192.0.2.2:3478", 0, None));
        assert_eq!(o.best_origin(), Some(switch(5)));
        o.insert(switch(3), offer("192.0.2.1:3478", 0, None));
        assert_eq!(o.best_origin(), Some(switch(3)));
        o.insert(Origin::Config(2), offer("192.0.2.5:3478", 0, Some(1)));
        assert_eq!(o.best_origin(), Some(Origin::Config(2)));
        o.remove(Origin::Config(2));
        assert_eq!(o.best_origin(), Some(switch(3)));
    }

    #[test]
    fn a_failed_server_rotates_to_the_next_address() {
        let mut o = TurnOffers::default();
        let mut first = offer("192.0.2.1:3478", 0, None);
        first
            .servers
            .push(Server::udp("192.0.2.2:3478".parse().unwrap()));
        assert!(o.insert(switch(0), first));
        assert_eq!(chosen(&o), "192.0.2.1:3478");
        o.next_server(false, any);
        assert_eq!(chosen(&o), "192.0.2.2:3478");
        o.reset();
        assert_eq!(chosen(&o), "192.0.2.1:3478");
    }

    #[test]
    fn a_timed_out_udp_server_makes_the_next_try_the_first_stream_server() {
        let mut o = TurnOffers::default();
        let mut offer = offer("192.0.2.1:3478", 0, None);
        offer
            .servers
            .push(Server::udp("192.0.2.2:3478".parse().unwrap()));
        offer.servers.push(Server {
            addr: "192.0.2.3:443".parse().unwrap(),
            transport: TurnTransport::Tls {
                host: "turn.example".to_owned(),
                auth: SwitchAuth::Web {
                    extra_roots: Vec::new(),
                },
            },
        });
        o.insert(switch(0), offer);
        o.next_server(true, any);
        assert_eq!(chosen(&o), "192.0.2.3:443");
    }

    #[test]
    fn servers_the_socket_cannot_reach_are_skipped() {
        let mut o = TurnOffers::default();
        let mut offer = offer("[2001:db8::1]:3478", 0, None);
        offer
            .servers
            .push(Server::udp("192.0.2.2:3478".parse().unwrap()));
        o.insert(switch(0), offer);
        let server = o.select(|a| a.is_ipv4()).unwrap().0;
        assert_eq!(server.addr.to_string(), "192.0.2.2:3478");
    }
}
