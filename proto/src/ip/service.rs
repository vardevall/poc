//! Service discovery (vve-14): the services of a node, the `svc` and `svcack` control messages and
//! the per-peer store behind `providers`.
//!
//! [`ServiceBook`] is sans-IO. The caller reports sessions starting and ending and the control
//! messages it receives, with an explicit [`Instant`], polls [`ServiceAction`]s and seals each
//! message it returns in the peer's session, on the routes it uses for `cand` messages
//! (vv-05 §4.9).

use std::cmp::Reverse;
use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use thiserror::Error;

use crate::addr::is_valid_label;
use crate::json::{self, Value};
use crate::keys::NodePublic;
use crate::route::Active;
use crate::route::{Band, Control, Latency};
use crate::time::Instant;

/// Most services a node announces, and most entries of `svc` a receiver considers (vve-14 §2.1).
pub const MAX_SERVICES: usize = 16;
/// Most providers an answer lists (vve-14 §3).
pub const MAX_PROVIDERS: usize = 8;
/// How long a peer's services are kept after its session ends (vve-14 §2.3).
pub const SERVICE_HOLD: Duration = Duration::from_secs(600);

/// A service could not be announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ServiceError {
    /// The name is not a label (vv-06 §4.2).
    #[error("invalid service name")]
    InvalidName,
    /// The port is 0.
    #[error("invalid port")]
    InvalidPort,
    /// The node already announces 16 services.
    #[error("too many services")]
    TooMany,
}

/// The transport of a service (vve-14 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Proto {
    /// TCP, the default.
    Tcp,
    /// UDP.
    Udp,
}

impl Proto {
    /// The text form used in messages and SRV names.
    pub const fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// A service a node offers (vve-14 §2.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Service {
    name: String,
    port: u16,
    proto: Proto,
}

impl Service {
    /// A service; `name` is a label (vv-06 §4.2) and `port` is not 0.
    pub fn new(name: &str, port: u16, proto: Proto) -> Result<Self, ServiceError> {
        if !is_valid_label(name) {
            return Err(ServiceError::InvalidName);
        }
        if port == 0 {
            return Err(ServiceError::InvalidPort);
        }
        Ok(Service {
            name: name.to_owned(),
            port,
            proto,
        })
    }

    /// The service name, the label of `<name>.<domain>`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The port it listens on, on the node's `ula`.
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The transport.
    pub const fn proto(&self) -> Proto {
        self.proto
    }

    pub(crate) fn write_json(&self, out: &mut String) {
        out.push_str("{\"name\":");
        json::write_string(out, &self.name);
        out.push_str(",\"port\":");
        out.push_str(&self.port.to_string());
        if self.proto == Proto::Udp {
            out.push_str(",\"proto\":\"udp\"");
        }
        out.push('}');
    }

    fn from_json(entry: &Value) -> Option<Self> {
        let name = entry.get("name")?.as_str()?;
        let port = u16::try_from(entry.get("port")?.as_u64()?).ok()?;
        let proto = match entry.get("proto") {
            None => Proto::Tcp,
            Some(p) => match p.as_str()? {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                _ => return None,
            },
        };
        Service::new(name, port, proto).ok()
    }
}

/// Appends the `svc` array of a message (vve-14 §2.2), at most 16 entries.
pub(crate) fn write_list(out: &mut String, services: &[Service]) {
    out.push('[');
    for (i, s) in services.iter().take(MAX_SERVICES).enumerate() {
        if i > 0 {
            out.push(',');
        }
        s.write_json(out);
    }
    out.push(']');
}

/// The usable entries of a `svc` array, among the first 16 (vve-14 §2.2).
pub(crate) fn usable(list: &[Value]) -> Vec<Service> {
    list.iter()
        .take(MAX_SERVICES)
        .filter_map(Service::from_json)
        .collect()
}

/// A node that offers a service (vve-14 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    /// The node.
    pub key: NodePublic,
    /// The port it listens on.
    pub port: u16,
    /// The transport.
    pub proto: Proto,
    /// Whether the node has a session with us (or is this node), against known from before.
    pub live: bool,
}

/// What the caller does for the book.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceAction {
    /// Seal `control` in the current session with `peer` and send it.
    Send {
        /// The peer.
        peer: NodePublic,
        /// A `svc` or `svcack` message.
        control: Control,
    },
}

#[derive(Debug, Clone, Copy)]
struct Retry {
    next: Instant,
    tries: u32,
}

#[derive(Debug)]
struct Peer {
    live: bool,
    ended: Option<Instant>,
    accepted: Option<u64>,
    services: Vec<Service>,
    acked: Option<u64>,
    retry: Option<Retry>,
}

impl Peer {
    fn new(live: bool, now: Instant) -> Self {
        Peer {
            live,
            ended: (!live).then_some(now),
            accepted: None,
            services: Vec::new(),
            acked: None,
            retry: None,
        }
    }
}

/// The services of this node and what its peers announced (vve-14 §2).
pub struct ServiceBook {
    own_key: NodePublic,
    keepalive_timeout: Duration,
    own: Vec<Service>,
    seq: u64,
    peers: BTreeMap<NodePublic, Peer>,
    actions: VecDeque<ServiceAction>,
}

impl ServiceBook {
    /// A book for the node `own_key`; `keepalive_timeout` caps the retransmission interval
    /// (vve-14 §2.2).
    pub fn new(own_key: NodePublic, keepalive_timeout: Duration) -> Self {
        ServiceBook {
            own_key,
            keepalive_timeout,
            own: Vec::new(),
            seq: 0,
            peers: BTreeMap::new(),
            actions: VecDeque::new(),
        }
    }

    /// Takes the next action.
    pub fn poll_action(&mut self) -> Option<ServiceAction> {
        self.actions.pop_front()
    }

    /// The services this node announces.
    pub fn own(&self) -> &[Service] {
        &self.own
    }

    /// The `seq` of the node's current set.
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Announces a service, replacing one of the same name and transport; peers with a session
    /// are sent the new set. `rto` gives the retransmission timer of a peer.
    pub fn announce(
        &mut self,
        now: Instant,
        service: Service,
        rto: impl Fn(&NodePublic) -> Duration,
    ) -> Result<(), ServiceError> {
        match self
            .own
            .iter()
            .position(|s| s.name == service.name && s.proto == service.proto)
        {
            Some(i) if self.own[i] == service => return Ok(()),
            Some(i) => self.own[i] = service,
            None if self.own.len() >= MAX_SERVICES => return Err(ServiceError::TooMany),
            None => self.own.push(service),
        }
        self.changed(now, &rto);
        Ok(())
    }

    /// Withdraws every service of that name; returns whether there was one.
    pub fn withdraw(
        &mut self,
        now: Instant,
        name: &str,
        rto: impl Fn(&NodePublic) -> Duration,
    ) -> bool {
        let before = self.own.len();
        self.own.retain(|s| s.name != name);
        let any = self.own.len() != before;
        if any {
            self.changed(now, &rto);
        }
        any
    }

    /// A session with `peer` is established. The set is sent if the peer has not acknowledged its
    /// current `seq` and no send of it is pending, so a rekey or a second session coming up
    /// before the `svcack` sends nothing.
    pub fn session_up(
        &mut self,
        now: Instant,
        peer: &NodePublic,
        rto: impl Fn(&NodePublic) -> Duration,
    ) {
        let entry = self
            .peers
            .entry(*peer)
            .or_insert_with(|| Peer::new(true, now));
        entry.live = true;
        entry.ended = None;
        if entry.acked != Some(self.seq) && entry.retry.is_none() {
            self.send_set(now, peer, &rto);
        }
    }

    /// The last session with `peer` ended: its services are known until `SERVICE_HOLD` passes,
    /// and the next session announces ours again.
    pub fn session_down(&mut self, now: Instant, peer: &NodePublic) {
        if let Some(e) = self.peers.get_mut(peer) {
            e.live = false;
            e.ended = Some(now);
            e.retry = None;
            e.acked = None;
        }
    }

    /// Forgets everything about a peer that is no longer accepted (vve-14 §2.3).
    pub fn forget(&mut self, peer: &NodePublic) {
        self.peers.remove(peer);
    }

    /// Forgets the peers for which `accepted` is false.
    pub fn retain_accepted(&mut self, accepted: impl Fn(&NodePublic) -> bool) {
        self.peers.retain(|k, _| accepted(k));
    }

    /// An authenticated control message arrived from `peer`; other messages than `svc` and
    /// `svcack` are ignored.
    pub fn handle_control(
        &mut self,
        now: Instant,
        peer: &NodePublic,
        control: &Control,
        rto: impl Fn(&NodePublic) -> Duration,
    ) {
        match control {
            Control::Svc { seq, services } => {
                let e = self
                    .peers
                    .entry(*peer)
                    .or_insert_with(|| Peer::new(true, now));
                if e.accepted.is_none_or(|a| *seq > a) {
                    e.accepted = Some(*seq);
                    e.services = services.iter().take(MAX_SERVICES).cloned().collect();
                }
                let greatest = e.accepted.unwrap_or(*seq);
                self.actions.push_back(ServiceAction::Send {
                    peer: *peer,
                    control: Control::SvcAck { seq: greatest },
                });
            }
            Control::SvcAck { seq } => {
                if *seq > self.seq {
                    self.seq = *seq;
                    self.changed(now, &rto);
                    return;
                }
                if let Some(e) = self.peers.get_mut(peer) {
                    e.acked = e.acked.max(Some(*seq));
                    if e.acked == Some(self.seq) {
                        e.retry = None;
                    }
                }
            }
            _ => {}
        }
    }

    /// The earliest instant at which [`ServiceBook::handle_timeout`] has work.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.peers
            .values()
            .filter_map(|e| match (e.live, e.retry, e.ended) {
                (true, Some(r), _) => Some(r.next),
                (false, _, Some(t)) => Some(t + SERVICE_HOLD),
                _ => None,
            })
            .min()
    }

    /// Resends unacknowledged sets and forgets the services of peers whose hold has run out.
    pub fn handle_timeout(&mut self, now: Instant, rto: impl Fn(&NodePublic) -> Duration) {
        self.peers
            .retain(|_, e| e.live || e.ended.is_none_or(|t| now < t + SERVICE_HOLD));
        let due: Vec<NodePublic> = self
            .peers
            .iter()
            .filter(|(_, e)| e.live && e.retry.is_some_and(|r| r.next <= now))
            .map(|(k, _)| *k)
            .collect();
        for peer in due {
            let tries = self
                .peers
                .get(&peer)
                .and_then(|e| e.retry)
                .map_or(0, |r| r.tries);
            self.emit_set(&peer);
            let wait = rto(&peer)
                .saturating_mul(1u32 << (tries + 1).min(8))
                .min(self.keepalive_timeout);
            if let Some(e) = self.peers.get_mut(&peer) {
                e.retry = Some(Retry {
                    next: now + wait,
                    tries: tries.saturating_add(1),
                });
            }
        }
    }

    /// The services last announced by `peer`, and whether it is live.
    pub fn peer_services(&self, peer: &NodePublic) -> Option<(&[Service], bool)> {
        self.peers.get(peer).map(|e| (&e.services[..], e.live))
    }

    /// The providers of `name`, at most 8: this node first, then live peers ordered by their
    /// active route (`active` gives it; peers without one come last), then known peers, the most
    /// recently live first (vve-14 §3). A peer is listed once, with its first matching service.
    pub fn providers(
        &self,
        name: &str,
        active: impl Fn(&NodePublic) -> Option<Active>,
    ) -> Vec<Provider> {
        self.providers_where(name, None, active)
    }

    /// Like [`ServiceBook::providers`], for services of one transport (an SRV answer).
    pub fn providers_for(
        &self,
        name: &str,
        proto: Proto,
        active: impl Fn(&NodePublic) -> Option<Active>,
    ) -> Vec<Provider> {
        self.providers_where(name, Some(proto), active)
    }

    fn providers_where(
        &self,
        name: &str,
        proto: Option<Proto>,
        active: impl Fn(&NodePublic) -> Option<Active>,
    ) -> Vec<Provider> {
        let wanted = |list: &[Service]| {
            list.iter()
                .find(|s| s.name == name && proto.is_none_or(|p| s.proto == p))
                .cloned()
        };
        type Order = (
            u8,
            bool,
            Option<(Reverse<Band>, bool, Reverse<Latency>, bool)>,
            Reverse<Option<Instant>>,
            NodePublic,
        );
        let mut found: Vec<(Order, Provider)> = Vec::new();
        if let Some(s) = wanted(&self.own) {
            found.push((
                (0, false, None, Reverse(None), self.own_key),
                Provider {
                    key: self.own_key,
                    port: s.port,
                    proto: s.proto,
                    live: true,
                },
            ));
        }
        for (key, e) in &self.peers {
            let Some(s) = wanted(&e.services) else {
                continue;
            };
            let order = if e.live {
                let route = active(key).map(|a| {
                    let v4 = a.path.addr().is_none_or(|x| x.is_ipv4());
                    (
                        Reverse(a.class.band),
                        a.class.metered,
                        Reverse(a.class.latency),
                        v4,
                    )
                });
                (1, route.is_none(), route, Reverse(None), *key)
            } else {
                (2, false, None, Reverse(e.ended), *key)
            };
            found.push((
                order,
                Provider {
                    key: *key,
                    port: s.port,
                    proto: s.proto,
                    live: e.live,
                },
            ));
        }
        found.sort_by_key(|f| f.0);
        found
            .into_iter()
            .take(MAX_PROVIDERS)
            .map(|(_, p)| p)
            .collect()
    }

    fn changed(&mut self, now: Instant, rto: &dyn Fn(&NodePublic) -> Duration) {
        self.seq = self.seq.saturating_add(1);
        let live: Vec<NodePublic> = self
            .peers
            .iter()
            .filter(|(_, e)| e.live)
            .map(|(k, _)| *k)
            .collect();
        for peer in live {
            self.send_set(now, &peer, rto);
        }
    }

    fn send_set(&mut self, now: Instant, peer: &NodePublic, rto: &dyn Fn(&NodePublic) -> Duration) {
        self.emit_set(peer);
        if let Some(e) = self.peers.get_mut(peer) {
            e.retry = Some(Retry {
                next: now + rto(peer).min(self.keepalive_timeout),
                tries: 0,
            });
        }
    }

    fn emit_set(&mut self, peer: &NodePublic) {
        self.actions.push_back(ServiceAction::Send {
            peer: *peer,
            control: Control::Svc {
                seq: self.seq,
                services: self.own.clone(),
            },
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::RouteClass;
    use crate::transport::{Path, Remote, TransportId};

    fn key(n: u8) -> NodePublic {
        NodePublic::from_bytes([n; 32])
    }

    fn svc(name: &str, port: u16) -> Service {
        Service::new(name, port, Proto::Tcp).unwrap()
    }

    fn at(ms: u64) -> Instant {
        Instant::from_millis(ms)
    }

    fn rto(_: &NodePublic) -> Duration {
        Duration::from_millis(200)
    }

    fn actions(b: &mut ServiceBook) -> Vec<ServiceAction> {
        std::iter::from_fn(|| b.poll_action()).collect()
    }

    fn sent_seq(a: &ServiceAction) -> Option<u64> {
        match a {
            ServiceAction::Send {
                control: Control::Svc { seq, .. },
                ..
            } => Some(*seq),
            _ => None,
        }
    }

    #[test]
    fn names_ports_and_counts_are_checked() {
        assert_eq!(
            Service::new("Web", 80, Proto::Tcp),
            Err(ServiceError::InvalidName)
        );
        assert_eq!(
            Service::new(&"a".repeat(52), 80, Proto::Tcp),
            Err(ServiceError::InvalidName)
        );
        assert_eq!(
            Service::new("web", 0, Proto::Tcp),
            Err(ServiceError::InvalidPort)
        );
        let mut b = ServiceBook::new(key(1), Duration::from_secs(10));
        for i in 0..MAX_SERVICES {
            b.announce(at(0), svc(&format!("s{i}"), 1000 + i as u16), rto)
                .unwrap();
        }
        assert_eq!(
            b.announce(at(0), svc("extra", 1), rto),
            Err(ServiceError::TooMany)
        );
        b.announce(at(0), svc("s0", 5), rto).unwrap();
        assert_eq!(b.own().len(), MAX_SERVICES);
    }

    #[test]
    fn a_new_session_sends_the_set_and_an_ack_stops_the_retransmission() {
        let mut b = ServiceBook::new(key(1), Duration::from_secs(10));
        b.announce(at(0), svc("web", 443), rto).unwrap();
        b.session_up(at(0), &key(2), rto);
        assert_eq!(
            actions(&mut b).iter().map(sent_seq).collect::<Vec<_>>(),
            [Some(1)]
        );
        assert_eq!(b.poll_timeout(), Some(at(200)));
        b.handle_timeout(at(200), rto);
        assert_eq!(actions(&mut b).len(), 1);
        assert_eq!(b.poll_timeout(), Some(at(600)));
        b.handle_control(at(300), &key(2), &Control::SvcAck { seq: 1 }, rto);
        assert_eq!(b.poll_timeout(), None);
        b.session_up(at(400), &key(2), rto);
        assert!(actions(&mut b).is_empty(), "acknowledged already");
    }

    #[test]
    fn two_sessions_coming_up_before_the_svcack_send_one_svc() {
        let mut b = ServiceBook::new(key(1), Duration::from_secs(10));
        b.announce(at(0), svc("web", 443), rto).unwrap();
        b.session_up(at(0), &key(2), rto);
        b.session_up(at(10), &key(2), rto);
        assert_eq!(
            actions(&mut b).iter().map(sent_seq).collect::<Vec<_>>(),
            [Some(1)]
        );
        b.handle_control(at(20), &key(2), &Control::SvcAck { seq: 1 }, rto);
        b.session_up(at(30), &key(2), rto);
        assert!(actions(&mut b).is_empty());
    }

    #[test]
    fn a_session_after_the_link_went_down_sends_the_set_again() {
        let mut b = ServiceBook::new(key(1), Duration::from_secs(10));
        b.announce(at(0), svc("web", 443), rto).unwrap();
        b.session_up(at(0), &key(2), rto);
        b.handle_control(at(20), &key(2), &Control::SvcAck { seq: 1 }, rto);
        actions(&mut b);
        b.session_down(at(30), &key(2));
        b.session_up(at(40), &key(2), rto);
        assert_eq!(
            actions(&mut b).iter().map(sent_seq).collect::<Vec<_>>(),
            [Some(1)]
        );
    }

    #[test]
    fn retransmission_doubles_up_to_the_keepalive_timeout() {
        let mut b = ServiceBook::new(key(1), Duration::from_secs(10));
        b.session_up(at(0), &key(2), rto);
        let mut t = b.poll_timeout().unwrap();
        let mut gaps = Vec::new();
        for _ in 0..8 {
            let before = t;
            b.handle_timeout(t, rto);
            t = b.poll_timeout().unwrap();
            gaps.push((t - before).as_millis());
        }
        assert_eq!(gaps, [400, 800, 1600, 3200, 6400, 10000, 10000, 10000]);
    }

    #[test]
    fn a_change_is_sent_to_live_peers_only() {
        let mut b = ServiceBook::new(key(1), Duration::from_secs(10));
        b.session_up(at(0), &key(2), rto);
        b.session_up(at(0), &key(3), rto);
        actions(&mut b);
        b.session_down(at(5), &key(3));
        b.announce(at(10), svc("web", 80), rto).unwrap();
        let sent = actions(&mut b);
        assert_eq!(sent.len(), 1);
        assert!(matches!(&sent[0], ServiceAction::Send { peer, .. } if *peer == key(2)));
    }

    #[test]
    fn an_ack_above_our_seq_makes_the_sender_jump_past_it() {
        let mut b = ServiceBook::new(key(1), Duration::from_secs(10));
        b.announce(at(0), svc("web", 80), rto).unwrap();
        b.session_up(at(0), &key(2), rto);
        actions(&mut b);
        b.handle_control(at(10), &key(2), &Control::SvcAck { seq: 7 }, rto);
        assert_eq!(b.seq(), 8);
        assert_eq!(
            actions(&mut b).iter().map(sent_seq).collect::<Vec<_>>(),
            [Some(8)]
        );
        b.handle_control(at(20), &key(2), &Control::SvcAck { seq: 8 }, rto);
        assert_eq!(b.poll_timeout(), None);
    }

    #[test]
    fn a_receiver_accepts_only_a_greater_seq_and_acknowledges_the_greatest() {
        let mut b = ServiceBook::new(key(1), Duration::from_secs(10));
        let peer = key(2);
        let set = |seq, name: &str| Control::Svc {
            seq,
            services: vec![svc(name, 80)],
        };
        b.handle_control(at(0), &peer, &set(5, "a"), rto);
        b.handle_control(at(1), &peer, &set(3, "b"), rto);
        b.handle_control(at(2), &peer, &set(5, "c"), rto);
        let acks: Vec<u64> = actions(&mut b)
            .into_iter()
            .filter_map(|a| match a {
                ServiceAction::Send {
                    control: Control::SvcAck { seq },
                    ..
                } => Some(seq),
                _ => None,
            })
            .collect();
        assert_eq!(acks, [5, 5, 5]);
        assert_eq!(b.peer_services(&peer).unwrap().0[0].name(), "a");
        b.handle_control(at(3), &peer, &set(6, "d"), rto);
        assert_eq!(b.peer_services(&peer).unwrap().0[0].name(), "d");
    }

    #[test]
    fn services_are_known_for_the_hold_time_then_forgotten() {
        let mut b = ServiceBook::new(key(1), Duration::from_secs(10));
        let peer = key(2);
        b.session_up(at(0), &peer, rto);
        b.handle_control(
            at(1),
            &peer,
            &Control::Svc {
                seq: 1,
                services: vec![svc("web", 80)],
            },
            rto,
        );
        b.session_down(at(1000), &peer);
        assert!(!b.peer_services(&peer).unwrap().1);
        let end = at(1000) + SERVICE_HOLD;
        assert_eq!(b.poll_timeout(), Some(end));
        b.handle_timeout(at(1000 + SERVICE_HOLD.as_millis() as u64 - 1), rto);
        assert!(b.peer_services(&peer).is_some());
        b.handle_timeout(end, rto);
        assert!(b.peer_services(&peer).is_none());
        b.session_up(at(2_000_000), &peer, rto);
        b.forget(&peer);
        assert!(b.peer_services(&peer).is_none());
    }

    fn active(latency: Latency, metered: bool) -> Option<Active> {
        Some(Active {
            path: Path {
                via: TransportId(0),
                to: Remote::Addr("203.0.113.9:1".parse().unwrap()),
            },
            class: RouteClass {
                band: Band::High,
                latency,
                metered,
            },
            label: "static",
            verified: true,
            meter: Default::default(),
        })
    }

    #[test]
    fn providers_list_ourselves_then_live_by_route_then_known() {
        let mut b = ServiceBook::new(key(1), Duration::from_secs(10));
        b.announce(at(0), svc("web", 8080), rto).unwrap();
        for (n, port) in [(2u8, 1000u16), (3, 1001), (4, 1002), (5, 1003), (6, 1004)] {
            b.session_up(at(0), &key(n), rto);
            b.handle_control(
                at(0),
                &key(n),
                &Control::Svc {
                    seq: 1,
                    services: vec![svc("web", port)],
                },
                rto,
            );
        }
        b.session_down(at(10), &key(5));
        b.session_down(at(20), &key(6));
        let route = |k: &NodePublic| match k.as_bytes()[0] {
            2 => active(Latency::High, true),
            3 => active(Latency::Low, false),
            _ => None,
        };
        let got: Vec<(u8, bool)> = b
            .providers("web", route)
            .iter()
            .map(|p| (p.key.as_bytes()[0], p.live))
            .collect();
        assert_eq!(
            got,
            [
                (1, true),
                (3, true),
                (2, true),
                (4, true),
                (6, false),
                (5, false)
            ]
        );
        assert!(b.providers("dns", route).is_empty());
    }

    #[test]
    fn at_most_eight_providers() {
        let mut b = ServiceBook::new(key(1), Duration::from_secs(10));
        for n in 2..20u8 {
            b.session_up(at(0), &key(n), rto);
            b.handle_control(
                at(0),
                &key(n),
                &Control::Svc {
                    seq: 1,
                    services: vec![svc("web", 80)],
                },
                rto,
            );
        }
        assert_eq!(b.providers("web", |_| None).len(), MAX_PROVIDERS);
    }
}
