//! The built-in mDNS transport: multicast sockets on port 5353 (vv-09 §2, RFC 6762).
//!
//! The sockets share the port with the system's responder (`SO_REUSEADDR` and `SO_REUSEPORT`).
//! Probing and conflict resolution are not performed: instance names derive from per-window
//! tags and do not collide in practice.

mod cache;
pub(crate) mod links;
mod wire;

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::time::{Instant, Sleep, sleep};

use self::cache::Cache;
use self::links::{Link, enumerate};
use self::wire::{GROUP_V4, GROUP_V6, MDNS_PORT, TTL};
use super::{MdnsEvent, MdnsRequest, MdnsTransport, SERVICE_TYPE};
use crate::config::BuiltinMdns;
use crate::net::mark::SocketMark;

pub(crate) use self::wire::Registration;

const FIRST_QUERY_GAP: Duration = Duration::from_secs(1);
/// Longest gap between queries; shorter than 80 % of the record TTL so records are renewed.
const MAX_QUERY_GAP: Duration = Duration::from_secs(60);
const ANNOUNCE_REPEAT: Duration = Duration::from_secs(1);
const RESPONSE_INTERVAL: Duration = Duration::from_secs(1);
/// How long after a local change a cached address may go unanswered before it is dropped
/// (RFC 6762 §10.3). The change starts a query at once and another `FIRST_QUERY_GAP` later; a
/// responder answers at most once per `RESPONSE_INTERVAL`, so the answer to the first may be
/// withheld and the one to the retry arrives about `FIRST_QUERY_GAP + RESPONSE_INTERVAL` after
/// the change. A further `FIRST_QUERY_GAP + RESPONSE_INTERVAL` of margin for propagation and
/// scheduling makes four seconds.
const CONFIRM_WITHIN: Duration =
    Duration::from_secs(2 * (FIRST_QUERY_GAP.as_secs() + RESPONSE_INTERVAL.as_secs()));
const MAX_PENDING_EVENTS: usize = 256;

/// The built-in transport.
pub(crate) struct BuiltinTransport {
    config: BuiltinMdns,
    overlay_prefix: [u8; 8],
    v4: Option<Multicast>,
    v6: Option<Multicast>,
    links: Vec<Link>,
    registered: Option<Registration>,
    browsing: bool,
    cache: Cache,
    events: VecDeque<MdnsEvent>,
    announce_at: Option<Instant>,
    announcements_left: u8,
    next_query: Option<Instant>,
    query_gap: Duration,
    last_response: Option<Instant>,
    timer: Pin<Box<Sleep>>,
    buf: Vec<u8>,
}

/// A multicast socket: the tokio handle receives, a clone of the descriptor sends, because
/// tokio's `try_send_to` refuses until it has seen a writability event.
struct Multicast {
    rx: UdpSocket,
    tx: std::net::UdpSocket,
}

impl Multicast {
    fn new(s: Socket) -> io::Result<Self> {
        let std: std::net::UdpSocket = s.into();
        let tx = std.try_clone()?;
        Ok(Multicast {
            rx: UdpSocket::from_std(std)?,
            tx,
        })
    }
}

fn socket_v4(mark: SocketMark) -> io::Result<Multicast> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    mark.apply(&s)?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())?;
    s.set_multicast_loop_v4(true)?;
    s.set_multicast_ttl_v4(255)?;
    Multicast::new(s)
}

fn socket_v6(mark: SocketMark) -> io::Result<Multicast> {
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    mark.apply(&s)?;
    s.set_only_v6(true)?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, MDNS_PORT)).into())?;
    s.set_multicast_loop_v6(true)?;
    s.set_multicast_hops_v6(255)?;
    Multicast::new(s)
}

impl BuiltinTransport {
    /// Opens the multicast sockets and joins the groups on the eligible links.
    ///
    /// Must be called inside a tokio runtime context. `overlay_prefix` is the `/64` of the
    /// overlay network; links carrying it are never used.
    pub(crate) fn new(
        config: BuiltinMdns,
        overlay_prefix: [u8; 8],
        mark: SocketMark,
    ) -> io::Result<Self> {
        let v4 = socket_v4(mark);
        let v6 = socket_v6(mark);
        if let (Err(e), Err(_)) = (&v4, &v6) {
            return Err(io::Error::new(e.kind(), e.to_string()));
        }
        let mut t = BuiltinTransport {
            config,
            overlay_prefix,
            v4: v4.ok(),
            v6: v6.ok(),
            links: Vec::new(),
            registered: None,
            browsing: false,
            cache: Cache::new(),
            events: VecDeque::new(),
            announce_at: None,
            announcements_left: 0,
            next_query: None,
            query_gap: FIRST_QUERY_GAP,
            last_response: None,
            timer: Box::pin(sleep(Duration::from_secs(3600))),
            buf: vec![0u8; 4096],
        };
        t.refresh_links();
        Ok(t)
    }

    fn refresh_links(&mut self) {
        let links = enumerate(&self.config, &self.overlay_prefix);
        self.set_links(links);
    }

    /// Takes `links` as the links in use and joins the groups on them. Every cached address
    /// then has to be repeated within `CONFIRM_WITHIN`, or it is dropped like one whose records
    /// expired.
    fn set_links(&mut self, links: Vec<Link>) {
        self.links = links;
        for l in &self.links {
            if let Some(s) = &self.v4 {
                for a in &l.v4 {
                    let _ = s.rx.join_multicast_v4(GROUP_V4, *a);
                }
            }
            if let Some(s) = &self.v6 {
                let _ = s.rx.join_multicast_v6(&GROUP_V6, l.index);
            }
        }
        if self.browsing {
            self.cache.unconfirm(Instant::now() + CONFIRM_WITHIN);
        }
    }

    fn send_all(&self, per_link: impl Fn(&Link) -> Option<Vec<u8>>) {
        for l in &self.links {
            let Some(data) = per_link(l) else { continue };
            if let (Some(s), Some(a)) = (&self.v4, l.v4.first())
                && SockRef::from(&s.tx).set_multicast_if_v4(a).is_ok()
            {
                let _ = s.tx.send_to(&data, SocketAddr::from((GROUP_V4, MDNS_PORT)));
            }
            if let Some(s) = &self.v6
                && SockRef::from(&s.tx).set_multicast_if_v6(l.index).is_ok()
            {
                let _ = s.tx.send_to(&data, SocketAddr::from((GROUP_V6, MDNS_PORT)));
            }
        }
    }

    fn announce(&self, ttl: u32) {
        let Some(reg) = &self.registered else { return };
        self.send_all(|l| {
            let addrs: Vec<IpAddr> =
                l.v4.iter()
                    .map(|a| IpAddr::V4(*a))
                    .chain(l.announced_v6().map(|a| IpAddr::V6(*a)))
                    .collect();
            wire::build_announcement(reg, &addrs, ttl)
        });
    }

    fn query(&self) {
        let q = wire::build_query();
        self.send_all(|_| q.clone());
    }

    fn push_event(&mut self, e: MdnsEvent) {
        if self.events.len() < MAX_PENDING_EVENTS {
            self.events.push_back(e);
        }
    }

    fn on_datagram(&mut self, n: usize, now: Instant) {
        let Some(parsed) = wire::parse(&self.buf[..n]) else {
            return;
        };
        if parsed.asks_for_service
            && self.registered.is_some()
            && self
                .last_response
                .is_none_or(|t| now.duration_since(t) >= RESPONSE_INTERVAL)
        {
            self.last_response = Some(now);
            self.announce(TTL);
        }
        if self.browsing {
            let own = self.registered.as_ref().map(|r| r.instance.clone());
            for e in self.cache.ingest(&parsed, now, own.as_deref()) {
                self.push_event(e);
            }
        }
    }

    fn recv_from(&mut self, v6: bool, cx: &mut Context<'_>) -> Option<usize> {
        let sock = if v6 { &self.v6 } else { &self.v4 }.as_ref()?;
        let mut rb = ReadBuf::new(&mut self.buf);
        match sock.rx.poll_recv_from(cx, &mut rb) {
            Poll::Ready(Ok(_)) => Some(rb.filled().len()),
            _ => None,
        }
    }

    fn recv(&mut self, cx: &mut Context<'_>, now: Instant) {
        for v6 in [false, true] {
            for _ in 0..32 {
                match self.recv_from(v6, cx) {
                    Some(n) => self.on_datagram(n, now),
                    None => break,
                }
            }
        }
    }

    fn deadlines(&self) -> Option<Instant> {
        [
            self.announce_at,
            self.next_query,
            self.cache.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn run_timers(&mut self, now: Instant) {
        if self.announce_at.is_some_and(|t| t <= now) {
            self.announce(TTL);
            self.announcements_left = self.announcements_left.saturating_sub(1);
            self.announce_at = (self.announcements_left > 0).then(|| now + ANNOUNCE_REPEAT);
        }
        if self.next_query.is_some_and(|t| t <= now) {
            self.query();
            self.next_query = Some(now + self.query_gap);
            self.query_gap = (self.query_gap * 2).min(MAX_QUERY_GAP);
        }
        for e in self.cache.expire(now) {
            self.push_event(e);
        }
    }
}

impl MdnsTransport for BuiltinTransport {
    fn request(&mut self, request: MdnsRequest) {
        let now = Instant::now();
        match request {
            MdnsRequest::Register {
                instance,
                service_type,
                port,
                txt,
            } => {
                if service_type != SERVICE_TYPE {
                    return;
                }
                self.registered = Some(Registration {
                    instance,
                    port,
                    txt,
                });
                self.announce_at = Some(now);
                self.announcements_left = 2;
            }
            MdnsRequest::Unregister { instance } => {
                if self
                    .registered
                    .as_ref()
                    .is_some_and(|r| r.instance == instance)
                {
                    self.announce(0);
                    self.registered = None;
                    self.announce_at = None;
                }
            }
            MdnsRequest::Browse => {
                self.browsing = true;
                self.query_gap = FIRST_QUERY_GAP;
                self.next_query = Some(now);
            }
            MdnsRequest::StopBrowse => {
                self.browsing = false;
                self.next_query = None;
            }
        }
    }

    fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<MdnsEvent> {
        loop {
            if let Some(e) = self.events.pop_front() {
                return Poll::Ready(e);
            }
            let now = Instant::now();
            self.recv(cx, now);
            self.run_timers(now);
            if !self.events.is_empty() {
                continue;
            }
            let Some(at) = self.deadlines() else {
                return Poll::Pending;
            };
            self.timer.as_mut().reset(at);
            if self.timer.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }
    }

    fn path_changed(&mut self) {
        self.refresh_links();
        if self.registered.is_some() {
            self.announce_at = Some(Instant::now());
            self.announcements_left = 2;
        }
        if self.browsing {
            self.query_gap = FIRST_QUERY_GAP;
            self.next_query = Some(Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport() -> Option<BuiltinTransport> {
        let config = BuiltinMdns {
            interfaces: Some(Vec::new()),
            exclude: Vec::new(),
        };
        let mut t = BuiltinTransport::new(config, [0xfd; 8], SocketMark::NONE).ok()?;
        t.browsing = true;
        Some(t)
    }

    fn link(index: u32, ip: &str) -> Link {
        Link {
            name: format!("en{index}"),
            index,
            v4: vec![ip.parse().unwrap()],
            v6: vec![],
        }
    }

    fn hear(t: &mut BuiltinTransport, addr: &str, now: Instant) {
        let reg = Registration {
            instance: "peer".into(),
            port: 4242,
            txt: vec![("v".into(), "0".into())],
        };
        let packet = wire::build_announcement(&reg, &[addr.parse().unwrap()], 120).unwrap();
        t.buf[..packet.len()].copy_from_slice(&packet);
        t.on_datagram(packet.len(), now);
    }

    fn at(t0: Instant, ms: u64) -> Instant {
        t0 + Duration::from_millis(ms)
    }

    #[tokio::test(start_paused = true)]
    async fn a_record_that_answers_after_a_change_stays_silently() {
        let Some(mut t) = transport() else { return };
        let t0 = Instant::now();
        hear(&mut t, "10.0.0.9", t0);
        assert!(matches!(t.events.pop_front(), Some(MdnsEvent::Found(_))));
        t.set_links(vec![link(3, "10.0.0.2")]);
        hear(&mut t, "10.0.0.9", at(t0, 100));
        t.run_timers(at(t0, 10_000));
        assert!(t.events.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_record_that_does_not_answer_is_lost_at_the_deadline() {
        let Some(mut t) = transport() else { return };
        let t0 = Instant::now();
        hear(&mut t, "10.0.0.9", t0);
        t.events.clear();
        t.set_links(vec![link(3, "10.0.0.2")]);
        let due = CONFIRM_WITHIN.as_millis() as u64;
        t.run_timers(at(t0, due - 1));
        assert!(t.events.is_empty());
        assert_eq!(t.deadlines(), Some(at(t0, due)));
        t.run_timers(at(t0, due));
        assert_eq!(
            t.events.pop_front(),
            Some(MdnsEvent::Lost {
                instance: "peer".into()
            })
        );
        assert!(t.events.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_change_does_not_drop_a_record_that_answered_after_the_first() {
        let Some(mut t) = transport() else { return };
        let t0 = Instant::now();
        hear(&mut t, "10.0.0.9", t0);
        t.events.clear();
        let due = CONFIRM_WITHIN.as_millis() as u64;
        t.set_links(vec![link(3, "10.0.0.2")]);
        hear(&mut t, "10.0.0.9", at(t0, 500));
        tokio::time::advance(Duration::from_millis(due - 1_000)).await;
        t.set_links(vec![link(3, "10.0.0.2"), link(4, "192.168.5.2")]);
        t.run_timers(at(t0, due + 500));
        assert!(t.events.is_empty());
        hear(&mut t, "10.0.0.9", at(t0, due + 600));
        t.run_timers(at(t0, 3 * due));
        assert!(t.events.is_empty());
    }
}
