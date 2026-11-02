//! `Udp`: the node's interface socket, its send health and its rebinding.
//!
//! One wildcard socket on the listen port carries handshakes, data, STUN and the datagrams of a
//! TURN server (vv-03 §2). A socket can outlive the network it was bound under (a Wi-Fi reconnect
//! on macOS leaves it receiving but unable to send), so it is rebound on every settled local
//! change and after [`FAILURES_BEFORE_REBIND`] consecutive send failures (vv-05 §4.6).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use vardevall_proto::handshake::message::MAX_FRAGMENT;
use vardevall_proto::plane::frame::{self, Class};
use vardevall_proto::route::{Band, Latency, RouteClass};
use vardevall_proto::time::Instant;
use vardevall_proto::transport::{Framing, Medium, Reachability, Remote};

use crate::event::LogLevel;
use crate::net::mark::SocketMark;
use crate::net::socket::{self, canonical, for_socket};
use vardevall_switch_proto::stun::Message;

/// Consecutive failed sends after which the socket is rebound.
const FAILURES_BEFORE_REBIND: u32 = 8;
/// Minimum time between two failure-triggered rebinds.
const REBIND_INTERVAL: Duration = Duration::from_secs(5);
/// Minimum time between two log lines for the same kind of error.
const LOG_INTERVAL: Duration = Duration::from_secs(10);

/// The addresses the socket can send to: IPv6 ones only if it is a dual-stack socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reach {
    dual_stack: bool,
}

impl Reach {
    #[cfg(test)]
    pub(crate) fn new(dual_stack: bool) -> Reach {
        Reach { dual_stack }
    }

    /// Whether the socket can send to `addr`.
    pub(crate) fn contains(self, addr: SocketAddr) -> bool {
        for_socket(addr, self.dual_stack).is_some()
    }
}

/// What a datagram from the socket is for.
#[derive(Debug)]
pub(crate) enum Datagram {
    /// A handshake fragment, cookie reply or data frame, for `proto`.
    Frame,
    /// A message of the TURN server the allocation talks to.
    TurnServer,
    /// A STUN message, parsed.
    Stun(Message),
    /// Anything else.
    Ignored,
}

/// The interface socket as `proto` sees it: probed, fragmented handshakes, reaches the families
/// the socket can send to.
pub(crate) struct UdpMedium {
    dual_stack: Arc<AtomicBool>,
}

impl Medium for UdpMedium {
    fn name(&self) -> &str {
        "udp"
    }

    fn class(&self) -> RouteClass {
        RouteClass {
            band: Band::High,
            latency: Latency::High,
            metered: false,
        }
    }

    fn reaches(&self, to: &Remote, _: bool) -> bool {
        matches!(to, Remote::Addr(a) if for_socket(*a, self.dual_stack.load(Ordering::Relaxed)).is_some())
    }

    fn reachability(&self) -> Reachability {
        Reachability::Probe
    }

    fn framing(&self) -> Framing {
        Framing::Fragmented { max: MAX_FRAGMENT }
    }

    fn on_demand(&self) -> bool {
        false
    }
}

/// Distinguishes errors for rate limiting: the raw OS error if there is one, else the kind.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum ErrorKey {
    Os(i32),
    Kind(io::ErrorKind),
}

impl ErrorKey {
    fn of(e: &io::Error) -> Self {
        e.raw_os_error()
            .map_or(ErrorKey::Kind(e.kind()), ErrorKey::Os)
    }
}

/// Failed sends: which errors were logged recently and how many failures happened in a row.
#[derive(Default)]
struct SendHealth {
    logged: HashMap<ErrorKey, Instant>,
    consecutive: u32,
    last_rebind: Option<Instant>,
}

impl SendHealth {
    fn ok(&mut self) {
        self.consecutive = 0;
    }

    /// Records a failure; returns whether it should be logged now.
    fn failed(&mut self, e: &io::Error, now: Instant) -> bool {
        self.consecutive = self.consecutive.saturating_add(1);
        let key = ErrorKey::of(e);
        let due = self
            .logged
            .get(&key)
            .is_none_or(|t| now.saturating_duration_since(*t) >= LOG_INTERVAL);
        if due {
            self.logged.insert(key, now);
        }
        due
    }

    /// Whether the failure streak warrants a rebind now.
    fn rebind_due(&self, now: Instant) -> bool {
        self.consecutive >= FAILURES_BEFORE_REBIND
            && self
                .last_rebind
                .is_none_or(|t| now.saturating_duration_since(t) >= REBIND_INTERVAL)
    }

    fn rebound(&mut self, now: Instant) {
        self.consecutive = 0;
        self.last_rebind = Some(now);
    }
}

/// How a rebind ended.
enum Rebound {
    /// A fresh socket on the same port; `family` says the address family differs from before.
    Same { family: bool },
    /// The port could not be bound again; the socket got an ephemeral port.
    Moved(io::Error),
    /// Neither worked; the old socket stays.
    Failed(io::Error),
}

/// The socket of a node.
pub(crate) struct Udp {
    socket: UdpSocket,
    sender: std::net::UdpSocket,
    dual_stack: Arc<AtomicBool>,
    port: u16,
    mark: SocketMark,
    health: SendHealth,
    log: Vec<(LogLevel, String)>,
}

impl Udp {
    /// The wildcard socket on `port`, dual-stack when the system allows it.
    pub(crate) fn bind(port: u16, mark: SocketMark) -> io::Result<Udp> {
        let bound = socket::bind(port, mark)?;
        let sender = bound.socket.try_clone()?;
        let socket = UdpSocket::from_std(bound.socket)?;
        let port = socket.local_addr()?.port();
        Ok(Udp {
            socket,
            sender,
            dual_stack: Arc::new(AtomicBool::new(bound.dual_stack)),
            port,
            mark,
            health: SendHealth::default(),
            log: Vec::new(),
        })
    }

    /// The medium to register with `proto`; it follows the socket through rebinds.
    pub(crate) fn medium(&self) -> UdpMedium {
        UdpMedium {
            dual_stack: self.dual_stack.clone(),
        }
    }

    /// The addresses the socket can send to now.
    pub(crate) fn reach(&self) -> Reach {
        Reach {
            dual_stack: self.dual_stack.load(Ordering::Relaxed),
        }
    }

    /// The local address of the socket.
    pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.local_addr().ok()
    }

    /// Polls for a datagram; `Some((length, source))` is a datagram, `None` a receive error to
    /// ignore. The source is in its canonical form.
    pub(crate) fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Option<(usize, SocketAddr)>> {
        let mut rb = ReadBuf::new(buf);
        match self.socket.poll_recv_from(cx, &mut rb) {
            Poll::Ready(Ok(from)) => Poll::Ready(Some((rb.filled().len(), canonical(from)))),
            Poll::Ready(Err(_)) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Takes a datagram that is already waiting.
    pub(crate) fn try_recv(&mut self, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
        let (n, from) = self.socket.try_recv_from(buf).ok()?;
        Some((n, canonical(from)))
    }

    /// Sorts a datagram that came from `from`; `turn` is the address of the TURN server the
    /// allocation talks to over this socket, if any.
    pub(crate) fn sort(data: &[u8], from: SocketAddr, turn: Option<SocketAddr>) -> Datagram {
        if turn == Some(from) {
            return Datagram::TurnServer;
        }
        let Some(&first) = data.first() else {
            return Datagram::Ignored;
        };
        match frame::classify(first, false) {
            Class::HandshakeFragment | Class::CookieReply | Class::DataFrame => Datagram::Frame,
            Class::StunTurn => Message::parse(data).map_or(Datagram::Ignored, Datagram::Stun),
            _ => Datagram::Ignored,
        }
    }

    /// Sends `data` to `to`; an address the socket cannot reach is not an error. Returns whether
    /// the send counts for the freshness of the STUN result: `false` after an error,
    /// which is logged unless it repeats and may rebind the socket.
    pub(crate) fn send(&mut self, now: Instant, to: SocketAddr, data: &[u8]) -> bool {
        let Some(dst) = for_socket(to, self.reach().dual_stack) else {
            return true;
        };
        match self.sender.send_to(data, dst) {
            Ok(_) => {
                self.health.ok();
                true
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => true,
            Err(e) => {
                self.send_failed(now, to, &e);
                false
            }
        }
    }

    fn send_failed(&mut self, now: Instant, dst: SocketAddr, e: &io::Error) {
        let log = self.health.failed(e, now);
        let n = self.health.consecutive;
        if log {
            let errno = e
                .raw_os_error()
                .map_or(String::new(), |n| format!(" (errno {n})"));
            self.log.push((
                LogLevel::Warn,
                format!("send to {dst} failed: {e}{errno}; {n} consecutive failure(s)"),
            ));
        }
        if self.health.rebind_due(now) {
            self.rebind(now);
        }
    }

    /// Replaces the socket with a fresh one on the same port.
    ///
    /// The old socket is closed first, since the port cannot be bound twice; if the bind then
    /// fails, an ephemeral socket keeps the node running.
    pub(crate) fn rebind(&mut self, now: Instant) {
        let port = self.port;
        self.health.rebound(now);
        match self.replace() {
            Rebound::Same { family } => {
                if family {
                    self.log.push((
                        LogLevel::Warn,
                        "socket changed address family on rebind".to_owned(),
                    ));
                }
                self.log
                    .push((LogLevel::Info, format!("socket rebound on port {port}")));
            }
            Rebound::Moved(e) | Rebound::Failed(e) => self.log.push((
                LogLevel::Warn,
                format!("socket rebind on port {port} failed: {e}"),
            )),
        }
    }

    fn replace(&mut self) -> Rebound {
        let Ok(placeholder) = Udp::bind(0, self.mark) else {
            return Rebound::Failed(io::Error::other("no placeholder socket"));
        };
        let (dual, port) = (self.reach().dual_stack, self.port);
        self.install(placeholder);
        let (fresh, moved) = match Udp::bind(port, self.mark) {
            Ok(fresh) => (fresh, None),
            Err(e) => match Udp::bind(0, self.mark) {
                Ok(fresh) => (fresh, Some(e)),
                Err(_) => return Rebound::Failed(e),
            },
        };
        self.install(fresh);
        match moved {
            None => Rebound::Same {
                family: self.reach().dual_stack != dual,
            },
            Some(e) => Rebound::Moved(e),
        }
    }

    fn install(&mut self, fresh: Udp) {
        self.socket = fresh.socket;
        self.sender = fresh.sender;
        self.port = fresh.port;
        self.dual_stack
            .store(fresh.dual_stack.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    /// The log lines since the last call.
    pub(crate) fn take_log(&mut self) -> Vec<(LogLevel, String)> {
        std::mem::take(&mut self.log)
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;

    use super::*;

    fn err(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    fn at(secs: u64) -> Instant {
        Instant::from_duration(Duration::from_secs(secs))
    }

    #[test]
    fn logs_once_per_error_per_interval() {
        let mut h = SendHealth::default();
        let t0 = at(100);
        assert!(h.failed(&err(65), t0));
        assert!(!h.failed(&err(65), t0 + Duration::from_secs(1)));
        assert!(h.failed(&err(51), t0 + Duration::from_secs(1)));
        assert!(h.failed(&err(65), t0 + LOG_INTERVAL));
        assert_eq!(h.consecutive, 4);
    }

    #[test]
    fn success_resets_the_streak() {
        let mut h = SendHealth::default();
        let t0 = at(100);
        for _ in 0..FAILURES_BEFORE_REBIND - 1 {
            h.failed(&err(65), t0);
        }
        assert!(!h.rebind_due(t0));
        h.ok();
        h.failed(&err(65), t0);
        assert!(!h.rebind_due(t0));
    }

    #[test]
    fn rebinds_are_spaced() {
        let mut h = SendHealth::default();
        let t0 = at(100);
        for _ in 0..FAILURES_BEFORE_REBIND {
            h.failed(&err(65), t0);
        }
        assert!(h.rebind_due(t0));
        h.rebound(t0);
        for _ in 0..FAILURES_BEFORE_REBIND {
            h.failed(&err(65), t0);
        }
        assert!(!h.rebind_due(t0 + Duration::from_secs(1)));
        assert!(h.rebind_due(t0 + REBIND_INTERVAL));
    }

    async fn receive(s: &mut Udp) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0u8; 64];
        let got = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some((n, from)) = poll_fn(|cx| s.poll_recv(cx, &mut buf)).await {
                    return (buf[..n].to_vec(), from);
                }
            }
        })
        .await;
        got.expect("no datagram")
    }

    #[tokio::test]
    async fn the_socket_is_bound_again_on_the_same_port() {
        let mut s = Udp::bind(0, SocketMark::NONE).unwrap();
        let port = s.local_addr().unwrap().port();
        s.rebind(at(1));
        assert_eq!(s.local_addr().unwrap().port(), port);
        assert!(
            s.take_log()
                .iter()
                .any(|(l, m)| *l == LogLevel::Info && m.contains("rebound"))
        );
        let mut peer = Udp::bind(0, SocketMark::NONE).unwrap();
        assert!(peer.send(at(1), SocketAddr::from(([127, 0, 0, 1], port)), b"again"));
        assert_eq!(receive(&mut s).await.0, b"again");
    }

    #[test]
    fn the_medium_has_one_class_whatever_the_address() {
        let udp = UdpMedium {
            dual_stack: Arc::new(AtomicBool::new(true)),
        };
        let addr = |s: &str| Remote::Addr(s.parse().unwrap());
        assert_eq!(udp.class().latency, Latency::High);
        assert!(!udp.class().metered);
        assert!(udp.reaches(&addr("192.168.1.5:1"), true));
        assert!(udp.reaches(&addr("[2001:db8::5]:1"), true));
        udp.dual_stack.store(false, Ordering::Relaxed);
        assert!(!udp.reaches(&addr("[2001:db8::5]:1"), true));
    }

    #[test]
    fn datagrams_are_sorted_by_their_first_byte_and_the_turn_server() {
        let turn: SocketAddr = "192.0.2.1:3478".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:4000".parse().unwrap();
        assert!(matches!(
            Udp::sort(&[0, 1, 2], turn, Some(turn)),
            Datagram::TurnServer
        ));
        assert!(matches!(
            Udp::sort(
                &[0x00, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42],
                other,
                Some(turn)
            ),
            Datagram::Ignored | Datagram::Stun(_)
        ));
        assert!(matches!(Udp::sort(&[], other, None), Datagram::Ignored));
    }
}
