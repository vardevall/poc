//! The TURN allocation over UDP or a stream [RFC 8656, RFC 7443 framing] with long-term
//! credentials.
//!
//! Sans-IO: the caller sends [`TurnAllocation::poll_transmit`] datagrams to the server from the
//! interface socket, feeds what arrives from the server to [`TurnAllocation::handle_datagram`] and
//! calls [`TurnAllocation::handle_timeout`] at [`TurnAllocation::poll_timeout`]. Time and
//! transaction ids are passed in. Responses are matched by their random transaction id;
//! MESSAGE-INTEGRITY of responses is not verified.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rand_core::CryptoRng;
use vardevall_proto::time::Instant;

use crate::address::SwitchAuth;
use crate::stun::{
    Builder, Class, Message, attr, encode_xor_addr, long_term_key, method, new_txid,
};

/// Lifetime requested for an allocation, which the server may shorten.
const DEFAULT_LIFETIME: u32 = 600;
/// A permission lasts 5 minutes (RFC 8656 §9); it is renewed after this.
const PERMISSION_RENEW: Duration = Duration::from_secs(240);
/// A channel binding lasts 10 minutes (RFC 8656 §12); it is renewed after this.
const CHANNEL_RENEW: Duration = Duration::from_secs(500);
/// Delays of the retransmissions of a request, and the time it fails after.
const RETRANSMIT: [Duration; 2] = [Duration::from_millis(500), Duration::from_millis(1500)];
const FAIL_AFTER: Duration = Duration::from_secs(3);
/// On a stream the request also waits for the connection and the TLS handshake.
const FAIL_AFTER_STREAM: Duration = Duration::from_secs(10);
/// Most 438 (stale nonce) answers in a row that are retried.
const MAX_NONCE_RETRIES: u8 = 3;
/// First channel number (RFC 8656 §12).
const CHANNEL_FIRST: u16 = 0x4000;
const CHANNEL_LAST: u16 = 0x4fff;
/// Most peer addresses with a channel; further peers use Send indications.
const MAX_CHANNELS: usize = 16;
/// UDP in REQUESTED-TRANSPORT.
const TRANSPORT_UDP: [u8; 4] = [17, 0, 0, 0];

/// The username and password of a long-term credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// `<expiry>:<id>` of a TURN REST credential (vv-04 §4.5).
    pub username: String,
    /// The `credential` of the REST scheme.
    pub password: String,
    /// The REALM the server accepts with the credential, if it was told (vv-04 §4.5); with the
    /// nonce, the first Allocate is authenticated.
    pub realm: Option<String>,
    /// The NONCE the server accepts with the credential.
    pub nonce: Option<String>,
}

impl Credentials {
    /// Credentials whose realm and nonce are learnt from the server's 401.
    pub fn new(username: String, password: String) -> Self {
        Credentials {
            username,
            password,
            realm: None,
            nonce: None,
        }
    }

    fn preset(&self) -> Option<Auth> {
        Some(Auth {
            realm: self.realm.as_deref()?.as_bytes().to_vec(),
            nonce: self.nonce.as_deref()?.as_bytes().to_vec(),
        })
    }
}

/// How a TURN server is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnTransport {
    /// UDP [RFC 8656].
    Udp,
    /// TLS 1.3 over TCP with ALPN `stun.turn` [RFC 7443, RFC 6062 framing], authenticated as
    /// the switch that issued the credentials is (vv-04 §2.3).
    Tls {
        /// The host of the `turns:` URI, for the TLS server name.
        host: String,
        /// How the server must prove itself.
        auth: SwitchAuth,
    },
}

/// A TURN server address and the way to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// The resolved address.
    pub addr: SocketAddr,
    /// UDP or TLS.
    pub transport: TurnTransport,
}

impl Server {
    /// A UDP server.
    pub fn udp(addr: SocketAddr) -> Server {
        Server {
            addr,
            transport: TurnTransport::Udp,
        }
    }

    /// Whether the server is reached over a stream.
    pub fn is_stream(&self) -> bool {
        !matches!(self.transport, TurnTransport::Udp)
    }
}

/// TURN credentials of an origin and the addresses of its TURN servers (vv-04 §4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnOffer {
    /// The servers of the `turn:` URIs (UDP) and then of the `turns:` URIs (TLS), IPv6 first.
    pub servers: Vec<Server>,
    /// The long-term credential username.
    pub username: String,
    /// The long-term credential password.
    pub password: String,
    /// Validity of the credential.
    pub ttl: Duration,
    /// Advertised sustained rate per allocation, bits per second (vv-04 §4.5 `limits`).
    pub bits_per_second: Option<u64>,
    /// Advertised volume per credential, bytes (vv-04 §4.5 `limits`); both directions count at
    /// the server.
    pub bytes: Option<u64>,
    /// The REALM the server accepts with the credential, if the switch says (vv-04 §4.5).
    pub realm: Option<String>,
    /// The NONCE the server accepts with the credential.
    pub nonce: Option<String>,
    /// Higher is preferred (vv-07 §3.4); switch-issued credentials have 0.
    pub priority: i32,
}

/// Why an allocation is gone or could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The server rejected the credentials (401, 441), for instance because they expired.
    Unauthorized,
    /// The server does not know the allocation any more (437).
    Mismatch,
    /// The server refused with another error code.
    Rejected(u16),
    /// No answer.
    Timeout,
}

/// A change in the allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The relayed transport address is usable (vv-05 §2.1 `relay`).
    Allocated(SocketAddr),
    /// The allocation ended or failed; the client is idle again.
    Lost(Failure),
}

/// What [`TurnAllocation::handle_datagram`] made of a datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handled {
    /// Data a peer sent to the relayed address, with the peer's transport address.
    Data {
        /// The peer's address as the server saw it.
        peer: SocketAddr,
        /// The datagram.
        payload: Vec<u8>,
    },
    /// A response or error of the client's own transactions.
    Consumed,
    /// Not for this client.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Allocate,
    Refresh { release: bool },
    Permission(Vec<IpAddr>),
    Bind(SocketAddr),
}

struct Pending {
    kind: Kind,
    bytes: Vec<u8>,
    sent: Instant,
    retransmitted: usize,
    authed: bool,
}

#[derive(Clone)]
struct Auth {
    realm: Vec<u8>,
    nonce: Vec<u8>,
}

enum State {
    Idle,
    Allocating,
    Allocated { relayed: SocketAddr },
}

struct Channel {
    number: u16,
    bound: Option<Instant>,
}

/// One allocation on one server.
pub struct TurnAllocation {
    server: SocketAddr,
    stream: bool,
    creds: Credentials,
    auth: Option<Auth>,
    nonce_retries: u8,
    state: State,
    pending: HashMap<[u8; 12], Pending>,
    permissions: HashMap<IpAddr, Instant>,
    channels: HashMap<SocketAddr, Channel>,
    numbers: HashMap<u16, SocketAddr>,
    next_channel: u16,
    refresh_at: Option<Instant>,
    out: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
}

impl TurnAllocation {
    /// An idle client for `server`.
    pub fn new(server: SocketAddr, creds: Credentials) -> Self {
        Self::with_transport(server, creds, false)
    }

    /// An idle client for a server reached over a stream: the transport is reliable, so requests
    /// are not retransmitted, and ChannelData is padded to a multiple of 4 (RFC 8656 §12.5).
    pub fn new_stream(server: SocketAddr, creds: Credentials) -> Self {
        Self::with_transport(server, creds, true)
    }

    fn with_transport(server: SocketAddr, creds: Credentials, stream: bool) -> Self {
        TurnAllocation {
            server,
            stream,
            auth: creds.preset(),
            creds,
            nonce_retries: 0,
            state: State::Idle,
            pending: HashMap::new(),
            permissions: HashMap::new(),
            channels: HashMap::new(),
            numbers: HashMap::new(),
            next_channel: CHANNEL_FIRST,
            refresh_at: None,
            out: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// The server's address.
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// Whether the server is reached over a stream.
    pub fn is_stream(&self) -> bool {
        self.stream
    }

    /// The stream to the server ended: the allocation is lost with it.
    pub fn connection_lost(&mut self) {
        if self.active() {
            self.fail(Failure::Timeout);
        }
    }

    fn fail_after(&self) -> Duration {
        if self.stream {
            FAIL_AFTER_STREAM
        } else {
            FAIL_AFTER
        }
    }

    /// The credentials the next allocation uses.
    pub fn credentials(&self) -> &Credentials {
        &self.creds
    }

    /// The relayed transport address, once allocated.
    pub fn relayed(&self) -> Option<SocketAddr> {
        match self.state {
            State::Allocated { relayed } => Some(relayed),
            _ => None,
        }
    }

    /// Whether an allocation exists or is being made.
    pub fn active(&self) -> bool {
        !matches!(self.state, State::Idle)
    }

    /// Replaces the credentials for the next allocation; the current one keeps its own, which
    /// the server requires for its refreshes (RFC 8656 §7).
    pub fn set_credentials(&mut self, creds: Credentials) {
        if !self.active() {
            if let Some(auth) = creds.preset() {
                self.auth = Some(auth);
            }
            self.creds = creds;
        }
    }

    /// Starts an allocation unless one exists.
    pub fn allocate(&mut self, now: Instant, rng: &mut impl CryptoRng) {
        if self.active() {
            return;
        }
        self.state = State::Allocating;
        let authed = self.auth.is_some();
        self.send_request(
            now,
            rng,
            Kind::Allocate,
            method::ALLOCATE,
            vec![(attr::REQUESTED_TRANSPORT, TRANSPORT_UDP.to_vec())],
            authed,
        );
    }

    /// Releases the allocation (a Refresh with lifetime 0) and forgets its state.
    pub fn release(&mut self, now: Instant, rng: &mut impl CryptoRng) {
        if matches!(self.state, State::Allocated { .. }) {
            self.send_request(
                now,
                rng,
                Kind::Refresh { release: true },
                method::REFRESH,
                vec![(attr::LIFETIME, 0u32.to_be_bytes().to_vec())],
                true,
            );
        }
        self.forget();
    }

    /// Forgets the allocation without telling the server, after a change of local address.
    pub fn reset(&mut self) {
        self.forget();
        self.auth = self.creds.preset();
    }

    fn forget(&mut self) {
        self.state = State::Idle;
        self.permissions.clear();
        self.channels.clear();
        self.numbers.clear();
        self.next_channel = CHANNEL_FIRST;
        self.refresh_at = None;
        self.pending
            .retain(|_, p| p.kind == Kind::Refresh { release: true });
    }

    /// Creates permissions for the addresses in `ips` that lack a fresh one (vv-05 §3.3).
    pub fn permit(&mut self, now: Instant, rng: &mut impl CryptoRng, ips: &[IpAddr]) {
        if !matches!(self.state, State::Allocated { .. }) {
            return;
        }
        let need: Vec<IpAddr> = ips
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .filter(|ip| {
                self.permissions
                    .get(ip)
                    .is_none_or(|t| now.saturating_duration_since(*t) >= PERMISSION_RENEW)
            })
            .collect();
        if need.is_empty() {
            return;
        }
        for ip in &need {
            self.permissions.insert(*ip, now);
        }
        self.send_permission(now, rng, need);
    }

    fn send_permission(&mut self, now: Instant, rng: &mut impl CryptoRng, ips: Vec<IpAddr>) {
        let txid = new_txid(rng);
        let attrs = ips
            .iter()
            .map(|ip| {
                (
                    attr::XOR_PEER_ADDRESS,
                    encode_xor_addr(SocketAddr::new(*ip, 0), &txid),
                )
            })
            .collect();
        self.send_with_txid(
            now,
            txid,
            Kind::Permission(ips),
            method::CREATE_PERMISSION,
            attrs,
            true,
        );
    }

    /// Sends `payload` to `peer` through the allocation; returns whether there is one.
    ///
    /// The first datagram to a peer goes as a Send indication while a channel is bound; later
    /// ones use ChannelData.
    pub fn send(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        peer: SocketAddr,
        payload: &[u8],
    ) -> bool {
        if !matches!(self.state, State::Allocated { .. }) {
            return false;
        }
        self.permit(now, rng, &[peer.ip()]);
        let live = self.channels.get(&peer).and_then(|c| {
            c.bound
                .filter(|t| {
                    now.saturating_duration_since(*t) < CHANNEL_RENEW + Duration::from_secs(60)
                })
                .map(|_| c.number)
        });
        if let Some(number) = live {
            let mut d = Vec::with_capacity(4 + payload.len());
            d.extend_from_slice(&number.to_be_bytes());
            d.extend_from_slice(&u16::try_from(payload.len()).unwrap_or(0).to_be_bytes());
            d.extend_from_slice(payload);
            if self.stream {
                d.resize(d.len().next_multiple_of(4), 0);
            }
            self.out.push_back(d);
            return true;
        }
        if !self.channels.contains_key(&peer) {
            self.bind_channel(now, rng, peer);
        }
        let txid = new_txid(rng);
        let msg = Builder::new(method::SEND, Class::Indication, &txid)
            .attr(attr::XOR_PEER_ADDRESS, &encode_xor_addr(peer, &txid))
            .attr(attr::DATA, payload)
            .finish();
        self.out.push_back(msg);
        true
    }

    fn bind_channel(&mut self, now: Instant, rng: &mut impl CryptoRng, peer: SocketAddr) {
        if self.channels.len() >= MAX_CHANNELS || self.next_channel > CHANNEL_LAST {
            return;
        }
        let number = self.next_channel;
        self.next_channel += 1;
        self.channels.insert(
            peer,
            Channel {
                number,
                bound: None,
            },
        );
        self.numbers.insert(number, peer);
        self.send_bind(now, rng, peer, number);
    }

    fn send_bind(&mut self, now: Instant, rng: &mut impl CryptoRng, peer: SocketAddr, number: u16) {
        let txid = new_txid(rng);
        let attrs = vec![
            (
                attr::CHANNEL_NUMBER,
                [(number >> 8) as u8, number as u8, 0, 0].to_vec(),
            ),
            (attr::XOR_PEER_ADDRESS, encode_xor_addr(peer, &txid)),
        ];
        self.send_with_txid(
            now,
            txid,
            Kind::Bind(peer),
            method::CHANNEL_BIND,
            attrs,
            true,
        );
    }

    fn send_request(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        kind: Kind,
        m: u16,
        attrs: Vec<(u16, Vec<u8>)>,
        authed: bool,
    ) {
        self.send_with_txid(now, new_txid(rng), kind, m, attrs, authed);
    }

    fn send_with_txid(
        &mut self,
        now: Instant,
        txid: [u8; 12],
        kind: Kind,
        m: u16,
        attrs: Vec<(u16, Vec<u8>)>,
        authed: bool,
    ) {
        let mut b = Builder::new(m, Class::Request, &txid);
        for (t, v) in &attrs {
            b = b.attr(*t, v);
        }
        let bytes = match (&self.auth, authed) {
            (Some(a), true) => {
                let key = long_term_key(
                    self.creds.username.as_bytes(),
                    &a.realm,
                    self.creds.password.as_bytes(),
                );
                b.attr(attr::USERNAME, self.creds.username.as_bytes())
                    .attr(attr::REALM, &a.realm)
                    .attr(attr::NONCE, &a.nonce)
                    .finish_with_integrity(&key)
            }
            _ => b.finish(),
        };
        self.out.push_back(bytes.clone());
        self.pending.insert(
            txid,
            Pending {
                kind,
                bytes,
                sent: now,
                retransmitted: 0,
                authed: authed && self.auth.is_some(),
            },
        );
    }

    /// The next datagram for the server.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.out.pop_front()
    }

    /// The next change of the allocation.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Processes a datagram that came from the server's address.
    pub fn handle_datagram(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        buf: &[u8],
    ) -> Handled {
        let Some(&first) = buf.first() else {
            return Handled::Unknown;
        };
        if (0x40..=0x4f).contains(&first) {
            return self.channel_data(buf);
        }
        let Some(msg) = Message::parse(buf) else {
            return Handled::Unknown;
        };
        if msg.method == method::DATA && msg.class == Class::Indication {
            let (Some(peer), Some(data)) =
                (msg.xor_addr(attr::XOR_PEER_ADDRESS), msg.get(attr::DATA))
            else {
                return Handled::Consumed;
            };
            return Handled::Data {
                peer,
                payload: data.to_vec(),
            };
        }
        let Some(p) = self.pending.remove(&msg.txid) else {
            return Handled::Unknown;
        };
        match msg.class {
            Class::Success => self.on_success(now, p, &msg),
            Class::Error => self.on_error(now, rng, p, &msg),
            _ => {}
        }
        Handled::Consumed
    }

    fn channel_data(&mut self, buf: &[u8]) -> Handled {
        if buf.len() < 4 {
            return Handled::Consumed;
        }
        let number = u16::from_be_bytes([buf[0], buf[1]]);
        let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        match (self.numbers.get(&number), buf.get(4..4 + len)) {
            (Some(peer), Some(payload)) => Handled::Data {
                peer: *peer,
                payload: payload.to_vec(),
            },
            _ => Handled::Consumed,
        }
    }

    fn on_success(&mut self, now: Instant, p: Pending, msg: &Message) {
        self.nonce_retries = 0;
        match p.kind {
            Kind::Allocate => {
                let Some(relayed) = msg.xor_addr(attr::XOR_RELAYED_ADDRESS) else {
                    self.fail(Failure::Rejected(0));
                    return;
                };
                let life = msg.lifetime().unwrap_or(DEFAULT_LIFETIME).max(2);
                self.refresh_at = Some(now + Duration::from_secs(u64::from(life) / 2));
                self.state = State::Allocated { relayed };
                self.events.push_back(Event::Allocated(relayed));
            }
            Kind::Refresh { release: false } => {
                let life = msg.lifetime().unwrap_or(DEFAULT_LIFETIME).max(2);
                self.refresh_at = Some(now + Duration::from_secs(u64::from(life) / 2));
            }
            Kind::Refresh { release: true } => {}
            Kind::Permission(_) => {}
            Kind::Bind(peer) => {
                if let Some(c) = self.channels.get_mut(&peer) {
                    c.bound = Some(now);
                }
            }
        }
    }

    fn on_error(&mut self, now: Instant, rng: &mut impl CryptoRng, p: Pending, msg: &Message) {
        let code = msg.error_code().unwrap_or(0);
        let challenge = matches!(code, 401 | 438);
        if challenge {
            if let (Some(realm), Some(nonce)) = (msg.get(attr::REALM), msg.get(attr::NONCE)) {
                self.auth = Some(Auth {
                    realm: realm.to_vec(),
                    nonce: nonce.to_vec(),
                });
            } else if let (Some(a), Some(nonce)) = (self.auth.as_mut(), msg.get(attr::NONCE)) {
                a.nonce = nonce.to_vec();
            }
            let retry = self.auth.is_some() && (!p.authed || code == 438);
            if code == 438 {
                self.nonce_retries = self.nonce_retries.saturating_add(1);
            }
            if retry && self.nonce_retries <= MAX_NONCE_RETRIES {
                self.retry(now, rng, p.kind);
                return;
            }
        }
        match p.kind {
            Kind::Allocate => self.fail(match code {
                401 | 441 => Failure::Unauthorized,
                c => Failure::Rejected(c),
            }),
            Kind::Refresh { release: false } => self.fail(match code {
                401 | 441 => Failure::Unauthorized,
                437 => Failure::Mismatch,
                c => Failure::Rejected(c),
            }),
            Kind::Refresh { release: true } | Kind::Permission(_) => {}
            Kind::Bind(peer) => {
                if let Some(c) = self.channels.remove(&peer) {
                    self.numbers.remove(&c.number);
                }
            }
        }
    }

    fn retry(&mut self, now: Instant, rng: &mut impl CryptoRng, kind: Kind) {
        match kind {
            Kind::Allocate => self.send_request(
                now,
                rng,
                Kind::Allocate,
                method::ALLOCATE,
                vec![(attr::REQUESTED_TRANSPORT, TRANSPORT_UDP.to_vec())],
                true,
            ),
            Kind::Refresh { release } => {
                let life = if release { 0 } else { DEFAULT_LIFETIME };
                self.send_request(
                    now,
                    rng,
                    Kind::Refresh { release },
                    method::REFRESH,
                    vec![(attr::LIFETIME, life.to_be_bytes().to_vec())],
                    true,
                );
            }
            Kind::Permission(ips) => {
                self.send_permission(now, rng, ips);
            }
            Kind::Bind(peer) => {
                if let Some(number) = self.channels.get(&peer).map(|c| c.number) {
                    self.send_bind(now, rng, peer, number);
                }
            }
        }
    }

    fn fail(&mut self, failure: Failure) {
        self.forget();
        self.events.push_back(Event::Lost(failure));
    }

    /// When [`TurnAllocation::handle_timeout`] must run next.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let fail_after = self.fail_after();
        let stream = self.stream;
        let pending = self.pending.values().map(|p| {
            p.sent
                + RETRANSMIT
                    .get(p.retransmitted)
                    .copied()
                    .filter(|_| !stream)
                    .unwrap_or(fail_after)
        });
        let renew = self
            .permissions
            .values()
            .map(|t| *t + PERMISSION_RENEW)
            .chain(
                self.channels
                    .values()
                    .filter_map(|c| c.bound.map(|t| t + CHANNEL_RENEW)),
            );
        pending.chain(self.refresh_at).chain(renew).min()
    }

    /// Retransmits, fails requests that got no answer, and renews the allocation, permissions and
    /// channels.
    pub fn handle_timeout(&mut self, now: Instant, rng: &mut impl CryptoRng) {
        let mut failed = Vec::new();
        let fail_after = self.fail_after();
        let stream = self.stream;
        for (txid, p) in &mut self.pending {
            if now >= p.sent + fail_after {
                failed.push(*txid);
            } else if RETRANSMIT
                .get(p.retransmitted)
                .is_some_and(|d| !stream && now >= p.sent + *d)
            {
                p.retransmitted += 1;
                self.out.push_back(p.bytes.clone());
            }
        }
        for txid in failed {
            let Some(p) = self.pending.remove(&txid) else {
                continue;
            };
            match p.kind {
                Kind::Allocate | Kind::Refresh { release: false } => {
                    self.fail(Failure::Timeout);
                    return;
                }
                Kind::Bind(peer) => {
                    if let Some(c) = self.channels.remove(&peer) {
                        self.numbers.remove(&c.number);
                    }
                }
                _ => {}
            }
        }
        if !matches!(self.state, State::Allocated { .. }) {
            return;
        }
        if self.refresh_at.is_some_and(|t| now >= t) {
            self.refresh_at = None;
            self.send_request(
                now,
                rng,
                Kind::Refresh { release: false },
                method::REFRESH,
                vec![(attr::LIFETIME, DEFAULT_LIFETIME.to_be_bytes().to_vec())],
                true,
            );
        }
        let stale: Vec<IpAddr> = self
            .permissions
            .iter()
            .filter(|(_, t)| now.saturating_duration_since(**t) >= PERMISSION_RENEW)
            .map(|(ip, _)| *ip)
            .collect();
        self.permit(now, rng, &stale);
        let rebind: Vec<(SocketAddr, u16)> = self
            .channels
            .iter()
            .filter(|(_, c)| {
                c.bound
                    .is_some_and(|t| now.saturating_duration_since(t) >= CHANNEL_RENEW)
            })
            .map(|(a, c)| (*a, c.number))
            .collect();
        for (peer, number) in rebind {
            if let Some(c) = self.channels.get_mut(&peer) {
                c.bound = Some(now);
            }
            self.send_bind(now, rng, peer, number);
        }
    }
}

/// The length of the next message on a byte stream, from its first four bytes: a STUN message (20-byte
/// header and its length) or ChannelData (4-byte header, the data and padding to a multiple of 4)
/// [RFC 8656 §12.5, RFC 7443]; `None` if they begin neither.
pub fn frame_len(head: [u8; 4]) -> Option<usize> {
    let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
    match head[0] >> 6 {
        0 => Some(20 + len),
        1 => Some(4 + len.next_multiple_of(4)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vardevall_proto::sim::SimRng;

    use crate::stun::verify_integrity;

    fn creds() -> Credentials {
        Credentials::new("9999999999:abc".to_owned(), "secret".to_owned())
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn server() -> SocketAddr {
        addr("192.0.2.10:3478")
    }

    fn key() -> [u8; 16] {
        long_term_key(b"9999999999:abc", b"realm", b"secret")
    }

    fn challenge(request: &[u8]) -> Vec<u8> {
        let m = Message::parse(request).unwrap();
        Builder::new(m.method, Class::Error, &m.txid)
            .attr(attr::ERROR_CODE, &[0, 0, 4, 1])
            .attr(attr::REALM, b"realm")
            .attr(attr::NONCE, b"n1")
            .finish()
    }

    fn allocated(request: &[u8], relayed: &str, life: u32) -> Vec<u8> {
        let m = Message::parse(request).unwrap();
        Builder::new(m.method, Class::Success, &m.txid)
            .attr(
                attr::XOR_RELAYED_ADDRESS,
                &encode_xor_addr(addr(relayed), &m.txid),
            )
            .attr(attr::LIFETIME, &life.to_be_bytes())
            .finish()
    }

    fn ok(request: &[u8]) -> Vec<u8> {
        let m = Message::parse(request).unwrap();
        Builder::new(m.method, Class::Success, &m.txid).finish()
    }

    fn up(c: &mut TurnAllocation, now: Instant, rng: &mut SimRng) -> SocketAddr {
        c.allocate(now, rng);
        let first = c.poll_transmit().unwrap();
        assert!(
            Message::parse(&first)
                .unwrap()
                .get(attr::INTEGRITY)
                .is_none()
        );
        c.handle_datagram(now, rng, &challenge(&first));
        let second = c.poll_transmit().unwrap();
        assert!(verify_integrity(&second, &key()));
        let m = Message::parse(&second).unwrap();
        assert_eq!(m.get(attr::USERNAME), Some(&b"9999999999:abc"[..]));
        assert_eq!(m.get(attr::REALM), Some(&b"realm"[..]));
        c.handle_datagram(now, rng, &allocated(&second, "198.51.100.5:49152", 600));
        match c.poll_event() {
            Some(Event::Allocated(a)) => a,
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn long_term_authentication_allocates() {
        let mut rng = SimRng::new(1);
        let now = Instant::from_millis(1000);
        let mut c = TurnAllocation::new(server(), creds());
        assert_eq!(up(&mut c, now, &mut rng), addr("198.51.100.5:49152"));
        assert_eq!(c.relayed(), Some(addr("198.51.100.5:49152")));
        assert!(c.poll_transmit().is_none());
    }

    #[test]
    fn permissions_and_channels_carry_data_both_ways() {
        let mut rng = SimRng::new(1);
        let now = Instant::from_millis(1000);
        let mut c = TurnAllocation::new(server(), creds());
        up(&mut c, now, &mut rng);
        let peer = addr("203.0.113.9:4000");

        assert!(c.send(now, &mut rng, peer, b"first"));
        let permission = c.poll_transmit().unwrap();
        let m = Message::parse(&permission).unwrap();
        assert_eq!(m.method, method::CREATE_PERMISSION);
        assert_eq!(m.xor_addr(attr::XOR_PEER_ADDRESS).unwrap().ip(), peer.ip());
        let bind = c.poll_transmit().unwrap();
        assert_eq!(Message::parse(&bind).unwrap().method, method::CHANNEL_BIND);
        let indication = c.poll_transmit().unwrap();
        let m = Message::parse(&indication).unwrap();
        assert_eq!((m.method, m.class), (method::SEND, Class::Indication));
        assert_eq!(m.get(attr::DATA), Some(&b"first"[..]));
        assert_eq!(m.xor_addr(attr::XOR_PEER_ADDRESS), Some(peer));

        c.handle_datagram(now, &mut rng, &ok(&permission));
        c.handle_datagram(now, &mut rng, &ok(&bind));
        assert!(c.send(now, &mut rng, peer, b"second"));
        let data = c.poll_transmit().unwrap();
        assert_eq!(&data[..2], &[0x40, 0x00]);
        assert_eq!(&data[2..4], &[0, 6]);
        assert_eq!(&data[4..], b"second");

        let mut inbound = vec![0x40, 0x00, 0, 3];
        inbound.extend_from_slice(b"abc");
        assert_eq!(
            c.handle_datagram(now, &mut rng, &inbound),
            Handled::Data {
                peer,
                payload: b"abc".to_vec()
            }
        );
        let txid = [1u8; 12];
        let ind = Builder::new(method::DATA, Class::Indication, &txid)
            .attr(
                attr::XOR_PEER_ADDRESS,
                &encode_xor_addr(addr("203.0.113.77:1"), &txid),
            )
            .attr(attr::DATA, b"xyz")
            .finish();
        assert_eq!(
            c.handle_datagram(now, &mut rng, &ind),
            Handled::Data {
                peer: addr("203.0.113.77:1"),
                payload: b"xyz".to_vec()
            }
        );
    }

    #[test]
    fn the_allocation_is_refreshed_and_released() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut c = TurnAllocation::new(server(), creds());
        up(&mut c, t0, &mut rng);
        assert_eq!(c.poll_timeout(), Some(t0 + Duration::from_secs(300)));
        c.handle_timeout(t0 + Duration::from_secs(300), &mut rng);
        let refresh = c.poll_transmit().unwrap();
        let m = Message::parse(&refresh).unwrap();
        assert_eq!(m.method, method::REFRESH);
        assert_eq!(m.lifetime(), Some(600));
        assert!(verify_integrity(&refresh, &key()));
        c.handle_datagram(t0 + Duration::from_secs(300), &mut rng, &ok(&refresh));
        c.release(t0 + Duration::from_secs(301), &mut rng);
        let release = c.poll_transmit().unwrap();
        assert_eq!(Message::parse(&release).unwrap().lifetime(), Some(0));
        assert!(!c.active());
        assert_eq!(c.relayed(), None);
    }

    #[test]
    fn rejected_credentials_and_silence_fail_the_allocation() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut c = TurnAllocation::new(server(), creds());
        c.allocate(t0, &mut rng);
        let first = c.poll_transmit().unwrap();
        c.handle_datagram(t0, &mut rng, &challenge(&first));
        let second = c.poll_transmit().unwrap();
        c.handle_datagram(t0, &mut rng, &challenge(&second));
        assert_eq!(c.poll_event(), Some(Event::Lost(Failure::Unauthorized)));
        assert!(!c.active());

        c.allocate(t0, &mut rng);
        c.poll_transmit();
        c.handle_timeout(t0 + Duration::from_millis(500), &mut rng);
        assert!(c.poll_transmit().is_some(), "retransmitted");
        c.handle_timeout(t0 + Duration::from_secs(3), &mut rng);
        assert_eq!(c.poll_event(), Some(Event::Lost(Failure::Timeout)));
    }

    #[test]
    fn a_stale_nonce_is_replaced_and_the_request_repeated() {
        let mut rng = SimRng::new(1);
        let now = Instant::from_millis(1000);
        let mut c = TurnAllocation::new(server(), creds());
        up(&mut c, now, &mut rng);
        c.handle_timeout(now + Duration::from_secs(300), &mut rng);
        let refresh = c.poll_transmit().unwrap();
        let m = Message::parse(&refresh).unwrap();
        let stale = Builder::new(m.method, Class::Error, &m.txid)
            .attr(attr::ERROR_CODE, &[0, 0, 4, 38])
            .attr(attr::REALM, b"realm")
            .attr(attr::NONCE, b"n2")
            .finish();
        c.handle_datagram(now, &mut rng, &stale);
        let again = Message::parse(&c.poll_transmit().unwrap()).unwrap();
        assert_eq!(again.get(attr::NONCE), Some(&b"n2"[..]));
        assert_eq!(again.method, method::REFRESH);
    }

    #[test]
    fn a_preset_realm_and_nonce_authenticate_the_first_allocate() {
        let mut rng = SimRng::new(1);
        let now = Instant::from_millis(1000);
        let mut c = TurnAllocation::new(
            server(),
            Credentials {
                realm: Some("vv".to_owned()),
                nonce: Some("n0".to_owned()),
                ..creds()
            },
        );
        c.allocate(now, &mut rng);
        let raw = c.poll_transmit().unwrap();
        let first = Message::parse(&raw).unwrap();
        assert_eq!(first.method, method::ALLOCATE);
        assert_eq!(first.get(attr::REALM), Some(&b"vv"[..]));
        assert_eq!(first.get(attr::NONCE), Some(&b"n0"[..]));
        let key = long_term_key(b"9999999999:abc", b"vv", b"secret");
        assert!(verify_integrity(&raw, &key));
        assert!(c.poll_transmit().is_none());
    }

    #[test]
    fn a_server_that_keeps_answering_stale_nonce_is_given_up_on() {
        let mut rng = SimRng::new(1);
        let now = Instant::from_millis(1000);
        let mut c = TurnAllocation::new(
            server(),
            Credentials {
                realm: Some("vv".to_owned()),
                nonce: Some("n0".to_owned()),
                ..creds()
            },
        );
        c.allocate(now, &mut rng);
        for i in 0..8u8 {
            let Some(raw) = c.poll_transmit() else { break };
            let req = Message::parse(&raw).unwrap();
            let stale = Builder::new(req.method, Class::Error, &req.txid)
                .attr(attr::ERROR_CODE, &[0, 0, 4, 38])
                .attr(attr::NONCE, &[i + 1])
                .finish();
            c.handle_datagram(now, &mut rng, &stale);
        }
        assert_eq!(c.poll_event(), Some(Event::Lost(Failure::Rejected(438))));
    }

    #[test]
    fn credentials_change_only_between_allocations() {
        let mut rng = SimRng::new(1);
        let now = Instant::from_millis(1000);
        let mut c = TurnAllocation::new(server(), creds());
        up(&mut c, now, &mut rng);
        let fresh = Credentials::new("1:x".to_owned(), "p".to_owned());
        c.set_credentials(fresh.clone());
        assert_eq!(c.credentials(), &creds());
        c.release(now, &mut rng);
        c.set_credentials(fresh.clone());
        assert_eq!(c.credentials(), &fresh);
    }

    #[test]
    fn unrelated_datagrams_are_not_consumed() {
        let mut rng = SimRng::new(1);
        let now = Instant::from_millis(1000);
        let mut c = TurnAllocation::new(server(), creds());
        let binding = Builder::new(method::BINDING, Class::Success, &[4; 12]).finish();
        assert_eq!(c.handle_datagram(now, &mut rng, &binding), Handled::Unknown);
        assert_eq!(c.handle_datagram(now, &mut rng, &[]), Handled::Unknown);
        assert_eq!(
            c.handle_datagram(now, &mut rng, &[0x41, 0, 0, 1, 7]),
            Handled::Consumed
        );
    }

    #[test]
    fn frame_lengths_follow_the_header() {
        assert_eq!(frame_len([0x00, 0x01, 0x00, 0x04]), Some(24));
        assert_eq!(frame_len([0x40, 0x01, 0x00, 0x03]), Some(8));
        assert_eq!(frame_len([0x40, 0x01, 0x00, 0x04]), Some(8));
        assert_eq!(frame_len([0xc0, 0, 0, 0]), None);
    }
}
