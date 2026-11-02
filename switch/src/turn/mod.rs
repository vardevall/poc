//! The embedded TURN server [RFC 8656] (vv-04 §4.5, §2.3).
//!
//! It serves what vardevall nodes and standard clients need: UDP allocations with an IPv4 or
//! IPv6 relayed address, Allocate, Refresh, CreatePermission, ChannelBind, Send and Data
//! indications and ChannelData, over UDP and over a TLS stream selected by ALPN `stun.turn`
//! [RFC 7443]. Long-term credentials are the TURN REST credentials the switch issues: the username
//! is `<expiry>:<id>` and the password the HMAC of it under the shared secret.
//!
//! Like the rest of the switch it keeps everything in memory and logs nothing: no allocation,
//! credential or address ever reaches a log (vv-04 §8). Peers in private, loopback and link-local
//! ranges are refused unless the operator allows them ([`peers`]).
//!
//! The credentials carry `realm` and `nonce` (vv-04 §4.5), so a client's first Allocate is already
//! authenticated. With `silent` the server sends nothing at all in reply to a request that is not
//! authenticated for a current credential, and a Binding request needs the credential of vv-04
//! §4.7 when `stun_auth` is on.
//!
//! Behind a 1:1 NAT the relay sockets bind to the local `relay_ipv4`/`relay_ipv6` while clients are
//! given `relay_ipv4_public`/`relay_ipv6_public`. A peer at one of those public addresses is one of
//! this switch's own relays: the datagram goes to the same port on the local address, only in the
//! relay port range (any other port is refused with 403), and datagrams arriving from a relay port
//! of the local address are attributed to the public one, so two allocations here reach each other.
//! Without a public address the relay address is the switch's own address, and so are the addresses
//! it listens on: unless private peers are allowed, a peer there is reachable only on relay ports,
//! never on the switch's own ports.

mod peers;
mod stream;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use vardevall_proto::keys::{base32, crypto};
use vardevall_switch_proto::api::turn_credential;
use vardevall_switch_proto::stun::{
    Builder, Class, Message, attr, encode_xor_addr, long_term_key, method, verify_integrity,
};

use crate::api::{credential_nonce, unix_now};
use crate::backoff::Backoff;
use crate::config::Turn;
use crate::limits::TokenBucket;
use crate::stun::signed;

/// Lifetime of an allocation without LIFETIME in the request (RFC 8656 §7.2).
const DEFAULT_LIFETIME: u32 = 600;
/// Longest lifetime granted.
const MAX_LIFETIME: u32 = 3600;
/// Lifetime of a permission (RFC 8656 §9).
const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
/// Lifetime of a channel binding (RFC 8656 §12).
const CHANNEL_LIFETIME: Duration = Duration::from_secs(600);
/// Validity of a nonce, after which the client is told it is stale.
const NONCE_LIFETIME: u64 = 600;
/// Idle time after which a TURN stream is closed.
const STREAM_IDLE: Duration = Duration::from_secs(600);
/// Datagrams queued towards one stream client; more are dropped.
const STREAM_QUEUE: usize = 128;
/// Relay ports tried before an allocation is refused for lack of capacity.
const BIND_TRIES: usize = 24;
/// Smallest burst of the per-allocation rate limit, so that a full-size packet always fits.
const MIN_BURST: f64 = 4096.0;

/// Where responses and relayed data go.
#[derive(Clone)]
pub enum Sink {
    /// A UDP client.
    Udp(Arc<UdpSocket>, SocketAddr),
    /// A stream client, through its writer.
    Stream(mpsc::Sender<Vec<u8>>),
}

impl Sink {
    async fn send(&self, data: Vec<u8>) {
        match self {
            Sink::Udp(socket, to) => {
                let _ = socket.send_to(&data, to).await;
            }
            Sink::Stream(tx) => {
                let _ = tx.try_send(data);
            }
        }
    }
}

/// Identifies a client: the 5-tuple of RFC 8656 reduced to what the switch distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKey {
    /// A UDP source address.
    Udp(SocketAddr),
    /// A stream connection.
    Stream(u64),
}

struct Alloc {
    username: String,
    limits: crate::config::TurnLimits,
    ip: IpAddr,
    v6: bool,
    expires: Instant,
    relay: Arc<UdpSocket>,
    perms: HashMap<IpAddr, Instant>,
    channels: HashMap<u16, (SocketAddr, Instant)>,
    bucket: Option<TokenBucket>,
    task: JoinHandle<()>,
}

impl Drop for Alloc {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
struct Cred {
    allocations: usize,
    bytes: u64,
    expiry: u64,
}

#[derive(Default)]
struct State {
    allocs: HashMap<ClientKey, Alloc>,
    creds: HashMap<String, Cred>,
    per_ip: HashMap<IpAddr, usize>,
}

impl State {
    fn remove(&mut self, key: &ClientKey) {
        let Some(a) = self.allocs.remove(key) else {
            return;
        };
        if let Some(c) = self.creds.get_mut(&a.username) {
            c.allocations = c.allocations.saturating_sub(1);
        }
        if let Some(n) = self.per_ip.get_mut(&a.ip) {
            *n -= 1;
            if *n == 0 {
                self.per_ip.remove(&a.ip);
            }
        }
    }
}

struct Authed {
    username: String,
    key: Vec<u8>,
    sha256: bool,
    /// The request up to its MESSAGE-INTEGRITY: the attributes it authenticates.
    request: Message,
}

/// The embedded TURN server.
pub struct TurnServer {
    cfg: crate::config::TurnServer,
    secret: String,
    silent: bool,
    stun_auth: bool,
    own: Vec<IpAddr>,
    counters: Arc<crate::status::Counters>,
    tokens: Arc<crate::api::Tokens>,
    nonce_key: [u8; 32],
    state: Mutex<State>,
    streams: AtomicU64,
    limiters: Arc<crate::limits::Limiters>,
}

fn txid() -> [u8; 12] {
    let mut t = [0u8; 12];
    let _ = getrandom::fill(&mut t);
    t
}

fn error_code(code: u16) -> [u8; 4] {
    [0, 0, (code / 100) as u8, (code % 100) as u8]
}

impl TurnServer {
    /// The server of `turn`, or `None` if the operator runs none. `stun_auth` makes Binding
    /// requests need a credential (vv-04 §4.7); `own` are the addresses the switch listens on.
    pub fn new(
        turn: &Turn,
        stun_auth: bool,
        own: &[IpAddr],
        tokens: Arc<crate::api::Tokens>,
        limiters: Arc<crate::limits::Limiters>,
        counters: Arc<crate::status::Counters>,
    ) -> Option<Arc<TurnServer>> {
        let cfg = turn.server.clone()?;
        let mut nonce_key = [0u8; 32];
        getrandom::fill(&mut nonce_key).ok()?;
        let own = own
            .iter()
            .copied()
            .chain(cfg.listen.iter().map(SocketAddr::ip))
            .chain(cfg.relay_ipv4.map(IpAddr::from))
            .chain(cfg.relay_ipv6.map(IpAddr::from))
            .map(|ip| ip.to_canonical())
            .filter(|ip| !ip.is_unspecified())
            .collect();
        Some(Arc::new(TurnServer {
            cfg,
            secret: turn.secret.clone(),
            silent: turn.silent,
            stun_auth,
            own,
            counters,
            tokens,
            nonce_key,
            state: Mutex::new(State::default()),
            streams: AtomicU64::new(0),
            limiters,
        }))
    }

    /// Whether TURN over TLS is accepted (ALPN `stun.turn`).
    pub fn tls(&self) -> bool {
        self.cfg.tls
    }

    /// The UDP addresses to listen on.
    pub fn listen(&self) -> &[SocketAddr] {
        &self.cfg.listen
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Removes expired allocations and the accounting of expired credentials.
    pub fn sweep(&self, now: Instant) {
        let unix = unix_now();
        let mut st = self.lock();
        let gone: Vec<ClientKey> = st
            .allocs
            .iter()
            .filter(|(_, a)| a.expires <= now)
            .map(|(k, _)| *k)
            .collect();
        for k in gone {
            st.remove(&k);
        }
        st.creds.retain(|_, c| c.allocations > 0 || c.expiry > unix);
        for a in st.allocs.values_mut() {
            a.perms.retain(|_, t| *t > now);
            a.channels.retain(|_, (_, t)| *t > now);
        }
    }

    /// Allocations held, for monitoring.
    pub fn allocations(&self) -> usize {
        self.lock().allocs.len()
    }

    fn nonce(&self, t: u64, ip: IpAddr) -> String {
        let octets = match ip.to_canonical() {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        let mac = crypto::hmac(&self.nonce_key, &[&t.to_le_bytes(), &octets]);
        let mut raw = t.to_le_bytes().to_vec();
        raw.extend_from_slice(&mac[..16]);
        base32::encode(&raw)
    }

    fn nonce_valid(&self, nonce: &[u8], ip: IpAddr) -> bool {
        let Ok(text) = std::str::from_utf8(nonce) else {
            return false;
        };
        let Ok(raw) = base32::decode(text) else {
            return false;
        };
        let Some(t) = raw.get(..8).and_then(|b| <[u8; 8]>::try_from(b).ok()) else {
            return false;
        };
        let t = u64::from_le_bytes(t);
        let now = unix_now();
        t <= now
            && now - t < NONCE_LIFETIME
            && bool::from(self.nonce(t, ip).as_bytes().ct_eq(nonce))
    }

    fn credential_nonce_valid(&self, nonce: &[u8], expiry: u64) -> bool {
        bool::from(
            credential_nonce(&self.secret, expiry)
                .as_bytes()
                .ct_eq(nonce),
        )
    }

    fn challenge(&self, m: &Message, code: u16, ip: IpAddr) -> Vec<u8> {
        Builder::new(m.method, Class::Error, &m.txid)
            .attr(attr::ERROR_CODE, &error_code(code))
            .attr(attr::REALM, self.cfg.realm.as_bytes())
            .attr(attr::NONCE, self.nonce(unix_now(), ip).as_bytes())
            .finish()
    }

    fn failure(m: &Message, code: u16) -> Vec<u8> {
        Builder::new(m.method, Class::Error, &m.txid)
            .attr(attr::ERROR_CODE, &error_code(code))
            .finish()
    }

    /// Checks that the request is signed for a current credential. The error is the reply to
    /// send, or `None` for silence: a silent server answers only authenticated requests.
    fn authenticate(&self, raw: &[u8], m: &Message, ip: IpAddr) -> Result<Authed, Option<Vec<u8>>> {
        let refuse = |reply: Vec<u8>| (!self.silent).then_some(reply);
        let Some(signed) = signed(m) else {
            return Err(refuse(self.challenge(m, 401, ip)));
        };
        let request = signed.message;
        let (Some(user), Some(realm), Some(nonce)) = (
            request.get(attr::USERNAME),
            request.get(attr::REALM),
            request.get(attr::NONCE),
        ) else {
            return Err(refuse(Self::failure(m, 400)));
        };
        let Ok(username) = std::str::from_utf8(user) else {
            return Err(refuse(Self::failure(m, 400)));
        };
        let Some(expiry) = username
            .split_once(':')
            .and_then(|(e, _)| e.parse::<u64>().ok())
            .filter(|e| *e > unix_now())
        else {
            return Err(refuse(self.challenge(m, 401, ip)));
        };
        if !(self.credential_nonce_valid(nonce, expiry) || self.nonce_valid(nonce, ip)) {
            return Err(refuse(self.challenge(m, 438, ip)));
        }
        if realm != self.cfg.realm.as_bytes() {
            return Err(refuse(Self::failure(m, 400)));
        }
        let key = long_term_key(
            user,
            realm,
            turn_credential(&self.secret, username).as_bytes(),
        );
        if !verify_integrity(raw, &key) {
            return Err(refuse(self.challenge(m, 401, ip)));
        }
        Ok(Authed {
            username: username.to_owned(),
            key: key.to_vec(),
            sha256: signed.sha256,
            request,
        })
    }

    fn success(m: &Message, auth: &Authed, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut b = Builder::new(m.method, Class::Success, &m.txid);
        for (t, v) in attrs {
            b = b.attr(*t, v);
        }
        if auth.sha256 {
            b.finish_with_integrity_sha256(&auth.key)
        } else {
            b.finish_with_integrity(&auth.key)
        }
    }

    /// Allocates a fresh stream key.
    pub fn new_stream_key(&self) -> ClientKey {
        ClientKey::Stream(self.streams.fetch_add(1, Ordering::Relaxed))
    }

    /// Forgets the allocation of a client whose connection ended.
    pub fn drop_client(&self, key: &ClientKey) {
        self.lock().remove(key);
    }

    /// Handles one datagram or stream frame from `key`, which was seen at `from`.
    pub async fn handle(
        self: &Arc<Self>,
        key: ClientKey,
        from: SocketAddr,
        sink: &Sink,
        raw: &[u8],
    ) {
        let Some(&first) = raw.first() else {
            return;
        };
        if (0x40..=0x7f).contains(&first) {
            self.channel_data(&key, raw).await;
            return;
        }
        let Some(m) = Message::parse(raw) else {
            return;
        };
        let from = SocketAddr::new(from.ip().to_canonical(), from.port());
        // Requests on UDP are cheap to send from a forged address and each gets an answer; on a
        // stream each costs a MAC or a relay bind. Limit both per client address.
        if m.class == Class::Request && self.limiters.stun(from.ip(), Instant::now()).is_err() {
            self.counters.unanswered();
            return;
        }
        match (m.class, m.method) {
            (Class::Request, method::BINDING) => {
                let reply = if self.stun_auth {
                    crate::stun::respond_authenticated(raw, from, &self.secret, unix_now())
                } else {
                    crate::stun::respond(raw, from)
                };
                match reply {
                    Some(reply) => sink.send(reply).await,
                    None => self.counters.unanswered(),
                }
            }
            (Class::Indication, method::SEND) => self.send_indication(&key, &m).await,
            (
                Class::Request,
                method::ALLOCATE
                | method::REFRESH
                | method::CREATE_PERMISSION
                | method::CHANNEL_BIND,
            ) => match self.request(key, from, sink, raw, &m).await {
                Some(reply) => sink.send(reply).await,
                None => self.counters.unanswered(),
            },
            _ => {}
        }
    }

    async fn request(
        self: &Arc<Self>,
        key: ClientKey,
        from: SocketAddr,
        sink: &Sink,
        raw: &[u8],
        m: &Message,
    ) -> Option<Vec<u8>> {
        let auth = match self.authenticate(raw, m, from.ip()) {
            Ok(a) => a,
            Err(reply) => return reply,
        };
        let m = &auth.request;
        let result = match m.method {
            method::ALLOCATE => self.allocate(key, from, sink, m, &auth).await,
            method::REFRESH => self.refresh(&key, m, &auth),
            method::CREATE_PERMISSION => self.permission(&key, m, &auth),
            _ => self.bind(&key, m, &auth),
        };
        Some(match result {
            Ok(attrs) => Self::success(m, &auth, &attrs),
            Err(code) => Self::failure(m, code),
        })
    }

    async fn allocate(
        self: &Arc<Self>,
        key: ClientKey,
        from: SocketAddr,
        sink: &Sink,
        m: &Message,
        auth: &Authed,
    ) -> Result<Vec<(u16, Vec<u8>)>, u16> {
        if m.get(attr::REQUESTED_TRANSPORT).and_then(|v| v.first()) != Some(&17) {
            return Err(442);
        }
        let v6 = match m
            .get(attr::REQUESTED_ADDRESS_FAMILY)
            .and_then(|v| v.first())
        {
            None => self.cfg.relay_ipv4.is_none(),
            Some(1) => false,
            Some(2) => true,
            Some(_) => return Err(440),
        };
        let (relay_ip, public_ip) = self.relay_ips(v6).ok_or(440u16)?;
        let expiry: u64 = auth
            .username
            .split_once(':')
            .and_then(|(e, _)| e.parse().ok())
            .unwrap_or(0);
        let now = Instant::now();
        let ip = from.ip();
        self.admit(&key, ip, &auth.username, expiry)?;
        let relay = Arc::new(self.bind_relay(relay_ip).await.ok_or(508u16)?);
        let relayed = SocketAddr::new(public_ip, relay.local_addr().map_err(|_| 508u16)?.port());
        let lifetime = m
            .lifetime()
            .unwrap_or(DEFAULT_LIFETIME)
            .clamp(1, MAX_LIFETIME)
            .min(
                u32::try_from(expiry.saturating_sub(unix_now()))
                    .unwrap_or(MAX_LIFETIME)
                    .max(1),
            );
        let task = tokio::spawn(relay_loop(self.clone(), key, sink.clone(), relay.clone()));
        let limits = self.limits_of(&auth.username);
        let bucket = limits
            .bits_per_second
            .map(|_| TokenBucket::full(Self::burst(limits), now));
        let mut st = self.lock();
        if let Err(code) = self.admit_locked(&mut st, &key, ip, &auth.username, expiry) {
            task.abort();
            return Err(code);
        }
        st.allocs.insert(
            key,
            Alloc {
                username: auth.username.clone(),
                limits,
                ip,
                v6,
                expires: now + Duration::from_secs(u64::from(lifetime)),
                relay,
                perms: HashMap::new(),
                channels: HashMap::new(),
                bucket,
                task,
            },
        );
        st.creds
            .entry(auth.username.clone())
            .or_default()
            .allocations += 1;
        *st.per_ip.entry(ip).or_default() += 1;
        drop(st);
        let txid = &m.txid;
        Ok(vec![
            (attr::XOR_RELAYED_ADDRESS, encode_xor_addr(relayed, txid)),
            (attr::LIFETIME, lifetime.to_be_bytes().to_vec()),
            (attr::XOR_MAPPED_ADDRESS, encode_xor_addr(from, txid)),
        ])
    }

    fn admit(&self, key: &ClientKey, ip: IpAddr, username: &str, expiry: u64) -> Result<(), u16> {
        self.admit_locked(&mut self.lock(), key, ip, username, expiry)
    }

    /// Whether a new allocation for `key` fits the quotas of the server, the credential and the
    /// client address. Checked before the relay is bound and again after, since binding waits
    /// and other requests run meanwhile.
    fn admit_locked(
        &self,
        st: &mut State,
        key: &ClientKey,
        ip: IpAddr,
        username: &str,
        expiry: u64,
    ) -> Result<(), u16> {
        if st.allocs.contains_key(key) {
            return Err(437);
        }
        let cred = st.creds.entry(username.to_owned()).or_default();
        cred.expiry = expiry;
        if cred.allocations >= self.cfg.allocations_per_credential
            || st.allocs.len() >= self.cfg.max_allocations
            || st.per_ip.get(&ip).copied().unwrap_or(0) >= self.cfg.allocations_per_ip
        {
            return Err(486);
        }
        Ok(())
    }

    /// The limits of the credential `username`: those of the class named in its id, which hold
    /// for as long as the credential does, whatever a reload changed since.
    fn limits_of(&self, username: &str) -> crate::config::TurnLimits {
        self.tokens.limits(crate::api::credential_class(username))
    }

    fn burst(limits: crate::config::TurnLimits) -> f64 {
        Self::rate(limits).max(MIN_BURST)
    }

    fn rate(limits: crate::config::TurnLimits) -> f64 {
        limits.bits_per_second.map_or(f64::MAX, |b| b as f64 / 8.0)
    }

    /// The local address relay sockets bind to and the address clients are given, for a family.
    fn relay_ips(&self, v6: bool) -> Option<(IpAddr, IpAddr)> {
        let c = &self.cfg;
        if v6 {
            let local = c.relay_ipv6?;
            Some((local.into(), c.relay_ipv6_public.unwrap_or(local).into()))
        } else {
            let local = c.relay_ipv4?;
            Some((local.into(), c.relay_ipv4_public.unwrap_or(local).into()))
        }
    }

    /// Where a datagram for `peer` is sent: the local relay address for one of this switch's own
    /// public relay addresses, and `None` if that is not a relay port. A peer at another address of
    /// the switch (its local relay and listen addresses) is also reachable only on relay ports,
    /// unless private peers are allowed. Any other peer is sent to as it is.
    fn destination(&self, peer: SocketAddr) -> Option<SocketAddr> {
        let c = &self.cfg;
        let (lo, hi) = c.relay_ports;
        let relay_port = (lo..=hi).contains(&peer.port());
        let public_of = match peer.ip() {
            IpAddr::V4(a) if c.relay_ipv4_public == Some(a) => Some(c.relay_ipv4?.into()),
            IpAddr::V6(a) if c.relay_ipv6_public == Some(a) => Some(c.relay_ipv6?.into()),
            _ => None,
        };
        if let Some(local) = public_of {
            return relay_port.then_some(SocketAddr::new(local, peer.port()));
        }
        if !c.allow_private_peers && !relay_port && self.own.contains(&peer.ip()) {
            return None;
        }
        Some(peer)
    }

    /// The address a datagram from `from` is attributed to: a relay port of the local relay
    /// address is that of the public one.
    fn public_source(&self, from: SocketAddr) -> SocketAddr {
        let c = &self.cfg;
        if !(c.relay_ports.0..=c.relay_ports.1).contains(&from.port()) {
            return from;
        }
        let public: Option<IpAddr> = match from.ip() {
            IpAddr::V4(a) if c.relay_ipv4 == Some(a) => c.relay_ipv4_public.map(Into::into),
            IpAddr::V6(a) if c.relay_ipv6 == Some(a) => c.relay_ipv6_public.map(Into::into),
            _ => None,
        };
        SocketAddr::new(public.unwrap_or(from.ip()), from.port())
    }

    async fn bind_relay(&self, ip: IpAddr) -> Option<UdpSocket> {
        let (lo, hi) = self.cfg.relay_ports;
        for _ in 0..BIND_TRIES {
            let mut r = [0u8; 4];
            getrandom::fill(&mut r).ok()?;
            let span = u32::from(hi - lo) + 1;
            let port = lo + (u32::from_le_bytes(r) % span) as u16;
            if let Ok(s) = UdpSocket::bind((ip, port)).await {
                return Some(s);
            }
        }
        None
    }

    fn refresh(
        &self,
        key: &ClientKey,
        m: &Message,
        auth: &Authed,
    ) -> Result<Vec<(u16, Vec<u8>)>, u16> {
        let mut st = self.lock();
        let a = st.allocs.get_mut(key).ok_or(437u16)?;
        if a.username != auth.username {
            return Err(441);
        }
        let life = m.lifetime().unwrap_or(DEFAULT_LIFETIME);
        if life == 0 {
            st.remove(key);
            return Ok(vec![(attr::LIFETIME, 0u32.to_be_bytes().to_vec())]);
        }
        let life = life.clamp(1, MAX_LIFETIME);
        a.expires = Instant::now() + Duration::from_secs(u64::from(life));
        Ok(vec![(attr::LIFETIME, life.to_be_bytes().to_vec())])
    }

    fn peers(&self, m: &Message, v6: bool) -> Result<Vec<SocketAddr>, u16> {
        let mut out = Vec::new();
        for (t, v) in m.attrs.iter().filter(|(t, _)| *t == attr::XOR_PEER_ADDRESS) {
            let one = Message {
                method: 0,
                class: Class::Request,
                txid: m.txid,
                attrs: vec![(*t, v.clone())],
            };
            let a = one.xor_addr(attr::XOR_PEER_ADDRESS).ok_or(400u16)?;
            let canon = SocketAddr::new(a.ip().to_canonical(), a.port());
            if canon.is_ipv6() != v6 {
                return Err(443);
            }
            if !peers::allowed(canon.ip(), self.cfg.allow_private_peers)
                || self.destination(canon).is_none()
            {
                return Err(403);
            }
            out.push(canon);
        }
        if out.is_empty() {
            return Err(400);
        }
        Ok(out)
    }

    fn permission(
        &self,
        key: &ClientKey,
        m: &Message,
        auth: &Authed,
    ) -> Result<Vec<(u16, Vec<u8>)>, u16> {
        let mut st = self.lock();
        let a = st.allocs.get_mut(key).ok_or(437u16)?;
        if a.username != auth.username {
            return Err(441);
        }
        let peers = self.peers(m, a.v6)?;
        let until = Instant::now() + PERMISSION_LIFETIME;
        for p in peers {
            a.perms.insert(p.ip(), until);
        }
        Ok(Vec::new())
    }

    fn bind(
        &self,
        key: &ClientKey,
        m: &Message,
        auth: &Authed,
    ) -> Result<Vec<(u16, Vec<u8>)>, u16> {
        let number = m
            .get(attr::CHANNEL_NUMBER)
            .and_then(|v| v.get(..2))
            .map(|v| u16::from_be_bytes([v[0], v[1]]))
            .filter(|n| (0x4000..=0x7fff).contains(n))
            .ok_or(400u16)?;
        let mut st = self.lock();
        let a = st.allocs.get_mut(key).ok_or(437u16)?;
        if a.username != auth.username {
            return Err(441);
        }
        let peer = *self.peers(m, a.v6)?.first().ok_or(400u16)?;
        let now = Instant::now();
        let clash = a.channels.iter().any(|(n, (p, t))| {
            *t > now && ((*n == number && *p != peer) || (*n != number && *p == peer))
        });
        if clash {
            return Err(400);
        }
        a.channels.insert(number, (peer, now + CHANNEL_LIFETIME));
        a.perms.insert(peer.ip(), now + PERMISSION_LIFETIME);
        Ok(Vec::new())
    }

    /// Charges `len` bytes to the allocation and its credential; whether they may pass.
    fn account(&self, st: &mut State, key: &ClientKey, len: usize, now: Instant) -> bool {
        let Some(a) = st.allocs.get_mut(key) else {
            return false;
        };
        let limits = a.limits;
        if let Some(b) = a.bucket.as_mut()
            && b.take(len as f64, Self::rate(limits), Self::burst(limits), now)
                .is_err()
        {
            return false;
        }
        let username = a.username.clone();
        let cred = st.creds.entry(username).or_default();
        if limits
            .bytes
            .is_some_and(|limit| cred.bytes + len as u64 > limit)
        {
            return false;
        }
        cred.bytes += len as u64;
        true
    }

    async fn forward(&self, key: &ClientKey, peer: SocketAddr, payload: &[u8]) {
        let now = Instant::now();
        let Some(to) = self.destination(peer) else {
            return;
        };
        let relay = {
            let mut st = self.lock();
            let Some(a) = st.allocs.get(key) else {
                return;
            };
            let permitted = a.perms.get(&peer.ip()).is_some_and(|t| *t > now);
            if !permitted
                || a.v6 != peer.is_ipv6()
                || !self.account(&mut st, key, payload.len(), now)
            {
                return;
            }
            st.allocs.get(key).map(|a| a.relay.clone())
        };
        if let Some(relay) = relay {
            let _ = relay.send_to(payload, to).await;
        }
    }

    async fn send_indication(&self, key: &ClientKey, m: &Message) {
        let (Some(peer), Some(data)) = (m.xor_addr(attr::XOR_PEER_ADDRESS), m.get(attr::DATA))
        else {
            return;
        };
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        if peers::allowed_addr(peer, self.cfg.allow_private_peers) {
            self.forward(key, peer, data).await;
        }
    }

    async fn channel_data(&self, key: &ClientKey, raw: &[u8]) {
        if raw.len() < 4 {
            return;
        }
        let number = u16::from_be_bytes([raw[0], raw[1]]);
        let len = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
        let Some(payload) = raw.get(4..4 + len) else {
            return;
        };
        let peer = {
            let st = self.lock();
            st.allocs
                .get(key)
                .and_then(|a| a.channels.get(&number))
                .filter(|(_, t)| *t > Instant::now())
                .map(|(p, _)| *p)
        };
        if let Some(peer) = peer {
            self.forward(key, peer, payload).await;
        }
    }

    /// Wraps data a peer sent to the relayed address for the client, or `None` to drop it.
    fn inbound(&self, key: &ClientKey, from: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
        let now = Instant::now();
        let from = self.public_source(SocketAddr::new(from.ip().to_canonical(), from.port()));
        let mut st = self.lock();
        let a = st.allocs.get(key)?;
        if a.perms.get(&from.ip()).is_none_or(|t| *t <= now) {
            return None;
        }
        let channel = a
            .channels
            .iter()
            .find(|(_, (p, t))| *p == from && *t > now)
            .map(|(n, _)| *n);
        if !self.account(&mut st, key, payload.len(), now) {
            return None;
        }
        Some(match channel {
            Some(n) => {
                let mut d = n.to_be_bytes().to_vec();
                d.extend_from_slice(&u16::try_from(payload.len()).ok()?.to_be_bytes());
                d.extend_from_slice(payload);
                d
            }
            None => {
                let t = txid();
                Builder::new(method::DATA, Class::Indication, &t)
                    .attr(attr::XOR_PEER_ADDRESS, &encode_xor_addr(from, &t))
                    .attr(attr::DATA, payload)
                    .finish()
            }
        })
    }
}

async fn relay_loop(server: Arc<TurnServer>, key: ClientKey, sink: Sink, relay: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 2048];
    let mut failing = Backoff::default();
    loop {
        let (n, from) = match relay.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(_) => {
                failing.wait().await;
                continue;
            }
        };
        failing.reset();
        if let Some(out) = server.inbound(&key, from, &buf[..n]) {
            sink.send(out).await;
        }
    }
}

/// Serves TURN and STUN Binding on a UDP socket until the future is dropped.
pub async fn serve_udp(server: Arc<TurnServer>, socket: UdpSocket) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 2048];
    let mut failing = Backoff::default();
    loop {
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(_) => {
                failing.wait().await;
                continue;
            }
        };
        failing.reset();
        let sink = Sink::Udp(socket.clone(), from);
        server
            .handle(ClientKey::Udp(from), from, &sink, &buf[..n])
            .await;
    }
}

/// Serves TURN over an established stream (TLS with ALPN `stun.turn`) until it ends.
pub async fn serve_stream<S>(server: Arc<TurnServer>, io: S, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(io);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(STREAM_QUEUE);
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if wr.write_all(&stream::frame(msg)).await.is_err() {
                break;
            }
        }
    });
    let key = server.new_stream_key();
    let sink = Sink::Stream(tx);
    while let Ok(Ok(Some(frame))) =
        tokio::time::timeout(STREAM_IDLE, stream::read_frame(&mut rd)).await
    {
        server.handle(key, peer, &sink, &frame).await;
    }
    server.drop_client(&key);
    writer.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TokenSettings, TurnLimits};
    use crate::limits::Limiters;

    fn server(configure: impl FnOnce(&mut crate::config::TurnServer)) -> Arc<TurnServer> {
        let mut cfg = crate::config::TurnServer {
            listen: vec!["198.51.101.5:3478".parse().unwrap()],
            relay_ipv4: Some("198.51.101.5".parse().unwrap()),
            relay_ipv6: Some("2606:4700::5".parse().unwrap()),
            relay_ipv4_public: None,
            relay_ipv6_public: None,
            relay_ports: (40000, 40999),
            realm: "vv".to_owned(),
            max_allocations: 10,
            allocations_per_credential: 1,
            allocations_per_ip: 1,
            allow_private_peers: false,
            tls: false,
        };
        configure(&mut cfg);
        let turn = Turn {
            urls: Vec::new(),
            secret: "s".to_owned(),
            ttl: Duration::from_secs(60),
            bits_per_second: None,
            bytes: None,
            silent: false,
            server: Some(cfg),
        };
        let tokens = crate::api::Tokens::new(&TokenSettings::default(), TurnLimits::default());
        let limiters = Limiters::new(&crate::config::Limits::default(), 10);
        TurnServer::new(
            &turn,
            false,
            &["198.51.101.7".parse().unwrap()],
            Arc::new(tokens.unwrap()),
            Arc::new(limiters),
            Arc::default(),
        )
        .unwrap()
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_switchs_own_addresses_are_reachable_only_on_relay_ports() {
        let t = server(|_| {});
        for own in ["198.51.101.5", "198.51.101.7", "[2606:4700::5]"] {
            for port in [443, 3478, 39999, 41000] {
                assert_eq!(
                    t.destination(addr(&format!("{own}:{port}"))),
                    None,
                    "{own}:{port}"
                );
            }
            let relay = addr(&format!("{own}:40500"));
            assert_eq!(t.destination(relay), Some(relay));
        }
        let elsewhere = addr("198.51.101.99:443");
        assert_eq!(t.destination(elsewhere), Some(elsewhere));
    }

    #[test]
    fn allowing_private_peers_allows_the_hosts_own_ports() {
        let t = server(|c| c.allow_private_peers = true);
        let own = addr("198.51.101.5:443");
        assert_eq!(t.destination(own), Some(own));
    }

    #[test]
    fn a_public_address_maps_to_the_local_one_on_relay_ports_only() {
        let t = server(|c| {
            c.relay_ipv4 = Some("10.0.0.5".parse().unwrap());
            c.relay_ipv4_public = Some("198.51.101.5".parse().unwrap());
        });
        assert_eq!(t.destination(addr("198.51.101.5:3478")), None);
        assert_eq!(
            t.destination(addr("198.51.101.5:40500")),
            Some(addr("10.0.0.5:40500"))
        );
        assert_eq!(
            t.public_source(addr("10.0.0.5:40500")),
            addr("198.51.101.5:40500")
        );
    }

    #[test]
    fn the_nonce_of_the_credential_is_compared_in_full() {
        let t = server(|_| {});
        let nonce = credential_nonce("s", 4_000_000_000);
        assert!(t.credential_nonce_valid(nonce.as_bytes(), 4_000_000_000));
        assert!(!t.credential_nonce_valid(nonce.as_bytes(), 4_000_000_001));
        assert!(!t.credential_nonce_valid(&nonce.as_bytes()[1..], 4_000_000_000));
        assert!(!t.credential_nonce_valid(b"", 4_000_000_000));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let fresh = t.nonce(unix_now(), ip);
        assert!(t.nonce_valid(fresh.as_bytes(), ip));
        assert!(!t.nonce_valid(fresh.as_bytes(), "192.0.2.2".parse().unwrap()));
        assert!(!t.nonce_valid(&fresh.as_bytes()[..fresh.len() - 1], ip));
    }
}
