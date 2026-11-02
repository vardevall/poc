//! In-memory registrations, sessions, presence and event delivery (vv-04 §4.4, §6, §7).
//!
//! Nothing here is persisted or logged (vv-04 §8).

mod stream;

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::time::Instant;
use vardevall_proto::keys::{NetworkPublic, NodePublic, base32};

use crate::config::Limits;
use crate::limits::{Exceeded, TokenBucket};

pub use stream::EventStream;
use stream::StreamGuard;

/// Events buffered for one stream; a reader that falls further behind is disconnected.
const STREAM_QUEUE: usize = 64;
/// How long the generation of an offline member is remembered, so that it keeps increasing.
const GEN_RETENTION: Duration = Duration::from_secs(24 * 3600);
/// Page size of `members` (vv-04 §5.1 requires at least 256).
pub const MEMBERS_PAGE: usize = 256;

/// A registration was refused because a cap is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full;

/// The outcome of a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// The session credential.
    pub session: [u8; 32],
    /// The registration generation.
    pub generation: u64,
}

/// The session credential is unknown or expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionInvalid;

/// Why a stream could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// The session is unknown.
    Session,
    /// The cap on open streams is reached.
    Full,
}

/// Why a message was not forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardError {
    /// The sender's session is unknown.
    Session,
    /// The recipient is not online on this switch.
    NotOnline,
    /// A per-sender or per-recipient limit was hit.
    Limit(Exceeded),
}

/// A member as listed (vv-04 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberInfo {
    /// The node key.
    pub node: NodePublic,
    /// Unix time of registration.
    pub online_since: u64,
    /// Registration generation.
    pub generation: u64,
}

/// Sizes of the tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Registered members.
    pub registrations: usize,
    /// Networks with at least one member.
    pub networks: usize,
    /// Open events streams.
    pub streams: usize,
}

struct OpenStream {
    id: u64,
    tx: mpsc::Sender<Bytes>,
}

struct Member {
    session: [u8; 32],
    generation: u64,
    since: u64,
    stream: Option<OpenStream>,
    offline_at: Option<Instant>,
    next_event: u64,
    forwarded: u64,
    bucket: TokenBucket,
}

#[derive(Default)]
struct Network {
    members: BTreeMap<NodePublic, Member>,
}

struct Inner {
    networks: HashMap<NetworkPublic, Network>,
    sessions: HashMap<[u8; 32], (NetworkPublic, NodePublic)>,
    /// Digest of the operator token each session was admitted with (absent if registration was
    /// open).
    tokens: HashMap<[u8; 32], [u8; 32]>,
    gens: HashMap<(NetworkPublic, NodePublic), (u64, Instant)>,
    registrations: usize,
    streams: usize,
    next_stream: u64,
}

/// The registry of one switch.
pub struct Registry {
    inner: Mutex<Inner>,
    limits: Limits,
    grace: Duration,
}

fn sse(id: u64, event: &str, data: &str) -> Bytes {
    Bytes::from(format!("id: {id}\nevent: {event}\ndata: {data}\n\n"))
}

fn random_session() -> Option<[u8; 32]> {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).ok()?;
    Some(s)
}

impl Member {
    fn push(&mut self, event: &str, data: &str) -> Result<(), TrySendError<Bytes>> {
        let Some(stream) = &self.stream else {
            return Ok(());
        };
        let id = self.next_event;
        self.next_event += 1;
        stream.tx.try_send(sse(id, event, data))
    }
}

impl Inner {
    fn close_stream(&mut self, net: &NetworkPublic, node: &NodePublic) -> bool {
        let Some(m) = self
            .networks
            .get_mut(net)
            .and_then(|n| n.members.get_mut(node))
        else {
            return false;
        };
        let had = m.stream.take().is_some();
        if had {
            self.streams -= 1;
        }
        had
    }

    fn broadcast(
        &mut self,
        net: &NetworkPublic,
        except: &NodePublic,
        event: &str,
        data: &str,
        now: Instant,
        grace: Duration,
    ) {
        let Some(network) = self.networks.get_mut(net) else {
            return;
        };
        let mut slow = Vec::new();
        for (key, m) in network.members.iter_mut() {
            if key == except {
                continue;
            }
            if let Err(TrySendError::Full(_)) = m.push(event, data) {
                slow.push(*key);
            }
        }
        for key in slow {
            if self.close_stream(net, &key)
                && let Some(m) = self
                    .networks
                    .get_mut(net)
                    .and_then(|n| n.members.get_mut(&key))
            {
                m.offline_at = Some(now + grace);
            }
        }
    }

    fn remove_member(
        &mut self,
        net: &NetworkPublic,
        node: &NodePublic,
        now: Instant,
        grace: Duration,
        max_gens: usize,
    ) {
        self.close_stream(net, node);
        let Some(network) = self.networks.get_mut(net) else {
            return;
        };
        let Some(m) = network.members.remove(node) else {
            return;
        };
        let empty = network.members.is_empty();
        self.sessions.remove(&m.session);
        self.tokens.remove(&m.session);
        self.registrations -= 1;
        if empty {
            self.networks.remove(net);
        }
        if self.gens.len() < max_gens || self.gens.contains_key(&(*net, *node)) {
            self.gens
                .insert((*net, *node), (m.generation, now + GEN_RETENTION));
        }
        let data = format!("{{\"node\":\"{node}\",\"gen\":{}}}", m.generation);
        self.broadcast(net, node, "offline", &data, now, grace);
    }
}

impl Registry {
    /// An empty registry with the caps of `limits` and the reconnect `grace` of vv-04 §7.3.
    pub fn new(limits: &Limits, grace: Duration) -> Arc<Self> {
        Arc::new(Registry {
            inner: Mutex::new(Inner {
                networks: HashMap::new(),
                sessions: HashMap::new(),
                tokens: HashMap::new(),
                gens: HashMap::new(),
                registrations: 0,
                streams: 0,
                next_stream: 1,
            }),
            limits: limits.clone(),
            grace,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn max_gens(&self) -> usize {
        self.limits.max_registrations.saturating_mul(4)
    }

    /// Registers `node` in `net`, replacing any earlier registration (vv-04 §4.4 step 5).
    ///
    /// `unix_ms` is the current Unix time in milliseconds. The generation is that time, or one
    /// more than the previous generation of the pair (kept for 24 h after the node goes offline)
    /// if that is not smaller, so generations keep increasing when the clock stalls or steps
    /// back.
    pub fn register(
        &self,
        net: NetworkPublic,
        node: NodePublic,
        now: Instant,
        unix_ms: u64,
    ) -> Result<Registered, Full> {
        let mut inner = self.lock();
        let existing = inner
            .networks
            .get(&net)
            .and_then(|n| n.members.get(&node))
            .map(|m| m.generation);
        if existing.is_none() {
            if inner.registrations >= self.limits.max_registrations {
                return Err(Full);
            }
            match inner.networks.get(&net) {
                None if inner.networks.len() >= self.limits.max_networks => return Err(Full),
                Some(n) if n.members.len() >= self.limits.registrations_per_network => {
                    return Err(Full);
                }
                _ => {}
            }
        }
        let remembered = inner.gens.get(&(net, node)).map_or(0, |(g, _)| *g);
        let generation = unix_ms.max(existing.unwrap_or(0).max(remembered).saturating_add(1));

        if existing.is_some() {
            if let Some(m) = inner
                .networks
                .get_mut(&net)
                .and_then(|n| n.members.get_mut(&node))
            {
                let _ = m.push("replaced", "{}");
                let old = m.session;
                inner.sessions.remove(&old);
                inner.tokens.remove(&old);
            }
            inner.close_stream(&net, &node);
        } else {
            inner.registrations += 1;
        }

        let session = random_session().ok_or(Full)?;
        let member = Member {
            session,
            generation,
            since: unix_ms / 1000,
            stream: None,
            offline_at: Some(now + self.grace),
            next_event: 1,
            forwarded: 0,
            bucket: TokenBucket::full(self.limits.sender_bytes_burst, now),
        };
        inner
            .networks
            .entry(net)
            .or_default()
            .members
            .insert(node, member);
        inner.sessions.insert(session, (net, node));
        let data = format!("{{\"node\":\"{node}\",\"gen\":{generation}}}");
        inner.broadcast(&net, &node, "online", &data, now, self.grace);
        Ok(Registered {
            session,
            generation,
        })
    }

    /// Records the digest of the operator token a session was admitted with.
    pub fn set_token(&self, session: &[u8; 32], token: Option<[u8; 32]>) {
        let mut inner = self.lock();
        if let Some(token) = token.filter(|_| inner.sessions.contains_key(session)) {
            inner.tokens.insert(*session, token);
        }
    }

    /// The digest of the operator token of a session, if it was admitted with one.
    pub fn token(&self, session: &[u8; 32]) -> Option<[u8; 32]> {
        self.lock().tokens.get(session).copied()
    }

    /// The network and node of a session.
    pub fn lookup(
        &self,
        session: &[u8; 32],
    ) -> Result<(NetworkPublic, NodePublic), SessionInvalid> {
        self.lock()
            .sessions
            .get(session)
            .copied()
            .ok_or(SessionInvalid)
    }

    /// Opens the events stream of a session, closing any previous one (vv-04 §7.1, §7.3).
    pub fn open_stream(self: &Arc<Self>, session: &[u8; 32]) -> Result<EventStream, OpenError> {
        let mut inner = self.lock();
        let (net, node) = *inner.sessions.get(session).ok_or(OpenError::Session)?;
        let had = inner
            .networks
            .get(&net)
            .and_then(|n| n.members.get(&node))
            .is_some_and(|m| m.stream.is_some());
        if !had && inner.streams >= self.limits.max_event_streams {
            return Err(OpenError::Full);
        }
        inner.close_stream(&net, &node);
        let id = inner.next_stream;
        inner.next_stream += 1;
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        let m = inner
            .networks
            .get_mut(&net)
            .and_then(|n| n.members.get_mut(&node))
            .ok_or(OpenError::Session)?;
        m.stream = Some(OpenStream { id, tx });
        m.offline_at = None;
        inner.streams += 1;
        Ok(EventStream::new(
            rx,
            StreamGuard::new(self.clone(), net, node, id),
        ))
    }

    fn stream_closed(&self, net: &NetworkPublic, node: &NodePublic, id: u64, now: Instant) {
        let mut inner = self.lock();
        let current = inner
            .networks
            .get(net)
            .and_then(|n| n.members.get(node))
            .and_then(|m| m.stream.as_ref())
            .map(|s| s.id);
        if current != Some(id) {
            return;
        }
        inner.close_stream(net, node);
        if let Some(m) = inner
            .networks
            .get_mut(net)
            .and_then(|n| n.members.get_mut(node))
        {
            m.offline_at = Some(now + self.grace);
        }
    }

    /// Members of the session's network other than the caller, sorted by key, after `after`.
    ///
    /// The flag says whether more members follow (vv-04 §5.1).
    pub fn members(
        &self,
        session: &[u8; 32],
        after: Option<&NodePublic>,
    ) -> Result<(Vec<MemberInfo>, bool), SessionInvalid> {
        let inner = self.lock();
        let (net, me) = inner.sessions.get(session).ok_or(SessionInvalid)?;
        let Some(network) = inner.networks.get(net) else {
            return Ok((Vec::new(), false));
        };
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut out = Vec::new();
        let mut truncated = false;
        for (node, m) in network.members.range((start, Bound::Unbounded)) {
            if node == me {
                continue;
            }
            if out.len() == MEMBERS_PAGE {
                truncated = true;
                break;
            }
            out.push(MemberInfo {
                node: *node,
                online_since: m.since,
                generation: m.generation,
            });
        }
        Ok((out, truncated))
    }

    /// One member of the session's network (vv-04 §5.2); `None` if it is not online here.
    pub fn member(
        &self,
        session: &[u8; 32],
        node: &NodePublic,
    ) -> Result<Option<MemberInfo>, SessionInvalid> {
        let inner = self.lock();
        let (net, _) = inner.sessions.get(session).ok_or(SessionInvalid)?;
        Ok(inner
            .networks
            .get(net)
            .and_then(|n| n.members.get(node))
            .map(|m| MemberInfo {
                node: *node,
                online_since: m.since,
                generation: m.generation,
            }))
    }

    /// Delivers `msg` from the session's node to `to` as a `forward` event (vv-04 §6).
    pub fn forward(
        &self,
        session: &[u8; 32],
        to: &NodePublic,
        msg: &[u8],
        now: Instant,
    ) -> Result<(), ForwardError> {
        let mut inner = self.lock();
        let (net, from) = *inner.sessions.get(session).ok_or(ForwardError::Session)?;
        let limits = &self.limits;
        let network = inner.networks.get_mut(&net).ok_or(ForwardError::Session)?;
        if !network.members.contains_key(to) {
            return Err(ForwardError::NotOnline);
        }
        let sender = network
            .members
            .get_mut(&from)
            .ok_or(ForwardError::Session)?;
        if sender.forwarded.saturating_add(msg.len() as u64) > limits.session_bytes {
            return Err(ForwardError::Limit(Exceeded { retry_after: 3600 }));
        }
        sender
            .bucket
            .take(
                msg.len() as f64,
                limits.sender_bytes_per_second,
                limits.sender_bytes_burst,
                now,
            )
            .map_err(ForwardError::Limit)?;
        sender.forwarded += msg.len() as u64;
        let data = format!(
            "{{\"from\":\"{from}\",\"msg\":\"{}\"}}",
            base32::encode(msg)
        );
        let target = network.members.get_mut(to).ok_or(ForwardError::NotOnline)?;
        if target.stream.is_none() {
            return Err(ForwardError::NotOnline);
        }
        match target.push("forward", &data) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(ForwardError::Limit(Exceeded { retry_after: 1 })),
            Err(TrySendError::Closed(_)) => Err(ForwardError::NotOnline),
        }
    }

    /// Takes the session's node offline at once (vv-04 §7.3); `false` if the session is unknown.
    pub fn logout(&self, session: &[u8; 32], now: Instant) -> bool {
        let mut inner = self.lock();
        let Some((net, node)) = inner.sessions.get(session).copied() else {
            return false;
        };
        inner.remove_member(&net, &node, now, self.grace, self.max_gens());
        true
    }

    /// Takes members whose grace period ended offline and forgets old generations.
    pub fn sweep(&self, now: Instant) {
        let mut inner = self.lock();
        let due: Vec<(NetworkPublic, NodePublic)> = inner
            .networks
            .iter()
            .flat_map(|(net, n)| {
                n.members
                    .iter()
                    .filter(|(_, m)| m.offline_at.is_some_and(|t| t <= now))
                    .map(move |(node, _)| (*net, *node))
            })
            .collect();
        for (net, node) in due {
            inner.remove_member(&net, &node, now, self.grace, self.max_gens());
        }
        inner.gens.retain(|_, (_, expires)| *expires > now);
    }

    /// The sizes of the tables.
    pub fn stats(&self) -> Stats {
        let inner = self.lock();
        Stats {
            registrations: inner.registrations,
            networks: inner.networks.len(),
            streams: inner.streams,
        }
    }
}

#[cfg(test)]
mod tests;
