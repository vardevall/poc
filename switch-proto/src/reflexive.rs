//! Server-reflexive gathering and mapping classification (vv-05 §3.1, §3.2).
//!
//! Sans-IO: the caller sends the [`Transmit`]s from the interface socket, feeds responses to
//! [`Reflexive::handle`] and calls [`Reflexive::handle_timeout`] at [`Reflexive::poll_timeout`];
//! time and transaction ids are passed in.
//! When to gather after a local change is for [`vardevall_proto::route::LocalChanges`]; a round
//! covers the address families it is told to.
//!
//! Volume: a family's result stays fresh while the socket keeps sending to that
//! family ([`Reflexive::sent`]); a gap longer than [`STALE_AFTER`] ages it, and
//! [`Reflexive::refresh`] asks only the aged families that answered last time. A family that did
//! not answer is asked again only on its own [`RETRY_BACKOFF`]. A mapping can also move under a
//! socket that keeps sending, when the path beneath it changes unseen (a host's routes in a
//! container); a direct route that keeps failing casts doubt on it ([`Reflexive::doubt`]).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use rand_core::CryptoRng;
use vardevall_proto::route::Families;
use vardevall_proto::time::Instant;

use crate::stun::{Builder, Class, Message, attr, method, new_txid, verify_integrity};

/// Time without any response after which a family is `udp-blocked` (vv-05 §3.2).
pub const BLOCKED_AFTER: Duration = Duration::from_secs(3);
/// Silence after which a family's result is out of date: no send to the family for this long
/// since the result, or between two sends.
pub const STALE_AFTER: Duration = Duration::from_secs(20);
/// Delays of the retransmissions of an unanswered Binding request.
const RETRANSMIT: [Duration; 2] = [Duration::from_millis(500), Duration::from_millis(1500)];
/// Delays before the successive rounds that retry a `udp-blocked` result, `STUN_RETRY_INITIAL`
/// doubling up to `STUN_RETRY_MAX` (vv-05 §3.2); the last repeats.
pub const RETRY_BACKOFF: [Duration; 6] = [
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(240),
    Duration::from_secs(480),
    Duration::from_secs(900),
];
/// Delays between the rounds that re-ask a doubted mapping, from the newest result: the step
/// grows while doubted rounds confirm the mapping and starts over when one changes it;
/// the last repeats.
pub const DOUBT_BACKOFF: [Duration; 4] = [
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(300),
];
/// Servers asked per address family; two suffice to compare mappings.
const PER_FAMILY: usize = 3;

/// A datagram to send from the interface socket.
pub type Transmit = (SocketAddr, Vec<u8>);

/// The short-term credential a server wants (RFC 8489 §9.1, vv-04 §4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    /// The USERNAME of requests.
    pub username: String,
    /// The key of MESSAGE-INTEGRITY.
    pub key: Vec<u8>,
    /// When the server stops accepting the credential; `None` if it never does.
    pub until: Option<Instant>,
}

impl Auth {
    /// Whether the server still accepts the credential at `now`.
    pub fn current(&self, now: Instant) -> bool {
        self.until.is_none_or(|t| now < t)
    }
}

/// A STUN server and the credential it is queried with, if it needs one. A server that needs a
/// credential the node does not hold is not listed: silence from it says nothing about UDP
/// (vv-04 §4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// Its address.
    pub addr: SocketAddr,
    /// The credential of its requests.
    pub auth: Option<Auth>,
}

impl Server {
    /// A server that answers without a credential.
    pub fn open(addr: SocketAddr) -> Self {
        Server { addr, auth: None }
    }
}

/// The classification of one address family (vv-05 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mapping {
    /// The mapping is reusable; the address is the `punch` candidate.
    Punchable(SocketAddr),
    /// Two servers saw different ports: punching cannot succeed.
    Symmetric,
    /// No server answered.
    Blocked,
}

impl Mapping {
    /// The `punch` candidate, if punching can succeed.
    pub fn punch(&self) -> Option<SocketAddr> {
        match self {
            Mapping::Punchable(a) => Some(*a),
            _ => None,
        }
    }
}

/// The outcome of gathering. A family without any result is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// IPv6.
    pub v6: Option<Mapping>,
    /// IPv4.
    pub v4: Option<Mapping>,
    /// When the newest round ended.
    pub at: Instant,
}

impl Snapshot {
    /// The families that were asked, IPv6 first.
    pub fn families(&self) -> impl Iterator<Item = Mapping> {
        [self.v6, self.v4].into_iter().flatten()
    }

    /// Whether punching cannot succeed in any family that was asked, and at least one was.
    pub fn unpunchable(&self) -> bool {
        let mut any = false;
        for m in self.families() {
            if m.punch().is_some() {
                return false;
            }
            any = true;
        }
        any
    }
}

struct Query {
    server: SocketAddr,
    request: Vec<u8>,
    key: Option<Vec<u8>>,
    answer: Option<SocketAddr>,
}

/// How recent a family's result is.
#[derive(Debug, Clone, Copy)]
struct Age {
    /// The result, or the latest send to the family since.
    at: Instant,
    /// A gap longer than [`STALE_AFTER`] has passed since the result.
    gapped: bool,
}

impl Age {
    fn new(at: Instant) -> Self {
        Age { at, gapped: false }
    }

    fn sent(&mut self, now: Instant) {
        if now.saturating_duration_since(self.at) > STALE_AFTER {
            self.gapped = true;
        }
        if now > self.at {
            self.at = now;
        }
    }

    fn stale(&self, now: Instant) -> bool {
        self.gapped || now.saturating_duration_since(self.at) > STALE_AFTER
    }
}

struct Round {
    started: Instant,
    families: Families,
    queries: HashMap<[u8; 12], Query>,
    retransmitted: usize,
    /// Started by [`Reflexive::doubt`].
    doubted: bool,
}

/// A doubt on the mapping, from the first direct route that failed until none fails.
#[derive(Debug, Clone, Copy)]
struct Doubt {
    /// The newest result, or the latest time a doubted round was due.
    since: Instant,
    /// The index into [`DOUBT_BACKOFF`].
    step: usize,
}

impl Doubt {
    fn due(&self) -> Instant {
        self.since + DOUBT_BACKOFF[self.step]
    }
}

/// Gathers `punch` candidates.
#[derive(Default)]
pub struct Reflexive {
    servers: Vec<Server>,
    round: Option<Round>,
    done: Option<Snapshot>,
    v6_age: Option<Age>,
    v4_age: Option<Age>,
    reported: bool,
    /// When to retry a `udp-blocked` result.
    retry_at: Option<Instant>,
    /// Consecutive finished rounds that left a family blocked.
    failures: usize,
    /// The delay of the retry that just started, until [`Reflexive::take_retry`].
    retried: Option<Duration>,
    doubt: Option<Doubt>,
}

impl Reflexive {
    /// Replaces the STUN servers; returns whether the addresses queried, or whether each needs
    /// a credential, changed. A changed credential for the same server is not a change.
    pub fn set_servers(&mut self, servers: Vec<Server>) -> bool {
        let key = |v: &[Server]| -> Vec<(SocketAddr, bool)> {
            v.iter().map(|s| (s.addr, s.auth.is_some())).collect()
        };
        let changed = key(&self.servers) != key(&servers);
        self.servers = servers;
        if changed {
            self.failures = 0;
            self.retry_at = None;
        }
        changed
    }

    /// Whether any STUN server is known.
    pub fn has_servers(&self) -> bool {
        !self.servers.is_empty()
    }

    /// The newest finished result.
    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.done.as_ref()
    }

    /// Whether a round is running.
    pub fn busy(&self) -> bool {
        self.round.is_some()
    }

    /// Records a datagram sent from the interface socket to `to`, which keeps the mapping of
    /// its family alive.
    pub fn sent(&mut self, now: Instant, to: SocketAddr) {
        let age = if to.is_ipv6() {
            &mut self.v6_age
        } else {
            &mut self.v4_age
        };
        if let Some(age) = age {
            age.sent(now);
        }
    }

    /// Whether there is no result yet, or a family that answered last time is out of date.
    pub fn stale(&self, now: Instant) -> bool {
        self.done.is_none() || !self.due(now).is_empty()
    }

    /// The families that answered last time and whose result is out of date.
    fn due(&self, now: Instant) -> Families {
        let Some(s) = self.done else {
            return Families::NONE;
        };
        let due = |m: Option<Mapping>, age: Option<Age>| {
            m.is_some_and(|m| m != Mapping::Blocked) && age.is_none_or(|a| a.stale(now))
        };
        Families {
            v6: due(s.v6, self.v6_age),
            v4: due(s.v4, self.v4_age),
        }
    }

    /// Abandons a running round and starts the backoff of retries over, for a local change
    /// (vv-05 §3.2); the results stay until a round replaces them. A doubt goes with it.
    pub fn reset(&mut self) {
        self.cancel();
        self.retry_at = None;
        self.failures = 0;
        self.doubt = None;
    }

    /// A direct route over `families` keeps failing, so their mappings may have moved although
    /// the socket kept sending. Once [`Reflexive::next_doubt`] has come, the families
    /// among them that answered last time are asked again and the first requests returned; a
    /// family that did not is left to its retry backoff. The caller calls this again at
    /// [`Reflexive::next_doubt`] while a route fails, and [`Reflexive::trust`] once none does.
    pub fn doubt(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        families: Families,
    ) -> Vec<Transmit> {
        let Some(done) = self.done else {
            return Vec::new();
        };
        let doubt = self.doubt.get_or_insert(Doubt {
            since: done.at,
            step: 0,
        });
        if now < doubt.due() {
            return Vec::new();
        }
        doubt.since = now;
        if self.busy() {
            return Vec::new();
        }
        let answered = self.answered();
        let families = Families {
            v4: families.v4 && answered.v4,
            v6: families.v6 && answered.v6,
        };
        if families.is_empty() {
            return Vec::new();
        }
        let sends = self.begin(now, rng, families);
        if let Some(r) = self.round.as_mut() {
            r.doubted = true;
        }
        sends
    }

    /// When a doubt standing since [`Reflexive::doubt`] may ask again.
    pub fn next_doubt(&self) -> Option<Instant> {
        self.doubt.map(|d| d.due())
    }

    /// No direct route fails any more: the doubt and its backoff end.
    pub fn trust(&mut self) {
        self.doubt = None;
    }

    /// Abandons a running round without a result.
    pub fn cancel(&mut self) {
        self.round = None;
        self.reported = true;
    }

    /// The delay of the retry that started since the last call.
    pub fn take_retry(&mut self) -> Option<Duration> {
        self.retried.take()
    }

    /// Starts a round for both families unless one is running, and returns the first requests.
    pub fn start(&mut self, now: Instant, rng: &mut impl CryptoRng) -> Vec<Transmit> {
        if self.busy() {
            return Vec::new();
        }
        self.begin(now, rng, Families::BOTH)
    }

    /// Starts a round for the families whose result is out of date, unless one is running, and
    /// returns the first requests: both families if there is no result yet, otherwise only those
    /// that answered last time. A family that did not is left to its retry backoff.
    pub fn refresh(&mut self, now: Instant, rng: &mut impl CryptoRng) -> Vec<Transmit> {
        if self.busy() {
            return Vec::new();
        }
        let families = if self.done.is_none() {
            Families::BOTH
        } else {
            self.due(now)
        };
        if families.is_empty() {
            return Vec::new();
        }
        self.begin(now, rng, families)
    }

    /// Starts a round for `families`, abandoning a running one, and returns the first requests.
    pub fn restart(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        families: Families,
    ) -> Vec<Transmit> {
        self.round = None;
        self.begin(now, rng, families)
    }

    fn begin(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        families: Families,
    ) -> Vec<Transmit> {
        let blocked = self.blocked();
        let retry = (families.v4 && blocked.v4) || (families.v6 && blocked.v6);
        if retry {
            self.retry_at = None;
        }
        let mut queries = HashMap::new();
        let mut v6 = 0;
        let mut v4 = 0;
        for server in &self.servers {
            if !families.contains(&server.addr) {
                continue;
            }
            if server.auth.as_ref().is_some_and(|a| !a.current(now)) {
                continue;
            }
            let count = if server.addr.is_ipv6() {
                &mut v6
            } else {
                &mut v4
            };
            if *count == PER_FAMILY {
                continue;
            }
            *count += 1;
            let txid = new_txid(rng);
            let builder = Builder::new(method::BINDING, Class::Request, &txid);
            let (request, key) = match &server.auth {
                Some(a) => (
                    builder
                        .attr(attr::USERNAME, a.username.as_bytes())
                        .finish_with_integrity(&a.key),
                    Some(a.key.clone()),
                ),
                None => (builder.finish(), None),
            };
            queries.insert(
                txid,
                Query {
                    server: server.addr,
                    request,
                    key,
                    answer: None,
                },
            );
        }
        if queries.is_empty() {
            return Vec::new();
        }
        let sends = queries
            .values()
            .map(|q| (q.server, q.request.clone()))
            .collect();
        self.reported = false;
        self.round = Some(Round {
            started: now,
            families,
            queries,
            retransmitted: 0,
            doubted: false,
        });
        sends
    }

    /// Consumes a response to one of the requests, `raw` being its bytes; returns whether it was
    /// one. A response to an authenticated request must carry a valid MESSAGE-INTEGRITY.
    pub fn handle(&mut self, now: Instant, from: SocketAddr, msg: &Message, raw: &[u8]) -> bool {
        let Some(round) = self.round.as_mut() else {
            return false;
        };
        if msg.method != method::BINDING || msg.class != Class::Success {
            return false;
        }
        let Some(q) = round.queries.get_mut(&msg.txid) else {
            return false;
        };
        if q.server != from {
            return false;
        }
        if q.key.as_ref().is_some_and(|k| !verify_integrity(raw, k)) {
            return false;
        }
        if let Some(a) = msg.xor_addr(attr::XOR_MAPPED_ADDRESS) {
            q.answer = Some(a);
        }
        if round.queries.values().all(|q| q.answer.is_some()) {
            self.finish(now);
        }
        true
    }

    /// When [`Reflexive::handle_timeout`] must run next.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let round = self.round.as_ref().map(|r| {
            let next = RETRANSMIT
                .get(r.retransmitted)
                .copied()
                .unwrap_or(BLOCKED_AFTER);
            r.started + next
        });
        let retry = self.round.is_none().then_some(self.retry_at).flatten();
        [round, retry].into_iter().flatten().min()
    }

    /// Starts the round after a backoff, retransmits unanswered requests and ends the round
    /// after [`BLOCKED_AFTER`].
    pub fn handle_timeout(&mut self, now: Instant, rng: &mut impl CryptoRng) -> Vec<Transmit> {
        if self.round.is_none() && self.retry_at.is_some_and(|t| now >= t) {
            let i = self.failures.saturating_sub(1).min(RETRY_BACKOFF.len() - 1);
            self.retried = Some(RETRY_BACKOFF[i]);
            let blocked = self.blocked();
            return self.begin(now, rng, blocked);
        }
        let Some(r) = self.round.as_mut() else {
            return Vec::new();
        };
        if now >= r.started + BLOCKED_AFTER {
            self.finish(now);
            return Vec::new();
        }
        let due = RETRANSMIT.get(r.retransmitted).copied();
        if due.is_none_or(|d| now < r.started + d) {
            return Vec::new();
        }
        r.retransmitted += 1;
        r.queries
            .values()
            .filter(|q| q.answer.is_none())
            .map(|q| (q.server, q.request.clone()))
            .collect()
    }

    /// The result of a round that ended since the last call.
    pub fn take_result(&mut self) -> Option<Snapshot> {
        if self.reported {
            return None;
        }
        self.reported = true;
        self.done
    }

    fn finish(&mut self, now: Instant) {
        let Some(round) = self.round.take() else {
            return;
        };
        let classify = |v6: bool| -> Option<Mapping> {
            let asked: Vec<&Query> = round
                .queries
                .values()
                .filter(|q| q.server.is_ipv6() == v6)
                .collect();
            if asked.is_empty() {
                return None;
            }
            let mapped: Vec<(SocketAddr, SocketAddr)> = asked
                .iter()
                .filter_map(|q| q.answer.map(|a| (q.server, a)))
                .collect();
            let Some(&(_, first)) = mapped.first() else {
                return Some(Mapping::Blocked);
            };
            let distinct_ports = mapped
                .iter()
                .any(|(s, a)| *s != mapped[0].0 && a.port() != first.port());
            Some(if distinct_ports {
                Mapping::Symmetric
            } else {
                Mapping::Punchable(first)
            })
        };
        let kept = self.done;
        let pick = |asked: bool, new: Option<Mapping>, old: Option<Mapping>| {
            if asked { new } else { old }
        };
        let done = Snapshot {
            v6: pick(round.families.v6, classify(true), kept.and_then(|s| s.v6)),
            v4: pick(round.families.v4, classify(false), kept.and_then(|s| s.v4)),
            at: now,
        };
        self.done = Some(done);
        if let Some(d) = self.doubt.as_mut() {
            let moved = (round.families.v6 && done.v6 != kept.and_then(|s| s.v6))
                || (round.families.v4 && done.v4 != kept.and_then(|s| s.v4));
            if moved {
                d.step = 0;
            } else if round.doubted {
                d.step = (d.step + 1).min(DOUBT_BACKOFF.len() - 1);
            }
            d.since = now;
        }
        for (m, age, asked) in [
            (done.v6, &mut self.v6_age, round.families.v6),
            (done.v4, &mut self.v4_age, round.families.v4),
        ] {
            if asked && m.is_some() {
                *age = Some(Age::new(now));
            }
        }
        self.reported = false;
        let blocked = self.blocked();
        let asked_blocked = (round.families.v4 && blocked.v4) || (round.families.v6 && blocked.v6);
        if blocked.is_empty() || asked_blocked || self.retry_at.is_none() {
            self.schedule_retry(now);
        }
    }

    /// The families whose latest result is an answer: `punchable` or `symmetric`.
    fn answered(&self) -> Families {
        let answered = |m: Option<Mapping>| m.is_some_and(|m| m != Mapping::Blocked);
        self.done.map_or(Families::NONE, |s| Families {
            v4: answered(s.v4),
            v6: answered(s.v6),
        })
    }

    /// The families whose latest result is `udp-blocked`.
    fn blocked(&self) -> Families {
        let is_blocked = |m: Option<Mapping>| m == Some(Mapping::Blocked);
        self.done.map_or(Families::NONE, |s| Families {
            v4: is_blocked(s.v4),
            v6: is_blocked(s.v6),
        })
    }

    /// Plans the next round while a family stays `udp-blocked`; otherwise resets the backoff.
    fn schedule_retry(&mut self, now: Instant) {
        let blocked = self.blocked();
        let any = self.servers.iter().any(|s| blocked.contains(&s.addr));
        if blocked.is_empty() || !any {
            self.failures = 0;
            self.retry_at = None;
            return;
        }
        let i = self.failures.min(RETRY_BACKOFF.len() - 1);
        self.failures += 1;
        self.retry_at = Some(now + RETRY_BACKOFF[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vardevall_proto::sim::SimRng;

    use crate::stun::encode_xor_addr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn open(list: &[&str]) -> Vec<Server> {
        list.iter().map(|a| Server::open(addr(a))).collect()
    }

    /// The response to `request`, signed with `key` if given.
    fn reply(request: &[u8], mapped: SocketAddr, key: Option<&[u8]>) -> Vec<u8> {
        let req = Message::parse(request).unwrap();
        let b = Builder::new(method::BINDING, Class::Success, &req.txid).attr(
            attr::XOR_MAPPED_ADDRESS,
            &encode_xor_addr(mapped, &req.txid),
        );
        match key {
            Some(k) => b.finish_with_integrity(k),
            None => b.finish(),
        }
    }

    fn feed(r: &mut Reflexive, now: Instant, from: SocketAddr, raw: &[u8]) -> bool {
        r.handle(now, from, &Message::parse(raw).unwrap(), raw)
    }

    fn answer_all(r: &mut Reflexive, now: Instant, sends: &[Transmit], mapped: &[(&str, &str)]) {
        for (to, req) in sends {
            let m = mapped.iter().find(|(s, _)| addr(s) == *to).unwrap().1;
            assert!(feed(r, now, *to, &reply(req, addr(m), None)));
        }
    }

    const V4: (&str, &str) = ("192.0.2.1:3478", "198.51.100.7:5000");

    /// A reflexive gathering for IPv4 whose first round has answered `V4` at `t0`.
    fn answered_at(t0: Instant, rng: &mut SimRng) -> Reflexive {
        let mut r = Reflexive::default();
        r.set_servers(open(&[V4.0]));
        let sends = r.start(t0, rng);
        answer_all(&mut r, t0, &sends, &[V4]);
        r.take_result().unwrap();
        r
    }

    #[test]
    fn a_doubt_asks_again_on_its_backoff_while_the_answer_stays() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = answered_at(t0, &mut rng);
        r.sent(t0 + Duration::from_secs(10), addr("203.0.113.9:4455"));
        assert!(
            r.doubt(t0 + Duration::from_secs(10), &mut rng, Families::V4)
                .is_empty()
        );
        let mut at = t0 + DOUBT_BACKOFF[0];
        assert_eq!(r.next_doubt(), Some(at));
        for step in 1..DOUBT_BACKOFF.len() + 1 {
            let sends = r.doubt(at, &mut rng, Families::V4);
            assert_eq!(sends.len(), 1);
            answer_all(&mut r, at, &sends, &[V4]);
            assert!(r.take_result().is_some());
            at = at + DOUBT_BACKOFF[step.min(DOUBT_BACKOFF.len() - 1)];
            assert_eq!(r.next_doubt(), Some(at));
        }
        r.trust();
        assert_eq!(r.next_doubt(), None);
    }

    #[test]
    fn a_doubted_round_that_finds_the_mapping_moved_starts_the_backoff_over() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = answered_at(t0, &mut rng);
        let t1 = t0 + DOUBT_BACKOFF[0];
        let sends = r.doubt(t1, &mut rng, Families::V4);
        answer_all(&mut r, t1, &sends, &[V4]);
        let t2 = t1 + DOUBT_BACKOFF[1];
        let sends = r.doubt(t2, &mut rng, Families::V4);
        answer_all(&mut r, t2, &sends, &[(V4.0, "192.0.2.200:5000")]);
        assert_eq!(
            r.take_result().unwrap().v4,
            Some(Mapping::Punchable(addr("192.0.2.200:5000")))
        );
        assert_eq!(r.next_doubt(), Some(t2 + DOUBT_BACKOFF[0]));
    }

    #[test]
    fn a_doubt_leaves_families_without_an_answer_to_their_retry() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = answered_at(t0, &mut rng);
        r.set_servers(open(&[V4.0, "[2001:db8::1]:3478"]));
        let t1 = t0 + DOUBT_BACKOFF[0];
        assert!(r.doubt(t1, &mut rng, Families::V6).is_empty());
        assert!(!r.busy());
        assert_eq!(r.next_doubt(), Some(t1 + DOUBT_BACKOFF[0]));
    }

    #[test]
    fn a_doubt_due_while_a_round_runs_waits_for_the_next_turn() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = answered_at(t0, &mut rng);
        let t1 = t0 + DOUBT_BACKOFF[0];
        assert_eq!(r.restart(t1, &mut rng, Families::V4).len(), 1);
        assert!(r.doubt(t1, &mut rng, Families::V4).is_empty());
        assert_eq!(r.next_doubt(), Some(t1 + DOUBT_BACKOFF[0]));
    }

    #[test]
    fn a_local_change_ends_the_doubt() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = answered_at(t0, &mut rng);
        r.doubt(t0, &mut rng, Families::V4);
        assert!(r.next_doubt().is_some());
        r.reset();
        assert_eq!(r.next_doubt(), None);
    }

    #[test]
    fn one_server_per_family_is_assumed_punchable() {
        let mut rng = SimRng::new(1);
        let now = Instant::from_millis(1000);
        let mut r = Reflexive::default();
        r.set_servers(open(&["[2001:db8::1]:3478", "192.0.2.1:3478"]));
        let sends = r.start(now, &mut rng);
        assert_eq!(sends.len(), 2);
        answer_all(
            &mut r,
            now,
            &sends,
            &[
                ("[2001:db8::1]:3478", "[2001:db8:5::7]:4000"),
                ("192.0.2.1:3478", "198.51.100.7:5000"),
            ],
        );
        let s = r.take_result().unwrap();
        assert_eq!(s.v6, Some(Mapping::Punchable(addr("[2001:db8:5::7]:4000"))));
        assert_eq!(s.v4, Some(Mapping::Punchable(addr("198.51.100.7:5000"))));
        assert!(!s.unpunchable());
        assert!(r.take_result().is_none());
    }

    #[test]
    fn different_ports_from_two_servers_mean_symmetric() {
        let mut rng = SimRng::new(1);
        let now = Instant::from_millis(1000);
        let mut r = Reflexive::default();
        r.set_servers(open(&["192.0.2.1:3478", "192.0.2.2:3478"]));
        let sends = r.start(now, &mut rng);
        answer_all(
            &mut r,
            now,
            &sends,
            &[
                ("192.0.2.1:3478", "198.51.100.7:5000"),
                ("192.0.2.2:3478", "198.51.100.7:5001"),
            ],
        );
        let s = r.take_result().unwrap();
        assert_eq!(s.v4, Some(Mapping::Symmetric));
        assert_eq!(s.v6, None);
        assert!(s.unpunchable());
    }

    #[test]
    fn equal_ports_from_two_servers_are_punchable() {
        let mut rng = SimRng::new(1);
        let now = Instant::from_millis(1000);
        let mut r = Reflexive::default();
        r.set_servers(open(&["192.0.2.1:3478", "192.0.2.2:3478"]));
        let sends = r.start(now, &mut rng);
        answer_all(
            &mut r,
            now,
            &sends,
            &[
                ("192.0.2.1:3478", "198.51.100.7:5000"),
                ("192.0.2.2:3478", "198.51.100.7:5000"),
            ],
        );
        assert_eq!(
            r.take_result().unwrap().v4,
            Some(Mapping::Punchable(addr("198.51.100.7:5000")))
        );
    }

    #[test]
    fn silence_means_blocked_after_three_seconds_with_retransmissions() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = Reflexive::default();
        r.set_servers(open(&["192.0.2.1:3478"]));
        assert_eq!(r.start(t0, &mut rng).len(), 1);
        assert!(
            r.handle_timeout(t0 + Duration::from_millis(100), &mut rng)
                .is_empty()
        );
        assert_eq!(
            r.handle_timeout(t0 + Duration::from_millis(500), &mut rng)
                .len(),
            1
        );
        assert_eq!(
            r.handle_timeout(t0 + Duration::from_millis(1500), &mut rng)
                .len(),
            1
        );
        assert!(r.take_result().is_none());
        assert_eq!(r.poll_timeout(), Some(t0 + BLOCKED_AFTER));
        assert!(r.handle_timeout(t0 + BLOCKED_AFTER, &mut rng).is_empty());
        let s = r.take_result().unwrap();
        assert_eq!(s.v4, Some(Mapping::Blocked));
        assert!(s.unpunchable());
        assert!(!r.stale(t0 + BLOCKED_AFTER + STALE_AFTER + Duration::from_secs(1)));
    }

    #[test]
    fn partial_answers_use_what_arrived() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = Reflexive::default();
        r.set_servers(open(&["192.0.2.1:3478", "192.0.2.2:3478"]));
        let sends = r.start(t0, &mut rng);
        let first = &sends[0];
        feed(
            &mut r,
            t0,
            first.0,
            &reply(&first.1, addr("198.51.100.7:5000"), None),
        );
        assert!(r.take_result().is_none());
        r.handle_timeout(t0 + BLOCKED_AFTER, &mut rng);
        assert_eq!(
            r.take_result().unwrap().v4,
            Some(Mapping::Punchable(addr("198.51.100.7:5000")))
        );
    }

    #[test]
    fn foreign_and_forged_responses_are_ignored() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = Reflexive::default();
        r.set_servers(open(&["192.0.2.1:3478"]));
        let sends = r.start(t0, &mut rng);
        let m = reply(&sends[0].1, addr("198.51.100.7:5000"), None);
        assert!(!feed(&mut r, t0, addr("192.0.2.9:3478"), &m));
        let other = reply(
            &Builder::new(method::BINDING, Class::Request, &[9; 12]).finish(),
            addr("198.51.100.7:5000"),
            None,
        );
        assert!(!feed(&mut r, t0, addr("192.0.2.1:3478"), &other));
        assert!(r.take_result().is_none());
    }

    /// Runs one round with no answer and returns when it ended.
    fn blocked_round(r: &mut Reflexive, rng: &mut SimRng, t: Instant) -> Instant {
        let end = t + BLOCKED_AFTER;
        assert!(!r.start(t, rng).is_empty());
        r.handle_timeout(end, rng);
        assert_eq!(r.take_result().unwrap().v4, Some(Mapping::Blocked));
        end
    }

    #[test]
    fn a_blocked_result_is_retried_with_growing_backoff() {
        let mut rng = SimRng::new(1);
        let mut r = Reflexive::default();
        r.set_servers(open(&["192.0.2.1:3478"]));
        let mut end = blocked_round(&mut r, &mut rng, Instant::from_millis(1000));
        for delay in [30, 60, 120, 240, 480, 900, 900] {
            let at = end + Duration::from_secs(delay);
            assert_eq!(r.poll_timeout(), Some(at));
            assert!(
                r.handle_timeout(
                    Instant::from_duration(at.as_duration() - Duration::from_millis(1)),
                    &mut rng,
                )
                .is_empty()
            );
            assert!(!r.busy());
            assert_eq!(r.handle_timeout(at, &mut rng).len(), 1);
            assert_eq!(r.take_retry(), Some(Duration::from_secs(delay)));
            assert!(r.busy());
            end = at + BLOCKED_AFTER;
            r.handle_timeout(end, &mut rng);
            assert_eq!(r.take_result().unwrap().v4, Some(Mapping::Blocked));
        }
    }

    #[test]
    fn success_resets_the_backoff() {
        let mut rng = SimRng::new(1);
        let mut r = Reflexive::default();
        r.set_servers(open(&["192.0.2.1:3478"]));
        let t0 = Instant::from_millis(1000);
        let end = blocked_round(&mut r, &mut rng, t0);
        let at = end + Duration::from_secs(30);
        let sends = r.handle_timeout(at, &mut rng);
        answer_all(
            &mut r,
            at,
            &sends,
            &[("192.0.2.1:3478", "198.51.100.7:5000")],
        );
        assert!(r.take_result().unwrap().v4.unwrap().punch().is_some());
        assert_eq!(r.poll_timeout(), None);
        let end = blocked_round(&mut r, &mut rng, at + Duration::from_secs(100));
        assert_eq!(r.poll_timeout(), Some(end + Duration::from_secs(30)));
    }

    #[test]
    fn a_running_round_prevents_a_retry() {
        let mut rng = SimRng::new(1);
        let mut r = Reflexive::default();
        r.set_servers(open(&["192.0.2.1:3478"]));
        let t0 = Instant::from_millis(1000);
        let end = blocked_round(&mut r, &mut rng, t0);
        let sends = r.start(end + Duration::from_secs(1), &mut rng);
        assert_eq!(sends.len(), 1);
        assert_eq!(r.poll_timeout(), Some(end + Duration::from_millis(1500)));
        assert!(
            r.handle_timeout(end + Duration::from_secs(5), &mut rng)
                .len()
                <= 1
        );
        assert_eq!(r.take_retry(), None);
    }

    #[test]
    fn a_local_change_or_new_servers_reset_the_backoff() {
        let mut rng = SimRng::new(1);
        let mut r = Reflexive::default();
        r.set_servers(open(&["192.0.2.1:3478"]));
        let t0 = Instant::from_millis(1000);
        let end = blocked_round(&mut r, &mut rng, t0);
        assert!(r.poll_timeout().is_some());
        r.reset();
        assert_eq!(r.poll_timeout(), None);
        let end2 = blocked_round(&mut r, &mut rng, end);
        assert_eq!(r.poll_timeout(), Some(end2 + Duration::from_secs(30)));
        assert!(r.set_servers(open(&["192.0.2.2:3478"])));
        assert_eq!(r.poll_timeout(), None);
    }

    #[test]
    fn a_round_covers_only_the_families_it_is_told_to() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = Reflexive::default();
        r.set_servers(open(&["[2001:db8::1]:3478", "192.0.2.1:3478"]));
        let sends = r.start(t0, &mut rng);
        answer_all(
            &mut r,
            t0,
            &sends,
            &[
                ("[2001:db8::1]:3478", "[2001:db8:5::7]:4000"),
                ("192.0.2.1:3478", "198.51.100.7:5000"),
            ],
        );
        r.take_result();
        let t1 = t0 + Duration::from_secs(5);
        let sends = r.restart(t1, &mut rng, Families::V4);
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].0, addr("192.0.2.1:3478"));
        answer_all(
            &mut r,
            t1,
            &sends,
            &[("192.0.2.1:3478", "198.51.100.8:6000")],
        );
        let s = r.take_result().unwrap();
        assert_eq!(s.v6, Some(Mapping::Punchable(addr("[2001:db8:5::7]:4000"))));
        assert_eq!(s.v4, Some(Mapping::Punchable(addr("198.51.100.8:6000"))));
    }

    #[test]
    fn a_round_with_no_server_of_its_families_does_not_start() {
        let mut rng = SimRng::new(1);
        let mut r = Reflexive::default();
        r.set_servers(open(&["192.0.2.1:3478"]));
        assert!(
            r.restart(Instant::from_millis(1000), &mut rng, Families::V6)
                .is_empty()
        );
        assert!(!r.busy());
    }

    #[test]
    fn a_server_with_a_credential_is_asked_with_it_and_its_answer_is_checked() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let key = b"secret".to_vec();
        let mut r = Reflexive::default();
        r.set_servers(vec![Server {
            addr: addr("192.0.2.1:3478"),
            auth: Some(Auth {
                username: "9999999999:id".to_owned(),
                key: key.clone(),
                until: Some(t0 + Duration::from_secs(60)),
            }),
        }]);
        let sends = r.start(t0, &mut rng);
        let request = Message::parse(&sends[0].1).unwrap();
        assert_eq!(request.get(attr::USERNAME), Some(&b"9999999999:id"[..]));
        assert!(verify_integrity(&sends[0].1, &key));
        let unsigned = reply(&sends[0].1, addr("198.51.100.7:5000"), None);
        assert!(!feed(&mut r, t0, sends[0].0, &unsigned));
        let wrong = reply(&sends[0].1, addr("198.51.100.7:5000"), Some(b"other"));
        assert!(!feed(&mut r, t0, sends[0].0, &wrong));
        let signed = reply(&sends[0].1, addr("198.51.100.7:5000"), Some(&key));
        assert!(feed(&mut r, t0, sends[0].0, &signed));
        assert!(r.take_result().unwrap().v4.unwrap().punch().is_some());
    }

    #[test]
    fn a_server_whose_credential_expired_is_not_asked_and_so_cannot_block() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = Reflexive::default();
        r.set_servers(vec![Server {
            addr: addr("192.0.2.1:3478"),
            auth: Some(Auth {
                username: "1:id".to_owned(),
                key: b"k".to_vec(),
                until: Some(t0 + Duration::from_secs(1)),
            }),
        }]);
        assert!(r.start(t0 + Duration::from_secs(2), &mut rng).is_empty());
        assert!(!r.busy());
        assert!(r.take_result().is_none());
    }

    const V6_SERVER: &str = "[2001:db8::1]:3478";
    const V4_SERVER: &str = "192.0.2.1:3478";
    const V6_MAPPED: &str = "[2001:db8:5::7]:4000";
    const V4_MAPPED: &str = "198.51.100.7:5000";

    /// A resolver with both families, the first round answered by IPv4 only; returns the time
    /// the round ended.
    fn v4_answers_v6_silent(r: &mut Reflexive, rng: &mut SimRng, t0: Instant) -> Instant {
        r.set_servers(open(&[V6_SERVER, V4_SERVER]));
        let sends = r.start(t0, rng);
        assert_eq!(sends.len(), 2);
        let v4: Vec<Transmit> = sends.into_iter().filter(|(a, _)| a.is_ipv4()).collect();
        answer_all(r, t0, &v4, &[(V4_SERVER, V4_MAPPED)]);
        let end = t0 + BLOCKED_AFTER;
        r.handle_timeout(end, rng);
        let s = r.take_result().unwrap();
        assert_eq!(s.v6, Some(Mapping::Blocked));
        assert_eq!(s.v4, Some(Mapping::Punchable(addr(V4_MAPPED))));
        end
    }

    #[test]
    fn a_result_stays_fresh_while_the_socket_keeps_sending() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = Reflexive::default();
        r.set_servers(open(&[V4_SERVER]));
        let sends = r.start(t0, &mut rng);
        answer_all(&mut r, t0, &sends, &[(V4_SERVER, V4_MAPPED)]);
        let to = addr("203.0.113.9:7000");
        let mut now = t0;
        for _ in 0..40 {
            now = now + Duration::from_secs(15);
            r.sent(now, to);
            assert!(!r.stale(now));
        }
        assert!(!r.stale(now + STALE_AFTER));
        assert!(r.stale(now + STALE_AFTER + Duration::from_millis(1)));
        assert!(r.refresh(now + STALE_AFTER, &mut rng).is_empty());
    }

    #[test]
    fn a_gap_between_sends_ages_the_result_for_good() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = Reflexive::default();
        r.set_servers(open(&[V4_SERVER]));
        let sends = r.start(t0, &mut rng);
        answer_all(&mut r, t0, &sends, &[(V4_SERVER, V4_MAPPED)]);
        let to = addr("203.0.113.9:7000");
        let late = t0 + STALE_AFTER + Duration::from_secs(5);
        r.sent(late, to);
        assert!(r.stale(late), "the gap before this send already aged it");
        r.sent(late + Duration::from_secs(1), to);
        assert!(r.stale(late + Duration::from_secs(1)));
        let sends = r.refresh(late + Duration::from_secs(1), &mut rng);
        assert_eq!(sends.len(), 1);
        answer_all(
            &mut r,
            late + Duration::from_secs(1),
            &sends,
            &[(V4_SERVER, V4_MAPPED)],
        );
        assert!(!r.stale(late + Duration::from_secs(2)));
    }

    #[test]
    fn sends_keep_only_their_own_family_fresh() {
        let mut rng = SimRng::new(1);
        let t0 = Instant::from_millis(1000);
        let mut r = Reflexive::default();
        r.set_servers(open(&[V6_SERVER, V4_SERVER]));
        let sends = r.start(t0, &mut rng);
        answer_all(
            &mut r,
            t0,
            &sends,
            &[(V6_SERVER, V6_MAPPED), (V4_SERVER, V4_MAPPED)],
        );
        r.take_result();
        let mut now = t0;
        for _ in 0..4 {
            now = now + Duration::from_secs(15);
            r.sent(now, addr("203.0.113.9:7000"));
        }
        let sends = r.refresh(now, &mut rng);
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].0, addr(V6_SERVER));
    }

    #[test]
    fn a_refresh_without_a_result_asks_both_families() {
        let mut rng = SimRng::new(1);
        let mut r = Reflexive::default();
        r.set_servers(open(&[V6_SERVER, V4_SERVER]));
        assert!(r.stale(Instant::from_millis(1000)));
        assert_eq!(r.refresh(Instant::from_millis(1000), &mut rng).len(), 2);
        assert!(
            r.refresh(Instant::from_millis(1001), &mut rng).is_empty(),
            "a round is running"
        );
    }

    #[test]
    fn a_refresh_asks_only_the_families_that_answered() {
        let mut rng = SimRng::new(1);
        let mut r = Reflexive::default();
        let end = v4_answers_v6_silent(&mut r, &mut rng, Instant::from_millis(1000));
        let retry = end + RETRY_BACKOFF[0];
        assert_eq!(r.poll_timeout(), Some(retry));
        let at = end + STALE_AFTER + Duration::from_secs(1);
        assert!(r.stale(at));
        let sends = r.refresh(at, &mut rng);
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].0, addr(V4_SERVER));
        answer_all(&mut r, at, &sends, &[(V4_SERVER, V4_MAPPED)]);
        let s = r.take_result().unwrap();
        assert_eq!(s.v6, Some(Mapping::Blocked));
        assert_eq!(s.v4, Some(Mapping::Punchable(addr(V4_MAPPED))));
        assert!(!r.stale(at));
        assert_eq!(
            r.poll_timeout(),
            Some(retry),
            "the silent family keeps its own backoff"
        );
    }

    #[test]
    fn a_refresh_leaves_the_backoff_of_a_silent_family_alone() {
        let mut rng = SimRng::new(1);
        let mut r = Reflexive::default();
        let mut now = v4_answers_v6_silent(&mut r, &mut rng, Instant::from_millis(1000));
        let retry = now + RETRY_BACKOFF[0];
        let mut v6_asked = 0;
        for _ in 0..20 {
            now = now + STALE_AFTER + Duration::from_secs(1);
            if now >= retry {
                break;
            }
            let sends = r.refresh(now, &mut rng);
            assert!(sends.iter().all(|(a, _)| a.is_ipv4()));
            answer_all(&mut r, now, &sends, &[(V4_SERVER, V4_MAPPED)]);
            r.take_result();
            assert_eq!(r.poll_timeout(), Some(retry));
            v6_asked += sends.iter().filter(|(a, _)| a.is_ipv6()).count();
        }
        assert_eq!(v6_asked, 0);
        let sends = r.handle_timeout(retry, &mut rng);
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].0, addr(V6_SERVER));
        assert_eq!(r.take_retry(), Some(RETRY_BACKOFF[0]));
    }

    #[test]
    fn a_retry_that_runs_alongside_a_refresh_waits_for_it() {
        let mut rng = SimRng::new(1);
        let mut r = Reflexive::default();
        let end = v4_answers_v6_silent(&mut r, &mut rng, Instant::from_millis(1000));
        let retry = end + RETRY_BACKOFF[0];
        let at = Instant::from_duration(retry.as_duration() - Duration::from_millis(100));
        assert_eq!(r.refresh(at, &mut rng).len(), 1);
        assert_eq!(
            r.poll_timeout(),
            Some(at + RETRANSMIT[0]),
            "the due retry does not wake the round's timer early"
        );
    }

    #[test]
    fn a_family_that_stops_answering_gets_a_backoff_of_its_own() {
        let mut rng = SimRng::new(1);
        let mut r = Reflexive::default();
        let end = v4_answers_v6_silent(&mut r, &mut rng, Instant::from_millis(1000));
        let at = end + STALE_AFTER + Duration::from_secs(1);
        assert_eq!(r.refresh(at, &mut rng).len(), 1);
        let done = at + BLOCKED_AFTER;
        r.handle_timeout(done, &mut rng);
        let s = r.take_result().unwrap();
        assert_eq!(
            (s.v6, s.v4),
            (Some(Mapping::Blocked), Some(Mapping::Blocked))
        );
        assert_eq!(r.poll_timeout(), Some(done + RETRY_BACKOFF[1]));
        assert!(!r.stale(done + Duration::from_secs(600)));
        assert!(
            r.refresh(done + Duration::from_secs(600), &mut rng)
                .is_empty()
        );
    }

    #[test]
    fn a_result_with_every_family_blocked_is_never_stale() {
        let mut rng = SimRng::new(1);
        let mut r = Reflexive::default();
        r.set_servers(open(&[V4_SERVER]));
        let end = blocked_round(&mut r, &mut rng, Instant::from_millis(1000));
        let later = end + Duration::from_secs(10);
        assert!(!r.stale(later));
        assert!(r.refresh(later, &mut rng).is_empty());
        assert_eq!(r.poll_timeout(), Some(end + RETRY_BACKOFF[0]));
    }

    #[test]
    fn no_servers_no_round() {
        let mut rng = SimRng::new(1);
        let mut r = Reflexive::default();
        assert!(r.start(Instant::from_millis(1000), &mut rng).is_empty());
        assert!(!r.busy());
    }
}
