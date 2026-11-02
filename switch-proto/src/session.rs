//! The switch client session as a sans-IO machine (vv-04 §3 to §7): info, registration,
//! the events stream, member listing, credential refresh, presence, forwarding with its pacing,
//! reconnection and backoff.
//!
//! The caller owns the connection. It carries out [`Out`] (open a connection, run a request, open
//! the events stream) and answers with the matching `connected`, `response`, `call_failed`,
//! `stream_data` and `stream_ended` calls; time and randomness are passed in.

use std::collections::{BTreeSet, VecDeque};
use std::time::Duration;

use rand_core::{CryptoRng, Rng};
use vardevall_proto::keys::{NetworkSecret, NodePublic, NodeSecret, SwitchPublic, base32, crypto};
use vardevall_proto::time::Instant;
use zeroize::Zeroizing;

use crate::address::SwitchAuth;
use crate::api::{
    Binding, InfoBinding, Limits, StunCredentials, SwitchEvent, SwitchInfo, TurnCredentials,
    bound_data, client_proofs, forward_request, parse_challenge_response, parse_event, parse_info,
    parse_members_page, parse_register_response, parse_stun_response, parse_turn_response,
    register_request,
};
use crate::pacing::{Pacer, Traffic};
use crate::presence::{ListToken, Presence};
use crate::sse::SseParser;

/// The events stream is dead if it stays silent this long; the switch sends a comment every 15 s at
/// most (vv-04 §7.1).
pub const STREAM_IDLE: Duration = Duration::from_secs(45);
/// Pause before reopening a broken stream, so that the same session can resume within the grace
/// period (vv-04 §7.3).
pub const RESUME_DELAY: Duration = Duration::from_millis(500);
/// Longest wait between failed attempts.
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Wait after a failure that a retry will not fix soon.
pub const SLOW_RETRY: Duration = Duration::from_secs(30);
/// Wait before registering again after another client took the node key (vv-04 §4.1).
pub const REPLACED_WAIT: Duration = Duration::from_secs(60);
/// Longest `Retry-After` obeyed, in seconds.
pub const RETRY_AFTER_MAX: u64 = 300;
/// Wait before asking for TURN or STUN credentials again after a failure.
pub const CREDENTIAL_RETRY: Duration = Duration::from_secs(30);
/// Largest datagram a switch accepts (vv-04 §3.4).
pub const MAX_FORWARD: usize = 4096;
/// Most requests in flight at once on an open session; further forwards are dropped.
pub const MAX_CALLS: usize = 64;

/// Why the node is not registered with a switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchFailure {
    /// No connection could be made.
    Unreachable,
    /// The switch did not present the configured key (vv-04 §2.3), or its registration proof failed
    /// (vv-04 §4.4).
    Untrusted,
    /// The operator token is missing or wrong (vv-04 §3.2).
    TokenRejected,
    /// The switch refused the proofs of the node or the network.
    Rejected,
    /// A limit was hit (vv-04 §8).
    RateLimited,
    /// Another client registered the same node key (vv-04 §4.4).
    Replaced,
    /// The switch answered something this client does not understand.
    Protocol,
}

/// The relationship with one switch (vv-04 §4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchState {
    /// Connecting or registering.
    Connecting,
    /// Registered, with the events stream open and members listed.
    Registered,
    /// Not registered; the node retries.
    Disconnected(SwitchFailure),
}

/// What a session needs to know about its switch and its own identity.
pub struct SessionConfig {
    /// The host of the switch address in the normal form registrations carry (vv-04 §4.3).
    pub host: String,
    /// The node key.
    pub node: NodeSecret,
    /// The network secret.
    pub network: NetworkSecret,
    /// How the switch is authenticated: a pinned key, or the Web PKI and `/v0/info`.
    pub trust: SwitchAuth,
    /// The operator token, if the switch wants one.
    pub token: Option<String>,
}

/// Names one request the caller runs for the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallId(u64);

/// The HTTP methods of the switch API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

/// A request for the caller to send on the open connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// The method.
    pub method: Method,
    /// The path and query.
    pub path: String,
    /// Extra headers, lowercase names. A body, if any, is JSON.
    pub headers: Vec<(&'static str, String)>,
    /// The body.
    pub body: Option<String>,
}

/// Why a connection or a request failed, as the caller saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// No connection, or it broke or timed out.
    Unreachable,
    /// The switch presented another key, or a certificate the Web PKI refuses (vv-04 §2.3).
    Untrusted,
    /// The response is larger than the caller reads, or the request could not be formed.
    Protocol,
}

/// What the session asks the caller to do or tells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    /// Open a connection; answer `connected` or `connect_failed`.
    Connect,
    /// Drop the connection, the events stream and every request in flight.
    Close,
    /// Send a request on the connection; answer `response` or `call_failed`.
    Call {
        /// Names the request in the answer.
        id: CallId,
        /// The request.
        req: HttpRequest,
    },
    /// Send `GET /v0/events` on a connection that is not busy with other requests (a shared one,
    /// or another one if the protocol cannot share). Answer `response` with the status, then
    /// `stream_data` and `stream_ended`.
    OpenStream {
        /// Names the stream in the answers.
        id: CallId,
        /// The request.
        req: HttpRequest,
    },
    /// The registration state changed.
    State(SwitchState),
    /// What `/v0/info` says about STUN (vv-04 §3.4); the caller resolves the URIs.
    Info {
        /// STUN URIs.
        stun: Vec<String>,
        /// Whether the servers answer only requests with the credential of vv-04 §4.7.
        stun_auth: bool,
    },
    /// The short-term credential of the STUN servers (vv-04 §4.7).
    StunCredentials(StunCredentials),
    /// Fresh TURN credentials (vv-04 §4.4, §4.5); the caller resolves the URIs.
    TurnCredentials(TurnCredentials),
    /// A new registration: the volume the switch lets this session forward, in bytes, or none
    /// stated. A resumed session emits nothing, since the switch counts per session.
    Budget(Option<u64>),
    /// A member came online or went offline on this switch.
    Presence {
        /// The member.
        node: NodePublic,
        /// Whether it is online.
        online: bool,
    },
    /// A datagram forwarded by a member (vv-04 §7.2).
    Forwarded {
        /// The sender.
        from: NodePublic,
        /// The datagram.
        msg: Vec<u8>,
    },
}

/// What a request in flight on an open session is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Forward,
    Turn,
    Stun,
}

/// A step of the registration after `/v0/info`.
enum Step {
    /// Waiting for the challenge a web switch behind a proxy issues (vv-04 §4.2).
    Challenge {
        call: CallId,
        switch: SwitchPublic,
        limits: Option<Limits>,
    },
    /// Waiting for the registration response; `expect` is the switch proof to compare it to.
    Register {
        call: CallId,
        expect: Zeroizing<[u8; 32]>,
        limits: Option<Limits>,
    },
}

/// The events stream of the connection.
struct Stream {
    id: CallId,
    parser: SseParser,
    deadline: Instant,
}

/// The member listing under way (vv-04 §5.1).
struct Page {
    call: CallId,
    after: Option<NodePublic>,
    token: ListToken,
}

enum Machine {
    /// No connection; `wake` says what ends the wait.
    Waiting { until: Instant, wake: Wake },
    /// Waiting for the connection.
    Connecting,
    /// Waiting for `/v0/info`.
    Info { call: CallId, exporter: [u8; 32] },
    /// Registering.
    Registering { step: Step },
    /// Waiting for the response head of the events stream.
    Opening { call: CallId },
    /// The stream is open; listing members page by page.
    Listing { stream: Stream, page: Page },
    /// Registered. `calls` are the requests in flight.
    Up {
        stream: Stream,
        calls: Vec<(CallId, Purpose)>,
    },
}

/// What ends a wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wake {
    /// Only the clock.
    Timer,
    /// The clock, or a request to reconnect (a local path change).
    Backoff,
}

/// How an attempt ended.
#[derive(Debug, Clone, Copy)]
enum Exit {
    Resume,
    Reregister,
    Fail(SwitchFailure, Option<Duration>),
}

/// When the credentials of the registration are due for a refresh (vv-04 §4.5, §4.7).
#[derive(Default)]
struct Refresh {
    turn: Option<Instant>,
    stun: Option<Instant>,
}

/// What a registration produced, kept while the session survives reconnections.
struct Registration {
    header: Zeroizing<String>,
    refresh: Refresh,
}

struct Reply<'a> {
    status: u16,
    retry_after: Option<u64>,
    body: &'a [u8],
}

fn protocol() -> Exit {
    Exit::Fail(SwitchFailure::Protocol, Some(SLOW_RETRY))
}

fn link_failure(e: LinkError) -> Exit {
    match e {
        LinkError::Unreachable => Exit::Fail(SwitchFailure::Unreachable, None),
        LinkError::Untrusted => Exit::Fail(SwitchFailure::Untrusted, Some(SLOW_RETRY)),
        LinkError::Protocol => protocol(),
    }
}

fn retry_hint(r: &Reply<'_>) -> Option<Duration> {
    r.retry_after
        .map(|s| Duration::from_secs(s.min(RETRY_AFTER_MAX)))
}

fn problem_code(body: &[u8]) -> String {
    std::str::from_utf8(body)
        .ok()
        .and_then(|t| t.split("\"type\":\"urn:vardevall:error:").nth(1))
        .and_then(|rest| rest.split('"').next())
        .map(|code| code.chars().take(32).collect())
        .unwrap_or_default()
}

fn status_failure(r: &Reply<'_>) -> Exit {
    match r.status {
        401 if problem_code(r.body) == "token-required" => {
            Exit::Fail(SwitchFailure::TokenRejected, Some(SLOW_RETRY))
        }
        401 => Exit::Reregister,
        403 => Exit::Fail(SwitchFailure::Rejected, Some(SLOW_RETRY)),
        429 => Exit::Fail(SwitchFailure::RateLimited, retry_hint(r)),
        _ => protocol(),
    }
}

/// `d` with up to a quarter of it added or taken off.
fn jitter(d: Duration, rng: &mut impl Rng) -> Duration {
    let quarter = u64::try_from(d.as_millis()).unwrap_or(u64::MAX) / 4;
    let extra = if quarter == 0 {
        0
    } else {
        u64::from(rng.next_u32()) % (quarter * 2)
    };
    d - Duration::from_millis(quarter) + Duration::from_millis(extra)
}

fn valid_header_value(v: &str) -> bool {
    !v.chars().any(|c| c.is_ascii_control() && c != '\t')
}

/// The session with one switch.
pub struct SwitchSession {
    cfg: SessionConfig,
    machine: Machine,
    registration: Option<Registration>,
    presence: Presence,
    announced: BTreeSet<NodePublic>,
    pacer: Pacer,
    last: Option<SwitchState>,
    backoff_step: u32,
    next_call: u64,
    out: VecDeque<Out>,
}

impl SwitchSession {
    /// A session that has not connected yet; the first [`SwitchSession::poll`] gives
    /// [`Out::State`] and [`Out::Connect`].
    pub fn new(cfg: SessionConfig) -> Self {
        let mut s = SwitchSession {
            cfg,
            machine: Machine::Connecting,
            registration: None,
            presence: Presence::new(),
            announced: BTreeSet::new(),
            pacer: Pacer::new(),
            last: None,
            backoff_step: 0,
            next_call: 0,
            out: VecDeque::new(),
        };
        s.state(SwitchState::Connecting);
        s.out.push_back(Out::Connect);
        s
    }

    /// The next thing for the caller to do.
    pub fn poll(&mut self) -> Option<Out> {
        self.out.pop_front()
    }

    /// When [`SwitchSession::handle_timeout`] next has something to do.
    pub fn poll_timeout(&self) -> Option<Instant> {
        match &self.machine {
            Machine::Waiting { until, .. } => Some(*until),
            Machine::Listing { stream, .. } => Some(stream.deadline),
            Machine::Up { stream, .. } => {
                let refresh = self.registration.as_ref().map(|r| &r.refresh);
                [
                    Some(stream.deadline),
                    refresh.and_then(|r| r.turn),
                    refresh.and_then(|r| r.stun),
                ]
                .into_iter()
                .flatten()
                .min()
            }
            _ => None,
        }
    }

    /// Whether a datagram can be forwarded now: the session is registered, the datagram fits and
    /// the limits of the switch allow it (vv-04 §3.4). If it can, a request for it is queued.
    pub fn forward(&mut self, now: Instant, to: &NodePublic, msg: &[u8], traffic: Traffic) -> bool {
        let Machine::Up { calls, .. } = &self.machine else {
            return false;
        };
        if msg.len() > MAX_FORWARD || calls.len() >= MAX_CALLS {
            return false;
        }
        if !self.pacer.allow(now, msg.len(), traffic) {
            return false;
        }
        let Some(headers) = self.session_headers() else {
            return false;
        };
        let req = HttpRequest {
            method: Method::Post,
            path: "/v0/forward".to_owned(),
            headers,
            body: Some(forward_request(to, msg)),
        };
        self.up_call(Purpose::Forward, req);
        true
    }

    /// Asks for fresh TURN credentials now, because the server rejected the last (vv-04 §4.5).
    /// Before the session is up, the request waits for it.
    pub fn refresh_turn(&mut self, now: Instant) {
        if matches!(self.machine, Machine::Up { .. }) {
            self.request_turn(now);
        } else if let Some(r) = &mut self.registration {
            r.refresh.turn = Some(now);
        }
    }

    /// When the next attempt starts, while the session waits between attempts.
    pub fn reconnect_at(&self) -> Option<Instant> {
        match self.machine {
            Machine::Waiting { until, .. } => Some(until),
            _ => None,
        }
    }

    /// The local path changed: reconnect now, keeping the registration (vv-05 §4.6).
    pub fn reconnect(&mut self, now: Instant) {
        match &self.machine {
            Machine::Waiting {
                wake: Wake::Backoff,
                ..
            } => self.start_connect(),
            Machine::Waiting { .. } => {}
            _ => self.resume(now),
        }
    }

    /// The connection is open; `exporter` is the TLS exporter value of its session (vv-04 §4.1).
    pub fn connected(&mut self, _now: Instant, exporter: [u8; 32]) {
        if !matches!(self.machine, Machine::Connecting) {
            return;
        }
        let call = self.call(HttpRequest {
            method: Method::Get,
            path: "/v0/info".to_owned(),
            headers: Vec::new(),
            body: None,
        });
        self.machine = Machine::Info { call, exporter };
    }

    /// The connection could not be made.
    pub fn connect_failed(&mut self, now: Instant, rng: &mut impl CryptoRng, e: LinkError) {
        if matches!(self.machine, Machine::Connecting) {
            self.exit(now, rng, link_failure(e));
        }
    }

    /// The response to request `id` (or the head of the events stream). `retry_after` is the
    /// `Retry-After` header in seconds.
    pub fn response(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        id: CallId,
        status: u16,
        retry_after: Option<u64>,
        body: &[u8],
    ) {
        let reply = Reply {
            status,
            retry_after,
            body,
        };
        match &self.machine {
            Machine::Info { call, exporter } if *call == id => {
                let exporter = *exporter;
                let info = if reply.status == 200 {
                    parse_info(reply.body).map_err(|_| protocol())
                } else {
                    Err(status_failure(&reply))
                };
                self.on_info(now, rng, exporter, info);
            }
            Machine::Registering {
                step:
                    Step::Challenge {
                        call,
                        switch,
                        limits,
                    },
            } if *call == id => {
                let (switch, limits) = (*switch, *limits);
                self.on_challenge(now, rng, &reply, switch, limits);
            }
            Machine::Registering {
                step:
                    Step::Register {
                        call,
                        expect,
                        limits,
                    },
            } if *call == id => {
                let (expect, limits) = (expect.clone(), *limits);
                self.on_registered(now, rng, &reply, &expect, limits);
            }
            Machine::Opening { call } if *call == id => self.on_opened(now, rng, &reply, id),
            Machine::Listing { page, .. } if page.call == id => self.on_page(now, rng, &reply),
            Machine::Up { calls, .. } => {
                if let Some(i) = calls.iter().position(|(c, _)| *c == id) {
                    let purpose = calls[i].1;
                    if let Machine::Up { calls, .. } = &mut self.machine {
                        calls.swap_remove(i);
                    }
                    self.on_up_reply(now, rng, purpose, &reply);
                }
            }
            _ => {}
        }
    }

    /// Request `id` (or opening the events stream) failed.
    pub fn call_failed(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        id: CallId,
        e: LinkError,
    ) {
        match &self.machine {
            Machine::Info { call, exporter } if *call == id => {
                let exporter = *exporter;
                self.on_info(now, rng, exporter, Err(link_failure(e)));
            }
            Machine::Registering {
                step: Step::Challenge { call, .. } | Step::Register { call, .. },
            } if *call == id => self.exit(now, rng, link_failure(e)),
            Machine::Opening { call } if *call == id => self.exit(now, rng, link_failure(e)),
            Machine::Listing { page, .. } if page.call == id => {
                self.exit(now, rng, link_failure(e));
            }
            Machine::Up { calls, .. } if calls.iter().any(|(c, _)| *c == id) => self.resume(now),
            _ => {}
        }
    }

    /// Bytes of the events stream `id` arrived.
    pub fn stream_data(&mut self, now: Instant, rng: &mut impl CryptoRng, id: CallId, data: &[u8]) {
        let Some(stream) = self.stream_mut(id) else {
            return;
        };
        stream.deadline = now + STREAM_IDLE;
        if stream.parser.push(data).is_err() {
            self.exit(now, rng, protocol());
            return;
        }
        while let Some(event) = self.stream_mut(id).and_then(|s| s.parser.next_event()) {
            let Ok(Some(event)) = parse_event(&event.name, &event.data) else {
                continue;
            };
            if let Some(exit) = self.on_event(event) {
                self.exit(now, rng, exit);
                return;
            }
        }
    }

    /// The events stream `id` ended or broke.
    pub fn stream_ended(&mut self, now: Instant, id: CallId) {
        if self.stream_mut(id).is_some() {
            self.resume(now);
        }
    }

    /// Time reached [`SwitchSession::poll_timeout`].
    pub fn handle_timeout(&mut self, now: Instant) {
        match &self.machine {
            Machine::Waiting { until, .. } if now >= *until => self.start_connect(),
            Machine::Listing { stream, .. } if now >= stream.deadline => self.resume(now),
            Machine::Up { stream, .. } => {
                if now >= stream.deadline {
                    self.resume(now);
                    return;
                }
                let refresh = self.registration.as_ref().map(|r| &r.refresh);
                let turn = refresh.and_then(|r| r.turn).is_some_and(|t| now >= t);
                let stun = refresh.and_then(|r| r.stun).is_some_and(|t| now >= t);
                if turn {
                    self.request_turn(now);
                }
                if stun {
                    self.request_stun(now);
                }
            }
            _ => {}
        }
    }

    fn state(&mut self, state: SwitchState) {
        if self.last != Some(state) {
            self.last = Some(state);
            self.out.push_back(Out::State(state));
        }
    }

    fn call(&mut self, req: HttpRequest) -> CallId {
        let id = CallId(self.next_call);
        self.next_call += 1;
        self.out.push_back(Out::Call { id, req });
        id
    }

    fn up_call(&mut self, purpose: Purpose, req: HttpRequest) {
        let id = self.call(req);
        if let Machine::Up { calls, .. } = &mut self.machine {
            calls.push((id, purpose));
        }
    }

    fn session_headers(&self) -> Option<Vec<(&'static str, String)>> {
        let r = self.registration.as_ref()?;
        Some(vec![("vv-session", r.header.to_string())])
    }

    fn stream_mut(&mut self, id: CallId) -> Option<&mut Stream> {
        match &mut self.machine {
            Machine::Listing { stream, .. } | Machine::Up { stream, .. } if stream.id == id => {
                Some(stream)
            }
            _ => None,
        }
    }

    fn start_connect(&mut self) {
        self.state(SwitchState::Connecting);
        self.out.push_back(Out::Connect);
        self.machine = Machine::Connecting;
    }

    /// Ends the attempt without a failure to report: reconnect shortly, keeping the registration.
    fn resume(&mut self, now: Instant) {
        self.settle();
        self.finish(now, Exit::Resume, RESUME_DELAY, Wake::Timer);
    }

    fn exit(&mut self, now: Instant, rng: &mut impl CryptoRng, exit: Exit) {
        self.settle();
        let (wait, wake) = match exit {
            Exit::Resume | Exit::Reregister => (RESUME_DELAY, Wake::Timer),
            Exit::Fail(_, Some(hint)) => (jitter(hint, rng), Wake::Timer),
            Exit::Fail(_, None) => (self.next_backoff(rng), Wake::Backoff),
        };
        self.finish(now, exit, wait, wake);
    }

    /// An attempt that got as far as `Registered` starts the backoff over.
    fn settle(&mut self) {
        if self.last == Some(SwitchState::Registered) {
            self.backoff_step = 0;
        }
    }

    /// 1 s doubling to [`BACKOFF_MAX`], each with jitter.
    fn next_backoff(&mut self, rng: &mut impl Rng) -> Duration {
        let base = Duration::from_secs(1u64 << self.backoff_step.min(6)).min(BACKOFF_MAX);
        self.backoff_step = (self.backoff_step + 1).min(6);
        jitter(base, rng)
    }

    fn finish(&mut self, now: Instant, exit: Exit, wait: Duration, wake: Wake) {
        let had_connection = !matches!(self.machine, Machine::Waiting { .. });
        self.machine = Machine::Waiting {
            until: now + wait,
            wake,
        };
        if had_connection {
            self.out.push_back(Out::Close);
        }
        self.sync();
        match exit {
            Exit::Resume => {}
            Exit::Reregister => self.registration = None,
            Exit::Fail(f, _) => {
                self.state(SwitchState::Disconnected(f));
                if f == SwitchFailure::Replaced {
                    self.registration = None;
                }
            }
        }
    }

    /// Tells the caller what changed in presence: nothing is online unless the session is up.
    fn sync(&mut self) {
        let desired: BTreeSet<NodePublic> = if matches!(self.machine, Machine::Up { .. }) {
            self.presence.online().copied().collect()
        } else {
            BTreeSet::new()
        };
        let gone: Vec<NodePublic> = self.announced.difference(&desired).copied().collect();
        let came: Vec<NodePublic> = desired.difference(&self.announced).copied().collect();
        for node in gone {
            self.announced.remove(&node);
            self.out.push_back(Out::Presence {
                node,
                online: false,
            });
        }
        for node in came {
            self.announced.insert(node);
            self.out.push_back(Out::Presence { node, online: true });
        }
    }

    /// `GET /v0/info` answered (vv-04 §3.4).
    fn on_info(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        exporter: [u8; 32],
        info: Result<SwitchInfo, Exit>,
    ) {
        if let Ok(info) = &info {
            self.out.push_back(Out::Info {
                stun: info.stun.clone(),
                stun_auth: info.stun_auth,
            });
            self.pacer.set(info.forward_limits, false);
        }
        if self.registration.is_some() {
            self.open_events(now, rng);
            return;
        }
        let info = match (info, &self.cfg.trust) {
            (Ok(info), _) => Some(info),
            (Err(_), SwitchAuth::Pinned(_)) => None,
            (Err(e), SwitchAuth::Web { .. }) => {
                self.exit(now, rng, e);
                return;
            }
        };
        self.register(now, rng, exporter, info);
    }

    /// The switch key and the binding of a registration (vv-04 §4.1): a pinned address uses the key
    /// of the address and the exporter; a web address uses what `/v0/info` advertises, and refuses a
    /// switch that names no key.
    fn register(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        exporter: [u8; 32],
        info: Option<SwitchInfo>,
    ) {
        let limits = info.as_ref().and_then(|i| i.forward_limits);
        let (switch, binding) = match &self.cfg.trust {
            SwitchAuth::Pinned(key) => (*key, Binding::Exporter(exporter)),
            SwitchAuth::Web { .. } => {
                let Some(info) = info else {
                    self.exit(now, rng, protocol());
                    return;
                };
                let Some(key) = info.key else {
                    self.exit(
                        now,
                        rng,
                        Exit::Fail(SwitchFailure::Untrusted, Some(SLOW_RETRY)),
                    );
                    return;
                };
                match info.binding {
                    InfoBinding::Exporter => (key, Binding::Exporter(exporter)),
                    InfoBinding::Challenge => {
                        let call = self.call(HttpRequest {
                            method: Method::Get,
                            path: "/v0/challenge".to_owned(),
                            headers: Vec::new(),
                            body: None,
                        });
                        self.machine = Machine::Registering {
                            step: Step::Challenge {
                                call,
                                switch: key,
                                limits,
                            },
                        };
                        return;
                    }
                }
            }
        };
        self.send_register(now, rng, switch, &binding, limits);
    }

    fn on_challenge(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        reply: &Reply<'_>,
        switch: SwitchPublic,
        limits: Option<Limits>,
    ) {
        if reply.status != 200 {
            self.exit(now, rng, status_failure(reply));
            return;
        }
        match parse_challenge_response(reply.body) {
            Ok((challenge, _)) => {
                self.send_register(now, rng, switch, &Binding::Challenge(challenge), limits);
            }
            Err(_) => self.exit(now, rng, protocol()),
        }
    }

    /// `POST /v0/register` (vv-04 §4.3).
    fn send_register(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        switch: SwitchPublic,
        binding: &Binding,
        limits: Option<Limits>,
    ) {
        let node = self.cfg.node.public();
        let network = self.cfg.network.public();
        let proofs = bound_data(binding, &self.cfg.host, &node, &network, &switch)
            .ok()
            .and_then(|b| client_proofs(&self.cfg.node, &self.cfg.network, &switch, &b).ok());
        let Some(proofs) = proofs else {
            self.exit(now, rng, protocol());
            return;
        };
        let body = register_request(&node, &network, binding, &self.cfg.host, &proofs);
        let mut headers = Vec::new();
        if let Some(token) = &self.cfg.token {
            let value = format!("Bearer {token}");
            if !valid_header_value(&value) {
                self.exit(now, rng, protocol());
                return;
            }
            headers.push(("authorization", value));
        }
        let call = self.call(HttpRequest {
            method: Method::Post,
            path: "/v0/register".to_owned(),
            headers,
            body: Some(body),
        });
        self.machine = Machine::Registering {
            step: Step::Register {
                call,
                expect: Zeroizing::new(proofs.switch_proof),
                limits,
            },
        };
    }

    /// The registration is accepted: the session starts with its whole rate and reports its
    /// volume. Open design point: the register response states no `forward_limits`
    /// of its own, so the volume is the one of the `/v0/info` the registration was made from.
    fn on_registered(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        reply: &Reply<'_>,
        expect: &[u8; 32],
        limits: Option<Limits>,
    ) {
        if reply.status != 200 {
            let exit = match status_failure(reply) {
                Exit::Reregister => protocol(),
                other => other,
            };
            self.exit(now, rng, exit);
            return;
        }
        let Ok(parsed) = parse_register_response(reply.body) else {
            self.exit(now, rng, protocol());
            return;
        };
        if !crypto::ct_eq(&parsed.switch_proof, expect) {
            self.exit(
                now,
                rng,
                Exit::Fail(SwitchFailure::Untrusted, Some(SLOW_RETRY)),
            );
            return;
        }
        let header = Zeroizing::new(base32::encode(&parsed.session));
        if !valid_header_value(&header) {
            self.exit(now, rng, protocol());
            return;
        }
        self.presence.on_registered();
        self.registration = Some(Registration {
            header,
            refresh: Refresh::default(),
        });
        self.pacer.set(limits, true);
        self.out
            .push_back(Out::Budget(limits.and_then(|l| l.bytes)));
        if let Some(s) = parsed.stun {
            self.publish_stun(now, s);
        }
        if let Some(t) = parsed.turn {
            self.publish_turn(now, t);
        }
        self.open_events(now, rng);
    }

    /// `GET /v0/events` (vv-04 §7).
    fn open_events(&mut self, now: Instant, rng: &mut impl CryptoRng) {
        let Some(mut headers) = self.session_headers() else {
            self.exit(now, rng, Exit::Reregister);
            return;
        };
        headers.push(("accept", "text/event-stream".to_owned()));
        let id = CallId(self.next_call);
        self.next_call += 1;
        self.out.push_back(Out::OpenStream {
            id,
            req: HttpRequest {
                method: Method::Get,
                path: "/v0/events".to_owned(),
                headers,
                body: None,
            },
        });
        self.machine = Machine::Opening { call: id };
    }

    fn on_opened(&mut self, now: Instant, rng: &mut impl CryptoRng, reply: &Reply<'_>, id: CallId) {
        if reply.status != 200 {
            let exit = match reply.status {
                401 => Exit::Reregister,
                429 => Exit::Fail(SwitchFailure::RateLimited, retry_hint(reply)),
                _ => protocol(),
            };
            self.exit(now, rng, exit);
            return;
        }
        self.presence.on_stream_opened();
        let stream = Stream {
            id,
            parser: SseParser::new(),
            deadline: now + STREAM_IDLE,
        };
        let page = self.list_page(None);
        self.machine = Machine::Listing { stream, page };
    }

    /// Requests a page of `GET /v0/members` after `after`.
    fn list_page(&mut self, after: Option<NodePublic>) -> Page {
        let token = self.presence.begin_list();
        let path = match &after {
            Some(a) => format!("/v0/members?after={a}"),
            None => "/v0/members".to_owned(),
        };
        let headers = self.session_headers().unwrap_or_default();
        let call = self.call(HttpRequest {
            method: Method::Get,
            path,
            headers,
            body: None,
        });
        Page { call, after, token }
    }

    fn on_page(&mut self, now: Instant, rng: &mut impl CryptoRng, reply: &Reply<'_>) {
        if reply.status != 200 {
            self.exit(now, rng, status_failure(reply));
            return;
        }
        let Ok(page) = parse_members_page(reply.body) else {
            self.exit(now, rng, protocol());
            return;
        };
        let Machine::Listing { page: current, .. } = &self.machine else {
            return;
        };
        let (token, after) = (current.token, current.after);
        self.presence.on_list_page(token, after.as_ref(), &page);
        if page.truncated {
            let Some(last) = page.members.last() else {
                self.exit(now, rng, protocol());
                return;
            };
            let next = self.list_page(Some(last.node));
            if let Machine::Listing { page, .. } = &mut self.machine {
                *page = next;
            }
            return;
        }
        let machine = std::mem::replace(&mut self.machine, Machine::Connecting);
        let Machine::Listing { stream, .. } = machine else {
            self.machine = machine;
            return;
        };
        self.machine = Machine::Up {
            stream,
            calls: Vec::new(),
        };
        self.sync();
        self.state(SwitchState::Registered);
    }

    fn on_event(&mut self, event: SwitchEvent) -> Option<Exit> {
        match event {
            SwitchEvent::Forward { from, msg } => self.out.push_back(Out::Forwarded { from, msg }),
            SwitchEvent::Online { .. } | SwitchEvent::Offline { .. } => {
                self.presence.on_event(&event);
                self.sync();
            }
            SwitchEvent::Replaced => {
                self.registration = None;
                return Some(Exit::Fail(SwitchFailure::Replaced, Some(REPLACED_WAIT)));
            }
        }
        None
    }

    fn on_up_reply(
        &mut self,
        now: Instant,
        rng: &mut impl CryptoRng,
        purpose: Purpose,
        reply: &Reply<'_>,
    ) {
        if reply.status == 401 {
            self.exit(now, rng, Exit::Reregister);
            return;
        }
        match purpose {
            Purpose::Forward => {}
            Purpose::Turn => match reply.status {
                200 => {
                    if let Ok(creds) = parse_turn_response(reply.body) {
                        self.publish_turn(now, creds);
                    }
                }
                404 => self.set_refresh(|r| r.turn = None),
                _ => {}
            },
            Purpose::Stun => match reply.status {
                200 => {
                    if let Ok(creds) = parse_stun_response(reply.body) {
                        self.publish_stun(now, creds);
                    }
                }
                404 => self.set_refresh(|r| r.stun = None),
                _ => {}
            },
        }
    }

    fn set_refresh(&mut self, f: impl FnOnce(&mut Refresh)) {
        if let Some(r) = &mut self.registration {
            f(&mut r.refresh);
        }
    }

    fn publish_turn(&mut self, now: Instant, creds: TurnCredentials) {
        let at = now + Duration::from_secs(creds.ttl / 2);
        self.set_refresh(|r| r.turn = Some(at));
        self.out.push_back(Out::TurnCredentials(creds));
    }

    fn publish_stun(&mut self, now: Instant, creds: StunCredentials) {
        let at = now + Duration::from_secs(creds.ttl / 2);
        self.set_refresh(|r| r.stun = Some(at));
        self.out.push_back(Out::StunCredentials(creds));
    }

    /// Asks for fresh TURN credentials; asks again in [`CREDENTIAL_RETRY`] if it fails
    /// (vv-04 §4.5).
    fn request_turn(&mut self, now: Instant) {
        self.request_credentials(now, "/v0/turn", Purpose::Turn);
    }

    /// Asks for fresh STUN credentials; asks again in [`CREDENTIAL_RETRY`] if it fails
    /// (vv-04 §4.7).
    fn request_stun(&mut self, now: Instant) {
        self.request_credentials(now, "/v0/stun", Purpose::Stun);
    }

    fn request_credentials(&mut self, now: Instant, path: &str, purpose: Purpose) {
        let Some(headers) = self.session_headers() else {
            return;
        };
        let retry = now + CREDENTIAL_RETRY;
        self.set_refresh(|r| match purpose {
            Purpose::Turn => r.turn = Some(retry),
            _ => r.stun = Some(retry),
        });
        self.up_call(
            purpose,
            HttpRequest {
                method: Method::Post,
                path: path.to_owned(),
                headers,
                body: Some(String::new()),
            },
        );
    }
}

#[cfg(test)]
mod tests;
