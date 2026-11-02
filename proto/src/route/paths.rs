//! The routes of one peer while a session is up: verification by ping and pong, keeping,
//! selection, roaming and the on-demand fallback.
//!
//! A [`Paths`] lives in `Link::Up` and survives rekeys; it is built when the link comes up and
//! dropped when it goes down. It knows routes only as [`Spec`]s the peer computes from the
//! transports and the candidates, and it says what to send as [`Do`]s; the peer seals pings and
//! pongs in its current session. Time is always an explicit [`Instant`], settings a borrowed
//! [`Config`].
//!
//! Directions are independent: a route is verified for sending when a pong answers a ping that
//! went out on it, whichever path the pong comes back on. There are no receive reports and no
//! leader.

use std::cmp::Reverse;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use crate::meter::Meter;
use crate::route::change::Families;
use crate::route::class::{Band, DeliveryClass, Latency, RouteClass};
use crate::route::rtt::{INITIAL_RTO, MIN_RTO, Rtt};
use crate::session::KEEPALIVE_TIMEOUT;
use crate::time::Instant;
use crate::transport::Path;

/// Offsets of the pings of a candidate route from the moment it became a candidate
///.
pub const EPISODE: [Duration; 7] = [
    Duration::from_millis(0),
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
    Duration::from_millis(800),
    Duration::from_millis(1600),
    Duration::from_millis(3200),
];
/// The interval at which an unmetered active route is pinged while data goes out on it and
/// nothing comes back on it, unless [`Config::detect_timeout`] says otherwise.
pub const DETECT_TIMEOUT: Duration = Duration::from_secs(2);
/// A verified route of a probed transport on which nothing was sent for this long gets a ping,
/// which also keeps NAT mappings open.
pub const NAT_KEEPALIVE: Duration = Duration::from_secs(25);
/// How long the direct routes get before a metered one is used: message 1 on the switch, data on
/// a reported route after a direct route was lost, and the request for on-demand transports
///.
pub const FALLBACK_DELAY: Duration = Duration::from_secs(1);
/// Most routes held for one peer.
pub const MAX_ROUTES: usize = 48;
/// Pings remembered to match pongs against.
const SENT_PINGS: usize = 64;

/// Settings of the routes of every peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// `KEEPALIVE_TIMEOUT` (vv-02 §6.4).
    pub keepalive_timeout: Duration,
    /// [`FALLBACK_DELAY`]; zero uses metered routes at once.
    pub fallback_delay: Duration,
    /// The interval at which an unmetered active route is pinged while data goes out on it;
    /// [`DETECT_TIMEOUT`] if `None`. A metered route is pinged every `keepalive_timeout`
    ///.
    pub detect_timeout: Option<Duration>,
    /// Whether a reported route (the switch) may carry data.
    pub switch_data: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            keepalive_timeout: KEEPALIVE_TIMEOUT,
            fallback_delay: FALLBACK_DELAY,
            detect_timeout: None,
            switch_data: true,
        }
    }
}

/// Where a route comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A candidate of the peer, found by a local source or shared by the peer, on a probed
    /// transport.
    Candidate,
    /// The source of a frame that matched no route.
    Learned,
    /// A [`crate::transport::Reachability::Reported`] transport that reports the peer reachable.
    Reported,
}

/// A route as the peer describes it: what the transports and candidates say it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spec {
    /// The path.
    pub path: Path,
    /// Its class: the medium's class for the far end, metered if the candidate or the local
    /// network is.
    pub class: RouteClass,
    /// For views and logs only: the candidate's label, `"learned"` or `"switch"`.
    pub label: &'static str,
    /// Where it comes from.
    pub origin: Origin,
}

/// The state of a route, for views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Known but not pinged: it could not become the active route.
    Dormant,
    /// Not known to work; pinged on its episode.
    Candidate,
    /// A pong answered a ping sent on it; reported routes are always verified.
    Verified,
    /// A ping on it went unanswered past the RTO.
    Suspect,
    /// It answered nothing; pinged now and then while it could win.
    Failed,
}

/// What a failed route waits for, for views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// One more ping at this instant, since it could still win.
    Retry(Instant),
    /// A learned route is dropped at this instant.
    Forget(Instant),
}

/// A summary of a route for views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteInfo {
    /// The path.
    pub path: Path,
    /// Its class.
    pub class: RouteClass,
    /// Its label.
    pub label: &'static str,
    /// Its state.
    pub status: Status,
    /// The smoothed round-trip time of its pings, if any was answered.
    pub srtt: Option<Duration>,
    /// Whether it is the active route.
    pub active: bool,
    /// The frames it has carried.
    pub meter: Meter,
    /// While it is failed, its next retry or when it is forgotten; `None` for a failed route
    /// that could not win, which is not pinged.
    pub next: Option<Next>,
}

/// The active route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Active {
    /// The path.
    pub path: Path,
    /// Its class.
    pub class: RouteClass,
    /// Its label.
    pub label: &'static str,
    /// Whether a pong verified it or it is reported; `false` while it is active only because
    /// the peer roamed to it or a local change put it back to `Candidate`.
    pub verified: bool,
    /// The frames it has carried.
    pub meter: Meter,
}

/// Where traffic of a delivery class goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// On the active route, which meets the class.
    Route(Path),
    /// On the active route, which does not meet the class; the application is told.
    Degraded(Path),
    /// Not yet: no route, or the active one does not meet a class that may not degrade.
    Wait,
}

/// What the peer does for its [`Paths`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Do {
    /// Seal `Control::Ping { txid }` in the current session and send it on `path`.
    Ping { path: Path, txid: u64 },
    /// Seal `Control::Pong { txid, observed }` in the current session and send it on `path`.
    Pong {
        path: Path,
        txid: u64,
        observed: Option<SocketAddr>,
    },
    /// Ask every on-demand transport that is not ready to come up.
    Demand,
    /// A candidate route ended its episode or its third miss without a pong:
    /// a source holding fallbacks for its address may offer the next one.
    Failed(Path),
    /// No reported route and every other route failed: the session is lost.
    Lost,
}

/// The state of one route.
#[derive(Debug, Clone, Copy)]
enum State {
    /// Known, not pinged: it could not win, or its turn in its class has not come.
    Dormant,
    /// Pinged at `since + EPISODE[i]` for `i < sent`; fails at `since + EPISODE[6] + RTO`
    /// without a pong.
    Candidate { since: Instant, sent: usize },
    /// A pong answered one of its pings. `deadline`: a keeping ping is out and must be answered
    /// by then.
    Verified {
        last_pong: Instant,
        deadline: Option<Instant>,
    },
    /// `misses` keeping pings in a row went unanswered (1 or 2); the latest must be answered by
    /// `deadline`.
    Suspect { misses: u8, deadline: Instant },
    /// Pinged at `retry_at` and then every `keepalive_timeout`, while it could win; a learned
    /// route is dropped at `retry_at` instead.
    Failed { retry_at: Instant },
}

#[derive(Debug, Clone)]
struct Route {
    spec: Spec,
    state: State,
    rtt: Rtt,
    last_ping: Option<Instant>,
    /// The latest ping sent because the peer's ping arrived on this route,
    /// or the latest retry ping of a `Failed` route.
    last_triggered: Option<Instant>,
    last_tx: Option<Instant>,
    /// The latest authenticated frame of the peer that arrived on this path.
    last_rx: Option<Instant>,
    /// When its episode last began: the routes of a class start [`MIN_RTO`] apart.
    started: Option<Instant>,
    /// The frames of the peer's sessions sent and received on it; kept when its spec changes.
    meter: Meter,
}

type ClassKey = (Reverse<Band>, bool, Reverse<Latency>);
type Rank = (ClassKey, bool, Duration);

fn class_key(c: &RouteClass) -> ClassKey {
    (Reverse(c.band), c.metered, Reverse(c.latency))
}

fn episode(now: Instant) -> State {
    State::Candidate {
        since: now,
        sent: 1,
    }
}

fn verified(now: Instant, deadline: Option<Instant>) -> State {
    State::Verified {
        last_pong: now,
        deadline,
    }
}

impl Route {
    fn new(spec: Spec, state: State) -> Self {
        Route {
            spec,
            state,
            rtt: Rtt::new(),
            last_ping: None,
            last_triggered: None,
            last_tx: None,
            last_rx: None,
            started: None,
            meter: Meter::default(),
        }
    }

    fn reported(&self) -> bool {
        self.spec.origin == Origin::Reported
    }

    fn rto(&self) -> Duration {
        self.rtt.rto()
    }

    fn rank(&self) -> Rank {
        let srtt = self.rtt.srtt();
        (
            class_key(&self.spec.class),
            srtt.is_none(),
            srtt.unwrap_or_default(),
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct SentPing {
    txid: u64,
    path: Path,
    at: Instant,
}

/// The active route and, while it is not verified, when it is given up.
#[derive(Debug, Clone, Copy)]
struct ActiveRoute {
    path: Path,
    revert_at: Option<Instant>,
}

/// A move onto a metered route that waits for a better unmetered route's pong.
#[derive(Debug, Clone, Copy)]
struct Settle {
    to: Path,
    until: Instant,
}

/// The on-demand fallback.
#[derive(Debug, Clone, Copy)]
enum Demand {
    /// An unmetered route is usable.
    Satisfied,
    /// None is; [`Do::Demand`] at `at`, then every `keepalive_timeout`.
    Wanting { at: Instant },
}

/// The routes of one peer while its link is up.
#[derive(Debug, Clone)]
pub(crate) struct Paths {
    routes: Vec<Route>,
    active: Option<ActiveRoute>,
    /// Reported routes are no target until then: a direct route was just lost.
    grace_until: Option<Instant>,
    settle: Option<Settle>,
    demand: Demand,
    pings: VecDeque<SentPing>,
    next_txid: u64,
    out: VecDeque<Do>,
    /// [`Do::Lost`] was emitted and the condition has not cleared since.
    lost: bool,
    /// When the newest session of the peer that a frame arrived on was established.
    heard: Option<Instant>,
    /// The roamed route whose first ping went unanswered, until [`Paths::maintain`] has decided
    /// whether it goes on.
    reverted: Option<Path>,
}

impl Paths {
    /// The routes of a session that just came up.
    ///
    /// Every spec becomes a route: `Reported` ones and `verified` (the path message 2 arrived on,
    /// if message 1 went out on it, rule 6) `Verified`, the others `Dormant`. The active route is
    /// selected and pinged at once (rule 7); then every route that could win starts probing, the
    /// routes of one class [`MIN_RTO`] apart (rules 1 and 2). The on-demand fallback is armed if
    /// no unmetered route is usable.
    pub(crate) fn new(now: Instant, cfg: &Config, specs: &[Spec], verified: Option<Path>) -> Self {
        let mut p = Paths {
            routes: Vec::new(),
            active: None,
            grace_until: None,
            settle: None,
            demand: Demand::Satisfied,
            pings: VecDeque::new(),
            next_txid: 0,
            out: VecDeque::new(),
            lost: false,
            heard: None,
            reverted: None,
        };
        for spec in specs {
            if p.routes.len() >= MAX_ROUTES {
                break;
            }
            if p.index(&spec.path).is_some() {
                continue;
            }
            let state = if spec.origin == Origin::Reported || verified == Some(spec.path) {
                self::verified(now, None)
            } else {
                State::Dormant
            };
            p.routes.push(Route::new(*spec, state));
        }
        p.select(now, cfg);
        if let Some(i) = p.active.and_then(|a| p.index(&a.path)) {
            p.ping(now, i);
            let r = &mut p.routes[i];
            if !r.reported()
                && let State::Verified { last_pong, .. } = r.state
            {
                r.state = State::Verified {
                    last_pong,
                    deadline: Some(now + r.rtt.rto()),
                };
            }
        }
        p.maintain(now, cfg);
        p.finish(now, cfg);
        p
    }

    /// The transports, the candidates or the local metering changed: `specs` is the whole new
    /// set, learned routes included.
    ///
    /// A route keeps its state and RTT if its path is still there, with the new class, label
    /// and origin. A route whose path is gone is dropped; if it was active, the active route is
    /// lost. A new path is `Dormant`, or `Verified` if `Reported`; it probes if it could win.
    /// Then the active route is selected again.
    pub(crate) fn sync(&mut self, now: Instant, cfg: &Config, specs: &[Spec]) {
        let mut old = std::mem::take(&mut self.routes);
        for spec in specs {
            if self.routes.len() >= MAX_ROUTES {
                break;
            }
            if self.index(&spec.path).is_some() {
                continue;
            }
            match old.iter().position(|r| r.spec.path == spec.path) {
                Some(j) => {
                    let mut r = old.remove(j);
                    r.spec = *spec;
                    if r.reported() && !matches!(r.state, State::Verified { .. }) {
                        r.state = verified(now, None);
                    }
                    self.routes.push(r);
                }
                None => {
                    let state = if spec.origin == Origin::Reported {
                        verified(now, None)
                    } else {
                        State::Dormant
                    };
                    self.routes.push(Route::new(*spec, state));
                }
            }
        }
        for gone in old {
            if self.active.is_some_and(|a| a.path == gone.spec.path) {
                self.lose_active(now, cfg, gone.reported());
            }
        }
        self.settle_routes(now, cfg);
    }

    /// A settled local change of `families`: every route of those families that is
    /// not `Reported` becomes `Dormant`. An active route among them stays active, unverified, is
    /// pinged at once and reverts one RTO after that ping without a pong. Then §4.1 decides what
    /// else is probed.
    pub(crate) fn local_change(&mut self, now: Instant, cfg: &Config, families: Families) {
        let mut active = None;
        for (i, r) in self.routes.iter_mut().enumerate() {
            if r.reported() || !r.spec.path.addr().is_some_and(|a| families.contains(&a)) {
                continue;
            }
            r.state = State::Dormant;
            if self.active.is_some_and(|a| a.path == r.spec.path) {
                active = Some(i);
            }
        }
        if let Some(i) = active {
            self.start(now, i);
            let rto = self.routes[i].rto();
            if let Some(a) = &mut self.active {
                a.revert_at = Some(now + rto);
            }
        }
        self.settle_routes(now, cfg);
    }

    /// A ping `txid` arrived on `from`.
    ///
    /// - A pong goes on `from.path` with `observed` = the far end of `from.path` if it has an
    ///   address, and also on the active route if that is another path.
    /// - No route on `from.path`: a `Learned` route is made (if below [`MAX_ROUTES`]), `Dormant`;
    ///   it never becomes active here.
    /// - A `Candidate` route: a triggered ping on it, unless one went out less than `EPISODE[1]`
    ///   ago.
    /// - A `Dormant` route that could win: its episode starts; the ping at offset 0 is the
    ///   triggered ping.
    /// - A `Failed` route that could win: one triggered ping, which counts as its retry: the next
    ///   is `cfg.keepalive_timeout` later (rule 5). A route that could not win is only answered.
    ///
    /// Reading of rule 5: a retry ping or a triggered ping on a `Failed` route within
    /// `cfg.keepalive_timeout` suppresses the triggered ping. A peer that keeps pinging every
    /// `DETECT_TIMEOUT` would otherwise get a ping on its dead route that often, where the route
    /// is retried every `keepalive_timeout`.
    ///
    /// Reading of rule 5: only triggered pings count towards the 100 ms limit. The episode ping
    /// that went out a moment earlier does not suppress the answer.
    pub(crate) fn on_ping(&mut self, now: Instant, cfg: &Config, from: Spec, txid: u64) {
        let observed = from.path.addr();
        self.pong(now, from.path, txid, observed);
        if let Some(a) = self.active.filter(|a| a.path != from.path) {
            self.pong(now, a.path, txid, observed);
        }
        let i = match self.index(&from.path) {
            Some(i) => Some(i),
            None if self.routes.len() < MAX_ROUTES => {
                let spec = Spec {
                    origin: Origin::Learned,
                    ..from
                };
                self.routes.push(Route::new(spec, State::Dormant));
                Some(self.routes.len() - 1)
            }
            None => None,
        };
        if let Some(i) = i {
            self.routes[i].last_rx = Some(now);
            match self.routes[i].state {
                State::Candidate { .. }
                    if self.routes[i]
                        .last_triggered
                        .is_none_or(|t| now - t >= EPISODE[1]) =>
                {
                    self.trigger(now, i);
                }
                State::Dormant if self.could_win(i) => {
                    self.start(now, i);
                    self.routes[i].last_triggered = Some(now);
                }
                State::Failed { .. }
                    if self.could_win(i)
                        && self.routes[i]
                            .last_triggered
                            .is_none_or(|t| now - t >= cfg.keepalive_timeout) =>
                {
                    self.routes[i].state = State::Failed {
                        retry_at: now + cfg.keepalive_timeout,
                    };
                    self.trigger(now, i);
                }
                _ => {}
            }
        }
        self.settle_routes(now, cfg);
    }

    /// A pong `txid` arrived on `from`.
    ///
    /// `from` records the arrival. The route the ping went out on, if `txid` is remembered and
    /// the route still exists, gets an RTT sample `now - sent` and becomes `Verified` with
    /// `last_pong = now`, from any state. An unknown `txid` is ignored. Then the active route is
    /// selected again.
    pub(crate) fn on_pong(&mut self, now: Instant, cfg: &Config, from: Path, txid: u64) {
        self.on_rx(now, from);
        let Some(pos) = self.pings.iter().position(|p| p.txid == txid) else {
            return;
        };
        let Some(sent) = self.pings.remove(pos) else {
            return;
        };
        let Some(i) = self.index(&sent.path) else {
            return;
        };
        let r = &mut self.routes[i];
        r.rtt.sample(now - sent.at);
        r.state = State::Verified {
            last_pong: now,
            deadline: None,
        };
        self.settle_routes(now, cfg);
    }

    /// Counts a frame of `len` bytes sent on `path` on its route, if it has one.
    pub(crate) fn count_sent(&mut self, path: Path, len: usize) {
        if let Some(i) = self.index(&path) {
            self.routes[i].meter.add_sent(len);
        }
    }

    /// Counts a frame of `len` bytes received on `path` on its route, if it has one.
    pub(crate) fn count_received(&mut self, path: Path, len: usize) {
        if let Some(i) = self.index(&path) {
            self.routes[i].meter.add_received(len);
        }
    }

    /// An authenticated frame of any kind arrived on `from`: a known route records it.
    pub(crate) fn on_rx(&mut self, now: Instant, from: Path) {
        if let Some(i) = self.index(&from) {
            self.routes[i].last_rx = Some(now);
        }
    }

    /// An authenticated frame of the peer's session established at `session` arrived. Returns
    /// whether the peer is still sending on it: no frame of a session established later has
    /// arrived.
    pub(crate) fn hear(&mut self, session: Instant) -> bool {
        let live = self.heard.is_none_or(|h| session >= h);
        if live {
            self.heard = Some(session);
        }
        live
    }

    /// An authenticated data frame arrived on `from`; `newest`: its counter is the highest yet
    /// in its session and the session is one the peer still sends on ([`Paths::hear`]).
    ///
    /// A known route records `last_rx`. Data from a path of worse class than a `Verified` route
    /// roams nothing and makes no route: selection would move straight back (§4.3), once per
    /// frame. Otherwise, with `newest` and no route on `from.path`, a
    /// `Learned` route is made; with `newest` and a `Dormant` route there, that route is taken.
    /// Either is a `Candidate` from `now` (its offset-0 ping goes out) and made active at once,
    /// unverified, with `revert_at = now + its RTO`. A route in any other state, `Failed`
    /// included, only records `last_rx`.
    pub(crate) fn on_data(&mut self, now: Instant, cfg: &Config, from: Spec, newest: bool) {
        let known = self.index(&from.path);
        if let Some(i) = known {
            self.routes[i].last_rx = Some(now);
            if !newest || !matches!(self.routes[i].state, State::Dormant) {
                return;
            }
        } else if !newest || self.routes.len() >= MAX_ROUTES {
            return;
        }
        let key = class_key(&known.map_or(from.class, |i| self.routes[i].spec.class));
        let outranked = self
            .best(cfg, |j| {
                let r = &self.routes[j];
                matches!(r.state, State::Verified { .. }) && class_key(&r.spec.class) < key
            })
            .is_some();
        if outranked {
            return;
        }
        let i = known.unwrap_or_else(|| {
            let spec = Spec {
                origin: Origin::Learned,
                ..from
            };
            let mut r = Route::new(spec, State::Dormant);
            r.last_rx = Some(now);
            self.routes.push(r);
            self.routes.len() - 1
        });
        self.start(now, i);
        let revert_at = now + self.routes[i].rto();
        self.active = Some(ActiveRoute {
            path: from.path,
            revert_at: Some(revert_at),
        });
        self.settle = None;
        self.grace_until = None;
        self.settle_routes(now, cfg);
    }

    /// A frame of the peer's session went out on `path`; `data` if it carried a packet.
    ///
    /// Records `last_tx`. Data on the active route pings it when nothing showed the path for
    /// `cfg.detect_timeout` (or [`DETECT_TIMEOUT`]), for a metered route `cfg.keepalive_timeout`:
    /// neither a ping went out on it nor a frame of the peer arrived on it in that time
    ///. The ping makes a `Verified` route wait for a pong until
    /// `deadline = now + RTO`; a `Reported` route has none, since its pong only shows that the
    /// peer still holds the session. A `Candidate` or `Suspect` route follows its own schedule
    /// instead.
    ///
    /// Reading of §4.2: a frame that arrived "since the previous ping" would skip every later
    /// keeping ping once the first pong had come, and never detect a peer that falls silent; a
    /// frame therefore counts as showing the path for that interval after it arrived, like a
    /// ping. The pong of the previous ping is such a frame.
    pub(crate) fn on_sent(&mut self, now: Instant, cfg: &Config, path: Path, data: bool) {
        let Some(i) = self.index(&path) else {
            return;
        };
        self.routes[i].last_tx = Some(now);
        if !data || self.active.is_none_or(|a| a.path != path) {
            return;
        }
        let r = &mut self.routes[i];
        let interval = if r.spec.class.metered {
            cfg.keepalive_timeout
        } else {
            cfg.detect_timeout.unwrap_or(DETECT_TIMEOUT)
        };
        if r.last_ping
            .max(r.last_rx)
            .is_some_and(|t| now - t < interval)
        {
            return;
        }
        if let State::Verified { last_pong, .. } = r.state {
            let deadline = (!r.reported()).then(|| now + r.rto());
            r.state = State::Verified {
                last_pong,
                deadline,
            };
            self.ping(now, i);
        }
    }

    /// Runs every timer due at `now`.
    ///
    /// For each route:
    /// - `Candidate`: the ping of the latest offset that is due, if not yet sent (one ping per
    ///   call even if several offsets passed). Once all seven went out and
    ///   `since + EPISODE[6] + RTO` has passed: `Failed { retry_at: now + keepalive_timeout }`, with
    ///   [`Do::Failed`] for an `Origin::Candidate` route.
    /// - `Verified` past its `deadline`: `Suspect { misses: 1, deadline: now + 2 × RTO }` and a
    ///   ping. Without a deadline, a non-reported route whose `last_tx` is [`NAT_KEEPALIVE`]
    ///   old gets a ping with `deadline = now + RTO`.
    /// - `Suspect` past its `deadline`: with 2 misses, `Failed { retry_at: now + keepalive_timeout }`
    ///   and [`Do::Failed`] for an `Origin::Candidate` route; else one more miss, a ping,
    ///   `deadline = now + RTO × 2^misses`.
    /// - `Failed` at `retry_at`: a learned route is dropped. Any other gets one ping if it could
    ///   win (§4.1), and the next `keepalive_timeout` later; if it could not it is left alone.
    ///
    /// Pings due in one call go out in rank order. Then the routes that could win and whose turn
    /// in their class has come start, the active route's `revert_at`, the end of a settle, the
    /// end of the fallback delay and the active route are handled, and the on-demand fallback
    /// ([`Paths::finish`]).
    pub(crate) fn handle_timeout(&mut self, now: Instant, cfg: &Config) {
        let could: Vec<bool> = (0..self.routes.len()).map(|i| self.could_win(i)).collect();
        let mut ping = Vec::new();
        let mut failed = Vec::new();
        let mut gone = Vec::new();
        for (i, r) in self.routes.iter_mut().enumerate() {
            let rto = r.rto();
            let candidate = r.spec.origin == Origin::Candidate;
            match r.state {
                State::Dormant => {}
                State::Candidate { since, sent } => {
                    let due = EPISODE
                        .iter()
                        .rposition(|o| since + *o <= now)
                        .filter(|&l| l >= sent);
                    if let Some(l) = due {
                        r.state = State::Candidate { since, sent: l + 1 };
                        ping.push(i);
                    } else if sent == EPISODE.len()
                        && now >= since + EPISODE[EPISODE.len() - 1] + rto
                    {
                        r.state = State::Failed {
                            retry_at: now + cfg.keepalive_timeout,
                        };
                        if candidate {
                            failed.push(r.spec.path);
                        }
                    }
                }
                State::Verified {
                    last_pong,
                    deadline,
                } => match deadline {
                    Some(d) if now >= d => {
                        r.state = State::Suspect {
                            misses: 1,
                            deadline: now + rto * 2,
                        };
                        ping.push(i);
                    }
                    None if !r.reported()
                        && r.last_tx.unwrap_or(last_pong) + NAT_KEEPALIVE <= now =>
                    {
                        r.state = State::Verified {
                            last_pong,
                            deadline: Some(now + rto),
                        };
                        ping.push(i);
                    }
                    _ => {}
                },
                State::Suspect { misses, deadline } if now >= deadline => {
                    if misses >= 2 {
                        r.state = State::Failed {
                            retry_at: now + cfg.keepalive_timeout,
                        };
                        if candidate {
                            failed.push(r.spec.path);
                        }
                    } else {
                        let misses = misses + 1;
                        r.state = State::Suspect {
                            misses,
                            deadline: now + rto * (1u32 << misses),
                        };
                        ping.push(i);
                    }
                }
                State::Suspect { .. } => {}
                State::Failed { retry_at } if now >= retry_at => {
                    if r.spec.origin == Origin::Learned {
                        gone.push(i);
                    } else if could[i] {
                        r.state = State::Failed {
                            retry_at: now + cfg.keepalive_timeout,
                        };
                        r.last_triggered = Some(now);
                        ping.push(i);
                    }
                }
                State::Failed { .. } => {}
            }
        }
        self.ping_all(now, ping);
        self.out.extend(failed.into_iter().map(Do::Failed));
        self.drop_routes(&gone);
        self.settle_routes(now, cfg);
    }

    /// The earliest instant at which [`Paths::handle_timeout`] has work: the next ping or end of
    /// an episode, the next start in a class, deadlines, NAT keepalives, retries,
    /// `revert_at`, the settle, the fallback delay and the on-demand fallback (which waits for the
    /// last unmetered probe to end).
    pub(crate) fn poll_timeout(&self, cfg: &Config) -> Option<Instant> {
        let mut t = Vec::new();
        for (i, r) in self.routes.iter().enumerate() {
            match r.state {
                State::Dormant => {}
                State::Candidate { since, sent, .. } => t.push(match EPISODE.get(sent) {
                    Some(o) => since + *o,
                    None => since + EPISODE[EPISODE.len() - 1] + r.rto(),
                }),
                State::Verified {
                    last_pong,
                    deadline,
                } => match deadline {
                    Some(d) => t.push(d),
                    None if !r.reported() => {
                        t.push(r.last_tx.unwrap_or(last_pong) + NAT_KEEPALIVE);
                    }
                    None => {}
                },
                State::Suspect { deadline, .. } => t.push(deadline),
                State::Failed { retry_at } => {
                    if r.spec.origin == Origin::Learned || self.could_win(i) {
                        t.push(retry_at);
                    }
                }
            }
        }
        t.extend(self.next_start());
        t.extend(self.active.and_then(|a| a.revert_at));
        t.extend(self.settle.map(|s| s.until));
        t.extend(self.grace_until);
        if let Demand::Wanting { at } = self.demand
            && self.may_demand(cfg)
        {
            t.push(at);
        }
        t.into_iter().min()
    }

    /// Takes the next thing to do.
    pub(crate) fn poll(&mut self) -> Option<Do> {
        self.out.pop_front()
    }

    /// The active route, if any.
    pub(crate) fn active(&self) -> Option<Active> {
        let a = self.active?;
        let r = &self.routes[self.index(&a.path)?];
        Some(Active {
            path: a.path,
            class: r.spec.class,
            label: r.spec.label,
            verified: a.revert_at.is_none(),
            meter: r.meter,
        })
    }

    /// Where traffic of `class` goes now: the active route if its class meets
    /// `class`, degraded if it does not and `class.degrade`, else wait.
    pub(crate) fn route_for(&self, class: &DeliveryClass) -> Delivery {
        match self.active() {
            Some(a) if class.met_by(&a.class) => Delivery::Route(a.path),
            Some(a) if class.degrade => Delivery::Degraded(a.path),
            _ => Delivery::Wait,
        }
    }

    /// Every route, in rank order.
    pub(crate) fn routes(&self) -> Vec<RouteInfo> {
        let mut all: Vec<usize> = (0..self.routes.len()).collect();
        all.sort_by_key(|&i| self.routes[i].rank());
        all.into_iter()
            .map(|i| (i, &self.routes[i]))
            .map(|(i, r)| RouteInfo {
                path: r.spec.path,
                class: r.spec.class,
                label: r.spec.label,
                status: match r.state {
                    State::Dormant => Status::Dormant,
                    State::Candidate { .. } => Status::Candidate,
                    State::Verified { .. } => Status::Verified,
                    State::Suspect { .. } => Status::Suspect,
                    State::Failed { .. } => Status::Failed,
                },
                srtt: r.rtt.srtt(),
                active: self.active.is_some_and(|a| a.path == r.spec.path),
                meter: r.meter,
                next: match r.state {
                    State::Failed { retry_at } if r.spec.origin == Origin::Learned => {
                        Some(Next::Forget(retry_at))
                    }
                    State::Failed { retry_at } if self.could_win(i) => Some(Next::Retry(retry_at)),
                    _ => None,
                },
            })
            .collect()
    }

    /// Where a `cand`, `svc` or `svcack` goes: every reported route, then the active route if it
    /// is not one of them.
    pub(crate) fn control_paths(&self) -> Vec<Path> {
        let mut out: Vec<Path> = self
            .routes
            .iter()
            .filter(|r| r.reported())
            .map(|r| r.spec.path)
            .collect();
        if let Some(a) = self.active
            && !out.contains(&a.path)
        {
            out.push(a.path);
        }
        out
    }

    /// The paths of the learned routes, which the peer lists again in its next [`Spec`]s while
    /// their transport still reaches them.
    pub(crate) fn learned(&self) -> impl Iterator<Item = Path> + '_ {
        self.routes
            .iter()
            .filter(|r| r.spec.origin == Origin::Learned)
            .map(|r| r.spec.path)
    }

    /// Whether a route on `path` exists.
    pub(crate) fn knows(&self, path: &Path) -> bool {
        self.index(path).is_some()
    }

    /// The smoothed round-trip time of the active route, once it has a sample.
    pub(crate) fn active_srtt(&self) -> Option<Duration> {
        self.active
            .and_then(|a| self.index(&a.path))
            .and_then(|i| self.routes[i].rtt.srtt())
    }

    /// The RTO of the active route, or of a route without samples.
    pub(crate) fn rto(&self) -> Duration {
        self.active
            .and_then(|a| self.index(&a.path))
            .map_or(INITIAL_RTO, |i| self.routes[i].rto())
    }

    /// Whether some candidate route is still in its episode.
    pub(crate) fn probing(&self) -> bool {
        self.routes
            .iter()
            .any(|r| matches!(r.state, State::Candidate { .. }))
    }

    /// Whether the on-demand fallback is armed.
    pub(crate) fn fallback(&self) -> bool {
        matches!(self.demand, Demand::Wanting { .. })
    }

    fn index(&self, path: &Path) -> Option<usize> {
        self.routes.iter().position(|r| r.spec.path == *path)
    }

    fn active_index(&self) -> Option<usize> {
        self.active.and_then(|a| self.index(&a.path))
    }

    /// Whether route `i` could become the active route: with no active
    /// route every route; otherwise a route of strictly better class than the active one's;
    /// while the active route is unverified also those of its class; while it is `Suspect`
    /// every route. The active route itself always could. A `Reported` route is never probed.
    fn could_win(&self, i: usize) -> bool {
        let r = &self.routes[i];
        if r.reported() {
            return false;
        }
        let Some(ai) = self.active_index() else {
            return true;
        };
        if ai == i {
            return true;
        }
        let a = &self.routes[ai];
        let (rk, ak) = (class_key(&r.spec.class), class_key(&a.spec.class));
        match a.state {
            State::Verified { .. } => rk < ak,
            State::Suspect { .. } => true,
            _ => rk <= ak,
        }
    }

    /// Sends a ping on route `i`.
    fn ping(&mut self, now: Instant, i: usize) {
        let txid = self.next_txid;
        self.next_txid = self.next_txid.wrapping_add(1);
        let r = &mut self.routes[i];
        r.last_ping = Some(now);
        r.last_tx = Some(now);
        let path = r.spec.path;
        self.pings.push_back(SentPing {
            txid,
            path,
            at: now,
        });
        if self.pings.len() > SENT_PINGS {
            self.pings.pop_front();
        }
        self.out.push_back(Do::Ping { path, txid });
    }

    /// Starts the episode of route `i`: its ping at offset 0 goes out.
    fn start(&mut self, now: Instant, i: usize) {
        let r = &mut self.routes[i];
        r.state = episode(now);
        r.started = Some(now);
        self.ping(now, i);
    }

    fn trigger(&mut self, now: Instant, i: usize) {
        self.routes[i].last_triggered = Some(now);
        self.ping(now, i);
    }

    /// Pings the routes `idx` in rank order.
    fn ping_all(&mut self, now: Instant, mut idx: Vec<usize>) {
        idx.sort_by_key(|&i| self.routes[i].rank());
        for i in idx {
            self.ping(now, i);
        }
    }

    fn pong(&mut self, now: Instant, path: Path, txid: u64, observed: Option<SocketAddr>) {
        if let Some(i) = self.index(&path) {
            self.routes[i].last_tx = Some(now);
        }
        self.out.push_back(Do::Pong {
            path,
            txid,
            observed,
        });
    }

    /// Removes the routes at `gone` (none of them the active route).
    fn drop_routes(&mut self, gone: &[usize]) {
        if gone.is_empty() {
            return;
        }
        let mut i = 0;
        self.routes.retain(|_| {
            i += 1;
            !gone.contains(&(i - 1))
        });
    }

    /// After any change: selects the active route, applies the probing rules and updates the
    /// on-demand fallback and the session loss check.
    fn settle_routes(&mut self, now: Instant, cfg: &Config) {
        self.select(now, cfg);
        self.maintain(now, cfg);
        self.finish(now, cfg);
    }

    /// The probing rules for the current active route.
    ///
    /// - Once the active route is `Verified`, only it and the best `Verified` route of each other
    ///   class are kept: the others become `Dormant`, learned ones are dropped.
    /// - A `Candidate` that could no longer win stops and becomes `Dormant`, a learned one is
    ///   dropped; a roamed route whose first ping went unanswered becomes `Failed` instead, so
    ///   that the next data does not roam onto it again.
    /// - In each class without a `Verified` route, the `Dormant` route that ranks best among
    ///   those that could win starts, if no route of the class started in the last [`MIN_RTO`].
    ///
    /// Reading of rule 2: a `Verified` route of a class stops the starts of its class even while
    /// the active route is unverified (after roaming) or `Suspect` and is of another class.
    fn maintain(&mut self, now: Instant, cfg: &Config) {
        let mut gone = Vec::new();
        if let Some(ai) = self.active_index()
            && matches!(self.routes[ai].state, State::Verified { .. })
        {
            let mut kept = vec![class_key(&self.routes[ai].spec.class)];
            let mut order: Vec<usize> = (0..self.routes.len()).collect();
            order.sort_by_key(|&i| self.routes[i].rank());
            for i in order {
                let r = &mut self.routes[i];
                if i == ai || r.reported() || !matches!(r.state, State::Verified { .. }) {
                    continue;
                }
                let key = class_key(&r.spec.class);
                if kept.contains(&key) {
                    if r.spec.origin == Origin::Learned {
                        gone.push(i);
                    } else {
                        r.state = State::Dormant;
                    }
                } else {
                    kept.push(key);
                }
            }
        }
        let reverted = self.reverted.take();
        for i in 0..self.routes.len() {
            if matches!(self.routes[i].state, State::Candidate { .. }) && !self.could_win(i) {
                if Some(self.routes[i].spec.path) == reverted {
                    self.routes[i].state = State::Failed {
                        retry_at: now + cfg.keepalive_timeout,
                    };
                } else if self.routes[i].spec.origin == Origin::Learned {
                    gone.push(i);
                } else {
                    self.routes[i].state = State::Dormant;
                }
            }
        }
        self.drop_routes(&gone);
        let mut starts: Vec<usize> = self
            .class_turns()
            .into_iter()
            .filter(|&(_, due)| due.is_none_or(|d| d <= now))
            .map(|(i, _)| i)
            .collect();
        starts.sort_by_key(|&i| self.routes[i].rank());
        for i in starts {
            self.start(now, i);
        }
    }

    /// For each class without a `Verified` route that has a `Dormant` route which could win: the
    /// best-ranked such route and when its turn comes (`None`: now).
    fn class_turns(&self) -> Vec<(usize, Option<Instant>)> {
        let mut keys: Vec<ClassKey> = Vec::new();
        for r in self.routes.iter().filter(|r| !r.reported()) {
            let key = class_key(&r.spec.class);
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        let mut out = Vec::new();
        for key in keys {
            let members: Vec<usize> = (0..self.routes.len())
                .filter(|&i| {
                    !self.routes[i].reported() && class_key(&self.routes[i].spec.class) == key
                })
                .collect();
            if members
                .iter()
                .any(|&i| matches!(self.routes[i].state, State::Verified { .. }))
            {
                continue;
            }
            let next = members
                .iter()
                .copied()
                .filter(|&i| matches!(self.routes[i].state, State::Dormant) && self.could_win(i))
                .min_by_key(|&i| self.routes[i].rank());
            let Some(next) = next else {
                continue;
            };
            let due = members
                .iter()
                .filter_map(|&i| self.routes[i].started)
                .max()
                .map(|s| s + MIN_RTO);
            out.push((next, due));
        }
        out
    }

    /// When the next route of a class that has to wait for its turn starts.
    fn next_start(&self) -> Option<Instant> {
        self.class_turns()
            .into_iter()
            .filter_map(|(_, due)| due)
            .min()
    }

    fn usable(&self, i: usize, cfg: &Config) -> bool {
        let r = &self.routes[i];
        match r.state {
            State::Verified { .. } => cfg.switch_data || !r.reported(),
            State::Suspect { .. } | State::Candidate { .. } => {
                self.active.is_some_and(|a| a.path == r.spec.path)
            }
            State::Dormant | State::Failed { .. } => false,
        }
    }

    /// The best usable route among those `keep` accepts.
    fn best(&self, cfg: &Config, keep: impl Fn(usize) -> bool) -> Option<usize> {
        (0..self.routes.len())
            .filter(|&i| self.usable(i, cfg) && keep(i))
            .min_by_key(|&i| self.routes[i].rank())
    }

    /// The route that the last selection rule moves to from route `ai`, if any: the best
    /// usable route of strictly better class.
    fn better_than(&self, ai: usize, cfg: &Config) -> Option<usize> {
        let ak = class_key(&self.routes[ai].spec.class);
        self.best(cfg, |i| {
            i != ai && class_key(&self.routes[i].spec.class) < ak
        })
    }

    fn activate(&mut self, i: usize) {
        self.active = Some(ActiveRoute {
            path: self.routes[i].spec.path,
            revert_at: None,
        });
        self.settle = None;
        self.grace_until = None;
    }

    fn lose_active(&mut self, now: Instant, cfg: &Config, reported: bool) {
        self.active = None;
        self.settle = None;
        if !reported && !cfg.fallback_delay.is_zero() {
            self.grace_until = Some(now + cfg.fallback_delay);
        }
    }

    /// The latest end of the RTO of an outstanding ping on an unmetered candidate route that
    /// outranks route `t`.
    fn outstanding_better(&self, t: usize, now: Instant) -> Option<Instant> {
        let rank = self.routes[t].rank();
        self.routes
            .iter()
            .filter(|r| {
                !r.spec.class.metered
                    && r.rank() < rank
                    && matches!(r.state, State::Candidate { .. })
            })
            .flat_map(|r| {
                self.pings
                    .iter()
                    .filter(|p| p.path == r.spec.path)
                    .map(|p| p.at + r.rto())
            })
            .filter(|end| *end > now)
            .max()
    }

    /// Makes route `t` active, unless it is metered and a better unmetered route is still being
    /// waited for (rule 5 of selection).
    fn move_to(&mut self, now: Instant, t: usize) {
        let r = &self.routes[t];
        if r.spec.class.metered
            && let Some(cap) = self.outstanding_better(t, now)
        {
            let to = r.spec.path;
            let until = match self.settle {
                Some(s) if s.to == to => s.until,
                _ => {
                    let until = r.rtt.srtt().map_or(cap, |s| cap.min(now + s * 2));
                    self.settle = Some(Settle { to, until });
                    until
                }
            };
            if now < until {
                return;
            }
        }
        self.activate(t);
    }

    /// Picks the active route.
    ///
    /// Usable routes: `Verified` ones (reported ones only with `cfg.switch_data`), and the
    /// active route while `Suspect` or unverified. Rank: band, then not metered, then latency,
    /// then smoothed RTT (none last); the class is the first three.
    ///
    /// 1. The active route is lost if its route is gone, `Failed` or `Dormant`, or it is
    ///    unverified and past `revert_at`. Losing a non-reported active route starts the switch
    ///    delay (`grace_until = now + cfg.fallback_delay`, unless zero).
    /// 2. No active route: the best usable route; reported ones only after the fallback delay.
    /// 3. Active `Suspect`: the best other usable route, of any rank; it stays if there is none.
    /// 4. Otherwise: only a route of strictly better class.
    /// 5. A move onto a metered route while an unmetered candidate route of better rank has a
    ///    ping out that is not yet past its RTO waits until that pong or
    ///    `min(2 × srtt of the metered route, the outstanding ping's sent + RTO)`; other moves
    ///    happen at once.
    ///
    /// Reading of rule 5: it applies to a move away from an active route. With none, the best
    /// usable route is taken at once.
    fn select(&mut self, now: Instant, cfg: &Config) {
        if let Some(a) = self.active {
            let lost = match self.index(&a.path).map(|i| &self.routes[i]) {
                None => Some(false),
                Some(r) => match r.state {
                    State::Failed { .. } | State::Dormant => Some(r.reported()),
                    State::Candidate { .. } if a.revert_at.is_some_and(|t| now >= t) => {
                        self.reverted = Some(a.path);
                        Some(r.reported())
                    }
                    _ => None,
                },
            };
            if let Some(reported) = lost {
                self.lose_active(now, cfg, reported);
            }
        }
        if self.grace_until.is_some_and(|g| now >= g) {
            self.grace_until = None;
        }
        match self.active_index() {
            None => {
                let grace = self.grace_until.is_some();
                if let Some(i) = self.best(cfg, |i| !(grace && self.routes[i].reported())) {
                    self.activate(i);
                }
                self.settle = None;
            }
            Some(ai) => {
                let target = if matches!(self.routes[ai].state, State::Suspect { .. }) {
                    self.best(cfg, |i| i != ai)
                } else {
                    self.better_than(ai, cfg)
                };
                match target {
                    Some(t) => self.move_to(now, t),
                    None => self.settle = None,
                }
            }
        }
        if let Some(a) = &mut self.active
            && let Some(i) = self.routes.iter().position(|r| r.spec.path == a.path)
            && !matches!(self.routes[i].state, State::Candidate { .. })
        {
            a.revert_at = None;
        }
    }

    /// Whether an unmetered route is still being probed: one is a `Candidate`, or one that could
    /// win waits for its turn in its class.
    fn probing_unmetered(&self) -> bool {
        self.routes
            .iter()
            .any(|r| !r.spec.class.metered && matches!(r.state, State::Candidate { .. }))
            || self
                .class_turns()
                .into_iter()
                .any(|(i, _)| !self.routes[i].spec.class.metered)
    }

    /// Whether the on-demand fallback may ask once its time has come: no unmetered route is still
    /// being probed, or `cfg.fallback_delay` is zero.
    fn may_demand(&self, cfg: &Config) -> bool {
        cfg.fallback_delay.is_zero() || !self.probing_unmetered()
    }

    /// Updates the on-demand fallback: `Demand` becomes `Satisfied` if an unmetered route is
    /// usable, and goes from `Satisfied` to `Wanting { at: now + cfg.fallback_delay }` if none is.
    /// A `Wanting` whose `at` has passed emits [`Do::Demand`] once no unmetered route is still
    /// being probed, and `at` moves on by `cfg.keepalive_timeout`. Emits
    /// [`Do::Lost`] once, when no reported route is left and every other route is `Failed`
    ///.
    fn finish(&mut self, now: Instant, cfg: &Config) {
        let unmetered = (0..self.routes.len())
            .any(|i| self.usable(i, cfg) && !self.routes[i].spec.class.metered);
        self.demand = match (self.demand, unmetered) {
            (_, true) => Demand::Satisfied,
            (Demand::Satisfied, false) => Demand::Wanting {
                at: now + cfg.fallback_delay,
            },
            (wanting, false) => wanting,
        };
        if let Demand::Wanting { at } = self.demand
            && now >= at
            && self.may_demand(cfg)
        {
            self.out.push_back(Do::Demand);
            self.demand = Demand::Wanting {
                at: now + cfg.keepalive_timeout,
            };
        }
        let lost = self
            .routes
            .iter()
            .all(|r| !r.reported() && matches!(r.state, State::Failed { .. }));
        if lost && !self.lost {
            self.out.push_back(Do::Lost);
        }
        self.lost = lost;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{NodePublic, NodeSecret};
    use crate::route::class::{WantBand, WantLatency};
    use crate::sim::SimRng;
    use crate::transport::{Remote, TransportId};

    const LAN: RouteClass = RouteClass {
        band: Band::High,
        latency: Latency::Low,
        metered: false,
    };
    const NET: RouteClass = RouteClass {
        band: Band::High,
        latency: Latency::High,
        metered: false,
    };
    const RELAY: RouteClass = RouteClass {
        band: Band::High,
        latency: Latency::High,
        metered: true,
    };
    const SWITCH: RouteClass = RouteClass {
        band: Band::Low,
        latency: Latency::High,
        metered: true,
    };

    fn at(ms: u64) -> Instant {
        Instant::from_millis(ms)
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn key(n: u64) -> NodePublic {
        NodeSecret::generate(&mut SimRng::new(n)).public()
    }

    fn path(via: u16, a: &str) -> Path {
        Path {
            via: TransportId(via),
            to: Remote::Addr(a.parse().unwrap()),
        }
    }

    fn switch_path() -> Path {
        Path {
            via: TransportId(9),
            to: Remote::Peer(key(1)),
        }
    }

    fn spec(path: Path, class: RouteClass, label: &'static str, origin: Origin) -> Spec {
        Spec {
            path,
            class,
            label,
            origin,
        }
    }

    fn lan(a: &str) -> Spec {
        spec(path(0, a), LAN, "lan", Origin::Candidate)
    }

    fn net(a: &str) -> Spec {
        spec(path(0, a), NET, "punch", Origin::Candidate)
    }

    fn relay(a: &str) -> Spec {
        spec(path(1, a), RELAY, "relay", Origin::Candidate)
    }

    fn sw() -> Spec {
        spec(switch_path(), SWITCH, "switch", Origin::Reported)
    }

    fn learned(a: &str) -> Spec {
        spec(path(0, a), NET, "learned", Origin::Learned)
    }

    const A1: &str = "203.0.113.1:1000";
    const A2: &str = "203.0.113.2:1000";
    const A3: &str = "203.0.113.3:1000";
    const L1: &str = "192.168.1.5:1000";

    fn dos(p: &mut Paths) -> Vec<Do> {
        std::iter::from_fn(|| p.poll()).collect()
    }

    fn ping_paths(d: &[Do]) -> Vec<Path> {
        d.iter()
            .filter_map(|d| match d {
                Do::Ping { path, .. } => Some(*path),
                _ => None,
            })
            .collect()
    }

    fn txid_on(p: &Paths, path: Path) -> u64 {
        p.pings.iter().rev().find(|s| s.path == path).unwrap().txid
    }

    fn answer(p: &mut Paths, c: &Config, now: Instant, path: Path) {
        let txid = txid_on(p, path);
        p.on_pong(now, c, path, txid);
    }

    fn sample(p: &mut Paths, c: &Config, path: Path, sent: u64, rtt: u64) {
        let i = p.index(&path).unwrap();
        p.ping(at(sent), i);
        answer(p, c, at(sent + rtt), path);
        dos(p);
    }

    fn status(p: &Paths, path: Path) -> Status {
        p.routes()
            .into_iter()
            .find(|r| r.path == path)
            .unwrap()
            .status
    }

    fn next(p: &Paths, path: Path) -> Option<Next> {
        p.routes()
            .into_iter()
            .find(|r| r.path == path)
            .unwrap()
            .next
    }

    fn active_path(p: &Paths) -> Option<Path> {
        p.active().map(|a| a.path)
    }

    /// Runs the timers up to and including `until`, returning what each call produced.
    fn run(p: &mut Paths, c: &Config, until: u64) -> Vec<(Instant, Do)> {
        let mut log = Vec::new();
        let mut last = Instant::ZERO;
        for _ in 0..10_000 {
            let Some(t) = p.poll_timeout(c).filter(|t| *t <= at(until)) else {
                return log;
            };
            last = last.max(t);
            p.handle_timeout(last, c);
            log.extend(std::iter::from_fn(|| p.poll()).map(|d| (last, d)));
        }
        panic!("timers do not settle");
    }

    /// Like [`run`], with the peer answering at once every ping that went out on `path`.
    fn run_answering(p: &mut Paths, c: &Config, path: Path, until: u64) -> Vec<(Instant, Do)> {
        let mut log = Vec::new();
        let mut last = Instant::ZERO;
        for _ in 0..10_000 {
            let Some(t) = p.poll_timeout(c).filter(|t| *t <= at(until)) else {
                return log;
            };
            last = last.max(t);
            p.handle_timeout(last, c);
            let batch: Vec<Do> = std::iter::from_fn(|| p.poll()).collect();
            for d in &batch {
                if let Do::Ping { path: on, txid } = d
                    && *on == path
                {
                    p.on_pong(last, c, path, *txid);
                }
            }
            log.extend(batch.into_iter().map(|d| (last, d)));
        }
        panic!("timers do not settle");
    }

    fn ping_times(log: &[(Instant, Do)], path: Path) -> Vec<u64> {
        log.iter()
            .filter(|(_, d)| matches!(d, Do::Ping { path: p, .. } if *p == path))
            .map(|(t, _)| t.as_duration().as_millis() as u64)
            .collect()
    }

    fn new(specs: &[Spec], verified: Option<Path>) -> (Paths, Config) {
        let c = Config::default();
        let mut p = Paths::new(at(0), &c, specs, verified);
        dos(&mut p);
        (p, c)
    }

    /// A punch route that failed while the switch was active, and a LAN route that has since
    /// become active: the punch route could not win any more.
    fn failed_under_a_better_active_route() -> (Paths, Config) {
        let (mut p, c) = new(&[net(A1), sw()], None);
        run(&mut p, &c, 4_200);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        p.sync(at(5_000), &c, &[lan(L1), net(A1), sw()]);
        answer(&mut p, &c, at(5_030), path(0, L1));
        dos(&mut p);
        assert_eq!(active_path(&p), Some(path(0, L1)));
        (p, c)
    }

    // ---- first round -----------------------------------------------------------------------

    #[test]
    fn the_path_message_2_arrived_on_starts_verified_and_a_route_that_could_not_win_is_dormant() {
        let (p, _) = new(&[lan(L1), net(A1), sw()], Some(path(0, L1)));
        assert_eq!(status(&p, path(0, L1)), Status::Verified);
        assert_eq!(status(&p, path(0, A1)), Status::Dormant);
        assert_eq!(status(&p, switch_path()), Status::Verified);
        assert_eq!(active_path(&p), Some(path(0, L1)));
        assert!(p.active().unwrap().verified);
    }

    #[test]
    fn a_route_that_could_win_starts_probing_at_once_next_to_the_verified_path() {
        let (p, _) = new(&[net(A1), lan(L1), sw()], Some(path(0, A1)));
        assert_eq!(status(&p, path(0, A1)), Status::Verified);
        assert_eq!(status(&p, path(0, L1)), Status::Candidate);
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    #[test]
    fn a_reported_route_is_verified_and_active_at_once() {
        let (p, _) = new(&[net(A1), sw()], None);
        assert_eq!(status(&p, switch_path()), Status::Verified);
        let a = p.active().unwrap();
        assert_eq!(
            (a.path, a.label, a.verified),
            (switch_path(), "switch", true)
        );
    }

    #[test]
    fn the_first_round_pings_the_active_route_then_the_routes_that_could_win_in_rank_order() {
        let c = Config::default();
        let specs = [
            net(A1),
            sw(),
            relay(A2),
            lan(L1),
            net(A2),
            lan("192.168.1.6:1000"),
        ];
        let mut p = Paths::new(at(0), &c, &specs, Some(path(0, A1)));
        let d = dos(&mut p);
        assert_eq!(ping_paths(&d), [path(0, A1), path(0, L1)]);
        let txids: Vec<u64> = d
            .iter()
            .filter_map(|d| match d {
                Do::Ping { txid, .. } => Some(*txid),
                _ => None,
            })
            .collect();
        assert_eq!(txids, [0, 1]);
        assert_eq!(status(&p, path(0, A2)), Status::Dormant);
        assert_eq!(status(&p, path(1, A2)), Status::Dormant);
        assert_eq!(status(&p, switch_path()), Status::Verified);
    }

    #[test]
    fn the_first_ping_goes_on_a_reported_active_route() {
        let c = Config::default();
        let mut p = Paths::new(at(0), &c, &[sw()], None);
        assert_eq!(ping_paths(&dos(&mut p)), [switch_path()]);
    }

    #[test]
    fn with_no_active_route_there_is_no_first_ping_and_every_class_probes() {
        let c = Config::default();
        let mut p = Paths::new(at(0), &c, &[net(A1), relay(A2), lan(L1)], None);
        assert_eq!(active_path(&p), None);
        assert_eq!(
            ping_paths(&dos(&mut p)),
            [path(0, L1), path(0, A1), path(1, A2)]
        );
    }

    #[test]
    fn the_active_verified_probe_route_must_answer_the_first_ping() {
        let (mut p, c) = new(&[net(A1), sw()], Some(path(0, A1)));
        assert_eq!(status(&p, path(0, A1)), Status::Verified);
        run(&mut p, &c, 1000);
        assert_eq!(status(&p, path(0, A1)), Status::Suspect);
    }

    #[test]
    fn a_reported_route_never_gets_a_deadline_or_turns_suspect() {
        let (mut p, c) = new(&[sw()], None);
        run(&mut p, &c, 120_000);
        assert_eq!(status(&p, switch_path()), Status::Verified);
        assert_eq!(active_path(&p), Some(switch_path()));
    }

    #[test]
    fn at_most_max_routes_are_held_in_the_order_of_the_specs() {
        let specs: Vec<Spec> = (0..60)
            .map(|i| net(&format!("203.0.113.9:{}", 1000 + i)))
            .collect();
        let (p, _) = new(&specs, None);
        let paths: Vec<Path> = p.routes().iter().map(|r| r.path).collect();
        assert_eq!(paths.len(), MAX_ROUTES);
        assert_eq!(paths[0], specs[0].path);
        assert_eq!(paths[MAX_ROUTES - 1], specs[MAX_ROUTES - 1].path);
    }

    #[test]
    fn duplicate_specs_make_one_route() {
        let (p, _) = new(&[net(A1), net(A1), sw()], None);
        assert_eq!(p.routes().len(), 2);
    }

    // ---- episode ---------------------------------------------------------------------------

    #[test]
    fn a_candidate_is_pinged_at_its_episode_offsets() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        let log = run(&mut p, &c, 5000);
        assert_eq!(
            ping_times(&log, path(0, A1)),
            [100, 200, 400, 800, 1600, 3200]
        );
    }

    #[test]
    fn a_candidate_fails_one_rto_after_the_last_ping_and_the_source_hears_of_it_once() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        let log = run(&mut p, &c, 4199);
        assert_eq!(status(&p, path(0, A1)), Status::Candidate);
        assert!(!log.iter().any(|(_, d)| matches!(d, Do::Failed(_))));
        let log = run(&mut p, &c, 4200);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        assert_eq!(
            log,
            [(at(4200), Do::Failed(path(0, A1))), (at(4200), Do::Demand)]
        );
    }

    #[test]
    fn the_end_of_an_episode_follows_the_rto_of_the_route() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        let i = p.index(&path(0, A1)).unwrap();
        p.routes[i].rtt.sample(ms(50));
        assert_eq!(p.routes[i].rto(), ms(200));
        run(&mut p, &c, 3399);
        assert_eq!(status(&p, path(0, A1)), Status::Candidate);
        run(&mut p, &c, 3400);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
    }

    #[test]
    fn a_failed_learned_route_is_not_announced_and_is_dropped_when_it_would_be_retried() {
        let (mut p, c) = new(&[sw()], None);
        p.on_ping(at(0), &c, learned(A1), 7);
        dos(&mut p);
        let log = run(&mut p, &c, 4200);
        assert!(!log.iter().any(|(_, d)| matches!(d, Do::Failed(_))));
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        assert_eq!(next(&p, path(0, A1)), Some(Next::Forget(at(14_200))));
        run(&mut p, &c, 14_199);
        assert_eq!(p.learned().count(), 1);
        run(&mut p, &c, 14_200);
        assert_eq!(p.learned().count(), 0);
    }

    #[test]
    fn a_pong_ends_the_episode() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        run(&mut p, &c, 150);
        answer(&mut p, &c, at(150), path(0, A1));
        let log = run(&mut p, &c, 6000);
        assert_eq!(ping_times(&log, path(0, A1)), Vec::<u64>::new());
        assert_eq!(status(&p, path(0, A1)), Status::Verified);
        assert!(!p.probing());
    }

    #[test]
    fn pings_due_at_one_instant_go_out_in_rank_order() {
        let (mut p, c) = new(&[net(A1), lan(L1), relay(A2), sw()], None);
        let log = run(&mut p, &c, 100);
        let order: Vec<Path> = log
            .iter()
            .filter_map(|(_, d)| match d {
                Do::Ping { path, .. } => Some(*path),
                _ => None,
            })
            .collect();
        assert_eq!(order, [path(0, L1), path(0, A1), path(1, A2)]);
    }

    #[test]
    fn one_ping_goes_out_per_call_even_if_several_offsets_passed() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        p.handle_timeout(at(900), &c);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A1)]);
        p.handle_timeout(at(1000), &c);
        assert!(ping_paths(&dos(&mut p)).is_empty());
    }

    // ---- pongs -----------------------------------------------------------------------------

    #[test]
    fn a_pong_verifies_the_route_its_ping_went_out_on_whichever_path_it_returns_on() {
        let (mut p, c) = new(&[net(A1), relay(A2), sw()], None);
        let txid = txid_on(&p, path(1, A2));
        p.on_pong(at(40), &c, path(0, A1), txid);
        assert_eq!(status(&p, path(1, A2)), Status::Verified);
        assert_eq!(status(&p, path(0, A1)), Status::Candidate);
        let r = p
            .routes()
            .into_iter()
            .find(|r| r.path == path(1, A2))
            .unwrap();
        assert_eq!(r.srtt, Some(ms(40)));
    }

    #[test]
    fn a_pong_with_an_unknown_txid_is_ignored() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        p.on_pong(at(40), &c, path(0, A1), 999);
        assert_eq!(status(&p, path(0, A1)), Status::Candidate);
    }

    #[test]
    fn a_txid_is_matched_once() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        let txid = txid_on(&p, path(0, A1));
        p.on_pong(at(40), &c, path(0, A1), txid);
        p.on_pong(at(900), &c, path(0, A1), txid);
        let r = p
            .routes()
            .into_iter()
            .find(|r| r.path == path(0, A1))
            .unwrap();
        assert_eq!(r.srtt, Some(ms(40)));
    }

    #[test]
    fn only_the_last_pings_are_remembered() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        let i = p.index(&path(0, A1)).unwrap();
        for k in 0..SENT_PINGS as u64 + 10 {
            p.ping(at(k), i);
        }
        let old = p.pings.front().unwrap().txid - 1;
        p.on_pong(at(100), &c, path(0, A1), old);
        assert_eq!(status(&p, path(0, A1)), Status::Candidate);
        let newest = p.pings.back().unwrap().txid;
        p.on_pong(at(100), &c, path(0, A1), newest);
        assert_eq!(status(&p, path(0, A1)), Status::Verified);
    }

    #[test]
    fn a_pong_for_a_route_that_is_gone_is_ignored() {
        let (mut p, c) = new(&[net(A1), net(A2), sw()], None);
        let txid = txid_on(&p, path(0, A1));
        p.sync(at(10), &c, &[net(A2), sw()]);
        p.on_pong(at(20), &c, path(0, A1), txid);
        assert_eq!(p.routes().len(), 2);
        assert_eq!(status(&p, path(0, A2)), Status::Candidate);
    }

    // ---- pings -----------------------------------------------------------------------------

    #[test]
    fn a_ping_is_answered_on_its_path_with_the_address_it_came_from() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        p.on_ping(at(10), &c, net(A1), 5);
        let d = dos(&mut p);
        assert!(d.contains(&Do::Pong {
            path: path(0, A1),
            txid: 5,
            observed: Some(A1.parse().unwrap()),
        }));
    }

    #[test]
    fn the_pong_also_goes_on_the_active_route_when_that_is_another_path() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        p.on_ping(at(10), &c, net(A1), 5);
        let pongs: Vec<Path> = dos(&mut p)
            .into_iter()
            .filter_map(|d| match d {
                Do::Pong { path, .. } => Some(path),
                _ => None,
            })
            .collect();
        assert_eq!(pongs, [path(0, A1), switch_path()]);
    }

    #[test]
    fn a_ping_on_the_active_route_gets_one_pong_without_an_address_on_a_keyed_path() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        p.on_ping(at(10), &c, sw(), 5);
        let pongs: Vec<Do> = dos(&mut p)
            .into_iter()
            .filter(|d| matches!(d, Do::Pong { .. }))
            .collect();
        assert_eq!(
            pongs,
            [Do::Pong {
                path: switch_path(),
                txid: 5,
                observed: None
            }]
        );
    }

    #[test]
    fn a_ping_on_a_candidate_route_gets_a_triggered_ping() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        p.on_ping(at(50), &c, net(A1), 5);
        let d = dos(&mut p);
        assert_eq!(ping_paths(&d), [path(0, A1)]);
        assert_eq!(p.pings.back().unwrap().at, at(50));
    }

    #[test]
    fn a_second_ping_within_100_ms_triggers_no_second_ping() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        p.on_ping(at(50), &c, net(A1), 5);
        dos(&mut p);
        p.on_ping(at(149), &c, net(A1), 6);
        assert!(ping_paths(&dos(&mut p)).is_empty());
        p.on_ping(at(150), &c, net(A1), 7);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A1)]);
    }

    #[test]
    fn the_episode_ping_just_before_does_not_suppress_the_triggered_one() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        p.on_ping(at(55), &c, net(A1), 5);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A1)]);
    }

    #[test]
    fn a_ping_on_a_verified_route_triggers_nothing() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        answer(&mut p, &c, at(30), path(0, A1));
        p.on_ping(at(500), &c, net(A1), 5);
        assert!(ping_paths(&dos(&mut p)).is_empty());
    }

    #[test]
    fn a_ping_on_a_failed_route_that_could_win_gets_one_triggered_ping_and_moves_its_retry() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        run(&mut p, &c, 4200);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        p.on_ping(at(4300), &c, net(A1), 5);
        let d = dos(&mut p);
        assert_eq!(ping_paths(&d), [path(0, A1)]);
        assert!(d.iter().any(|d| matches!(d, Do::Pong { txid: 5, .. })));
        assert_eq!(status(&p, path(0, A1)), Status::Failed, "no episode");
        assert_eq!(next(&p, path(0, A1)), Some(Next::Retry(at(14_300))));
        assert_eq!(next(&p, switch_path()), None);
        let log = run(&mut p, &c, 14_299);
        assert!(
            ping_times(&log, path(0, A1)).is_empty(),
            "the retry due at 14.2 s moved to 14.3 s"
        );
        let log = run(&mut p, &c, 14_300);
        assert_eq!(ping_times(&log, path(0, A1)), [14_300]);
        let log = run(&mut p, &c, 24_300);
        assert_eq!(ping_times(&log, path(0, A1)), [24_300]);
    }

    #[test]
    fn pings_on_a_failed_route_within_10_s_of_its_triggered_ping_or_retry_are_only_answered() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        run(&mut p, &c, 4200);
        p.on_ping(at(4300), &c, net(A1), 5);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A1)]);
        for (t, txid) in [(6_300, 6), (14_299, 7)] {
            p.on_ping(at(t), &c, net(A1), txid);
            let d = dos(&mut p);
            assert!(ping_paths(&d).is_empty(), "{t}");
            assert!(d.iter().any(|d| matches!(d, Do::Pong { .. })));
        }
        let log = run(&mut p, &c, 14_300);
        assert_eq!(ping_times(&log, path(0, A1)), [14_300], "the retry");
        p.on_ping(at(18_000), &c, net(A1), 8);
        assert!(ping_paths(&dos(&mut p)).is_empty(), "4 s after the retry");
        p.on_ping(at(24_300), &c, net(A1), 9);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A1)], "10 s after it");
    }

    #[test]
    fn the_pong_to_the_triggered_ping_of_a_failed_route_verifies_it_and_the_active_route_moves_at_once()
     {
        let (mut p, c) = new(&[net(A1), sw()], None);
        run(&mut p, &c, 4200);
        p.on_ping(at(4300), &c, net(A1), 5);
        dos(&mut p);
        let txid = txid_on(&p, path(0, A1));
        p.on_pong(at(4_330), &c, path(0, A1), txid);
        assert_eq!(status(&p, path(0, A1)), Status::Verified);
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    #[test]
    fn a_ping_on_a_failed_route_that_could_not_win_is_only_answered() {
        let (mut p, c) = failed_under_a_better_active_route();
        p.on_ping(at(8_000), &c, net(A1), 5);
        let d = dos(&mut p);
        assert!(ping_paths(&d).is_empty());
        assert!(d.iter().any(|d| matches!(d, Do::Pong { txid: 5, .. })));
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
    }

    #[test]
    fn a_ping_on_a_dormant_route_that_could_not_win_is_only_answered() {
        let (mut p, c) = new(&[lan(L1), net(A1), sw()], Some(path(0, L1)));
        assert_eq!(status(&p, path(0, A1)), Status::Dormant);
        p.on_ping(at(50), &c, net(A1), 5);
        let d = dos(&mut p);
        assert!(ping_paths(&d).is_empty());
        assert!(d.iter().any(|d| matches!(d, Do::Pong { txid: 5, .. })));
        assert_eq!(status(&p, path(0, A1)), Status::Dormant);
    }

    #[test]
    fn a_ping_on_a_dormant_route_that_could_win_starts_its_episode_without_waiting_for_its_turn() {
        let (mut p, c) = new(&[net(A1), net(A2), sw()], None);
        assert_eq!(status(&p, path(0, A2)), Status::Dormant);
        p.on_ping(at(50), &c, net(A2), 5);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A2)]);
        assert_eq!(status(&p, path(0, A2)), Status::Candidate);
    }

    #[test]
    fn a_ping_from_a_new_source_makes_a_learned_route_and_never_moves_the_active_route() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        p.on_ping(at(50), &c, net(A2), 5);
        let d = dos(&mut p);
        assert_eq!(ping_paths(&d), [path(0, A2)]);
        assert_eq!(p.learned().collect::<Vec<_>>(), [path(0, A2)]);
        assert_eq!(status(&p, path(0, A2)), Status::Candidate);
        assert_eq!(active_path(&p), Some(switch_path()));
    }

    #[test]
    fn a_ping_from_a_new_source_is_answered_even_at_the_route_limit() {
        let specs: Vec<Spec> = (0..MAX_ROUTES)
            .map(|i| net(&format!("203.0.113.9:{}", 1000 + i)))
            .collect();
        let (mut p, c) = new(&specs, None);
        p.on_ping(at(50), &c, learned(A1), 5);
        let d = dos(&mut p);
        assert!(d.iter().any(|d| matches!(d, Do::Pong { txid: 5, .. })));
        assert_eq!(p.routes().len(), MAX_ROUTES);
    }

    // ---- keeping routes --------------------------------------------------------------------

    fn verified_pair() -> (Paths, Config) {
        let (mut p, c) = new(&[net(A1), sw()], Some(path(0, A1)));
        answer(&mut p, &c, at(30), path(0, A1));
        (p, c)
    }

    #[test]
    fn an_unanswered_keeping_ping_makes_a_route_suspect_then_failed_on_the_third_miss() {
        let (mut p, c) = verified_pair();
        assert_eq!(p.rto(), ms(200));
        p.on_sent(at(10_030), &c, path(0, A1), true);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A1)]);
        let log = run(&mut p, &c, 10_229);
        assert!(log.is_empty());
        assert_eq!(status(&p, path(0, A1)), Status::Verified);

        let log = run(&mut p, &c, 10_230);
        assert_eq!(ping_times(&log, path(0, A1)), [10_230]);
        assert_eq!(status(&p, path(0, A1)), Status::Suspect);
        let log = run(&mut p, &c, 10_629);
        assert!(log.is_empty());

        let log = run(&mut p, &c, 10_630);
        assert_eq!(ping_times(&log, path(0, A1)), [10_630]);
        assert_eq!(status(&p, path(0, A1)), Status::Suspect);
        let log = run(&mut p, &c, 11_429);
        assert!(ping_times(&log, path(0, A1)).is_empty());

        let log = run(&mut p, &c, 11_430);
        assert_eq!(log, [(at(11_430), Do::Failed(path(0, A1)))]);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
    }

    #[test]
    fn a_pong_makes_a_suspect_route_verified_again() {
        let (mut p, c) = verified_pair();
        p.on_sent(at(10_030), &c, path(0, A1), true);
        run(&mut p, &c, 10_230);
        assert_eq!(status(&p, path(0, A1)), Status::Suspect);
        answer(&mut p, &c, at(10_280), path(0, A1));
        assert_eq!(status(&p, path(0, A1)), Status::Verified);
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    #[test]
    fn a_dead_address_gets_one_episode_then_one_ping_every_10_s_and_26_pings_in_200_s() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        let log = run(&mut p, &c, 200_000);
        let times = ping_times(&log, path(0, A1));
        let mut all = vec![0];
        all.extend(times);
        assert_eq!(all.len(), 26);
        assert_eq!(all[..7], [0, 100, 200, 400, 800, 1_600, 3_200]);
        let retries: Vec<u64> = (0..19).map(|k| 14_200 + 10_000 * k).collect();
        assert_eq!(all[7..], retries[..]);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        assert_eq!(active_path(&p), Some(switch_path()));
    }

    #[test]
    fn failed_routes_and_demands_follow_the_configured_keepalive_timeout() {
        let c = Config {
            keepalive_timeout: ms(4_000),
            ..Config::default()
        };
        let mut p = Paths::new(at(0), &c, &[net(A1), sw()], None);
        dos(&mut p);
        let log = run(&mut p, &c, 4_200);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        assert_eq!(ping_times(&log, path(0, A1)).len(), 6);
        let log = run(&mut p, &c, 16_200);
        assert_eq!(
            ping_times(&log, path(0, A1)),
            [8_200, 12_200, 16_200],
            "the first retry comes a keepalive timeout after the failure"
        );
        let asks: Vec<u64> = log
            .iter()
            .filter(|(_, d)| *d == Do::Demand)
            .map(|(t, _)| t.as_duration().as_millis() as u64)
            .collect();
        assert!(asks.windows(2).all(|w| w[1] - w[0] == 4_000), "{asks:?}");
    }

    #[test]
    fn a_failed_route_that_could_not_win_gets_no_ping() {
        let (mut p, c) = failed_under_a_better_active_route();
        let log = run_answering(&mut p, &c, path(0, L1), 200_000);
        assert!(
            ping_times(&log, path(0, L1)).len() > 5,
            "the active route is kept"
        );
        assert!(ping_times(&log, path(0, A1)).is_empty());
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        assert_eq!(active_path(&p), Some(path(0, L1)));
    }

    #[test]
    fn a_failed_route_that_could_win_gets_one_ping_every_10_s() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        let log = run(&mut p, &c, 4_200);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        assert_eq!(ping_times(&log, path(0, A1)).len(), 6);
        let log = run(&mut p, &c, 14_199);
        assert!(ping_times(&log, path(0, A1)).is_empty());
        let log = run(&mut p, &c, 44_200);
        assert_eq!(
            ping_times(&log, path(0, A1)),
            [14_200, 24_200, 34_200, 44_200]
        );
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
    }

    #[test]
    fn a_pong_to_the_retry_ping_of_a_failed_route_verifies_it_and_the_active_route_moves_at_once() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        run(&mut p, &c, 14_200);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        assert_eq!(active_path(&p), Some(switch_path()));
        answer(&mut p, &c, at(14_230), path(0, A1));
        assert_eq!(status(&p, path(0, A1)), Status::Verified);
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    #[test]
    fn a_route_back_from_failed_can_be_the_first_choice() {
        let (mut p, c) = new(&[net(A1)], None);
        run(&mut p, &c, 14_200);
        assert_eq!(active_path(&p), None);
        answer(&mut p, &c, at(14_250), path(0, A1));
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    #[test]
    fn a_verified_probe_route_idle_for_25_s_gets_a_keepalive_ping() {
        let (mut p, c) = verified_pair();
        let log = run(&mut p, &c, 24_999);
        assert!(log.is_empty());
        let log = run(&mut p, &c, 25_000);
        assert_eq!(ping_times(&log, path(0, A1)), [25_000]);
        assert_eq!(ping_times(&log, switch_path()), Vec::<u64>::new());
        answer(&mut p, &c, at(25_030), path(0, A1));
        for k in [50_000, 75_000, 100_000] {
            let log = run(&mut p, &c, k);
            assert_eq!(ping_times(&log, path(0, A1)), [k]);
            assert!(ping_times(&log, switch_path()).is_empty());
            answer(&mut p, &c, at(k + 30), path(0, A1));
        }
    }

    #[test]
    fn a_frame_sent_on_a_route_postpones_its_keepalive() {
        let (mut p, c) = new(&[lan(L1), net(A1), sw()], Some(path(0, L1)));
        answer(&mut p, &c, at(5), path(0, L1));
        sample(&mut p, &c, path(0, A1), 10, 40);
        assert_eq!(active_path(&p), Some(path(0, L1)));
        p.on_sent(at(20_000), &c, path(0, A1), false);
        let log = run(&mut p, &c, 44_999);
        assert!(ping_times(&log, path(0, A1)).is_empty());
        let log = run(&mut p, &c, 45_000);
        assert_eq!(ping_times(&log, path(0, A1)), [45_000]);
    }

    #[test]
    fn data_on_the_active_route_pings_it_every_detect_timeout() {
        let (mut p, c) = verified_pair();
        p.on_sent(at(1_000), &c, path(0, A1), true);
        assert!(dos(&mut p).is_empty());
        p.on_sent(at(2_029), &c, path(0, A1), true);
        assert!(dos(&mut p).is_empty());
        p.on_sent(at(2_030), &c, path(0, A1), true);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A1)]);
        p.on_sent(at(2_130), &c, path(0, A1), true);
        assert!(dos(&mut p).is_empty());
        let i = p.index(&path(0, A1)).unwrap();
        assert!(matches!(
            p.routes[i].state,
            State::Verified { deadline: Some(d), .. } if d == at(2_230)
        ));
    }

    #[test]
    fn a_metered_active_route_is_pinged_every_keepalive_timeout_while_data_goes_out() {
        let (mut p, c) = new(&[sw()], None);
        assert_eq!(active_path(&p), Some(switch_path()));
        let mut times = Vec::new();
        for k in 0..600 {
            let t = 100 * k;
            p.on_sent(at(t), &c, switch_path(), true);
            if dos(&mut p).iter().any(|d| matches!(d, Do::Ping { .. })) {
                times.push(t);
            }
        }
        assert_eq!(times, [10_000, 20_000, 30_000, 40_000, 50_000]);
    }

    #[test]
    fn a_relay_route_is_pinged_every_keepalive_timeout_whatever_the_detect_timeout() {
        let c = Config {
            detect_timeout: Some(ms(500)),
            ..Config::default()
        };
        let mut p = Paths::new(at(0), &c, &[relay(A2), sw()], Some(path(1, A2)));
        dos(&mut p);
        assert_eq!(active_path(&p), Some(path(1, A2)));
        answer(&mut p, &c, at(30), path(1, A2));
        p.on_sent(at(5_000), &c, path(1, A2), true);
        assert!(dos(&mut p).is_empty());
        p.on_sent(at(10_030), &c, path(1, A2), true);
        assert_eq!(ping_paths(&dos(&mut p)), [path(1, A2)]);
    }

    #[test]
    fn the_default_detect_timeout_is_2_s() {
        assert_eq!(Config::default().detect_timeout, None);
        assert_eq!(DETECT_TIMEOUT, Duration::from_secs(2));
    }

    #[test]
    fn data_pings_the_active_route_at_the_detect_timeout_that_is_set() {
        let (mut p, mut c) = verified_pair();
        c.detect_timeout = Some(KEEPALIVE_TIMEOUT);
        p.on_sent(at(2_030), &c, path(0, A1), true);
        assert!(dos(&mut p).is_empty());
        p.on_sent(at(10_029), &c, path(0, A1), true);
        assert!(dos(&mut p).is_empty());
        p.on_sent(at(10_030), &c, path(0, A1), true);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A1)]);
    }

    #[test]
    fn a_frame_that_is_not_data_does_not_ping() {
        let (mut p, c) = verified_pair();
        p.on_sent(at(20_000), &c, path(0, A1), false);
        assert!(dos(&mut p).is_empty());
    }

    #[test]
    fn data_on_a_route_that_is_not_active_does_not_ping() {
        let (mut p, c) = verified_pair();
        p.on_sent(at(20_000), &c, switch_path(), true);
        assert!(dos(&mut p).is_empty());
    }

    #[test]
    fn the_keeping_ping_is_skipped_while_the_peers_frames_arrive_on_the_active_path() {
        let (mut p, c) = verified_pair();
        p.on_data(at(1_950), &c, net(A1), true);
        p.on_sent(at(2_030), &c, path(0, A1), true);
        assert!(dos(&mut p).is_empty());
        p.on_data(at(3_900), &c, net(A1), true);
        p.on_sent(at(3_950), &c, path(0, A1), true);
        assert!(dos(&mut p).is_empty());
        p.on_sent(at(5_900), &c, path(0, A1), true);
        assert_eq!(
            ping_paths(&dos(&mut p)),
            [path(0, A1)],
            "the peer fell silent: the ping is due 2 s after its last frame"
        );
    }

    #[test]
    fn the_keeping_ping_goes_out_while_the_peers_frames_arrive_on_another_path() {
        let (mut p, c) = verified_pair();
        for t in (1_000..2_100).step_by(100) {
            p.on_data(at(t), &c, sw(), true);
        }
        p.on_sent(at(2_030), &c, path(0, A1), true);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A1)]);
    }

    #[test]
    fn a_ping_a_pong_and_other_frames_each_record_their_arrival_on_the_path_they_came_on() {
        for how in 0..3 {
            let (mut p, c) = verified_pair();
            match how {
                0 => p.on_ping(at(1_990), &c, net(A1), 77),
                1 => p.on_pong(at(1_990), &c, path(0, A1), 999),
                _ => p.on_rx(at(1_990), path(0, A1)),
            }
            dos(&mut p);
            p.on_sent(at(2_030), &c, path(0, A1), true);
            assert!(ping_paths(&dos(&mut p)).is_empty(), "case {how}");
        }
    }

    #[test]
    fn a_reported_active_route_is_pinged_while_sending_without_a_deadline() {
        let (mut p, c) = new(&[sw()], None);
        answer(&mut p, &c, at(80), switch_path());
        p.on_sent(at(2_080), &c, switch_path(), true);
        assert!(dos(&mut p).is_empty());
        p.on_sent(at(10_080), &c, switch_path(), true);
        assert_eq!(ping_paths(&dos(&mut p)), [switch_path()]);
        run(&mut p, &c, 60_000);
        assert_eq!(status(&p, switch_path()), Status::Verified);
    }

    #[test]
    fn data_does_not_ping_a_suspect_route_outside_its_schedule() {
        let (mut p, mut c) = new(&[net(A1)], None);
        c.detect_timeout = Some(ms(50));
        answer(&mut p, &c, at(30), path(0, A1));
        p.on_sent(at(10_000), &c, path(0, A1), true);
        dos(&mut p);
        run(&mut p, &c, 10_200);
        assert_eq!(status(&p, path(0, A1)), Status::Suspect);
        dos(&mut p);
        p.on_sent(at(10_300), &c, path(0, A1), true);
        assert!(dos(&mut p).is_empty());
    }

    // ---- selection -------------------------------------------------------------------------

    #[test]
    fn routes_rank_by_band_then_metering_then_latency_then_srtt() {
        let (mut p, c) = new(&[sw(), relay(A3), net(A1), lan(L1), net(A2)], None);
        sample(&mut p, &c, path(0, A1), 10, 50);
        sample(&mut p, &c, path(0, A2), 10, 20);
        let order: Vec<Path> = p.routes().iter().map(|r| r.path).collect();
        assert_eq!(
            order,
            [
                path(0, L1),
                path(0, A2),
                path(0, A1),
                path(1, A3),
                switch_path()
            ]
        );
    }

    #[test]
    fn a_route_without_a_sample_ranks_after_one_with() {
        let (mut p, c) = new(&[net(A1), net(A2), sw()], None);
        sample(&mut p, &c, path(0, A2), 10, 300);
        let order: Vec<Path> = p.routes().iter().map(|r| r.path).collect();
        assert_eq!(order, [path(0, A2), path(0, A1), switch_path()]);
    }

    #[test]
    fn with_no_active_route_the_best_usable_route_is_taken() {
        let (mut p, c) = new(&[net(A1), lan(L1)], None);
        assert_eq!(active_path(&p), None);
        answer(&mut p, &c, at(40), path(0, A1));
        assert_eq!(active_path(&p), Some(path(0, A1)));
        answer(&mut p, &c, at(45), path(0, L1));
        assert_eq!(active_path(&p), Some(path(0, L1)));
    }

    #[test]
    fn a_route_of_strictly_better_class_takes_over_at_once() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        assert_eq!(active_path(&p), Some(switch_path()));
        answer(&mut p, &c, at(30), path(0, A1));
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    #[test]
    fn a_route_of_worse_class_never_takes_over() {
        let (mut p, c) = new(&[net(A1), relay(A2)], None);
        answer(&mut p, &c, at(30), path(0, A1));
        answer(&mut p, &c, at(31), path(1, A2));
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    /// A pair of punch routes: `second` is added after the first became active.
    fn two_nets(second_rtt: u64) -> Paths {
        let c = Config::default();
        let mut p = Paths::new(at(0), &c, &[net(A1)], None);
        answer(&mut p, &c, at(100), path(0, A1));
        p.sync(at(1000), &c, &[net(A1), net(A2)]);
        let i = p.index(&path(0, A2)).unwrap();
        p.ping(at(1000), i);
        answer(&mut p, &c, at(1000 + second_rtt), path(0, A2));
        p
    }

    #[test]
    fn a_route_of_the_same_class_never_takes_over_whatever_its_srtt() {
        for rtt in [10, 79, 80, 120] {
            assert_eq!(active_path(&two_nets(rtt)), Some(path(0, A1)), "rtt {rtt}");
        }
    }

    #[test]
    fn a_route_of_the_same_class_is_not_probed_while_the_active_route_is_verified() {
        let c = Config::default();
        let mut p = Paths::new(at(0), &c, &[net(A1)], None);
        answer(&mut p, &c, at(100), path(0, A1));
        dos(&mut p);
        p.sync(at(1000), &c, &[net(A1), net(A2)]);
        assert_eq!(status(&p, path(0, A2)), Status::Dormant);
        assert!(dos(&mut p).is_empty());
        let log = run(&mut p, &c, 20_000);
        assert!(ping_times(&log, path(0, A2)).is_empty());
    }

    #[test]
    fn a_route_of_the_same_class_that_answers_later_does_not_take_over_and_goes_dormant() {
        let (mut p, c) = new(&[net(A1), net(A2)], None);
        run(&mut p, &c, 200);
        answer(&mut p, &c, at(210), path(0, A2));
        assert_eq!(active_path(&p), Some(path(0, A2)));
        assert_eq!(status(&p, path(0, A1)), Status::Dormant);
        answer(&mut p, &c, at(300), path(0, A1));
        assert_eq!(active_path(&p), Some(path(0, A2)));
        assert_eq!(status(&p, path(0, A1)), Status::Dormant);
    }

    #[test]
    fn a_route_of_a_class_no_better_than_the_active_routes_is_never_pinged() {
        let (mut p, c) = new(&[lan(L1), net(A1), relay(A2), sw()], Some(path(0, L1)));
        answer(&mut p, &c, at(5), path(0, L1));
        for a in [path(0, A1), path(1, A2)] {
            assert_eq!(status(&p, a), Status::Dormant);
        }
        let log = run_answering(&mut p, &c, path(0, L1), 100_000);
        assert!(
            ping_times(&log, path(0, L1)).len() > 3,
            "the active route is kept"
        );
        assert!(ping_times(&log, path(0, A1)).is_empty());
        assert!(ping_times(&log, path(1, A2)).is_empty());
        assert_eq!(active_path(&p), Some(path(0, L1)));
    }

    #[test]
    fn a_probing_candidate_stops_when_a_route_of_a_better_class_becomes_active() {
        let (mut p, c) = new(&[net(A1), lan(L1)], None);
        assert_eq!(status(&p, path(0, A1)), Status::Candidate);
        answer(&mut p, &c, at(10), path(0, L1));
        assert_eq!(active_path(&p), Some(path(0, L1)));
        assert_eq!(status(&p, path(0, A1)), Status::Dormant);
        let log = run(&mut p, &c, 10_000);
        assert!(ping_times(&log, path(0, A1)).is_empty());
    }

    #[test]
    fn a_learned_candidate_that_could_no_longer_win_is_dropped_instead() {
        let (mut p, c) = new(&[sw()], None);
        p.on_ping(at(10), &c, learned(A1), 7);
        dos(&mut p);
        assert_eq!(p.learned().count(), 1);
        p.sync(at(20), &c, &[lan(L1), sw(), learned(A1)]);
        answer(&mut p, &c, at(30), path(0, L1));
        assert_eq!(active_path(&p), Some(path(0, L1)));
        assert_eq!(p.learned().count(), 0);
    }

    fn pings_of_three(p: &mut Paths, c: &Config, until: u64) -> Vec<(u64, Path)> {
        let mut out: Vec<(u64, Path)> = dos(p)
            .iter()
            .filter_map(|d| match d {
                Do::Ping { path, .. } => Some((0, *path)),
                _ => None,
            })
            .collect();
        out.extend(run(p, c, until).into_iter().filter_map(|(t, d)| match d {
            Do::Ping { path, .. } => Some((t.as_duration().as_millis() as u64, path)),
            _ => None,
        }));
        out
    }

    #[test]
    fn three_routes_of_one_class_start_0_200_and_400_ms_apart_while_none_answers() {
        let c = Config::default();
        let mut p = Paths::new(at(0), &c, &[net(A1), net(A2), net(A3)], None);
        let pings = pings_of_three(&mut p, &c, 450);
        let first = |a: &str| pings.iter().find(|(_, p)| *p == path(0, a)).unwrap().0;
        assert_eq!((first(A1), first(A2), first(A3)), (0, 200, 400));
        assert_eq!(status(&p, path(0, A3)), Status::Candidate);
    }

    #[test]
    fn the_second_and_third_route_of_a_class_never_start_if_the_first_answers_within_200_ms() {
        let c = Config::default();
        let mut p = Paths::new(at(0), &c, &[net(A1), net(A2), net(A3)], None);
        dos(&mut p);
        run(&mut p, &c, 150);
        answer(&mut p, &c, at(150), path(0, A1));
        let log = run_answering(&mut p, &c, path(0, A1), 60_000);
        assert!(ping_times(&log, path(0, A2)).is_empty());
        assert!(ping_times(&log, path(0, A3)).is_empty());
        assert_eq!(status(&p, path(0, A2)), Status::Dormant);
        assert_eq!(status(&p, path(0, A3)), Status::Dormant);
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    #[test]
    fn the_next_route_of_a_class_starts_200_ms_after_the_previous_one_even_if_that_one_failed() {
        let c = Config::default();
        let mut p = Paths::new(at(0), &c, &[net(A1), net(A2)], None);
        dos(&mut p);
        p.handle_timeout(at(199), &c);
        assert!(!ping_paths(&dos(&mut p)).contains(&path(0, A2)));
        p.handle_timeout(at(200), &c);
        assert!(ping_paths(&dos(&mut p)).contains(&path(0, A2)));
    }

    #[test]
    fn with_no_active_route_two_classes_probe_at_once() {
        let (p, _) = new(&[net(A1), lan(L1)], None);
        assert_eq!(active_path(&p), None);
        assert_eq!(status(&p, path(0, A1)), Status::Candidate);
        assert_eq!(status(&p, path(0, L1)), Status::Candidate);
    }

    #[test]
    fn a_suspect_active_route_wakes_every_dormant_route() {
        let (mut p, c) = new(
            &[lan(L1), net(A1), relay(A2), net(A3), sw()],
            Some(path(0, L1)),
        );
        answer(&mut p, &c, at(5), path(0, L1));
        for a in [path(0, A1), path(1, A2), path(0, A3)] {
            assert_eq!(status(&p, a), Status::Dormant);
        }
        p.on_sent(at(10_005), &c, path(0, L1), true);
        dos(&mut p);
        let log = run(&mut p, &c, 10_205);
        assert_eq!(status(&p, path(0, L1)), Status::Suspect);
        assert_eq!(ping_times(&log, path(0, A1)), [10_205]);
        assert_eq!(ping_times(&log, path(1, A2)), [10_205]);
        assert_eq!(
            status(&p, path(0, A3)),
            Status::Dormant,
            "its class waits for its turn"
        );
        let log = run(&mut p, &c, 10_405);
        assert_eq!(ping_times(&log, path(0, A3)), [10_405]);
    }

    #[test]
    fn a_verified_active_route_that_recovers_sends_the_woken_routes_back_to_sleep() {
        let (mut p, c) = new(&[lan(L1), net(A1), sw()], Some(path(0, L1)));
        answer(&mut p, &c, at(5), path(0, L1));
        p.on_sent(at(10_005), &c, path(0, L1), true);
        run(&mut p, &c, 10_205);
        assert_eq!(status(&p, path(0, A1)), Status::Candidate);
        answer(&mut p, &c, at(10_250), path(0, L1));
        assert_eq!(status(&p, path(0, L1)), Status::Verified);
        assert_eq!(status(&p, path(0, A1)), Status::Dormant);
    }

    #[test]
    fn while_a_route_of_the_class_is_verified_no_other_one_of_it_starts_even_if_the_active_route_is_not()
     {
        let (mut p, c) = roamed();
        dos(&mut p);
        p.sync(at(1_000), &c, &[net(A1), net(A3), learned(A2), sw()]);
        dos(&mut p);
        assert_eq!(status(&p, path(0, A3)), Status::Dormant);
        let log = run(&mut p, &c, 1_900);
        assert!(ping_times(&log, path(0, A3)).is_empty());
        answer(&mut p, &c, at(1_930), path(0, A2));
        assert_eq!(status(&p, path(0, A3)), Status::Dormant);
    }

    #[test]
    fn a_reported_route_waits_for_the_fallback_delay_after_a_direct_route_is_lost() {
        let (mut p, c) = new(&[net(A1), sw()], Some(path(0, A1)));
        answer(&mut p, &c, at(30), path(0, A1));
        assert_eq!(active_path(&p), Some(path(0, A1)));
        p.sync(at(1_000), &c, &[sw()]);
        assert_eq!(active_path(&p), None);
        assert_eq!(p.route_for(&DeliveryClass::default()), Delivery::Wait);
        assert_eq!(p.poll_timeout(&c), Some(at(2_000)));
        run(&mut p, &c, 1_999);
        assert_eq!(active_path(&p), None);
        run(&mut p, &c, 2_000);
        assert_eq!(active_path(&p), Some(switch_path()));
    }

    #[test]
    fn a_zero_fallback_delay_moves_to_a_reported_route_at_once() {
        let (mut p, mut c) = new(&[net(A1), sw()], Some(path(0, A1)));
        c.fallback_delay = Duration::ZERO;
        answer(&mut p, &c, at(30), path(0, A1));
        p.sync(at(1_000), &c, &[sw()]);
        assert_eq!(active_path(&p), Some(switch_path()));
    }

    #[test]
    fn a_direct_route_is_probed_and_taken_during_the_fallback_delay() {
        let (mut p, c) = new(&[net(A1), net(A2), sw()], Some(path(0, A1)));
        answer(&mut p, &c, at(30), path(0, A1));
        assert_eq!(status(&p, path(0, A2)), Status::Dormant);
        p.sync(at(1_000), &c, &[net(A2), sw()]);
        assert_eq!(active_path(&p), None);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A2)]);
        answer(&mut p, &c, at(1_040), path(0, A2));
        assert_eq!(active_path(&p), Some(path(0, A2)));
    }

    #[test]
    fn losing_a_reported_active_route_starts_no_grace() {
        let other = Path {
            via: TransportId(8),
            to: Remote::Peer(key(2)),
        };
        let other_sw = spec(other, SWITCH, "switch", Origin::Reported);
        let (mut p, c) = new(&[sw(), other_sw], None);
        assert_eq!(active_path(&p), Some(switch_path()));
        p.sync(at(1_000), &c, &[other_sw]);
        assert_eq!(active_path(&p), Some(other));
    }

    #[test]
    fn reported_routes_carry_no_data_without_switch_data() {
        let c = Config {
            switch_data: false,
            ..Config::default()
        };
        let mut p = Paths::new(at(0), &c, &[net(A1), sw()], None);
        assert_eq!(active_path(&p), None);
        p.on_pong(at(30), &c, path(0, A1), 0);
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    #[test]
    fn a_suspect_active_route_gives_way_to_the_best_other_usable_route_of_any_rank() {
        let (mut p, c) = verified_pair();
        assert_eq!(active_path(&p), Some(path(0, A1)));
        p.on_sent(at(10_030), &c, path(0, A1), true);
        run(&mut p, &c, 10_230);
        assert_eq!(status(&p, path(0, A1)), Status::Suspect);
        assert_eq!(active_path(&p), Some(switch_path()));
    }

    #[test]
    fn a_suspect_active_route_stays_if_there_is_no_other_usable_route() {
        let (mut p, c) = new(&[net(A1)], None);
        answer(&mut p, &c, at(30), path(0, A1));
        p.on_sent(at(10_030), &c, path(0, A1), true);
        run(&mut p, &c, 10_630);
        assert_eq!(status(&p, path(0, A1)), Status::Suspect);
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    #[test]
    fn a_failed_active_route_is_lost_and_the_best_usable_route_is_taken() {
        let (mut p, c) = new(&[net(A1), relay(A2)], None);
        answer(&mut p, &c, at(30), path(0, A1));
        answer(&mut p, &c, at(31), path(1, A2));
        assert_eq!(active_path(&p), Some(path(0, A1)));
        p.on_sent(at(10_030), &c, path(0, A1), true);
        run(&mut p, &c, 11_430);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        assert_eq!(active_path(&p), Some(path(1, A2)));
    }

    #[test]
    fn a_failed_active_route_with_nothing_else_leaves_no_active_route() {
        let (mut p, c) = new(&[net(A1)], None);
        answer(&mut p, &c, at(30), path(0, A1));
        p.on_sent(at(10_030), &c, path(0, A1), true);
        run(&mut p, &c, 11_430);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        assert_eq!(active_path(&p), None);
    }

    // ---- settle ----------------------------------------------------------------------------

    fn wifi_cell() -> (Paths, Config) {
        let (p, c) = new(&[net(A1), relay(A2), sw()], None);
        assert_eq!(active_path(&p), Some(switch_path()));
        (p, c)
    }

    #[test]
    fn a_move_onto_a_metered_route_waits_while_a_better_unmetered_ping_is_out() {
        let (mut p, c) = wifi_cell();
        answer(&mut p, &c, at(30), path(1, A2));
        assert_eq!(active_path(&p), Some(switch_path()));
        assert_eq!(p.poll_timeout(&c), Some(at(90)));
        answer(&mut p, &c, at(45), path(0, A1));
        assert_eq!(active_path(&p), Some(path(0, A1)));
        assert_eq!(status(&p, path(1, A2)), Status::Verified);
        run(&mut p, &c, 200);
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    #[test]
    fn the_settle_ends_after_twice_the_srtt_of_the_metered_route() {
        let (mut p, c) = wifi_cell();
        answer(&mut p, &c, at(30), path(1, A2));
        run(&mut p, &c, 89);
        assert_eq!(active_path(&p), Some(switch_path()));
        run(&mut p, &c, 90);
        assert_eq!(active_path(&p), Some(path(1, A2)));
    }

    #[test]
    fn the_settle_never_outlasts_the_rto_of_the_outstanding_ping() {
        let (mut p, c) = wifi_cell();
        answer(&mut p, &c, at(700), path(1, A2));
        assert_eq!(active_path(&p), Some(switch_path()));
        run(&mut p, &c, 999);
        assert_eq!(active_path(&p), Some(switch_path()));
        run(&mut p, &c, 1_000);
        assert_eq!(active_path(&p), Some(path(1, A2)));
    }

    #[test]
    fn a_move_onto_a_metered_route_with_no_better_unmetered_route_is_immediate() {
        let (mut p, c) = new(&[relay(A2), sw()], None);
        answer(&mut p, &c, at(30), path(1, A2));
        assert_eq!(active_path(&p), Some(path(1, A2)));
    }

    #[test]
    fn a_move_that_adds_no_metering_is_immediate() {
        let (mut p, c) = new(&[net(A1), net(A2), sw()], None);
        answer(&mut p, &c, at(30), path(0, A1));
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    // ---- roaming ---------------------------------------------------------------------------

    fn roamed() -> (Paths, Config) {
        let (mut p, c) = new(&[net(A1), sw()], Some(path(0, A1)));
        answer(&mut p, &c, at(30), path(0, A1));
        p.on_data(at(1_000), &c, learned(A2), true);
        (p, c)
    }

    #[test]
    fn newest_data_from_an_unknown_source_makes_a_learned_route_active_at_once_unverified() {
        let (mut p, _) = roamed();
        let a = p.active().unwrap();
        assert_eq!(
            (a.path, a.label, a.verified),
            (path(0, A2), "learned", false)
        );
        assert_eq!(p.learned().collect::<Vec<_>>(), [path(0, A2)]);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A2)]);
        assert_eq!(status(&p, path(0, A2)), Status::Candidate);
        assert_eq!(status(&p, path(0, A1)), Status::Verified);
    }

    #[test]
    fn data_that_is_not_the_newest_makes_no_route() {
        let (mut p, c) = new(&[net(A1), sw()], Some(path(0, A1)));
        p.on_data(at(1_000), &c, learned(A2), false);
        assert_eq!(p.routes().len(), 2);
        assert_eq!(active_path(&p), Some(path(0, A1)));
    }

    #[test]
    fn only_a_session_not_older_than_the_newest_heard_is_live() {
        let (mut p, _) = new(&[net(A1), sw()], Some(path(0, A1)));
        assert!(p.hear(at(10)));
        assert!(p.hear(at(10)), "the same session");
        assert!(p.hear(at(20)), "a newer session");
        assert!(!p.hear(at(10)), "the session the peer has left");
        assert!(p.hear(at(20)));
    }

    #[test]
    fn data_on_a_route_that_is_not_dormant_moves_nothing() {
        let (mut p, c) = new(&[net(A1), lan(L1), sw()], Some(path(0, A1)));
        assert_eq!(status(&p, path(0, L1)), Status::Candidate);
        p.on_data(at(10), &c, lan(L1), true);
        assert_eq!(active_path(&p), Some(path(0, A1)));
        assert_eq!(p.routes().len(), 3);
    }

    #[test]
    fn newest_data_on_a_dormant_route_moves_the_active_route_there_and_starts_its_episode() {
        let (mut p, c) = new(&[net(A1), net(A2), sw()], Some(path(0, A1)));
        assert_eq!(status(&p, path(0, A2)), Status::Dormant);
        dos(&mut p);
        p.on_data(at(1_000), &c, net(A2), true);
        let a = p.active().unwrap();
        assert_eq!((a.path, a.label, a.verified), (path(0, A2), "punch", false));
        assert_eq!(status(&p, path(0, A2)), Status::Candidate);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A2)]);
        assert_eq!(p.routes().len(), 3, "the route is the one it was");
        answer(&mut p, &c, at(1_030), path(0, A2));
        assert_eq!(status(&p, path(0, A2)), Status::Verified);
        assert_eq!(status(&p, path(0, A1)), Status::Dormant);
    }

    #[test]
    fn data_that_is_not_the_newest_does_not_roam_onto_a_dormant_route() {
        let (mut p, c) = new(&[net(A1), net(A2), sw()], Some(path(0, A1)));
        p.on_data(at(1_000), &c, net(A2), false);
        assert_eq!(active_path(&p), Some(path(0, A1)));
        assert_eq!(status(&p, path(0, A2)), Status::Dormant);
    }

    #[test]
    fn data_from_an_unknown_source_of_worse_class_than_a_verified_route_makes_no_route() {
        let (mut p, c) = new(&[lan(L1), net(A1), sw()], None);
        answer(&mut p, &c, at(30), path(0, L1));
        assert_eq!(active_path(&p), Some(path(0, L1)));
        dos(&mut p);
        let routes = p.routes().len();
        for k in 0..50 {
            p.on_data(at(1_000 + k), &c, learned(A2), true);
        }
        assert_eq!(p.routes().len(), routes, "no learned route");
        assert_eq!(p.learned().count(), 0);
        assert_eq!(active_path(&p), Some(path(0, L1)));
        assert!(ping_paths(&dos(&mut p)).is_empty(), "no ping");
    }

    #[test]
    fn data_from_an_unknown_source_of_the_class_of_the_verified_route_still_roams() {
        let (mut p, c) = new(&[net(A1), sw()], Some(path(0, A1)));
        answer(&mut p, &c, at(30), path(0, A1));
        dos(&mut p);
        p.on_data(at(1_000), &c, learned(A2), true);
        assert_eq!(active_path(&p), Some(path(0, A2)));
    }

    #[test]
    fn data_never_roams_onto_a_failed_route() {
        let (mut p, c) = new(&[net(A1), lan(L1), sw()], Some(path(0, A1)));
        run_answering(&mut p, &c, path(0, A1), 4_300);
        assert_eq!(status(&p, path(0, L1)), Status::Failed);
        dos(&mut p);
        p.on_data(at(4_400), &c, lan(L1), true);
        assert_eq!(active_path(&p), Some(path(0, A1)));
        assert_eq!(status(&p, path(0, L1)), Status::Failed);
        assert!(ping_paths(&dos(&mut p)).is_empty());
    }

    #[test]
    fn a_roamed_dormant_route_that_fails_its_first_ping_is_failed_and_the_next_data_does_not_roam()
    {
        let (mut p, c) = new(&[net(A1), net(A2), sw()], Some(path(0, A1)));
        answer(&mut p, &c, at(30), path(0, A1));
        p.on_data(at(1_000), &c, net(A2), true);
        dos(&mut p);
        run(&mut p, &c, 1_999);
        assert_eq!(active_path(&p), Some(path(0, A2)));
        run(&mut p, &c, 2_000);
        assert_eq!(active_path(&p), Some(path(0, A1)));
        assert_eq!(status(&p, path(0, A2)), Status::Failed);
        dos(&mut p);
        p.on_data(at(2_100), &c, net(A2), true);
        assert_eq!(active_path(&p), Some(path(0, A1)), "no flap");
        assert!(ping_paths(&dos(&mut p)).is_empty());
    }

    #[test]
    fn an_unanswered_roamed_route_gives_way_after_its_rto_and_is_failed_if_it_could_not_win() {
        let (mut p, c) = roamed();
        dos(&mut p);
        let log = run(&mut p, &c, 1_999);
        assert_eq!(active_path(&p), Some(path(0, A2)));
        assert_eq!(ping_times(&log, path(0, A2)), [1_100, 1_200, 1_400, 1_800]);
        run(&mut p, &c, 2_000);
        assert_eq!(active_path(&p), Some(path(0, A1)));
        assert!(p.active().unwrap().verified);
        assert_eq!(status(&p, path(0, A2)), Status::Failed);
        dos(&mut p);
        p.on_data(at(2_100), &c, learned(A2), true);
        assert_eq!(
            active_path(&p),
            Some(path(0, A1)),
            "no roaming onto it again"
        );
        run(&mut p, &c, 2_000 + 10_000);
        assert_eq!(p.learned().count(), 0, "dropped when it would be retried");
    }

    #[test]
    fn an_unanswered_roamed_route_goes_on_with_its_episode_while_it_could_win() {
        let (mut p, c) = new(&[sw()], None);
        p.on_data(at(1_000), &c, learned(A2), true);
        dos(&mut p);
        run(&mut p, &c, 2_000);
        assert_eq!(active_path(&p), None, "the fallback delay");
        let mut log = run(&mut p, &c, 3_000);
        assert_eq!(active_path(&p), Some(switch_path()));
        assert_eq!(status(&p, path(0, A2)), Status::Candidate);
        log.extend(run(&mut p, &c, 5_200));
        assert_eq!(ping_times(&log, path(0, A2)), [2_600, 4_200]);
        assert_eq!(status(&p, path(0, A2)), Status::Failed);
    }

    #[test]
    fn a_pong_verifies_a_roamed_route_and_ends_the_revert() {
        let (mut p, c) = roamed();
        answer(&mut p, &c, at(1_030), path(0, A2));
        assert_eq!(status(&p, path(0, A2)), Status::Verified);
        assert!(p.active().unwrap().verified);
        run(&mut p, &c, 5_000);
        assert_eq!(active_path(&p), Some(path(0, A2)));
    }

    #[test]
    fn after_roaming_the_route_the_data_left_is_dormant_once_the_learned_route_is_verified() {
        let (mut p, c) = roamed();
        assert_eq!(status(&p, path(0, A1)), Status::Verified);
        answer(&mut p, &c, at(1_030), path(0, A2));
        assert_eq!(status(&p, path(0, A2)), Status::Verified);
        assert_eq!(status(&p, path(0, A1)), Status::Dormant);
        assert_eq!(active_path(&p), Some(path(0, A2)));
        assert_eq!(p.learned().count(), 1, "the learned route is the one kept");
    }

    #[test]
    fn the_route_the_data_left_gets_no_nat_keepalive_afterwards() {
        let (mut p, c) = roamed();
        answer(&mut p, &c, at(1_030), path(0, A2));
        dos(&mut p);
        let log = run_answering(&mut p, &c, path(0, A2), 120_000);
        assert!(ping_times(&log, path(0, A1)).is_empty());
        assert!(
            !ping_times(&log, path(0, A2)).is_empty(),
            "the active route is kept"
        );
    }

    #[test]
    fn a_verified_standby_of_another_class_keeps_its_nat_keepalive() {
        let (mut p, c) = new(&[net(A1), relay(A2), sw()], None);
        answer(&mut p, &c, at(30), path(1, A2));
        answer(&mut p, &c, at(45), path(0, A1));
        run(&mut p, &c, 200);
        assert_eq!(active_path(&p), Some(path(0, A1)));
        assert_eq!(status(&p, path(1, A2)), Status::Verified);
        let log = run(&mut p, &c, 25_100);
        assert_eq!(ping_times(&log, path(1, A2)), [25_000]);
        assert_eq!(ping_times(&log, path(0, A1)), [25_000]);
    }

    #[test]
    fn only_the_best_verified_route_of_each_class_is_kept() {
        let (mut p, c) = new(&[net(A1), relay(A2), relay(A3), sw()], None);
        run(&mut p, &c, 200);
        answer(&mut p, &c, at(300), path(1, A3));
        answer(&mut p, &c, at(320), path(1, A2));
        answer(&mut p, &c, at(330), path(0, A1));
        assert_eq!(active_path(&p), Some(path(0, A1)));
        let kept = [path(1, A2), path(1, A3)]
            .into_iter()
            .filter(|a| status(&p, *a) == Status::Verified)
            .count();
        assert_eq!(kept, 1);
    }

    #[test]
    fn a_roamed_route_not_yet_verified_with_no_other_route_reverts_to_nothing() {
        let (mut p, c) = new(&[sw()], None);
        p.sync(at(10), &c, &[]);
        assert_eq!(active_path(&p), None);
        p.on_data(at(1_000), &c, learned(A2), true);
        assert_eq!(active_path(&p), Some(path(0, A2)));
        run(&mut p, &c, 2_000);
        assert_eq!(active_path(&p), None);
    }

    // ---- local change ----------------------------------------------------------------------

    const V6: &str = "[2001:db8::1]:1000";

    fn dual() -> (Paths, Config) {
        let (mut p, c) = new(&[lan(L1), net(V6), sw()], Some(path(0, L1)));
        answer(&mut p, &c, at(20), path(0, L1));
        sample(&mut p, &c, path(0, V6), 21, 4);
        assert_eq!(active_path(&p), Some(path(0, L1)));
        assert_eq!(status(&p, path(0, V6)), Status::Verified);
        (p, c)
    }

    #[test]
    fn a_local_change_makes_the_routes_of_the_changed_families_dormant_and_pings_the_active_one() {
        let (mut p, c) = dual();
        p.local_change(at(1_000), &c, Families::V4);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, L1)]);
        assert_eq!(status(&p, path(0, L1)), Status::Candidate);
        assert_eq!(status(&p, path(0, V6)), Status::Verified);
        assert_eq!(status(&p, switch_path()), Status::Verified);
        let log = run(&mut p, &c, 1_200);
        assert_eq!(ping_times(&log, path(0, L1)), [1_100, 1_200]);
    }

    #[test]
    fn a_local_change_makes_a_verified_standby_of_the_changed_family_dormant() {
        let (mut p, c) = dual();
        p.local_change(at(1_000), &c, Families::V6);
        assert_eq!(status(&p, path(0, V6)), Status::Dormant);
        assert_eq!(status(&p, path(0, L1)), Status::Verified);
        assert!(
            dos(&mut p).is_empty(),
            "a route of a worse class is not probed"
        );
    }

    #[test]
    fn a_local_change_with_a_fast_pong_on_the_active_route_pings_nothing_else() {
        let (mut p, c) = new(
            &[lan(L1), net(A1), net(A2), relay(A3), sw()],
            Some(path(0, L1)),
        );
        answer(&mut p, &c, at(5), path(0, L1));
        p.local_change(at(1_000), &c, Families::V4);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, L1)]);
        answer(&mut p, &c, at(1_010), path(0, L1));
        assert_eq!(status(&p, path(0, L1)), Status::Verified);
        for a in [path(0, A1), path(0, A2), path(1, A3)] {
            assert_eq!(status(&p, a), Status::Dormant);
        }
        let log = run(&mut p, &c, 24_000);
        assert!(ping_paths(&log.iter().map(|(_, d)| *d).collect::<Vec<_>>()).is_empty());
    }

    #[test]
    fn after_a_local_change_the_routes_that_could_win_probe_staggered_and_stop_when_one_answers() {
        let (mut p, c) = new(&[net(A1), net(A2), sw()], None);
        answer(&mut p, &c, at(30), path(0, A1));
        p.local_change(at(1_000), &c, Families::V4);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A1)]);
        assert_eq!(status(&p, path(0, A2)), Status::Dormant);
        let log = run(&mut p, &c, 1_200);
        assert_eq!(ping_times(&log, path(0, A2)), [1_200]);
    }

    #[test]
    fn a_local_change_keeps_the_active_route_unverified_until_one_rto_after_its_first_ping() {
        let (mut p, c) = dual();
        p.local_change(at(1_000), &c, Families::V4);
        let a = p.active().unwrap();
        assert_eq!((a.path, a.verified), (path(0, L1), false));
        run(&mut p, &c, 1_199);
        assert_eq!(active_path(&p), Some(path(0, L1)));
        run(&mut p, &c, 1_200);
        assert_eq!(active_path(&p), Some(path(0, V6)));
    }

    #[test]
    fn a_pong_after_a_local_change_verifies_the_active_route_again() {
        let (mut p, c) = dual();
        p.local_change(at(1_000), &c, Families::V4);
        answer(&mut p, &c, at(1_010), path(0, L1));
        assert!(p.active().unwrap().verified);
        run(&mut p, &c, 3_000);
        assert_eq!(active_path(&p), Some(path(0, L1)));
    }

    #[test]
    fn a_local_change_starts_a_failed_route_that_could_win_afresh_and_leaves_reported_routes_alone()
    {
        let (mut p, c) = new(&[net(A1), sw()], None);
        run(&mut p, &c, 4_200);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        p.local_change(at(5_000), &c, Families::V4);
        assert_eq!(status(&p, path(0, A1)), Status::Candidate);
        assert_eq!(status(&p, switch_path()), Status::Verified);
        run(&mut p, &c, 9_200);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        let log = run(&mut p, &c, 19_199);
        assert!(ping_times(&log, path(0, A1)).is_empty());
        let log = run(&mut p, &c, 19_200);
        assert_eq!(ping_times(&log, path(0, A1)), [19_200]);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
    }

    #[test]
    fn a_local_change_of_the_other_family_changes_nothing() {
        let (mut p, c) = dual();
        p.local_change(at(1_000), &c, Families::NONE);
        assert!(dos(&mut p).is_empty());
        assert!(p.active().unwrap().verified);
    }

    // ---- on-demand fallback ----------------------------------------------------------------

    #[test]
    fn the_fallback_asks_after_the_fallback_delay_then_every_10_s() {
        let (mut p, c) = new(&[sw()], None);
        assert!(p.fallback());
        let log = run(&mut p, &c, 200_000);
        let asks: Vec<u64> = log
            .iter()
            .filter(|(_, d)| *d == Do::Demand)
            .map(|(t, _)| t.as_duration().as_millis() as u64)
            .collect();
        let expected: Vec<u64> = (0..20).map(|k| 1_000 + 10_000 * k).collect();
        assert_eq!(asks, expected);
    }

    fn asks(log: &[(Instant, Do)]) -> Vec<Instant> {
        log.iter()
            .filter(|(_, d)| *d == Do::Demand)
            .map(|(t, _)| *t)
            .collect()
    }

    #[test]
    fn no_demand_while_an_unmetered_candidate_may_still_answer() {
        let (mut p, c) = new(&[lan(L1), net(A1), net(A2), sw()], Some(path(0, L1)));
        answer(&mut p, &c, at(30), path(0, L1));
        p.sync(at(1_000), &c, &[net(A1), net(A2), sw()]);
        assert!(p.fallback());
        let mut log = run(&mut p, &c, 1_950);
        assert_eq!(status(&p, path(0, A1)), Status::Candidate);
        assert_eq!(status(&p, path(0, A2)), Status::Candidate);
        answer(&mut p, &c, at(1_950), path(0, A2));
        assert!(!p.fallback());
        log.extend(run(&mut p, &c, 20_000));
        assert!(asks(&log).is_empty(), "{log:?}");
    }

    #[test]
    fn the_demand_follows_the_end_of_the_last_unmetered_episode() {
        let (mut p, c) = new(&[lan(L1), net(A1), net(A2), sw()], Some(path(0, L1)));
        answer(&mut p, &c, at(30), path(0, L1));
        p.sync(at(1_000), &c, &[net(A1), net(A2), sw()]);
        let log = run(&mut p, &c, 5_399);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        assert_eq!(status(&p, path(0, A2)), Status::Candidate);
        assert!(asks(&log).is_empty(), "{log:?}");
        let log = run(&mut p, &c, 6_400);
        assert_eq!(status(&p, path(0, A2)), Status::Failed);
        assert_eq!(asks(&log), [at(5_400)]);
    }

    #[test]
    fn the_demand_comes_after_the_fallback_delay_without_a_direct_candidate() {
        let (mut p, c) = new(&[sw()], None);
        let log = run(&mut p, &c, 999);
        assert!(asks(&log).is_empty());
        let log = run(&mut p, &c, 1_000);
        assert_eq!(asks(&log), [at(1_000)]);
    }

    #[test]
    fn a_route_waiting_for_its_turn_holds_the_demand_back() {
        let (mut p, c) = new(&[net(A1), net(A2), sw()], None);
        p.routes[0].state = State::Failed {
            retry_at: at(100_000),
        };
        p.routes[1].state = State::Dormant;
        p.routes[1].started = None;
        p.routes[0].started = Some(at(2_500));
        p.demand = Demand::Wanting { at: at(2_000) };
        p.settle_routes(at(2_500), &c);
        assert!(p.poll().is_none(), "A2's turn is at 2.7 s");
        assert_eq!(p.poll_timeout(&c), Some(at(2_700)));
        run(&mut p, &c, 2_700);
        assert_eq!(status(&p, path(0, A2)), Status::Candidate);
        assert!(asks(&run(&mut p, &c, 3_000)).is_empty());
    }

    #[test]
    fn a_zero_fallback_delay_demands_at_once_while_a_probe_runs() {
        let c = Config {
            fallback_delay: Duration::ZERO,
            ..Config::default()
        };
        let mut p = Paths::new(at(0), &c, &[net(A1), sw()], None);
        assert_eq!(status(&p, path(0, A1)), Status::Candidate);
        assert!(dos(&mut p).contains(&Do::Demand));
    }

    #[test]
    fn the_fallback_follows_the_configured_fallback_delay() {
        let c = Config {
            fallback_delay: ms(500),
            ..Config::default()
        };
        let mut p = Paths::new(at(0), &c, &[sw()], None);
        dos(&mut p);
        let log = run(&mut p, &c, 600);
        assert_eq!(log, [(at(500), Do::Demand)]);
    }

    #[test]
    fn an_unmetered_usable_route_disarms_the_fallback() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        assert!(p.fallback());
        answer(&mut p, &c, at(30), path(0, A1));
        assert!(!p.fallback());
        let log = run(&mut p, &c, 20_000);
        assert!(!log.iter().any(|(_, d)| *d == Do::Demand));
    }

    #[test]
    fn losing_the_last_unmetered_route_arms_the_fallback_again_from_that_moment() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        answer(&mut p, &c, at(30), path(0, A1));
        assert!(!p.fallback());
        p.sync(at(10_000), &c, &[sw()]);
        assert!(p.fallback());
        let log = run(&mut p, &c, 14_000);
        let asks: Vec<Instant> = log
            .iter()
            .filter(|(_, d)| *d == Do::Demand)
            .map(|(t, _)| *t)
            .collect();
        assert_eq!(asks, [at(11_000)]);
    }

    #[test]
    fn a_metered_route_does_not_satisfy_the_fallback() {
        let (mut p, c) = new(&[relay(A2), sw()], None);
        answer(&mut p, &c, at(30), path(1, A2));
        assert!(p.fallback());
    }

    // ---- loss ------------------------------------------------------------------------------

    #[test]
    fn lost_is_reported_once_when_every_route_has_failed() {
        let (mut p, c) = new(&[net(A1), net(A2)], None);
        let log = run(&mut p, &c, 4_399);
        assert!(!log.iter().any(|(_, d)| *d == Do::Lost));
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        let log = run(&mut p, &c, 4_400);
        assert_eq!(log.iter().filter(|(_, d)| *d == Do::Lost).count(), 1);
        let log = run(&mut p, &c, 60_000);
        assert!(!log.iter().any(|(_, d)| *d == Do::Lost));
    }

    #[test]
    fn with_no_active_route_no_route_stays_dormant_so_lost_follows_the_last_failure() {
        let (mut p, c) = new(&[net(A1), net(A2), net(A3), lan(L1)], None);
        run(&mut p, &c, 450);
        assert!(
            p.routes()
                .iter()
                .all(|r| r.status == Status::Candidate || r.status == Status::Failed),
            "{:?}",
            p.routes()
        );
        let log = run(&mut p, &c, 4_599);
        assert!(!log.iter().any(|(_, d)| *d == Do::Lost));
        let log = run(&mut p, &c, 4_600);
        assert_eq!(log.iter().filter(|(_, d)| *d == Do::Lost).count(), 1);
        assert!(p.routes().iter().all(|r| r.status == Status::Failed));
    }

    #[test]
    fn the_last_active_route_failing_wakes_the_dormant_routes_before_the_session_is_lost() {
        let (mut p, c) = new(&[lan(L1), net(A1)], Some(path(0, L1)));
        answer(&mut p, &c, at(5), path(0, L1));
        assert_eq!(status(&p, path(0, A1)), Status::Dormant);
        p.on_sent(at(10_005), &c, path(0, L1), true);
        let log = run(&mut p, &c, 11_405);
        assert_eq!(status(&p, path(0, L1)), Status::Failed);
        assert_eq!(
            status(&p, path(0, A1)),
            Status::Candidate,
            "woken by the Suspect route"
        );
        assert!(!log.iter().any(|(_, d)| *d == Do::Lost));
        let log = run(&mut p, &c, 20_000);
        assert_eq!(log.iter().filter(|(_, d)| *d == Do::Lost).count(), 1);
    }

    #[test]
    fn lost_is_not_reported_while_a_reported_route_remains() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        let log = run(&mut p, &c, 20_000);
        assert!(!log.iter().any(|(_, d)| *d == Do::Lost));
    }

    #[test]
    fn lost_is_not_reported_while_a_probe_route_is_not_failed() {
        let (mut p, c) = new(&[net(A1), relay(A2)], None);
        answer(&mut p, &c, at(30), path(1, A2));
        let log = run(&mut p, &c, 20_000);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
        assert!(!log.iter().any(|(_, d)| *d == Do::Lost));
    }

    #[test]
    fn lost_is_reported_again_after_the_condition_cleared() {
        let (mut p, c) = new(&[net(A1)], None);
        let log = run(&mut p, &c, 14_200);
        assert_eq!(log.iter().filter(|(_, d)| *d == Do::Lost).count(), 1);
        answer(&mut p, &c, at(14_250), path(0, A1));
        assert_eq!(active_path(&p), Some(path(0, A1)));
        p.on_sent(at(25_000), &c, path(0, A1), true);
        let log = run(&mut p, &c, 26_400);
        assert_eq!(log.iter().filter(|(_, d)| *d == Do::Lost).count(), 1);
        assert_eq!(status(&p, path(0, A1)), Status::Failed);
    }

    // ---- sync ------------------------------------------------------------------------------

    #[test]
    fn sync_keeps_the_state_and_rtt_of_a_route_and_updates_its_class_label_and_origin() {
        let (mut p, c) = verified_pair();
        let upgraded = spec(path(0, A1), LAN, "lan", Origin::Candidate);
        p.sync(at(100), &c, &[upgraded, sw()]);
        let r = p
            .routes()
            .into_iter()
            .find(|r| r.path == path(0, A1))
            .unwrap();
        assert_eq!(
            (r.status, r.srtt, r.class, r.label),
            (Status::Verified, Some(ms(30)), LAN, "lan")
        );
        assert!(dos(&mut p).is_empty());
    }

    #[test]
    fn sync_makes_a_new_path_dormant_until_its_turn_and_a_reported_one_verified() {
        let (mut p, c) = new(&[net(A1)], None);
        let other = Path {
            via: TransportId(8),
            to: Remote::Peer(key(2)),
        };
        let other_sw = spec(other, SWITCH, "switch", Origin::Reported);
        p.sync(at(50), &c, &[net(A1), net(A2), other_sw]);
        assert!(dos(&mut p).is_empty());
        assert_eq!(status(&p, path(0, A2)), Status::Dormant);
        assert_eq!(status(&p, other), Status::Verified);
        let log = run(&mut p, &c, 200);
        assert_eq!(ping_times(&log, path(0, A2)), [200]);
        assert_eq!(status(&p, path(0, A2)), Status::Candidate);
    }

    #[test]
    fn sync_starts_a_new_path_at_once_if_it_could_win_and_its_class_is_not_busy() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        run(&mut p, &c, 500);
        p.sync(at(500), &c, &[net(A1), net(A2), sw()]);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, A2)]);
        p.sync(at(600), &c, &[net(A1), net(A2), lan(L1), sw()]);
        assert_eq!(ping_paths(&dos(&mut p)), [path(0, L1)]);
    }

    #[test]
    fn sync_drops_a_route_that_is_gone_and_loses_it_if_it_was_active() {
        let (mut p, c) = new(&[net(A1), net(A2), sw()], None);
        answer(&mut p, &c, at(30), path(0, A1));
        assert_eq!(active_path(&p), Some(path(0, A1)));
        p.sync(at(40), &c, &[net(A2), sw()]);
        assert_eq!(p.routes().len(), 2);
        assert!(p.routes().iter().all(|r| r.path != path(0, A1)));
        assert_eq!(active_path(&p), None);
    }

    #[test]
    fn sync_keeps_the_order_of_the_specs() {
        let (mut p, c) = new(&[net(A1), net(A2), net(A3)], None);
        p.sync(at(10), &c, &[net(A3), net(A1), net(A2)]);
        let order: Vec<Path> = p.routes.iter().map(|r| r.spec.path).collect();
        assert_eq!(order, [path(0, A3), path(0, A1), path(0, A2)]);
    }

    #[test]
    fn sync_lists_the_learned_routes_again() {
        let (mut p, c) = roamed();
        let again: Vec<Spec> = [net(A1), sw()]
            .into_iter()
            .chain(p.learned().map(|l| learned(&l.addr().unwrap().to_string())))
            .collect();
        p.sync(at(1_100), &c, &again);
        assert_eq!(p.learned().collect::<Vec<_>>(), [path(0, A2)]);
        assert_eq!(active_path(&p), Some(path(0, A2)));
    }

    // ---- accessors -------------------------------------------------------------------------

    #[test]
    fn traffic_goes_on_the_active_route_when_it_meets_the_class() {
        let (p, _) = new(&[net(A1), sw()], Some(path(0, A1)));
        let any = DeliveryClass {
            band: WantBand::Any,
            latency: WantLatency::Any,
            degrade: false,
        };
        assert_eq!(
            p.route_for(&DeliveryClass::default()),
            Delivery::Route(path(0, A1))
        );
        assert_eq!(p.route_for(&any), Delivery::Route(path(0, A1)));
        let low = DeliveryClass {
            latency: WantLatency::Low,
            ..DeliveryClass::default()
        };
        assert_eq!(p.route_for(&low), Delivery::Wait);
        let low = DeliveryClass {
            degrade: true,
            ..low
        };
        assert_eq!(p.route_for(&low), Delivery::Degraded(path(0, A1)));
    }

    #[test]
    fn traffic_waits_on_a_low_band_route_unless_it_may_degrade() {
        let (p, _) = new(&[net(A1), sw()], None);
        assert_eq!(p.route_for(&DeliveryClass::default()), Delivery::Wait);
        let degrade = DeliveryClass {
            degrade: true,
            ..DeliveryClass::default()
        };
        assert_eq!(p.route_for(&degrade), Delivery::Degraded(switch_path()));
    }

    #[test]
    fn traffic_waits_without_an_active_route() {
        let (p, _) = new(&[net(A1)], None);
        let degrade = DeliveryClass {
            degrade: true,
            ..DeliveryClass::default()
        };
        assert_eq!(p.route_for(&degrade), Delivery::Wait);
    }

    #[test]
    fn control_goes_on_every_reported_route_then_the_active_one() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        assert_eq!(p.control_paths(), [switch_path()]);
        answer(&mut p, &c, at(30), path(0, A1));
        assert_eq!(p.control_paths(), [switch_path(), path(0, A1)]);
        let (p, _) = new(&[net(A1)], None);
        assert!(p.control_paths().is_empty());
    }

    #[test]
    fn the_rto_is_the_active_routes_or_the_initial_one() {
        let (p, _) = new(&[net(A1)], None);
        assert_eq!(p.rto(), INITIAL_RTO);
        let (p, _) = verified_pair();
        assert_eq!(p.rto(), ms(200));
    }

    #[test]
    fn route_infos_are_in_rank_order_and_mark_the_active_route() {
        let (p, _) = verified_pair();
        let infos = p.routes();
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].path, path(0, A1));
        assert!(infos[0].active && !infos[1].active);
        assert_eq!(infos[0].srtt, Some(ms(30)));
        assert_eq!(infos[1].label, "switch");
    }

    #[test]
    fn probing_lasts_while_a_candidate_is_in_its_episode() {
        let (mut p, c) = new(&[net(A1), sw()], None);
        assert!(p.probing());
        answer(&mut p, &c, at(30), path(0, A1));
        assert!(!p.probing());
    }

    #[test]
    fn the_next_timeout_is_the_next_ping_of_an_episode() {
        let (p, c) = new(&[net(A1), sw()], None);
        assert_eq!(p.poll_timeout(&c), Some(at(100)));
    }

    #[test]
    fn nothing_is_due_for_a_settled_unmetered_session() {
        let (p, c) = verified_pair();
        assert_eq!(p.poll_timeout(&c), Some(at(25_000)));
    }

    // ---- Two sides exchanging pings and pongs ----------------------------------------------

    enum Frame {
        Ping(u64),
        Pong(u64),
    }

    struct Msg {
        at: Instant,
        seq: u64,
        to: usize,
        path: Path,
        frame: Frame,
    }

    type Link = Box<dyn Fn(usize, Path, Instant) -> Option<(Duration, Path)>>;

    /// Two [`Paths`], side 0 and side 1. What one side asks to send is delivered to the other
    /// after the latency of `link` on the path the other sees it arrive on, or dropped.
    struct Pair {
        now: Instant,
        cfg: Config,
        sides: [Option<Paths>; 2],
        specs: [Vec<Spec>; 2],
        link: Link,
        queue: Vec<Msg>,
        seq: u64,
        active: [Option<Path>; 2],
        changes: Vec<(Instant, usize, Option<Path>)>,
        pings: Vec<(Instant, usize, Path)>,
        events: Vec<(Instant, usize, Do)>,
    }

    impl Pair {
        fn new(a: Vec<Spec>, b: Vec<Spec>, link: Link) -> Pair {
            Pair {
                now: Instant::ZERO,
                cfg: Config::default(),
                sides: [None, None],
                specs: [a, b],
                link,
                queue: Vec::new(),
                seq: 0,
                active: [None, None],
                changes: Vec::new(),
                pings: Vec::new(),
                events: Vec::new(),
            }
        }

        fn start(&mut self, side: usize, verified: Option<Path>) {
            self.sides[side] = Some(Paths::new(self.now, &self.cfg, &self.specs[side], verified));
            self.pump(side);
        }

        fn pump(&mut self, side: usize) {
            let now = self.now;
            let p = self.sides[side].as_mut().unwrap();
            let out: Vec<Do> = std::iter::from_fn(|| p.poll()).collect();
            let active = p.active().map(|a| a.path);
            for d in out {
                match d {
                    Do::Ping { path, txid } => {
                        self.pings.push((now, side, path));
                        self.send(side, path, Frame::Ping(txid));
                    }
                    Do::Pong { path, txid, .. } => self.send(side, path, Frame::Pong(txid)),
                    other => self.events.push((now, side, other)),
                }
            }
            if active != self.active[side] {
                self.active[side] = active;
                self.changes.push((now, side, active));
            }
        }

        fn send(&mut self, side: usize, path: Path, frame: Frame) {
            if let Some((latency, arrives_on)) = (self.link)(side, path, self.now) {
                self.seq += 1;
                self.queue.push(Msg {
                    at: self.now + latency,
                    seq: self.seq,
                    to: 1 - side,
                    path: arrives_on,
                    frame,
                });
            }
        }

        fn deliver(&mut self, m: Msg) {
            if self.sides[m.to].is_none() {
                self.start(m.to, None);
            }
            let spec = self.specs[m.to]
                .iter()
                .find(|s| s.path == m.path)
                .copied()
                .unwrap_or_else(|| spec(m.path, NET, "learned", Origin::Learned));
            let (now, cfg) = (self.now, self.cfg);
            let p = self.sides[m.to].as_mut().unwrap();
            match m.frame {
                Frame::Ping(txid) => p.on_ping(now, &cfg, spec, txid),
                Frame::Pong(txid) => p.on_pong(now, &cfg, m.path, txid),
            }
            self.pump(m.to);
        }

        fn run_until(&mut self, until: Instant) {
            let cfg = self.cfg;
            for _ in 0..100_000 {
                let msg = self.queue.iter().map(|m| m.at).min();
                let timer = self
                    .sides
                    .iter()
                    .flatten()
                    .filter_map(|p| p.poll_timeout(&cfg))
                    .min();
                let Some(t) = msg.into_iter().chain(timer).min().filter(|t| *t <= until) else {
                    self.now = self.now.max(until);
                    return;
                };
                self.now = self.now.max(t);
                while let Some(i) = self
                    .queue
                    .iter()
                    .enumerate()
                    .filter(|(_, m)| m.at <= self.now)
                    .min_by_key(|(_, m)| (m.at, m.seq))
                    .map(|(i, _)| i)
                {
                    let m = self.queue.remove(i);
                    self.deliver(m);
                }
                for side in 0..2 {
                    let now = self.now;
                    if let Some(p) = &mut self.sides[side]
                        && p.poll_timeout(&cfg).is_some_and(|t| t <= now)
                    {
                        p.handle_timeout(now, &cfg);
                        self.pump(side);
                    }
                }
            }
            panic!("the exchange does not settle");
        }

        fn changes(&self, side: usize) -> Vec<(Instant, Option<Path>)> {
            self.changes
                .iter()
                .filter(|(_, s, _)| *s == side)
                .map(|(t, _, a)| (*t, *a))
                .collect()
        }

        fn sent_on(&self, side: usize, path: Path) -> Vec<Instant> {
            self.pings
                .iter()
                .filter(|(_, s, p)| *s == side && *p == path)
                .map(|(t, _, _)| *t)
                .collect()
        }

        fn status(&self, side: usize, path: Path) -> Status {
            status(self.sides[side].as_ref().unwrap(), path)
        }

        fn lost(&self) -> bool {
            self.events.iter().any(|(_, _, d)| *d == Do::Lost)
        }
    }

    fn us(n: u64) -> Instant {
        Instant::from_duration(Duration::from_micros(n))
    }

    #[test]
    fn exchange_10_1_two_port_restricted_nats_end_up_on_the_direct_path_on_both_sides() {
        let s = switch_path();
        let u = path(0, "2.2.2.2:5000");
        let u2 = path(0, "1.1.1.1:4000");
        let link: Link = Box::new(move |from, p, now| match (from, p) {
            (_, p) if p == s => Some((ms(40), s)),
            (0, p) if p == u => (now >= at(120)).then_some((ms(15), u2)),
            (1, p) if p == u2 => Some((ms(15), u)),
            _ => None,
        });
        let mut pair = Pair::new(
            vec![spec(u, NET, "punch", Origin::Candidate), sw()],
            vec![spec(u2, NET, "punch", Origin::Candidate), sw()],
            link,
        );
        pair.run_until(at(80));
        pair.start(0, Some(s));
        pair.run_until(at(1_000));

        assert_eq!(pair.changes(0), [(at(80), Some(s)), (at(165), Some(u))]);
        assert_eq!(pair.changes(1), [(at(120), Some(s)), (at(150), Some(u2))]);
        assert_eq!(pair.sent_on(0, u), [at(80), at(135)]);
        assert_eq!(pair.sent_on(1, u2), [at(120)]);

        pair.run_until(at(30_000));
        assert_eq!(pair.changes(0).len(), 2);
        assert_eq!(pair.changes(1).len(), 2);
        assert_eq!(pair.status(0, u), Status::Verified);
        assert_eq!(pair.status(1, u2), Status::Verified);
        assert!(!pair.lost());
    }

    #[test]
    fn exchange_10_2_a_one_way_path_leaves_the_two_sides_on_different_routes() {
        let s = switch_path();
        let e = path(0, "198.51.100.7:51820");
        let l = path(0, "1.1.1.1:4000");
        let link: Link = Box::new(move |from, p, _| match (from, p) {
            (_, p) if p == s => Some((ms(40), s)),
            (0, p) if p == e => Some((ms(15), l)),
            _ => None,
        });
        let mut pair = Pair::new(
            vec![spec(e, NET, "static", Origin::Candidate), sw()],
            vec![spec(l, NET, "punch", Origin::Candidate), sw()],
            link,
        );
        pair.run_until(at(1_080));
        pair.start(0, Some(s));
        pair.run_until(at(1_200));

        assert_eq!(
            pair.changes(0),
            [(at(1_080), Some(s)), (at(1_135), Some(e))]
        );
        assert_eq!(pair.changes(1), [(at(1_095), Some(s))]);
        let on_l = pair.sent_on(1, l);
        assert_eq!(on_l[..2], [at(1_095), at(1_095)]);

        pair.run_until(at(4_300));
        assert_eq!(pair.status(1, l), Status::Candidate);
        pair.run_until(at(5_294));
        assert_eq!(pair.status(1, l), Status::Candidate);
        pair.run_until(at(5_295));
        assert_eq!(pair.status(1, l), Status::Failed);
        assert_eq!(pair.sent_on(1, l).len(), 8);

        pair.run_until(at(60_000));
        assert_eq!(pair.changes(0).len(), 2);
        assert_eq!(pair.changes(1).len(), 1);
        assert_eq!(pair.active, [Some(e), Some(s)]);
        assert!(!pair.lost());
        let retries: Vec<Instant> = pair
            .sent_on(1, l)
            .into_iter()
            .filter(|t| *t > at(5_300) && *t < at(26_000))
            .collect();
        assert_eq!(
            retries,
            [15_295, 25_295].map(at),
            "one ping every 10 s to the address that never answers"
        );
    }

    #[test]
    fn exchange_10_4_a_lan_known_before_the_handshake_wins_on_both_sides_and_the_punch_goes_dormant()
     {
        let s = switch_path();
        let la = path(0, "192.168.1.5:5000");
        let lb = path(0, "192.168.1.4:5000");
        let pa = path(0, "1.1.1.1:5000");
        let pb = path(0, "1.1.1.1:6000");
        let link: Link = Box::new(move |from, p, _| match (from, p) {
            (_, p) if p == s => Some((ms(40), s)),
            (0, p) if p == la => Some((ms(1), lb)),
            (1, p) if p == lb => Some((ms(1), la)),
            _ => None,
        });
        let mut pair = Pair::new(
            vec![
                spec(la, LAN, "lan", Origin::Candidate),
                spec(pa, NET, "punch", Origin::Candidate),
                sw(),
            ],
            vec![
                spec(lb, LAN, "lan", Origin::Candidate),
                spec(pb, NET, "punch", Origin::Candidate),
                sw(),
            ],
            link,
        );
        pair.run_until(at(2));
        pair.start(0, Some(la));
        pair.run_until(at(10));

        assert_eq!(pair.changes(0), [(at(2), Some(la))]);
        assert_eq!(pair.changes(1), [(at(3), Some(s)), (at(5), Some(lb))]);
        assert_eq!(pair.status(0, pa), Status::Dormant, "A: P cannot win");
        assert_eq!(
            pair.status(1, pb),
            Status::Dormant,
            "B: P stops when L is active"
        );

        pair.run_until(at(60_000));
        assert!(pair.sent_on(0, pa).is_empty(), "A never pings P");
        assert_eq!(
            pair.sent_on(1, pb),
            [at(3)],
            "B pings P once, before L answers"
        );
        assert_eq!(pair.active, [Some(la), Some(lb)]);
        assert_eq!(pair.changes(0).len(), 1);
        assert_eq!(pair.changes(1).len(), 2);
        assert!(!pair.lost());
    }

    fn wifi_and_cell(wifi_up: bool) -> Pair {
        let s = switch_path();
        let wa = path(1, "10.0.0.2:1000");
        let wb = path(1, "10.0.0.3:1000");
        let ca = path(2, "100.64.0.2:1000");
        let cb = path(2, "100.64.0.3:1000");
        let link: Link = Box::new(move |from, p, _| match (from, p) {
            (_, p) if p == s => Some((ms(40), s)),
            (0, p) if p == wa => wifi_up.then_some((Duration::from_micros(22_500), wb)),
            (1, p) if p == wb => wifi_up.then_some((Duration::from_micros(22_500), wa)),
            (0, p) if p == ca => Some((ms(15), cb)),
            (1, p) if p == cb => Some((ms(15), ca)),
            _ => None,
        });
        Pair::new(
            vec![
                spec(wa, NET, "lan", Origin::Candidate),
                spec(ca, RELAY, "relay", Origin::Candidate),
                sw(),
            ],
            vec![
                spec(wb, NET, "lan", Origin::Candidate),
                spec(cb, RELAY, "relay", Origin::Candidate),
                sw(),
            ],
            link,
        )
    }

    #[test]
    fn exchange_10_6_reordered_pongs_never_put_data_on_the_metered_route() {
        let wa = path(1, "10.0.0.2:1000");
        let ca = path(2, "100.64.0.2:1000");
        let mut pair = wifi_and_cell(true);
        pair.start(0, None);

        pair.run_until(us(44_999));
        assert_eq!(pair.status(0, ca), Status::Verified);
        assert_eq!(pair.status(0, wa), Status::Candidate);
        assert_eq!(pair.active[0], Some(switch_path()));
        assert!(pair.sides[0].as_ref().unwrap().settle.is_some());

        pair.run_until(us(45_000));
        assert_eq!(pair.active[0], Some(wa));
        assert_eq!(
            pair.changes(0),
            [(us(0), Some(switch_path())), (us(45_000), Some(wa))]
        );
        assert!(pair.sides[0].as_ref().unwrap().settle.is_none());

        pair.run_until(at(30_000));
        assert_eq!(pair.active[0], Some(wa));
        assert_eq!(pair.changes(0).len(), 2);
    }

    #[test]
    fn exchange_10_6_with_no_pong_on_wifi_the_move_to_cellular_happens_after_twice_its_srtt() {
        let ca = path(2, "100.64.0.2:1000");
        let mut pair = wifi_and_cell(false);
        pair.start(0, None);
        pair.run_until(us(89_999));
        assert_eq!(pair.active[0], Some(switch_path()));
        pair.run_until(us(90_000));
        assert_eq!(pair.active[0], Some(ca));
        assert_eq!(
            pair.changes(0),
            [(us(0), Some(switch_path())), (us(90_000), Some(ca))]
        );
    }
}
