//! Routing end to end on the simulator: whole nodes with handshakes, NATs, the switch and TURN
//!. Time is measured from the instant both ends of the session were up.
//!
//! Topologies. The public pair: A at 203.0.113.1 and B at 203.0.113.2, 10 ms apart, both
//! registered with a switch (10 ms), a TURN server (20 ms to a host and back through the relayed
//! address). Data flows both ways every 100 ms. The LAN pair: A and B on one LAN behind a NAT
//! that does not hairpin, 10 ms apart.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use vardevall_proto::discovery::candidate::Candidate;
use vardevall_proto::node::{Config, Event, PeerState, RouteView};
use vardevall_proto::route::{DETECT_TIMEOUT, DeliveryClass, FALLBACK_DELAY, Latency, Status};
use vardevall_proto::session::KEEPALIVE_TIMEOUT;
use vardevall_proto::sim::*;
use vardevall_proto::time::Instant;
use vardevall_proto::transport::{Path, Remote};

mod trace;

const DATA_EVERY_MS: u64 = 100;
/// Bytes of a packet of the streams.
const PACKET: usize = 300;
/// Frames of at least this size are data.
const DATA_FRAME: usize = 200;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn link(n: u64) -> LinkConfig {
    LinkConfig::latency(ms(n))
}

fn cfg(_: &mut Config) {}

fn up(sim: &Sim, a: HostId, b: HostId) -> bool {
    [(a, b), (b, a)].iter().all(|(x, y)| {
        sim.states(*x, *y)
            .iter()
            .any(|(_, s)| matches!(s, PeerState::Up { .. }))
    })
}

/// What a route is: `"switch"`, `"relay"` for any other metered route (a relay candidate, or a
/// route through a TURN allocation), else its label.
fn kind(v: &RouteView) -> &'static str {
    match v.label {
        "switch" => "switch",
        _ if v.class.metered => "relay",
        label => label,
    }
}

fn kinds_of(sim: &Sim, a: HostId, b: HostId) -> [Option<&'static str>; 2] {
    [sim.active(a, b), sim.active(b, a)].map(|r| r.as_ref().map(kind))
}

struct Scene {
    sim: Sim,
    a: HostId,
    b: HostId,
    /// When both ends had the session up.
    t0: Instant,
    /// The site of the hosts.
    site: SiteId,
}

impl Drop for Scene {
    fn drop(&mut self) {
        trace::save(&self.sim, self.t0);
    }
}

impl Scene {
    fn at(&self, ms_after: u64) -> Instant {
        self.t0 + ms(ms_after)
    }

    /// Runs until `ms_after` ms after the session came up.
    fn until_ms(&mut self, ms_after: u64) {
        let d = self.at(ms_after) - self.sim.now();
        self.sim.run(d);
    }

    fn until(&mut self, s: u64) {
        self.until_ms(s * 1000);
    }

    /// Runs until the session is up at both ends; time zero is that instant.
    fn start(&mut self) {
        let (a, b) = (self.a, self.b);
        assert!(self.sim.run_until(secs(10), |s| up(s, a, b)), "no session");
        let first_up = |h: HostId, p: HostId| {
            self.sim
                .states(h, p)
                .iter()
                .find(|(_, s)| matches!(s, PeerState::Up { .. }))
                .unwrap()
                .0
        };
        self.t0 = first_up(a, b).max(first_up(b, a));
    }

    /// What the two active routes are, by [`kind`].
    fn kinds(&self) -> [Option<&'static str>; 2] {
        kinds_of(&self.sim, self.a, self.b)
    }

    fn routes(&self) -> [Option<RouteView>; 2] {
        [
            self.sim.active(self.a, self.b),
            self.sim.active(self.b, self.a),
        ]
    }

    fn paths(&self) -> [Option<Path>; 2] {
        self.routes().map(|r| r.map(|v| v.path))
    }

    fn gap(&self, side: usize, from: Instant, to: Instant) -> Duration {
        let (me, other) = if side == 0 {
            (self.a, self.b)
        } else {
            (self.b, self.a)
        };
        self.sim.gap(me, other, from, to)
    }

    /// Hands out the hosts as `[A, B]`.
    fn hosts(&self) -> [HostId; 2] {
        [self.a, self.b]
    }

    /// Frames with content that left `host` after `after`, on UDP or through TURN.
    fn signals(&self, host: HostId, after: Instant) -> Vec<&Hop> {
        self.sim
            .hops()
            .iter()
            .filter(|h| {
                h.from == End::Host(host)
                    && h.at > after
                    && h.signal
                    && matches!(h.medium, MediumKind::Udp | MediumKind::Turn)
            })
            .collect()
    }

    /// Pings that left `host` between `from` and `to`, on `medium` or on any.
    fn pings(&self, host: HostId, medium: Option<MediumKind>, from: Instant, to: Instant) -> usize {
        self.sim
            .hops()
            .iter()
            .filter(|h| {
                h.from == End::Host(host)
                    && h.what == "ping"
                    && h.at >= from
                    && h.at <= to
                    && medium.is_none_or(|m| h.medium == m)
            })
            .count()
    }

    /// When pings left `host` towards the UDP address `dst`.
    fn pings_to(&self, host: HostId, dst: SocketAddr) -> Vec<Instant> {
        self.sim
            .hops()
            .iter()
            .filter(|h| {
                h.from == End::Host(host)
                    && h.what == "ping"
                    && h.medium == MediumKind::Udp
                    && h.dst == Some(dst)
            })
            .map(|h| h.at)
            .collect()
    }

    /// The pings of a link that works from `sender` to `dead` only, after 30 s. `sender` pings
    /// the other node's address every `DETECT_TIMEOUT`, no frame of the peer coming back on it.
    /// `dead` pings `sender`'s address in one episode, with a triggered ping for each ping that
    /// arrives while the route is `Candidate`, then once per 10 s; its active route, a relay,
    /// is pinged once per `KEEPALIVE_TIMEOUT`.
    fn one_way_pings(&self, sender: HostId, dead: HostId) {
        let all = |h: HostId, m: MediumKind| self.pings(h, Some(m), Instant::ZERO, self.sim.now());
        let to = |h: HostId, dst: SocketAddr| -> Vec<Duration> {
            self.pings_to(h, dst).iter().map(|t| *t - self.t0).collect()
        };
        let live = to(sender, self.sim.addr(dead));
        assert_eq!(live.len(), 15, "one per 2 s: {live:?}");
        assert!(
            live[1..].windows(2).all(|w| w[1] - w[0] == secs(2)),
            "{live:?}"
        );
        let blocked = to(dead, self.sim.addr(sender));
        let (episode, later): (Vec<Duration>, Vec<Duration>) =
            blocked.iter().partition(|t| **t < secs(5));
        assert_eq!(episode.len(), 10, "7 pings and 3 triggered: {blocked:?}");
        assert_eq!(later.len(), 2, "one per 10 s: {blocked:?}");
        assert!(later.windows(2).all(|w| w[1] - w[0] == secs(10)));
        assert_eq!(all(sender, MediumKind::Udp), 15);
        assert_eq!(all(sender, MediumKind::Turn), 0);
        assert_eq!(all(dead, MediumKind::Udp), 12);
        assert_eq!(all(dead, MediumKind::Turn), 3, "one per 10 s on the relay");
        assert_eq!(all(sender, MediumKind::Switch), 1);
        assert_eq!(all(dead, MediumKind::Switch), 1);
    }

    /// Data that left `host` after `after` through the switch.
    fn switch_data(&self, host: HostId, after: Instant) -> Vec<Instant> {
        self.sim
            .hops()
            .iter()
            .filter(|h| {
                h.from == End::Host(host)
                    && h.medium == MediumKind::Switch
                    && !h.signal
                    && h.len >= DATA_FRAME
                    && h.at >= after
            })
            .map(|h| h.at)
            .collect()
    }

    /// How often the active path of `host` to `peer` changed after `after`.
    fn route_changes(&self, host: HostId, peer: HostId, after: Instant) -> usize {
        let mut previous = None;
        let mut changes = 0;
        for (t, route) in self.sim.routes(host, peer) {
            let path = route.map(|v| v.path);
            changes += usize::from(t > after && path != previous);
            previous = path;
        }
        changes
    }

    /// Times at which `host` asked for a relay.
    /// When `host` asked for an on-demand transport.
    fn ask_times(&self, host: HostId) -> Vec<Instant> {
        self.sim
            .demands()
            .iter()
            .filter(|d| d.1 == host && d.2)
            .map(|d| d.0)
            .collect()
    }

    fn asks(&self, host: HostId) -> usize {
        self.sim
            .demands()
            .iter()
            .filter(|d| d.1 == host && d.2)
            .count()
    }

    /// Direct UDP between the two hosts, each way.
    fn direct(&mut self, a_to_b: bool, b_to_a: bool) {
        let (a, b) = (End::Host(self.a), End::Host(self.b));
        self.sim.block(a, b, !a_to_b);
        self.sim.block(b, a, !b_to_a);
    }

    /// The TURN server, as far as the hosts reach it.
    fn relay(&mut self, up: bool) {
        for h in self.hosts() {
            self.sim.block(End::Host(h), End::Turn, !up);
            self.sim.block(End::Turn, End::Host(h), !up);
        }
    }

    /// Nothing but the switch.
    fn no_udp(&mut self) {
        self.direct(false, false);
        self.relay(false);
    }

    fn a_addr(&self) -> SocketAddr {
        self.sim.addr(self.a)
    }

    fn b_addr(&self) -> SocketAddr {
        self.sim.addr(self.b)
    }

    fn udp_path(&self, host: HostId, to: SocketAddr) -> Path {
        Path {
            via: self.sim.transport(host, MediumKind::Udp).unwrap(),
            to: Remote::Addr(to),
        }
    }

    fn turn_path(&self, host: HostId, to: SocketAddr) -> Path {
        Path {
            via: self.sim.transport(host, MediumKind::Turn).unwrap(),
            to: Remote::Addr(to),
        }
    }

    /// A relay that stands ready: a short outage of the direct path lets B allocate, and the
    /// direct path is back and in use when this returns.
    fn with_relay_standing(&mut self) {
        let (a, b) = (self.a, self.b);
        let relay = [Some("relay"), Some("relay")];
        let punch = [Some("punch"), Some("punch")];
        self.direct(false, false);
        assert!(self.sim.run_until(secs(40), |s| kinds_of(s, a, b) == relay));
        self.direct(true, true);
        assert!(self.sim.run_until(secs(60), |s| kinds_of(s, a, b) == punch));
    }
}

/// The public pair. B has a TURN transport; A has one too if `turn_a`.
fn public_pair(
    configure: &dyn Fn(&mut Config),
    turn_a: bool,
    class: DeliveryClass,
    every: Duration,
) -> Scene {
    let mut sim = Sim::new(5, link(5));
    sim.turn_server(ip("198.51.100.1"), link(5));
    let a = sim.host(INTERNET, ip("203.0.113.1"), |c| configure(c));
    let b = sim.host(INTERNET, ip("203.0.113.2"), |c| configure(c));
    sim.peer(a, b);
    sim.register(a, link(5));
    sim.register(b, link(5));
    sim.enable_turn(b);
    if turn_a {
        sim.enable_turn(a);
    }
    sim.stream(a, b, every, class, PACKET);
    sim.stream(b, a, every, class, PACKET);
    Scene {
        sim,
        a,
        b,
        t0: Instant::ZERO,
        site: INTERNET,
    }
}

fn pair() -> Scene {
    public_pair(&cfg, false, DeliveryClass::default(), ms(DATA_EVERY_MS))
}

fn degrading() -> DeliveryClass {
    DeliveryClass {
        degrade: true,
        ..DeliveryClass::default()
    }
}

#[test]
fn stable_links_end_on_the_direct_route_and_go_quiet() {
    let mut n = pair();
    n.start();
    n.until(15);
    assert_eq!(n.kinds(), [Some("punch"), Some("punch")]);
    for (h, p) in [(n.a, n.b), (n.b, n.a)] {
        assert!(n.route_changes(h, p, Instant::ZERO) <= 3, "no flapping");
    }
    assert_eq!(n.paths()[0], Some(n.udp_path(n.a, n.b_addr())));
    assert_eq!(n.paths()[1], Some(n.udp_path(n.b, n.a_addr())));
    let mark = n.sim.now();
    n.until(55);
    let end = n.sim.now();
    for h in n.hosts() {
        assert_eq!(
            n.pings(h, None, mark, end),
            0,
            "the peer's frames show the path: no keeping ping while data flows both ways"
        );
        assert_eq!(
            n.pings(h, Some(MediumKind::Udp), Instant::ZERO, end),
            2,
            "the probe of the direct route and the triggered ping: 7 pings in 55 s before"
        );
        assert_eq!(
            n.pings(h, Some(MediumKind::Switch), Instant::ZERO, end),
            1,
            "the first ping on the active route"
        );
        let signals = n.signals(h, mark);
        assert!(signals.is_empty(), "nothing but data: {}", signals.len());
    }
    assert!(n.gap(0, mark, n.sim.now()) <= ms(DATA_EVERY_MS + 30));
    assert!(n.gap(1, mark, n.sim.now()) <= ms(DATA_EVERY_MS + 30));
}

#[test]
fn a_one_way_direct_link_leaves_the_sender_direct_and_the_other_node_on_the_relay() {
    let mut n = pair();
    n.direct(true, false);
    n.start();
    n.until(30);
    assert_eq!(n.kinds(), [Some("punch"), Some("relay")]);
    assert_eq!(n.paths()[0], Some(n.udp_path(n.a, n.b_addr())));
    assert_eq!(n.paths()[1], Some(n.turn_path(n.b, n.a_addr())));
    let (from, to) = (n.at(10_000), n.sim.now());
    assert!(n.gap(0, from, to) <= ms(300));
    assert!(n.gap(1, from, to) <= ms(300));
    n.one_way_pings(n.a, n.b);
}

#[test]
fn a_one_way_direct_link_the_other_way_gives_the_mirror_result() {
    let mut n = public_pair(&cfg, true, DeliveryClass::default(), ms(DATA_EVERY_MS));
    n.direct(false, true);
    n.start();
    n.until(30);
    assert_eq!(n.kinds(), [Some("relay"), Some("punch")]);
    assert_eq!(n.paths()[0], Some(n.turn_path(n.a, n.b_addr())));
    assert_eq!(n.paths()[1], Some(n.udp_path(n.b, n.a_addr())));
    n.one_way_pings(n.b, n.a);
}

#[test]
fn nothing_over_udp_leaves_the_switch_path() {
    let mut n = pair();
    n.no_udp();
    n.start();
    n.until(20);
    assert_eq!(n.kinds(), [Some("switch"), Some("switch")]);
    for (host, dead) in [(n.a, n.b_addr()), (n.b, n.a_addr())] {
        let pings = n.pings_to(host, dead);
        assert_eq!(
            pings.len(),
            8,
            "an episode of 7 pings, then one 10 s after it failed: {pings:?}"
        );
        assert_eq!(pings[7] - pings[6], secs(11));
    }
    assert!(
        n.sim.arrivals(n.a, n.b).is_empty() && n.sim.arrivals(n.b, n.a).is_empty(),
        "the default class waits for a better route"
    );
    assert!(n.switch_data(n.a, Instant::ZERO).is_empty());
    let (a, b) = (n.a, n.b);
    n.sim.send(a, b, degrading(), b"degraded");
    let view = n.sim.node(a).peer_view(&n.sim.public(b)).unwrap();
    assert!(view.degraded);
    n.sim.run(secs(1));
    assert_eq!(n.sim.arrivals(b, a).len(), 1, "a degrading class goes on");
}

#[test]
fn degrading_traffic_flows_through_the_switch() {
    let mut n = public_pair(&cfg, false, degrading(), ms(DATA_EVERY_MS));
    n.no_udp();
    n.start();
    n.until(20);
    let (from, to) = (n.at(10_000), n.sim.now());
    assert!(n.gap(0, from, to) <= ms(300));
    assert!(n.gap(1, from, to) <= ms(300));
}

#[test]
fn without_switch_data_nothing_is_active() {
    let mut n = public_pair(
        &|c| c.routes.switch_data = false,
        false,
        DeliveryClass::default(),
        ms(DATA_EVERY_MS),
    );
    n.no_udp();
    n.start();
    n.until(20);
    assert_eq!(n.kinds(), [None, None]);
}

#[test]
fn an_interface_going_down_moves_both_to_the_relay_within_seconds() {
    let mut n = pair();
    let cellular = n.sim.site(
        Some(NatConfig::new(NatKind::Symmetric, ip("100.64.0.1"))),
        link(5),
        link(1),
    );
    n.sim.add_iface(n.a, cellular, ip("10.9.0.2"));
    n.start();
    n.with_relay_standing();
    assert_eq!(n.kinds(), [Some("punch"), Some("punch")]);
    let t = n.sim.now();
    n.direct(false, false);
    n.sim.set_iface(n.a, ip("10.9.0.2"), false);
    n.sim.run(secs(10));
    assert_eq!(n.kinds(), [Some("relay"), Some("relay")]);
    let end = n.sim.now();
    assert!(n.gap(1, t, end) <= ms(2500), "gap {:?}", n.gap(1, t, end));
    assert!(
        n.gap(0, t, end) <= KEEPALIVE_TIMEOUT + ms(1000),
        "B learns of the dead route from its own keeping ping: gap {:?}",
        n.gap(0, t, end)
    );
}

/// A's data reaches B from the new mapping before A's `cand` does: B follows the data and the
/// candidate then names the route it already has.
#[test]
fn a_nat_rebinding_is_followed_by_roaming() {
    rebinding(true, false);
}

/// Both streams start at once, so the handshakes cross and each node sends on the session that is
/// the other's `previous`: B still follows A's new source.
#[test]
fn a_nat_rebinding_is_followed_by_roaming_when_the_handshakes_cross() {
    rebinding(true, true);
}

/// A's `cand` reaches B before any data from the new mapping: the new address is a candidate.
#[test]
fn a_nat_rebinding_is_followed_by_the_new_candidate() {
    rebinding(false, false);
}

fn rebinding(data_first: bool, crossing: bool) {
    let mut sim = Sim::new(8, link(5));
    let nat = NatConfig::new(NatKind::PortRestricted, ip("203.0.113.1"));
    let site = sim.site(Some(nat), link(5), link(1));
    let a = sim.host(site, ip("10.0.0.2"), |_| {});
    let b = sim.host(INTERNET, ip("203.0.113.2"), |_| {});
    sim.peer(a, b);
    sim.register(a, link(5));
    sim.register(b, link(5));
    let class = DeliveryClass::default();
    sim.stream(a, b, ms(DATA_EVERY_MS), class, PACKET);
    if crossing {
        sim.stream(b, a, ms(DATA_EVERY_MS), class, PACKET);
    }
    let mut n = Scene {
        sim,
        a,
        b,
        t0: Instant::ZERO,
        site,
    };
    n.start();
    if !crossing {
        n.sim.stream(b, a, ms(DATA_EVERY_MS), class, PACKET);
    }
    n.until(15);
    assert_eq!(n.kinds(), [Some("punch"), Some("punch")]);
    if data_first {
        let phase = n.sim.now().as_duration().as_millis() as u64 % DATA_EVERY_MS;
        n.sim
            .run(ms((2 * DATA_EVERY_MS - 2 - phase) % DATA_EVERY_MS));
    }
    let t = n.sim.now();
    if data_first {
        n.sim.rebind(site);
    } else {
        n.sim.rebind_quietly(site);
        n.sim.regather(a);
    }
    n.sim.run(secs(10));
    let moved = n
        .sim
        .candidates_of(a)
        .iter()
        .find(|c| c.label == "punch")
        .unwrap()
        .addr;
    assert_eq!(n.kinds(), [Some("punch"), Some("punch")]);
    assert_eq!(n.paths()[1], Some(n.udp_path(b, moved)));
    let learned = n
        .sim
        .routes(b, a)
        .iter()
        .filter(|(at, r)| *at > t && r.as_ref().is_some_and(|v| v.label == "learned"))
        .count();
    assert_eq!(learned > 0, data_first, "{:?}", n.sim.routes(b, a));
    let end = n.sim.now();
    assert!(n.gap(1, t, end) <= ms(400), "gap {:?}", n.gap(1, t, end));
    assert!(n.gap(0, t, end) <= ms(1500), "gap {:?}", n.gap(0, t, end));
}

/// Both directions of the direct path go silent at 15 s, with data flowing both ways. Returns
/// when the later of the two nodes left the direct route and the longest gap in the data.
fn silent_failure(detect: Option<Duration>) -> (Duration, Duration) {
    let mut n = public_pair(
        &|c| c.routes.detect_timeout = detect,
        false,
        DeliveryClass::default(),
        ms(DATA_EVERY_MS),
    );
    n.start();
    n.until(15);
    let t = n.sim.now();
    n.direct(false, false);
    n.sim.run(secs(30));
    assert_eq!(n.kinds(), [Some("relay"), Some("relay")]);
    let end = n.sim.now();
    let left = |host: HostId, peer: HostId| {
        n.sim
            .routes(host, peer)
            .into_iter()
            .find(|(at, _)| *at > t)
            .map(|(at, _)| at - t)
            .expect("the route changed")
    };
    let detected = left(n.a, n.b).max(left(n.b, n.a));
    (detected, n.gap(1, t, end).max(n.gap(0, t, end)))
}

/// The keeping ping goes out with the first data 2 s after the last frame came on the path (the
/// stream is 80 ms off the failure), is unanswered after its RTO of 200 ms, and the route is
/// `Suspect`: the active route moves at once. The data waits for the relay, which is asked for
/// after `fallback_delay`, 1 s later.
#[test]
fn a_link_that_fails_silently_is_detected_by_the_unanswered_pings() {
    let (detected, gap) = silent_failure(None);
    assert!(
        detected <= DETECT_TIMEOUT + ms(300),
        "detected after {detected:?}"
    );
    assert!(gap <= ms(5_400), "gap {gap:?}");
}

#[test]
fn a_detect_timeout_below_the_default_shortens_the_detection_of_a_silent_failure() {
    let (detected, gap) = silent_failure(Some(ms(500)));
    assert!(detected <= ms(500 + 300), "detected after {detected:?}");
    assert!(gap <= ms(3_900), "gap {gap:?}");
}

#[test]
fn a_relay_is_left_for_a_direct_route_that_appears_later() {
    let mut n = pair();
    n.direct(false, false);
    n.start();
    n.until(20);
    assert_eq!(n.kinds(), [Some("relay"), Some("relay")]);
    n.direct(true, true);
    n.sim.run(secs(40));
    assert_eq!(n.kinds(), [Some("punch"), Some("punch")]);
}

#[test]
fn the_relay_fallback_waits_for_the_direct_episode_and_asks_again_every_10_s() {
    let mut n = public_pair(&cfg, true, DeliveryClass::default(), ms(DATA_EVERY_MS));
    n.sim.set_turn(false);
    n.direct(false, false);
    n.start();
    let asks_by = |n: &mut Scene, at: u64| {
        n.until_ms(at);
        (n.asks(n.a), n.asks(n.b))
    };
    assert_eq!(
        asks_by(&mut n, 4_100),
        (0, 0),
        "the fallback delay passed at 1 s, the direct episode ends at 4.2 s"
    );
    assert_eq!(asks_by(&mut n, 4_300), (1, 1));
    assert_eq!(asks_by(&mut n, 14_100), (1, 1));
    assert_eq!(asks_by(&mut n, 14_300), (2, 2), "10 s later");
    assert_eq!(asks_by(&mut n, 24_100), (2, 2));
    assert_eq!(asks_by(&mut n, 24_300), (3, 3), "10 s later");
    assert_eq!(asks_by(&mut n, 171_900), (17, 17));
    assert_eq!(
        asks_by(&mut n, 198_100),
        (20, 20),
        "the idle session ended at 180 s; its successor asks at 4.2 s and 14.2 s after coming up"
    );
}

/// A pair that is up with a working switch and a direct path nobody answers on; TURN is down.
fn dead_direct(streams: bool) -> Scene {
    let mut n = public_pair(&cfg, true, DeliveryClass::default(), ms(DATA_EVERY_MS));
    n.sim.set_turn(false);
    n.direct(false, false);
    if !streams {
        n.sim.set_stream(StreamId(1), false);
    }
    n.start();
    n
}

#[test]
fn a_route_that_never_answers_is_probed_in_one_episode_then_every_10_s_in_200_s() {
    let mut n = dead_direct(false);
    n.until(200);
    for (host, dead, expected) in [(n.a, n.b_addr(), 26), (n.b, n.a_addr(), 24)] {
        let pings = n.pings_to(host, dead);
        assert_eq!(
            pings.len(),
            expected,
            "7 pings of the episode, then one every 10 s after it failed; B's session ends \
             idle at 180 s: {pings:?}"
        );
        let gaps: Vec<Duration> = pings[7..].windows(2).map(|w| w[1] - w[0]).collect();
        assert!(gaps.iter().all(|g| *g == secs(10)), "{gaps:?}");
    }
}

#[test]
fn an_idle_session_with_dead_direct_routes_and_a_working_switch_starts_no_handshake() {
    let mut n = dead_direct(true);
    let t0 = n.t0;
    n.until(60);
    for h in [n.a, n.b] {
        let initiations = n
            .sim
            .events(h)
            .iter()
            .filter(|(at, e)| *at > t0 && matches!(e, Event::Initiation { .. }))
            .count();
        assert_eq!(
            initiations, 0,
            "queued data with no route arms no loss timer (every 15 s before)"
        );
    }
}

#[test]
fn on_a_one_way_link_the_other_node_changes_route_once_and_loses_no_data_after_it() {
    let mut n = pair();
    n.direct(true, false);
    n.start();
    n.until(30);
    let (a, b) = (n.a, n.b);
    let t0 = n.t0;
    assert_eq!(
        n.route_changes(b, a, t0),
        1,
        "the switch, then the allocation: {:?}",
        n.sim.routes(b, a)
    );
    assert!(
        n.sim
            .routes(b, a)
            .iter()
            .all(|(t, r)| *t <= t0 || r.is_some()),
        "B never has no route after it is up (twice before): {:?}",
        n.sim.routes(b, a)
    );
    let changed = n
        .sim
        .routes(b, a)
        .into_iter()
        .rev()
        .find(|(t, _)| *t > t0)
        .map(|(t, _)| t)
        .unwrap();
    let end = n.sim.now();
    let from = changed + ms(500);
    let expected = (end - from).as_millis() / u128::from(DATA_EVERY_MS);
    let arrived = n
        .sim
        .arrivals(a, b)
        .into_iter()
        .filter(|t| *t >= from)
        .count() as u128;
    assert!(
        arrived + 2 >= expected,
        "B's data after the change: {arrived} of {expected}"
    );
    assert!(n.gap(0, from, end) <= ms(300));
}

#[test]
fn no_fallback_when_a_direct_route_is_verified_in_time() {
    let mut n = public_pair(&cfg, true, DeliveryClass::default(), ms(DATA_EVERY_MS));
    n.start();
    n.until(10);
    assert_eq!(n.asks(n.a) + n.asks(n.b), 0);
}

#[test]
fn a_dead_peer_makes_the_session_lost_once_the_switch_does_not_answer() {
    let mut n = pair();
    n.start();
    n.until(15);
    let t = n.sim.now();
    n.no_udp();
    for h in n.hosts() {
        n.sim.block(End::Host(h), End::Switch, true);
        n.sim.block(End::Switch, End::Host(h), true);
    }
    n.sim.run(secs(40));
    let key = n.sim.public(n.b);
    let lost = n
        .sim
        .events(n.a)
        .iter()
        .filter(|(at, e)| *at > t && matches!(e, Event::Initiation { peer } if *peer == key))
        .count();
    assert!(lost >= 1);
}

#[test]
fn candidate_updates_are_repeated_until_confirmed_and_replace_the_peers_set() {
    let mut n = pair();
    n.start();
    n.until(5);
    let fresh = SocketAddr::new(ip("203.0.113.11"), PORT);
    n.sim.add_iface(n.a, INTERNET, fresh.ip());
    n.sim.set_iface(n.a, ip("203.0.113.1"), false);
    n.sim.run(secs(2));
    let view = n.sim.node(n.b).peer_view(&n.sim.public(n.a)).unwrap();
    assert_eq!(view.shared, [Candidate::punch(fresh)]);
    assert!(view.routes.iter().any(|r| r.path.addr() == Some(fresh)));
}

/// A's own candidates change twice at one instant, on links that reorder: the older `cand` can
/// arrive after the newer.
fn cand_run(seed: u64) -> (bool, bool) {
    let jittery = LinkConfig {
        latency: ms(10),
        jitter: ms(80),
        loss: 0.0,
    };
    let mut sim = Sim::new(seed, jittery);
    let a = sim.host(INTERNET, ip("203.0.113.1"), |_| {});
    let b = sim.host(INTERNET, ip("203.0.113.2"), |_| {});
    sim.peer(a, b);
    sim.register(a, jittery);
    sim.register(b, jittery);
    sim.send(a, b, DeliveryClass::default(), b"up");
    assert!(sim.run_until(secs(10), |s| up(s, a, b)));
    sim.run(secs(3));
    let mark = sim.hops().len();
    let (second, third) = (ip("203.0.113.11"), ip("203.0.113.12"));
    sim.add_iface(a, INTERNET, second);
    sim.set_iface(a, ip("203.0.113.1"), false);
    sim.add_iface(a, INTERNET, third);
    sim.set_iface(a, second, false);
    let wanted = [Candidate::punch(SocketAddr::new(third, PORT))];
    let mut seen_wanted = false;
    let mut regressed = false;
    for _ in 0..400 {
        sim.run(ms(1));
        let shared = sim.node(b).peer_view(&sim.public(a)).unwrap().shared;
        if shared == wanted {
            seen_wanted = true;
        } else if seen_wanted {
            regressed = true;
        }
    }
    let sent: Vec<&Hop> = sim.hops()[mark..]
        .iter()
        .filter(|h| h.from == End::Host(a) && h.medium == MediumKind::Switch)
        .collect();
    let reordered = sent.windows(2).any(|w| match (w[0].fate, w[1].fate) {
        (Fate::Delivered(x), Fate::Delivered(y)) => y < x,
        _ => false,
    });
    trace::save(&sim, Instant::ZERO);
    assert!(seen_wanted, "seed {seed}: B never got the last set");
    (regressed, reordered)
}

#[test]
fn an_old_cand_does_not_replace_a_newer_set() {
    let mut reordered = 0;
    for seed in 0..40 {
        let (regressed, swapped) = cand_run(seed);
        assert!(!regressed, "seed {seed}: an older set replaced the newer");
        reordered += usize::from(swapped);
    }
    assert!(reordered > 0, "no seed reordered the messages");
}

const A_LAN: [&str; 3] = ["192.168.1.62", "fd00::62", "fe80::62"];
const B_LAN: [&str; 3] = ["192.168.1.51", "fd00::51", "fe80::51"];
const A_NEW: &str = "192.168.7.62";
const B_NEW: &str = "192.168.7.51";

fn sock(s: &str) -> SocketAddr {
    SocketAddr::new(ip(s), PORT)
}

/// Both nodes on one LAN behind a NAT that does not hairpin, each with an IPv4, a unique-local
/// and a link-local address found by local discovery (the first `addresses` of each), and the
/// switch. Every route works both ways.
fn lan_pair(
    configure: &dyn Fn(&mut Config),
    class: DeliveryClass,
    every: Duration,
    jitter: u64,
    addresses: usize,
) -> Scene {
    let mut sim = Sim::new(5, link(5));
    let nat = NatConfig::new(NatKind::PortRestricted, ip("1.1.1.1"));
    let lan = LinkConfig {
        latency: ms(10),
        jitter: ms(jitter),
        loss: 0.0,
    };
    let site = sim.site(Some(nat), link(5), lan);
    let switch = LinkConfig {
        latency: ms(5),
        jitter: ms(jitter / 2),
        loss: 0.0,
    };
    let a = sim.host(site, ip(A_LAN[0]), |c| configure(c));
    let b = sim.host(site, ip(B_LAN[0]), |c| configure(c));
    for i in 1..addresses {
        sim.add_iface(a, site, ip(A_LAN[i]));
        sim.add_iface(b, site, ip(B_LAN[i]));
    }
    sim.peer(a, b);
    sim.register(a, switch);
    sim.register(b, switch);
    let known = |list: &[&str; 3]| -> Vec<Candidate> {
        list[..addresses]
            .iter()
            .map(|s| Candidate::lan(sock(s)))
            .collect()
    };
    sim.know(a, b, known(&B_LAN));
    sim.know(b, a, known(&A_LAN));
    sim.stream(a, b, every, class, PACKET);
    sim.stream(b, a, every, class, PACKET);
    Scene {
        sim,
        a,
        b,
        t0: Instant::ZERO,
        site,
    }
}

#[test]
fn several_lan_routes_of_one_kind_settle_on_one_route() {
    for every in [100, 1000] {
        for jitter in [0, 30] {
            lan_settles(every, jitter);
        }
    }
}

#[test]
fn several_lan_routes_of_one_kind_settle_on_one_route_with_steady_data() {
    lan_settles(100, 0);
}

fn lan_settles(every: u64, jitter: u64) {
    let mut n = lan_pair(&cfg, DeliveryClass::default(), ms(every), jitter, 3);
    n.start();
    n.until(15);
    let settled = n.paths();
    assert!(settled.iter().all(Option::is_some));
    let mark = n.sim.now();
    n.sim.run(secs(30));
    assert_eq!(n.paths(), settled);
    let end = n.sim.now();
    for h in n.hosts() {
        assert_eq!(
            n.pings(h, None, Instant::ZERO, end),
            1,
            "data every {every} ms, jitter {jitter} ms: the first ping and no other LAN address \
             is probed (every address at once, 16 to 18 pings before)"
        );
    }
    for (h, p) in [(n.a, n.b), (n.b, n.a)] {
        let later = n.route_changes(h, p, mark);
        assert_eq!(
            later,
            0,
            "data every {every} ms, jitter {jitter} ms: route changes after settling: {:?}",
            n.sim.routes(h, p)
        );
        let all = n.route_changes(h, p, Instant::ZERO);
        assert!(
            all <= 4,
            "data every {every} ms, jitter {jitter} ms: {all} changes"
        );
    }
}

impl Scene {
    /// Both nodes leave their LAN addresses: the old routes are gone and, if `to_new`, a new
    /// pair of addresses is found by local discovery at the same instant.
    fn renumber(&mut self, to_new: bool) {
        let (a, b) = (self.a, self.b);
        for (h, old) in [(a, A_LAN), (b, B_LAN)] {
            for i in old {
                self.sim.set_iface(h, ip(i), false);
            }
        }
        let (to_b, to_a) = if to_new {
            self.sim.add_iface(a, self.site, ip(A_NEW));
            self.sim.add_iface(b, self.site, ip(B_NEW));
            (
                vec![Candidate::lan(sock(B_NEW))],
                vec![Candidate::lan(sock(A_NEW))],
            )
        } else {
            (Vec::new(), Vec::new())
        };
        self.sim.know(a, b, to_b);
        self.sim.know(b, a, to_a);
    }
}

fn degrading_lan() -> Scene {
    let mut n = lan_pair(&cfg, degrading(), ms(DATA_EVERY_MS), 0, 3);
    n.start();
    n.until(15);
    assert!(n.kinds().iter().all(|k| *k == Some("lan")));
    assert!(
        n.hosts()
            .iter()
            .all(|h| n.switch_data(*h, Instant::ZERO).is_empty())
    );
    n
}

#[test]
fn a_quick_move_between_direct_routes_sends_no_data_through_the_switch() {
    let mut n = degrading_lan();
    let t = n.sim.now();
    n.renumber(true);
    n.sim.run(secs(10));
    assert_eq!(n.kinds(), [Some("lan"), Some("lan")]);
    assert_eq!(n.paths()[0], Some(n.udp_path(n.a, sock(B_NEW))));
    assert_eq!(n.paths()[1], Some(n.udp_path(n.b, sock(A_NEW))));
    let end = n.sim.now();
    for (i, h) in n.hosts().into_iter().enumerate() {
        let data = n.switch_data(h, Instant::ZERO);
        assert!(data.is_empty(), "side {i}: {data:?}");
        assert!(n.gap(i, t, end) <= ms(300), "gap {:?}", n.gap(i, t, end));
    }
}

#[test]
fn without_a_direct_route_the_switch_carries_data_after_the_fallback_delay() {
    let mut n = degrading_lan();
    let t = n.sim.now();
    n.renumber(false);
    let grace = FALLBACK_DELAY;
    n.sim.run(grace - ms(50));
    assert_eq!(n.kinds(), [None, None], "waiting for a direct route");
    n.sim.run(ms(350));
    assert_eq!(n.kinds(), [Some("switch"), Some("switch")]);
    for (i, h) in n.hosts().into_iter().enumerate() {
        let data = n.switch_data(h, Instant::ZERO);
        assert!(!data.is_empty(), "side {i}");
        assert!(data.iter().all(|at| *at >= t + grace), "side {i}: {data:?}");
    }
}

#[test]
fn with_a_zero_fallback_delay_the_switch_carries_data_at_once() {
    let mut n = lan_pair(
        &|c| c.routes.fallback_delay = Duration::ZERO,
        degrading(),
        ms(DATA_EVERY_MS),
        0,
        3,
    );
    n.start();
    n.until(15);
    let t = n.sim.now();
    n.renumber(false);
    n.sim.run(secs(1));
    assert_eq!(n.kinds(), [Some("switch"), Some("switch")]);
    for h in n.hosts() {
        assert!(
            n.switch_data(h, Instant::ZERO)
                .iter()
                .any(|at| *at <= t + ms(150))
        );
    }
}

/// What a local discovery source does with the addresses of one peer on one interface: it
/// offers the best and, when that route fails, the next.
struct Worker {
    me: HostId,
    peer: HostId,
    ranked: Vec<Candidate>,
    offered: usize,
    seen: usize,
}

impl Worker {
    fn new(me: HostId, peer: HostId, ranked: &[&str]) -> Worker {
        Worker {
            me,
            peer,
            ranked: ranked.iter().map(|s| Candidate::lan(sock(s))).collect(),
            offered: 0,
            seen: 0,
        }
    }

    fn offer(&self, sim: &mut Sim) {
        sim.know(self.me, self.peer, vec![self.ranked[self.offered]]);
    }

    fn follow(&mut self, sim: &mut Sim) {
        let key = sim.public(self.peer);
        let failed: Vec<SocketAddr> = sim
            .events(self.me)
            .iter()
            .filter_map(|(_, e)| match e {
                Event::RouteFailed { peer, addr } if *peer == key => Some(*addr),
                _ => None,
            })
            .collect();
        for addr in &failed[self.seen..] {
            if *addr == self.ranked[self.offered].addr {
                self.offered = (self.offered + 1) % self.ranked.len();
                self.offer(sim);
            }
        }
        self.seen = failed.len();
    }
}

#[test]
fn a_failed_offered_lan_route_is_replaced_by_the_next_address_of_the_ranking() {
    let (a_ranked, b_ranked) = ([A_LAN[1], A_LAN[0]], [B_LAN[1], B_LAN[0]]);
    let mut n = lan_pair(&cfg, DeliveryClass::default(), ms(DATA_EVERY_MS), 0, 1);
    let (a, b) = (n.a, n.b);
    let mut workers = [Worker::new(a, b, &b_ranked), Worker::new(b, a, &a_ranked)];
    for w in &workers {
        w.offer(&mut n.sim);
    }
    while n.sim.now() < Instant::from_millis(20_000) {
        n.sim.run(ms(10));
        for w in &mut workers {
            w.follow(&mut n.sim);
        }
    }
    assert_eq!(n.kinds(), [Some("lan"), Some("lan")]);
    assert_eq!(n.paths()[0], Some(n.udp_path(a, sock(B_LAN[0]))));
    assert_eq!(n.paths()[1], Some(n.udp_path(b, sock(A_LAN[0]))));
    for (h, p, dead) in [(a, b, b_ranked[0]), (b, a, a_ranked[0])] {
        let key = n.sim.public(p);
        let failed: Vec<SocketAddr> = n
            .sim
            .events(h)
            .iter()
            .filter_map(|(_, e)| match e {
                Event::RouteFailed { peer, addr } if *peer == key => Some(*addr),
                _ => None,
            })
            .filter(|addr| addr.ip().to_string().starts_with("fd00"))
            .collect();
        assert_eq!(failed, [sock(dead)], "fails once, not again");
        assert!(n.route_changes(h, p, Instant::ZERO) <= 3);
    }
}

/// A and B on the internet (203.0.113.1 and .2, 10 ms apart) and on one Wi-Fi LAN behind a NAT
/// that does not hairpin (10 ms apart), with data both ways; neither registry knows the other
/// node yet.
fn wifi_and_internet() -> Scene {
    let mut sim = Sim::new(5, link(5));
    let nat = NatConfig::new(NatKind::PortRestricted, ip("1.1.1.1"));
    let wifi = sim.site(Some(nat), link(5), link(10));
    let a = sim.host(INTERNET, ip("203.0.113.1"), cfg);
    let b = sim.host(INTERNET, ip("203.0.113.2"), cfg);
    sim.add_iface(a, wifi, ip(A_LAN[0]));
    sim.add_iface(b, wifi, ip(B_LAN[0]));
    sim.peer(a, b);
    sim.register(a, link(5));
    sim.register(b, link(5));
    sim.stream(a, b, ms(DATA_EVERY_MS), DeliveryClass::default(), PACKET);
    sim.stream(b, a, ms(DATA_EVERY_MS), DeliveryClass::default(), PACKET);
    Scene {
        sim,
        a,
        b,
        t0: Instant::ZERO,
        site: wifi,
    }
}

/// A LAN appearing after the handshake. Only A's registry finds B, on the LAN. A moves to its
/// LAN route and its data comes from its LAN address; B roams onto that address, a learned route
/// of internet class, like its punch route. When B's registry finds A the same route becomes B's
/// `lan` route, with its state and RTT and no new episode.
#[test]
fn a_learned_lan_route_becomes_the_lan_route_when_the_registry_finds_the_peer() {
    let mut n = wifi_and_internet();
    let (a, b) = (n.a, n.b);
    n.start();
    n.until(10);
    assert_eq!(n.kinds(), [Some("punch"), Some("punch")]);
    let (a_lan, b_lan) = (sock(A_LAN[0]), sock(B_LAN[0]));
    let b_punch = n.paths()[1];
    let t = n.sim.now();
    let routes_of =
        |n: &Scene, x: HostId, y: HostId| n.sim.node(x).peer_view(&n.sim.public(y)).unwrap().routes;
    let at = |n: &Scene, x: HostId, y: HostId, addr: SocketAddr| {
        routes_of(n, x, y)
            .into_iter()
            .filter(|r| r.path.addr() == Some(addr))
            .collect::<Vec<_>>()
    };

    n.sim.know(a, b, vec![Candidate::lan(b_lan)]);
    n.until(14);
    let a_route = n.sim.active(a, b).unwrap();
    assert_eq!(
        (a_route.label, a_route.class.latency, a_route.path),
        ("lan", Latency::Low, n.udp_path(a, b_lan))
    );

    let moves: Vec<_> = n
        .sim
        .routes(b, a)
        .into_iter()
        .filter(|(at, _)| *at > t)
        .map(|(at, r)| {
            let r = r.unwrap();
            (at - t, r.label, r.class.latency, r.verified, r.path)
        })
        .collect();
    let learned_path = n.udp_path(b, a_lan);
    assert_eq!(
        moves,
        [
            (ms(90), "learned", Latency::High, false, learned_path),
            (ms(110), "learned", Latency::High, true, learned_path),
        ],
        "B roams onto the LAN source of A's data, one data packet after A's route is up, and \
         its ping is answered at once"
    );
    let roam = n.pings_to(b, a_lan);
    assert_eq!(roam.len(), 1, "{roam:?}");
    assert_eq!(roam[0] - t, ms(90));
    let learned = at(&n, b, a, a_lan);
    assert_eq!(learned.len(), 1, "{learned:?}");
    let l = &learned[0];
    assert_eq!(
        (l.label, l.class.latency, l.status, l.srtt, l.active),
        (
            "learned",
            Latency::High,
            Status::Verified,
            Some(ms(20)),
            true
        )
    );
    assert_eq!(
        at(&n, b, a, n.sim.addr(a))[0].status,
        Status::Dormant,
        "the punch route stays a standby of its class"
    );
    let routes_before = routes_of(&n, b, a).len();
    let events_before = n.sim.routes(b, a).len();

    n.sim.know(b, a, vec![Candidate::lan(a_lan)]);
    let stitched = at(&n, b, a, a_lan);
    assert_eq!(
        stitched.len(),
        1,
        "the same route, not a second one: {stitched:?}"
    );
    let s = &stitched[0];
    assert_eq!(
        (s.label, s.class.latency, s.status, s.srtt, s.active),
        ("lan", Latency::Low, Status::Verified, Some(ms(20)), true),
        "the provider's label and class on the route it was"
    );
    assert_eq!(routes_of(&n, b, a).len(), routes_before);

    n.until(18);
    let after: Vec<_> = n.sim.routes(b, a).split_off(events_before);
    assert_eq!(
        after.len(),
        1,
        "only the label and the class change: {after:?}"
    );
    let r = after[0].1.unwrap();
    assert_eq!(
        (r.label, r.class.latency, r.verified, r.path),
        ("lan", Latency::Low, true, learned_path)
    );
    assert_eq!(n.pings_to(b, a_lan).len(), 1, "no new episode");
    assert_eq!(n.kinds(), [Some("lan"), Some("lan")]);
    assert_ne!(n.paths()[1], b_punch);
    assert!(n.gap(1, t, n.sim.now()) <= ms(300));
}

/// A pair whose B also has an interface at 203.0.113.3: A has two internet candidates for B, and
/// the direct path goes down 5 s into the session.
fn two_internet_candidates() -> Scene {
    let mut n = public_pair(&cfg, true, DeliveryClass::default(), ms(DATA_EVERY_MS));
    let b = n.b;
    n.sim.add_iface(b, INTERNET, ip("203.0.113.3"));
    n.start();
    n.until(5);
    assert_eq!(n.kinds(), [Some("punch"), Some("punch")]);
    n
}

#[test]
fn no_relay_is_asked_for_while_an_internet_candidate_is_about_to_answer() {
    let mut n = two_internet_candidates();
    let lost = n.sim.now();
    n.direct(false, false);
    n.sim.run(ms(4_500));
    n.direct(true, true);
    n.sim.run(secs(40));
    assert!(
        n.ask_times(n.a).is_empty(),
        "A lost its direct route at {lost:?} and a candidate answered 3.5 s later: {:?}",
        n.ask_times(n.a)
    );
    assert_eq!(n.kinds()[0], Some("punch"));
}

#[test]
fn the_relay_is_asked_for_when_the_last_internet_candidate_has_failed() {
    let mut n = two_internet_candidates();
    n.sim.set_turn(false);
    let lost = n.sim.now();
    n.direct(false, false);
    n.sim.run(secs(30));
    let asks = n.ask_times(n.a);
    assert!(!asks.is_empty());
    let first = asks[0];
    let last_ping = n
        .sim
        .hops()
        .iter()
        .filter(|h| {
            h.from == End::Host(n.a)
                && h.what == "ping"
                && h.medium == MediumKind::Udp
                && h.at > lost
                && h.at <= first
        })
        .map(|h| h.at)
        .max()
        .expect("A probed the direct candidates");
    let rto_after_the_last_ping = secs(1);
    assert!(
        first >= last_ping + rto_after_the_last_ping,
        "asked at {first:?}, before the last episode ended ({last_ping:?} + 1 s)"
    );
    assert!(
        first <= last_ping + rto_after_the_last_ping + FALLBACK_DELAY,
        "asked at {first:?}, more than the fallback delay after the last episode ended"
    );
}

#[test]
fn with_a_zero_fallback_delay_the_relay_is_asked_for_while_the_direct_route_is_probed() {
    let mut n = public_pair(
        &|c| c.routes.fallback_delay = Duration::ZERO,
        true,
        DeliveryClass::default(),
        ms(DATA_EVERY_MS),
    );
    n.direct(false, false);
    n.start();
    n.until_ms(500);
    assert!(!n.ask_times(n.a).is_empty(), "asked at once");
    assert!(n.ask_times(n.a)[0] <= n.at(100));
    let view = n.sim.node(n.a).peer_view(&n.sim.public(n.b)).unwrap();
    assert!(
        view.routes.iter().any(|r| r.status == Status::Candidate),
        "the direct route is still being probed: {:?}",
        view.routes
    );
}
