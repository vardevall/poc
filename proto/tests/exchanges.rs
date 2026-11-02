//! Exchanges between two nodes, one test each, on whole nodes over the simulator with the
//! topology and the one-way latencies of the diagram. Every test checks the order of the active
//! routes of both sides, the instants the diagram gives (within 10 ms; within 50 ms for the `~`
//! ones) and the steady state. Times are milliseconds from the first packet the scenario sends.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use vardevall_proto::node::PeerState;
use vardevall_proto::route::{DeliveryClass, Status, WantBand};
use vardevall_proto::sim::*;
use vardevall_proto::time::Instant;

mod trace;

/// Tolerance of an instant the diagram states exactly, in ms.
const EXACT: u64 = 10;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn sock(s: &str) -> SocketAddr {
    SocketAddr::new(ip(s), PORT)
}

fn link(n: u64) -> LinkConfig {
    LinkConfig::latency(ms(n))
}

/// Any band: the traffic of a test goes on whatever route is active.
fn any_band() -> DeliveryClass {
    DeliveryClass {
        band: WantBand::Any,
        ..DeliveryClass::default()
    }
}

struct World {
    sim: Sim,
    a: HostId,
    b: HostId,
}

impl Drop for World {
    fn drop(&mut self) {
        trace::save(&self.sim, Instant::ZERO);
    }
}

impl World {
    fn ms(&self) -> u64 {
        self.sim.now().as_duration().as_millis() as u64
    }

    /// Runs to `t` ms from the start.
    fn to(&mut self, t: u64) {
        let d = ms(t) - self.sim.now().as_duration();
        self.sim.run(d);
    }

    /// When `x` reported `y` up, in ms.
    fn up_at(&self, x: HostId, y: HostId) -> u64 {
        self.sim
            .states(x, y)
            .iter()
            .find(|(_, s)| matches!(s, PeerState::Up { .. }))
            .map(|(t, _)| t.as_duration().as_millis() as u64)
            .expect("up")
    }

    /// The active routes `x` reported for `y` with the instants in ms: the label of the route,
    /// `"none"` for no route; a route that is not verified is marked with `?`.
    fn routes(&self, x: HostId, y: HostId) -> Vec<(u64, String)> {
        self.sim
            .routes(x, y)
            .into_iter()
            .map(|(t, r)| {
                let what = match r {
                    None => "none".to_owned(),
                    Some(v) => format!("{}{}", v.label, if v.verified { "" } else { "?" }),
                };
                (t.as_duration().as_millis() as u64, what)
            })
            .collect()
    }

    /// The routes of `x` for `y` with the status of the one at `addr` of `host`'s peer.
    fn status(&self, x: HostId, y: HostId, addr: &str) -> Option<Status> {
        let view = self.sim.node(x).peer_view(&self.sim.public(y))?;
        let addr = addr.parse().ok();
        view.routes
            .iter()
            .find(|r| r.path.addr() == addr)
            .map(|r| r.status)
    }

    /// The pings that left `host` towards `dst`.
    fn pings_to(&self, host: HostId, dst: &str, after: u64) -> Vec<u64> {
        let dst = dst.parse().ok();
        self.sim
            .hops()
            .iter()
            .filter(|h| h.from == End::Host(host) && h.what == "ping" && h.dst == dst)
            .map(|h| h.at.as_duration().as_millis() as u64)
            .filter(|t| *t >= after)
            .collect()
    }

    /// Every ping that left `host`, whatever the path.
    fn pings(&self, host: HostId) -> usize {
        self.sim
            .hops()
            .iter()
            .filter(|h| h.from == End::Host(host) && h.what == "ping")
            .count()
    }

    /// Packets that arrived at `host` from `from` after `after`, in ms.
    fn arrivals_after(&self, host: HostId, from: HostId, after: u64) -> usize {
        self.sim
            .arrivals(host, from)
            .into_iter()
            .filter(|t| t.as_duration().as_millis() as u64 >= after)
            .count()
    }

    /// Data frames that left `host` after `after` on `medium`.
    fn data_on(&self, host: HostId, medium: MediumKind, after: u64) -> usize {
        self.sim
            .hops()
            .iter()
            .filter(|h| {
                h.from == End::Host(host)
                    && h.medium == medium
                    && h.what == "data"
                    && h.at.as_duration().as_millis() as u64 >= after
            })
            .count()
    }
}

/// Asserts the sequence of `got` has these labels, and each instant within `tolerance` of the
/// one given.
#[track_caller]
fn expect(got: &[(u64, String)], want: &[(u64, &str)], tolerance: u64) {
    let labels: Vec<&str> = got.iter().map(|(_, l)| l.as_str()).collect();
    let wanted: Vec<&str> = want.iter().map(|(_, l)| *l).collect();
    assert_eq!(labels, wanted, "the order of the routes: {got:?}");
    for ((t, _), (w, l)) in got.iter().zip(want) {
        assert!(
            t.abs_diff(*w) <= tolerance,
            "{l} at {t} ms, wanted {w} ms (±{tolerance}): {got:?}"
        );
    }
}

/// A behind NAT-A (1.1.1.1) and B behind NAT-B (2.2.2.2), both port-restricted, the direct path
/// 15 ms one way, both registered with a switch 40 ms away.
fn two_nats() -> World {
    let mut sim = Sim::new(1, link(5));
    let nat_a = NatConfig::new(NatKind::PortRestricted, ip("1.1.1.1"));
    let nat_b = NatConfig::new(NatKind::PortRestricted, ip("2.2.2.2"));
    let site_a = sim.site(Some(nat_a), link(7), link(1));
    let site_b = sim.site(Some(nat_b), link(8), link(1));
    let a = sim.host(site_a, ip("10.0.0.2"), |_| {});
    let b = sim.host(site_b, ip("192.168.1.5"), |_| {});
    sim.peer(a, b);
    sim.register(a, link(20));
    sim.register(b, link(20));
    World { sim, a, b }
}

/// §10.1: both sides come up through the switch, punch through, and each moves to its own
/// direct route when its own ping is answered.
#[test]
fn two_port_restricted_nats() {
    let mut w = two_nats();
    let (a, b) = (w.a, w.b);
    w.sim.send(a, b, any_band(), b"hello");
    w.to(500);

    assert_eq!(w.up_at(a, b), 80);
    assert!(w.up_at(b, a).abs_diff(120) <= EXACT);
    expect(&w.routes(a, b), &[(80, "switch"), (165, "punch")], EXACT);
    expect(&w.routes(b, a), &[(120, "switch"), (150, "punch")], EXACT);

    let pings = w.pings_to(a, "2.2.2.2:4000", 0);
    assert!(
        pings[0].abs_diff(80) <= EXACT,
        "ping#2 on U at 80: {pings:?}"
    );
    let filtered = w
        .sim
        .hops()
        .iter()
        .filter(|h| h.from == End::Host(a) && h.what == "ping" && h.fate == Fate::Filtered)
        .count();
    assert!(filtered >= 1, "ping#2 dies at NAT-B");

    w.to(30_000);
    assert_eq!(w.routes(a, b).len(), 2, "no further moves");
    assert_eq!(w.routes(b, a).len(), 2);
    assert_eq!(
        (w.pings(a), w.pings(b)),
        (4, 2),
        "A: the switch, U at 80 and 135 (ping#2 and the triggered ping#4), U's NAT keepalive at \
         25 s; B: the switch and U' (B's pong to that keepalive makes it quiet)"
    );
    w.sim.send(a, b, any_band(), b"steady");
    w.sim.send(b, a, any_band(), b"steady");
    w.to(30_100);
    assert_eq!(w.data_on(a, MediumKind::Switch, 30_000), 0);
    assert_eq!(w.data_on(b, MediumKind::Switch, 30_000), 0);
    assert_eq!(w.arrivals_after(b, a, 30_000), 1);
    assert_eq!(w.arrivals_after(a, b, 30_000), 1);
}

/// A behind a stateful firewall (a port-restricted NAT), B public at E but multi-homed: its
/// other interface sits behind a NAT of its own, so replies leave from another address.
fn one_way() -> World {
    let mut sim = Sim::new(2, link(5));
    let nat_a = NatConfig::new(NatKind::PortRestricted, ip("1.1.1.1"));
    let nat_b = NatConfig::new(NatKind::Symmetric, ip("9.9.9.9"));
    let site_a = sim.site(Some(nat_a), link(10), link(1));
    let site_b = sim.site(Some(nat_b), link(10), link(1));
    let a = sim.host(site_a, ip("10.0.0.2"), |_| {});
    let b = sim.host(site_b, ip("172.16.0.2"), |_| {});
    sim.add_iface(b, INTERNET, ip("203.0.113.3"));
    sim.peer(a, b);
    sim.register(a, link(20));
    sim.register(b, link(20));
    let e = sock("203.0.113.3");
    sim.know(
        a,
        b,
        vec![vardevall_proto::discovery::candidate::Candidate::static_(e)],
    );
    World { sim, a, b }
}

/// §10.2: message 2 cannot come back from E, the switch copy of message 1 gets the cached
/// message 2, and A sends on E while B answers on the switch.
#[test]
fn one_way_path() {
    let mut w = one_way();
    let (a, b) = (w.a, w.b);
    w.sim.send(a, b, any_band(), b"hello");
    w.to(2_000);

    assert!(w.up_at(a, b).abs_diff(1_080) <= EXACT, "{}", w.up_at(a, b));
    assert!(w.up_at(b, a).abs_diff(1_095) <= EXACT, "{}", w.up_at(b, a));
    expect(
        &w.routes(a, b),
        &[(1_080, "switch"), (1_135, "static")],
        EXACT,
    );
    expect(&w.routes(b, a), &[(1_095, "switch")], EXACT);

    let msg2_via_switch = w
        .sim
        .hops()
        .iter()
        .filter(|h| h.from == End::Host(b) && h.what == "msg2" && h.medium == MediumKind::Switch)
        .count();
    assert_eq!(msg2_via_switch, 1, "the cached message 2");

    let a_nat = w.sim.node(a).peer_view(&w.sim.public(b)).unwrap();
    assert_eq!(a_nat.link, PeerState::Up { initiator: true });

    w.to(5_245);
    assert_eq!(w.status(b, a, "1.1.1.1:4000"), Some(Status::Candidate));
    w.to(5_345);
    assert_eq!(
        w.status(b, a, "1.1.1.1:4000"),
        Some(Status::Failed),
        "~5295: the episode ends with the last ping and one RTO"
    );

    w.to(19_999);
    let retries = w.pings_to(b, "1.1.1.1:4000", 5_300);
    assert_eq!(
        retries.len(),
        1,
        "one ping after KEEPALIVE_TIMEOUT, not an episode: {retries:?}"
    );
    assert!(retries[0].abs_diff(15_295) <= EXACT, "{retries:?}");
    w.to(20_000);
    expect(
        &w.routes(a, b),
        &[(1_080, "switch"), (1_135, "static")],
        EXACT,
    );
    expect(&w.routes(b, a), &[(1_095, "switch")], EXACT);
    w.sim.send(a, b, any_band(), b"steady");
    w.sim.send(b, a, any_band(), b"steady");
    w.to(20_300);
    assert_eq!(w.data_on(a, MediumKind::Udp, 20_000), 1, "A to B on E");
    assert_eq!(w.data_on(b, MediumKind::Switch, 20_000), 1, "B to A on S");
    assert_eq!(w.data_on(b, MediumKind::Udp, 20_000), 0);
    assert_eq!(w.arrivals_after(b, a, 20_000), 1);
    assert_eq!(w.arrivals_after(a, b, 20_000), 1);
    assert_eq!(
        (w.pings(a), w.pings(b)),
        (3, 11),
        "A's keeping ping on E goes out with the data at 20 s, no frame of B having come on E; \
         B's failed route to A's address was retried at 15.3 s, so the ping that arrives on it \
         gets no triggered ping (rule 5)"
    );
}

/// §10.3: the data of A comes from a new source; B follows it at once and verifies it by ping; the
/// old mapping, of the same class, goes dormant and is not pinged again.
#[test]
fn nat_rebinding() {
    let mut sim = Sim::new(3, link(5));
    let nat_a = NatConfig::new(NatKind::PortRestricted, ip("1.1.1.1"));
    let site_a = sim.site(Some(nat_a), link(10), link(1));
    let a = sim.host(site_a, ip("10.0.0.2"), |_| {});
    let b = sim.host(INTERNET, ip("203.0.113.2"), |_| {});
    sim.peer(a, b);
    sim.register(a, link(20));
    sim.register(b, link(20));
    let mut w = World { sim, a, b };
    w.sim.send(a, b, any_band(), b"hello");
    w.to(10_000);
    assert_eq!(
        w.routes(b, a).last().map(|(_, l)| l.as_str()),
        Some("punch")
    );
    let before = w.routes(b, a).len();

    let t = w.ms();
    w.sim.rebind_quietly(site_a);
    w.to(t + 5);
    w.sim.send(a, b, any_band(), b"from the new source");
    w.to(t + 200);

    let moved: Vec<(u64, String)> = w.routes(b, a).split_off(before);
    expect(
        &moved
            .iter()
            .map(|(at, l)| (at - t, l.clone()))
            .collect::<Vec<_>>(),
        &[(20, "learned?"), (50, "learned")],
        EXACT,
    );
    let learned = w
        .sim
        .active(b, a)
        .expect("a route")
        .path
        .addr()
        .expect("an address");
    assert_ne!(learned.to_string(), "1.1.1.1:4000");
    assert_eq!(learned.ip(), ip("1.1.1.1"));

    assert!(
        w.pings_to(b, "1.1.1.1:4000", t).is_empty(),
        "the old mapping is not pinged once the learned route is verified"
    );
    w.to(t + 40_000);
    assert_eq!(w.routes(b, a).len(), before + 2, "B stays on the new route");
    assert!(
        w.pings_to(b, "1.1.1.1:4000", t).is_empty(),
        "no keepalive either"
    );
    assert_eq!(
        (w.pings(a), w.pings(b)),
        (4, 6),
        "A: the switch, the direct route and the triggered ping, then the keeping ping of the \
         first data from the new mapping at 10 s; B: the switch and two pings on the old mapping \
         at 95 ms, the ping on the learned route and the triggered ping on it (A's keeping ping \
         arrives on it), and its keepalive at 25 s"
    );
    assert_eq!(
        w.status(b, a, "1.1.1.1:4000"),
        Some(Status::Dormant),
        "the old mapping is the learned route's class, which is active"
    );
}

/// A and B on one LAN behind NAT 1.1.1.1, which does not hairpin, and both registered with a
/// switch. Each knows the other's LAN address.
fn lan_pair() -> World {
    let mut sim = Sim::new(4, link(5));
    let nat = NatConfig::new(NatKind::PortRestricted, ip("1.1.1.1"));
    let site = sim.site(Some(nat), link(10), link(1));
    let a = sim.host(site, ip("192.168.1.62"), |_| {});
    let b = sim.host(site, ip("192.168.1.51"), |_| {});
    sim.peer(a, b);
    sim.register(a, link(20));
    sim.register(b, link(20));
    World { sim, a, b }
}

/// §10.4: message 1 goes out on the known LAN address, whose answer verifies it; the punch route
/// through the NAT cannot win against it: A never pings it, B pings it once before the LAN route
/// answers, and it is dormant on both sides.
#[test]
fn lan_known_before_the_handshake() {
    use vardevall_proto::discovery::candidate::Candidate;
    let mut w = lan_pair();
    let (a, b) = (w.a, w.b);
    let (la, lb) = (w.sim.addr(a), w.sim.addr(b));
    w.sim.know(a, b, vec![Candidate::lan(lb)]);
    w.sim.know(b, a, vec![Candidate::lan(la)]);
    w.sim.send(a, b, any_band(), b"hello");
    w.to(300);

    assert!(w.up_at(a, b).abs_diff(2) <= EXACT);
    assert!(w.up_at(b, a).abs_diff(3) <= EXACT);
    expect(&w.routes(a, b), &[(2, "lan")], EXACT);
    expect(&w.routes(b, a), &[(3, "switch"), (5, "lan")], EXACT);

    assert_eq!(w.status(a, b, "1.1.1.1:4001"), Some(Status::Dormant));
    assert_eq!(w.status(b, a, "1.1.1.1:4000"), Some(Status::Dormant));

    w.to(40_000);
    expect(&w.routes(a, b), &[(2, "lan")], EXACT);
    expect(&w.routes(b, a), &[(3, "switch"), (5, "lan")], EXACT);
    assert!(
        w.pings_to(a, "1.1.1.1:4001", 0).is_empty(),
        "A never pings the punch route: it cannot win against the LAN route"
    );
    let p_at_b = w.pings_to(b, "1.1.1.1:4000", 0);
    assert_eq!(
        p_at_b.len(),
        1,
        "B pings it once, before the LAN route answers: {p_at_b:?}"
    );
    assert_eq!(
        (w.pings(a), w.pings(b)),
        (1, 5),
        "A: the ping on L; B: the switch, L twice (its own and the triggered one), P once, and \
         L's NAT keepalive at 25 s"
    );
}

/// A and B on the internet at 203.0.113.1 and .2 (10 ms apart) and on one Wi-Fi LAN behind a NAT
/// that does not hairpin (1 ms apart): the punch route over the internet works from the start,
/// the LAN address is found later.
fn wifi_and_internet() -> World {
    let mut sim = Sim::new(5, link(5));
    let nat = NatConfig::new(NatKind::PortRestricted, ip("1.1.1.1"));
    let wifi = sim.site(Some(nat), link(10), link(1));
    let a = sim.host(INTERNET, ip("203.0.113.1"), |_| {});
    let b = sim.host(INTERNET, ip("203.0.113.2"), |_| {});
    sim.add_iface(a, wifi, ip("192.168.1.62"));
    sim.add_iface(b, wifi, ip("192.168.1.51"));
    sim.peer(a, b);
    sim.register(a, link(20));
    sim.register(b, link(20));
    World { sim, a, b }
}

/// §10.5: the registry finds B on the LAN while the punch route is active; the LAN route is
/// verified two milliseconds later and takes over; when the Wi-Fi drops the punch route is back.
#[test]
fn lan_appearing_later() {
    use vardevall_proto::discovery::candidate::Candidate;
    let mut w = wifi_and_internet();
    let (a, b) = (w.a, w.b);
    w.sim.stream(a, b, ms(100), any_band(), 200);
    w.sim.stream(b, a, ms(100), any_band(), 200);
    w.to(9_999);
    let before = w.routes(a, b);
    assert_eq!(before.last().map(|(_, l)| l.as_str()), Some("punch"));

    let lan_b = Candidate::lan(sock("192.168.1.51"));
    w.to(10_000);
    w.sim.know(a, b, vec![lan_b]);
    w.to(10_500);
    let after: Vec<(u64, String)> = w.routes(a, b).split_off(before.len());
    expect(&after, &[(10_002, "lan")], EXACT);
    let on_lan = |w: &World| {
        w.sim
            .node(a)
            .peer_view(&w.sim.public(b))
            .unwrap()
            .routes
            .iter()
            .any(|r| r.path.addr().is_some_and(|x| x.ip() == ip("203.0.113.2")))
    };
    assert!(on_lan(&w), "the punch route stays a standby");
    let b_route = w.sim.active(b, a).unwrap();
    assert_eq!(
        (b_route.label, b_route.path.addr().map(|x| x.ip())),
        ("learned", Some(ip("192.168.1.62"))),
        "B roamed onto the LAN source of A's data and verified it"
    );
    let b_after: Vec<(u64, String)> = w
        .routes(b, a)
        .into_iter()
        .filter(|r| r.0 > 10_000)
        .collect();
    expect(
        &b_after,
        &[(10_101, "learned?"), (10_103, "learned")],
        EXACT,
    );

    w.to(20_000);
    let marks = w.routes(a, b).len();
    w.sim.set_iface(a, ip("192.168.1.62"), false);
    w.to(21_000);
    let dropped: Vec<(u64, String)> = w.routes(a, b).split_off(marks);
    assert_eq!(
        dropped.last().map(|(_, l)| l.as_str()),
        Some("punch"),
        "{dropped:?}"
    );
    assert!(
        dropped.last().unwrap().0 < 20_500,
        "A is back on the punch route within a retransmission timeout: {dropped:?}"
    );
    w.to(40_000);
    let on_u = w.pings_to(a, "203.0.113.2:51820", 20_000);
    assert_eq!(
        on_u.len(),
        1,
        "A: the ping that wakes the punch route; B's data then keeps it: {on_u:?}"
    );
    assert!(on_u[0].abs_diff(20_200) <= EXACT, "{on_u:?}");
    assert_eq!(
        w.pings_to(b, "203.0.113.1:51820", 20_000),
        [20_310],
        "B: one ping, on its roam onto the punch route"
    );
    assert_eq!(
        w.pings_to(a, "192.168.1.51:51820", 20_000).len(),
        8,
        "the dead LAN route: one episode of 7 pings, then one ping 10 s after it failed"
    );
    assert_eq!(
        (w.pings(a), w.pings(b)),
        (13, 5),
        "A: the handshake's 3, the LAN ping, the dead LAN route's 8 and the wake-up ping; B: the \
         handshake's 3, the ping of its roam onto A's LAN source at 10.101 s and the one of its roam \
         back onto A's punch address at 20.3 s"
    );
    assert_eq!(
        w.routes(b, a).last().map(|(_, l)| l.as_str()),
        Some("punch"),
        "B roams back as soon as A's data arrives from its punch address"
    );
    assert_eq!(w.sim.active(a, b).unwrap().label, "punch");
    assert!(w.arrivals_after(a, b, 39_000) >= 9);
    assert!(w.arrivals_after(b, a, 39_000) >= 9);
}

/// A reaches B over the internet at 203.0.113.2 and, through another interface, B's Wi-Fi
/// address; B's other interface is the cellular one (metered) and the first, so B's replies
/// leave from it. Round trips: 30 ms on cellular, 45 ms on Wi-Fi.
fn wifi_and_cellular() -> World {
    let mut sim = Sim::new(6, link(5));
    let cellular = sim.site(None, link(10), link(1));
    let wifi = sim.site(None, link(25), link(1));
    let a = sim.host(INTERNET, ip("203.0.113.1"), |_| {});
    let b = sim.host(cellular, ip("203.0.113.2"), |_| {});
    sim.add_iface(b, wifi, ip("198.51.100.2"));
    sim.set_metered(b, ip("203.0.113.2"), true);
    sim.peer(a, b);
    sim.register(a, link(20));
    sim.register(b, link(20));
    World { sim, a, b }
}

/// §10.6: the cellular pong comes first; the move onto the metered route waits for the Wi-Fi
/// pong, which arrives before the wait ends, so cellular never carries data.
#[test]
fn reordered_pongs_onto_a_metered_route() {
    let mut w = wifi_and_cellular();
    let (a, b) = (w.a, w.b);
    w.sim.send(a, b, any_band(), b"hello");
    w.to(400);

    let up = w.up_at(a, b);
    assert_eq!(up, 80);
    let rel: Vec<(u64, String)> = w
        .routes(a, b)
        .into_iter()
        .map(|(t, l)| (t - up, l))
        .collect();
    expect(&rel, &[(0, "switch"), (45, "punch")], EXACT);
    let v = w.sim.active(a, b).unwrap();
    assert_eq!(v.path.addr().unwrap().to_string(), "198.51.100.2:51820");
    assert!(!v.class.metered, "the Wi-Fi route is unmetered");

    let pongs: Vec<u64> = w
        .sim
        .hops()
        .iter()
        .filter(|h| h.from == End::Host(b) && h.what == "pong" && h.medium == MediumKind::Udp)
        .filter_map(|h| match h.fate {
            Fate::Delivered(t) => Some(t.as_duration().as_millis() as u64 - up),
            _ => None,
        })
        .collect();
    assert!(
        pongs.iter().any(|t| t.abs_diff(30) <= EXACT),
        "the cellular pong: {pongs:?}"
    );
    assert!(
        pongs.iter().any(|t| t.abs_diff(45) <= EXACT),
        "the Wi-Fi pong: {pongs:?}"
    );

    w.to(10_000);
    w.sim.send(a, b, any_band(), b"steady");
    w.to(10_200);
    assert_eq!(w.data_on(a, MediumKind::Udp, 0), 1);
    let cellular_data = w
        .sim
        .hops()
        .iter()
        .filter(|h| {
            h.from == End::Host(a)
                && h.what == "data"
                && h.dst.is_some_and(|d| d.ip() == ip("203.0.113.2"))
        })
        .count();
    assert_eq!(cellular_data, 0, "cellular never carried data");
    assert_eq!(
        (w.pings(a), w.pings(b)),
        (5, 3),
        "A: the switch, Wi-Fi and cellular at once, the triggered ping on cellular and the keeping \
         ping of the data at 10 s; B: the switch and cellular twice (its own and the triggered \
         one)"
    );
}
