//! The simulator on small topologies: handshakes, NATs, the switch and TURN.

use std::net::IpAddr;
use std::time::Duration;

use vardevall_proto::discovery::candidate::Candidate;
use vardevall_proto::node::{Event, PeerState};
use vardevall_proto::route::DeliveryClass;
use vardevall_proto::sim::*;
use vardevall_proto::time::Instant;

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

fn up(sim: &Sim, a: HostId, b: HostId) -> bool {
    [(a, b), (b, a)].iter().all(|(x, y)| {
        sim.states(*x, *y)
            .iter()
            .any(|(_, s)| matches!(s, PeerState::Up { .. }))
    })
}

#[test]
fn two_public_hosts_handshake_and_exchange_packets() {
    let mut sim = Sim::new(1, link(5));
    let a = sim.host(INTERNET, ip("203.0.113.1"), |_| {});
    let b = sim.host(INTERNET, ip("203.0.113.2"), |_| {});
    sim.peer(a, b);
    let to_b = vec![Candidate::static_(sim.addr(b))];
    let to_a = vec![Candidate::static_(sim.addr(a))];
    sim.know(a, b, to_b);
    sim.know(b, a, to_a);
    let class = DeliveryClass::default();
    sim.send(a, b, class, b"hello");
    assert!(sim.run_until(secs(5), |s| up(s, a, b)));
    sim.send(b, a, class, b"hi");
    sim.run(secs(1));

    assert_eq!(
        sim.states(a, b).iter().map(|s| s.1).collect::<Vec<_>>(),
        [PeerState::Connecting, PeerState::Up { initiator: true }]
    );
    assert_eq!(
        sim.states(b, a).last().map(|s| s.1),
        Some(PeerState::Up { initiator: false })
    );
    let got = |h: HostId| -> Vec<Vec<u8>> {
        sim.events(h)
            .iter()
            .filter_map(|(_, e)| match e {
                Event::Packet { packet, .. } => Some(packet[40..].to_vec()),
                _ => None,
            })
            .collect()
    };
    assert_eq!(got(b), [b"hello".to_vec()]);
    assert_eq!(got(a), [b"hi".to_vec()]);
    let route = sim.active(a, b).expect("a route");
    assert_eq!(route.label, "static");
    assert!(sim.hops().iter().all(|h| h.medium == MediumKind::Udp));
}

struct Nats {
    sim: Sim,
    a: HostId,
    b: HostId,
}

/// A behind NAT `ka`, B behind NAT `kb`, both registered with a switch 40 ms away; the direct
/// path takes 15 ms.
fn behind_nats(seed: u64, ka: NatKind, kb: NatKind) -> Nats {
    let mut sim = Sim::new(seed, link(5));
    let site_a = sim.site(Some(NatConfig::new(ka, ip("1.1.1.1"))), link(7), link(1));
    let site_b = sim.site(Some(NatConfig::new(kb, ip("2.2.2.2"))), link(8), link(1));
    let a = sim.host(site_a, ip("10.0.0.2"), |_| {});
    let b = sim.host(site_b, ip("192.168.1.5"), |_| {});
    sim.peer(a, b);
    sim.register(a, link(20));
    sim.register(b, link(20));
    Nats { sim, a, b }
}

#[test]
fn two_port_restricted_nats_come_up_through_the_switch_and_move_to_the_direct_route() {
    let Nats { mut sim, a, b } = behind_nats(2, NatKind::PortRestricted, NatKind::PortRestricted);
    let (ca, cb) = (sim.candidates_of(a), sim.candidates_of(b));
    sim.know(a, b, cb);
    sim.know(b, a, ca);
    sim.stream(a, b, ms(100), DeliveryClass::default(), 100);
    assert!(sim.run_until(secs(5), |s| up(s, a, b)));
    let up_at = sim.states(a, b).last().unwrap().0;
    sim.run(secs(5));

    for (x, y) in [(a, b), (b, a)] {
        let labels: Vec<&str> = sim
            .routes(x, y)
            .into_iter()
            .filter_map(|r| r.1.map(|v| v.label))
            .collect();
        assert_eq!(labels, ["switch", "punch"], "{x:?} to {y:?}");
        let moved = sim
            .routes(x, y)
            .iter()
            .find_map(|(t, r)| r.filter(|v| v.label == "punch").map(|_| *t));
        assert!(
            moved.unwrap() - up_at < ms(500),
            "direct within a few round trips"
        );
    }
    let route = sim.active(a, b).unwrap();
    assert_eq!(route.path.addr(), Some("2.2.2.2:4000".parse().unwrap()));
    let punch_in = sim.hops().iter().any(|h| {
        h.medium == MediumKind::Udp
            && h.from == End::Host(b)
            && matches!(h.fate, Fate::Delivered(_))
    });
    assert!(punch_in);
    let filtered = sim
        .hops()
        .iter()
        .filter(|h| h.fate == Fate::Filtered && h.from == End::Host(a))
        .count();
    assert!(filtered > 0, "A's first probes die at B's NAT");
    assert!(sim.arrivals(b, a).len() > 50);
    assert!(sim.gap(b, a, up_at, sim.now()) < ms(300));
}

/// The peer may send straight to our relayed address; its data then comes from an address the
/// allocation has no route for and roams: the route is learned, still metered.
#[test]
fn two_symmetric_nats_with_turn_end_on_a_turn_route() {
    let Nats { mut sim, a, b } = behind_nats(3, NatKind::Symmetric, NatKind::Symmetric);
    sim.turn_server(ip("198.51.100.1"), link(5));
    sim.enable_turn(a);
    sim.enable_turn(b);
    sim.stream(a, b, ms(100), DeliveryClass::default(), 100);
    sim.stream(b, a, ms(100), DeliveryClass::default(), 100);
    sim.run(secs(15));

    let on = |h: HostId| sim.demands().iter().filter(|d| d.1 == h && d.2).count();
    assert!(on(a) >= 1 && on(b) >= 1, "both asked for a relay");
    for (x, y) in [(a, b), (b, a)] {
        let route = sim.active(x, y).expect("a route");
        assert!(
            matches!(route.label, "relay" | "learned"),
            "{x:?} to {y:?}: {}",
            route.label
        );
        assert!(route.class.metered);
    }
    assert!(
        sim.hops()
            .iter()
            .any(|h| h.medium == MediumKind::Turn && h.from == End::Turn)
    );
    assert!(sim.gap(b, a, Instant::from_millis(6_000), sim.now()) < ms(300));
    assert!(sim.gap(a, b, Instant::from_millis(6_000), sim.now()) < ms(300));
}

#[test]
fn a_rebind_gives_the_new_reflexive_address_one_stun_round_trip_later() {
    let Nats { mut sim, a, b } = behind_nats(4, NatKind::PortRestricted, NatKind::PortRestricted);
    let (ca, cb) = (sim.candidates_of(a), sim.candidates_of(b));
    sim.know(a, b, cb);
    sim.know(b, a, ca);
    sim.stream(a, b, ms(100), DeliveryClass::default(), 100);
    assert!(sim.run_until(secs(5), |s| up(s, a, b)));
    sim.run(secs(5));
    let shared = |sim: &Sim| sim.node(b).peer_view(&sim.public(a)).unwrap().shared;
    let before = shared(&sim);
    assert_eq!(before.len(), 1);

    let t = sim.now();
    sim.rebind(SiteId(1));
    sim.run(secs(1));
    let cand = sim
        .hops()
        .iter()
        .find(|h| h.what == "cand" && h.from == End::Host(a) && h.at > t)
        .expect("A tells B its new address");
    assert_eq!(
        cand.at - t,
        ms(16),
        "the binding request crosses A's LAN and uplink twice"
    );
    let after = shared(&sim);
    assert_eq!(after.len(), 1);
    assert_ne!(after, before);
    assert_eq!(after[0].addr.ip(), ip("1.1.1.1"));
}

fn lossy_run(seed: u64) -> Vec<Hop> {
    let lossy = LinkConfig {
        latency: ms(10),
        jitter: ms(20),
        loss: 0.05,
    };
    let mut sim = Sim::new(seed, lossy);
    let a = sim.host(INTERNET, ip("203.0.113.1"), |_| {});
    let b = sim.host(INTERNET, ip("203.0.113.2"), |_| {});
    sim.peer(a, b);
    sim.register(a, lossy);
    sim.register(b, lossy);
    sim.stream(a, b, ms(50), DeliveryClass::default(), 200);
    sim.stream(b, a, ms(70), DeliveryClass::default(), 200);
    sim.run(secs(20));
    sim.hops().to_vec()
}

#[test]
fn the_same_seed_gives_the_same_hops_and_another_seed_other_ones() {
    let first = lossy_run(7);
    assert!(first.len() > 500);
    assert!(first.iter().any(|h| h.fate == Fate::Lost));
    assert_eq!(first, lossy_run(7));
    assert_ne!(first, lossy_run(8));
}
