//! Metering on the simulator: what the transports and routes count, and what a budget that runs
//! out does.

use std::net::IpAddr;
use std::time::Duration;

use vardevall_proto::meter::{Budget, BudgetSource, Level};
use vardevall_proto::node::{Event, PeerState, Reason, TransportView};
use vardevall_proto::route::DeliveryClass;
use vardevall_proto::sim::*;
use vardevall_proto::time::Instant;

/// Bytes of a packet of the streams.
const PACKET: usize = 300;

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

fn degrading() -> DeliveryClass {
    DeliveryClass {
        degrade: true,
        ..DeliveryClass::default()
    }
}

fn up(sim: &Sim, a: HostId, b: HostId) -> bool {
    [(a, b), (b, a)].iter().all(|(x, y)| {
        sim.states(*x, *y)
            .last()
            .is_some_and(|(_, s)| matches!(s, PeerState::Up { .. }))
    })
}

fn view(sim: &Sim, host: HostId, medium: MediumKind) -> TransportView {
    let via = sim.transport(host, medium).unwrap();
    sim.node(host)
        .transports()
        .into_iter()
        .find(|t| t.id == via)
        .unwrap()
}

fn budget(sim: &Sim, host: HostId, medium: MediumKind) -> Budget {
    view(sim, host, medium).budget.expect("a budget")
}

/// The levels `host` reported for its `medium` transport, `None` for a removal.
fn levels(sim: &Sim, host: HostId, medium: MediumKind) -> Vec<Option<Level>> {
    let via = sim.transport(host, medium).unwrap();
    sim.events(host)
        .iter()
        .filter_map(|(_, e)| match e {
            Event::Budget { via: v, budget } if *v == via => Some(budget.map(|b| b.level())),
            _ => None,
        })
        .collect()
}

/// When `host` reported its `medium` budget exhausted.
fn exhausted_at(sim: &Sim, host: HostId, medium: MediumKind) -> Option<Instant> {
    let via = sim.transport(host, medium).unwrap();
    sim.events(host).iter().find_map(|(t, e)| match e {
        Event::Budget { via: v, budget } if *v == via && budget.is_some_and(|b| b.exhausted()) => {
            Some(*t)
        }
        _ => None,
    })
}

/// Bytes that left `host` on `medium`, the TURN leg to the server included.
fn sent_on(sim: &Sim, host: HostId, medium: MediumKind) -> u64 {
    sim.hops()
        .iter()
        .filter(|h| h.from == End::Host(host) && h.medium == medium)
        .map(|h| h.len as u64)
        .sum()
}

/// Bytes delivered to `host` on `medium` by now.
fn received_on(sim: &Sim, host: HostId, medium: MediumKind) -> u64 {
    sim.hops()
        .iter()
        .filter(|h| h.to == End::Host(host) && h.medium == medium)
        .filter(|h| matches!(h.fate, Fate::Delivered(t) if t <= sim.now()))
        .map(|h| h.len as u64)
        .sum()
}

fn hops_after(sim: &Sim, host: HostId, medium: MediumKind, after: Instant) -> usize {
    sim.hops()
        .iter()
        .filter(|h| h.from == End::Host(host) && h.medium == medium && h.at > after)
        .count()
}

/// Two public hosts that trust each other and are registered with a switch; with a TURN
/// transport each if `turn`. Both send a stream of `class`.
fn pair(turn: bool, class: DeliveryClass) -> (Sim, HostId, HostId) {
    let mut sim = Sim::new(5, link(5));
    sim.turn_server(ip("198.51.100.1"), link(5));
    let a = sim.host(INTERNET, ip("203.0.113.1"), |_| {});
    let b = sim.host(INTERNET, ip("203.0.113.2"), |_| {});
    sim.peer(a, b);
    sim.register(a, link(5));
    sim.register(b, link(5));
    if turn {
        sim.enable_turn(a);
        sim.enable_turn(b);
    }
    sim.stream(a, b, ms(100), class, PACKET);
    sim.stream(b, a, ms(100), class, PACKET);
    (sim, a, b)
}

fn block_direct(sim: &mut Sim, a: HostId, b: HostId) {
    sim.block(End::Host(a), End::Host(b), true);
    sim.block(End::Host(b), End::Host(a), true);
}

#[test]
fn a_switch_budget_that_runs_out_takes_the_link_down_and_a_fresh_one_brings_it_back() {
    let (mut sim, a, b) = pair(false, degrading());
    block_direct(&mut sim, a, b);
    for h in [a, b] {
        sim.set_budget(
            h,
            MediumKind::Switch,
            Some(Budget::new(30_000, BudgetSource::Reported, false)),
        );
    }
    assert!(sim.run_until(secs(10), |s| up(s, a, b)), "no session");
    assert!(
        sim.run_until(secs(60), |s| {
            [a, b]
                .iter()
                .all(|h| exhausted_at(s, *h, MediumKind::Switch).is_some())
        }),
        "the budgets never ran out"
    );
    sim.run(secs(20));

    for (h, p) in [(a, b), (b, a)] {
        assert_eq!(
            levels(&sim, h, MediumKind::Switch),
            [
                Some(Level::Plenty),
                Some(Level::Half),
                Some(Level::Low),
                Some(Level::Exhausted)
            ]
        );
        let at = exhausted_at(&sim, h, MediumKind::Switch).unwrap();
        assert_eq!(
            hops_after(&sim, h, MediumKind::Switch, at),
            0,
            "no datagram on the switch once its budget ran out, handshakes and pings included"
        );
        let t = view(&sim, h, MediumKind::Switch);
        assert!(t.ready && !t.usable);
        assert_eq!(t.budget.unwrap().remaining, 0);
        let states = sim.states(h, p);
        let down = states
            .iter()
            .position(|(_, s)| *s == PeerState::Down(Reason::Unreachable))
            .unwrap_or_else(|| panic!("no Down(Unreachable): {states:?}"));
        assert!(
            states[..down]
                .iter()
                .any(|(_, s)| matches!(s, PeerState::Up { .. })),
            "{states:?}"
        );
        assert!(!matches!(states.last().unwrap().1, PeerState::Up { .. }));
    }

    let before = sim.hops().len();
    for h in [a, b] {
        sim.set_budget(
            h,
            MediumKind::Switch,
            Some(Budget::new(1_000_000, BudgetSource::Reported, false)),
        );
    }
    assert!(
        sim.run_until(secs(60), |s| up(s, a, b)),
        "a fresh budget did not bring the link back"
    );
    assert!(sim.hops().len() > before);
    assert!(view(&sim, a, MediumKind::Switch).usable);
}

#[test]
fn direct_traffic_costs_the_switch_budget_nothing() {
    let (mut sim, a, b) = pair(false, DeliveryClass::default());
    for h in [a, b] {
        sim.set_budget(
            h,
            MediumKind::Switch,
            Some(Budget::new(1_000_000, BudgetSource::Reported, false)),
        );
    }
    assert!(sim.run_until(secs(10), |s| up(s, a, b)), "no session");
    sim.run(secs(15));
    let settled: Vec<u64> = [a, b]
        .iter()
        .map(|h| budget(&sim, *h, MediumKind::Switch).remaining)
        .collect();
    let direct_before = [a, b].map(|h| view(&sim, h, MediumKind::Udp).meter.sent);
    sim.run(secs(30));
    for (i, h) in [a, b].into_iter().enumerate() {
        let b = budget(&sim, h, MediumKind::Switch);
        assert_eq!(b.remaining, settled[i], "30 s of data on the direct route");
        let on_switch = sent_on(&sim, h, MediumKind::Switch);
        assert_eq!(
            b.total - b.remaining,
            on_switch,
            "only what went on the switch"
        );
        let data = sim
            .hops()
            .iter()
            .filter(|x| x.from == End::Host(h) && x.medium == MediumKind::Switch)
            .filter(|x| x.what == "data")
            .count();
        assert_eq!(data, 0, "no data went through the switch");
        assert!(
            on_switch < 6_000,
            "the handshake and the first pings only: {on_switch}"
        );
        let direct = view(&sim, h, MediumKind::Udp).meter.sent;
        assert!(direct > direct_before[i] + 30_000, "the data went direct");
    }
}

#[test]
fn a_turn_budget_that_runs_out_sends_the_data_to_the_switch() {
    let (mut sim, a, b) = pair(true, degrading());
    block_direct(&mut sim, a, b);
    for h in [a, b] {
        sim.set_budget(
            h,
            MediumKind::Switch,
            Some(Budget::new(1_000_000, BudgetSource::Reported, false)),
        );
        sim.set_budget(
            h,
            MediumKind::Turn,
            Some(Budget::new(60_000, BudgetSource::Relay, true)),
        );
    }
    let on = |s: &Sim, h: HostId, medium: MediumKind| {
        let via = s.transport(h, medium).unwrap();
        s.active(h, if h == a { b } else { a })
            .is_some_and(|r| r.path.via == via)
    };
    assert!(
        sim.run_until(secs(60), |s| on(s, a, MediumKind::Turn)
            && on(s, b, MediumKind::Turn)),
        "the relay never carried the data"
    );
    assert!(
        sim.run_until(secs(60), |s| budget(s, b, MediumKind::Turn).level()
            == Level::Half),
        "the TURN budget never reached half"
    );
    let t = view(&sim, b, MediumKind::Turn);
    let turn = t.budget.unwrap();
    assert_eq!(
        turn.total - turn.remaining,
        t.meter.sent + t.meter.received,
        "a TURN budget is charged both ways"
    );
    assert!(t.meter.received > 0);
    let s = view(&sim, b, MediumKind::Switch);
    let sw = s.budget.unwrap();
    assert_eq!(
        sw.total - sw.remaining,
        s.meter.sent,
        "a switch budget is charged what is sent, not what is received"
    );
    assert!(s.meter.received > 0);

    assert!(
        sim.run_until(secs(120), |s| [a, b].iter().all(|h| exhausted_at(
            s,
            *h,
            MediumKind::Turn
        )
        .is_some())),
        "the TURN budgets never ran out"
    );
    let ran_out = [a, b].map(|h| exhausted_at(&sim, h, MediumKind::Turn).unwrap());
    let mark = sim.now();
    sim.run(secs(90));
    for (i, (h, p)) in [(a, b), (b, a)].into_iter().enumerate() {
        assert!(
            !sim.demands()
                .iter()
                .any(|d| d.1 == h && d.2 && d.0 > ran_out[i]),
            "an exhausted on-demand transport is not asked for again"
        );
        assert!(!view(&sim, h, MediumKind::Turn).usable);
        assert_eq!(hops_after(&sim, h, MediumKind::Turn, ran_out[i]), 0);
        let r = sim.active(h, p).expect("a route");
        assert_eq!(r.label, "switch", "the data falls back to the switch");
        assert!(
            sim.gap(h, p, mark + secs(10), sim.now()) <= ms(500),
            "the data goes on over the switch once the relay routes are gone"
        );
        assert!(
            view(&sim, h, MediumKind::Switch).budget.unwrap().remaining > 0,
            "the switch budget is the one that pays now"
        );
    }
}

#[test]
fn the_meters_count_every_datagram_the_simulator_delivered() {
    let (mut sim, a, b) = pair(true, DeliveryClass::default());
    assert!(sim.run_until(secs(10), |s| up(s, a, b)), "no session");
    sim.run(secs(55));
    let handshake = ["msg1", "msg2", "cookie"];
    let mut total = 0;
    for h in [a, b] {
        let p = if h == a { b } else { a };
        for medium in [MediumKind::Udp, MediumKind::Turn, MediumKind::Switch] {
            let t = view(&sim, h, medium);
            assert_eq!(
                t.meter.sent,
                sent_on(&sim, h, medium),
                "sent on {medium:?} by {h:?}"
            );
            assert_eq!(
                t.meter.received,
                received_on(&sim, h, medium),
                "received on {medium:?} by {h:?}"
            );
            total += t.meter.sent + t.meter.received;

            let routes = sim.node(h).peer_view(&sim.public(p)).unwrap().routes;
            let on_routes = routes
                .iter()
                .filter(|r| r.path.via == t.id)
                .fold((0, 0), |(s, r), x| (s + x.meter.sent, r + x.meter.received));
            let frames: u64 = sim
                .hops()
                .iter()
                .filter(|x| {
                    x.from == End::Host(h) && x.medium == medium && !handshake.contains(&x.what)
                })
                .map(|x| x.len as u64)
                .sum();
            assert_eq!(
                on_routes.0, frames,
                "route meters, sent on {medium:?} by {h:?}"
            );
            assert!(on_routes.1 <= t.meter.received);
        }
    }
    assert!(total > 100_000, "data and pings flowed: {total}");
}
