//! Behaviour of the node above the sessions: message 2 cache, fan-out, demand, states and
//! events.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::sim::*;
use vardevall_proto::discovery::candidate::Candidate;
use vardevall_proto::error::PeerError;
use vardevall_proto::ip::service::{Proto, Service};
use vardevall_proto::keys::{NetworkSecret, NodePublic};
use vardevall_proto::node::{Config, Event, Node as Core, PeerState, Reason, Trust};
use vardevall_proto::peer::Found;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn packet(p: &Pair, from: usize, n: u8) -> Vec<u8> {
    let (a, b) = (p.nodes[from].ula(), p.nodes[1 - from].ula());
    ipv6(a, b, &[n; 20])
}

fn count_type(wires: &[Wire], from: usize, ty: u8) -> usize {
    wires
        .iter()
        .filter(|w| w.from == from && w.data[0] == ty)
        .count()
}

#[test]
fn a_copy_of_message_1_through_the_switch_gets_the_cached_message_2() {
    let mut p = Pair::new();
    p.add_switch();
    let (a, b) = (p.nodes[0].public(), p.nodes[1].public());
    let udp_of_a = p.nodes[0].udp;
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    let mut msg2_on_switch = 0;
    let mut msg1_whole = 0;
    let mut msg1_fragments = 0;
    p.advance_with(secs(3), |w| {
        msg2_on_switch += usize::from(w.from == 1 && w.data[0] == 11);
        msg1_whole += usize::from(w.from == 0 && w.data[0] == 10);
        msg1_fragments += usize::from(w.from == 0 && w.data[0] == 4);
        // message 2 on the direct path is lost
        !(w.from == 1 && w.path.via == udp_of_a)
    });
    assert_eq!(msg1_fragments, 1, "no retransmission was needed");
    assert_eq!(
        msg1_whole, 1,
        "the copy went through the switch after FALLBACK_DELAY"
    );
    assert_eq!(msg2_on_switch, 1, "answered from the cache");
    assert_eq!(p.nodes[1].packets(), vec![pkt]);
    assert_eq!(
        p.nodes[0].states(&b),
        vec![PeerState::Connecting, PeerState::Up { initiator: true }]
    );
    assert_eq!(
        p.nodes[1].states(&a),
        vec![PeerState::Connecting, PeerState::Up { initiator: false }]
    );
    assert!(
        p.nodes[1].node.stats().indices <= 3,
        "one session, not two: {:?}",
        p.nodes[1].node.stats()
    );
}

#[test]
fn a_replayed_message_1_on_the_same_path_gets_no_second_message_2() {
    let mut p = Pair::new();
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    let wires = p.collect();
    for w in wires.clone() {
        p.deliver(w);
    }
    let first = p.collect();
    assert!(count_type(&first, 1, 6) == 1);
    for w in wires {
        p.deliver(w);
    }
    assert!(p.collect().is_empty());
}

#[test]
fn message_1_goes_through_the_switch_after_the_fallback_delay_when_a_direct_target_exists() {
    let mut p = Pair::new();
    p.add_switch();
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    let first = p.collect();
    assert_eq!(count_type(&first, 0, 4), 1);
    assert_eq!(count_type(&first, 0, 10), 0, "direct first");
    let mut whole = 0;
    p.advance_with(Duration::from_millis(999), |w| {
        whole += usize::from(w.from == 0 && w.data[0] == 10);
        false
    });
    assert_eq!(whole, 0);
    p.advance_with(Duration::from_millis(2), |w| {
        whole += usize::from(w.from == 0 && w.data[0] == 10);
        false
    });
    assert_eq!(whole, 1);
}

#[test]
fn message_1_follows_the_configured_fallback_delay() {
    let mut p = Pair::with(
        |c| c.routes.fallback_delay = Duration::from_millis(300),
        |_| {},
    );
    p.add_switch();
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    let first = p.collect();
    assert_eq!(count_type(&first, 0, 10), 0, "direct first");
    let mut whole = 0;
    p.advance_with(Duration::from_millis(299), |w| {
        whole += usize::from(w.from == 0 && w.data[0] == 10);
        false
    });
    assert_eq!(whole, 0);
    p.advance_with(Duration::from_millis(2), |w| {
        whole += usize::from(w.from == 0 && w.data[0] == 10);
        false
    });
    assert_eq!(whole, 1);
}

#[test]
fn message_1_goes_through_the_switch_at_once_with_a_zero_fallback_delay() {
    let mut p = Pair::with(|c| c.routes.fallback_delay = Duration::ZERO, |_| {});
    p.add_switch();
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    let first = p.collect();
    assert_eq!(count_type(&first, 0, 4), 1);
    assert_eq!(count_type(&first, 0, 10), 1);
}

#[test]
fn message_1_goes_through_the_switch_at_once_without_a_direct_target() {
    let mut p = Pair::new();
    p.switch_mode();
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    let first = p.collect();
    assert_eq!(count_type(&first, 0, 10), 1);
    assert_eq!(count_type(&first, 0, 4), 0);
}

#[test]
fn demand_is_raised_for_an_on_demand_transport_and_released_when_idle() {
    let mut p = Pair::new();
    p.switch_mode();
    let relay = p.nodes[0]
        .node
        .add_transport(Arc::new(SimMedium(MediumKind::Turn)));
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    p.advance(Duration::from_millis(900));
    assert!(p.nodes[0].demands.is_empty());
    p.advance(Duration::from_millis(200));
    assert_eq!(
        p.nodes[0].demands,
        vec![(relay, true)],
        "after the fallback delay"
    );
    let now = p.now;
    let a = &mut p.nodes[0];
    a.node.set_ready(now, &mut a.rng, relay, true);
    p.advance(secs(58));
    assert!(
        !p.nodes[0].demands.contains(&(relay, false)),
        "still in use"
    );
    p.advance(secs(10));
    assert!(
        p.nodes[0].demands.contains(&(relay, false)),
        "idle for 60 s"
    );
    let now = p.now;
    let a = &mut p.nodes[0];
    a.node.set_ready(now, &mut a.rng, relay, false);
    let before = p.nodes[0].demands.iter().filter(|d| !d.1).count();
    p.advance(secs(30));
    let after = p.nodes[0].demands.iter().filter(|d| !d.1).count();
    assert_eq!(before, after, "released once");
}

#[test]
fn a_pending_message_1_is_resent_when_candidates_appear() {
    let mut p = Pair::bare(|_| {}, |_| {});
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    assert!(p.collect().iter().all(|w| w.from != 0), "nowhere to send");
    let now = p.now;
    let [a, b] = &mut p.nodes;
    a.know(now, b);
    let wires = p.collect();
    assert_eq!(count_type(&wires, 0, 4), 1);
    assert_eq!(count_type(&wires, 0, 5), 1);
    for w in wires {
        p.deliver(w);
    }
    p.pump();
    assert_eq!(p.nodes[1].packets(), vec![pkt]);
}

#[test]
fn a_pending_message_1_is_resent_when_the_switch_reports_the_peer() {
    let mut p = Pair::bare(|_| {}, |_| {});
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    assert!(p.collect().iter().all(|w| w.from != 0));
    let now = p.now;
    let b = p.nodes[1].public();
    let a = &mut p.nodes[0];
    a.node.set_ready(now, &mut a.rng, a.sw, true);
    assert!(a.node.set_reachable(now, &mut a.rng, a.sw, &b, true));
    assert_eq!(count_type(&p.collect(), 0, 10), 1);
}

#[test]
fn states_are_reported_in_order_for_both_roles() {
    let mut p = Pair::new();
    let (a, b) = (p.nodes[0].public(), p.nodes[1].public());
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    p.pump();
    assert_eq!(
        p.nodes[0].states(&b),
        vec![PeerState::Connecting, PeerState::Up { initiator: true }]
    );
    assert_eq!(
        p.nodes[1].states(&a),
        vec![PeerState::Connecting, PeerState::Up { initiator: false }]
    );
    let added = |n: &Node, peer: &NodePublic| {
        n.events
            .iter()
            .position(|e| matches!(e, Event::Added { peer: x, trust: Trust::Key } if x == peer))
    };
    let first_state = |n: &Node| {
        n.events
            .iter()
            .position(|e| matches!(e, Event::Peer { .. }))
    };
    assert!(added(&p.nodes[0], &b).unwrap() < first_state(&p.nodes[0]).unwrap());
    assert!(added(&p.nodes[1], &a).unwrap() < first_state(&p.nodes[1]).unwrap());
}

#[test]
fn a_responder_whose_initiator_never_confirms_is_never_up_nor_down() {
    let mut p = Pair::new();
    let (a, b) = (p.nodes[0].public(), p.nodes[1].public());
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    p.advance_with(secs(400), |w| w.from != 1);
    assert_eq!(
        p.nodes[1].states(&a),
        vec![PeerState::Connecting, PeerState::Idle]
    );
    assert_eq!(
        p.nodes[0].states(&b),
        vec![PeerState::Connecting, PeerState::Down(Reason::Unreachable)]
    );
    assert_eq!(p.nodes[1].ups(), 0);
}

#[test]
fn a_rekey_that_gives_up_while_the_session_is_valid_reports_no_down() {
    let mut p = Pair::new();
    p.add_switch();
    let (a, b) = (p.nodes[0].public(), p.nodes[1].public());
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    p.pump();
    p.advance(secs(6));
    let pkt = packet(&p, 0, 2);
    p.send(0, &pkt);
    let mut handshakes = 0;
    p.advance_with(secs(150), |w| {
        handshakes += usize::from(w.from == 0 && w.data[0] == 4);
        w.from != 1
    });
    assert!(handshakes >= 10, "an attempt ran its course: {handshakes}");
    let view = p.nodes[0].node.peer_view(&b).unwrap();
    assert!(matches!(view.link, PeerState::Up { .. }));
    assert_eq!(
        p.nodes[0].states(&b),
        vec![PeerState::Connecting, PeerState::Up { initiator: true }]
    );
    assert!(
        p.nodes[1].node.peer_view(&a).is_some(),
        "the peer is still known"
    );
}

#[test]
fn a_peer_is_reported_up_before_it_has_a_route() {
    let mut p = Pair::new();
    let a = p.nodes[0].public();
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    p.advance(secs(10));
    p.advance_with(secs(190), |_| false);
    let seq: Vec<_> = p.nodes[1]
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Peer { peer, state } if *peer == a => Some(format!("{state:?}")),
            Event::Active { peer, route } if *peer == a => {
                Some(format!("route {}", route.is_some()))
            }
            _ => None,
        })
        .collect();
    let at = |s: &str| seq.iter().position(|x| x.starts_with(s)).unwrap();
    assert!(at("Up") < at("route true"), "{seq:?}");
}

#[test]
fn the_active_route_is_reported_gone_when_the_peer_goes_down() {
    let mut p = Pair::new();
    let a = p.nodes[0].public();
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    p.advance(secs(10));
    p.advance_with(secs(190), |_| false);
    let routes: Vec<_> = p.nodes[1]
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Active { peer, route } if *peer == a => Some(route.is_some()),
            _ => None,
        })
        .collect();
    assert_eq!(routes.first(), Some(&true), "{routes:?}");
    assert_eq!(routes.last(), Some(&false), "{routes:?}");
    assert_eq!(
        p.nodes[1].states(&a).last(),
        Some(&PeerState::Down(Reason::Unreachable))
    );
}

fn lone(accept: bool) -> (Core, SimRng) {
    let mut rng = SimRng::new(5);
    let mut cfg = Config::new(
        vardevall_proto::keys::NodeSecret::generate(&mut rng),
        NetworkSecret::from_bytes([3; 32]),
    );
    cfg.accept_members = accept;
    (Core::new(cfg, now_at(0), &mut rng), rng)
}

fn found(addr: &str) -> Found {
    Found {
        offered: vec![Candidate::lan(addr.parse().unwrap())],
        spare: Vec::new(),
    }
}

#[test]
fn a_member_is_created_by_set_candidates_only_when_members_are_accepted() {
    let (mut n, mut rng) = lone(false);
    let key = NodePublic::from_bytes([7; 32]);
    let g = static_group();
    assert_eq!(
        n.set_candidates(now_at(0), &mut rng, &key, g.clone(), found("192.0.2.1:1")),
        Err(PeerError::Unknown)
    );
    n.set_accept_members(true);
    assert_eq!(
        n.set_candidates(now_at(0), &mut rng, &key, g.clone(), Found::default()),
        Ok(false),
        "withdrawing creates nothing"
    );
    assert!(n.peer_view(&key).is_none());
    assert_eq!(
        n.set_candidates(now_at(0), &mut rng, &key, g, found("192.0.2.1:1")),
        Ok(true)
    );
    assert_eq!(n.peer_view(&key).unwrap().trust, Trust::Member);
    let mut added = Vec::new();
    while let Some(o) = n.poll_output() {
        if let vardevall_proto::node::Output::Event(Event::Added { peer, trust }) = o {
            added.push((peer, trust));
        }
    }
    assert_eq!(added, vec![(key, Trust::Member)]);
}

#[test]
fn evicted_members_are_reported_removed() {
    let (mut n, mut rng) = lone(true);
    let total = 4400u32;
    let mut keys = Vec::new();
    for i in 0..total {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&(i + 1).to_le_bytes());
        let key = NodePublic::from_bytes(k);
        keys.push(key);
        let now = now_at(u64::from(i));
        n.set_candidates(now, &mut rng, &key, static_group(), found("192.0.2.1:1"))
            .unwrap();
    }
    let (mut added, mut removed) = (Vec::new(), Vec::new());
    while let Some(o) = n.poll_output() {
        match o {
            vardevall_proto::node::Output::Event(Event::Added { peer, .. }) => added.push(peer),
            vardevall_proto::node::Output::Event(Event::Removed { peer }) => removed.push(peer),
            _ => {}
        }
    }
    assert_eq!(added.len(), total as usize);
    assert!(removed.len() >= 256, "{}", removed.len());
    assert_eq!(n.stats().peers, added.len() - removed.len());
    for r in &removed {
        assert!(n.peer_view(r).is_none());
    }
    assert!(
        n.peer_view(keys.last().unwrap()).is_some(),
        "the newest stays"
    );
}

#[test]
fn services_travel_to_the_peer_and_are_announced_by_an_event() {
    let mut p = Pair::new();
    let a = p.nodes[0].public();
    let svc = Service::new("web", 8080, Proto::Tcp).unwrap();
    let now = p.now;
    let n = &mut p.nodes[0];
    n.node.set_services(now, &mut n.rng, vec![svc]);
    let pkt = packet(&p, 0, 1);
    p.send(0, &pkt);
    p.advance(secs(3));
    let providers = p.nodes[1].node.providers("web", None);
    assert!(
        providers
            .iter()
            .any(|x| x.key == a && x.port == 8080 && x.live),
        "{providers:?}"
    );
    assert_eq!(p.nodes[1].node.service_names(), vec!["web".to_owned()]);
    assert!(p.nodes[1].count(|e| matches!(e, Event::Services)) > 0);
    assert!(
        p.nodes[1]
            .node
            .providers("web", Some(Proto::Udp))
            .is_empty()
    );
}

#[test]
fn a_frame_from_a_new_source_on_an_exhausted_transport_is_handled_but_makes_and_moves_no_route() {
    use std::net::SocketAddr;
    use vardevall_proto::meter::{Budget, BudgetSource};
    use vardevall_proto::transport::{Path, Remote};

    let mut p = Pair::new();
    p.add_switch();
    let (a, b) = (p.nodes[0].public(), p.nodes[1].public());
    let first = packet(&p, 0, 1);
    p.send(0, &first);
    p.advance(secs(3));
    assert_eq!(p.nodes[1].packets().len(), 1);
    let udp = p.nodes[1].udp;
    let now = p.now;
    let spent = Budget {
        remaining: 0,
        ..Budget::new(1, BudgetSource::Relay, true)
    };
    let n = &mut p.nodes[1];
    n.node.set_budget(now, &mut n.rng, udp, Some(spent));
    p.advance(secs(2));
    let view = p.nodes[1].node.peer_view(&a).unwrap();
    assert!(view.routes.iter().all(|r| r.path.via != udp));
    let before = view.active.expect("the switch route is active");
    assert_ne!(before.path.via, udp);

    let second = packet(&p, 0, 2);
    p.send(0, &second);
    let from_elsewhere: SocketAddr = "[2001:db8::77]:4000".parse().unwrap();
    let wires: Vec<Wire> = p.collect().into_iter().filter(|w| w.from == 0).collect();
    assert!(!wires.is_empty());
    for mut w in wires {
        w.path = Path {
            via: udp,
            to: Remote::Addr(from_elsewhere),
        };
        p.deliver(w);
    }
    p.collect();
    assert_eq!(
        p.nodes[1].packets().len(),
        2,
        "the frame is handled as usual"
    );
    let view = p.nodes[1].node.peer_view(&a).unwrap();
    assert!(
        view.routes.iter().all(|r| r.path.via != udp),
        "no learned route on the exhausted transport"
    );
    assert_eq!(view.active.map(|r| r.path), Some(before.path));
    let _ = b;
}
