//! Behaviour of the session state machine (vv-02 §4, §6; vv-03 §3).

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::sim::*;
use vardevall_proto::discovery::candidate::Candidate;
use vardevall_proto::keys::{NetworkSecret, NodePublic, PairPsk};
use vardevall_proto::node::{Event, PeerConfig, PeerState, Reason, Trust};
use vardevall_proto::session::KEEPALIVE_TIMEOUT;
use vardevall_proto::transport::{Path, Remote};

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn packet_a_to_b(p: &Pair, n: u8) -> Vec<u8> {
    ipv6(p.nodes[0].ula(), p.nodes[1].ula(), &[n; 20])
}

fn packet_b_to_a(p: &Pair, n: u8) -> Vec<u8> {
    ipv6(p.nodes[1].ula(), p.nodes[0].ula(), &[n; 20])
}

fn is_up(s: &PeerState) -> bool {
    matches!(s, PeerState::Up { .. })
}

/// Whether node `n` holds a session with `peer` that can carry data.
fn has_session(n: &Node, peer: &NodePublic) -> bool {
    n.node.peer_view(peer).is_some_and(|v| is_up(&v.link))
}

/// Message 1 fragments and whole messages among `wires`, sent by node `from`.
fn msg1s(wires: &[Wire], from: usize) -> usize {
    wires
        .iter()
        .filter(|w| w.from == from && matches!(w.data[0], 4 | 10))
        .count()
}

#[test]
fn round_trip_over_udp_fragments() {
    let mut p = Pair::new();
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.pump();
    assert_eq!(p.nodes[1].packets(), vec![pkt]);
    let (a, b) = (p.nodes[0].public(), p.nodes[1].public());
    assert_eq!(p.nodes[0].ups(), 1);
    assert_eq!(p.nodes[1].ups(), 1);
    assert_eq!(
        p.nodes[1].states(&a).last(),
        Some(&PeerState::Up { initiator: false }),
        "the responder is up once its session is confirmed"
    );
    let view = p.nodes[1].node.peer_view(&a).unwrap();
    assert!(is_up(&view.link) && !view.unconfirmed);
    let pkt2 = packet_b_to_a(&p, 2);
    p.send(1, &pkt2);
    p.pump();
    assert_eq!(p.nodes[0].packets(), vec![pkt2]);
    assert_eq!(
        p.nodes[0].states(&b).last(),
        Some(&PeerState::Up { initiator: true })
    );
}

#[test]
fn round_trip_through_a_switch() {
    let mut p = Pair::new();
    p.switch_mode();
    let pkt = packet_a_to_b(&p, 7);
    p.send(0, &pkt);
    p.pump();
    assert_eq!(p.nodes[1].packets(), vec![pkt]);
    for n in &p.nodes {
        assert_eq!(n.ups(), 1);
        let peer = if n.public() == p.nodes[0].public() {
            p.nodes[1].public()
        } else {
            p.nodes[0].public()
        };
        assert!(n.node.peer_view(&peer).unwrap().shared.is_empty());
    }
}

#[test]
fn candidates_travel_in_both_payloads() {
    let ca = Candidate::punch("[2001:db8::a]:1111".parse().unwrap());
    let cb = Candidate::relay("198.51.100.4:2222".parse().unwrap());
    let mut p = Pair::new();
    p.switch_mode();
    let now = p.now;
    let [a, b] = &mut p.nodes;
    a.node.set_own_candidates(now, &mut a.rng, vec![ca]);
    b.node.set_own_candidates(now, &mut b.rng, vec![cb]);
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.pump();
    let (pa, pb) = (p.nodes[0].public(), p.nodes[1].public());
    assert_eq!(p.nodes[1].node.peer_view(&pa).unwrap().shared, vec![ca]);
    assert_eq!(p.nodes[0].node.peer_view(&pb).unwrap().shared, vec![cb]);
}

#[test]
fn udp_response_never_exceeds_the_request() {
    let many: Vec<Candidate> = (0..8)
        .map(|i| {
            Candidate::relay(
                format!("[2001:db8:1234:5678:9abc:def0:1234:567{i}]:51820")
                    .parse()
                    .unwrap(),
            )
        })
        .collect();
    let mut p = Pair::new();
    let now = p.now;
    p.nodes[1]
        .node
        .set_own_candidates(now, &mut SimRng::new(3), many);
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    let (mut sent1, mut sent2) = (0, 0);
    for _ in 0..4 {
        let wires = p.collect();
        if wires.is_empty() {
            break;
        }
        for w in wires {
            if w.from == 0 && w.data[0] <= 5 {
                sent1 += w.data.len();
            }
            if w.from == 1 && (6..=7).contains(&w.data[0]) {
                sent2 += w.data.len();
            }
            p.deliver(w);
        }
    }
    assert!(
        sent1 > 0 && sent2 > 0 && sent2 <= sent1,
        "{sent2} > {sent1}"
    );
    assert_eq!(p.nodes[0].ups(), 1);
}

#[test]
fn responder_waits_for_confirmation_before_sending() {
    let mut p = Pair::new();
    let (a, b) = (p.nodes[0].public(), p.nodes[1].public());
    let pa = packet_a_to_b(&p, 1);
    p.send(0, &pa);
    // deliver message 1 only; hold back everything B sends
    let wires = p.collect();
    for w in wires {
        p.deliver(w);
    }
    let b_wires = p.collect();
    assert!(
        b_wires.iter().any(|w| (6..=7).contains(&w.data[0])),
        "message 2 sent"
    );
    let view = p.nodes[1].node.peer_view(&a).unwrap();
    assert!(!is_up(&view.link), "no session can carry data yet");
    assert!(view.unconfirmed);
    assert_eq!(p.nodes[1].states(&a), vec![PeerState::Connecting]);
    // B never sends data on the unconfirmed session
    let pb = packet_b_to_a(&p, 3);
    p.send(1, &pb);
    let wires = p.collect();
    assert_eq!(
        wires
            .iter()
            .filter(|w| w.from == 1 && w.data[0] == 9)
            .count(),
        0,
        "nothing but handshake messages left B"
    );
    assert_eq!(p.nodes[1].node.peer_view(&a).unwrap().queued, 1);
    // once A's first frame confirms the session, the queue is sent
    for w in b_wires {
        p.deliver(w);
    }
    p.pump();
    assert_eq!(p.nodes[1].packets(), vec![pa]);
    assert_eq!(p.nodes[0].packets(), vec![pb]);
    assert!(has_session(&p.nodes[1], &a) && has_session(&p.nodes[0], &b));
}

#[test]
fn received_data_causes_no_keepalive_of_the_session() {
    let mut p = Pair::new();
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.advance(secs(6));
    let empty_from_b = |p: &mut Pair, d: Duration| {
        let mut n = 0;
        p.advance_with(d, |w| {
            n += usize::from(
                w.from == 1 && w.data.len() == vardevall_proto::plane::frame::FRAME_OVERHEAD,
            );
            true
        });
        n
    };
    assert_eq!(empty_from_b(&mut p, secs(9)), 0);
    assert_eq!(empty_from_b(&mut p, secs(2)), 0);
}

/// The session's own loss timer (vv-02 §6.4): the routes do not notice first because their
/// keeping ping is as slow as `KEEPALIVE_TIMEOUT`.
#[test]
fn path_loss_starts_a_new_handshake() {
    let mut p = Pair::with(
        |c| c.routes.detect_timeout = Some(KEEPALIVE_TIMEOUT),
        |_| {},
    );
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.pump();
    p.advance(secs(6));
    // A sends, B's replies never arrive
    let pkt = packet_a_to_b(&p, 2);
    p.send(0, &pkt);
    let mut handshakes = 0;
    p.advance_with(secs(14), |w| {
        handshakes += msg1s(std::slice::from_ref(w), 0);
        w.from == 0 && w.data[0] == 9
    });
    assert_eq!(handshakes, 0);
    p.advance_with(secs(2), |w| {
        handshakes += msg1s(std::slice::from_ref(w), 0);
        true
    });
    assert!(handshakes > 0, "KEEPALIVE_TIMEOUT + REKEY_TIMEOUT");
    let b = p.nodes[1].public();
    assert!(has_session(&p.nodes[0], &b));
}

/// With the default `DETECT_TIMEOUT` the unanswered keeping pings fail the route first and the
/// session is lost; the next packet starts a handshake.
#[test]
fn unanswered_keeping_pings_lose_the_session_and_the_next_packet_starts_a_handshake() {
    let mut p = Pair::new();
    let (a, b) = (p.nodes[0].public(), p.nodes[1].public());
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.pump();
    p.advance(secs(6));
    let pkt = packet_a_to_b(&p, 2);
    p.send(0, &pkt);
    let mut handshakes = 0;
    p.advance_with(secs(8), |w| {
        handshakes += msg1s(std::slice::from_ref(w), 0);
        w.from == 0 && w.data[0] == 9
    });
    assert_eq!(handshakes, 0, "nothing to send");
    assert!(!has_session(&p.nodes[0], &b), "lost within 8 s");
    assert_eq!(
        p.nodes[0].states(&b).last(),
        Some(&PeerState::Down(Reason::Unreachable))
    );
    let pkt = packet_a_to_b(&p, 3);
    p.send(0, &pkt);
    p.advance_with(secs(6), |w| {
        handshakes += msg1s(std::slice::from_ref(w), 0);
        true
    });
    assert!(handshakes > 0);
    assert!(has_session(&p.nodes[0], &b) && has_session(&p.nodes[1], &a));
}

#[test]
fn rekey_after_two_minutes_on_the_initiators_next_send() {
    let mut p = Pair::new();
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.pump();
    let mut early = 0;
    p.advance_with(secs(119), |w| {
        early += msg1s(std::slice::from_ref(w), 0);
        true
    });
    assert_eq!(early, 0, "no rekey before REKEY_AFTER_TIME");
    p.advance(secs(5));
    let pkt = packet_a_to_b(&p, 2);
    p.send(0, &pkt);
    p.pump();
    assert_eq!(p.nodes[1].packets().len(), 2);
    let pkt = packet_a_to_b(&p, 3);
    p.send(0, &pkt);
    p.pump();
    assert_eq!(p.nodes[1].packets().len(), 3);
    let (a, b) = (p.nodes[0].public(), p.nodes[1].public());
    assert!(has_session(&p.nodes[0], &b) && has_session(&p.nodes[1], &a));
    assert_eq!(p.nodes[0].ups(), 1, "a rekey is not a new state");
}

#[test]
fn sessions_expire_after_180_seconds() {
    let mut p = Pair::new();
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.pump();
    p.advance_with(secs(181), |_| false);
    let (a, b) = (p.nodes[0].public(), p.nodes[1].public());
    assert!(!has_session(&p.nodes[0], &b));
    assert!(!has_session(&p.nodes[1], &a));
    assert_eq!(
        p.nodes[1].states(&a).last(),
        Some(&PeerState::Down(Reason::Idle))
    );
    let pkt = packet_a_to_b(&p, 2);
    p.send(0, &pkt);
    p.advance(secs(6));
    assert_eq!(p.nodes[1].packets().len(), 2);
}

#[test]
fn crossing_handshakes_keep_both_sessions_usable() {
    let mut p = Pair::new();
    let (pa, pb) = (packet_a_to_b(&p, 1), packet_b_to_a(&p, 2));
    p.send(0, &pa);
    p.send(1, &pb);
    p.pump();
    assert_eq!(p.nodes[1].packets(), vec![pa.clone()]);
    assert_eq!(p.nodes[0].packets(), vec![pb.clone()]);
    for i in 0..4u8 {
        let (x, y) = (packet_a_to_b(&p, 10 + i), packet_b_to_a(&p, 20 + i));
        p.send(0, &x);
        p.send(1, &y);
        p.pump();
    }
    assert_eq!(p.nodes[0].packets().len(), 5);
    assert_eq!(p.nodes[1].packets().len(), 5);
}

/// The data frame that `from` sends for a packet, held back, with the source `addr`; the other
/// datagrams are delivered, except frames of `from`, which would number above it.
fn data_frame_from(p: &mut Pair, from: usize, n: u8, addr: SocketAddr) -> Wire {
    let packet = if from == 0 {
        packet_a_to_b(p, n)
    } else {
        packet_b_to_a(p, n)
    };
    p.send(from, &packet);
    let mut wires = p.collect();
    let i = wires
        .iter()
        .enumerate()
        .filter(|(_, w)| w.from == from && w.data[0] == 9)
        .max_by_key(|(_, w)| w.data.len())
        .map(|(i, _)| i)
        .expect("a data frame");
    let frame = wires.remove(i);
    for w in wires
        .into_iter()
        .filter(|w| w.from != from || w.data[0] != 9)
    {
        p.deliver(w);
    }
    Wire {
        path: Path {
            to: Remote::Addr(addr),
            ..frame.path
        },
        ..frame
    }
}

fn active_of(p: &Pair, node: usize) -> Option<Remote> {
    let peer = p.nodes[1 - node].public();
    let view = p.nodes[node].node.peer_view(&peer)?;
    view.active.map(|r| r.path.to)
}

/// After crossing handshakes each node sends on the session that is the other's `previous`
///.
#[test]
fn data_roams_after_crossing_handshakes() {
    let moved: SocketAddr = "203.0.113.90:4001".parse().unwrap();
    for (from, to) in [(0, 1), (1, 0)] {
        let mut p = Pair::new();
        let (pa, pb) = (packet_a_to_b(&p, 1), packet_b_to_a(&p, 2));
        p.send(0, &pa);
        p.send(1, &pb);
        p.pump();
        let w = data_frame_from(&mut p, from, 10, moved);
        p.deliver(w);
        assert_eq!(
            active_of(&p, to),
            Some(Remote::Addr(moved)),
            "{from} -> {to}"
        );
    }
}

/// A frame of the session that the peer has left, arriving after one of the newer session, makes
/// no route.
#[test]
fn data_of_a_session_the_peer_has_left_moves_nothing() {
    let mut p = Pair::new();
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.pump();
    p.advance(secs(125));
    let stale: SocketAddr = "203.0.113.91:4002".parse().unwrap();
    let old = data_frame_from(&mut p, 0, 2, stale);
    p.pump();
    let before = active_of(&p, 1);
    let pkt = packet_a_to_b(&p, 3);
    p.send(0, &pkt);
    p.pump();
    assert_eq!(p.nodes[1].packets().len(), 2);

    p.deliver(old);
    let b = &p.nodes[1];
    let view = b.node.peer_view(&p.nodes[0].public()).unwrap();
    assert!(
        view.routes.iter().all(|r| r.path.to != Remote::Addr(stale)),
        "no route for the left session"
    );
    assert_eq!(active_of(&p, 1), before);
}

#[test]
fn accepting_message_1_keeps_the_own_pending_initiation() {
    let mut p = Pair::new();
    let (a, b) = (p.nodes[0].public(), p.nodes[1].public());
    let (pa, pb) = (packet_a_to_b(&p, 1), packet_b_to_a(&p, 2));
    p.send(0, &pa);
    p.send(1, &pb);
    let wires = p.collect();
    for w in wires {
        p.deliver(w);
    }
    assert_eq!(p.nodes[0].node.peer_view(&b).unwrap().pending, 1);
    assert_eq!(p.nodes[1].node.peer_view(&a).unwrap().pending, 1);
    p.pump();
    assert_eq!(p.nodes[0].node.peer_view(&b).unwrap().pending, 0);
    assert!(has_session(&p.nodes[0], &b));
}

#[test]
fn replayed_message_1_is_dropped() {
    let mut p = Pair::new();
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    let wires = p.collect();
    for w in wires.clone() {
        p.deliver(w);
    }
    p.pump();
    assert_eq!(p.nodes[1].ups(), 1);
    for w in wires {
        p.deliver(w);
    }
    assert!(p.collect().is_empty(), "no reply to a replay");
    assert_eq!(p.nodes[1].ups(), 1);
}

#[test]
fn replayed_data_frame_is_dropped() {
    let mut p = Pair::new();
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.pump();
    let pkt2 = packet_a_to_b(&p, 2);
    p.send(0, &pkt2);
    let wires = p.collect();
    let frames: Vec<Wire> = wires.iter().filter(|w| w.data[0] == 9).cloned().collect();
    assert!(!frames.is_empty());
    for w in wires {
        p.deliver(w);
    }
    for f in frames {
        p.deliver(f.clone());
        p.deliver(f);
    }
    p.collect();
    assert_eq!(p.nodes[1].packets().len(), 2);
}

#[test]
fn frames_with_a_wrong_source_are_dropped() {
    let mut p = Pair::new();
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.pump();
    let spoofed = ipv6("fd00::1".parse().unwrap(), p.nodes[1].ula(), &[0; 8]);
    p.send(0, &spoofed);
    p.pump();
    assert_eq!(p.nodes[1].packets(), vec![pkt]);
}

#[test]
fn oversized_packets_are_refused() {
    let mut p = Pair::new();
    let to = p.nodes[1].public();
    let now = p.now;
    let class = p.class;
    let n = &mut p.nodes[0];
    assert!(
        n.node
            .send(now, &mut n.rng, &to, class, &vec![0u8; 1281])
            .is_err()
    );
}

#[test]
fn unknown_initiators_get_no_answer_and_members_are_accepted_on_request() {
    let network = NetworkSecret::from_bytes([42; 32]);
    let now = now_at(0);
    let mut a = new_node(1, &network, 1, now, |_| {});
    let b = new_node(2, &network, 2, now, |_| {});
    let bpk = b.public();
    a.node.add_peer(PeerConfig::new(bpk), now.instant);
    a.know(now, &b);
    let apk = a.public();
    let ula_a = a.ula();
    let ula_b = b.ula();
    let mut p = Pair {
        nodes: [a, b],
        now,
        ms: 0,
        network,
        class: Default::default(),
    };
    let pkt = ipv6(ula_a, ula_b, &[1; 8]);
    p.send(0, &pkt);
    let wires = p.collect();
    for w in wires {
        p.deliver(w);
    }
    assert!(
        p.collect().is_empty(),
        "B does not answer an unknown initiator"
    );
    assert!(p.nodes[1].node.peer_view(&apk).is_none());

    p.nodes[1].node.set_accept_members(true);
    p.advance(secs(6));
    assert_eq!(p.nodes[1].packets(), vec![pkt]);
    assert_eq!(
        p.nodes[1].node.peer_view(&apk).unwrap().trust,
        Trust::Member
    );
    p.nodes[1].node.set_accept_members(false);
    assert!(p.nodes[1].node.peer_view(&apk).is_none());
}

#[test]
fn another_network_is_silently_ignored() {
    let now = now_at(0);
    let n1 = NetworkSecret::from_bytes([1; 32]);
    let n2 = NetworkSecret::from_bytes([2; 32]);
    let mut a = new_node(1, &n1, 1, now, |_| {});
    let mut b = new_node(2, &n2, 2, now, |_| {});
    a.node.add_peer(PeerConfig::new(b.public()), now.instant);
    b.node.add_peer(PeerConfig::new(a.public()), now.instant);
    a.know(now, &b);
    b.know(now, &a);
    let (ula_a, ula_b) = (a.ula(), b.ula());
    let mut p = Pair {
        nodes: [a, b],
        now,
        ms: 0,
        network: n1,
        class: Default::default(),
    };
    let pkt = ipv6(ula_a, ula_b, &[1; 8]);
    p.send(0, &pkt);
    let wires = p.collect();
    for w in wires {
        p.deliver(w);
    }
    assert!(p.collect().is_empty());
}

#[test]
fn a_mismatched_pair_psk_never_completes_and_gives_up() {
    let mut p = Pair::new();
    let (pa, pb) = (p.nodes[0].public(), p.nodes[1].public());
    let now = p.now.instant;
    p.nodes[0].node.add_peer(
        PeerConfig {
            public: pb,
            psk: PairPsk::from_bytes([1; 32]),
        },
        now,
    );
    p.nodes[1].node.add_peer(
        PeerConfig {
            public: pa,
            psk: PairPsk::from_bytes([2; 32]),
        },
        now,
    );
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.advance(secs(100));
    assert_eq!(p.nodes[0].ups(), 0);
    assert_eq!(
        p.nodes[0].states(&pb),
        vec![PeerState::Connecting, PeerState::Down(Reason::Unreachable)]
    );
    assert_eq!(p.nodes[0].node.peer_view(&pb).unwrap().queued, 0);
    assert_eq!(p.nodes[0].node.peer_view(&pb).unwrap().pending, 0);
}

#[test]
fn matching_pair_psk_works() {
    let mut p = Pair::new();
    let (pa, pb) = (p.nodes[0].public(), p.nodes[1].public());
    let now = p.now.instant;
    p.nodes[0].node.add_peer(
        PeerConfig {
            public: pb,
            psk: PairPsk::from_bytes([9; 32]),
        },
        now,
    );
    p.nodes[1].node.add_peer(
        PeerConfig {
            public: pa,
            psk: PairPsk::from_bytes([9; 32]),
        },
        now,
    );
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.pump();
    assert_eq!(p.nodes[1].packets(), vec![pkt]);
}

#[test]
fn one_handshake_is_pending_per_peer() {
    let mut p = Pair::new();
    let b = p.nodes[1].public();
    let (p1, p2) = (packet_a_to_b(&p, 1), packet_a_to_b(&p, 2));
    p.send(0, &p1);
    let first = p.collect();
    assert!(msg1s(&first, 0) > 0);
    p.send(0, &p2);
    assert_eq!(msg1s(&p.collect(), 0), 0, "the second send starts nothing");
    let v = p.nodes[0].node.peer_view(&b).unwrap();
    assert_eq!((v.pending, v.queued), (1, 2));
}

#[test]
fn retransmissions_are_fresh_messages_spaced_by_rekey_timeout() {
    let mut p = Pair::new();
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    let mut firsts = Vec::new();
    let mut times = Vec::new();
    for w in p.collect() {
        if w.data[0] == 4 {
            firsts.push(w.data[8..48].to_vec());
            times.push(p.ms);
        }
    }
    for _ in 0..3 {
        let end = p.ms + 6000;
        while p.ms < end {
            let step = p.nodes[0]
                .node
                .poll_timeout()
                .map(ms_ceil)
                .unwrap_or(end)
                .min(end);
            p.set_time(step);
            let now = p.now;
            p.nodes[0].node.handle_timeout(now, &mut SimRng::new(step));
            for w in p.collect() {
                if w.data[0] == 4 {
                    firsts.push(w.data[8..48].to_vec());
                    times.push(p.ms);
                }
            }
        }
    }
    assert!(firsts.len() >= 3, "{times:?}");
    assert!(firsts.windows(2).all(|w| w[0] != w[1]));
    let gaps: Vec<u64> = times.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(gaps.iter().all(|g| (5000..=5333).contains(g)), "{gaps:?}");
}

#[test]
fn under_load_the_responder_asks_for_a_cookie_and_the_retry_carries_mac2() {
    let mut p = Pair::with(|_| {}, |c| c.load_threshold = 0);
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    let mut cookie_replies = 0;
    let mut mac2_seen = false;
    let mut handshakes = 0;
    for _ in 0..20 {
        let wires = p.collect();
        if wires.is_empty() {
            break;
        }
        for w in wires {
            if w.data[0] == 8 {
                cookie_replies += 1;
            }
            if w.from == 0 && w.data[0] == 4 {
                handshakes += 1;
                mac2_seen |= w.data[w.data.len() - 16..].iter().any(|b| *b != 0);
            }
            p.deliver(w);
        }
    }
    assert_eq!(cookie_replies, 2, "one reply per fragment, no loop");
    assert_eq!(handshakes, 2, "the original and one early retransmission");
    assert!(mac2_seen);
    assert_eq!(p.nodes[1].packets(), vec![pkt]);
}

#[test]
fn cookie_replies_from_non_members_are_ignored() {
    let mut p = Pair::with(|_| {}, |c| c.load_threshold = 0);
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    let wires = p.collect();
    let mut reply = None;
    for w in wires {
        p.deliver(w);
    }
    for w in p.collect() {
        if w.data[0] == 8 {
            reply = Some(w);
        }
    }
    let mut w = reply.unwrap();
    w.data[40] ^= 1;
    p.deliver(w);
    assert!(
        p.collect().is_empty(),
        "a forged cookie does not trigger a retransmission"
    );
}

#[test]
fn fragments_in_any_order_and_duplicated_reassemble() {
    let mut p = Pair::new();
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    let mut wires = p.collect();
    wires.reverse();
    let dup = wires[0].clone();
    wires.insert(1, dup);
    for w in wires {
        p.deliver(w);
    }
    p.pump();
    assert_eq!(p.nodes[1].packets(), vec![pkt]);
}

#[test]
fn a_lone_fragment_expires_after_two_seconds() {
    let mut p = Pair::new();
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    let wires = p.collect();
    let (f0, f1) = (wires[0].clone(), wires[1].clone());
    p.deliver(f0);
    assert!(p.nodes[1].node.poll_timeout().is_some());
    p.set_time(2_100);
    let now = p.now;
    let n = &mut p.nodes[1];
    n.node.handle_timeout(now, &mut n.rng);
    p.deliver(f1);
    p.pump_with(|w| w.from == 1);
    assert_eq!(p.nodes[1].ups(), 0);
    assert_eq!(
        p.nodes[1].count(|e| matches!(e, Event::Peer { .. })),
        0,
        "the lone fragment started nothing"
    );
}

#[test]
fn malformed_datagrams_are_ignored() {
    let mut p = Pair::new();
    let pkt = packet_a_to_b(&p, 1);
    p.send(0, &pkt);
    p.pump();
    let a = p.nodes[0].public();
    let origin = Path {
        via: p.nodes[1].udp,
        to: Remote::Addr(p.nodes[0].addr),
    };
    let switch = Path {
        via: p.nodes[1].sw,
        to: Remote::Peer(a),
    };
    let now = p.now;
    let n = &mut p.nodes[1];
    for len in [
        0usize, 1, 3, 7, 8, 31, 32, 47, 48, 79, 80, 1199, 1200, 1201, 2000,
    ] {
        for first in 0..=255u8 {
            let mut d = vec![0xa5u8; len];
            if len > 0 {
                d[0] = first;
            }
            n.node.handle_datagram(now, &mut n.rng, origin, &d);
            n.node.handle_datagram(now, &mut n.rng, switch, &d);
        }
    }
    assert!(n.node.poll_output().is_none());
    assert_eq!(p.nodes[1].packets().len(), 1);
}
