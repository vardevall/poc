mod common;

use common::{Setup, ipv6};
use vardevall::view::Route;
use vardevall::{NodeEvent, PeerState, Trust, os_rng};
use vardevall_proto::keys::NetworkSecret;

#[tokio::test]
async fn packets_flow_over_a_static_endpoint() {
    let net = NetworkSecret::generate(&mut os_rng());
    let b_setup = Setup::new(&net);
    let b_key = b_setup.public();
    let a_setup = Setup::new(&net);
    let a_key = a_setup.public();

    let mut b = b_setup.peer(a_key, None).start();
    let mut a = a_setup.peer(b_key, Some(b.loopback())).start();

    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"hello overlay");
    assert!(a.handle.send_packet(&b_key, &packet));
    let (from, got) = b.packet().await;
    assert_eq!(from, a_key);
    assert_eq!(got, packet);

    let reply = ipv6(b.overlay.ula, a.overlay.ula, b"hello back");
    assert!(b.handle.send_packet(&a_key, &reply));
    let (from, got) = a.packet().await;
    assert_eq!(from, b_key);
    assert_eq!(got, reply);

    a.handle.stop();
    b.handle.stop();
    a.next(|e| matches!(e, NodeEvent::Status(vardevall::Status::Stopped)).then_some(()))
        .await;
    b.task.await.unwrap();
}

#[tokio::test]
async fn reports_peer_states() {
    let net = NetworkSecret::generate(&mut os_rng());
    let b_setup = Setup::new(&net);
    let b_key = b_setup.public();
    let a_setup = Setup::new(&net);
    let a_key = a_setup.public();
    let b = b_setup.peer(a_key, None).start();
    let mut a = a_setup.peer(b_key, Some(b.loopback())).start();

    a.handle
        .send_packet(&b_key, &ipv6(a.overlay.ula, b.overlay.ula, b"x"));
    let mut seen = Vec::new();
    a.next(|e| match e {
        NodeEvent::Added { .. } | NodeEvent::Peer { .. } => {
            seen.push(e);
            None
        }
        NodeEvent::Route { .. } => {
            seen.push(e);
            Some(())
        }
        _ => None,
    })
    .await;
    assert_eq!(
        seen,
        vec![
            NodeEvent::Added {
                peer: b_key,
                trust: Trust::Key
            },
            NodeEvent::Peer {
                peer: b_key,
                state: PeerState::Connecting
            },
            NodeEvent::Peer {
                peer: b_key,
                state: PeerState::Up { initiator: true }
            },
            NodeEvent::Route {
                peer: b_key,
                route: Some(Route::Internet(b.loopback()))
            },
        ]
    );
}

#[tokio::test]
async fn a_local_static_endpoint_is_a_lan_route() {
    let net = NetworkSecret::generate(&mut os_rng());
    let b_setup = Setup::new(&net);
    let b_key = b_setup.public();
    let a_setup = Setup::new(&net);
    let a_key = a_setup.public();
    let b = b_setup.peer(a_key, None).start();
    let mut a = a_setup.peer_local(b_key, b.loopback()).start();

    a.handle
        .send_packet(&b_key, &ipv6(a.overlay.ula, b.overlay.ula, b"x"));
    let route = a
        .next(|e| match e {
            NodeEvent::Route { route, .. } => route,
            _ => None,
        })
        .await;
    assert_eq!(route, Route::Lan(b.loopback()));
}

#[tokio::test]
async fn path_change_keeps_the_session_working() {
    let net = NetworkSecret::generate(&mut os_rng());
    let b_setup = Setup::new(&net);
    let b_key = b_setup.public();
    let a_setup = Setup::new(&net);
    let a_key = a_setup.public();
    let mut b = b_setup.peer(a_key, None).start();
    let a = a_setup.peer(b_key, Some(b.loopback())).start();

    a.handle
        .send_packet(&b_key, &ipv6(a.overlay.ula, b.overlay.ula, b"one"));
    b.packet().await;
    a.handle.path_changed();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    a.handle
        .send_packet(&b_key, &ipv6(a.overlay.ula, b.overlay.ula, b"two"));
    let (_, got) = b.packet().await;
    assert!(got.ends_with(b"two"));
}

#[tokio::test]
async fn unknown_senders_are_ignored() {
    let net = NetworkSecret::generate(&mut os_rng());
    let other = NetworkSecret::generate(&mut os_rng());
    let b_setup = Setup::new(&net);
    let b_key = b_setup.public();
    let c_setup = Setup::new(&other);
    let c_key = c_setup.public();
    let b = b_setup.start();
    let c = c_setup.peer(b_key, Some(b.loopback())).start();
    assert!(
        c.handle
            .send_packet(&b_key, &ipv6(c.overlay.ula, b.overlay.ula, b"x"))
    );
    let _ = c_key;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let mut b = b;
    while let Ok(e) = b.events.try_recv() {
        assert!(!matches!(
            e,
            NodeEvent::Packet { .. } | NodeEvent::Peer { .. }
        ));
    }
}

#[tokio::test]
async fn path_change_rebinds_on_the_same_port() {
    let net = NetworkSecret::generate(&mut os_rng());
    let b_setup = Setup::new(&net);
    let b_key = b_setup.public();
    let a_setup = Setup::new(&net);
    let a_key = a_setup.public();

    let mut b = b_setup.peer(a_key, None).start();
    let mut a = a_setup.peer(b_key, Some(b.loopback())).start();
    let port = a.handle.local_addr().port();

    let first = ipv6(a.overlay.ula, b.overlay.ula, b"before");
    assert!(a.handle.send_packet(&b_key, &first));
    assert_eq!(b.packet().await.1, first);

    a.handle.path_changed();
    a.next(|e| match e {
        NodeEvent::Log { message, .. } if message.contains("rebound on port") => Some(()),
        _ => None,
    })
    .await;
    assert_eq!(a.handle.local_addr().port(), port);

    // Both directions work over the fresh socket.
    let second = ipv6(a.overlay.ula, b.overlay.ula, b"after");
    assert!(a.handle.send_packet(&b_key, &second));
    assert_eq!(b.packet().await.1, second);
    let reply = ipv6(b.overlay.ula, a.overlay.ula, b"back");
    assert!(b.handle.send_packet(&a_key, &reply));
    assert_eq!(a.packet().await.1, reply);

    a.handle.stop();
    b.handle.stop();
    b.task.await.unwrap();
}

#[tokio::test]
async fn a_peer_that_goes_down_has_no_route_in_events_and_view() {
    let net = NetworkSecret::generate(&mut os_rng());
    let b_setup = Setup::new(&net);
    let b_key = b_setup.public();
    let a_setup = Setup::new(&net);
    let a_key = a_setup.public();
    let b = b_setup.peer(a_key, None).start();
    let mut a = a_setup.peer(b_key, Some(b.loopback())).start();

    a.handle
        .send_packet(&b_key, &ipv6(a.overlay.ula, b.overlay.ula, b"x"));
    a.next(|e| matches!(e, NodeEvent::Route { route: Some(_), .. }).then_some(()))
        .await;
    b.handle.stop();
    b.task.await.unwrap();

    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(200)).await;
    let mut last_route = None;
    let view = a
        .next(|e| match e {
            NodeEvent::Route { route, .. } => {
                last_route = Some(route);
                None
            }
            NodeEvent::View(v) => matches!(v.peers[0].state, PeerState::Down(_)).then_some(v),
            _ => None,
        })
        .await;
    assert_eq!(last_route, Some(None));
    assert_eq!(view.peers[0].route, None);
    assert!(!view.peers[0].metered && !view.peers[0].degraded);
}
