//! How often the view is reported while traffic flows.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{Setup, ipv6, run_for};
use tokio::time::Instant;
use vardevall::view::{METER_INTERVAL, Route};
use vardevall::{Endpoint, NodeEvent, PeerSpec, PeerState, os_rng};
use vardevall_proto::keys::NetworkSecret;
use vardevall_proto::route::Status;

#[tokio::test(start_paused = true)]
async fn meters_alone_refresh_the_view_every_ten_seconds_and_a_state_change_at_once() {
    let net = NetworkSecret::generate(&mut os_rng());
    let a_setup = Setup::new(&net);
    let b_setup = Setup::new(&net);
    let (a_key, b_key) = (a_setup.public(), b_setup.public());
    let b = b_setup.peer(a_key, None).start();
    let mut a = a_setup.peer(b_key, Some(b.loopback())).start();
    let packet = ipv6(a.overlay.ula, b.overlay.ula, &[7; 200]);

    let mut views = Vec::new();
    let mut up = false;
    let mut settled = None;
    let mut sent = Duration::ZERO;
    while sent < Duration::from_secs(80) {
        a.handle.send_packet(&b_key, &packet);
        run_for(Duration::from_millis(100)).await;
        sent += Duration::from_millis(100);
        while let Ok(e) = a.events.try_recv() {
            match e {
                NodeEvent::Peer {
                    state: PeerState::Up { .. },
                    ..
                } => up = true,
                NodeEvent::View(v) if settled.is_some() => views.push((Instant::now(), v)),
                _ => {}
            }
        }
        if up && settled.is_none() && sent >= Duration::from_secs(20) {
            settled = Some(sent);
        }
    }
    assert!(up, "the nodes never connected");
    assert!(
        (3..=6).contains(&views.len()),
        "about one view per {METER_INTERVAL:?} over 60 s of steady traffic: {}",
        views.len()
    );
    for w in views.windows(2) {
        assert!(
            w[1].0 - w[0].0 >= METER_INTERVAL - Duration::from_millis(300),
            "two views {:?} apart",
            w[1].0 - w[0].0
        );
    }
    let sent_bytes = |v: &vardevall::view::View| v.local.transports[0].meter.sent;
    assert!(
        sent_bytes(&views[views.len() - 1].1) > sent_bytes(&views[0].1),
        "each view carries the current meters"
    );

    a.handle.set_metered(true);
    let mut at_once = None;
    for _ in 0..8 {
        run_for(Duration::from_millis(100)).await;
        while let Ok(e) = a.events.try_recv() {
            if let NodeEvent::View(v) = e
                && v.peers.iter().any(|p| p.metered)
            {
                at_once = Some(v);
            }
        }
    }
    assert!(
        at_once.is_some(),
        "a change of more than meters is reported within a throttle interval"
    );
}

#[tokio::test(start_paused = true)]
async fn a_peer_lists_every_route_with_the_active_one_and_its_rtt() {
    let net = NetworkSecret::generate(&mut os_rng());
    let a_setup = Setup::new(&net);
    let b_setup = Setup::new(&net);
    let (a_key, b_key) = (a_setup.public(), b_setup.public());
    let b = b_setup.peer(a_key, None).start();
    let spare: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let mut a_setup = a_setup;
    a_setup.peers.push(PeerSpec {
        public: b_key,
        psk: None,
        endpoints: vec![Endpoint::Addr(b.loopback()), Endpoint::Addr(spare)],
        endpoints_local: true,
    });
    let mut a = a_setup.start();
    let packet = ipv6(a.overlay.ula, b.overlay.ula, &[7; 100]);

    let mut last = None;
    for _ in 0..300 {
        a.handle.send_packet(&b_key, &packet);
        run_for(Duration::from_millis(100)).await;
        while let Ok(e) = a.events.try_recv() {
            if let NodeEvent::View(v) = e {
                last = Some(v);
            }
        }
    }
    let view = last.expect("no view");
    let peer = &view.peers[0];
    assert_eq!(peer.routes.len(), 2, "{:?}", peer.routes);
    let active: Vec<_> = peer.routes.iter().filter(|r| r.active).collect();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].route, Route::Lan(b.loopback()));
    assert_eq!(active[0].status, Status::Verified);
    assert!(!active[0].metered);
    assert!(active[0].rtt.is_some(), "the active route answered pings");
    assert_eq!(peer.rtt, active[0].rtt);
    assert_eq!(peer.route, Some(active[0].route));
    let other = peer.routes.iter().find(|r| !r.active).unwrap();
    assert_eq!(other.route, Route::Lan(spare));
    assert_ne!(other.status, Status::Verified);
    assert_eq!(other.rtt, None);
}
