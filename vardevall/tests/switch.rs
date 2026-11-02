//! Nodes that know each other only through a switch (vv-04, vv-05 §4.2, §4.7).

mod common;

use std::future::pending;
use std::sync::Arc;
use std::time::Duration;

use common::{Setup, SwitchUse, ipv6};
use tokio::net::TcpListener;
use vardevall::view::Route;
use vardevall::{
    Level, NodeEvent, PeerState, Reason, SwitchAuth, SwitchFailure, SwitchSpec, SwitchState, os_rng,
};
use vardevall_proto::keys::{NetworkSecret, SwitchPublic, SwitchSecret};
use vardevall_switch::config::Config;
use vardevall_switch::{Switch, key};

struct Running {
    spec: SwitchSpec,
    public: SwitchPublic,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn switch(tokens: &[&str]) -> Running {
    switch_on(0, key::generate().unwrap(), tokens).await
}

async fn switch_on(port: u16, secret: SwitchSecret, tokens: &[&str]) -> Running {
    switch_with(port, secret, tokens, |_| {}).await
}

async fn switch_with(
    port: u16,
    secret: SwitchSecret,
    tokens: &[&str],
    configure: impl FnOnce(&mut Config),
) -> Running {
    let mut config = Config::new(vec!["127.0.0.1:0".parse().unwrap()], "unused".into());
    configure(&mut config);
    config.names = vec!["127.0.0.1".to_owned()];
    config.tokens = tokens.iter().map(|t| (*t).to_owned()).collect();
    config.timeouts.reconnect_grace = Duration::from_secs(5);
    let public = secret.public();
    let switch = Arc::new(Switch::new(&config, secret).unwrap());
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move { switch.run(vec![listener], pending()).await });
    Running {
        spec: SwitchSpec::pinned(public, "127.0.0.1", port, None),
        public,
        task,
    }
}

#[tokio::test]
async fn nodes_without_any_other_address_connect_and_exchange_packets_through_a_switch() {
    let sw = switch(&[]).await;
    let net = NetworkSecret::generate(&mut os_rng());
    let a_setup = Setup::new(&net);
    let b_setup = Setup::new(&net);
    let (a_key, b_key) = (a_setup.public(), b_setup.public());
    let mut b = b_setup
        .peer(a_key, None)
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();
    let mut a = a_setup
        .peer(b_key, None)
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();

    a.next(|e| {
        matches!(
            e,
            NodeEvent::Switch {
                state: SwitchState::Registered,
                ..
            }
        )
        .then_some(())
    })
    .await;
    b.next(|e| {
        matches!(
            e,
            NodeEvent::Switch {
                state: SwitchState::Registered,
                ..
            }
        )
        .then_some(())
    })
    .await;

    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"hello through the switch");
    let mut sent = 0;
    let got = loop {
        assert!(a.handle.send_packet(&b_key, &packet));
        sent += 1;
        let wait = tokio::time::timeout(Duration::from_millis(500), b.packet()).await;
        if let Ok(p) = wait {
            break p;
        }
        assert!(sent < 20, "no packet arrived");
    };
    assert_eq!(got.0, a_key);
    assert_eq!(got.1, packet);

    let reply = ipv6(b.overlay.ula, a.overlay.ula, b"and back");
    assert!(b.handle.send_packet(&a_key, &reply));
    let mut saw_switch = false;
    let (from, got) = a
        .next(|e| match e {
            NodeEvent::Route {
                route: Some(Route::Switch(_)),
                ..
            } => {
                saw_switch = true;
                None
            }
            NodeEvent::Packet { peer, packet } => Some((peer, packet)),
            _ => None,
        })
        .await;
    assert_eq!((from, got), (b_key, reply));
    assert!(saw_switch, "the peer's path is reported as the switch");
}

#[tokio::test]
async fn the_default_policy_carries_the_handshake_but_not_tunnel_data() {
    let sw = switch(&[]).await;
    let net = NetworkSecret::generate(&mut os_rng());
    let a_setup = Setup::new(&net);
    let b_setup = Setup::new(&net);
    let (a_key, b_key) = (a_setup.public(), b_setup.public());
    let mut b = b_setup
        .peer(a_key, None)
        .switch(sw.spec.clone(), SwitchUse::Handshake)
        .start();
    let mut a = a_setup
        .peer(b_key, None)
        .switch(sw.spec.clone(), SwitchUse::Handshake)
        .start();
    a.next(|e| {
        matches!(
            e,
            NodeEvent::Switch {
                state: SwitchState::Registered,
                ..
            }
        )
        .then_some(())
    })
    .await;
    b.next(|e| {
        matches!(
            e,
            NodeEvent::Switch {
                state: SwitchState::Registered,
                ..
            }
        )
        .then_some(())
    })
    .await;
    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"x");
    a.handle.send_packet(&b_key, &packet);
    a.next(|e| {
        matches!(
            e,
            NodeEvent::Peer {
                state: PeerState::Up { .. },
                ..
            }
        )
        .then_some(())
    })
    .await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), b.packet())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn switch_failures_are_reported() {
    let net = NetworkSecret::generate(&mut os_rng());

    let sw = switch(&["right"]).await;
    let mut node = Setup::new(&net)
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();
    let state = node
        .next(|e| match e {
            NodeEvent::Switch {
                state: SwitchState::Disconnected(f),
                ..
            } => Some(f),
            _ => None,
        })
        .await;
    assert_eq!(state, SwitchFailure::TokenRejected);

    let mut spec = sw.spec.clone();
    spec.token = Some("right".into());
    let mut ok = Setup::new(&net).switch(spec, SwitchUse::Data).start();
    ok.next(|e| {
        matches!(
            e,
            NodeEvent::Switch {
                state: SwitchState::Registered,
                ..
            }
        )
        .then_some(())
    })
    .await;

    let mut wrong_key = sw.spec.clone();
    wrong_key.auth = SwitchAuth::Pinned(key::generate().unwrap().public());
    let mut node = Setup::new(&net).switch(wrong_key, SwitchUse::Data).start();
    let state = node
        .next(|e| match e {
            NodeEvent::Switch {
                state: SwitchState::Disconnected(f),
                ..
            } => Some(f),
            _ => None,
        })
        .await;
    assert_eq!(state, SwitchFailure::Untrusted);

    let mut dead = sw.spec.clone();
    dead.port = 1;
    let mut node = Setup::new(&net).switch(dead, SwitchUse::Data).start();
    let state = node
        .next(|e| match e {
            NodeEvent::Switch {
                state: SwitchState::Disconnected(f),
                ..
            } => Some(f),
            _ => None,
        })
        .await;
    assert_eq!(state, SwitchFailure::Unreachable);
    let _ = sw.public;
}

fn registered(e: &NodeEvent) -> bool {
    matches!(
        e,
        NodeEvent::Switch {
            state: SwitchState::Registered,
            ..
        }
    )
}

#[tokio::test]
async fn a_node_registers_again_after_the_switch_restarts() {
    let secret = key::generate().unwrap();
    let sw = switch_on(0, secret.clone(), &[]).await;
    let port = sw.spec.port;
    let net = NetworkSecret::generate(&mut os_rng());
    let mut node = Setup::new(&net)
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();
    node.next(|e| registered(&e).then_some(())).await;
    drop(sw);
    node.next(|e| {
        matches!(
            e,
            NodeEvent::Switch {
                state: SwitchState::Disconnected(_),
                ..
            }
        )
        .then_some(())
    })
    .await;
    let _again = switch_on(port, secret, &[]).await;
    node.next(|e| registered(&e).then_some(())).await;
}

#[tokio::test]
async fn a_path_change_reconnects_to_the_switch() {
    let sw = switch(&[]).await;
    let net = NetworkSecret::generate(&mut os_rng());
    let mut node = Setup::new(&net)
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();
    node.next(|e| registered(&e).then_some(())).await;
    node.handle.path_changed();
    node.next(|e| {
        matches!(
            e,
            NodeEvent::Switch {
                state: SwitchState::Connecting,
                ..
            }
        )
        .then_some(())
    })
    .await;
    node.next(|e| registered(&e).then_some(())).await;
}

#[tokio::test]
async fn a_dead_direct_candidate_falls_back_to_the_switch_after_a_second() {
    let sw = switch(&[]).await;
    let net = NetworkSecret::generate(&mut os_rng());
    let a_setup = Setup::new(&net);
    let b_setup = Setup::new(&net);
    let (a_key, b_key) = (a_setup.public(), b_setup.public());
    let mut b = b_setup
        .peer(a_key, None)
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();
    let dead = "127.0.0.1:9".parse().unwrap();
    let mut a = a_setup
        .peer(b_key, Some(dead))
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();
    a.next(|e| registered(&e).then_some(())).await;
    b.next(|e| registered(&e).then_some(())).await;
    let started = std::time::Instant::now();
    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"late");
    a.handle.send_packet(&b_key, &packet);
    let (from, got) = b.packet().await;
    assert_eq!((from, got), (a_key, packet));
    assert!(started.elapsed() >= Duration::from_millis(900));
}

#[tokio::test]
async fn the_view_reports_a_degraded_metered_switch_route() {
    let sw = switch(&[]).await;
    let net = NetworkSecret::generate(&mut os_rng());
    let a_setup = Setup::new(&net);
    let b_setup = Setup::new(&net);
    let (a_key, b_key) = (a_setup.public(), b_setup.public());
    let mut b = b_setup
        .peer(a_key, None)
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();
    let mut a = a_setup
        .peer(b_key, None)
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();
    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"x");
    let mut sent = 0;
    loop {
        a.handle.send_packet(&b_key, &packet);
        sent += 1;
        if tokio::time::timeout(Duration::from_millis(500), b.packet())
            .await
            .is_ok()
        {
            break;
        }
        assert!(sent < 20, "no packet arrived");
    }
    let view = a
        .next(|e| match e {
            NodeEvent::View(v) => v
                .peers
                .iter()
                .any(|p| matches!(p.route, Some(Route::Switch(_))))
                .then_some(v),
            _ => None,
        })
        .await;
    let peer = &view.peers[0];
    assert!(peer.metered && peer.degraded);
}

/// Bytes the switch lets a session forward in [`a_switch_volume_that_runs_out_ends_the_use_of_the_switch`].
const SESSION_BYTES: u64 = 12_000;

#[tokio::test]
async fn a_switch_volume_that_runs_out_ends_the_use_of_the_switch() {
    let sw = switch_with(0, key::generate().unwrap(), &[], |c| {
        c.limits.session_bytes = SESSION_BYTES;
    })
    .await;
    let net = NetworkSecret::generate(&mut os_rng());
    let a_setup = Setup::new(&net);
    let b_setup = Setup::new(&net);
    let (a_key, b_key) = (a_setup.public(), b_setup.public());
    let mut b = b_setup
        .peer(a_key, None)
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();
    let mut a = a_setup
        .peer(b_key, None)
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();
    let first = a
        .next(|e| match e {
            NodeEvent::Budget {
                transport,
                budget: Some(b),
            } => Some((transport, b)),
            _ => None,
        })
        .await;
    assert_eq!(first.1.total, SESSION_BYTES, "the volume the switch states");
    assert_eq!(first.1.source, vardevall::BudgetSource::Reported);
    assert!(!first.1.received);
    let switch_name = first.0;
    a.next(|e| registered(&e).then_some(())).await;
    b.next(|e| registered(&e).then_some(())).await;

    let packet = ipv6(
        a.overlay.ula,
        b.overlay.ula,
        b"through a switch with a small volume",
    );
    let mut levels = Vec::new();
    let mut was_up = false;
    let mut down = None;
    let mut sent = 0;
    while !levels.contains(&Level::Exhausted) {
        assert!(sent < 600, "the budget never ran out: {levels:?}");
        a.handle.send_packet(&b_key, &packet);
        sent += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
        while let Ok(e) = a.events.try_recv() {
            match e {
                NodeEvent::Budget {
                    transport,
                    budget: Some(b),
                } if transport == switch_name => levels.push(b.level()),
                NodeEvent::Peer { state, .. } => {
                    was_up |= matches!(state, PeerState::Up { .. });
                    if matches!(state, PeerState::Down(_)) {
                        down = Some(state);
                    }
                }
                _ => {}
            }
        }
    }
    assert_eq!(
        levels,
        [Level::Half, Level::Low, Level::Exhausted],
        "each level is reported once"
    );
    assert!(was_up, "the peer was up on the switch");
    let down = match down {
        Some(d) => d,
        None => {
            a.next(|e| match e {
                NodeEvent::Peer {
                    state: s @ PeerState::Down(_),
                    ..
                } => Some(s),
                _ => None,
            })
            .await
        }
    };
    assert_eq!(down, PeerState::Down(Reason::Unreachable));

    while tokio::time::timeout(Duration::from_millis(500), b.packet())
        .await
        .is_ok()
    {}
    let view_meter = |v: &vardevall::view::View| {
        v.local
            .transports
            .iter()
            .find(|t| t.name == switch_name)
            .map(|t| (t.usable, t.meter))
    };
    let at_exhaustion = loop {
        let v = a
            .next(|e| match e {
                NodeEvent::View(v) => Some(v),
                _ => None,
            })
            .await;
        if let Some((false, meter)) = view_meter(&v) {
            break meter;
        }
    };
    for _ in 0..50 {
        a.handle.send_packet(&b_key, &packet);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(500), b.packet())
            .await
            .is_err(),
        "the switch forwards nothing from the exhausted node"
    );
    let mut last = None;
    while let Ok(e) = a.events.try_recv() {
        if let NodeEvent::View(v) = e {
            last = view_meter(&v);
        }
    }
    if let Some((usable, meter)) = last {
        assert!(!usable);
        assert_eq!(
            meter.sent, at_exhaustion.sent,
            "nothing more was sent on it"
        );
    }
}
