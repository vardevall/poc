//! Service announcements between connected nodes (vve-14).

mod common;

use std::time::Duration;

use common::{STEP, Setup, TestNode, ipv6, run_for};
use vardevall::{Proto, Provider, Service, ServiceError, os_rng};
use vardevall_proto::keys::{NetworkSecret, NodePublic};

/// Two nodes with a session, `a` configured with `b` as a static endpoint.
async fn connected(a_setup: Setup, b_setup: Setup) -> (TestNode, TestNode, NodePublic, NodePublic) {
    let (a_key, b_key) = (a_setup.public(), b_setup.public());
    let mut b = b_setup.peer(a_key, None).start();
    let a = a_setup.peer(b_key, Some(b.loopback())).start();
    a.handle
        .send_packet(&b_key, &ipv6(a.overlay.ula, b.overlay.ula, b"x"));
    b.packet_stepped().await;
    (a, b, a_key, b_key)
}

/// Polls `f` in steps of paused time until it gives a value.
async fn until<T>(mut f: impl FnMut() -> Option<T>) -> T {
    for _ in 0..(Duration::from_secs(60).as_millis() / STEP.as_millis()) {
        if let Some(v) = f() {
            return v;
        }
        run_for(STEP).await;
    }
    panic!("timed out");
}

fn keys(providers: &[Provider]) -> Vec<(NodePublic, u16, bool)> {
    providers.iter().map(|p| (p.key, p.port, p.live)).collect()
}

#[tokio::test(start_paused = true)]
async fn an_announced_service_reaches_the_peer_and_a_withdrawn_one_leaves() {
    let net = NetworkSecret::generate(&mut os_rng());
    let (a, b, a_key, _) = connected(Setup::new(&net), Setup::new(&net)).await;
    a.handle.announce("web", 8080, Proto::Tcp).unwrap();
    let got = until(|| {
        let p = b.handle.providers("web");
        (!p.is_empty()).then_some(p)
    })
    .await;
    assert_eq!(keys(&got), [(a_key, 8080, true)]);
    assert_eq!(b.handle.providers_for("web", Proto::Udp), []);
    assert_eq!(keys(&b.handle.providers_for("web", Proto::Tcp)).len(), 1);

    assert!(a.handle.withdraw("web"));
    until(|| b.handle.providers("web").is_empty().then_some(())).await;
    assert!(!a.handle.withdraw("web"));
}

#[tokio::test(start_paused = true)]
async fn a_service_of_the_configuration_is_announced_at_the_session_and_listed_for_its_node() {
    let net = NetworkSecret::generate(&mut os_rng());
    let mut a_setup = Setup::new(&net);
    a_setup.services = vec![Service::new("dns", 53, Proto::Udp).unwrap()];
    let (a, b, a_key, b_key) = connected(a_setup, Setup::new(&net)).await;
    let own = until(|| {
        let p = a.handle.providers("dns");
        (!p.is_empty()).then_some(p)
    })
    .await;
    assert_eq!(keys(&own), [(a_key, 53, true)]);
    let got = until(|| {
        let p = b.handle.providers_for("dns", Proto::Udp);
        (!p.is_empty()).then_some(p)
    })
    .await;
    assert_eq!(keys(&got), [(a_key, 53, true)]);
    assert_eq!(b.handle.providers("web"), []);
    let _ = b_key;
}

#[tokio::test(start_paused = true)]
async fn a_node_lists_itself_first_and_replaces_a_service_of_the_same_name() {
    let net = NetworkSecret::generate(&mut os_rng());
    let (a, b, a_key, b_key) = connected(Setup::new(&net), Setup::new(&net)).await;
    a.handle.announce("web", 80, Proto::Tcp).unwrap();
    b.handle.announce("web", 8443, Proto::Tcp).unwrap();
    let both = until(|| {
        let p = b.handle.providers("web");
        (p.len() == 2).then_some(p)
    })
    .await;
    assert_eq!(keys(&both), [(b_key, 8443, true), (a_key, 80, true)]);
    a.handle.announce("web", 81, Proto::Tcp).unwrap();
    until(|| {
        let p = b.handle.providers("web");
        (p.len() == 2 && p[1].port == 81).then_some(())
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn invalid_services_and_too_many_are_refused() {
    let net = NetworkSecret::generate(&mut os_rng());
    let node = Setup::new(&net).start();
    assert_eq!(
        node.handle.announce("Not A Label", 80, Proto::Tcp),
        Err(ServiceError::InvalidName)
    );
    assert_eq!(
        node.handle.announce("web", 0, Proto::Tcp),
        Err(ServiceError::InvalidPort)
    );
    for i in 0..16 {
        node.handle
            .announce(&format!("s{i}"), 1000 + i, Proto::Tcp)
            .unwrap();
    }
    assert_eq!(
        node.handle.announce("one-more", 80, Proto::Tcp),
        Err(ServiceError::TooMany)
    );
    node.handle.announce("s3", 4000, Proto::Tcp).unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_peer_stays_listed_after_its_provider_stops() {
    let net = NetworkSecret::generate(&mut os_rng());
    let (a, b, a_key, _) = connected(Setup::new(&net), Setup::new(&net)).await;
    a.handle.announce("web", 8080, Proto::Tcp).unwrap();
    until(|| (!b.handle.providers("web").is_empty()).then_some(())).await;
    a.handle.stop();
    a.task.await.unwrap();
    // The session is still up on b's side until it expires; the services stay listed.
    assert_eq!(keys(&b.handle.providers("web"))[0].0, a_key);
}
