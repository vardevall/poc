mod common;

use common::{FakeBonjour, Setup, ipv6};
use vardevall::{Found, MdnsEvent, MdnsRequest, NodeEvent, Trust, os_rng};
use vardevall_proto::keys::NetworkSecret;

#[tokio::test]
async fn key_trusted_peers_find_each_other() {
    let net = NetworkSecret::generate(&mut os_rng());
    let bonjour = FakeBonjour::default();
    let mut sa = Setup::new(&net);
    let mut sb = Setup::new(&net);
    let (ka, kb) = (sa.public(), sb.public());
    sa.mdns = bonjour.sink(0);
    sb.mdns = bonjour.sink(1);
    let mut a = sa.peer(kb, None).start();
    let mut b = sb.peer(ka, None).start();
    bonjour.attach(0, a.handle.clone());
    bonjour.attach(1, b.handle.clone());

    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"found by mdns");
    assert!(a.handle.send_packet(&kb, &packet));
    let (from, got) = b.packet().await;
    assert_eq!(from, ka);
    assert_eq!(got, packet);

    let reply = ipv6(b.overlay.ula, a.overlay.ula, b"ack");
    assert!(b.handle.send_packet(&ka, &reply));
    assert_eq!(a.packet().await.1, reply);

    let reqs = bonjour.requests(0);
    let Some(MdnsRequest::Register {
        service_type,
        txt,
        port,
        ..
    }) = reqs.first()
    else {
        panic!("first request is {:?}", reqs.first());
    };
    assert_eq!(service_type, "_vardevall._udp");
    assert_eq!(
        txt.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
        ["v", "n", "k", "p"]
    );
    assert_eq!(*port, a.handle.local_addr().port());
    assert!(reqs.contains(&MdnsRequest::Browse));

    a.handle.stop();
    a.task.await.unwrap();
    let reqs = bonjour.requests(0);
    assert!(matches!(
        reqs.iter().rev().nth(1),
        Some(MdnsRequest::Unregister { .. })
    ));
    assert_eq!(reqs.last(), Some(&MdnsRequest::StopBrowse));
}

#[tokio::test]
async fn members_are_discovered_by_their_sealed_key() {
    let net = NetworkSecret::generate(&mut os_rng());
    let bonjour = FakeBonjour::default();
    let mut sa = Setup::new(&net);
    let mut sb = Setup::new(&net);
    let (ka, kb) = (sa.public(), sb.public());
    sa.accept_members = true;
    sb.accept_members = true;
    sa.mdns = bonjour.sink(0);
    sb.mdns = bonjour.sink(1);
    let mut a = sa.start();
    let b = sb.start();
    bonjour.attach(0, a.handle.clone());
    bonjour.attach(1, b.handle.clone());

    let found = a
        .next(|e| match e {
            NodeEvent::Added {
                peer,
                trust: Trust::Member,
            } => Some(peer),
            _ => None,
        })
        .await;
    assert_eq!(found, kb);
    let mut b = b;
    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"member");
    assert!(a.handle.send_packet(&kb, &packet));
    let (from, got) = b.packet().await;
    assert_eq!(from, ka);
    assert_eq!(got, packet);
}

fn withdrawn(e: NodeEvent) -> Option<()> {
    match e {
        NodeEvent::Log { message, .. } => message.contains("candidates withdrawn").then_some(()),
        _ => None,
    }
}

#[tokio::test]
async fn a_goodbye_removes_the_candidate_after_the_hold() {
    let net = NetworkSecret::generate(&mut os_rng());
    let bonjour = FakeBonjour::default();
    let mut sa = Setup::new(&net);
    let mut sb = Setup::new(&net);
    let (ka, kb) = (sa.public(), sb.public());
    sa.mdns = bonjour.sink(0);
    sb.mdns = bonjour.sink(1);
    let mut a = sa.peer(kb, None).start();
    let b = sb.peer(ka, None).start();
    bonjour.attach(0, a.handle.clone());
    bonjour.attach(1, b.handle.clone());

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    b.handle.stop();
    b.task.await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    while let Ok(e) = a.events.try_recv() {
        assert!(withdrawn(e).is_none(), "withdrawn before the hold ended");
    }
    a.next_within(std::time::Duration::from_secs(15), withdrawn)
        .await;

    a.handle
        .send_packet(&kb, &ipv6(a.overlay.ula, b.overlay.ula, b"x"));
    a.next(|e| match e {
        NodeEvent::Log { message, .. } => message.contains("parked").then_some(()),
        _ => None,
    })
    .await;
}

#[tokio::test]
async fn a_flap_shorter_than_the_hold_keeps_the_candidate() {
    let net = NetworkSecret::generate(&mut os_rng());
    let bonjour = FakeBonjour::default();
    let mut sa = Setup::new(&net);
    let mut sb = Setup::new(&net);
    let (ka, kb) = (sa.public(), sb.public());
    sa.mdns = bonjour.sink(0);
    sb.mdns = bonjour.sink(1);
    let mut a = sa.peer(kb, None).start();
    let mut b = sb.peer(ka, None).start();
    bonjour.attach(0, a.handle.clone());
    bonjour.attach(1, b.handle.clone());

    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"before");
    assert!(a.handle.send_packet(&kb, &packet));
    assert_eq!(b.packet().await.1, packet);

    let Some(MdnsRequest::Register {
        instance,
        port,
        txt,
        ..
    }) = bonjour.requests(1).into_iter().next()
    else {
        panic!("no register");
    };
    for _ in 0..3 {
        a.handle.mdns_event(MdnsEvent::Lost {
            instance: instance.clone(),
        });
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        a.handle.mdns_event(MdnsEvent::Found(Found {
            instance: instance.clone(),
            txt: txt.clone(),
            port,
            addrs: vec!["127.0.0.1".parse().unwrap()],
            ifindex: 1,
        }));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"after");
    assert!(a.handle.send_packet(&kb, &packet));
    assert_eq!(b.packet().await.1, packet);
    while let Ok(e) = a.events.try_recv() {
        assert!(withdrawn(e).is_none(), "a flap must not withdraw");
    }
}
