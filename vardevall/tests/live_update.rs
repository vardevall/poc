mod common;

use std::net::SocketAddr;

use common::{Setup, TestNode, ipv6};
use vardevall::{Endpoint, LiveUpdate, NodeEvent, PeerSpec, Trust, os_rng};
use vardevall_proto::keys::{NetworkSecret, NodePublic};

fn spec(public: NodePublic, endpoint: Option<SocketAddr>) -> PeerSpec {
    PeerSpec {
        public,
        psk: None,
        endpoints: endpoint.into_iter().map(Endpoint::Addr).collect(),
        endpoints_local: false,
    }
}

fn peers(list: Vec<PeerSpec>) -> LiveUpdate {
    LiveUpdate {
        peers: list,
        exit: None,
        stun: Vec::new(),
        turn: Vec::new(),
    }
}

async fn added(node: &mut TestNode, key: NodePublic) {
    node.next(|e| match e {
        NodeEvent::Added { peer, trust } if peer == key => {
            assert_eq!(trust, Trust::Key);
            Some(())
        }
        _ => None,
    })
    .await;
}

#[tokio::test]
async fn peers_added_while_running_talk_and_unchanged_ones_keep_their_session() {
    let net = NetworkSecret::generate(&mut os_rng());
    let (a_setup, b_setup, c_setup) = (Setup::new(&net), Setup::new(&net), Setup::new(&net));
    let (a_key, b_key, c_key) = (a_setup.public(), b_setup.public(), c_setup.public());
    let mut a = a_setup.start();
    let mut b = b_setup.peer(a_key, None).start();
    let mut c = c_setup.peer(a_key, None).start();

    a.handle
        .update(peers(vec![spec(b_key, Some(b.loopback()))]));
    added(&mut a, b_key).await;
    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"first");
    assert!(a.handle.send_packet(&b_key, &packet));
    assert_eq!(b.packet().await, (a_key, packet));

    a.handle.update(peers(vec![
        spec(b_key, Some(b.loopback())),
        spec(c_key, Some(c.loopback())),
    ]));
    added(&mut a, c_key).await;
    let to_c = ipv6(a.overlay.ula, c.overlay.ula, b"hello c");
    assert!(a.handle.send_packet(&c_key, &to_c));
    assert_eq!(c.packet().await, (a_key, to_c));

    let again = ipv6(a.overlay.ula, b.overlay.ula, b"second");
    assert!(a.handle.send_packet(&b_key, &again));
    assert_eq!(b.packet().await, (a_key, again));
    while let Ok(e) = a.events.try_recv() {
        assert!(
            !matches!(e, NodeEvent::Added { peer, .. } | NodeEvent::Removed { peer } if peer == b_key),
            "b was neither removed nor added again: {e:?}"
        );
    }

    a.handle
        .update(peers(vec![spec(c_key, Some(c.loopback()))]));
    a.next(|e| matches!(e, NodeEvent::Removed { peer } if peer == b_key).then_some(()))
        .await;
    let late = ipv6(a.overlay.ula, c.overlay.ula, b"still c");
    assert!(a.handle.send_packet(&c_key, &late));
    assert_eq!(c.packet().await, (a_key, late));

    a.handle.stop();
    b.handle.stop();
    c.handle.stop();
}
