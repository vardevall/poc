//! Using an exit makes the node connect to the peers held by key.

mod common;

use std::time::Duration;

use common::{Setup, run_for};
use vardevall::{ExitUse, NodeEvent, PeerState, os_rng};
use vardevall_proto::keys::NetworkSecret;

#[tokio::test(start_paused = true)]
async fn setting_the_use_of_an_exit_connects_to_the_peers_without_any_packet() {
    let net = NetworkSecret::generate(&mut os_rng());
    let (a_setup, b_setup) = (Setup::new(&net), Setup::new(&net));
    let (a_key, b_key) = (a_setup.public(), b_setup.public());
    let b = b_setup.peer(a_key, None).start();
    let mut a = a_setup.peer(b_key, Some(b.loopback())).start();
    let up = |e: NodeEvent| match e {
        NodeEvent::Peer {
            peer,
            state: PeerState::Up { .. },
        } if peer == b_key => Some(()),
        _ => None,
    };

    run_for(Duration::from_secs(10)).await;
    while let Ok(e) = a.events.try_recv() {
        assert!(up(e).is_none(), "nothing asked for a session");
    }

    a.handle.set_exit(Some(ExitUse::default()));
    a.next_stepped(Duration::from_secs(30), up).await;
}
