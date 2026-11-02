//! Two nodes on this host discovering each other over real multicast sockets.
//!
//! Needs a multicast-capable physical interface, so it is not part of the default run:
//! `cargo test --test builtin_mdns -- --ignored`.

mod common;

use common::{Setup, ipv6};
use vardevall::{BuiltinMdns, MdnsMode, os_rng};
use vardevall_proto::keys::NetworkSecret;

#[tokio::test]
#[ignore = "needs a multicast-capable interface"]
async fn built_in_mdns_finds_a_peer_on_the_same_host() {
    let net = NetworkSecret::generate(&mut os_rng());
    let mut sa = Setup::new(&net);
    let mut sb = Setup::new(&net);
    let (ka, kb) = (sa.public(), sb.public());
    sa.mdns = MdnsMode::Builtin(BuiltinMdns::default());
    sb.mdns = MdnsMode::Builtin(BuiltinMdns::default());
    let mut a = sa.peer(kb, None).start();
    let mut b = sb.peer(ka, None).start();

    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"via multicast");
    assert!(a.handle.send_packet(&kb, &packet));
    assert_eq!(b.packet().await.1, packet);
    let reply = ipv6(b.overlay.ula, a.overlay.ula, b"back");
    assert!(b.handle.send_packet(&ka, &reply));
    assert_eq!(a.packet().await.1, reply);
}
