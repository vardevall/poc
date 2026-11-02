use std::net::{Ipv4Addr, Ipv6Addr};

use vardevall_proto::addr::OverlayAddrs;
use vardevall_proto::ip::site::{self, Site};
use vardevall_proto::keys::{NetworkId, NodePublic};

use super::*;
use crate::packet;
use vardevall_proto::ip::exit::ExitServe;

const NET: &str = "4922546c33892e07359467d6976c3bd90734120918899ecb1bb9a6419d46c413";
const ALICE: &str = "2c7f6e6864189eaeebfb42cfde0f4f28e1c36f49b8f8573ddff648b0ddc66416";
const BOB: &str = "ccfbf6ad114ab8d101a938b24011dc1199d99f5244b9fd24d498cf19d11b5872";
const CAROL: &str = "9f1c2b7a0d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c";

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn net() -> NetworkId {
    NetworkId::from_bytes(hex32(NET))
}

fn key(hex: &str) -> NodePublic {
    NodePublic::from_bytes(hex32(hex))
}

fn addrs(hex: &str) -> OverlayAddrs {
    OverlayAddrs::derive(&net(), &key(hex))
}

fn router() -> Router {
    let mut r = Router::new(net(), key(ALICE));
    r.add_peer(key(BOB)).unwrap();
    r
}

fn pkt(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    packet::build(&src, &dst, 59, 64, b"payload!")
}

#[test]
fn vector_addresses() {
    assert_eq!(
        addrs(ALICE).ula.to_string(),
        "fdef:813d:8791:0:6d0a:8bf2:5ecf:91dd"
    );
    assert_eq!(
        addrs(BOB).link_local.to_string(),
        "fe80::c291:2f0f:d639:e00e"
    );
}

#[test]
fn unicast_to_ula_and_link_local_of_a_peer() {
    let r = router();
    let (a, b) = (addrs(ALICE), addrs(BOB));
    assert_eq!(r.route(&pkt(a.ula, b.ula)), Route::Unicast(key(BOB)));
    assert_eq!(
        r.route(&pkt(a.link_local, b.link_local)),
        Route::Unicast(key(BOB))
    );
}

#[test]
fn unknown_overlay_address_is_unreachable_code_3() {
    let r = router();
    let a = addrs(ALICE);
    let stranger: Ipv6Addr = "fdef:813d:8791:0:1:2:3:4".parse().unwrap();
    let Route::Reply(reply) = r.route(&pkt(a.ula, stranger)) else {
        panic!("expected a reply");
    };
    let h = packet::parse(&reply).unwrap();
    assert_eq!(h.src, a.ula);
    assert_eq!(h.dst, a.ula);
    let msg = &reply[packet::HEADER_LEN..];
    assert_eq!((msg[0], msg[1]), (1, 3));
    assert_eq!(packet::checksum(&h.src, &h.dst, packet::ICMPV6, msg), 0);
    assert_eq!(&msg[8..], &pkt(a.ula, stranger)[..]);
}

#[test]
fn a_removed_member_is_unroutable_and_not_live() {
    let mut r = router();
    let (a, b) = (addrs(ALICE), addrs(BOB));
    r.set_live(key(BOB), true);
    assert_eq!(r.route(&pkt(a.ula, b.ula)), Route::Unicast(key(BOB)));
    r.remove_peer(&key(BOB));
    assert_eq!(r.peer_for(&b.ula), None);
    assert!(matches!(r.route(&pkt(a.ula, b.ula)), Route::Reply(_)));
    assert_eq!(
        r.route(&pkt(a.link_local, "ff02::fb".parse().unwrap())),
        Route::Drop
    );
    r.add_peer(key(BOB)).unwrap();
    let mdns: Ipv6Addr = "ff02::fb".parse().unwrap();
    assert_eq!(
        r.route(&pkt(a.link_local, mdns)),
        Route::Drop,
        "not live again"
    );
    assert_eq!(r.route(&pkt(a.ula, b.ula)), Route::Unicast(key(BOB)));
}

#[test]
fn outside_the_overlay_has_no_route() {
    let r = router();
    let a = addrs(ALICE);
    let Route::Reply(reply) = r.route(&pkt(a.ula, "2001:db8::1".parse().unwrap())) else {
        panic!();
    };
    assert_eq!(&reply[packet::HEADER_LEN..][..2], &[1, 0]);
}

#[test]
fn errors_are_not_answered_with_errors() {
    let r = router();
    let a = addrs(ALICE);
    let stranger: Ipv6Addr = "fdef:813d:8791:0:1:2:3:4".parse().unwrap();
    let err = packet::build_icmpv6(&a.ula, &stranger, 1, 3, &[0; 4], 64);
    assert_eq!(r.route(&err), Route::Drop);
    let from_unspecified = pkt(Ipv6Addr::UNSPECIFIED, stranger);
    assert_eq!(r.route(&from_unspecified), Route::Drop);
}

#[test]
fn malformed_packets_are_dropped() {
    let r = router();
    assert_eq!(r.route(&[]), Route::Drop);
    assert_eq!(r.route(&[0x45; 60]), Route::Drop);
    let p = pkt(addrs(ALICE).ula, addrs(BOB).ula);
    assert_eq!(r.route(&p[..p.len() - 3]), Route::Drop);
}

#[test]
fn packets_to_own_addresses_are_looped_back() {
    let r = router();
    let a = addrs(ALICE);
    let p = pkt(a.ula, a.ula);
    assert_eq!(r.route(&p), Route::Reply(p.clone()));
}

#[test]
fn link_local_multicast_goes_to_live_peers() {
    let mut r = router();
    let a = addrs(ALICE);
    let mdns: Ipv6Addr = "ff02::fb".parse().unwrap();
    assert_eq!(r.route(&pkt(a.link_local, mdns)), Route::Drop);
    r.set_live(key(BOB), true);
    assert_eq!(
        r.route(&pkt(a.link_local, mdns)),
        Route::Multicast(vec![key(BOB)])
    );
    r.set_live(key(BOB), false);
    assert_eq!(r.route(&pkt(a.link_local, mdns)), Route::Drop);
}

#[test]
fn wider_scopes_are_not_forwarded() {
    let mut r = router();
    r.set_live(key(BOB), true);
    let a = addrs(ALICE);
    for dst in ["ff05::fb", "ff0e::1", "ff01::1"] {
        assert_eq!(
            r.route(&pkt(a.ula, dst.parse().unwrap())),
            Route::Drop,
            "{dst}"
        );
    }
}

#[test]
fn neighbour_discovery_and_mld_never_leave() {
    let mut r = router();
    r.set_live(key(BOB), true);
    let a = addrs(ALICE);
    for (kind, dst) in [
        (133u8, "ff02::2"),
        (135, "ff02::1:ff00:1"),
        (130, "ff02::1"),
        (131, "ff02::2"),
        (143, "ff02::16"),
    ] {
        let p = packet::build_icmpv6(&a.link_local, &dst.parse().unwrap(), kind, 0, &[0; 20], 255);
        assert_eq!(r.route(&p), Route::Drop, "type {kind}");
    }
    let mut hbh = vec![packet::ICMPV6, 0, 5, 2, 0, 0, 1, 0, 143, 0, 0, 0];
    hbh.extend_from_slice(&[0; 20]);
    let p = packet::build(&a.link_local, &"ff02::16".parse().unwrap(), 0, 1, &hbh);
    assert_eq!(r.route(&p), Route::Drop);
}

#[test]
fn echo_request_to_multicast_is_forwarded() {
    let mut r = router();
    r.set_live(key(BOB), true);
    let a = addrs(ALICE);
    let p = packet::build_icmpv6(
        &a.link_local,
        &"ff02::1".parse().unwrap(),
        128,
        0,
        &[0; 8],
        1,
    );
    assert_eq!(r.route(&p), Route::Multicast(vec![key(BOB)]));
}

#[test]
fn inbound_control_traffic_is_filtered() {
    let mut r = router();
    let (a, b) = (addrs(ALICE), addrs(BOB));
    let bob = key(BOB);
    assert!(accepts(&mut r, &bob, &pkt(b.ula, a.ula)));
    let ns = packet::build_icmpv6(&b.ula, &a.ula, 135, 0, &[0; 20], 255);
    assert!(!accepts(&mut r, &bob, &ns));
    let echo = packet::build_icmpv6(&b.ula, &a.ula, 128, 0, &[0; 8], 64);
    assert!(accepts(&mut r, &bob, &echo));
}

#[test]
fn rejects_colliding_reserved_and_own_peers() {
    let mut r = Router::new(net(), key(ALICE));
    assert_eq!(r.add_peer(key(ALICE)), Err(Rejected::Own));
    assert_eq!(r.add_peer(key(BOB)), Ok(()));
    assert_eq!(r.add_peer(key(BOB)), Ok(()));
}

#[test]
fn synthetic_ndp_answers_for_known_peers() {
    let mut r = Router::new(net(), key(ALICE)).with_synthetic_ndp();
    r.add_peer(key(BOB)).unwrap();
    let (a, b) = (addrs(ALICE), addrs(BOB));
    let ns = ndp::solicitation(a.ula, b.ula);
    let Route::Reply(na) = r.route(&ns) else {
        panic!("expected NA");
    };
    assert_eq!(packet::parse(&na).unwrap().src, b.ula);
    let stranger = ndp::solicitation(a.ula, "fdef:813d:8791:0:1:2:3:4".parse().unwrap());
    assert_eq!(r.route(&stranger), Route::Drop);
    let l3 = Router::new(net(), key(ALICE));
    assert_eq!(l3.route(&ns), Route::Drop);
}

fn chosen(peer: NodePublic) -> Option<Chosen> {
    Some(Chosen { peer, ipv4: None })
}

fn site() -> Site {
    "it/home".parse().unwrap()
}

fn site_addr(of: &str) -> Ipv6Addr {
    site::site_addr(&net(), &site(), &key(of))
}

fn serve(ipv4: bool) -> ExitServe {
    ExitServe { site: site(), ipv4 }
}

fn accepts(r: &mut Router, from: &NodePublic, p: &[u8]) -> bool {
    matches!(r.inbound(from, p), Inbound::Deliver(_))
}

fn outside() -> Ipv6Addr {
    "2001:db8::7".parse().unwrap()
}

#[test]
fn a_peer_may_use_its_own_overlay_addresses_and_no_other() {
    let mut r = router();
    r.add_peer(key(CAROL)).unwrap();
    let (a, b, c) = (addrs(ALICE), addrs(BOB), addrs(CAROL));
    let bob = key(BOB);
    assert!(accepts(&mut r, &bob, &pkt(b.ula, a.ula)));
    assert!(accepts(&mut r, &bob, &pkt(b.link_local, a.link_local)));
    assert!(
        !accepts(&mut r, &bob, &pkt(c.ula, a.ula)),
        "another peer's address"
    );
    assert!(!accepts(&mut r, &bob, &pkt(c.link_local, a.ula)));
    assert!(
        !accepts(&mut r, &bob, &pkt(a.ula, a.ula)),
        "this node's own address"
    );
    assert!(
        !accepts(&mut r, &bob, &pkt(outside(), a.ula)),
        "an outside address"
    );
    assert!(!accepts(&mut r, &bob, &pkt(Ipv6Addr::UNSPECIFIED, a.ula)));
    assert!(
        !accepts(&mut r, &bob, &pkt(site_addr(BOB), a.ula)),
        "a site address, unserved"
    );
}

#[test]
fn the_chosen_exit_may_send_anything_to_this_nodes_address_in_its_site() {
    let mut r = router();
    r.add_peer(key(CAROL)).unwrap();
    let (a, bob) = (addrs(ALICE), key(BOB));
    let mine = site_addr(ALICE);
    let from_internet = pkt(outside(), mine);
    assert!(!accepts(&mut r, &bob, &from_internet), "no exit in use");

    r.set_exit_use(Some(ExitUse::default()));
    r.set_exit_peer(site(), chosen(bob));
    assert!(accepts(&mut r, &bob, &from_internet));
    assert!(
        !accepts(&mut r, &bob, &pkt(outside(), a.ula)),
        "not for the site address: the overlay address needs an overlay source"
    );
    assert!(!accepts(&mut r, &bob, &pkt(outside(), site_addr(BOB))));
    assert!(
        !accepts(&mut r, &key(CAROL), &from_internet),
        "not the chosen exit"
    );

    r.set_exit_peer(site(), chosen(key(CAROL)));
    assert!(!accepts(&mut r, &bob, &from_internet), "no longer chosen");
    assert!(accepts(&mut r, &key(CAROL), &from_internet));

    r.set_exit_peer(site(), None);
    assert!(
        !accepts(&mut r, &key(CAROL), &from_internet),
        "the site has no exit"
    );
}

#[test]
fn only_the_site_in_use_counts() {
    let mut r = router();
    let bob = key(BOB);
    let de: Site = "de".parse().unwrap();
    r.set_exit_peer(site(), chosen(bob));
    r.set_exit_peer(de.clone(), chosen(key(CAROL)));
    let in_home = pkt(outside(), site_addr(ALICE));
    let in_de = pkt(outside(), site::site_addr(&net(), &de, &key(ALICE)));

    r.set_exit_use(Some(ExitUse::default()));
    assert!(
        !accepts(&mut r, &bob, &in_home),
        "two sites and none picked"
    );
    assert_eq!(r.exit_in_use(), None);

    r.set_exit_use(Some(ExitUse { site: Some(site()) }));
    assert!(accepts(&mut r, &bob, &in_home));
    assert!(
        !accepts(&mut r, &key(CAROL), &in_de),
        "a site that is not in use"
    );
    assert_eq!(
        r.exit_in_use().map(|(s, k)| (s.clone(), k)),
        Some((site(), bob))
    );

    r.set_exit_use(None);
    assert!(!accepts(&mut r, &bob, &in_home));
}

#[test]
fn the_only_site_is_used_when_none_is_picked() {
    let mut r = router();
    r.set_exit_use(Some(ExitUse::default()));
    r.set_exit_peer(site(), chosen(key(BOB)));
    assert_eq!(r.exit_in_use().map(|(_, k)| k), Some(key(BOB)));
    r.set_exit_peer("de".parse().unwrap(), chosen(key(CAROL)));
    assert_eq!(r.exit_in_use(), None);
}

#[test]
fn a_second_site_whose_exits_are_down_is_not_left_out_of_the_only_site() {
    let mut r = router();
    r.set_exit_use(Some(ExitUse::default()));
    r.set_known_sites([site()]);
    r.set_exit_peer(site(), chosen(key(BOB)));
    assert_eq!(r.exit_in_use().map(|(_, k)| k), Some(key(BOB)));
    let de: Site = "de".parse().unwrap();
    r.set_known_sites([de.clone(), site()]);
    assert_eq!(r.exit_in_use(), None, "the second site is remembered, down");
    r.set_known_sites([site()]);
    assert_eq!(r.exit_in_use().map(|(_, k)| k), Some(key(BOB)));
}

#[test]
fn a_served_site_takes_its_peers_addresses_in_the_site_prefix() {
    let mut r = router();
    r.add_peer(key(CAROL)).unwrap();
    let (a, bob) = (addrs(ALICE), key(BOB));
    let from_bob = pkt(site_addr(BOB), outside());
    assert!(!accepts(&mut r, &bob, &from_bob), "not serving");

    r.set_serving(Some(serve(true)));
    assert!(!accepts(&mut r, &bob, &from_bob), "a peer not held by key");

    r.set_keyed(bob);
    r.set_keyed(key(CAROL));
    assert!(accepts(&mut r, &bob, &from_bob));
    assert!(accepts(&mut r, &bob, &pkt(site_addr(BOB), a.ula)));
    assert!(
        !accepts(&mut r, &bob, &pkt(site_addr(CAROL), outside())),
        "another peer's address in the site"
    );
    assert!(!accepts(&mut r, &bob, &pkt(addrs(CAROL).ula, outside())));
    let other = site::site_addr(&net(), &"de".parse().unwrap(), &bob);
    assert!(
        !accepts(&mut r, &bob, &pkt(other, outside())),
        "a site that is not served"
    );
    assert!(
        !accepts(&mut r, &bob, &pkt(site_addr(ALICE), outside())),
        "this node's own address"
    );
    let ns = packet::build_icmpv6(&site_addr(BOB), &a.ula, 135, 0, &[0; 20], 255);
    assert!(
        !accepts(&mut r, &bob, &ns),
        "neighbour discovery never crosses"
    );

    r.set_serving(None);
    assert!(!accepts(&mut r, &bob, &from_bob));
}

fn no_route(r: &Router, p: &[u8]) -> bool {
    matches!(r.route(p), Route::Reply(reply) if reply[packet::HEADER_LEN..][..2] == [1, 0])
}

#[test]
fn a_destination_outside_the_overlay_goes_to_the_exit_in_use() {
    let mut r = router();
    let a = addrs(ALICE);
    let web = pkt(site_addr(ALICE), outside());
    assert!(no_route(&r, &web), "no exit use");

    r.set_exit_use(Some(ExitUse::default()));
    assert!(no_route(&r, &web), "no exit chosen");

    r.set_exit_peer(site(), chosen(key(BOB)));
    assert_eq!(r.route(&web), Route::Unicast(key(BOB)));
    assert_eq!(
        r.route(&pkt(a.ula, "2606:4700::1111".parse().unwrap())),
        Route::Unicast(key(BOB))
    );

    r.set_exit_peer(site(), None);
    assert!(no_route(&r, &web), "the exit is gone");
}

#[test]
fn what_the_exit_cannot_carry_has_no_route_and_the_overlay_is_unchanged() {
    let mut r = router();
    r.set_exit_use(Some(ExitUse::default()));
    r.set_exit_peer(site(), chosen(key(BOB)));
    let (a, b) = (addrs(ALICE), addrs(BOB));
    for dst in ["::1", "::", "fe80::1:2:3:4", "febf::1"] {
        let dst: Ipv6Addr = dst.parse().unwrap();
        assert_ne!(r.route(&pkt(a.ula, dst)), Route::Unicast(key(BOB)), "{dst}");
    }
    assert_eq!(r.route(&pkt(a.ula, b.ula)), Route::Unicast(key(BOB)));
    let stranger: Ipv6Addr = "fdef:813d:8791:0:1:2:3:4".parse().unwrap();
    let Route::Reply(reply) = r.route(&pkt(a.ula, stranger)) else {
        panic!();
    };
    assert_eq!(
        &reply[packet::HEADER_LEN..][..2],
        &[1, 3],
        "an unknown overlay address"
    );
    let elsewhere: Ipv6Addr = "fdef:813d:8791:5::7".parse().unwrap();
    let Route::Reply(reply) = r.route(&pkt(a.ula, elsewhere)) else {
        panic!();
    };
    assert_eq!(
        &reply[packet::HEADER_LEN..][..2],
        &[1, 3],
        "inside the /48, outside the /64"
    );
    let mdns: Ipv6Addr = "ff02::fb".parse().unwrap();
    assert_eq!(
        r.route(&pkt(a.link_local, mdns)),
        Route::Drop,
        "multicast stays out"
    );
}

#[test]
fn a_packet_to_this_nodes_address_in_the_site_in_use_is_looped_back() {
    let mut r = router();
    r.set_exit_use(Some(ExitUse::default()));
    r.set_exit_peer(site(), chosen(key(BOB)));
    let p = pkt(site_addr(ALICE), site_addr(ALICE));
    assert_eq!(r.route(&p), Route::Reply(p.clone()));
}

#[test]
fn a_served_site_routes_to_its_peers_by_their_interface_identifiers() {
    let mut r = router();
    r.add_peer(key(CAROL)).unwrap();
    let to_bob = pkt(outside(), site_addr(BOB));
    let Route::Reply(reply) = r.route(&to_bob) else {
        panic!();
    };
    assert_eq!(&reply[packet::HEADER_LEN..][..2], &[1, 3], "not serving");

    r.set_serving(Some(serve(true)));
    r.set_keyed(key(BOB));
    assert_eq!(r.route(&to_bob), Route::Unicast(key(BOB)));
    assert!(
        matches!(r.route(&pkt(outside(), site_addr(CAROL))), Route::Reply(_)),
        "a peer not held by key"
    );
    let other = site::site_addr(&net(), &"de".parse().unwrap(), &key(BOB));
    assert!(matches!(r.route(&pkt(outside(), other)), Route::Reply(_)));
    let nobody = site::site_addr(&net(), &site(), &NodePublic::from_bytes([9; 32]));
    assert!(matches!(r.route(&pkt(outside(), nobody)), Route::Reply(_)));
}

fn serving(ipv4: bool) -> Router {
    let mut r = router();
    r.add_peer(key(CAROL)).unwrap();
    r.set_keyed(key(BOB));
    r.set_keyed(key(CAROL));
    r.set_serving(Some(serve(ipv4)));
    r.set_exit_client(key(BOB), Some(bob4()));
    r.set_exit_client(key(CAROL), Some(carol4()));
    r
}

fn echo(src: Ipv6Addr, dst: Ipv6Addr, hop: u8) -> Vec<u8> {
    packet::build_icmpv6(&src, &dst, 128, 0, &[0, 1, 0, 1], hop)
}

fn bob4() -> Ipv4Addr {
    Ipv4Addr::new(198, 18, 4, 2)
}

fn carol4() -> Ipv4Addr {
    Ipv4Addr::new(198, 18, 4, 3)
}

fn google() -> Ipv4Addr {
    Ipv4Addr::new(8, 8, 8, 8)
}

/// A UDP datagram over IPv4, with a valid header checksum.
fn v4(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 17, 0, 0];
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&[0x13, 0x88, 0, 53, 0, 8, 0, 0]);
    p
}

fn prohibited_v4(r: &mut Router, from: &NodePublic, p: &[u8]) -> bool {
    let Inbound::Return(reply) = r.inbound(from, p) else {
        return false;
    };
    packet::v4::addrs(&reply).map(|(s, _)| s) == Some(EXIT_IPV4)
        && reply[packet::v4::HEADER_LEN..][..2] == [3, 13]
}

#[test]
fn ipv4_from_the_address_the_exit_gave_goes_to_that_exit_as_it_is() {
    let mut r = router();
    let mine = Ipv4Addr::new(198, 18, 7, 7);
    let p = v4(mine, google());
    assert_eq!(r.route(&p), Route::Drop, "no exit use");
    r.set_exit_use(Some(ExitUse::default()));
    r.set_exit_peer(
        site(),
        Some(Chosen {
            peer: key(BOB),
            ipv4: Some(mine),
        }),
    );
    assert_eq!(r.route(&p), Route::Unicast(key(BOB)));
    assert_eq!(
        r.route(&v4(Ipv4Addr::new(198, 18, 7, 8), google())),
        Route::Drop,
        "another source"
    );
    r.set_exit_peer(site(), chosen(key(BOB)));
    assert_eq!(r.route(&p), Route::Drop, "an exit without IPv4");
    r.set_exit_peer(site(), None);
    assert_eq!(r.route(&p), Route::Drop, "no live exit");
}

#[test]
fn ipv4_from_the_exit_in_use_is_delivered_only_to_the_address_it_gave() {
    let mut r = router();
    r.add_peer(key(CAROL)).unwrap();
    let mine = Ipv4Addr::new(198, 18, 7, 7);
    let from_web = v4(google(), mine);
    assert!(!accepts(&mut r, &key(BOB), &from_web), "no exit in use");
    r.set_exit_use(Some(ExitUse::default()));
    r.set_exit_peer(
        site(),
        Some(Chosen {
            peer: key(BOB),
            ipv4: Some(mine),
        }),
    );
    assert!(accepts(&mut r, &key(BOB), &from_web));
    assert!(!accepts(&mut r, &key(CAROL), &from_web), "not the exit");
    assert!(!accepts(
        &mut r,
        &key(BOB),
        &v4(google(), Ipv4Addr::new(198, 18, 7, 8))
    ));
}

#[test]
fn the_exit_delivers_ipv4_from_a_client_s_own_address_to_the_host_unchanged() {
    let mut r = serving(true);
    let p = v4(bob4(), google());
    assert_eq!(r.inbound(&key(BOB), &p), Inbound::Deliver(p.clone()));
    assert!(
        !accepts(&mut r, &key(BOB), &v4(carol4(), google())),
        "another client's address"
    );
    assert!(!accepts(
        &mut r,
        &key(BOB),
        &v4(Ipv4Addr::new(198, 18, 9, 9), google())
    ));
    r.set_exit_client(key(BOB), None);
    assert!(!accepts(&mut r, &key(BOB), &p), "freed");
    let mut off = serving(false);
    assert!(!accepts(&mut off, &key(BOB), &p), "an exit without IPv4");
}

#[test]
fn ipv4_from_the_host_to_a_client_address_goes_to_that_client() {
    let mut r = serving(true);
    assert_eq!(r.route(&v4(google(), bob4())), Route::Unicast(key(BOB)));
    assert_eq!(r.route(&v4(google(), carol4())), Route::Unicast(key(CAROL)));
    assert_eq!(
        r.route(&v4(google(), Ipv4Addr::new(198, 18, 9, 9))),
        Route::Drop
    );
    r.remove_peer(&key(CAROL));
    assert_eq!(r.route(&v4(google(), carol4())), Route::Drop);
}

#[test]
fn refused_ipv4_destinations_are_answered_with_administratively_prohibited() {
    let mut r = serving(true);
    for dst in [
        Ipv4Addr::new(10, 1, 2, 3),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(172, 31, 255, 254),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(169, 254, 9, 9),
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(0, 1, 2, 3),
        EXIT_IPV4,
        carol4(),
        Ipv4Addr::new(224, 0, 0, 251),
        Ipv4Addr::new(255, 255, 255, 255),
    ] {
        assert!(prohibited_v4(&mut r, &key(BOB), &v4(bob4(), dst)), "{dst}");
    }
    for dst in [
        Ipv4Addr::new(172, 15, 0, 1),
        Ipv4Addr::new(172, 32, 0, 1),
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(192, 169, 0, 1),
        Ipv4Addr::new(198, 20, 0, 1),
        google(),
    ] {
        assert!(accepts(&mut r, &key(BOB), &v4(bob4(), dst)), "{dst}");
    }
}

fn refused_with_code_1(r: &mut Router, p: &[u8]) -> bool {
    let Inbound::Return(reply) = r.inbound(&key(BOB), p) else {
        return false;
    };
    reply[packet::HEADER_LEN..][..2] == [1, 1]
}

#[test]
fn unique_local_and_link_local_ipv6_outside_the_overlay_are_refused() {
    let from = site_addr(BOB);
    let mut r = serving(true);
    for dst in ["fd12:3456::1", "fc00::1", "fe80:0:0:1::5"] {
        let dst: Ipv6Addr = dst.parse().unwrap();
        assert!(refused_with_code_1(&mut r, &echo(from, dst, 64)), "{dst}");
    }
    assert!(accepts(&mut r, &key(BOB), &echo(from, outside(), 64)));
}

#[test]
fn the_overlay_is_not_private_to_the_exit() {
    let mut r = serving(true);
    let bob = key(BOB);
    let from = site_addr(BOB);
    assert!(accepts(&mut r, &bob, &echo(from, addrs(ALICE).ula, 64)));
    assert!(accepts(&mut r, &bob, &echo(from, site_addr(CAROL), 64)));
    assert!(accepts(
        &mut r,
        &bob,
        &echo(addrs(BOB).ula, addrs(ALICE).ula, 64)
    ));
}

#[test]
fn with_no_ipv6_uplink_a_global_destination_has_no_route_and_the_rest_is_unchanged() {
    let mut r = serving(true);
    let (bob, from) = (key(BOB), site_addr(BOB));
    let a = addrs(ALICE);
    let google6: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
    assert!(r.ipv6_uplink(), "on by default");
    assert!(accepts(&mut r, &bob, &echo(from, google6, 64)));

    r.set_ipv6_uplink(false);
    let packet = echo(from, google6, 64);
    let Inbound::Return(reply) = r.inbound(&bob, &packet) else {
        panic!("no route is answered");
    };
    let h = packet::parse(&reply).unwrap();
    assert_eq!((h.src, h.dst), (a.ula, from));
    assert_eq!(&reply[packet::HEADER_LEN..][..2], &[1, 0]);
    assert_eq!(&reply[packet::HEADER_LEN + 8..], &packet[..]);

    assert!(accepts(&mut r, &bob, &echo(from, a.ula, 64)), "overlay");
    assert!(accepts(&mut r, &bob, &echo(from, site_addr(CAROL), 64)));
    assert!(refused_with_code_1(
        &mut r,
        &echo(from, "fd12:3456::1".parse().unwrap(), 64)
    ));
    assert!(
        accepts(&mut r, &bob, &v4(bob4(), google())),
        "IPv4 is unaffected"
    );

    r.set_serving(Some(serve(true)));
    assert!(!accepts(&mut r, &bob, &echo(from, google6, 64)), "kept");
    r.set_ipv6_uplink(true);
    assert!(accepts(&mut r, &bob, &echo(from, google6, 64)));
}
