//! The exit offer in the handshake.

mod common;

use std::net::Ipv4Addr;
use std::time::Duration;

use common::sim::*;
use vardevall_proto::handshake::payload::{
    self, Hello, MAX_PAYLOAD_1, MAX_PAYLOAD_2, PADDED_PAYLOAD_1, REPLY_PAYLOAD_2, decode_msg1,
    decode_msg2, encode_msg1, encode_msg2,
};
use vardevall_proto::ip::exit::{ExitOffer, ExitServe, MAX_OFFER_LEN, home_ipv4};
use vardevall_proto::node::Trust;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn offer(site: &str) -> ExitOffer {
    ExitOffer {
        site: site.parse().unwrap(),
        ipv4: None,
    }
}

fn serve(site: &str) -> ExitServe {
    ExitServe {
        site: site.parse().unwrap(),
        ipv4: true,
    }
}

/// The offer node `by` heard from the other, without the address it carries.
fn heard(p: &Pair, by: usize) -> Option<ExitOffer> {
    heard_with_ipv4(p, by).map(|o| ExitOffer { ipv4: None, ..o })
}

fn heard_with_ipv4(p: &Pair, by: usize) -> Option<ExitOffer> {
    let other = p.nodes[1 - by].public();
    p.nodes[by].node.peer_view(&other).unwrap().exit
}

fn connect(p: &mut Pair) {
    let pkt = ipv6(p.nodes[0].ula(), p.nodes[1].ula(), &[1; 20]);
    p.send(0, &pkt);
    p.pump();
}

#[test]
fn the_offer_is_the_exit_member_of_the_payload() {
    let hello = Hello {
        candidates: Vec::new(),
        exit: Some(offer("it/home")),
    };
    let bytes = encode_msg1(5, &hello, MAX_PAYLOAD_1);
    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        r#"{"ts":"5","exit":{"site":"it/home"}}"#
    );
    assert_eq!(decode_msg1(&bytes).unwrap(), (5, hello.clone()));
    let bytes = encode_msg2(&hello, MAX_PAYLOAD_2);
    assert_eq!(decode_msg2(&bytes).unwrap(), hello);
}

#[test]
fn an_offer_that_does_not_parse_is_no_offer() {
    for exit in [
        r#"{"site":"italy"}"#,
        r#"{"site":"it/home","ipv4":"10.0.0.2"}"#,
        r#"{"site":"it/home","ipv4":"198.18.0.1"}"#,
        r#"{"site":"it/home","ipv4":7}"#,
        r#"{"ipv4":"198.18.0.2"}"#,
        r#""it/home""#,
        "7",
    ] {
        let body = format!(r#"{{"ts":"1","exit":{exit}}}"#);
        let (ts, hello) = decode_msg1(body.as_bytes()).expect(exit);
        assert_eq!((ts, hello.exit), (1, None), "{exit}");
    }
}

fn largest_offer() -> ExitOffer {
    ExitOffer {
        site: format!("de/{}", "a".repeat(31)).parse().unwrap(),
        ipv4: Some(Ipv4Addr::new(198, 19, 255, 254)),
    }
}

#[test]
fn the_largest_offers_fit_the_payload_limits() {
    let big = largest_offer();
    assert!(big.encoded_len() <= MAX_OFFER_LEN, "{}", big.encoded_len());
    let hello = Hello {
        candidates: Vec::new(),
        exit: Some(big.clone()),
    };
    let one = encode_msg1(u64::MAX, &hello, MAX_PAYLOAD_1);
    assert!(one.len() <= MAX_PAYLOAD_1, "{}", one.len());
    assert_eq!(decode_msg1(&one).unwrap().1.exit, Some(big.clone()));
    let two = encode_msg2(&hello, REPLY_PAYLOAD_2);
    assert!(two.len() <= REPLY_PAYLOAD_2, "{}", two.len());
    assert_eq!(decode_msg2(&two).unwrap().exit, Some(big));
}

#[test]
fn a_reply_to_a_padded_message_1_is_300_bytes() {
    assert_eq!(PADDED_PAYLOAD_1, 256);
    assert_eq!(REPLY_PAYLOAD_2, 300);
}

#[test]
fn candidates_give_way_to_the_offer() {
    let cands = vec![
        vardevall_proto::discovery::candidate::Candidate::relay(
            "[2001:db8:1234:5678:9abc:def0:1234:5678]:51820"
                .parse()
                .unwrap(),
        );
        8
    ];
    let hello = Hello {
        candidates: cands,
        exit: Some(offer("it/home")),
    };
    let (bytes, carried) = payload::encode_msg1_counted(u64::MAX, &hello, MAX_PAYLOAD_1);
    assert!(bytes.len() <= MAX_PAYLOAD_1);
    assert!(carried < 8);
    assert!(decode_msg1(&bytes).unwrap().1.exit.is_some());
    let tight = encode_msg2(&hello, 20);
    assert_eq!(tight, b"{}", "an offer that cannot fit is left out");
}

#[test]
fn both_ends_hear_the_offer_of_the_other_with_their_own_address() {
    let mut p = Pair::bare(
        |c| c.exit = Some(serve("it/home")),
        |c| c.exit = Some(serve("de")),
    );
    p.know_each_other();
    connect(&mut p);
    let net = *p.nodes[0].node.network_id();
    let home = |n: usize| Some(home_ipv4(&net, &p.nodes[n].public()));
    let to = |n: usize, site: &str| ExitOffer {
        ipv4: home(n),
        ..offer(site)
    };
    assert_eq!(
        heard_with_ipv4(&p, 1),
        Some(to(1, "it/home")),
        "from message 1"
    );
    assert_eq!(heard_with_ipv4(&p, 0), Some(to(0, "de")), "from message 2");
    assert_eq!(
        p.nodes[0].node.exit_client_ipv4(&p.nodes[1].public()),
        home(1)
    );
}

#[test]
fn an_exit_without_ipv4_offers_no_address() {
    let mut p = Pair::bare(
        |_| {},
        |c| {
            c.exit = Some(ExitServe {
                ipv4: false,
                ..serve("it/home")
            })
        },
    );
    p.know_each_other();
    connect(&mut p);
    assert_eq!(heard_with_ipv4(&p, 0), Some(offer("it/home")));
    assert_eq!(p.nodes[1].node.exit_client_ipv4(&p.nodes[0].public()), None);
}

#[test]
fn no_offer_is_sent_to_a_member_and_none_is_kept_from_one() {
    let mut p = Pair::bare(
        |c| c.exit = Some(serve("it/home")),
        |c| {
            c.exit = Some(serve("de"));
            c.accept_members = true;
        },
    );
    let a = p.nodes[0].public();
    p.nodes[1].node.remove_peer(&a);
    p.know_each_other();
    connect(&mut p);
    let view = p.nodes[1].node.peer_view(&a).unwrap();
    assert_eq!(view.trust, Trust::Member);
    assert_eq!(
        view.exit, None,
        "the offer of a member is dropped on receipt"
    );
    assert_eq!(heard(&p, 0), None, "a member is never offered one");
}

#[test]
fn a_malformed_offer_does_not_fail_the_handshake() {
    let hello = br#"{"ts":"1","exit":{"site":"!!"}}"#;
    assert!(decode_msg1(hello).is_ok());
    assert!(decode_msg2(br#"{"exit":[]}"#).is_ok());
}

#[test]
fn a_rekey_updates_and_clears_the_offer() {
    let mut p = Pair::bare(|_| {}, |c| c.exit = Some(serve("it/home")));
    p.know_each_other();
    connect(&mut p);
    assert_eq!(heard(&p, 0), Some(offer("it/home")));

    let now = p.now;
    let b = &mut p.nodes[1];
    b.node.set_exit(now, &mut b.rng, Some(serve("it/work")));
    p.advance(secs(125));
    assert_eq!(
        heard(&p, 0),
        Some(offer("it/home")),
        "until the next handshake"
    );
    let pkt = ipv6(p.nodes[0].ula(), p.nodes[1].ula(), &[2; 20]);
    p.send(0, &pkt);
    p.pump();
    assert_eq!(heard(&p, 0), Some(offer("it/work")));

    let now = p.now;
    let b = &mut p.nodes[1];
    b.node.set_exit(now, &mut b.rng, None);
    p.advance(secs(125));
    let pkt = ipv6(p.nodes[0].ula(), p.nodes[1].ula(), &[3; 20]);
    p.send(0, &pkt);
    p.pump();
    assert_eq!(heard(&p, 0), None);
}

#[test]
fn the_link_going_down_keeps_the_offer_until_a_handshake_carries_none() {
    let mut p = Pair::bare(|_| {}, |c| c.exit = Some(serve("it/home")));
    p.know_each_other();
    connect(&mut p);
    assert!(heard(&p, 0).is_some());
    p.advance_with(secs(200), |_| false);
    let b = p.nodes[1].public();
    let link = p.nodes[0].node.peer_view(&b).unwrap().link;
    assert!(
        !matches!(link, vardevall_proto::node::PeerState::Up { .. }),
        "{link:?}"
    );
    assert_eq!(heard(&p, 0), Some(offer("it/home")), "remembered");

    let now = p.now;
    let n = &mut p.nodes[1];
    n.node.set_exit(now, &mut n.rng, None);
    connect(&mut p);
    p.advance(secs(20));
    assert_eq!(heard(&p, 0), None, "the new handshake carried none");
}

#[test]
fn a_client_with_no_candidates_receives_the_largest_allowed_offer() {
    let big = largest_offer();
    let mut p = Pair::bare(
        |_| {},
        |c| {
            c.exit = Some(ExitServe {
                site: big.site.clone(),
                ipv4: true,
            })
        },
    );
    p.know_each_other();
    connect(&mut p);
    assert_eq!(heard(&p, 0).map(|o| o.site), Some(big.site));
    assert!(heard_with_ipv4(&p, 0).unwrap().ipv4.is_some());
}

#[test]
fn a_message_1_to_a_peer_held_by_key_is_padded_to_256_bytes() {
    let mut p = Pair::bare(|_| {}, |_| {});
    p.know_each_other();
    let pkt = ipv6(p.nodes[0].ula(), p.nodes[1].ula(), &[1; 20]);
    p.send(0, &pkt);
    let first: usize = p
        .collect()
        .iter()
        .filter(|w| w.from == 0)
        .map(|w| w.data.len())
        .sum();
    let bare = vardevall_proto::handshake::message::MIN_MESSAGE1 + 10;
    assert!(
        first >= bare + PADDED_PAYLOAD_1 - 10,
        "message 1 is {first} bytes, an unpadded one {bare}"
    );
}

fn site() -> vardevall_proto::ip::site::Site {
    "it/home".parse().unwrap()
}

fn site_addr_of(p: &Pair, node: usize) -> std::net::Ipv6Addr {
    vardevall_proto::ip::site::site_addr(
        p.nodes[0].node.network_id(),
        &site(),
        &p.nodes[node].public(),
    )
}

fn outside() -> std::net::Ipv6Addr {
    "2001:db8::9".parse().unwrap()
}

/// Sends `packet` from node `from` and returns how many packets the other one delivered.
fn delivered(p: &mut Pair, from: usize, packet: &[u8]) -> usize {
    let before = p.nodes[1 - from].packets().len();
    p.send(from, packet);
    p.pump();
    p.nodes[1 - from].packets().len() - before
}

#[test]
fn a_source_outside_the_overlay_is_delivered_only_in_the_cases_of_the_exit_rules() {
    let mut p = Pair::bare(|_| {}, |c| c.exit = Some(serve("it/home")));
    p.know_each_other();
    connect(&mut p);
    let (client_site, exit_site) = (site_addr_of(&p, 0), site_addr_of(&p, 1));
    let (client, exit) = (p.nodes[0].ula(), p.nodes[1].ula());

    assert_eq!(
        delivered(&mut p, 0, &ipv6(client, exit, &[1])),
        1,
        "an overlay source"
    );
    assert_eq!(
        delivered(&mut p, 0, &ipv6(client_site, outside(), &[2])),
        1,
        "the client's address in the site the exit serves"
    );
    assert_eq!(
        delivered(&mut p, 0, &ipv6(outside(), exit, &[3])),
        0,
        "another source"
    );
    assert_eq!(
        delivered(&mut p, 0, &ipv6(exit_site, outside(), &[4])),
        0,
        "the exit's address in the site"
    );

    assert_eq!(
        delivered(&mut p, 1, &ipv6(outside(), client_site, &[5])),
        1,
        "anything, to the client's address in the exit's site"
    );
    assert_eq!(
        delivered(&mut p, 1, &ipv6(outside(), client, &[6])),
        0,
        "not to its overlay address"
    );
    assert_eq!(delivered(&mut p, 1, &ipv6(outside(), outside(), &[7])), 0);
    assert_eq!(
        delivered(&mut p, 1, &ipv6(exit, client, &[8])),
        1,
        "an overlay source"
    );
}

#[test]
fn ipv4_is_delivered_only_from_the_address_the_exit_gave_or_to_the_one_it_gave_this_node() {
    let mut p = Pair::bare(|_| {}, |c| c.exit = Some(serve("it/home")));
    p.know_each_other();
    connect(&mut p);
    let given = heard_with_ipv4(&p, 0).unwrap().ipv4.unwrap();
    let other = Ipv4Addr::new(198, 18, 9, 9);
    let world = Ipv4Addr::new(1, 1, 1, 1);
    assert_ne!(given, other);
    assert_eq!(
        delivered(&mut p, 0, &ipv4(given, world, &[1])),
        1,
        "from the client's address, to anywhere"
    );
    assert_eq!(
        delivered(&mut p, 0, &ipv4(other, world, &[2])),
        0,
        "from another address"
    );
    assert_eq!(
        delivered(&mut p, 1, &ipv4(world, given, &[3])),
        1,
        "anything, to the client's address"
    );
    assert_eq!(
        delivered(&mut p, 1, &ipv4(world, other, &[4])),
        0,
        "to another address"
    );
}

#[test]
fn nothing_is_delivered_by_the_exit_rules_when_no_offer_was_made() {
    let mut p = Pair::bare(|_| {}, |_| {});
    p.know_each_other();
    connect(&mut p);
    let client_site = site_addr_of(&p, 0);
    let home = home_ipv4(p.nodes[0].node.network_id(), &p.nodes[0].public());
    let world = Ipv4Addr::new(1, 1, 1, 1);
    assert_eq!(delivered(&mut p, 0, &ipv6(client_site, outside(), &[1])), 0);
    assert_eq!(delivered(&mut p, 1, &ipv6(outside(), client_site, &[2])), 0);
    assert_eq!(delivered(&mut p, 0, &ipv4(home, world, &[3])), 0);
    assert_eq!(delivered(&mut p, 1, &ipv4(world, home, &[4])), 0);
}

#[test]
fn a_member_never_uses_the_exit_rules() {
    let mut p = Pair::bare(
        |c| c.exit = Some(serve("it/home")),
        |c| {
            c.exit = Some(serve("it/home"));
            c.accept_members = true;
        },
    );
    let a = p.nodes[0].public();
    p.nodes[1].node.remove_peer(&a);
    p.know_each_other();
    connect(&mut p);
    let client_site = site_addr_of(&p, 0);
    assert_eq!(delivered(&mut p, 0, &ipv6(client_site, outside(), &[1])), 0);
    assert_eq!(delivered(&mut p, 1, &ipv6(outside(), client_site, &[2])), 0);
}
