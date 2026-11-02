//! Queries relayed for an exit, against a fake resolver on loopback.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use simple_dns::rdata::{A, AAAA, RData};
use simple_dns::{CLASS, Name, Packet, PacketFlag, QTYPE, RCODE, ResourceRecord, TYPE};
use tokio::net::UdpSocket;
use vardevall_proto::addr::OverlayAddrs;
use vardevall_proto::keys::NodePublic;

use super::*;
use crate::config::{Config, Context};
use crate::keys;

const A_TTL: u32 = 123;

fn a_record(name: &'static str, ip: Ipv4Addr) -> ResourceRecord<'static> {
    let address = u32::from(ip);
    ResourceRecord::new(
        Name::new(name).unwrap(),
        CLASS::IN,
        A_TTL,
        RData::A(A { address }),
    )
}

fn aaaa_record(name: &'static str, ip: Ipv6Addr) -> ResourceRecord<'static> {
    let address = u128::from(ip);
    ResourceRecord::new(
        Name::new(name).unwrap(),
        CLASS::IN,
        A_TTL,
        RData::AAAA(AAAA { address }),
    )
}

/// A resolver that answers from `zone`, following CNAMEs, and counts nothing else.
async fn upstream(zone: Vec<ResourceRecord<'static>>) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let q = Packet::parse(&buf[..n]).unwrap();
            let question = &q.questions[0];
            let mut reply = Packet::new_reply(q.id());
            reply.questions.push(question.clone().into_owned());
            let mut name = question.qname.to_string();
            for _ in 0..4 {
                let alias = zone
                    .iter()
                    .find(|r| r.name.to_string() == name && matches!(r.rdata, RData::CNAME(_)));
                if let Some(r) = alias {
                    reply.answers.push(r.clone());
                    let RData::CNAME(target) = &r.rdata else {
                        unreachable!()
                    };
                    name = target.0.to_string();
                    continue;
                }
                for r in zone.iter().filter(|r| r.name.to_string() == name) {
                    if QTYPE::TYPE(r.rdata.type_code()) == question.qtype {
                        reply.answers.push(r.clone());
                    }
                }
                break;
            }
            let _ = sock.send_to(&reply.build_bytes_vec().unwrap(), from).await;
        }
    });
    addr
}

struct Rig {
    exit: Responder,
    peer: Ipv6Addr,
    member: Ipv6Addr,
}

fn rig(exit_keys: &str, forward: &str) -> Rig {
    let net = keys::generate_network_secret();
    let (me, peer) = (keys::generate_node_key(), keys::generate_node_key());
    let peer_pub = keys::public_key(&peer).unwrap();
    let text = format!(
        "[interface]\nprivate_key = \"{me}\"\nnetwork_secret = \"{net}\"\nlisten_port = 0\n{forward}\n[exit]\nsite = \"it/home\"\n{exit_keys}\n[[peer]]\npublic_key = \"{peer_pub}\"\n"
    );
    let config = Config::parse(&text, &Context::default()).unwrap();
    let network_id = keys::network_id(&net).unwrap();
    let ula = |k: &str| keys::overlay_addrs(k, &network_id).unwrap().ula;
    let stranger = keys::public_key(&keys::generate_node_key()).unwrap();
    Rig {
        exit: Responder::from_config(&config),
        peer: ula(&peer_pub),
        member: ula(&stranger),
    }
}

fn question(name: &str, qtype: TYPE) -> Vec<u8> {
    let mut p = Packet::new_query(0x4242);
    p.set_flags(PacketFlag::RECURSION_DESIRED);
    p.questions.push(simple_dns::Question::new(
        Name::new(name).unwrap(),
        QTYPE::TYPE(qtype),
        simple_dns::QCLASS::CLASS(CLASS::IN),
        false,
    ));
    p.build_bytes_vec().unwrap()
}

fn relayed(reply: Reply) -> Relay {
    match reply {
        Reply::Relay(r) => r,
        other => panic!("{other:?}"),
    }
}

/// The response of the fake resolver to a relayed query.
async fn ask_through(upstream: SocketAddr, relay: Relay) -> Vec<u8> {
    let f = Forwarder::new(vec![upstream], tokio::runtime::Handle::current());
    let (tx, rx) = tokio::sync::oneshot::channel();
    assert!(f.relay(relay, move |r| {
        let _ = tx.send(r);
    }));
    tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("timed out")
        .unwrap()
}

fn addrs6(p: &Packet<'_>) -> Vec<(Ipv6Addr, u32)> {
    p.answers
        .iter()
        .filter_map(|r| match &r.rdata {
            RData::AAAA(a) => Some((Ipv6Addr::from(a.address), r.ttl)),
            _ => None,
        })
        .collect()
}

const WEB: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);

#[tokio::test]
async fn an_exits_relay_passes_on_what_the_upstream_answers() {
    let r = rig("", "");
    let real: Ipv6Addr = "2001:db8::80".parse().unwrap();
    let up = upstream(vec![
        a_record("both.example", WEB),
        aaaa_record("both.example", real),
        a_record("v4only.example", WEB),
    ])
    .await;
    let ask = |name: &str, qtype| {
        let relay = relayed(r.exit.respond_from(&question(name, qtype), Some(&r.peer)));
        assert_eq!(relay.via, None);
        ask_through(up, relay)
    };
    let bytes = ask("both.example", TYPE::AAAA).await;
    let p = Packet::parse(&bytes).unwrap();
    assert_eq!(addrs6(&p), [(real, A_TTL)]);
    assert_eq!((p.id(), p.questions.len()), (0x4242, 1));
    let bytes = ask("v4only.example", TYPE::AAAA).await;
    let p = Packet::parse(&bytes).unwrap();
    assert_eq!(
        (p.rcode(), p.answers.len()),
        (RCODE::NoError, 0),
        "nothing synthesised"
    );
    let bytes = ask("both.example", TYPE::A).await;
    let p = Packet::parse(&bytes).unwrap();
    assert!(matches!(p.answers[..], [ref a] if matches!(a.rdata, RData::A(_))));
}

#[test]
fn only_peers_held_by_key_are_relayed_for_and_only_outside_the_overlay_domains() {
    let r = rig("", "");
    let outside = question("example.com", TYPE::A);
    assert!(matches!(
        r.exit.respond_from(&outside, Some(&r.peer)),
        Reply::Relay(_)
    ));
    assert!(
        matches!(
            r.exit.respond_from(&outside, Some(&r.member)),
            Reply::Answer(_)
        ),
        "a member that is not held by key is refused"
    );
    let outsider: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert!(matches!(
        r.exit.respond_from(&outside, Some(&outsider)),
        Reply::Answer(_)
    ));
    assert!(matches!(
        r.exit.respond_from(&outside, None),
        Reply::Answer(_)
    ));
    assert!(matches!(r.exit.respond(&outside), Reply::Answer(_)));

    let own = question("whatever.vardevall.internal", TYPE::AAAA);
    assert!(matches!(
        r.exit.respond_from(&own, Some(&r.peer)),
        Reply::Answer(_)
    ));
    let reverse = question(
        &format!(
            "1.{}",
            vardevall_proto::addr::reverse_zone(&r.exit.network_id)
        ),
        TYPE::PTR,
    );
    assert!(!matches!(
        r.exit.respond_from(&reverse, Some(&r.peer)),
        Reply::Relay(_)
    ));
    assert!(matches!(
        r.exit.respond_from(&[0; 5], Some(&r.peer)),
        Reply::Drop | Reply::Answer(_)
    ));
}

#[test]
fn a_node_that_serves_nothing_relays_nothing_for_peers() {
    let plain = {
        let net = keys::generate_network_secret();
        let me = keys::generate_node_key();
        let text = format!(
            "[interface]\nprivate_key = \"{me}\"\nnetwork_secret = \"{net}\"\nlisten_port = 0\n"
        );
        Responder::from_config(&Config::parse(&text, &Context::default()).unwrap())
    };
    let any = OverlayAddrs::derive(&plain.network_id, &NodePublic::from_bytes([3; 32])).ula;
    assert!(matches!(
        plain.respond_from(&question("example.com", TYPE::A), Some(&any)),
        Reply::Answer(_)
    ));
}

#[test]
fn a_client_with_an_exit_in_use_relays_to_its_resolver_unless_the_file_has_forward() {
    let r = rig("", "");
    let client = &r.exit;
    let exit = NodePublic::from_bytes([9; 32]);
    let outside = question("example.com", TYPE::A);
    assert!(matches!(
        client.respond_from(&outside, None),
        Reply::Answer(_)
    ));

    client.set_exit(Some(&exit));
    let ula = OverlayAddrs::derive(&client.network_id, &exit).ula;
    let relay = relayed(client.respond_from(&outside, None));
    assert_eq!(relay.via, Some(SocketAddr::new(ula.into(), 53)));
    let own = OverlayAddrs::derive(&client.network_id, &NodePublic::from_bytes([1; 32])).ula;
    assert!(
        matches!(client.respond_from(&outside, Some(&own)), Reply::Answer(_)),
        "not this host"
    );
    assert!(matches!(
        client.respond_from(&outside, Some(&Ipv6Addr::LOCALHOST)),
        Reply::Relay(_)
    ));
    assert!(matches!(
        client.respond_from(&question("laptop.vardevall.internal", TYPE::AAAA), None),
        Reply::Answer(_)
    ));

    client.set_exit(None);
    assert!(matches!(
        client.respond_from(&outside, None),
        Reply::Answer(_)
    ));

    let with_forward = rig("", "forward = [\"192.0.2.53:53\"]\n").exit;
    with_forward.set_exit(Some(&exit));
    assert!(matches!(
        with_forward.respond_from(&outside, None),
        Reply::Answer(_)
    ));
}

#[tokio::test]
async fn a_relay_asks_its_own_resolver_instead_of_the_upstreams() {
    let up = upstream(vec![a_record("example.com", WEB)]).await;
    let nowhere: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let f = Forwarder::new(vec![nowhere], tokio::runtime::Handle::current());
    let (tx, rx) = tokio::sync::oneshot::channel();
    f.relay(
        Relay {
            query: question("example.com", TYPE::A),
            via: Some(up),
        },
        move |r| {
            let _ = tx.send(r);
        },
    );
    let bytes = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(Packet::parse(&bytes).unwrap().answers.len(), 1);

    let none = Forwarder::new(vec![], tokio::runtime::Handle::current());
    assert!(!none.relay(
        Relay {
            query: question("example.com", TYPE::A),
            via: None,
        },
        |_| {}
    ));
}

#[tokio::test]
async fn the_mark_goes_on_the_upstream_sockets_and_not_on_those_towards_the_exit() {
    let up = upstream(vec![a_record("example.com", WEB)]).await;
    let relay = |via| Relay {
        query: question("example.com", TYPE::A),
        via,
    };
    let f = Forwarder::new(vec![up], tokio::runtime::Handle::current())
        .with_mark(vardevall::SocketMark::new(0x7664));
    let (tx, rx) = tokio::sync::oneshot::channel();
    f.relay(relay(Some(up)), move |r| {
        let _ = tx.send(r);
    });
    let bytes = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("the query to the exit is not marked")
        .unwrap();
    assert_eq!(Packet::parse(&bytes).unwrap().answers.len(), 1);

    #[cfg(not(target_os = "linux"))]
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        f.relay(relay(None), move |r| {
            let _ = tx.send(r);
        });
        let answer = tokio::time::timeout(Duration::from_millis(300), rx).await;
        assert!(
            !matches!(answer, Ok(Ok(_))),
            "a mark this build cannot put on a socket fails the query"
        );
    }
}

#[test]
fn the_upstreams_are_forward_else_the_hosts_resolvers_for_an_exit() {
    let net = keys::generate_network_secret();
    let me = keys::generate_node_key();
    let parse = |extra: &str| {
        let text =
            format!("[interface]\nprivate_key = \"{me}\"\nnetwork_secret = \"{net}\"\n{extra}");
        let mut c = Config::parse(&text, &Context::default()).unwrap();
        c.system_resolvers = vec!["192.0.2.9:53".parse().unwrap()];
        c
    };
    let system: Vec<SocketAddr> = vec!["192.0.2.9:53".parse().unwrap()];
    let forward: Vec<SocketAddr> = vec!["198.51.100.1:53".parse().unwrap()];
    assert_eq!(parse("").upstreams(), vec![]);
    assert_eq!(parse("\n[exit]\nsite = \"it\"\n").upstreams(), system);
    let both = parse("forward = [\"198.51.100.1:53\"]\n[exit]\nsite = \"it\"\n");
    assert_eq!(both.upstreams(), forward);
}
