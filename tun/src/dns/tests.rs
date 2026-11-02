use simple_dns::rdata::RData;
use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, RCODE, TYPE};
use vardevall_proto::keys::{NetworkId, NodePublic};

use super::*;

const VECTORS: &str = include_str!("../../tests/vectors/06-addressing-dns.json");

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn query(name: &str, qtype: TYPE) -> Vec<u8> {
    let mut p = Packet::new_query(0x1234);
    p.questions.push(Question::new(
        Name::new(name).unwrap(),
        QTYPE::TYPE(qtype),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    p.build_bytes_vec().unwrap()
}

fn answer(r: &Responder, name: &str, qtype: TYPE) -> (RCODE, Vec<String>) {
    let Reply::Answer(bytes) = r.respond(&query(name, qtype)) else {
        panic!("no answer for {name}");
    };
    let p = Packet::parse(&bytes).unwrap();
    assert_eq!(p.id(), 0x1234);
    let texts = p
        .answers
        .iter()
        .map(|a| match &a.rdata {
            RData::AAAA(x) => std::net::Ipv6Addr::from(x.address).to_string(),
            RData::PTR(t) => t.0.to_string(),
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    (p.rcode(), texts)
}

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn responder_for(v: &serde_json::Value, forward: bool) -> (Responder, NodePublic) {
    let net = NetworkId::from_bytes(hex32(v["input"]["network_id"].as_str().unwrap()));
    let key = NodePublic::from_bytes(hex32(v["input"]["node_pk"].as_str().unwrap()));
    let domain = v["input"]["domain"].as_str().unwrap();
    let name = v["input"]["configured_name"].as_str();
    let own = NodePublic::from_bytes([9; 32]);
    let r = Responder::new(net, domain, own, None, &[(name, key)], forward);
    (r, key)
}

#[test]
fn ptr_and_key_id_vectors() {
    let doc = vectors();
    for v in doc["ptr_names"].as_array().unwrap().iter().take(2) {
        let (r, key) = responder_for(v, false);
        let o = &v["output"];
        let (rc, got) = answer(&r, o["ptr_query_name"].as_str().unwrap(), TYPE::PTR);
        assert_eq!(rc, RCODE::NoError, "{}", v["description"]);
        assert_eq!(got, vec![o["ptr_answer"].as_str().unwrap().to_owned()]);

        let (rc, got) = answer(
            &r,
            o["aaaa_query_name_by_key_id"].as_str().unwrap(),
            TYPE::AAAA,
        );
        assert_eq!(rc, RCODE::NoError);
        let ula = hex32(&format!("{}{}", o["ula"].as_str().unwrap(), "0".repeat(32)));
        let want = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ula[..16]).unwrap());
        assert_eq!(got, vec![want.to_string()]);
        assert_eq!(r.resolve(&key.key_id()), Some(key));
    }
}

#[test]
fn configured_names_resolve_in_any_case() {
    let doc = vectors();
    let (r, _) = responder_for(&doc["ptr_names"][0], false);
    let (rc, a) = answer(&r, "laptop.home.internal", TYPE::AAAA);
    assert_eq!((rc, a.len()), (RCODE::NoError, 1));
    assert_eq!(answer(&r, "LAPTOP.Home.Internal.", TYPE::AAAA).1, a);
    assert_eq!(
        answer(&r, "laptop.home.internal", TYPE::A),
        (RCODE::NoError, vec![])
    );
}

#[test]
fn unknown_and_foreign_names() {
    let doc = vectors();
    let (r, _) = responder_for(&doc["ptr_names"][0], false);
    assert_eq!(
        answer(&r, "nobody.home.internal", TYPE::AAAA).0,
        RCODE::NameError
    );
    assert_eq!(answer(&r, "example.com", TYPE::AAAA).0, RCODE::Refused);
    assert_eq!(
        answer(&r, "home.internal.example.com", TYPE::AAAA).0,
        RCODE::Refused
    );
    let (rc, _) = answer(&r, "1.0.0.0.ip6.arpa", TYPE::PTR);
    assert_eq!(rc, RCODE::Refused);
}

#[test]
fn misses_are_forwarded_when_configured() {
    let doc = vectors();
    let (r, _) = responder_for(&doc["ptr_names"][0], true);
    let q = query("nobody.home.internal", TYPE::AAAA);
    assert_eq!(r.respond(&q), Reply::Forward(q));
    assert!(matches!(
        r.respond(&query("laptop.home.internal", TYPE::AAAA)),
        Reply::Answer(_)
    ));
    assert_eq!(answer(&r, "example.com", TYPE::AAAA).0, RCODE::Refused);
}

#[test]
fn own_name_and_members() {
    let net = NetworkId::from_bytes([5; 32]);
    let me = NodePublic::from_bytes([1; 32]);
    let r = Responder::new(net, "lab.internal", me, Some("mac"), &[], false);
    assert_eq!(r.resolve("mac"), Some(me));
    assert_eq!(r.name(&me).as_deref(), Some("mac"));
    let member = NodePublic::from_bytes([2; 32]);
    assert_eq!(
        r.resolve(&format!("{}.lab.internal", member.key_id())),
        Some(member)
    );
    let ptr = vardevall_proto::addr::ptr_name(
        &vardevall_proto::addr::OverlayAddrs::derive(&net, &member).ula,
    );
    assert_eq!(answer(&r, &ptr, TYPE::PTR).0, RCODE::NameError);
    r.add_key(member);
    let (rc, got) = answer(&r, &ptr, TYPE::PTR);
    assert_eq!(rc, RCODE::NoError);
    assert_eq!(got, vec![format!("{}.lab.internal", member.key_id())]);
}

#[test]
fn a_removed_key_is_no_longer_known() {
    let net = NetworkId::from_bytes([5; 32]);
    let me = NodePublic::from_bytes([1; 32]);
    let friend = NodePublic::from_bytes([3; 32]);
    let r = Responder::new(
        net,
        "lab.internal",
        me,
        None,
        &[(Some("pc"), friend)],
        false,
    );
    let member = NodePublic::from_bytes([2; 32]);
    let ptr_of = |k: &NodePublic| {
        vardevall_proto::addr::ptr_name(&vardevall_proto::addr::OverlayAddrs::derive(&net, k).ula)
    };
    r.add_key(member);
    assert_eq!(answer(&r, &ptr_of(&member), TYPE::PTR).0, RCODE::NoError);
    r.remove_key(&member);
    assert_eq!(answer(&r, &ptr_of(&member), TYPE::PTR).0, RCODE::NameError);
    assert_eq!(answer(&r, &ptr_of(&friend), TYPE::PTR).0, RCODE::NoError);
    r.remove_key(&friend);
    assert_eq!(r.resolve("pc"), None);
    assert_eq!(r.name(&friend), None);
    assert_eq!(answer(&r, &ptr_of(&friend), TYPE::PTR).0, RCODE::NameError);
}

#[test]
fn garbage_and_responses_get_no_answer() {
    let r = Responder::new(
        NetworkId::from_bytes([5; 32]),
        "lab.internal",
        NodePublic::from_bytes([1; 32]),
        None,
        &[],
        false,
    );
    assert_eq!(r.respond(&[1, 2, 3]), Reply::Drop);
    let mut resp = query("a.lab.internal", TYPE::AAAA);
    resp[2] |= 0x80;
    assert_eq!(r.respond(&resp), Reply::Drop);
    let mut bad = query("a.lab.internal", TYPE::AAAA);
    bad.truncate(20);
    let Reply::Answer(a) = r.respond(&bad) else {
        panic!();
    };
    assert_eq!(a[3] & 0x0f, 1);
}

#[test]
fn zones_are_matched_on_whole_labels() {
    let net = NetworkId::from_bytes([5; 32]);
    let r = Responder::new(
        net,
        "home.internal.",
        NodePublic::from_bytes([9; 32]),
        None,
        &[],
        false,
    );
    let zone = |name: &str| r.zone_len(&query(name, TYPE::AAAA));
    assert_eq!(zone("beta.home.internal"), Some("home.internal".len()));
    assert_eq!(zone("HOME.internal."), Some("home.internal".len()));
    assert_eq!(zone("beta.nothome.internal"), None);
    assert_eq!(zone("beta.example.org"), None);
    let reverse = vardevall_proto::addr::reverse_zone(&net);
    assert_eq!(zone(&format!("1.{reverse}")), Some(reverse.len()));
    assert_eq!(r.zone_len(b"garbage"), None);
}

#[test]
fn intercepts_queries_to_the_own_address() {
    let net = NetworkId::from_bytes([5; 32]);
    let me = NodePublic::from_bytes([1; 32]);
    let own = vardevall_proto::addr::OverlayAddrs::derive(&net, &me);
    let client: std::net::Ipv6Addr = "fd00::77".parse().unwrap();
    let msg = query("x.lab.internal", TYPE::AAAA);
    let pkt = crate::packet::build_udp(&client, &own.ula, 5000, 53, &msg);
    let q = intercept(&pkt, &own).unwrap();
    assert_eq!((q.client, q.server, q.client_port), (client, own.ula, 5000));
    assert_eq!(q.message, msg);
    let back = reply_packet(&q, b"answer");
    let h = crate::packet::parse(&back).unwrap();
    assert_eq!((h.src, h.dst), (own.ula, client));
    let u = crate::packet::parse_udp(&back, &h, true).unwrap();
    assert_eq!((u.src_port, u.dst_port), (53, 5000));

    let other = crate::packet::build_udp(&client, &own.ula, 5000, 80, &msg);
    assert!(intercept(&other, &own).is_none());
    let elsewhere = crate::packet::build_udp(&client, &"fd00::1".parse().unwrap(), 5000, 53, &msg);
    assert!(intercept(&elsewhere, &own).is_none());
}

#[tokio::test]
async fn serves_udp_and_tcp() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let doc = vectors();
    let (r, _) = responder_for(&doc["ptr_names"][0], false);
    let r = std::sync::Arc::new(r);
    let f = std::sync::Arc::new(Forwarder::new(vec![], tokio::runtime::Handle::current()));
    let (udp, tcp) = loop {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if let Ok(tcp) = tokio::net::TcpListener::bind(udp.local_addr().unwrap()).await {
            break (udp, tcp);
        }
    };
    let addr = udp.local_addr().unwrap();
    tokio::spawn(serve_udp(r.clone(), f.clone(), udp));
    tokio::spawn(serve_tcp(r, f, tcp));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&query("laptop.home.internal", TYPE::AAAA), addr)
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(Packet::parse(&buf[..n]).unwrap().answers.len(), 1);

    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let q = query("laptop.home.internal", TYPE::AAAA);
    tcp.write_all(&(q.len() as u16).to_be_bytes())
        .await
        .unwrap();
    tcp.write_all(&q).await.unwrap();
    let mut len = [0u8; 2];
    tcp.read_exact(&mut len).await.unwrap();
    let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
    tcp.read_exact(&mut resp).await.unwrap();
    assert_eq!(Packet::parse(&resp).unwrap().answers.len(), 1);
}

use std::time::Duration;

mod services {
    use std::collections::HashMap;
    use std::net::Ipv6Addr;
    use std::sync::{Arc, Mutex};

    use simple_dns::rdata::RData;
    use simple_dns::{Packet, RCODE, ResourceRecord, TYPE};
    use vardevall_proto::addr::OverlayAddrs;
    use vardevall_proto::ip::service::{Proto, Provider};
    use vardevall_proto::keys::{NetworkId, NodePublic};

    use super::{Reply, Responder, query};
    use crate::dns::{Providers, SERVICE_TTL};

    const NET: [u8; 32] = [5; 32];

    type Table = HashMap<(String, Option<Proto>), Vec<Provider>>;

    #[derive(Default)]
    struct Fake(Mutex<Table>);

    impl Fake {
        fn set(&self, service: &str, proto: Option<Proto>, list: Vec<Provider>) {
            self.0
                .lock()
                .unwrap()
                .insert((service.to_owned(), proto), list);
        }
    }

    impl Providers for Fake {
        fn providers(&self, service: &str, proto: Option<Proto>) -> Vec<Provider> {
            self.0
                .lock()
                .unwrap()
                .get(&(service.to_owned(), proto))
                .cloned()
                .unwrap_or_default()
        }
    }

    fn key(n: u8) -> NodePublic {
        NodePublic::from_bytes([n; 32])
    }

    fn ula(n: u8) -> Ipv6Addr {
        OverlayAddrs::derive(&NetworkId::from_bytes(NET), &key(n)).ula
    }

    fn provider(n: u8, port: u16, proto: Proto, live: bool) -> Provider {
        Provider {
            key: key(n),
            port,
            proto,
            live,
        }
    }

    fn responder(forward: bool, fake: &Arc<Fake>) -> Responder {
        Responder::new(
            NetworkId::from_bytes(NET),
            "lab.internal",
            key(1),
            Some("mac"),
            &[(Some("nas"), key(2))],
            forward,
        )
        .with_services(fake.clone())
    }

    fn parse(r: &Responder, name: &str, qtype: TYPE) -> Packet<'static> {
        let Reply::Answer(bytes) = r.respond(&query(name, qtype)) else {
            panic!("no answer for {name}");
        };
        Packet::parse(Box::leak(bytes.into_boxed_slice())).unwrap()
    }

    fn addrs(p: &Packet<'_>) -> Vec<(Ipv6Addr, u32)> {
        p.answers
            .iter()
            .map(|a| match &a.rdata {
                RData::AAAA(x) => (Ipv6Addr::from(x.address), a.ttl),
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    fn srv(a: &ResourceRecord<'_>) -> (u16, u16, String, u32) {
        match &a.rdata {
            RData::SRV(s) => (s.priority, s.port, s.target.to_string(), a.ttl),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn names_under_a_node_are_that_node() {
        let r = responder(false, &Arc::default());
        for name in [
            "web.mac.lab.internal",
            "a.b.mac.lab.internal",
            "WEB.Mac.Lab.Internal.",
            &format!("web.{}.lab.internal", key(2).key_id()),
        ] {
            let p = parse(&r, name, TYPE::AAAA);
            assert_eq!(p.rcode(), RCODE::NoError, "{name}");
            let want = if name.to_ascii_lowercase().contains("mac") {
                ula(1)
            } else {
                ula(2)
            };
            assert_eq!(addrs(&p), vec![(want, 300)], "{name}");
        }
        let p = parse(&r, "web.nas.lab.internal", TYPE::AAAA);
        assert_eq!(addrs(&p), vec![(ula(2), 300)]);
        let p = parse(&r, "web.mac.lab.internal", TYPE::A);
        assert_eq!((p.rcode(), p.answers.len()), (RCODE::NoError, 0));
        let p = parse(&r, "web.nobody.lab.internal", TYPE::AAAA);
        assert_eq!(p.rcode(), RCODE::NameError);
        let p = parse(&r, "web.mac.elsewhere.example", TYPE::AAAA);
        assert_eq!(p.rcode(), RCODE::Refused);
    }

    #[test]
    fn names_under_a_node_are_not_forwarded() {
        let r = responder(true, &Arc::default());
        let p = parse(&r, "web.mac.lab.internal", TYPE::AAAA);
        assert_eq!(addrs(&p), vec![(ula(1), 300)]);
        let q = query("web.nobody.lab.internal", TYPE::AAAA);
        assert_eq!(r.respond(&q), Reply::Forward(q));
    }

    #[test]
    fn service_names_answer_with_the_providers_in_order() {
        let fake = Arc::new(Fake::default());
        fake.set(
            "web",
            None,
            vec![
                provider(1, 443, Proto::Tcp, true),
                provider(3, 8443, Proto::Tcp, true),
                provider(4, 80, Proto::Tcp, false),
            ],
        );
        let r = responder(false, &fake);
        let p = parse(&r, "web.lab.internal", TYPE::AAAA);
        assert_eq!(p.rcode(), RCODE::NoError);
        assert_eq!(
            addrs(&p),
            vec![
                (ula(1), SERVICE_TTL),
                (ula(3), SERVICE_TTL),
                (ula(4), SERVICE_TTL)
            ]
        );
        let p = parse(&r, "web.lab.internal", TYPE::A);
        assert_eq!((p.rcode(), p.answers.len()), (RCODE::NoError, 0));
        let p = parse(&r, "web.lab.internal", TYPE::SRV);
        assert_eq!((p.rcode(), p.answers.len()), (RCODE::NoError, 0));
        let p = parse(&r, "db.lab.internal", TYPE::AAAA);
        assert_eq!(p.rcode(), RCODE::NameError);
    }

    #[test]
    fn srv_records_name_the_providers() {
        let fake = Arc::new(Fake::default());
        fake.set(
            "web",
            Some(Proto::Tcp),
            vec![
                provider(1, 443, Proto::Tcp, true),
                provider(2, 8080, Proto::Tcp, true),
                provider(4, 80, Proto::Tcp, false),
            ],
        );
        fake.set(
            "dns",
            Some(Proto::Udp),
            vec![provider(2, 53, Proto::Udp, true)],
        );
        let r = responder(false, &fake);
        let p = parse(&r, "_web._tcp.lab.internal", TYPE::SRV);
        assert_eq!(p.rcode(), RCODE::NoError);
        let got: Vec<_> = p.answers.iter().map(srv).collect();
        assert_eq!(
            got,
            vec![
                (0, 443, "mac.lab.internal".to_owned(), SERVICE_TTL),
                (0, 8080, "nas.lab.internal".to_owned(), SERVICE_TTL),
                (
                    1,
                    80,
                    format!("{}.lab.internal", key(4).key_id()),
                    SERVICE_TTL
                ),
            ]
        );
        assert_eq!(p.additional_records.len(), 3);
        let p = parse(&r, "_dns._udp.lab.internal", TYPE::SRV);
        assert_eq!(p.answers.len(), 1);
        let p = parse(&r, "_dns._tcp.lab.internal", TYPE::SRV);
        assert_eq!(p.rcode(), RCODE::NameError);
        let p = parse(&r, "_web._tcp.lab.internal", TYPE::AAAA);
        assert_eq!((p.rcode(), p.answers.len()), (RCODE::NoError, 0));
        let p = parse(&r, "_web._sctp.lab.internal", TYPE::SRV);
        assert_eq!(p.rcode(), RCODE::NameError);
    }

    #[test]
    fn the_table_comes_before_services() {
        let fake = Arc::new(Fake::default());
        fake.set("nas", None, vec![provider(3, 1, Proto::Tcp, true)]);
        fake.set("mac", None, vec![provider(3, 1, Proto::Tcp, true)]);
        let r = responder(false, &fake);
        assert_eq!(
            addrs(&parse(&r, "nas.lab.internal", TYPE::AAAA)),
            vec![(ula(2), 300)]
        );
        assert_eq!(
            addrs(&parse(&r, "mac.lab.internal", TYPE::AAAA)),
            vec![(ula(1), 300)]
        );
    }

    #[test]
    fn forward_answers_come_before_services() {
        let fake = Arc::new(Fake::default());
        fake.set("web", None, vec![provider(1, 443, Proto::Tcp, true)]);
        let r = responder(true, &fake);
        let q = query("web.lab.internal", TYPE::AAAA);
        assert_eq!(r.respond(&q), Reply::Forward(q.clone()));

        let upstream = |rcode: RCODE| {
            let mut p = Packet::new_reply(0x1234);
            *p.rcode_mut() = rcode;
            p.build_bytes_vec().unwrap()
        };
        let nx = upstream(RCODE::NameError);
        let answer = r.after_forward(&q, nx);
        let p = Packet::parse(&answer).unwrap();
        assert_eq!(addrs(&p), vec![(ula(1), SERVICE_TTL)]);
        assert_eq!(p.id(), 0x1234);

        for rcode in [RCODE::NoError, RCODE::ServerFailure, RCODE::Refused] {
            let other = upstream(rcode);
            assert_eq!(r.after_forward(&q, other.clone()), other);
        }
        let nx = upstream(RCODE::NameError);
        let none = query("db.lab.internal", TYPE::AAAA);
        assert_eq!(r.after_forward(&none, nx.clone()), nx);
        let reverse = query("1.0.0.0.ip6.arpa", TYPE::PTR);
        assert_eq!(r.after_forward(&reverse, nx.clone()), nx);
    }

    #[test]
    fn without_services_names_are_unknown() {
        let r = Responder::new(
            NetworkId::from_bytes(NET),
            "lab.internal",
            key(1),
            Some("mac"),
            &[],
            false,
        );
        let p = parse(&r, "web.lab.internal", TYPE::AAAA);
        assert_eq!(p.rcode(), RCODE::NameError);
    }
}
