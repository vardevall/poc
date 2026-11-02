//! DNS for a host whose resolver is the node and receives every name (Android): the
//! resolver alias and the relay of names outside the overlay to the host's resolvers.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use simple_dns::rdata::{A, RData};
use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, RCODE, ResourceRecord, TYPE};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use vardevall_tun::embed::{
    Callbacks, HostDns, NetworkSpec, Networks, StartOptions, resolver_alias,
};
use vardevall_tun::{keys, packet};

const WEB: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);

struct Running {
    networks: Networks,
    packets: mpsc::UnboundedReceiver<Vec<u8>>,
    own: Ipv6Addr,
}

fn start(extra: &str, dns: HostDns) -> Running {
    let secret = keys::generate_node_key();
    let public = keys::public_key(&secret).unwrap();
    let net = keys::generate_network_secret();
    let text = format!(
        "[interface]\nprivate_key = \"{secret}\"\nnetwork_secret = \"{net}\"\nlisten_port = 0\nmdns = false\nname = \"phone\"\n{extra}\n"
    );
    let (tx, packets) = mpsc::unbounded_channel();
    let callbacks = Callbacks {
        packets: Box::new(move |batch| {
            for p in batch {
                let _ = tx.send(p.to_vec());
            }
        }),
        event: Box::new(|_, _| {}),
        mdns: None,
    };
    let networks = Networks::start_with(
        &tokio::runtime::Handle::current(),
        vec![NetworkSpec {
            name: "home".into(),
            config_toml: text,
        }],
        StartOptions::default(),
        dns,
        callbacks,
    )
    .unwrap();
    let id = keys::network_id(&net).unwrap();
    Running {
        networks,
        packets,
        own: keys::overlay_addrs(&public, &id).unwrap().ula,
    }
}

fn query(name: &str, qtype: TYPE) -> Vec<u8> {
    let mut q = Packet::new_query(0x1234);
    q.set_flags(simple_dns::PacketFlag::RECURSION_DESIRED);
    q.questions.push(Question::new(
        Name::new(name).unwrap(),
        QTYPE::TYPE(qtype),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    q.build_bytes_vec().unwrap()
}

async fn ask(r: &mut Running, server: Ipv6Addr, name: &str, qtype: TYPE) -> Vec<u8> {
    r.networks.packet_in(&packet::build_udp(
        &r.own,
        &server,
        40000,
        53,
        &query(name, qtype),
    ));
    let reply = tokio::time::timeout(Duration::from_secs(5), r.packets.recv())
        .await
        .expect("timed out")
        .expect("closed");
    let h = packet::parse(&reply).unwrap();
    assert_eq!(h.src, server, "the answer comes from the address asked");
    packet::parse_udp(&reply, &h, true)
        .unwrap()
        .payload
        .to_vec()
}

/// A resolver on loopback that answers every A query with `WEB` and counts them.
async fn resolver() -> (SocketAddr, Arc<Mutex<usize>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(0));
    let count = seen.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let q = Packet::parse(&buf[..n]).unwrap();
            *count.lock().unwrap() += 1;
            let mut reply = Packet::new_reply(q.id());
            reply.questions.push(q.questions[0].clone().into_owned());
            reply.answers.push(ResourceRecord::new(
                q.questions[0].qname.clone().into_owned(),
                CLASS::IN,
                60,
                RData::A(A {
                    address: u32::from(WEB),
                }),
            ));
            let _ = sock.send_to(&reply.build_bytes_vec().unwrap(), from).await;
        }
    });
    (addr, seen)
}

const ANDROID: HostDns = HostDns {
    resolver_alias: true,
    relay: true,
};

#[tokio::test]
async fn the_alias_is_the_ula_of_the_64_with_53() {
    let ula: Ipv6Addr = "fd12:3456:789a::1:2:3:4".parse().unwrap();
    assert_eq!(
        resolver_alias(ula),
        "fd12:3456:789a::53".parse::<Ipv6Addr>().unwrap()
    );
}

#[tokio::test]
async fn names_of_the_overlay_are_answered_at_the_alias() {
    let mut r = start("", ANDROID);
    let alias = resolver_alias(r.own);
    let bytes = ask(&mut r, alias, "phone.home.internal", TYPE::AAAA).await;
    let p = Packet::parse(&bytes).unwrap();
    assert_eq!(p.rcode(), RCODE::NoError);
    assert!(
        matches!(p.answers[..], [ref a] if matches!(a.rdata, RData::AAAA(ref x) if Ipv6Addr::from(x.address) == r.own))
    );
    r.networks.stop();
}

#[tokio::test]
async fn names_outside_the_overlay_go_to_the_hosts_resolvers() {
    let mut r = start("", ANDROID);
    let alias = resolver_alias(r.own);

    let bytes = ask(&mut r, alias, "example.com", TYPE::A).await;
    assert_eq!(
        Packet::parse(&bytes).unwrap().rcode(),
        RCODE::ServerFailure,
        "no resolver known yet"
    );

    let (up, seen) = resolver().await;
    r.networks.set_resolvers(&[up]);
    let bytes = ask(&mut r, alias, "example.com", TYPE::A).await;
    let p = Packet::parse(&bytes).unwrap();
    assert_eq!((p.id(), p.rcode()), (0x1234, RCODE::NoError));
    assert!(matches!(p.answers[..], [ref a] if matches!(a.rdata, RData::A(_))));
    assert_eq!(*seen.lock().unwrap(), 1);

    let (other, other_seen) = resolver().await;
    r.networks.set_resolvers(&[other]);
    ask(&mut r, alias, "example.org", TYPE::A).await;
    assert_eq!((*seen.lock().unwrap(), *other_seen.lock().unwrap()), (1, 1));

    let bytes = ask(&mut r, alias, "phone.home.internal", TYPE::AAAA).await;
    assert_eq!(Packet::parse(&bytes).unwrap().answers.len(), 1);
    assert_eq!(*other_seen.lock().unwrap(), 1, "overlay names stay home");
    r.networks.stop();
}

#[tokio::test]
async fn a_file_with_forward_keeps_its_upstream_for_the_overlay_domain_only() {
    let (file_upstream, file_seen) = resolver().await;
    let (host_upstream, host_seen) = resolver().await;
    let mut r = start(&format!("forward = [\"{file_upstream}\"]"), ANDROID);
    let alias = resolver_alias(r.own);
    r.networks.set_resolvers(&[host_upstream]);

    ask(&mut r, alias, "example.com", TYPE::A).await;
    assert_eq!(
        (*host_seen.lock().unwrap(), *file_seen.lock().unwrap()),
        (1, 0)
    );
    ask(&mut r, alias, "unknown.home.internal", TYPE::A).await;
    assert_eq!(
        (*host_seen.lock().unwrap(), *file_seen.lock().unwrap()),
        (1, 1)
    );
    r.networks.stop();
}

#[tokio::test]
async fn without_the_option_the_alias_is_nobodys_and_outside_names_are_refused() {
    let mut r = start("", HostDns::default());
    r.networks.packet_in(&packet::build_udp(
        &r.own,
        &resolver_alias(r.own),
        40000,
        53,
        &query("phone.home.internal", TYPE::AAAA),
    ));
    let reply = tokio::time::timeout(Duration::from_secs(5), r.packets.recv())
        .await
        .unwrap()
        .unwrap();
    let h = packet::parse(&reply).unwrap();
    assert_eq!(h.next, 58, "an ICMPv6 error, not a DNS answer");

    let own = r.own;
    let bytes = ask(&mut r, own, "example.com", TYPE::A).await;
    assert_eq!(Packet::parse(&bytes).unwrap().rcode(), RCODE::Refused);
    r.networks.stop();
}

#[tokio::test]
async fn tcp_to_the_alias_fails_at_once() {
    let mut r = start("", ANDROID);
    let alias = resolver_alias(r.own);
    let mut syn = [0u8; 20];
    syn[..2].copy_from_slice(&40000u16.to_be_bytes());
    syn[2..4].copy_from_slice(&53u16.to_be_bytes());
    syn[12] = 5 << 4;
    syn[13] = 0x02;
    let syn = packet::with_checksum(&packet::build(&r.own, &alias, 6, 64, &syn));
    r.networks.packet_in(&syn);
    let reply = tokio::time::timeout(Duration::from_secs(5), r.packets.recv())
        .await
        .unwrap()
        .unwrap();
    let h = packet::parse(&reply).unwrap();
    assert_eq!(h.next, 58);
    assert_eq!(reply[40], 1, "destination unreachable");
    r.networks.stop();
}
