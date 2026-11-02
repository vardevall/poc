//! A client, an exit and the traffic between them, each a real node on loopback.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use simple_dns::rdata::{A, RData};
use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, ResourceRecord, TYPE};
use tokio::sync::mpsc;
use vardevall_proto::ip::site::{Site, site_addr};
use vardevall_proto::keys::{NetworkId, NodePublic};
use vardevall_tun::dns::{self, Forwarder, Reply};
use vardevall_tun::embed::{Callbacks, ExitUse, NetworkSpec, Networks, StartOptions, Tunnel};
use vardevall_tun::{keys, packet};

struct Side {
    secret: String,
    public: String,
}

fn side() -> Side {
    let secret = keys::generate_node_key();
    let public = keys::public_key(&secret).unwrap();
    Side { secret, public }
}

/// A UDP port for a node to listen on, from a range of its own.
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let start = 24_000 + (std::process::id() % 50) as u16 * 100;
    loop {
        let port = start + NEXT.fetch_add(1, Ordering::Relaxed) % 100;
        if std::net::UdpSocket::bind(("::", port)).is_ok() {
            return port;
        }
    }
}

fn config(me: &Side, net: &str, port: u16, peer: (&Side, Option<u16>), tables: &str) -> String {
    let (peer, endpoint) = peer;
    let ep = endpoint
        .map(|p| format!("endpoint = \"127.0.0.1:{p}\"\n"))
        .unwrap_or_default();
    format!(
        "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{net}\"\nlisten_port = {port}\nmdns = false\n{tables}\n[[peer]]\npublic_key = \"{}\"\n{ep}",
        me.secret, peer.public,
    )
}

struct Sink {
    packets: mpsc::UnboundedReceiver<Vec<u8>>,
    events: Arc<Mutex<Vec<Value>>>,
}

fn callbacks() -> (Callbacks, Sink) {
    let (ptx, packets) = mpsc::unbounded_channel();
    let events = Arc::new(Mutex::new(Vec::new()));
    let e = events.clone();
    let callbacks = Callbacks {
        packets: Box::new(move |packets| {
            for p in packets {
                let _ = ptx.send(p.to_vec());
            }
        }),
        event: Box::new(move |network, ev| {
            e.lock()
                .unwrap()
                .push(serde_json::from_str(&ev.to_json(network)).unwrap())
        }),
        mdns: None,
    };
    (callbacks, Sink { packets, events })
}

fn single(text: &str) -> (Tunnel, Sink) {
    let (callbacks, sink) = callbacks();
    let tunnel = Tunnel::start(
        &tokio::runtime::Handle::current(),
        text,
        StartOptions::default(),
        callbacks,
    )
    .unwrap();
    (tunnel, sink)
}

async fn recv(sink: &mut Sink) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(10), sink.packets.recv())
        .await
        .expect("timed out")
        .expect("closed")
}

/// Waits for the `exit` event whose `via` is `via` (null for none) and returns it.
async fn exit_event(sink: &Sink, via: Option<&str>) -> Value {
    let wanted = via.map_or(Value::Null, Value::from);
    for _ in 0..200 {
        if let Some(e) = sink
            .events
            .lock()
            .unwrap()
            .iter()
            .find(|e| e["type"] == "exit" && e["via"] == wanted)
        {
            return e.clone();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no exit event: {:?}", sink.events.lock().unwrap());
}

fn echo(src: Ipv6Addr, dst: Ipv6Addr, id: u8) -> Vec<u8> {
    packet::build_icmpv6(&src, &dst, 128, 0, &[id, 1, 0, 1], 64)
}

fn site(text: &str) -> Site {
    text.parse().unwrap()
}

fn network_id(net: &str) -> NetworkId {
    keys::network_id(net).unwrap().parse().unwrap()
}

fn node(of: &Side) -> NodePublic {
    of.public.parse().unwrap()
}

fn outside() -> Ipv6Addr {
    "2001:db8::53".parse().unwrap()
}

/// A client and the exit of site `it/home`, linked, with the exit in use at the client.
struct Pair {
    client: Tunnel,
    from_client: Sink,
    exit: Arc<Tunnel>,
    from_exit: Sink,
    mine: Ipv6Addr,
    mine4: Option<Ipv4Addr>,
    own: Ipv6Addr,
    exit_ula: Ipv6Addr,
    exit_key: String,
}

async fn pair() -> Pair {
    pair_with("").await
}

/// As [`pair`], with `exit_keys` added to the exit's `[exit]` table.
async fn pair_with(exit_keys: &str) -> Pair {
    let net = keys::generate_network_secret();
    let (c, x) = (side(), side());
    let (pc, px) = (free_port(), free_port());
    let (client, from_client) = single(&config(&c, &net, pc, (&x, Some(px)), ""));
    let (exit, from_exit) = single(&config(
        &x,
        &net,
        px,
        (&c, None),
        &format!("[exit]\nsite = \"it/home\"\n{exit_keys}"),
    ));
    client.set_exit(Some(ExitUse::default()));
    let ula = keys::overlay_addrs(&x.public, &keys::network_id(&net).unwrap())
        .unwrap()
        .ula;
    let own = keys::overlay_addrs(&c.public, &keys::network_id(&net).unwrap())
        .unwrap()
        .ula;
    client.packet_in(&echo(own, ula, 0));
    let e = exit_event(&from_client, Some(&x.public)).await;
    assert_eq!(e["site"], "it/home");
    let mine = site_addr(&network_id(&net), &site("it/home"), &node(&c));
    assert_eq!(e["addr"], mine.to_string());
    let home = vardevall::home_ipv4(&network_id(&net), &node(&c));
    let ipv4 = (!exit_keys.contains("ipv4 = false")).then_some(home);
    assert_eq!(
        e["ipv4"],
        ipv4.map_or(Value::Null, |a| a.to_string().into())
    );
    Pair {
        client,
        from_client,
        exit: Arc::new(exit),
        from_exit,
        mine,
        mine4: ipv4,
        own,
        exit_ula: ula,
        exit_key: x.public,
    }
}

/// An IPv4 packet with a valid header checksum.
fn v4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0];
    p.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let mut sum = 0u32;
    for c in p.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn web() -> Ipv4Addr {
    Ipv4Addr::new(93, 184, 216, 34)
}

#[tokio::test]
async fn a_packet_outside_the_overlay_goes_to_the_exit_and_the_answer_comes_back() {
    let mut p = pair().await;
    // the packet that opened the link
    recv(&mut p.from_exit).await;

    let out = echo(p.mine, outside(), 1);
    p.client.packet_in(&out);
    assert_eq!(recv(&mut p.from_exit).await, out);

    let back = echo(outside(), p.mine, 2);
    p.exit.packet_in(&back);
    assert_eq!(recv(&mut p.from_client).await, back);
    p.client.stop_async().await;
    p.exit.stop_async().await;
}

#[tokio::test]
async fn a_spoofed_source_is_dropped_by_the_exit() {
    let mut p = pair().await;
    recv(&mut p.from_exit).await;

    let stranger: Ipv6Addr = "2001:db8::bad".parse().unwrap();
    p.client.packet_in(&echo(stranger, outside(), 3));
    let ok = echo(p.mine, outside(), 4);
    p.client.packet_in(&ok);
    assert_eq!(
        recv(&mut p.from_exit).await,
        ok,
        "the spoofed packet was dropped, the next one arrived"
    );

    let to_exit = echo(outside(), p.mine, 5);
    let elsewhere: Ipv6Addr = "2001:db8::77".parse().unwrap();
    p.exit.packet_in(&echo(outside(), elsewhere, 6));
    p.exit.packet_in(&to_exit);
    assert_eq!(
        recv(&mut p.from_client).await,
        to_exit,
        "the exit has no route for another destination"
    );
    p.client.stop_async().await;
    p.exit.stop_async().await;
}

#[tokio::test]
async fn without_the_exit_in_use_there_is_no_route() {
    let mut p = pair().await;
    recv(&mut p.from_exit).await;
    p.client.set_exit(None);
    p.client.packet_in(&echo(p.mine, outside(), 7));
    let reply = recv(&mut p.from_client).await;
    assert_eq!(
        (reply[40], reply[41]),
        (1, 0),
        "destination unreachable, no route"
    );
    assert!(p.from_exit.packets.try_recv().is_err());

    p.client.set_exit(Some(ExitUse {
        site: Some(site("de")),
    }));
    p.client.packet_in(&echo(p.mine, outside(), 8));
    let reply = recv(&mut p.from_client).await;
    assert_eq!((reply[40], reply[41]), (1, 0), "a site with no exit");
    p.client.stop_async().await;
    p.exit.stop_async().await;
}

#[tokio::test]
async fn the_view_names_the_sites_and_the_exit_in_use() {
    let p = pair().await;
    let mut seen = None;
    for _ in 0..100 {
        seen = p
            .from_client
            .events
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|e| e["type"] == "view" && e["exit"].is_object())
            .cloned();
        if seen.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let v = seen.expect("a view with the exit in use");
    assert_eq!(v["sites"][0]["site"], "it/home");
    assert_eq!(v["sites"][0]["chosen"], p.exit_key);
    assert_eq!(v["sites"][0]["addr"], p.mine.to_string());
    assert_eq!(v["exit"]["site"], "it/home");
    assert_eq!(v["exit"]["via"], p.exit_key);
    p.client.stop_async().await;
    p.exit.stop_async().await;
}

/// Two networks, `home` and `work`, each with an exit on a tunnel of its own.
#[tokio::test]
async fn the_network_that_carries_the_exit_takes_what_no_network_holds() {
    let (s_home, s_work) = (
        keys::generate_network_secret(),
        keys::generate_network_secret(),
    );
    let (me_home, me_work, x_home, x_work) = (side(), side(), side(), side());
    let (p_me_home, p_me_work, p_x_home, p_x_work) =
        (free_port(), free_port(), free_port(), free_port());
    let (_keep_home, mut exit_home) = single(&config(
        &x_home,
        &s_home,
        p_x_home,
        (&me_home, None),
        "[exit]\nsite = \"it/home\"\n",
    ));
    let (_keep_work, mut exit_work) = single(&config(
        &x_work,
        &s_work,
        p_x_work,
        (&me_work, None),
        "[exit]\nsite = \"de\"\n",
    ));
    let (callbacks, mut sink) = callbacks();
    let nets = Networks::start(
        &tokio::runtime::Handle::current(),
        vec![
            NetworkSpec {
                name: "home".into(),
                config_toml: config(&me_home, &s_home, p_me_home, (&x_home, Some(p_x_home)), ""),
            },
            NetworkSpec {
                name: "work".into(),
                config_toml: config(&me_work, &s_work, p_me_work, (&x_work, Some(p_x_work)), ""),
            },
        ],
        StartOptions::default(),
        callbacks,
    )
    .unwrap();
    assert!(
        nets.set_exit(Some(("nowhere", ExitUse::default())))
            .is_err()
    );

    let ula = |of: &Side, net: &str| {
        keys::overlay_addrs(&of.public, &keys::network_id(net).unwrap())
            .unwrap()
            .ula
    };
    nets.packet_in(&echo(ula(&me_home, &s_home), ula(&x_home, &s_home), 0));
    nets.packet_in(&echo(ula(&me_work, &s_work), ula(&x_work, &s_work), 0));
    exit_event(&sink, Some(&x_home.public)).await;
    exit_event(&sink, Some(&x_work.public)).await;
    recv(&mut exit_home).await;
    recv(&mut exit_work).await;

    let mine_home = site_addr(&network_id(&s_home), &site("it/home"), &node(&me_home));
    let mine_work = site_addr(&network_id(&s_work), &site("de"), &node(&me_work));

    let out = echo(mine_home, outside(), 1);
    nets.packet_in(&out);
    let reply = recv(&mut sink).await;
    assert_eq!(
        (reply[40], reply[41]),
        (1, 0),
        "no exit is set: the first network has no route"
    );

    assert!(nets.exit_in_use().is_none());
    nets.set_exit(Some(("work", ExitUse::default()))).unwrap();
    let (carrier, used) = nets.exit_in_use().expect("the work exit is in use");
    assert_eq!((carrier, used.addr), ("work", mine_work));
    let out = echo(mine_work, outside(), 2);
    nets.packet_in(&out);
    assert_eq!(recv(&mut exit_work).await, out);
    assert!(exit_home.packets.try_recv().is_err());

    nets.set_exit(Some(("home", ExitUse::default()))).unwrap();
    let out = echo(mine_home, outside(), 3);
    nets.packet_in(&out);
    assert_eq!(recv(&mut exit_home).await, out);
    assert!(exit_work.packets.try_recv().is_err());

    assert_eq!(nets.exit_in_use().map(|(n, _)| n), Some("home"));
    nets.set_exit(None).unwrap();
    assert!(nets.exit_in_use().is_none());
    nets.packet_in(&echo(mine_home, outside(), 4));
    let reply = recv(&mut sink).await;
    assert_eq!((reply[40], reply[41]), (1, 0));
    nets.stop_async().await;
}

#[tokio::test]
async fn ipv4_from_the_address_the_exit_gave_crosses_as_it_is_and_the_answer_comes_back() {
    let mut p = pair().await;
    recv(&mut p.from_exit).await;
    let mine4 = p.mine4.expect("the exit carries IPv4");
    assert!(vardevall::is_client_ipv4(mine4));

    let ping = v4(mine4, web(), 1, &[8, 0, 0, 0, 0, 5, 0, 6]);
    p.client.packet_in(&ping);
    assert_eq!(recv(&mut p.from_exit).await, ping, "unchanged");

    let answer = v4(web(), mine4, 1, &[0, 0, 0, 0, 0, 5, 0, 6]);
    p.exit.packet_in(&answer);
    assert_eq!(recv(&mut p.from_client).await, answer, "unchanged");

    p.exit
        .packet_in(&v4(web(), Ipv4Addr::new(198, 18, 77, 77), 1, &[0; 8]));
    p.client
        .packet_in(&v4(Ipv4Addr::new(192, 0, 0, 2), web(), 1, &[0; 8]));
    p.client.packet_in(&echo(p.mine, outside(), 2));
    assert_eq!(
        recv(&mut p.from_exit).await,
        echo(p.mine, outside(), 2),
        "nothing for an address of nobody, nothing from another source"
    );
    assert!(p.from_client.packets.try_recv().is_err());
    p.client.stop_async().await;
    p.exit.stop_async().await;
}

#[tokio::test]
async fn the_exit_refuses_private_ipv4_with_administratively_prohibited() {
    let mut p = pair().await;
    recv(&mut p.from_exit).await;
    let mine4 = p.mine4.unwrap();
    let lan = v4(
        mine4,
        Ipv4Addr::new(192, 168, 1, 1),
        1,
        &[8, 0, 0, 0, 0, 5, 0, 6],
    );
    p.client.packet_in(&lan);
    let e = recv(&mut p.from_client).await;
    assert_eq!((e[0], e[20], e[21]), (0x45, 3, 13));
    assert_eq!(&e[12..16], &vardevall::EXIT_IPV4.octets());
    assert_eq!(&e[16..20], &mine4.octets());
    assert!(p.from_exit.packets.try_recv().is_err());
    p.client.stop_async().await;
    p.exit.stop_async().await;
}

#[tokio::test]
async fn without_the_exit_in_use_or_without_ipv4_at_the_exit_ipv4_is_dropped() {
    let mut p = pair().await;
    recv(&mut p.from_exit).await;
    let mine4 = p.mine4.unwrap();
    p.client.set_exit(None);
    p.client.packet_in(&v4(mine4, web(), 1, &[0; 8]));
    p.client.packet_in(&echo(p.mine, outside(), 1));
    let reply = recv(&mut p.from_client).await;
    assert_eq!(
        (reply[0] >> 4, reply[40]),
        (6, 1),
        "only the IPv6 is answered"
    );
    assert!(p.from_exit.packets.try_recv().is_err());

    let mut off = pair_with(
        "ipv4 = false
",
    )
    .await;
    recv(&mut off.from_exit).await;
    assert_eq!(off.client.exit_in_use().unwrap().ipv4, None);
    let home = off.client.home_ipv4();
    off.client.packet_in(&v4(home, web(), 1, &[0; 8]));
    let ok = echo(off.mine, outside(), 2);
    off.client.packet_in(&ok);
    assert_eq!(recv(&mut off.from_exit).await, ok);
    for q in [p, off] {
        q.client.stop_async().await;
        q.exit.stop_async().await;
    }
}

#[tokio::test]
async fn the_tunnel_reports_the_exit_in_use_with_the_addresses_the_host_configures() {
    let p = pair().await;
    let used = p.client.exit_in_use().expect("an exit is in use");
    assert_eq!(used.site, site("it/home"));
    assert_eq!(used.via.to_base32(), p.exit_key);
    assert_eq!(used.addr, p.mine);
    assert_eq!(used.ipv4, Some(p.client.home_ipv4()));
    assert_eq!(
        used.via_addr.octets()[..6],
        p.mine.octets()[..6],
        "the exit's overlay address is in the network's /48"
    );
    p.client.set_exit(None);
    assert_eq!(p.client.exit_in_use(), None);
    p.client.stop_async().await;
    p.exit.stop_async().await;
}

#[tokio::test]
async fn the_offers_learned_are_reported_and_taken_back_after_a_restart() {
    let p = pair().await;
    let mut offers = None;
    for _ in 0..100 {
        offers = p
            .from_client
            .events
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|e| e["type"] == "exits")
            .map(|e| e["offers"].to_string());
        if offers.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let offers = vardevall_tun::embed::exits_from_json(&offers.expect("an exits event")).unwrap();
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].0.to_base32(), p.exit_key);
    assert_eq!(offers[0].1, site("it/home"));
    p.client.stop_async().await;
    p.exit.stop_async().await;
}

/// A resolver on loopback that notes the queries it gets; if it is `answering`, every name has
/// the A record of [`web`] and no AAAA record.
struct Upstream {
    addr: std::net::SocketAddr,
    seen: Arc<Mutex<Vec<(u16, String, TYPE)>>>,
}

async fn upstream(answering: bool) -> Upstream {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let notes = seen.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let q = Packet::parse(&buf[..n]).unwrap();
            let qs = &q.questions[0];
            let QTYPE::TYPE(kind) = qs.qtype else {
                continue;
            };
            notes
                .lock()
                .unwrap()
                .push((q.id(), qs.qname.to_string(), kind));
            if !answering {
                continue;
            }
            let mut r = q.into_reply();
            if kind == TYPE::A {
                let name = r.questions[0].qname.clone();
                r.answers.push(ResourceRecord::new(
                    name,
                    CLASS::IN,
                    60,
                    RData::A(A::from(web())),
                ));
            }
            let _ = sock.send_to(&r.build_bytes_vec().unwrap(), from).await;
        }
    });
    Upstream { addr, seen }
}

fn dns_query(id: u16, name: &str, kind: TYPE) -> Vec<u8> {
    let mut p = Packet::new_query(id);
    p.questions.push(Question::new(
        Name::new(name).unwrap(),
        QTYPE::TYPE(kind),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    p.build_bytes_vec().unwrap()
}

/// What the exit's host does with the packets it is handed: DNS queries to the exit's own
/// address are answered by its responder, as `serve_udp` does on a host with a socket for it.
fn serve_dns_at_exit(exit: &Arc<Tunnel>, from_exit: Sink, upstream: std::net::SocketAddr) {
    let (exit, mut packets) = (exit.clone(), from_exit.packets);
    let forwarder = Arc::new(Forwarder::new(
        vec![upstream],
        tokio::runtime::Handle::current(),
    ));
    tokio::spawn(async move {
        while let Some(packet) = packets.recv().await {
            let Some(q) = dns::intercept(&packet, exit.responder().own_addrs()) else {
                continue;
            };
            let Reply::Relay(r) = exit.responder().respond_from(&q.message, Some(&q.client)) else {
                continue;
            };
            let exit = exit.clone();
            forwarder.relay(r, move |a| exit.packet_in(&dns::reply_packet(&q, &a)));
        }
    });
}

/// The DNS message of a packet the client's host receives from the resolver.
fn dns_reply(packet: &[u8]) -> (u16, Vec<u8>) {
    let h = packet::parse(packet).unwrap();
    let u = packet::parse_udp(packet, &h, true).unwrap();
    assert_eq!(u.src_port, 53);
    (u.dst_port, u.payload.to_vec())
}

/// The client's host asks its tunnel's resolver `name`, from `port`.
fn host_asks(p: &Pair, port: u16, id: u16, name: &str, kind: TYPE) {
    let q = dns_query(id, name, kind);
    p.client
        .packet_in(&packet::build_udp(&p.mine, &p.own, port, 53, &q));
}

async fn nothing_arrives(sink: &mut Sink) {
    assert!(
        tokio::time::timeout(Duration::from_millis(300), sink.packets.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_name_outside_the_overlay_domain_is_relayed_to_the_exit_through_the_engine() {
    let up = upstream(true).await;
    let mut p = pair().await;
    serve_dns_at_exit(
        &p.exit,
        std::mem::replace(&mut p.from_exit, callbacks().1),
        up.addr,
    );

    host_asks(&p, 40_000, 0x1111, "example.com", TYPE::A);
    let (port, bytes) = dns_reply(&recv(&mut p.from_client).await);
    let answer = Packet::parse(&bytes).unwrap();
    assert_eq!((port, answer.id()), (40_000, 0x1111));
    assert_eq!(answer.answers.len(), 1);
    assert!(matches!(&answer.answers[0].rdata, RData::A(a) if Ipv4Addr::from(a.address) == web()));
    assert_eq!(
        *up.seen.lock().unwrap(),
        [(0x1111, "example.com".to_owned(), TYPE::A)],
        "the exit's resolver asked its upstream; the client's own sockets were not used"
    );
    p.client.stop_async().await;
    p.exit.stop_async().await;
}

#[tokio::test]
async fn an_aaaa_query_is_relayed_as_it_is_with_nothing_synthesised() {
    let up = upstream(true).await;
    let mut p = pair().await;
    serve_dns_at_exit(
        &p.exit,
        std::mem::replace(&mut p.from_exit, callbacks().1),
        up.addr,
    );

    host_asks(&p, 40_001, 0x2222, "example.com", TYPE::AAAA);
    let (port, bytes) = dns_reply(&recv(&mut p.from_client).await);
    let answer = Packet::parse(&bytes).unwrap();
    assert_eq!((port, answer.id()), (40_001, 0x2222));
    assert!(answer.answers.is_empty(), "{answer:?}");
    let kinds: Vec<TYPE> = up.seen.lock().unwrap().iter().map(|s| s.2).collect();
    assert_eq!(kinds, [TYPE::AAAA]);
    p.client.stop_async().await;
    p.exit.stop_async().await;
}

#[tokio::test]
async fn at_most_eight_relays_are_pending_and_a_timeout_frees_the_slots() {
    let up = upstream(false).await;
    let mut p = pair().await;
    serve_dns_at_exit(
        &p.exit,
        std::mem::replace(&mut p.from_exit, callbacks().1),
        up.addr,
    );

    for i in 0..9 {
        host_asks(&p, 40_100 + i, i, &format!("n{i}.example.com"), TYPE::A);
    }
    for _ in 0..100 {
        if up.seen.lock().unwrap().len() >= 8 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let names = |up: &Upstream| -> Vec<String> {
        let mut n: Vec<_> = up
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.1.clone())
            .collect();
        n.sort();
        n
    };
    assert_eq!(
        names(&up),
        (0..8)
            .map(|i| format!("n{i}.example.com"))
            .collect::<Vec<_>>(),
        "the ninth was dropped"
    );

    tokio::time::sleep(Duration::from_millis(1700)).await;
    host_asks(&p, 40_200, 100, "late.example.com", TYPE::A);
    for _ in 0..100 {
        if up.seen.lock().unwrap().len() >= 9 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(names(&up).contains(&"late.example.com".to_owned()));
    nothing_arrives(&mut p.from_client).await;
    p.client.stop_async().await;
    p.exit.stop_async().await;
}

#[tokio::test]
async fn a_packet_from_the_resolver_port_that_answers_nothing_reaches_the_host() {
    let mut p = pair().await;
    let stray = packet::build_udp(
        &p.exit_ula,
        &p.own,
        53,
        5300,
        &dns_query(1, "example.com", TYPE::A),
    );
    p.exit.packet_in(&stray);
    assert_eq!(recv(&mut p.from_client).await, stray);
    p.client.stop_async().await;
    p.exit.stop_async().await;
}
