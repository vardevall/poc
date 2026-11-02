//! Several networks behind one tunnel device, each a real node on loopback.

use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, RCODE, TYPE, rdata::RData};
use tokio::sync::mpsc;
use vardevall_tun::embed::{
    Callbacks, NetworkError, NetworkSpec, Networks, Proto, StartError, StartOptions, Tunnel,
    event_from_json, request_to_json, tunnel_settings_networks,
};
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

/// A UDP port for a node to listen on, from a range of its own so that no other test's socket
/// takes it between the check and the node's bind.
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let start = 21_000 + (std::process::id() % 50) as u16 * 100;
    loop {
        let port = start + NEXT.fetch_add(1, Ordering::Relaxed) % 100;
        if std::net::UdpSocket::bind(("::", port)).is_ok() {
            return port;
        }
    }
}

fn config(
    me: &Side,
    net: &str,
    port: u16,
    peer: (&Side, &str, Option<u16>),
    extra: &str,
) -> String {
    let (peer, peer_name, endpoint) = peer;
    let ep = endpoint
        .map(|p| format!("endpoint = \"127.0.0.1:{p}\"\n"))
        .unwrap_or_default();
    format!(
        "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{net}\"\nlisten_port = {port}\n{extra}\n[[peer]]\npublic_key = \"{}\"\nname = \"{peer_name}\"\n{ep}",
        me.secret, peer.public,
    )
}

fn ula(of: &Side, net: &str) -> Ipv6Addr {
    let id = keys::network_id(net).unwrap();
    keys::overlay_addrs(&of.public, &id).unwrap().ula
}

fn echo(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    packet::build_icmpv6(&src, &dst, 128, 0, &[0, 1, 0, 1, 0xde, 0xad], 64)
}

struct Sink {
    packets: mpsc::UnboundedReceiver<Vec<u8>>,
    events: Arc<Mutex<Vec<Value>>>,
    mdns: Arc<Mutex<Vec<Value>>>,
}

fn callbacks(external_mdns: bool) -> (Callbacks, Sink) {
    let (ptx, packets) = mpsc::unbounded_channel();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mdns = Arc::new(Mutex::new(Vec::new()));
    let (e, m) = (events.clone(), mdns.clone());
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
        mdns: external_mdns.then(|| {
            Box::new(move |r: &vardevall::MdnsRequest| {
                m.lock()
                    .unwrap()
                    .push(serde_json::from_str(&request_to_json(r)).unwrap());
            }) as Box<dyn FnMut(&vardevall::MdnsRequest) + Send>
        }),
    };
    (
        callbacks,
        Sink {
            packets,
            events,
            mdns,
        },
    )
}

fn single(text: &str) -> (Tunnel, Sink) {
    let (callbacks, sink) = callbacks(false);
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

fn spec(name: &str, text: String) -> NetworkSpec {
    NetworkSpec {
        name: name.into(),
        config_toml: text,
    }
}

/// Two networks, `home` and `work`, each with a peer called `beta` on a tunnel of its own.
struct Rig {
    nets: Networks,
    sink: Sink,
    home: (Tunnel, Sink),
    work: (Tunnel, Sink),
    home_ula: Ipv6Addr,
    work_ula: Ipv6Addr,
    home_beta: Ipv6Addr,
    work_beta: Ipv6Addr,
}

fn rig(extra: &str, external_mdns: bool) -> Rig {
    let (s_home, s_work) = (
        keys::generate_network_secret(),
        keys::generate_network_secret(),
    );
    let (me_home, me_work, beta_home, beta_work) = (side(), side(), side(), side());
    let (p_me_home, p_me_work, p_beta_home, p_beta_work) =
        (free_port(), free_port(), free_port(), free_port());
    let home_cfg = config(
        &me_home,
        &s_home,
        p_me_home,
        (&beta_home, "beta", Some(p_beta_home)),
        &format!("name = \"alpha\"\nmtu = 1500\n{extra}"),
    );
    let work_cfg = config(
        &me_work,
        &s_work,
        p_me_work,
        (&beta_work, "beta", Some(p_beta_work)),
        &format!("name = \"alpha\"\nmtu = 1400\n{extra}"),
    );
    let home = single(&config(
        &beta_home,
        &s_home,
        p_beta_home,
        (&me_home, "alpha", None),
        "mdns = false\n",
    ));
    let work = single(&config(
        &beta_work,
        &s_work,
        p_beta_work,
        (&me_work, "alpha", None),
        "mdns = false\n",
    ));
    let (callbacks, sink) = callbacks(external_mdns);
    let nets = Networks::start(
        &tokio::runtime::Handle::current(),
        vec![spec("home", home_cfg), spec("work", work_cfg)],
        StartOptions::default(),
        callbacks,
    )
    .unwrap();
    Rig {
        nets,
        sink,
        home,
        work,
        home_ula: ula(&me_home, &s_home),
        work_ula: ula(&me_work, &s_work),
        home_beta: ula(&beta_home, &s_home),
        work_beta: ula(&beta_work, &s_work),
    }
}

impl Rig {
    async fn stop(self) {
        self.nets.stop_async().await;
        self.home.0.stop_async().await;
        self.work.0.stop_async().await;
    }
}

fn question(name: &str, qtype: TYPE) -> Vec<u8> {
    let mut q = Packet::new_query(9);
    q.questions.push(Question::new(
        Name::new(name).unwrap(),
        QTYPE::TYPE(qtype),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    q.build_bytes_vec().unwrap()
}

/// Sends a DNS query to `server` and returns the source of the reply and the answer.
async fn ask(r: &mut Rig, server: Ipv6Addr, name: &str, qtype: TYPE) -> (Ipv6Addr, Vec<u8>) {
    let client = r.home_ula;
    let query = packet::build_udp(&client, &server, 40000, 53, &question(name, qtype));
    r.nets.packet_in(&query);
    let reply = recv(&mut r.sink).await;
    let h = packet::parse(&reply).unwrap();
    let u = packet::parse_udp(&reply, &h, true).unwrap();
    assert_eq!((u.src_port, u.dst_port), (53, 40000));
    (h.src, u.payload.to_vec())
}

fn first_aaaa(message: &[u8]) -> Ipv6Addr {
    let p = Packet::parse(message).unwrap();
    let RData::AAAA(a) = &p.answers[0].rdata else {
        panic!("not an AAAA answer")
    };
    Ipv6Addr::from(a.address)
}

#[tokio::test]
async fn packets_go_to_the_network_that_holds_the_destination() {
    let mut r = rig("mdns = false\n", false);
    r.nets.packet_in(&echo(r.home_ula, r.home_beta));
    r.nets.packet_in(&echo(r.work_ula, r.work_beta));
    assert_eq!(recv(&mut r.home.1).await, echo(r.home_ula, r.home_beta));
    assert_eq!(recv(&mut r.work.1).await, echo(r.work_ula, r.work_beta));
    assert!(r.home.1.packets.try_recv().is_err());
    assert!(r.work.1.packets.try_recv().is_err());

    let stranger = |of: Ipv6Addr| {
        let mut o = of.octets();
        o[15] ^= 0xff;
        o[14] ^= 0x55;
        Ipv6Addr::from(o)
    };
    let source: Ipv6Addr = "fd00::1".parse().unwrap();
    for (own, near) in [(r.home_ula, r.home_beta), (r.work_ula, r.work_beta)] {
        r.nets.packet_in(&echo(source, stranger(near)));
        let reply = recv(&mut r.sink).await;
        assert_eq!(packet::parse(&reply).unwrap().src, own);
        assert_eq!((reply[40], reply[41]), (1, 3));
    }

    r.nets
        .packet_in(&echo(source, "2001:db8::1".parse().unwrap()));
    let reply = recv(&mut r.sink).await;
    assert_eq!(packet::parse(&reply).unwrap().src, r.home_ula);
    assert_eq!((reply[40], reply[41]), (1, 0));
    r.stop().await;
}

#[tokio::test]
async fn each_domain_is_answered_by_its_network_from_the_one_resolver_address() {
    let mut r = rig("mdns = false\n", false);
    let resolver = r.home_ula;
    let (src, a) = ask(&mut r, resolver, "beta.home.internal", TYPE::AAAA).await;
    assert_eq!((src, first_aaaa(&a)), (resolver, r.home_beta));
    let (src, a) = ask(&mut r, resolver, "beta.work.internal", TYPE::AAAA).await;
    assert_eq!((src, first_aaaa(&a)), (resolver, r.work_beta));

    let ptr = vardevall_proto::addr::ptr_name(&r.work_beta);
    let (src, a) = ask(&mut r, resolver, &ptr, TYPE::PTR).await;
    assert_eq!(src, resolver);
    let p = Packet::parse(&a).unwrap();
    let RData::PTR(target) = &p.answers[0].rdata else {
        panic!("not a PTR answer")
    };
    assert_eq!(target.0.to_string(), "beta.work.internal");

    let (src, a) = ask(&mut r, resolver, "beta.example.org", TYPE::AAAA).await;
    assert_eq!(src, resolver);
    assert_eq!(Packet::parse(&a).unwrap().rcode(), RCODE::Refused);

    let work = r.work_ula;
    let (src, a) = ask(&mut r, work, "beta.work.internal", TYPE::AAAA).await;
    assert_eq!((src, first_aaaa(&a)), (work, r.work_beta));
    let (src, a) = ask(&mut r, work, "beta.home.internal", TYPE::AAAA).await;
    assert_eq!(src, work);
    assert_eq!(Packet::parse(&a).unwrap().rcode(), RCODE::Refused);
    r.stop().await;
}

#[tokio::test]
async fn the_settings_of_the_set_merge_those_of_its_networks() {
    let r = rig("mdns = false\n", false);
    let s = r.nets.settings();
    let (home, work) = (
        r.nets.config(Some("home")).unwrap(),
        r.nets.config(Some("work")).unwrap(),
    );
    assert_eq!(s.addrs.len(), 4);
    assert_eq!(
        [
            s.addrs[0].addr,
            s.addrs[1].addr,
            s.addrs[2].addr,
            s.addrs[3].addr
        ],
        [
            r.home_ula,
            home.own_addrs().link_local,
            r.work_ula,
            work.own_addrs().link_local,
        ]
    );
    assert_eq!(s.routes.len(), 2);
    assert_eq!(s.mtu, 1400);
    assert_eq!(s.dns.servers, vec![r.home_ula]);
    assert_eq!(
        s.dns.match_domains,
        [
            home.domain.clone(),
            vardevall_proto::addr::reverse_zone(&home.network_id),
            work.domain.clone(),
            vardevall_proto::addr::reverse_zone(&work.network_id),
        ]
    );
    assert_eq!(home.domain, "home.internal");
    assert_eq!(work.domain, "work.internal");
    assert!(r.nets.listen_port(Some("work")).is_some());
    assert!(r.nets.listen_port(Some("none")).is_none());
    r.stop().await;
}

#[tokio::test]
async fn settings_without_starting_match_the_running_ones() {
    let (a, b) = (side(), side());
    let (na, nb) = (
        keys::generate_network_secret(),
        keys::generate_network_secret(),
    );
    let specs = vec![
        spec("one", config(&a, &na, 0, (&b, "x", None), "")),
        spec("two", config(&b, &nb, 0, (&a, "y", None), "")),
    ];
    let s = tunnel_settings_networks(&specs).unwrap();
    assert_eq!(s.addrs.len(), 4);
    assert_eq!(s.dns.servers, vec![ula(&a, &na)]);
    assert_eq!(s.dns.match_domains[0], "one.internal");
    assert_eq!(s.dns.match_domains[2], "two.internal");
    assert!(tunnel_settings_networks(&[]).is_err());
}

#[tokio::test]
async fn events_name_their_network() {
    let mut r = rig("mdns = false\n", false);
    r.nets.packet_in(&echo(r.home_ula, r.home_beta));
    recv(&mut r.home.1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = r.sink.events.lock().unwrap().clone();
    assert!(
        events
            .iter()
            .all(|e| matches!(e["network"].as_str(), Some("home" | "work")))
    );
    for net in ["home", "work"] {
        assert!(
            events
                .iter()
                .any(|e| e["type"] == "status" && e["state"] == "started" && e["network"] == net),
            "{net} started"
        );
    }
    assert!(
        events
            .iter()
            .any(|e| e["type"] == "peer" && e["state"] == "up" && e["network"] == "home")
    );
    assert!(
        !events
            .iter()
            .any(|e| e["type"] == "peer" && e["state"] == "up" && e["network"] == "work")
    );
    r.stop().await;
}

#[tokio::test]
async fn the_host_sees_one_browse_and_one_stop_browse() {
    let r = rig("mdns = true\n", true);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let ops = |r: &Rig| -> Vec<String> {
        r.sink
            .mdns
            .lock()
            .unwrap()
            .iter()
            .map(|v| v["op"].as_str().unwrap().to_owned())
            .collect()
    };
    let count = |ops: &[String], op: &str| ops.iter().filter(|o| *o == op).count();
    let seen = ops(&r);
    assert_eq!((count(&seen, "browse"), count(&seen, "register")), (1, 2));
    let instances: Vec<Value> = r
        .sink
        .mdns
        .lock()
        .unwrap()
        .iter()
        .filter(|v| v["op"] == "register")
        .map(|v| v["instance"].clone())
        .collect();
    assert_ne!(
        instances[0], instances[1],
        "two networks, one instance name"
    );

    let found = event_from_json(r#"{"op":"lost","instance":"x"}"#).unwrap();
    r.nets.mdns_event(found);
    let mdns = r.sink.mdns.clone();
    let (nets, home, work) = (r.nets, r.home.0, r.work.0);
    nets.stop_async().await;
    let seen: Vec<String> = mdns
        .lock()
        .unwrap()
        .iter()
        .map(|v| v["op"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(count(&seen, "stop_browse"), 1);
    assert_eq!(count(&seen, "unregister"), 2);
    assert_eq!(seen.last().unwrap(), "stop_browse");
    home.stop_async().await;
    work.stop_async().await;
}

#[tokio::test]
async fn networks_with_the_same_id_are_refused() {
    let (a, b) = (side(), side());
    let net = keys::generate_network_secret();
    let r = Networks::start(
        &tokio::runtime::Handle::current(),
        vec![
            spec(
                "one",
                config(&a, &net, 0, (&b, "x", None), "mdns = false\n"),
            ),
            spec(
                "two",
                config(&b, &net, 0, (&a, "y", None), "mdns = false\n"),
            ),
        ],
        StartOptions::default(),
        callbacks(false).0,
    );
    assert!(matches!(
        r,
        Err(StartError::SameNetwork { first, second }) if (first.as_str(), second.as_str()) == ("one", "two")
    ));
}

#[tokio::test]
async fn the_set_of_names_is_checked() {
    let (a, b) = (side(), side());
    let net = keys::generate_network_secret();
    let text = config(&a, &net, 0, (&b, "x", None), "mdns = false\n");
    let try_start = |names: &[&str]| {
        Networks::start(
            &tokio::runtime::Handle::current(),
            names.iter().map(|n| spec(n, text.clone())).collect(),
            StartOptions::default(),
            callbacks(false).0,
        )
        .err()
    };
    let long = "a".repeat(52);
    assert!(matches!(try_start(&[]), Some(StartError::Networks(_))));
    assert!(matches!(
        try_start(&["Home"]),
        Some(StartError::Networks(_))
    ));
    assert!(matches!(
        try_start(&[long.as_str()]),
        Some(StartError::Networks(_))
    ));
    assert!(matches!(
        try_start(&["a", "a"]),
        Some(StartError::Networks(_))
    ));
    let nine: Vec<String> = (0..9).map(|i| format!("n{i}")).collect();
    let nine: Vec<&str> = nine.iter().map(String::as_str).collect();
    assert!(matches!(try_start(&nine), Some(StartError::Networks(_))));
    let bad = Networks::start(
        &tokio::runtime::Handle::current(),
        vec![spec("x", "[interface]\n".into())],
        StartOptions::default(),
        callbacks(false).0,
    );
    assert!(matches!(bad, Err(StartError::Network { name, .. }) if name == "x"));
}

#[tokio::test]
async fn services_belong_to_the_network_they_are_announced_in() {
    let r = rig("mdns = false\n", false);
    r.nets
        .announce(Some("work"), "db", 5432, Proto::Tcp)
        .unwrap();
    r.nets.announce(None, "web", 80, Proto::Tcp).unwrap();
    assert!(matches!(
        r.nets.announce(Some("none"), "db", 1, Proto::Tcp),
        Err(NetworkError::Unknown(_))
    ));
    assert!(matches!(
        r.nets.announce(None, "Bad Name", 1, Proto::Tcp),
        Err(NetworkError::Service(_))
    ));
    assert!(!r.nets.withdraw(Some("home"), "db"));
    assert!(r.nets.withdraw(Some("work"), "db"));
    assert!(r.nets.withdraw(Some("home"), "web"));
    assert!(r.nets.providers_json(Some("none"), "db").is_err());
    assert_eq!(r.nets.providers_json(None, "db").unwrap(), "[]");
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_callbacks_after_stop() {
    let mut r = rig("mdns = false\n", false);
    r.nets.packet_in(&echo(r.home_ula, r.home_beta));
    recv(&mut r.home.1).await;
    let events = r.sink.events.clone();
    let nets = Arc::new(r.nets);
    let stopper = nets.clone();
    tokio::task::spawn_blocking(move || stopper.stop())
        .await
        .unwrap();
    let after = events.lock().unwrap().len();
    let stopped: Vec<String> = events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == "status" && e["state"] == "stopped")
        .map(|e| e["network"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(stopped.len(), 2, "{stopped:?}");

    r.home.0.packet_in(&echo(r.home_beta, r.home_ula));
    r.work.0.packet_in(&echo(r.work_beta, r.work_ula));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(events.lock().unwrap().len(), after);
    assert!(r.sink.packets.try_recv().is_err());
    nets.stop();
    r.home.0.stop_async().await;
    r.work.0.stop_async().await;
}
