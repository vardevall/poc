use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use simple_dns::rdata::RData;
use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, TYPE};
use tokio::sync::mpsc;
use vardevall_tun::config::Context;
use vardevall_tun::embed::{
    Callbacks, StartError, StartOptions, Tunnel, event_from_json, path_update_from_json,
    request_to_json, tunnel_settings,
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

/// A UDP port for a node to listen on. The ports come from a range below the ephemeral one, in
/// sequence, so that no other test's ephemeral socket takes one between the check and the
/// node's bind.
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let start = 20_000 + (std::process::id() % 1000) as u16 * 20;
    loop {
        let port = start + NEXT.fetch_add(1, Ordering::Relaxed) % 20;
        if std::net::UdpSocket::bind(("::", port)).is_ok() {
            return port;
        }
    }
}

fn config(
    me: &Side,
    net: &str,
    port: u16,
    peer: &Side,
    endpoint: Option<u16>,
    extra: &str,
) -> String {
    let ep = endpoint
        .map(|p| format!("endpoint = \"127.0.0.1:{p}\"\n"))
        .unwrap_or_default();
    format!(
        "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{net}\"\nlisten_port = {port}\nmdns = false\nname = \"{}\"\n{extra}\n[[peer]]\npublic_key = \"{}\"\nname = \"{}\"\n{ep}",
        me.secret,
        if endpoint.is_some() { "alpha" } else { "beta" },
        peer.public,
        if endpoint.is_some() { "beta" } else { "alpha" },
    )
}

struct Running {
    tunnel: Tunnel,
    packets: mpsc::UnboundedReceiver<Vec<u8>>,
    events: Arc<Mutex<Vec<Value>>>,
    mdns: Arc<Mutex<Vec<Value>>>,
}

fn start(text: &str, external_mdns: bool) -> Running {
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
    let tunnel = Tunnel::start(
        &tokio::runtime::Handle::current(),
        text,
        StartOptions {
            interface_name: "test".into(),
            ..StartOptions::default()
        },
        callbacks,
    )
    .unwrap();
    Running {
        tunnel,
        packets,
        events,
        mdns,
    }
}

async fn recv(r: &mut Running) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(10), r.packets.recv())
        .await
        .expect("timed out")
        .expect("closed")
}

struct Pair {
    a: Running,
    b: Running,
    a_ula: Ipv6Addr,
    b_ula: Ipv6Addr,
}

fn pair() -> Pair {
    let net = keys::generate_network_secret();
    let (sa, sb) = (side(), side());
    let (pa, pb) = (free_port(), free_port());
    let a = start(&config(&sa, &net, pa, &sb, Some(pb), ""), false);
    let b = start(&config(&sb, &net, pb, &sa, None, ""), false);
    let id = keys::network_id(&net).unwrap();
    Pair {
        a_ula: keys::overlay_addrs(&sa.public, &id).unwrap().ula,
        b_ula: keys::overlay_addrs(&sb.public, &id).unwrap().ula,
        a,
        b,
    }
}

fn echo(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    packet::build_icmpv6(&src, &dst, 128, 0, &[0, 1, 0, 1, 0xde, 0xad], 64)
}

#[tokio::test]
async fn packets_cross_between_two_tunnels() {
    let mut p = pair();
    let req = echo(p.a_ula, p.b_ula);
    p.a.tunnel.packet_in(&req);
    assert_eq!(recv(&mut p.b).await, req);
    let rep = echo(p.b_ula, p.a_ula);
    p.b.tunnel.packet_in(&rep);
    assert_eq!(recv(&mut p.a).await, rep);

    let link_local = keys::overlay_addrs(
        &p.b.tunnel.config().public_key.to_base32(),
        &p.b.tunnel.config().network_id.to_base32(),
    )
    .unwrap()
    .link_local;
    let req = echo(p.a.tunnel.config().own_addrs().link_local, link_local);
    p.a.tunnel.packet_in(&req);
    assert_eq!(recv(&mut p.b).await, req);

    let events = p.a.events.lock().unwrap().clone();
    assert!(
        events
            .iter()
            .any(|e| e["type"] == "status" && e["state"] == "started")
    );
    assert!(
        events
            .iter()
            .any(|e| e["type"] == "peer" && e["state"] == "up" && e["name"] == "beta")
    );
    assert!(events.iter().all(|e| e["network"] == "test"));
    p.a.tunnel.stop_async().await;
    p.b.tunnel.stop_async().await;
}

#[tokio::test]
async fn path_updates_are_accepted_while_traffic_flows() {
    let net = keys::generate_network_secret();
    let (sa, sb) = (side(), side());
    let (pa, pb) = (free_port(), free_port());
    let a = start(&config(&sa, &net, pa, &sb, Some(pb), ""), false);
    let mut b = start(&config(&sb, &net, pb, &sa, None, ""), false);
    let update = path_update_from_json(
        r#"{"metered":false,"interfaces":[{"name":"pdp_ip0","metered":true},{"name":"lo0","metered":false}]}"#,
    )
    .unwrap();
    a.tunnel.path_update(&update);
    b.tunnel.path_update(&update);
    let id = keys::network_id(&net).unwrap();
    let a_ula = keys::overlay_addrs(&sa.public, &id).unwrap().ula;
    let b_ula = keys::overlay_addrs(&sb.public, &id).unwrap().ula;
    let req = echo(a_ula, b_ula);
    a.tunnel.packet_in(&req);
    assert_eq!(recv(&mut b).await, req);
    a.tunnel.stop_async().await;
    b.tunnel.stop_async().await;
}

#[tokio::test]
async fn multicast_reaches_peers_with_a_session() {
    let mut p = pair();
    let mdns: Ipv6Addr = "ff02::fb".parse().unwrap();
    let ll = p.a.tunnel.config().own_addrs().link_local;
    let query = packet::build_udp(&ll, &mdns, 5353, 5353, b"mdns");
    p.a.tunnel.packet_in(&query);
    p.a.tunnel.packet_in(&echo(p.a_ula, p.b_ula));
    assert_eq!(recv(&mut p.b).await[..4], echo(p.a_ula, p.b_ula)[..4]);
    tokio::time::sleep(Duration::from_millis(300)).await;
    p.a.tunnel.packet_in(&query);
    let got = recv(&mut p.b).await;
    assert_eq!(got, query);
    let ns = packet::build_icmpv6(
        &ll,
        &"ff02::1:ff00:1".parse().unwrap(),
        135,
        0,
        &[0; 20],
        255,
    );
    p.a.tunnel.packet_in(&ns);
    p.a.tunnel.packet_in(&echo(p.a_ula, p.b_ula));
    let next = recv(&mut p.b).await;
    assert_eq!(next[40], 128, "neighbour solicitation must not cross");
}

#[tokio::test]
async fn unknown_addresses_get_icmp_unreachable() {
    let mut p = pair();
    let stranger: Ipv6Addr = {
        let mut o = p.b_ula.octets();
        o[15] ^= 0xff;
        o[14] ^= 0x55;
        Ipv6Addr::from(o)
    };
    p.a.tunnel.packet_in(&echo(p.a_ula, stranger));
    let reply = recv(&mut p.a).await;
    let h = packet::parse(&reply).unwrap();
    assert_eq!(h.next, packet::ICMPV6);
    assert_eq!((reply[40], reply[41]), (1, 3));
}

#[tokio::test]
async fn dns_queries_to_the_own_address_are_answered() {
    let mut p = pair();
    let mut q = Packet::new_query(7);
    let fqdn = format!("beta.{}", p.a.tunnel.config().domain);
    q.questions.push(Question::new(
        Name::new(&fqdn).unwrap(),
        QTYPE::TYPE(TYPE::AAAA),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let msg = q.build_bytes_vec().unwrap();
    let client: Ipv6Addr = p.a_ula;
    let pkt = packet::build_udp(&client, &p.a_ula, 40000, 53, &msg);
    p.a.tunnel.packet_in(&pkt);
    let reply = recv(&mut p.a).await;
    let h = packet::parse(&reply).unwrap();
    let u = packet::parse_udp(&reply, &h, true).unwrap();
    assert_eq!((u.src_port, u.dst_port), (53, 40000));
    let parsed = Packet::parse(u.payload).unwrap();
    let RData::AAAA(a) = &parsed.answers[0].rdata else {
        panic!()
    };
    assert_eq!(Ipv6Addr::from(a.address), p.b_ula);

    let settings = p.a.tunnel.settings();
    assert_eq!(settings.dns.servers, vec![p.a_ula]);
}

#[tokio::test]
async fn external_mdns_round_trip_through_json() {
    let net = keys::generate_network_secret();
    let (sa, sb) = (side(), side());
    let (pa, pb) = (free_port(), free_port());
    let mdns_on = "mdns = true";
    let strip = |s: String| s.replace("mdns = false\n", "");
    let a = start(&strip(config(&sa, &net, pa, &sb, None, mdns_on)), true);
    let mut b = start(&strip(config(&sb, &net, pb, &sa, None, mdns_on)), true);
    let id = keys::network_id(&net).unwrap();
    let a_ula = keys::overlay_addrs(&sa.public, &id).unwrap().ula;
    let b_ula = keys::overlay_addrs(&sb.public, &id).unwrap().ula;

    tokio::time::sleep(Duration::from_millis(100)).await;
    let register_of = |r: &Running| {
        r.mdns
            .lock()
            .unwrap()
            .iter()
            .find(|v| v["op"] == "register")
            .cloned()
            .expect("register request")
    };
    let found_from = |reg: &Value| {
        let mut f = reg.clone();
        f["op"] = "found".into();
        f.as_object_mut().unwrap().remove("type");
        f["addrs"] = serde_json::json!(["127.0.0.1"]);
        f["ifindex"] = 1.into();
        f.to_string()
    };
    assert_eq!(register_of(&a)["type"], "_vardevall._udp");
    assert!(a.mdns.lock().unwrap().iter().any(|v| v["op"] == "browse"));
    let to_b = found_from(&register_of(&a));
    let to_a = found_from(&register_of(&b));
    b.tunnel.mdns_event(event_from_json(&to_b).unwrap());
    a.tunnel.mdns_event(event_from_json(&to_a).unwrap());

    let req = echo(a_ula, b_ula);
    a.tunnel.packet_in(&req);
    assert_eq!(recv(&mut b).await, req);

    a.tunnel.stop_async().await;
    let reqs = a.mdns.lock().unwrap().clone();
    assert!(reqs.iter().any(|v| v["op"] == "unregister"));
    assert_eq!(reqs.last().unwrap()["op"], "stop_browse");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_callbacks_after_stop() {
    let mut p = pair();
    p.a.tunnel.packet_in(&echo(p.a_ula, p.b_ula));
    recv(&mut p.b).await;

    let count = Arc::new(Mutex::new(0usize));
    let (b_events, b_tunnel) = (p.b.events.clone(), p.b.tunnel);
    let stopper = tokio::task::spawn_blocking(move || {
        b_tunnel.stop();
        b_tunnel
    });
    let b_tunnel = stopper.await.unwrap();
    let after = b_events.lock().unwrap().len();
    *count.lock().unwrap() = after;
    let last = b_events.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        (last["type"].as_str(), last["state"].as_str()),
        (Some("status"), Some("stopped"))
    );

    p.a.tunnel.packet_in(&echo(p.a_ula, p.b_ula));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(b_events.lock().unwrap().len(), after);
    assert!(p.b.packets.try_recv().is_err());
    b_tunnel.stop();
    p.a.tunnel.stop_async().await;
}

#[tokio::test]
async fn stop_from_inside_a_callback_suppresses_later_callbacks() {
    let net = keys::generate_network_secret();
    let (sa, sb) = (side(), side());
    let text = config(&sa, &net, free_port(), &sb, None, "");
    let slot: Arc<Mutex<Option<Arc<Tunnel>>>> = Arc::new(Mutex::new(None));
    let calls = Arc::new(Mutex::new(0usize));
    let (s2, c2) = (slot.clone(), calls.clone());
    let tunnel = Arc::new(
        Tunnel::start(
            &tokio::runtime::Handle::current(),
            &text,
            StartOptions::default(),
            Callbacks {
                packets: Box::new(|_| {}),
                event: Box::new(move |_, _| {
                    *c2.lock().unwrap() += 1;
                    if let Some(t) = s2.lock().unwrap().as_ref() {
                        t.stop();
                    }
                }),
                mdns: None,
            },
        )
        .unwrap(),
    );
    *slot.lock().unwrap() = Some(tunnel.clone());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let n = *calls.lock().unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(*calls.lock().unwrap(), n);
    assert!(n >= 1);
    slot.lock().unwrap().take();
}

#[tokio::test]
async fn bad_configuration_does_not_start() {
    let r = Tunnel::start(
        &tokio::runtime::Handle::current(),
        "[interface]\n",
        StartOptions::default(),
        Callbacks {
            packets: Box::new(|_| {}),
            event: Box::new(|_, _| {}),
            mdns: None,
        },
    );
    assert!(matches!(r, Err(StartError::Config(_))));
}

#[test]
fn settings_without_starting() {
    let (me, other) = (side(), side());
    let net = keys::generate_network_secret();
    let s = tunnel_settings(&config(&me, &net, 0, &other, None, ""), &Context::default()).unwrap();
    assert_eq!(s.addrs.len(), 2);
    assert!(tunnel_settings("nonsense", &Context::default()).is_err());
}

async fn dns(r: &mut Running, own: Ipv6Addr, name: &str, qtype: TYPE) -> Vec<u8> {
    let mut q = Packet::new_query(9);
    q.questions.push(Question::new(
        Name::new(name).unwrap(),
        QTYPE::TYPE(qtype),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    r.tunnel.packet_in(&packet::build_udp(
        &own,
        &own,
        40000,
        53,
        &q.build_bytes_vec().unwrap(),
    ));
    let reply = recv(r).await;
    let h = packet::parse(&reply).unwrap();
    packet::parse_udp(&reply, &h, true)
        .unwrap()
        .payload
        .to_vec()
}

async fn providers_of(r: &Running, service: &str, count: usize) -> Value {
    for _ in 0..100 {
        let v: Value = serde_json::from_str(&r.tunnel.providers_json(service)).unwrap();
        if v.as_array().is_some_and(|a| a.len() == count) {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("providers of {service} never reached {count}");
}

#[tokio::test]
async fn services_are_announced_listed_and_resolved() {
    use vardevall_tun::embed::Proto;

    let net = keys::generate_network_secret();
    let (sa, sb) = (side(), side());
    let (pa, pb) = (free_port(), free_port());
    let service = "[[service]]\nname = \"web\"\nport = 8080\n";
    let a = start(&config(&sa, &net, pa, &sb, Some(pb), service), false);
    let mut b = start(&config(&sb, &net, pb, &sa, None, ""), false);
    let id = keys::network_id(&net).unwrap();
    let a_ula = keys::overlay_addrs(&sa.public, &id).unwrap().ula;
    let b_ula = keys::overlay_addrs(&sb.public, &id).unwrap().ula;
    a.tunnel.packet_in(&echo(a_ula, b_ula));
    recv(&mut b).await;

    let list = providers_of(&b, "web", 1).await;
    assert_eq!(list[0]["key"], sa.public);
    assert_eq!(list[0]["port"], 8080);
    assert_eq!(list[0]["proto"], "tcp");
    assert_eq!(list[0]["live"], true);
    assert_eq!(list[0]["name"], "alpha");
    assert_eq!(list[0]["addr"], a_ula.to_string());

    let domain = b.tunnel.config().domain.clone();
    let bytes = dns(&mut b, b_ula, &format!("web.{domain}"), TYPE::AAAA).await;
    let p = Packet::parse(&bytes).unwrap();
    let RData::AAAA(x) = &p.answers[0].rdata else {
        panic!()
    };
    assert_eq!((Ipv6Addr::from(x.address), p.answers[0].ttl), (a_ula, 10));
    let bytes = dns(&mut b, b_ula, &format!("_web._tcp.{domain}"), TYPE::SRV).await;
    let p = Packet::parse(&bytes).unwrap();
    let RData::SRV(srv) = &p.answers[0].rdata else {
        panic!()
    };
    assert_eq!(
        (srv.priority, srv.port, srv.target.to_string()),
        (0, 8080, format!("alpha.{domain}"))
    );

    b.tunnel.announce("db", 5432, Proto::Tcp).unwrap();
    assert!(b.tunnel.announce("Bad Name", 1, Proto::Tcp).is_err());
    let list = providers_of(&a, "db", 1).await;
    assert_eq!(list[0]["key"], sb.public);
    assert!(a.tunnel.withdraw("web"));
    assert!(!a.tunnel.withdraw("web"));
    providers_of(&b, "web", 0).await;
    let bytes = dns(&mut b, b_ula, &format!("web.{domain}"), TYPE::AAAA).await;
    assert_eq!(
        Packet::parse(&bytes).unwrap().rcode(),
        simple_dns::RCODE::NameError
    );
    a.tunnel.stop_async().await;
    b.tunnel.stop_async().await;
}

#[tokio::test]
async fn switch_events_say_how_the_switch_is_addressed() {
    let net = keys::generate_network_secret();
    let (sa, sb) = (side(), side());
    let key = keys::public_key(&keys::generate_node_key()).unwrap();
    let extra = format!(
        "[[switch]]\naddress = \"{key}@127.0.0.1:9\"\n[[switch]]\naddress = \"switch.invalid:9\"\n"
    );
    let r = start(&config(&sa, &net, free_port(), &sb, None, &extra), false);
    for _ in 0..100 {
        let seen = r
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e["type"] == "switch")
            .count();
        if seen >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let events = r.events.lock().unwrap().clone();
    let auth = |address: &str| {
        events
            .iter()
            .find(|e| e["type"] == "switch" && e["address"] == address)
            .map(|e| e["auth"].clone())
    };
    assert_eq!(auth("127.0.0.1:9"), Some(Value::from("pinned")));
    assert_eq!(auth("switch.invalid:9"), Some(Value::from("web")));
    r.tunnel.stop_async().await;
}

#[tokio::test]
async fn a_batch_of_packets_crosses_in_order() {
    let mut p = pair();
    let sent: Vec<Vec<u8>> = (0..20u8)
        .map(|i| packet::build_icmpv6(&p.a_ula, &p.b_ula, 128, 0, &[i, 0, 0, 1, 0xbe, 0xef], 64))
        .collect();
    p.a.tunnel.packets_in(sent.iter().map(Vec::as_slice));
    for want in &sent {
        assert_eq!(&recv(&mut p.b).await, want);
    }
}
