//! Applying a file read again to a running interface (`Tunnel::apply`).

use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc;
use vardevall_tun::config::{Config, Context};
use vardevall_tun::embed::{ApplyError, Callbacks, ExitUse, StartOptions, Tunnel};
use vardevall_tun::{keys, packet};

struct Node {
    secret: String,
    public: String,
    port: u16,
}

fn node(port: u16) -> Node {
    let secret = keys::generate_node_key();
    let public = keys::public_key(&secret).unwrap();
    Node {
        secret,
        public,
        port,
    }
}

fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let start = 23_000 + (std::process::id() % 1000) as u16 * 20;
    loop {
        let port = start + NEXT.fetch_add(1, Ordering::Relaxed) % 20;
        if std::net::UdpSocket::bind(("::", port)).is_ok() {
            return port;
        }
    }
}

fn file(me: &Node, net: &str, extra: &str, peers: &[(&Node, &str, bool)]) -> String {
    let mut s = format!(
        "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{net}\"\nlisten_port = {}\nmdns = false\n{extra}\n",
        me.secret, me.port
    );
    for (p, name, endpoint) in peers {
        s.push_str(&format!(
            "\n[[peer]]\npublic_key = \"{}\"\nname = \"{name}\"\n",
            p.public
        ));
        if *endpoint {
            s.push_str(&format!("endpoint = \"127.0.0.1:{}\"\n", p.port));
        }
    }
    s
}

fn ctx() -> Context {
    Context {
        interface_name: "test".into(),
        hostname: None,
    }
}

struct Running {
    tunnel: Tunnel,
    packets: mpsc::UnboundedReceiver<Vec<u8>>,
    events: Arc<Mutex<Vec<Value>>>,
}

fn start(text: &str) -> Running {
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
    }
}

async fn recv(r: &mut Running) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(10), r.packets.recv())
        .await
        .expect("timed out")
        .expect("closed")
}

fn echo(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
    packet::build_icmpv6(&src, &dst, 128, 0, &[0, 1, 0, 1, 0xde, 0xad], 64)
}

fn ula(key: &Node, net: &str) -> Ipv6Addr {
    keys::overlay_addrs(&key.public, &keys::network_id(net).unwrap())
        .unwrap()
        .ula
}

fn count(r: &Running, kind: &str, name: &str) -> usize {
    r.events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e["type"] == kind && e["name"] == name)
        .count()
}

#[tokio::test]
async fn a_file_read_again_adds_renames_and_removes_peers_without_touching_the_others() {
    let net = keys::generate_network_secret();
    let (a, b, c) = (node(free_port()), node(free_port()), node(free_port()));
    let run_a = start(&file(&a, &net, "", &[(&b, "beta", true)]));
    let mut run_b = start(&file(&b, &net, "", &[(&a, "alpha", false)]));
    let mut run_c = start(&file(&c, &net, "", &[(&a, "alpha", false)]));

    let req = echo(ula(&a, &net), ula(&b, &net));
    run_a.tunnel.packet_in(&req);
    assert_eq!(recv(&mut run_b).await, req);

    let renamed = file(&a, &net, "", &[(&b, "bee", true), (&c, "cee", true)]);
    let diff = run_a
        .tunnel
        .apply(Config::parse(&renamed, &ctx()).unwrap())
        .unwrap();
    assert_eq!(diff.peers_added.len(), 1);
    assert_eq!(diff.peers_renamed.len(), 1);
    assert!(diff.peers_removed.is_empty() && diff.restart.is_empty());
    assert!(run_a.tunnel.responder().resolve("bee").is_some());
    assert!(run_a.tunnel.responder().resolve("beta").is_none());
    assert!(run_a.tunnel.responder().resolve("cee").is_some());

    for _ in 0..100 {
        if count(&run_a, "added", "cee") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(count(&run_a, "added", "cee"), 1);
    let to_c = echo(ula(&a, &net), ula(&c, &net));
    run_a.tunnel.packet_in(&to_c);
    assert_eq!(recv(&mut run_c).await, to_c);

    let again = echo(ula(&a, &net), ula(&b, &net));
    run_a.tunnel.packet_in(&again);
    assert_eq!(recv(&mut run_b).await, again);
    assert_eq!(count(&run_a, "removed", "beta"), 0);

    let only_c = file(&a, &net, "", &[(&c, "cee", true)]);
    let diff = run_a
        .tunnel
        .apply(Config::parse(&only_c, &ctx()).unwrap())
        .unwrap();
    assert_eq!(diff.peers_removed.len(), 1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(count(&run_a, "removed", "bee"), 1);
    assert!(run_a.tunnel.responder().resolve("bee").is_none());
    assert_eq!(run_a.tunnel.config().peers.len(), 1);
}

#[tokio::test]
async fn a_change_that_needs_a_restart_is_refused_with_its_field_and_nothing_changes() {
    let net = keys::generate_network_secret();
    let (a, b) = (node(free_port()), node(free_port()));
    let text = file(&a, &net, "", &[(&b, "beta", true)]);
    let run = start(&text);

    let other = node(a.port);
    let bad = file(
        &other,
        &net,
        "mtu = 1400\n",
        &[(&b, "beta", true), (&a, "alpha", false)],
    );
    let err = run
        .tunnel
        .apply(Config::parse(&bad, &ctx()).unwrap())
        .unwrap_err();
    let ApplyError::NeedsRestart(fields) = err;
    assert_eq!(fields, vec!["private_key", "mtu"]);
    assert_eq!(run.tunnel.config().peers.len(), 1, "left as it was");
    assert_eq!(run.tunnel.config().mtu, 1280);

    let same = run
        .tunnel
        .apply(Config::parse(&text, &ctx()).unwrap())
        .unwrap();
    assert!(same.is_empty());
}

#[tokio::test]
async fn the_domain_the_names_and_the_exit_follow_the_file() {
    let net = keys::generate_network_secret();
    let (a, b) = (node(free_port()), node(free_port()));
    let run = start(&file(&a, &net, "", &[(&b, "beta", true)]));
    assert!(run.tunnel.config().exit.is_none());
    let before = run.tunnel.settings();

    let text = file(
        &a,
        &net,
        "domain = \"lab.example\"\nname = \"me\"\n",
        &[(&b, "beta", true)],
    ) + "\n[exit]\nsite = \"it/home\"\nipv4 = false\n";
    let diff = run
        .tunnel
        .apply(Config::parse(&text, &ctx()).unwrap())
        .unwrap();
    assert!(diff.domain && diff.own_name && diff.exit);
    assert!(!diff.forward && !diff.turn && !diff.stun);
    assert_eq!(diff.lines().len(), 3, "{:?}", diff.lines());
    let responder = run.tunnel.responder();
    assert!(responder.resolve("beta.lab.example").is_some());
    assert!(responder.resolve("me.lab.example").is_some());
    assert_eq!(
        run.tunnel.config().exit.as_ref().unwrap().site.to_string(),
        "it/home"
    );
    let after = run.tunnel.settings();
    assert_ne!(before.dns.match_domains, after.dns.match_domains);
    assert_eq!(after.dns.match_domains[0], "lab.example");

    let off = file(
        &a,
        &net,
        "domain = \"lab.example\"\nname = \"me\"\n",
        &[(&b, "beta", true)],
    );
    let diff = run
        .tunnel
        .apply(Config::parse(&off, &ctx()).unwrap())
        .unwrap();
    assert!(diff.exit && !diff.domain);
    assert!(run.tunnel.config().exit.is_none());
}

#[tokio::test]
async fn an_exit_added_to_a_running_node_is_offered_at_the_next_handshake() {
    let net = keys::generate_network_secret();
    let (server, client) = (node(free_port()), node(free_port()));
    let run_server = start(&file(&server, &net, "", &[(&client, "client", false)]));
    let run_client = start(&file(&client, &net, "", &[(&server, "server", true)]));

    let with_exit = file(&server, &net, "", &[(&client, "client", false)])
        + "\n[exit]\nsite = \"it/home\"\nipv4 = false\n";
    run_server
        .tunnel
        .apply(Config::parse(&with_exit, &ctx()).unwrap())
        .unwrap();
    run_client.tunnel.set_exit(Some(ExitUse { site: None }));

    let via = server.public.clone();
    for _ in 0..200 {
        let seen = run_client
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e["type"] == "exit" && e["via"] == via.as_str());
        if seen {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no exit: {:?}", run_client.events.lock().unwrap());
}
