//! A whole interface registering with a switch and reaching a peer through it (vv-04, vv-07 §3.3).

use std::future::pending;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use vardevall_switch::config::Config;
use vardevall_switch::{Switch, key};
use vardevall_tun::embed::{Callbacks, StartOptions, Tunnel};
use vardevall_tun::{keys, packet};

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

fn config(me: &str, net: &str, peer: &str, switch: &str, extra: &str) -> String {
    format!(
        "[interface]\nprivate_key = \"{me}\"\nnetwork_secret = \"{net}\"\nmdns = false\ntun_class = {{ degrade = true }}\n{extra}\n[[switch]]\naddress = \"{switch}\"\n\n[[peer]]\npublic_key = \"{peer}\"\n"
    )
}

fn switch_config() -> Config {
    let mut config = Config::new(vec![], "unused".into());
    config.names = vec!["127.0.0.1".into()];
    config
}

async fn wait_for(r: &Running, f: impl Fn(&Value) -> bool) {
    for _ in 0..200 {
        if r.events.lock().unwrap().iter().any(&f) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("event not seen: {:?}", r.events.lock().unwrap());
}

#[tokio::test]
async fn two_interfaces_connect_through_a_switch_and_report_it() {
    let secret = key::generate().unwrap();
    let address_key = secret.public();
    let switch = Arc::new(Switch::new(&switch_config(), secret).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move { switch.run(vec![listener], pending()).await });
    let address = format!("{address_key}@127.0.0.1:{port}");

    let net = keys::generate_network_secret();
    let a_secret = keys::generate_node_key();
    let b_secret = keys::generate_node_key();
    let a_public = keys::public_key(&a_secret).unwrap();
    let b_public = keys::public_key(&b_secret).unwrap();
    let mut b = start(&config(&b_secret, &net, &a_public, &address, ""));
    let a = start(&config(&a_secret, &net, &b_public, &address, ""));

    let id = keys::network_id(&net).unwrap();
    let a_ula = keys::overlay_addrs(&a_public, &id).unwrap().ula;
    let b_ula = keys::overlay_addrs(&b_public, &id).unwrap().ula;
    wait_for(&a, |e| {
        e["type"] == "switch" && e["state"] == "registered" && e["auth"] == "pinned"
    })
    .await;
    wait_for(&b, |e| e["type"] == "switch" && e["state"] == "registered").await;

    let req = packet::build_icmpv6(&a_ula, &b_ula, 128, 0, &[0, 1, 0, 1, 0xde, 0xad], 64);
    let got = loop {
        a.tunnel.packet_in(&req);
        if let Ok(Some(p)) =
            tokio::time::timeout(Duration::from_millis(500), b.packets.recv()).await
        {
            break p;
        }
    };
    assert_eq!(got, req);
    wait_for(&a, |e| e["type"] == "peer" && e["state"] == "up").await;
    wait_for(&a, |e| {
        e["type"] == "route" && e["route"]["kind"] == "switch"
    })
    .await;
    a.tunnel.stop_async().await;
    b.tunnel.stop_async().await;
    task.abort();
}

#[tokio::test]
async fn a_wrong_switch_key_is_reported_not_trusted() {
    let secret = key::generate().unwrap();
    let wrong = key::generate().unwrap().public();
    let switch = Arc::new(Switch::new(&switch_config(), secret).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move { switch.run(vec![listener], pending()).await });
    let net = keys::generate_network_secret();
    let me = keys::generate_node_key();
    let peer = keys::public_key(&keys::generate_node_key()).unwrap();
    let node = start(&config(
        &me,
        &net,
        &peer,
        &format!("{wrong}@127.0.0.1:{port}"),
        "",
    ));
    wait_for(&node, |e| {
        e["type"] == "switch" && e["state"] == "disconnected" && e["reason"] == "untrusted"
    })
    .await;
    node.tunnel.stop_async().await;
    task.abort();
}
