//! The engine on a pair of sockets that stands for the interface: packets written to one end are
//! read by the engine, and its packets come out of the same end.

use std::net::{Ipv6Addr, UdpSocket};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::sync::mpsc;
use std::time::Duration;

use vardevall_tun::embed::{NetworkSpec, resolver_alias};
use vardevall_tun::{keys, packet};

use crate::engine::{Engine, Sinks};

struct Rig {
    engine: Engine,
    phone: UnixDatagram,
    own: Ipv6Addr,
    events: mpsc::Receiver<String>,
}

fn interface() -> (UnixDatagram, OwnedFd) {
    let (phone, engine_end) = UnixDatagram::pair().unwrap();
    phone
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    (phone, OwnedFd::from(engine_end))
}

fn start() -> Rig {
    let secret = keys::generate_node_key();
    let public = keys::public_key(&secret).unwrap();
    let net = keys::generate_network_secret();
    let text = format!(
        "[interface]\nprivate_key = \"{secret}\"\nnetwork_secret = \"{net}\"\nlisten_port = 0\nmdns = false\nname = \"phone\"\n"
    );
    let (phone, fd) = interface();
    let (tx, events) = mpsc::channel();
    let engine = Engine::start(
        vec![NetworkSpec {
            name: "home".into(),
            config_toml: text,
        }],
        fd,
        Sinks {
            event: Box::new(move |json| {
                let _ = tx.send(json.to_owned());
            }),
            mdns: None,
        },
    )
    .unwrap();
    let id = keys::network_id(&net).unwrap();
    Rig {
        engine,
        phone,
        own: keys::overlay_addrs(&public, &id).unwrap().ula,
        events,
    }
}

/// A query for the AAAA records of `name`, written by hand so that the crate needs no DNS library.
fn query(name: &str) -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&[0, 28, 0, 1]);
    m
}

fn ask(rig: &Rig, name: &str) -> Vec<u8> {
    let alias = resolver_alias(rig.own);
    rig.phone
        .send(&packet::build_udp(
            &rig.own,
            &alias,
            40000,
            53,
            &query(name),
        ))
        .unwrap();
    let mut buf = vec![0u8; 2048];
    let n = rig.phone.recv(&mut buf).unwrap();
    let h = packet::parse(&buf[..n]).unwrap();
    assert_eq!(h.src, alias);
    packet::parse_udp(&buf[..n], &h, true)
        .unwrap()
        .payload
        .to_vec()
}

fn rcode(message: &[u8]) -> u8 {
    message[3] & 0x0f
}

#[test]
fn a_query_written_to_the_interface_is_answered_on_it() {
    let rig = start();
    let reply = ask(&rig, "phone.home.internal");
    assert_eq!((reply[0], reply[1]), (0x12, 0x34));
    assert_eq!(rcode(&reply), 0);
    assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1, "one answer");
    rig.engine.stop();
}

#[test]
fn names_outside_the_overlay_follow_the_resolvers_set_while_running() {
    let rig = start();
    assert_eq!(rcode(&ask(&rig, "example.com")), 2, "no resolver yet");

    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = upstream.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = upstream.recv_from(&mut buf) {
            let mut reply = buf[..n].to_vec();
            reply[2] |= 0x80;
            let _ = upstream.send_to(&reply, from);
        }
    });
    rig.engine.set_resolvers(&[addr]);
    let reply = ask(&rig, "example.com");
    assert_eq!(rcode(&reply), 0);
    assert_ne!(reply[2] & 0x80, 0, "the upstream's answer");

    rig.engine.set_resolvers(&[]);
    assert_eq!(rcode(&ask(&rig, "example.org")), 2);
    rig.engine.stop();
}

#[test]
fn a_new_interface_replaces_the_old_and_the_engine_goes_on() {
    let rig = start();
    ask(&rig, "phone.home.internal");

    let (second, fd) = interface();
    rig.engine.set_tun(fd).unwrap();
    let alias = resolver_alias(rig.own);
    second
        .send(&packet::build_udp(
            &rig.own,
            &alias,
            40001,
            53,
            &query("phone.home.internal"),
        ))
        .unwrap();
    let mut buf = vec![0u8; 2048];
    let n = second.recv(&mut buf).unwrap();
    assert_eq!(packet::parse(&buf[..n]).unwrap().src, alias);

    let mut closed = vec![0u8; 16];
    rig.phone
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert_eq!(
        rig.phone.recv(&mut closed).unwrap_or(0),
        0,
        "the old interface is closed"
    );
    rig.engine.stop();
}

#[test]
fn events_reach_the_sink_and_stop_ends_them() {
    let rig = start();
    let started = rig
        .events
        .iter()
        .take_while(|_| true)
        .find(|e| e.contains("\"state\":\"started\""))
        .expect("started");
    assert!(started.contains("\"network\":\"home\""));
    let events = rig.events;
    rig.engine.stop();
    while events.try_recv().is_ok() {}
    assert!(
        events.recv_timeout(Duration::from_millis(300)).is_err(),
        "nothing after stop"
    );
}
