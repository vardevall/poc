//! Vectors of vve-14 (`14-services.json`) and the service book on a pair of nodes.

mod common;

use std::time::Duration;

use common::*;
use serde_json::Value;
use vardevall_proto::ip::service::*;
use vardevall_proto::keys::NodePublic;
use vardevall_proto::route::{Control, encode_control, parse_control};
use vardevall_proto::time::Instant;

fn proto(v: &Value) -> Proto {
    match v.as_str().unwrap() {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        p => panic!("{p}"),
    }
}

fn services(list: &Value) -> Vec<Service> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|s| {
            Service::new(
                s["name"].as_str().unwrap(),
                s["port"].as_u64().unwrap() as u16,
                s.get("proto").map_or(Proto::Tcp, proto),
            )
            .unwrap()
        })
        .collect()
}

fn message(m: &Value) -> Control {
    let seq = m["seq"].as_str().unwrap().parse().unwrap();
    match m["t"].as_str().unwrap() {
        "svc" => Control::Svc {
            seq,
            services: services(&m["svc"]),
        },
        "svcack" => Control::SvcAck { seq },
        t => panic!("{t}"),
    }
}

fn typed(parsed: &Value) -> Control {
    let seq = parsed["seq"].as_u64().unwrap();
    match parsed["t"].as_str().unwrap() {
        "svc" => Control::Svc {
            seq,
            services: services(&parsed["services"]),
        },
        "svcack" => Control::SvcAck { seq },
        t => panic!("{t}"),
    }
}

#[test]
fn encoding() {
    let doc = load("14-services.json");
    for v in group(&doc, "message_encoding") {
        let what = v["description"].as_str().unwrap();
        let control = message(&v["input"]["message"]);
        let plaintext = v["output"]["plaintext"].as_str().unwrap();
        assert_eq!(to_hex(&encode_control(&control)), plaintext, "{what}");
        assert_eq!(
            parse_control(&hv(&v["output"]["plaintext"])),
            Some(typed(&v["output"]["parsed"])),
            "{what}"
        );
    }
}

#[test]
fn parsing() {
    let doc = load("14-services.json");
    for v in group(&doc, "message_parsing") {
        let what = v["description"].as_str().unwrap();
        let got = parse_control(&hv(&v["input"]["plaintext"]));
        let want = &v["output"]["parsed"];
        if want.is_null() {
            assert_eq!(got, None, "{what}");
        } else {
            assert_eq!(got, Some(typed(want)), "{what}");
        }
    }
}

fn key(n: u8) -> NodePublic {
    NodePublic::from_bytes([n; 32])
}

fn rto(_: &NodePublic) -> Duration {
    Duration::from_millis(200)
}

/// Delivers what `from` wants sent to `to` and back until both are quiet.
fn exchange(a: &mut ServiceBook, ka: NodePublic, b: &mut ServiceBook, kb: NodePublic, ms: u64) {
    let now = Instant::from_millis(ms);
    for _ in 0..10 {
        let mut any = false;
        while let Some(ServiceAction::Send { control, .. }) = a.poll_action() {
            b.handle_control(now, &ka, &control, rto);
            any = true;
        }
        while let Some(ServiceAction::Send { control, .. }) = b.poll_action() {
            a.handle_control(now, &kb, &control, rto);
            any = true;
        }
        if !any {
            return;
        }
    }
    panic!("no quiescence");
}

#[test]
fn a_restarted_node_catches_up_with_the_seq_the_peer_remembers() {
    let (ka, kb) = (key(1), key(2));
    let kt = Duration::from_secs(10);
    let t0 = Instant::from_millis(0);
    let mut a = ServiceBook::new(ka, kt);
    let mut b = ServiceBook::new(kb, kt);
    a.announce(t0, Service::new("web", 443, Proto::Tcp).unwrap(), rto)
        .unwrap();
    a.announce(t0, Service::new("dns", 53, Proto::Udp).unwrap(), rto)
        .unwrap();
    a.session_up(t0, &kb, rto);
    b.session_up(t0, &ka, rto);
    exchange(&mut a, ka, &mut b, kb, 10);
    assert_eq!(b.peer_services(&ka).unwrap().0.len(), 2);
    assert_eq!(a.poll_timeout(), None, "acknowledged");

    let t1 = Instant::from_millis(5_000);
    let mut a = ServiceBook::new(ka, kt);
    a.announce(t1, Service::new("web", 8443, Proto::Tcp).unwrap(), rto)
        .unwrap();
    a.session_up(t1, &kb, rto);
    exchange(&mut a, ka, &mut b, kb, 5_010);
    let (got, live) = b.peer_services(&ka).unwrap();
    assert!(live);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].port(), 8443);
    assert!(a.seq() > 2, "jumped past the peer's seq");
    assert_eq!(a.poll_timeout(), None);
}

#[test]
fn retransmissions_reach_a_peer_that_missed_the_first_message() {
    let (ka, kb) = (key(1), key(2));
    let kt = Duration::from_secs(10);
    let mut a = ServiceBook::new(ka, kt);
    let mut b = ServiceBook::new(kb, kt);
    a.announce(
        Instant::ZERO,
        Service::new("web", 443, Proto::Tcp).unwrap(),
        rto,
    )
    .unwrap();
    a.session_up(Instant::ZERO, &kb, rto);
    while a.poll_action().is_some() {}
    let t = a.poll_timeout().unwrap();
    a.handle_timeout(t, rto);
    exchange(&mut a, ka, &mut b, kb, 300);
    assert_eq!(b.peer_services(&ka).unwrap().0[0].name(), "web");
    assert_eq!(a.poll_timeout(), None);
}
