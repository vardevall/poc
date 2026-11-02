//! Vectors of vv-05 (`05-connection.json`).

mod common;

use common::*;
use vardevall_proto::discovery::candidate::*;
use vardevall_proto::route::control::{Control, encode_control, parse_control};

fn make(name: &str, addr: std::net::SocketAddr) -> Candidate {
    match name {
        "punch" => Candidate::punch(addr),
        "relay" => Candidate::relay(addr),
        k => panic!("{k}"),
    }
}

fn candidate(c: &serde_json::Value) -> Candidate {
    let ip: std::net::IpAddr = c["ip"].as_str().unwrap().parse().unwrap();
    let addr = std::net::SocketAddr::new(ip, c["port"].as_u64().unwrap() as u16);
    make(c["kind"].as_str().unwrap(), addr).with_metered(c["metered"].as_bool().unwrap_or(false))
}

#[test]
fn encoding() {
    let doc = load("05-connection.json");
    for v in group(&doc, "candidate_encoding") {
        let cands: Vec<Candidate> = match v["input"]["candidates"].as_array() {
            Some(list) => list
                .iter()
                .map(|c| {
                    let ip: std::net::IpAddr = c[1].as_str().unwrap().parse().unwrap();
                    make(
                        c[0].as_str().unwrap(),
                        std::net::SocketAddr::new(ip, c[2].as_u64().unwrap() as u16),
                    )
                })
                .collect(),
            None => vec![candidate(&v["input"])],
        };
        assert_eq!(
            encode_list(&cands),
            v["output"]["cand_json"].as_str().unwrap(),
            "{}",
            v["description"]
        );
    }
}

#[test]
fn parsing() {
    let doc = load("05-connection.json");
    for v in group(&doc, "candidate_parsing") {
        let text = serde_json::to_vec(&v["input"]["cand"]).unwrap();
        let got = decode_list(&text).unwrap();
        let want = v["output"]["usable"].as_array().unwrap();
        assert_eq!(got.len(), want.len(), "{}", v["description"]);
        for (g, w) in got.iter().zip(want) {
            let ip = match g.addr.ip() {
                std::net::IpAddr::V4(a) => a.octets().to_vec(),
                std::net::IpAddr::V6(a) => a.octets().to_vec(),
            };
            assert_eq!(g.label, w["kind"].as_str().unwrap());
            assert!(g.shared && !g.local);
            assert_eq!(
                to_hex(&ip),
                w["ip"].as_str().unwrap(),
                "{}",
                v["description"]
            );
            assert_eq!(u64::from(g.addr.port()), w["port"].as_u64().unwrap());
            assert_eq!(
                g.metered,
                w["metered"].as_bool().unwrap(),
                "{}",
                v["description"]
            );
        }
    }
}

/// The `ask` and `report` messages of the spec are receive reports, which this
/// implementation drops; their vectors are left in the file and skipped here.
fn removed(t: &serde_json::Value) -> bool {
    matches!(t.as_str(), Some("ask" | "report"))
}

fn decimal(v: &serde_json::Value) -> u64 {
    match v {
        serde_json::Value::String(s) => s.parse().unwrap(),
        other => other.as_u64().unwrap(),
    }
}

fn message(m: &serde_json::Value) -> Control {
    match m["t"].as_str().unwrap() {
        "cand" => Control::Cand {
            seq: decimal(&m["seq"]),
            cand: m["cand"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| {
                    let addr = parse_addr(c["addr"].as_str().unwrap()).unwrap();
                    make(c["kind"].as_str().unwrap(), addr)
                        .with_metered(c["metered"].as_bool().unwrap_or(false))
                })
                .collect(),
        },
        t => panic!("{t}"),
    }
}

fn matches_parsed(got: &Control, want: &serde_json::Value, what: &str) {
    match got {
        Control::Cand { seq, cand } => {
            assert_eq!(want["t"], "cand", "{what}");
            assert_eq!(*seq, want["seq"].as_u64().unwrap(), "{what}");
            let usable = want["usable"].as_array().unwrap();
            assert_eq!(cand.len(), usable.len(), "{what}");
            for (g, w) in cand.iter().zip(usable) {
                let ip = match g.addr.ip() {
                    std::net::IpAddr::V4(a) => a.octets().to_vec(),
                    std::net::IpAddr::V6(a) => a.octets().to_vec(),
                };
                assert_eq!(g.label, w["kind"].as_str().unwrap(), "{what}");
                assert_eq!(to_hex(&ip), w["ip"].as_str().unwrap(), "{what}");
                assert_eq!(u64::from(g.addr.port()), w["port"].as_u64().unwrap());
                assert_eq!(g.metered, w["metered"].as_bool().unwrap(), "{what}");
            }
        }
        Control::Ping { .. }
        | Control::Pong { .. }
        | Control::CandAck { .. }
        | Control::Svc { .. }
        | Control::SvcAck { .. } => panic!("{what}"),
    }
}

#[test]
fn control_encoding() {
    let doc = load("05-connection.json");
    for v in group(&doc, "control_encoding") {
        let what = v["description"].as_str().unwrap();
        if removed(&v["input"]["message"]["t"]) {
            continue;
        }
        let control = message(&v["input"]["message"]);
        assert_eq!(
            to_hex(&encode_control(&control)),
            v["output"]["plaintext"].as_str().unwrap(),
            "{what}"
        );
        let parsed = parse_control(&hv(&v["output"]["plaintext"])).expect(what);
        assert_eq!(parsed, control, "{what}");
        matches_parsed(&parsed, &v["output"]["parsed"], what);
    }
}

#[test]
fn control_parsing() {
    let doc = load("05-connection.json");
    for v in group(&doc, "control_parsing") {
        let what = v["description"].as_str().unwrap();
        let got = parse_control(&hv(&v["input"]["plaintext"]));
        let want = &v["output"]["parsed"];
        if removed(&want["t"]) {
            assert_eq!(got, None, "{what}: a removed message is dropped");
        } else if want.is_null() {
            assert_eq!(got, None, "{what}");
        } else {
            matches_parsed(&got.expect(what), want, what);
        }
    }
}
