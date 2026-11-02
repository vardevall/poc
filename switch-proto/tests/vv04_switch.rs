//! Vectors of vv-04 (`04-switch-api.json`) and the registration proofs of vv-01 §5.5.

mod common;

use common::*;
use serde_json::Value;
use vardevall_proto::error::ParseError;
use vardevall_proto::keys::base32;
use vardevall_proto::keys::*;
use vardevall_switch_proto::api::*;

#[test]
fn challenge_construction() {
    let doc = load("04-switch-api.json");
    for v in group(&doc, "challenge_construction") {
        let i = &v["input"];
        let o = &v["output"];
        let nonce: [u8; 16] = hv(&i["nonce"]).try_into().unwrap();
        let c = build_challenge(
            &h32(&i["challenge_secret"]),
            i["t"].as_u64().unwrap(),
            &nonce,
        );
        assert_eq!(to_hex(&c), o["challenge"].as_str().unwrap());
        assert_eq!(base32::encode(&c), o["challenge_base32"].as_str().unwrap());
        let body = format!(
            "{{\"challenge\":\"{}\",\"expires_in\":60}}",
            base32::encode(&c)
        );
        assert_eq!(body, o["response_body"].as_str().unwrap());
        let (parsed, expires) = parse_challenge_response(body.as_bytes()).unwrap();
        assert_eq!((parsed, expires), (c, 60));
    }
}

#[test]
fn challenge_verification() {
    let doc = load("04-switch-api.json");
    for v in group(&doc, "challenge_verification") {
        let i = &v["input"];
        let ok = verify_challenge(
            &h32(&i["challenge_secret"]),
            &hv(&i["challenge"]),
            i["now"].as_u64().unwrap(),
        );
        assert_eq!(
            ok,
            v["output"]["valid"].as_bool().unwrap(),
            "{}",
            v["description"]
        );
    }
}

fn check_registration(i: &Value, o: &Value, description: &str) {
    let node = NodeSecret::from_bytes(h32(&i["node_sk"]));
    let net = NetworkSecret::from_bytes(h32(&i["net_sk"]));
    let switch_pk = SwitchPublic::from_bytes(h32(&i["A"]));
    let binding = if let Some(e) = i.get("exporter") {
        Binding::Exporter(h32(e))
    } else {
        Binding::Challenge(hv(&i["challenge"]).try_into().unwrap())
    };
    let host = i["host"].as_str().unwrap();
    assert_eq!(normalize_host(host).as_deref(), Some(host), "{description}");
    let b = bound_data(&binding, host, &node.public(), &net.public(), &switch_pk).unwrap();
    assert_eq!(to_hex(&b), o["b"].as_str().unwrap(), "{description}");
    let proofs = client_proofs(&node, &net, &switch_pk, &b).unwrap();
    assert_eq!(
        proofs.node_proof.to_vec(),
        hv(&o["node_proof"]),
        "{description}"
    );
    assert_eq!(
        proofs.net_proof.to_vec(),
        hv(&o["net_proof"]),
        "{description}"
    );
    assert_eq!(
        proofs.switch_proof.to_vec(),
        hv(&o["switch_proof"]),
        "{description}"
    );

    if let Some(seed) = i.get("switch_seed") {
        let switch = SwitchSecret::from_bytes(h32(seed));
        assert_eq!(switch.public(), switch_pk);
        let reply = verify_registration(
            &switch,
            &node.public(),
            &net.public(),
            &b,
            &proofs.node_proof,
            &proofs.net_proof,
        );
        assert_eq!(reply, Some(proofs.switch_proof), "{description}");
        let mut bad = proofs.node_proof;
        bad[0] ^= 1;
        assert!(
            verify_registration(
                &switch,
                &node.public(),
                &net.public(),
                &b,
                &bad,
                &proofs.net_proof
            )
            .is_none()
        );
        let mut bad = proofs.net_proof;
        bad[31] ^= 0x80;
        assert!(
            verify_registration(
                &switch,
                &node.public(),
                &net.public(),
                &b,
                &proofs.node_proof,
                &bad
            )
            .is_none()
        );
    }
    if let Some(body) = o.get("request_body") {
        assert_eq!(
            register_request(&node.public(), &net.public(), &binding, host, &proofs),
            body.as_str().unwrap(),
            "{description}"
        );
        let parsed = parse_register_request(body.as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(parsed.node, node.public());
        assert_eq!(parsed.network, net.public());
        assert_eq!(parsed.host, host);
        assert_eq!(parsed.node_proof, proofs.node_proof);
        assert_eq!(parsed.net_proof, proofs.net_proof);
        match binding {
            Binding::Exporter(_) => assert_eq!(parsed.binding, RequestBinding::Exporter),
            Binding::Challenge(c) => assert_eq!(parsed.binding, RequestBinding::Challenge(c)),
        }
    }
}

#[test]
fn request_parsers_reject_malformed_bodies() {
    assert!(parse_register_request(b"{}").is_err());
    assert!(parse_register_request(b"not json").is_err());
    assert!(parse_register_request(br#"{"binding":"other"}"#).is_err());
    let doc = load("04-switch-api.json");
    let body = doc["registration"][0]["output"]["request_body"]
        .as_str()
        .unwrap();
    assert!(parse_register_request(body.as_bytes()).is_ok());
    let without_host = body.replace(",\"host\":\"switch.example.org\"", "");
    assert_ne!(without_host, body);
    assert!(parse_register_request(without_host.as_bytes()).is_err());
    let numeric_host = body.replace("\"switch.example.org\"", "5");
    assert!(parse_register_request(numeric_host.as_bytes()).is_err());
    assert!(parse_forward_request(br#"{"to":"x","msg":"aa"}"#).is_err());
    let to = NodePublic::from_bytes([7; 32]);
    let body = forward_request(&to, b"hello");
    let parsed = parse_forward_request(body.as_bytes()).unwrap();
    assert_eq!((parsed.to, parsed.msg.as_slice()), (to, &b"hello"[..]));
}

#[test]
fn registration() {
    let doc = load("04-switch-api.json");
    for v in group(&doc, "registration") {
        check_registration(
            &v["input"],
            &v["output"],
            v["description"].as_str().unwrap(),
        );
    }
    for v in group(&doc, "proof_relay") {
        check_registration(
            &v["input"],
            &v["output"],
            v["description"].as_str().unwrap(),
        );
    }
}

#[test]
fn the_host_is_bound_into_b() {
    let doc = load("04-switch-api.json");
    let i = &doc["registration"][0]["input"];
    let node = NodeSecret::from_bytes(h32(&i["node_sk"])).public();
    let net = NetworkSecret::from_bytes(h32(&i["net_sk"])).public();
    let a = SwitchPublic::from_bytes(h32(&i["A"]));
    let binding = Binding::Exporter(h32(&i["exporter"]));
    let b = |host: &str| bound_data(&binding, host, &node, &net, &a);
    assert_ne!(b("a.example").unwrap(), b("b.example").unwrap());
    assert_eq!(b("").unwrap_err(), ParseError::Length);
    assert!(b(&"a".repeat(253)).is_ok());
    assert_eq!(b(&"a".repeat(254)).unwrap_err(), ParseError::Length);
    let one = b("h").unwrap();
    assert_eq!(&one[33..35], b"\x01h");
}

#[test]
fn hosts_are_normalised() {
    for (given, normal) in [
        ("Switch.Example.ORG", "switch.example.org"),
        ("switch.example.org.", "switch.example.org"),
        ("192.0.2.7", "192.0.2.7"),
        ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),
        ("2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"),
        ("2001:0:0:1:0:0:0:1", "2001:0:0:1::1"),
        ("0:0:0:0:0:0:0:0", "::"),
        ("::ffff:192.0.2.1", "::ffff:c000:201"),
        ("1:0:3:4:5:6:7:8", "1:0:3:4:5:6:7:8"),
    ] {
        assert_eq!(normalize_host(given).as_deref(), Some(normal), "{given}");
    }
    for bad in [
        "",
        ".",
        "a..b",
        "[192.0.2.7]",
        "192.0.2.07",
        "switch example",
        "caf\u{e9}.example",
        "[2001:db8::1",
        "-",
        "a.b.123",
    ] {
        assert_eq!(normalize_host(bad), None, "{bad}");
    }
    assert_eq!(normalize_host(&"a".repeat(64)), None);
    assert_eq!(
        normalize_host(&format!("{0}.{0}.{0}.{0}.{0}", "a".repeat(62))),
        None
    );
}

#[test]
fn pinned_certificate_key() {
    let doc = load("04-switch-api.json");
    for v in group(&doc, "pinned_certificate") {
        let a = SwitchPublic::from_bytes(h32(&v["input"]["A"]));
        let spki = hv(&v["output"]["subject_public_key_info_der"]);
        assert_eq!(a.to_spki().to_vec(), spki);
        assert_eq!(SwitchPublic::from_spki(&spki), Some(a));
    }
}

#[test]
fn proofs_of_vv01() {
    let doc = load("01-keys.json");
    for v in group(&doc, "registration_proofs") {
        let i = &v["input"];
        let o = &v["output"];
        let node = NodeSecret::from_bytes(h32(&i["node_sk"]));
        let net = NetworkSecret::from_bytes(h32(&i["net_sk"]));
        let a = SwitchPublic::from_bytes(h32(&i["A"]));
        let proofs = client_proofs(&node, &net, &a, &hv(&i["b"])).unwrap();
        assert_eq!(proofs.node_proof.to_vec(), hv(&o["node_proof"]));
        assert_eq!(proofs.net_proof.to_vec(), hv(&o["net_proof"]));
        assert_eq!(proofs.switch_proof.to_vec(), hv(&o["switch_proof"]));
        assert_eq!(node.public().as_bytes().to_vec(), hv(&o["node_pk"]));
        assert_eq!(net.public().as_bytes().to_vec(), hv(&o["net_pk"]));
        let server = switch_proofs(
            &SwitchSecret::from_bytes(h32(&i["switch_seed"])),
            &node.public(),
            &net.public(),
            &hv(&i["b"]),
        )
        .unwrap();
        assert_eq!(server, proofs);
    }
}

#[test]
fn turn_credentials() {
    let doc = load("04-switch-api.json");
    for v in group(&doc, "turn_credentials") {
        let i = &v["input"];
        let secret = i["turn_secret_string"].as_str().unwrap();
        assert_eq!(secret.as_bytes(), hv(&i["turn_secret_utf8"]).as_slice());
        let username = format!(
            "{}:{}",
            i["expiry"].as_u64().unwrap(),
            i["opaque_id"].as_str().unwrap()
        );
        assert_eq!(username, v["output"]["username"].as_str().unwrap());
        assert_eq!(
            turn_credential(secret, &username),
            v["output"]["credential"].as_str().unwrap()
        );
    }
}

#[test]
fn register_response() {
    let body = format!(
        "{{\"session\":\"{}\",\"switch_proof\":\"{}\",\"turn\":{{\"urls\":[\"turn:a:1\"],\"username\":\"1:x\",\"credential\":\"c=\",\"ttl\":86400}}}}",
        base32::encode(&[7u8; 32]),
        base32::encode(&[9u8; 32])
    );
    let r = parse_register_response(body.as_bytes()).unwrap();
    assert_eq!(r.session, [7; 32]);
    let turn = r.turn.unwrap();
    assert_eq!(
        (turn.ttl, turn.bits_per_second, turn.bytes),
        (86400, None, None)
    );
    assert!(parse_register_response(b"{}").is_err());
    assert!(parse_register_response(b"not json").is_err());
}

#[test]
fn turn_response_with_limits() {
    let t = vardevall_switch_proto::api::parse_turn_response(
        b"{\"urls\":[\"turn:a:1\",\"turns:a:443?transport=tcp\"],\"username\":\"9:x\",\"credential\":\"c=\",\"ttl\":60,\"limits\":{\"bits_per_second\":8000}}",
    )
    .unwrap();
    assert_eq!(t.urls.len(), 2);
    assert_eq!((t.bits_per_second, t.bytes), (Some(8000), None));
    assert!(vardevall_switch_proto::api::parse_turn_response(b"{\"urls\":[]}").is_err());
}

#[test]
fn register_response_with_stun_credentials_and_turn_nonce() {
    let body = format!(
        "{{\"session\":\"{}\",\"switch_proof\":\"{}\",\"turn\":{{\"urls\":[\"turn:a:1\"],\"username\":\"1:x\",\"credential\":\"c=\",\"ttl\":60,\"realm\":\"r\",\"nonce\":\"n\"}},\"stun\":{{\"username\":\"2:y\",\"credential\":\"d=\",\"ttl\":30}}}}",
        base32::encode(&[7u8; 32]),
        base32::encode(&[9u8; 32])
    );
    let r = parse_register_response(body.as_bytes()).unwrap();
    let turn = r.turn.unwrap();
    assert_eq!(turn.realm.as_deref(), Some("r"));
    assert_eq!(turn.nonce.as_deref(), Some("n"));
    let stun = r.stun.unwrap();
    assert_eq!(
        (stun.username.as_str(), stun.credential.as_str()),
        ("2:y", "d=")
    );
    assert_eq!(stun.ttl, 30);
    assert_eq!(
        parse_stun_response(br#"{"username":"2:y","credential":"d=","ttl":30}"#).unwrap(),
        stun
    );
    assert!(parse_stun_response(br#"{"username":"2:y","ttl":30}"#).is_err());
    let no_stun = body.replace(
        ",\"stun\":{\"username\":\"2:y\",\"credential\":\"d=\",\"ttl\":30}",
        "",
    );
    assert!(
        parse_register_response(no_stun.as_bytes())
            .unwrap()
            .stun
            .is_none()
    );
    let bad_nonce = body.replace("\"nonce\":\"n\"", "\"nonce\":1");
    assert!(parse_register_response(bad_nonce.as_bytes()).is_err());
}

#[test]
fn info() {
    let key = SwitchPublic::from_bytes([5; 32]);
    let full = format!(
        "{{\"versions\":[\"v0\"],\"key\":\"{}\",\"binding\":\"challenge\",\"token_required\":false,\"max_forward_size\":4096,\"stun\":[\"stun:s.example:3478\"],\"stun_auth\":true,\"turn\":true,\"forward_limits\":{{\"bits_per_second\":8000,\"bytes\":1000000}}}}",
        base32::encode(key.as_bytes())
    );
    let i = parse_info(full.as_bytes()).unwrap();
    assert_eq!(i.key, Some(key));
    assert_eq!(i.binding, InfoBinding::Challenge);
    assert!(i.stun_auth && i.turn && !i.token_required);
    assert_eq!(
        i.forward_limits,
        Some(Limits {
            bits_per_second: Some(8000),
            bytes: Some(1_000_000)
        })
    );
    assert_eq!(i.stun, ["stun:s.example:3478"]);

    let minimal = parse_info(
        br#"{"versions":["v0"],"token_required":true,"max_forward_size":4096,"turn":false}"#,
    )
    .unwrap();
    assert_eq!(minimal.key, None);
    assert_eq!(minimal.binding, InfoBinding::Exporter);
    assert!(!minimal.stun_auth && minimal.stun.is_empty() && minimal.forward_limits.is_none());

    for bad in [
        full.replace("challenge", "other"),
        full.replace("\"stun_auth\":true", "\"stun_auth\":1"),
        full.replace(&base32::encode(key.as_bytes()), "aaaa"),
        full.replace("\"forward_limits\":{", "\"forward_limits\":[{")
            .replace("1000000}", "1000000}]"),
    ] {
        assert!(parse_info(bad.as_bytes()).is_err(), "{bad}");
    }
}
