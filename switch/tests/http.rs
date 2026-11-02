//! The API over TLS: registration, listing, forwarding, events and what outsiders learn.

mod common;

use std::time::Duration;

use common::*;
use http::{Method, StatusCode};
use vardevall_proto::keys::{NetworkSecret, NodePublic, base32};
use vardevall_switch_proto::api::{
    Binding, bound_data, client_proofs, parse_challenge_response, register_request,
};

async fn pair(s: &TestSwitch) -> (Client, Member, Client, Member, Events, Events) {
    let mut ca = Client::connect(s.addr, s.public).await;
    let a = register(&mut ca, &s.public, node_key(1), net_secret(1)).await;
    let mut ea = Client::connect(s.addr, s.public).await;
    let ea = ea.open_events(&a.session).await;
    let mut cb = Client::connect(s.addr, s.public).await;
    let b = register(&mut cb, &s.public, node_key(2), net_secret(1)).await;
    let mut eb = Client::connect(s.addr, s.public).await;
    let eb = eb.open_events(&b.session).await;
    (ca, a, cb, b, ea, eb)
}

#[tokio::test]
async fn info_describes_the_switch() {
    let s = start(config()).await;
    let mut c = Client::connect(s.addr, s.public).await;
    let r = c.get("/v0/info", None).await;
    assert_eq!(r.status, StatusCode::OK);
    let j = r.json();
    assert_eq!(j["versions"][0], "v0");
    assert_eq!(j["token_required"], false);
    assert_eq!(j["max_forward_size"], 4096);
    assert_eq!(j["turn"], false);
    assert_eq!(j["key"], s.public.to_string());
    assert_eq!(j["binding"], "exporter");
    assert_eq!(j["stun_auth"], false);
    assert_eq!(j["forward_limits"]["bits_per_second"], 64_000);
    assert_eq!(j["forward_limits"]["bytes"], 50_000_000);
    assert_eq!(r.headers["content-type"], "application/json");
}

#[tokio::test]
async fn registration_works_over_http2_and_http1() {
    let s = start(config()).await;
    for (alpn, expect) in [
        (&[&b"h2"[..]][..], &b"h2"[..]),
        (&[&b"http/1.1"[..]][..], &b"http/1.1"[..]),
    ] {
        let mut c = Client::connect_alpn(s.addr, s.public, alpn).await;
        assert_eq!(c.alpn, expect);
        let m = register(&mut c, &s.public, node_key(10), net_secret(10)).await;
        assert_eq!(m.session.len(), 52);
        let r = c.get("/v0/members", Some(&m.session)).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.json()["members"].as_array().unwrap().len(), 0);
    }
}

#[tokio::test]
async fn a_client_that_expects_another_switch_key_aborts() {
    let s = start(config()).await;
    let other = vardevall_switch::key::generate().unwrap().public();
    assert!(Client::try_connect(s.addr, other, &[b"h2"]).await.is_err());
}

#[tokio::test]
async fn challenge_bound_registration() {
    let s = start(config()).await;
    let mut c = Client::connect(s.addr, s.public).await;
    let r = c.get("/v0/challenge", None).await;
    assert_eq!(r.status, StatusCode::OK);
    let (challenge, expires) = parse_challenge_response(&r.body).unwrap();
    assert_eq!(expires, 60);

    let node = node_key(3);
    let net = net_secret(3);
    let binding = Binding::Challenge(challenge);
    let b = bound_data(&binding, HOST, &node.public(), &net.public(), &s.public).unwrap();
    let proofs = client_proofs(&node, &net, &s.public, &b).unwrap();
    let body = register_request(&node.public(), &net.public(), &binding, HOST, &proofs);
    let r = c.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(r.status, StatusCode::OK);
    let reply = vardevall_switch_proto::api::parse_register_response(&r.body).unwrap();
    assert_eq!(reply.switch_proof, proofs.switch_proof);

    let mut forged = challenge;
    forged[30] ^= 1;
    let binding = Binding::Challenge(forged);
    let b = bound_data(&binding, HOST, &node.public(), &net.public(), &s.public).unwrap();
    let proofs = client_proofs(&node, &net, &s.public, &b).unwrap();
    let body = register_request(&node.public(), &net.public(), &binding, HOST, &proofs);
    let r = c.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_code(), "urn:vardevall:error:invalid-proof");
}

#[tokio::test]
async fn proofs_of_another_connection_or_secret_are_refused() {
    let s = start(config()).await;
    let mut c1 = Client::connect(s.addr, s.public).await;
    let mut c2 = Client::connect(s.addr, s.public).await;
    let body = register_body(&c1, &s.public, &node_key(1), &net_secret(1));
    let r = c2.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let wrong_net = register_body(&c1, &s.public, &node_key(1), &net_secret(2));
    let tampered = wrong_net.replace(
        &net_secret(2).public().to_base32(),
        &net_secret(1).public().to_base32(),
    );
    let r = c1
        .request(Method::POST, "/v0/register", &[], &tampered)
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_code(), "urn:vardevall:error:invalid-proof");
    let r = c1.request(Method::POST, "/v0/register", &[], "{}").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.headers["content-type"], "application/problem+json");
    let r = c1
        .request(Method::POST, "/v0/register", &[], "not json")
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_host_the_switch_does_not_serve_is_an_invalid_proof() {
    let mut cfg = config();
    cfg.names.push("192.0.2.7".into());
    cfg.names.push("2001:db8::1".into());
    let s = start(cfg).await;
    let mut c = Client::connect(s.addr, s.public).await;
    let (node, net) = (node_key(1), net_secret(1));
    let long = format!("{}.test", "a".repeat(250));
    let unserved = register_body_for(&c, &s.public, "other.test", &node, &net);
    for host in [
        "other.test",
        "192.0.2.8",
        "switch.test:443",
        "",
        long.as_str(),
    ] {
        let body = unserved.replace("\"host\":\"other.test\"", &format!("\"host\":\"{host}\""));
        let r = c.request(Method::POST, "/v0/register", &[], &body).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{host:?}");
        assert_eq!(r.error_code(), "urn:vardevall:error:invalid-proof");
    }
    let r = c.get("/v0/info", None).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn the_served_names_match_in_normal_form() {
    let mut cfg = config();
    cfg.names.push("192.0.2.7".into());
    cfg.names.push("2001:db8::1".into());
    let s = start(cfg).await;
    let (node, net) = (node_key(1), net_secret(1));
    for (n, host) in [
        "switch.test",
        "Switch.TEST.",
        "192.0.2.7",
        "2001:db8::1",
        "[2001:DB8:0:0:0:0:0:1]",
    ]
    .into_iter()
    .enumerate()
    {
        let mut c = Client::connect(s.addr, s.public).await;
        let normal = vardevall_switch_proto::api::normalize_host(host).unwrap();
        let body = register_body_for(&c, &s.public, &normal, &node_key(n as u8 + 1), &net);
        let body = body.replace(
            &format!("\"host\":\"{normal}\""),
            &format!("\"host\":\"{host}\""),
        );
        let r = c.request(Method::POST, "/v0/register", &[], &body).await;
        assert_eq!(r.status, StatusCode::OK, "{host}");
    }
    let mut c = Client::connect(s.addr, s.public).await;
    let body = register_body_for(&c, &s.public, "SWITCH.test", &node, &net);
    let r = c.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn proofs_made_for_one_served_name_do_not_register_under_another() {
    let mut cfg = config();
    cfg.names.push("relay.test".into());
    let s = start(cfg).await;
    let mut c = Client::connect(s.addr, s.public).await;
    let (node, net) = (node_key(1), net_secret(1));
    let body = register_body_for(&c, &s.public, "relay.test", &node, &net);
    let relayed = body.replace("\"host\":\"relay.test\"", "\"host\":\"switch.test\"");
    assert_ne!(body, relayed);
    let r = c.request(Method::POST, "/v0/register", &[], &relayed).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_code(), "urn:vardevall:error:invalid-proof");
    let r = c.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn a_registration_without_host_is_malformed() {
    let s = start(config()).await;
    let mut c = Client::connect(s.addr, s.public).await;
    let body = register_body(&c, &s.public, &node_key(1), &net_secret(1));
    let without = body.replace("\"host\":\"switch.test\",", "");
    assert_ne!(body, without);
    let r = c.request(Method::POST, "/v0/register", &[], &without).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn operator_tokens() {
    let mut cfg = config();
    cfg.tokens = vec!["s3cret".into()];
    let s = start(cfg).await;
    let mut c = Client::connect(s.addr, s.public).await;
    assert_eq!(c.get("/v0/info", None).await.json()["token_required"], true);
    let body = register_body(&c, &s.public, &node_key(1), &net_secret(1));
    for headers in [
        vec![],
        vec![("authorization", "Bearer wrong")],
        vec![("authorization", "Basic s3cret")],
    ] {
        let r = c
            .request(Method::POST, "/v0/register", &headers, &body)
            .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert_eq!(r.error_code(), "urn:vardevall:error:token-required");
    }
    let r = c
        .request(
            Method::POST,
            "/v0/register",
            &[("authorization", "Bearer s3cret")],
            &body,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn members_events_and_forwarding() {
    let s = start(config()).await;
    let (mut ca, a, mut cb, b, mut ea, mut eb) = pair(&s).await;

    let online = ea.expect("online").await;
    assert_eq!(online.data["node"], b.public().to_base32());
    let generation = online.data["gen"].as_u64().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(
        generation.abs_diff(now) < 60_000,
        "gen is the switch clock in ms"
    );

    let list = ca.get("/v0/members", Some(&a.session)).await.json();
    assert_eq!(list["members"].as_array().unwrap().len(), 1);
    assert_eq!(list["members"][0]["node"], b.public().to_base32());
    assert_eq!(list["truncated"], false);
    let one = ca
        .get(&format!("/v0/members/{}", b.public()), Some(&a.session))
        .await;
    assert_eq!(one.status, StatusCode::OK);
    assert_eq!(one.json()["gen"], generation);

    let msg = base32::encode(b"hello through the switch");
    let body = format!("{{\"to\":\"{}\",\"msg\":\"{msg}\"}}", b.public());
    let r = ca
        .request(
            Method::POST,
            "/v0/forward",
            &[("vv-session", &a.session)],
            &body,
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let f = eb.expect("forward").await;
    assert_eq!(f.data["from"], a.public().to_base32());
    assert_eq!(f.data["msg"], msg);

    let body = format!("{{\"to\":\"{}\",\"msg\":\"{msg}\"}}", a.public());
    let r = cb
        .request(
            Method::POST,
            "/v0/forward",
            &[("vv-session", &b.session)],
            &body,
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    ea.expect("forward").await;

    let r = cb
        .request(
            Method::DELETE,
            "/v0/session",
            &[("vv-session", &b.session)],
            "",
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let off = ea.expect("offline").await;
    assert_eq!(off.data["node"], b.public().to_base32());
    assert!(eb.next().await.is_none());
    let r = cb.get("/v0/members", Some(&b.session)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = ca
        .get(&format!("/v0/members/{}", b.public()), Some(&a.session))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.error_code(), "urn:vardevall:error:not-online");
}

#[tokio::test]
async fn registering_again_replaces_the_session() {
    let s = start(config()).await;
    let mut c1 = Client::connect(s.addr, s.public).await;
    let first = register(&mut c1, &s.public, node_key(1), net_secret(1)).await;
    let mut ce = Client::connect(s.addr, s.public).await;
    let mut events = ce.open_events(&first.session).await;
    let mut c2 = Client::connect(s.addr, s.public).await;
    let second = register(&mut c2, &s.public, node_key(1), net_secret(1)).await;
    assert_ne!(first.session, second.session);
    events.expect("replaced").await;
    assert!(events.next().await.is_none());
    let r = c1.get("/v0/members", Some(&first.session)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        c2.get("/v0/members", Some(&second.session)).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn presence_ends_when_the_stream_stays_closed() {
    let mut cfg = config();
    cfg.timeouts.reconnect_grace = Duration::from_millis(300);
    let s = start(cfg).await;
    let (mut ca, a, _cb, b, mut ea, eb) = pair(&s).await;
    ea.expect("online").await;
    drop(eb);
    let off = tokio::time::timeout(Duration::from_secs(5), ea.expect("offline"))
        .await
        .unwrap();
    assert_eq!(off.data["node"], b.public().to_base32());
    let r = ca
        .get(&format!("/v0/members/{}", b.public()), Some(&a.session))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn forwarding_limits_and_errors() {
    let s = start(config()).await;
    let (mut ca, a, _cb, b, _ea, _eb) = pair(&s).await;
    let big = base32::encode(&vec![0u8; 4097]);
    let body = format!("{{\"to\":\"{}\",\"msg\":\"{big}\"}}", b.public());
    let r = ca
        .request(
            Method::POST,
            "/v0/forward",
            &[("vv-session", &a.session)],
            &body,
        )
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(r.error_code(), "urn:vardevall:error:too-large");

    let huge = "a".repeat(100_000);
    let r = ca
        .request(
            Method::POST,
            "/v0/forward",
            &[("vv-session", &a.session)],
            &huge,
        )
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);

    let r = ca
        .request(
            Method::POST,
            "/v0/forward",
            &[("vv-session", &a.session)],
            "{\"to\":1}",
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = ca.request(Method::GET, "/v0/forward", &[], "").await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(r.headers["allow"], "POST");
    let r = ca.get("/v0/nothing", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn outsiders_learn_nothing_about_who_is_online() {
    let s = start(config()).await;
    let (mut ca, a, _cb, b, _ea, _eb) = pair(&s).await;
    let mut other = Client::connect(s.addr, s.public).await;
    let outsider = register(&mut other, &s.public, node_key(9), net_secret(9)).await;
    let mut anon = Client::connect(s.addr, s.public).await;

    let msg = base32::encode(b"x");
    let forward_to = |node: &NodePublic| format!("{{\"to\":\"{node}\",\"msg\":\"{msg}\"}}");
    let absent = NodePublic::from_bytes([0x77; 32]);

    let mut seen = Vec::new();
    for session in [
        None,
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Some("garbage"),
    ] {
        for target in [b.public(), absent] {
            let h: Vec<(&str, &str)> = session.map(|s| ("vv-session", s)).into_iter().collect();
            let r = anon
                .request(Method::POST, "/v0/forward", &h, &forward_to(&target))
                .await;
            seen.push((r.status, r.body.clone()));
            let r = anon.get(&format!("/v0/members/{target}"), session).await;
            seen.push((r.status, r.body.clone()));
        }
        let r = anon.get("/v0/members", session).await;
        seen.push((r.status, r.body.clone()));
        let r = anon.get("/v0/events", session).await;
        seen.push((r.status, r.body.clone()));
    }
    assert!(seen.iter().all(|x| *x == seen[0]), "{seen:?}");
    assert_eq!(seen[0].0, StatusCode::UNAUTHORIZED);

    let to_member = anon
        .request(
            Method::POST,
            "/v0/forward",
            &[("vv-session", &outsider.session)],
            &forward_to(&b.public()),
        )
        .await;
    let to_absent = anon
        .request(
            Method::POST,
            "/v0/forward",
            &[("vv-session", &outsider.session)],
            &forward_to(&absent),
        )
        .await;
    assert_eq!(to_member.status, StatusCode::NOT_FOUND);
    assert_eq!(
        (to_member.status, &to_member.body),
        (to_absent.status, &to_absent.body)
    );

    let lookup_member = anon
        .get(
            &format!("/v0/members/{}", b.public()),
            Some(&outsider.session),
        )
        .await;
    let lookup_absent = anon
        .get(&format!("/v0/members/{absent}"), Some(&outsider.session))
        .await;
    assert_eq!(lookup_member.status, StatusCode::NOT_FOUND);
    assert_eq!(lookup_member.body, lookup_absent.body);
    let list = anon
        .get("/v0/members", Some(&outsider.session))
        .await
        .json();
    assert_eq!(list["members"].as_array().unwrap().len(), 0);

    let claim = |pk: &NetworkSecret, node: u8| {
        register_body(&anon, &s.public, &node_key(node), &net_secret(2)).replace(
            &net_secret(2).public().to_base32(),
            &pk.public().to_base32(),
        )
    };
    let existing = claim(&net_secret(1), 1);
    let unknown = claim(&net_secret(77), 55);
    let r1 = anon
        .request(Method::POST, "/v0/register", &[], &existing)
        .await;
    let r2 = anon
        .request(Method::POST, "/v0/register", &[], &unknown)
        .await;
    assert_eq!((r1.status, &r1.body), (r2.status, &r2.body));
    assert_eq!(r1.status, StatusCode::FORBIDDEN);
    let _ = (&mut ca, &a);
}

#[tokio::test]
async fn per_address_rate_limit_answers_429_with_retry_after() {
    let mut cfg = config();
    cfg.limits.per_ip_burst = 3.0;
    let s = start(cfg).await;
    let mut c = Client::connect(s.addr, s.public).await;
    for _ in 0..3 {
        assert_eq!(c.get("/v0/challenge", None).await.status, StatusCode::OK);
    }
    let r = c.get("/v0/challenge", None).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.error_code(), "urn:vardevall:error:rate-limited");
    assert!(
        r.headers["retry-after"]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            >= 1
    );
    let body = register_body(&c, &s.public, &node_key(1), &net_secret(1));
    let r = c.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(c.get("/v0/info", None).await.status, StatusCode::OK);
}

#[tokio::test]
async fn per_network_limits_apply_after_the_proofs_verify() {
    let mut cfg = config();
    cfg.limits.register_burst = 2.0;
    cfg.limits.register_rate = 0.01;
    cfg.limits.per_ip_burst = 1000.0;
    let s = start(cfg).await;
    let mut c = Client::connect(s.addr, s.public).await;
    for n in 0..2 {
        register(&mut c, &s.public, node_key(n), net_secret(1)).await;
    }
    let body = register_body(&c, &s.public, &node_key(5), &net_secret(1));
    let r = c.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    let forged = register_body(&c, &s.public, &node_key(5), &net_secret(2)).replace(
        &net_secret(2).public().to_base32(),
        &net_secret(1).public().to_base32(),
    );
    let r = c.request(Method::POST, "/v0/register", &[], &forged).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    register(&mut c, &s.public, node_key(5), net_secret(3)).await;
}

#[tokio::test]
async fn global_caps_answer_429() {
    let mut cfg = config();
    cfg.limits.max_registrations = 2;
    cfg.limits.max_event_streams = 1;
    cfg.limits.per_ip_burst = 1000.0;
    let s = start(cfg).await;
    let mut c = Client::connect(s.addr, s.public).await;
    let a = register(&mut c, &s.public, node_key(1), net_secret(1)).await;
    let b = register(&mut c, &s.public, node_key(2), net_secret(1)).await;
    let body = register_body(&c, &s.public, &node_key(3), &net_secret(1));
    let r = c.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers.contains_key("retry-after"));
    let mut e1 = Client::connect(s.addr, s.public).await;
    let _events = e1.open_events(&a.session).await;
    let r = c
        .request(Method::GET, "/v0/events", &[("vv-session", &b.session)], "")
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn slow_clients_are_cut_off() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cfg = config();
    cfg.timeouts.tls_handshake = Duration::from_millis(300);
    cfg.timeouts.request_header = Duration::from_millis(300);
    cfg.timeouts.idle = Duration::from_millis(300);
    let s = start(cfg).await;

    let mut raw = tokio::net::TcpStream::connect(s.addr).await.unwrap();
    raw.write_all(&[0x16, 0x03]).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), raw.read(&mut buf))
        .await
        .expect("the switch must close a stalled handshake")
        .unwrap_or(0);
    assert_eq!(n, 0);

    let mut h1 = Client::try_connect(s.addr, s.public, &[b"http/1.1"])
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(900)).await;
    let req = http::Request::builder()
        .uri("https://switch.invalid/v0/info")
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap();
    assert!(h1.try_send(req).await.is_err());
}

#[tokio::test]
async fn errors_carry_the_codes_of_vv_04() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cfg = config();
    cfg.timeouts.request_body = Duration::from_millis(300);
    let s = start(cfg).await;
    let mut c = Client::connect(s.addr, s.public).await;

    for path in ["/v0/nothing", "/elsewhere", "/v0/members/not-a-key"] {
        let r = c.get(path, None).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(r.error_code(), "urn:vardevall:error:not-found");
        assert_eq!(r.headers["content-type"], "application/problem+json");
    }
    for (method, path, allow) in [
        (Method::POST, "/v0/info", "GET"),
        (Method::GET, "/v0/register", "POST"),
        (Method::GET, "/v0/forward", "POST"),
        (Method::POST, "/v0/session", "DELETE"),
    ] {
        let r = c.request(method, path, &[], "").await;
        assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
        assert_eq!(r.error_code(), "urn:vardevall:error:method-not-allowed");
        assert_eq!(r.headers["allow"], allow);
    }

    let tcp = tokio::net::TcpStream::connect(s.addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("switch.invalid").unwrap();
    let mut tls = tls_connector(s.public, &[b"http/1.1"])
        .connect(name, tcp)
        .await
        .unwrap();
    tls.write_all(b"POST /v0/register HTTP/1.1\r\nhost: x\r\ncontent-length: 100\r\n\r\n{")
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("the switch must answer a body that does not arrive")
        .unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 408"), "{text}");
    assert!(text.contains("urn:vardevall:error:timeout"), "{text}");

    let mut cfg = config();
    cfg.limits.max_registrations = 1;
    let s = start(cfg).await;
    let mut c = Client::connect(s.addr, s.public).await;
    register(&mut c, &s.public, node_key(1), net_secret(1)).await;
    let body = register_body(&c, &s.public, &node_key(2), &net_secret(2));
    let r = c.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.error_code(), "urn:vardevall:error:rate-limited");
}

#[tokio::test]
async fn the_status_line_counts_and_names_no_one() {
    let mut cfg = config();
    cfg.tokens = vec!["secret-token".into()];
    let s = start(cfg).await;
    let mut c = Client::connect(s.addr, s.public).await;
    let body = register_body(&c, &s.public, &node_key(1), &net_secret(1));
    let r = c.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let auth = [("authorization", "Bearer secret-token")];
    let forged = body.replace(
        &node_key(1).public().to_base32(),
        &node_key(2).public().to_base32(),
    );
    let r = c
        .request(Method::POST, "/v0/register", &auth, &forged)
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = c.request(Method::POST, "/v0/register", &auth, &body).await;
    assert_eq!(r.status, StatusCode::OK);

    let line = s.switch.api().status_line();
    assert!(
        line.contains("1 registrations in 1 networks, 0 event streams"),
        "{line}"
    );
    assert!(
        line.contains("0 rate-limited, 1 token-required, 1 invalid-proof"),
        "{line}"
    );
    for secret in [
        node_key(1).public().to_base32(),
        net_secret(1).public().to_base32(),
        "secret-token".to_owned(),
    ] {
        assert!(!line.contains(&secret));
    }
    let again = s.switch.api().status_line();
    assert!(
        again.contains("0 rate-limited, 0 token-required, 0 invalid-proof"),
        "{again}"
    );
}

fn turn_config() -> vardevall_switch::config::Config {
    let mut c = config();
    c.turn = Some(vardevall_switch::config::Turn {
        urls: vec!["turn:turn.example:3478?transport=udp".to_owned()],
        secret: "vardevall t\u{eb}st t\u{fc}rn secret".to_owned(),
        ttl: Duration::from_secs(3600),
        bits_per_second: Some(5_000_000),
        bytes: None,
        silent: false,
        server: None,
    });
    c.stun.uris = vec!["stun:stun.example:3478".to_owned()];
    c
}

fn check_turn(turn: &serde_json::Value, secret: &str) -> String {
    let username = turn["username"].as_str().unwrap();
    let (expiry, id) = username.split_once(':').unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiry: u64 = expiry.parse().unwrap();
    assert!((now + 3590..=now + 3601).contains(&expiry));
    assert_eq!(id.len(), 16);
    assert_eq!(
        turn["credential"],
        vardevall_switch_proto::api::turn_credential(secret, username)
    );
    assert_eq!(turn["ttl"], 3600);
    assert_eq!(turn["limits"]["bits_per_second"], 5_000_000);
    assert_eq!(turn["urls"][0], "turn:turn.example:3478?transport=udp");
    username.to_owned()
}

#[tokio::test]
async fn turn_credentials_are_issued_at_registration_and_on_request() {
    let s = start(turn_config()).await;
    let secret = "vardevall t\u{eb}st t\u{fc}rn secret";
    let mut c = Client::connect(s.addr, s.public).await;
    let info = c.get("/v0/info", None).await.json();
    assert_eq!(info["turn"], true);
    assert_eq!(info["stun"][0], "stun:stun.example:3478");

    let body = register_body(&c, &s.public, &node_key(1), &net_secret(1));
    let r = c.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(r.status, StatusCode::OK);
    let j = r.json();
    let first = check_turn(&j["turn"], secret);
    let session = j["session"].as_str().unwrap().to_owned();

    let r = c
        .request(Method::POST, "/v0/turn", &[("vv-session", &session)], "")
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let second = check_turn(&r.json(), secret);
    assert_ne!(first, second, "the opaque id is random per issuance");

    let r = c.request(Method::POST, "/v0/turn", &[], "").await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.error_code(), "urn:vardevall:error:session-invalid");
}

#[tokio::test]
async fn without_turn_registration_has_none_and_the_endpoint_is_absent() {
    let s = start(config()).await;
    let mut c = Client::connect(s.addr, s.public).await;
    let body = register_body(&c, &s.public, &node_key(1), &net_secret(1));
    let r = c.request(Method::POST, "/v0/register", &[], &body).await;
    let j = r.json();
    assert!(j.get("turn").is_none());
    let session = j["session"].as_str().unwrap().to_owned();
    let r = c
        .request(Method::POST, "/v0/turn", &[("vv-session", &session)], "")
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[cfg(feature = "stun-turn")]
#[tokio::test]
async fn the_embedded_stun_server_reports_the_mapped_address() {
    use tokio::net::UdpSocket;
    let secret = vardevall_switch::key::generate().unwrap();
    let switch = vardevall_switch::Switch::new(&config(), secret).unwrap();
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let to = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let sockets = vardevall_switch::Sockets {
            stun: vec![server],
            ..Default::default()
        };
        switch.run_with(sockets, std::future::pending()).await;
    });
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut req = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
    req.extend_from_slice(&[9u8; 12]);
    client.send_to(&req, to).await.unwrap();
    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..2], &[1, 1]);
    let port = u16::from_be_bytes([buf[26], buf[27]]) ^ 0x2112;
    assert_eq!(n, 32);
    assert_eq!(port, client.local_addr().unwrap().port());
    assert_eq!(&buf[28..32], &[127 ^ 0x21, 0x12, 0xa4, 1 ^ 0x42]);
    task.abort();
}

#[cfg(feature = "stun-turn")]
#[tokio::test]
async fn the_stun_server_stops_answering_a_client_that_floods_it() {
    use tokio::net::UdpSocket;
    let mut c = config();
    c.limits.stun_burst = 5.0;
    c.limits.stun_rate = 0.01;
    let switch =
        vardevall_switch::Switch::new(&c, vardevall_switch::key::generate().unwrap()).unwrap();
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let to = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let sockets = vardevall_switch::Sockets {
            stun: vec![server],
            ..Default::default()
        };
        switch.run_with(sockets, std::future::pending()).await;
    });
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut req = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
    req.extend_from_slice(&[9u8; 12]);
    for _ in 0..20 {
        client.send_to(&req, to).await.unwrap();
    }
    let mut answers = 0;
    let mut buf = [0u8; 128];
    while tokio::time::timeout(Duration::from_millis(500), client.recv(&mut buf))
        .await
        .is_ok()
    {
        answers += 1;
    }
    assert_eq!(answers, 5);
    task.abort();
}
