//! STUN servers of the configuration (vv-05 §3.1, vv-07 §3.6), with and without a short-term
//! credential (RFC 8489 §9.1).

mod common;

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use common::Setup;
use tokio::net::UdpSocket;
use vardevall::{LogLevel, NodeEvent, StunSpec, os_rng};
use vardevall_proto::keys::NetworkSecret;
use vardevall_switch_proto::api::turn_credential;

const SECRET: &str = "stun-secret";

/// A STUN server on loopback; with `secret` it answers only requests that carry a credential
/// derived from it.
async fn server(secret: Option<&'static str>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 576];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            let unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let reply = match secret {
                Some(s) => vardevall_switch::stun::respond_authenticated(&buf[..n], from, s, unix),
                None => vardevall_switch::stun::respond(&buf[..n], from),
            };
            if let Some(r) = reply {
                let _ = socket.send_to(&r, from).await;
            }
        }
    });
    addr
}

fn credential(secret: &str) -> (String, String) {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let username = format!("{}:test", unix + 3600);
    let password = turn_credential(secret, &username);
    (username, password)
}

async fn result(spec: StunSpec) -> String {
    let net = NetworkSecret::generate(&mut os_rng());
    let mut setup = Setup::new(&net);
    setup.stun = vec![spec];
    let mut node = setup.start();
    node.next(|e| match e {
        NodeEvent::Log {
            level: LogLevel::Info,
            message,
        } if message.starts_with("STUN: ") => Some(message),
        _ => None,
    })
    .await
}

#[tokio::test]
async fn a_configured_server_gives_the_punch_candidate() {
    let addr = server(None).await;
    let r = result(StunSpec {
        urls: vec![format!("stun:127.0.0.1:{}", addr.port())],
        username: None,
        credential: None,
    })
    .await;
    assert!(r.contains("ipv4 punchable"), "{r}");
}

#[tokio::test]
async fn a_configured_credential_authenticates_the_binding_requests() {
    let addr = server(Some(SECRET)).await;
    let (username, password) = credential(SECRET);
    let r = result(StunSpec {
        urls: vec![format!("stun:127.0.0.1:{}", addr.port())],
        username: Some(username),
        credential: Some(password),
    })
    .await;
    assert!(r.contains("ipv4 punchable"), "{r}");
}

#[tokio::test]
async fn a_wrong_credential_gets_silence_and_counts_as_udp_blocked() {
    let addr = server(Some(SECRET)).await;
    let (username, password) = credential("another secret");
    let r = result(StunSpec {
        urls: vec![format!("stun:127.0.0.1:{}", addr.port())],
        username: Some(username),
        credential: Some(password),
    })
    .await;
    assert!(r.contains("ipv4 udp-blocked"), "{r}");
}
