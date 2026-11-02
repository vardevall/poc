//! HTTP/3 on the same port as TCP (vv-04 §2.2): registration with the QUIC exporter, listing and
//! the events stream.

mod common;

use std::future::pending;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use common::{Client, HOST, client_config, net_secret, node_key, register_body};
use http::{Method, Request, StatusCode};
use quinn::crypto::rustls::QuicClientConfig;
use vardevall_proto::keys::{NodeSecret, SwitchPublic, base32};
use vardevall_switch::{Sockets, Switch, key};
use vardevall_switch_proto::api::{
    Binding, EXPORTER_LABEL, bound_data, client_proofs, parse_register_response, register_request,
};

struct Running {
    addr: SocketAddr,
    public: SwitchPublic,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start() -> Running {
    let secret = key::generate().unwrap();
    let public = secret.public();
    let config = common::config();
    let switch = Arc::new(Switch::new(&config, secret).unwrap());
    let (tcp, udp) = common::tcp_and_udp().await;
    let addr = tcp.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let sockets = Sockets {
            tcp: vec![tcp],
            h3: vec![udp],
            ..Default::default()
        };
        switch.run_with(sockets, pending()).await;
    });
    Running { addr, public, task }
}

struct H3 {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    exporter: [u8; 32],
    _conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
}

impl H3 {
    async fn connect(addr: SocketAddr, expect: SwitchPublic) -> H3 {
        let crypto = QuicClientConfig::try_from(client_config(expect, &[b"h3"])).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let conn = endpoint
            .connect(addr, "switch.invalid")
            .unwrap()
            .await
            .unwrap();
        let mut exporter = [0u8; 32];
        conn.export_keying_material(&mut exporter, EXPORTER_LABEL.as_bytes(), &[])
            .unwrap();
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        H3 {
            send,
            exporter,
            _conn: conn,
            _endpoint: endpoint,
        }
    }

    async fn request(
        &mut self,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (StatusCode, Bytes) {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("https://switch.invalid{path}"));
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut stream = self.send.send_request(b.body(()).unwrap()).await.unwrap();
        stream
            .send_data(Bytes::from(body.to_owned()))
            .await
            .unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        let mut out = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            out.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        (resp.status(), Bytes::from(out))
    }
}

#[tokio::test]
async fn http3_registers_with_the_quic_exporter_and_lists_members() {
    let s = start().await;
    let mut c = H3::connect(s.addr, s.public).await;

    let (st, body) = c.request(Method::GET, "/v0/info", &[], "").await;
    assert_eq!(st, StatusCode::OK);
    assert!(std::str::from_utf8(&body).unwrap().contains("\"versions\""));

    let node: NodeSecret = node_key(1);
    let net = net_secret(1);
    let binding = Binding::Exporter(c.exporter);
    let b = bound_data(&binding, HOST, &node.public(), &net.public(), &s.public).unwrap();
    let proofs = client_proofs(&node, &net, &s.public, &b).unwrap();
    let req = register_request(&node.public(), &net.public(), &binding, HOST, &proofs);
    let (st, body) = c.request(Method::POST, "/v0/register", &[], &req).await;
    assert_eq!(st, StatusCode::OK, "{body:?}");
    let parsed = parse_register_response(&body).unwrap();
    assert_eq!(parsed.switch_proof, proofs.switch_proof);
    let session = base32::encode(&parsed.session);

    let (st, body) = c
        .request(Method::GET, "/v0/members", &[("vv-session", &session)], "")
        .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("\"members\":[]")
    );

    let (st, _) = c.request(Method::GET, "/v0/members", &[], "").await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _) = c.request(Method::GET, "/nope", &[], "").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_http3_events_stream_receives_presence_from_a_tcp_member() {
    let s = start().await;
    let mut c = H3::connect(s.addr, s.public).await;
    let node = node_key(1);
    let net = net_secret(1);
    let binding = Binding::Exporter(c.exporter);
    let b = bound_data(&binding, HOST, &node.public(), &net.public(), &s.public).unwrap();
    let proofs = client_proofs(&node, &net, &s.public, &b).unwrap();
    let req = register_request(&node.public(), &net.public(), &binding, HOST, &proofs);
    let (_, body) = c.request(Method::POST, "/v0/register", &[], &req).await;
    let session = base32::encode(&parse_register_response(&body).unwrap().session);

    let r = Request::builder()
        .uri("https://switch.invalid/v0/events")
        .header("vv-session", &session)
        .header("accept", "text/event-stream")
        .body(())
        .unwrap();
    let mut events = c.send.send_request(r).await.unwrap();
    events.finish().await.unwrap();
    assert_eq!(
        events.recv_response().await.unwrap().status(),
        StatusCode::OK
    );

    let mut tcp = Client::connect(s.addr, s.public).await;
    let body = register_body(&tcp, &s.public, &node_key(2), &net_secret(1));
    let r = tcp.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(r.status, StatusCode::OK);
    let session_b = r.json()["session"].as_str().unwrap().to_owned();
    let mut tcp2 = Client::connect(s.addr, s.public).await;
    let _events_b = tcp2.open_events(&session_b).await;

    let mut seen = String::new();
    let read = async {
        while !seen.contains("event: online") {
            let mut chunk = events.recv_data().await.unwrap().expect("stream ended");
            seen.push_str(std::str::from_utf8(&chunk.copy_to_bytes(chunk.remaining())).unwrap());
        }
    };
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("no online event");
    assert!(seen.contains(&node_key(2).public().to_string()));
}

#[tokio::test]
async fn http3_aborts_when_the_switch_key_is_not_the_expected_one() {
    let s = start().await;
    let other = key::generate().unwrap().public();
    let crypto = QuicClientConfig::try_from(client_config(other, &[b"h3"])).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let r = endpoint.connect(s.addr, "switch.invalid").unwrap().await;
    assert!(r.is_err());
}
