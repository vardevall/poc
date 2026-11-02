//! A switch behind a proxy (vv-04 §2.5): the client address from the PROXY protocol or a
//! forwarding header, only from configured sources, and plain HTTP on loopback for a tunnel daemon.

mod common;

use std::future::pending;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use common::tls_connector;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use vardevall_proto::keys::SwitchPublic;
use vardevall_switch::config::Config;
use vardevall_switch::{Sockets, Switch, key};

struct Running {
    tls: SocketAddr,
    plain: SocketAddr,
    public: SwitchPublic,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start(text: &str) -> Running {
    let config = Config::parse(
        &format!("key_file = \"unused\"\nnames = [\"switch.test\"]\nplain_listen = [\"127.0.0.1:0\"]\n{text}"),
        std::path::Path::new("."),
    )
    .unwrap();
    let secret = key::generate().unwrap();
    let public = secret.public();
    let switch = Arc::new(Switch::new(&config, secret).unwrap());
    let tls = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (tls_addr, plain_addr) = (tls.local_addr().unwrap(), plain.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let sockets = Sockets {
            tcp: vec![tls],
            plain: vec![plain],
            ..Default::default()
        };
        switch.run_with(sockets, pending()).await;
    });
    Running {
        tls: tls_addr,
        plain: plain_addr,
        public,
        task,
    }
}

const LIMITS: &str = "[limits]\nregister_per_ip_burst = 2\nregister_per_ip_per_second = 0.001\n";

async fn get<T>(io: T, path: &str, headers: &[(&str, &str)]) -> (StatusCode, Bytes)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut send, conn) = http1::handshake(TokioIo::new(io)).await.unwrap();
    tokio::spawn(conn);
    let mut req = Request::builder()
        .uri(path)
        .header("host", "switch.invalid");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = send
        .send_request(req.body(Empty::<Bytes>::new()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.into_body().collect().await.unwrap().to_bytes())
}

async fn plain_get(s: &Running, headers: &[(&str, &str)]) -> StatusCode {
    let tcp = TcpStream::connect(s.plain).await.unwrap();
    get(tcp, "/v0/challenge", headers).await.0
}

fn v2(src: &str) -> Vec<u8> {
    let src: SocketAddr = src.parse().unwrap();
    let mut out = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    match src {
        SocketAddr::V4(a) => {
            out.extend([0x21, 0x11, 0, 12]);
            out.extend(a.ip().octets());
            out.extend([10, 0, 0, 1]);
            out.extend(a.port().to_be_bytes());
            out.extend(443u16.to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.extend([0x21, 0x21, 0, 36]);
            out.extend(a.ip().octets());
            out.extend([0; 16]);
            out.extend(a.port().to_be_bytes());
            out.extend(443u16.to_be_bytes());
        }
    }
    out
}

async fn over_proxy_protocol(s: &Running, header: Option<&[u8]>, path: &str) -> StatusCode {
    let mut tcp = TcpStream::connect(s.tls).await.unwrap();
    if let Some(h) = header {
        tcp.write_all(h).await.unwrap();
    }
    let name = ServerName::try_from("switch.invalid").unwrap();
    let tls = tls_connector(s.public, &[b"http/1.1"])
        .connect(name, tcp)
        .await
        .unwrap();
    get(tls, path, &[]).await.0
}

#[tokio::test]
async fn plain_http_serves_the_api_and_reports_the_binding() {
    let s = start("binding = \"challenge\"\n").await;
    let tcp = TcpStream::connect(s.plain).await.unwrap();
    let (status, body) = get(tcp, "/v0/info", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let info: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(info["binding"], "challenge");
    assert_eq!(plain_get(&s, &[]).await, StatusCode::OK);
}

#[tokio::test]
async fn the_forwarded_header_counts_only_from_configured_sources() {
    let trusting = format!(
        "forwarded_header = {{ name = \"CF-Connecting-IP\", from = [\"127.0.0.0/8\"] }}\n{LIMITS}"
    );
    let s = start(&trusting).await;
    for ip in ["192.0.2.1", "192.0.2.2"] {
        assert_eq!(
            plain_get(&s, &[("cf-connecting-ip", ip)]).await,
            StatusCode::OK
        );
        assert_eq!(
            plain_get(&s, &[("cf-connecting-ip", ip)]).await,
            StatusCode::OK
        );
        assert_eq!(
            plain_get(&s, &[("cf-connecting-ip", ip)]).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    assert_eq!(
        plain_get(&s, &[("cf-connecting-ip", "2001:db8::1")]).await,
        StatusCode::OK
    );

    let stranger =
        format!("forwarded_header = {{ name = \"Forwarded\", from = [\"10.0.0.0/8\"] }}\n{LIMITS}");
    let s = start(&stranger).await;
    for (ip, want) in [
        ("192.0.2.1", StatusCode::OK),
        ("192.0.2.2", StatusCode::OK),
        ("192.0.2.3", StatusCode::TOO_MANY_REQUESTS),
    ] {
        let value = format!("for={ip}");
        assert_eq!(plain_get(&s, &[("forwarded", &value)]).await, want);
    }
}

#[tokio::test]
async fn the_forwarded_header_works_over_tls_too() {
    let text = format!(
        "forwarded_header = {{ name = \"X-Forwarded-For\", from = [\"127.0.0.1\"] }}\n{LIMITS}"
    );
    let s = start(&text).await;
    let name = ServerName::try_from("switch.invalid").unwrap();
    for ip in ["192.0.2.1", "192.0.2.2"] {
        for _ in 0..2 {
            let tcp = TcpStream::connect(s.tls).await.unwrap();
            let tls = tls_connector(s.public, &[b"http/1.1"])
                .connect(name.clone(), tcp)
                .await
                .unwrap();
            assert_eq!(
                get(
                    tls,
                    "/v0/challenge",
                    &[("x-forwarded-for", &format!("1.1.1.1, {ip}"))]
                )
                .await
                .0,
                StatusCode::OK
            );
        }
    }
}

#[tokio::test]
async fn the_proxy_protocol_names_the_client_from_configured_sources() {
    let s = start(&format!("proxy_protocol = [\"127.0.0.0/8\"]\n{LIMITS}")).await;
    let a = v2("192.0.2.1:4000");
    let b = v2("[2001:db8::7]:4000");
    for h in [&a, &b] {
        for _ in 0..2 {
            assert_eq!(
                over_proxy_protocol(&s, Some(h), "/v0/challenge").await,
                StatusCode::OK
            );
        }
        assert_eq!(
            over_proxy_protocol(&s, Some(h), "/v0/challenge").await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    let plain = TcpStream::connect(s.plain).await.unwrap();
    let mut plain = plain;
    plain.write_all(&a).await.unwrap();
    assert_eq!(
        get(plain, "/v0/challenge", &[]).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn a_configured_source_must_send_the_header() {
    let s = start("proxy_protocol = [\"127.0.0.1\"]\n").await;
    let tcp = TcpStream::connect(s.tls).await.unwrap();
    let name = ServerName::try_from("switch.invalid").unwrap();
    assert!(
        tls_connector(s.public, &[b"http/1.1"])
            .connect(name, tcp)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn other_sources_are_not_asked_for_the_header() {
    let s = start("proxy_protocol = [\"10.0.0.0/8\"]\n").await;
    assert_eq!(
        over_proxy_protocol(&s, None, "/v0/challenge").await,
        StatusCode::OK
    );
}
