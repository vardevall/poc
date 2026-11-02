//! The certificates of vv-04 §2.3: the Web PKI certificate for the names configured as web
//! addresses and the pinned one for every other name or none, chosen by SNI on one configuration,
//! on TCP and on QUIC.

mod common;

use std::future::pending;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use common::Client;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::crypto::ring as provider;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use vardevall_proto::keys::SwitchPublic;
use vardevall_switch::config::{Certificate, Config};
use vardevall_switch::{Sockets, Switch, key};

struct Running {
    addr: SocketAddr,
    public: SwitchPublic,
    roots: RootCertStore,
    switch: Arc<Switch>,
    dir: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn temp_dir() -> PathBuf {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).unwrap();
    let dir = std::env::temp_dir().join(format!("vv-cert-{}", u64::from_be_bytes(random)));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn start() -> Running {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let dir = temp_dir();
    std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key_pair.serialize_pem()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();

    let secret = key::generate().unwrap();
    let public = secret.public();
    let mut config = Config::new(vec!["127.0.0.1:0".parse().unwrap()], "unused".into());
    config.certificate = Some(Certificate::Files {
        cert_file: dir.join("cert.pem"),
        key_file: dir.join("key.pem"),
        names: vec!["localhost".to_owned()],
    });
    let switch = Arc::new(Switch::new(&config, secret).unwrap());
    let (tcp, udp) = common::tcp_and_udp().await;
    let addr = tcp.local_addr().unwrap();
    let running = switch.clone();
    let task = tokio::spawn(async move {
        let sockets = Sockets {
            tcp: vec![tcp],
            h3: vec![udp],
            ..Default::default()
        };
        running.run_with(sockets, pending()).await;
    });
    Running {
        addr,
        public,
        roots,
        switch,
        dir,
        task,
    }
}

/// A client that checks the Web PKI: it accepts the certificate of `roots` for `localhost`.
fn browser(roots: RootCertStore, alpn: &[&[u8]]) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

#[tokio::test]
async fn a_configured_web_name_gets_the_web_certificate_over_tcp() {
    let s = start().await;
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let tls = TlsConnector::from(Arc::new(browser(s.roots.clone(), &[b"http/1.1"])))
        .connect(name, tcp)
        .await
        .unwrap();
    let (mut send, conn) = http1::handshake(TokioIo::new(tls)).await.unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .uri("https://localhost/v0/info")
        .header("host", "localhost")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = send.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let alt_svc = resp.headers()["alt-svc"].to_str().unwrap().to_owned();
    assert_eq!(alt_svc, format!("h3=\":{}\"; ma=86400", s.addr.port()));
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(!body.is_empty());
}

#[tokio::test]
async fn any_other_name_gets_the_pinned_certificate() {
    let s = start().await;
    let mut c = Client::connect(s.addr, s.public).await;
    assert_eq!(c.get("/v0/info", None).await.status, StatusCode::OK);
    assert!(
        Client::try_connect(s.addr, key::generate().unwrap().public(), &[b"h2"])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_connection_without_sni_gets_the_pinned_certificate() {
    let s = start().await;
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let ip = ServerName::try_from("127.0.0.1").unwrap();
    let pinned = common::tls_connector(s.public, &[b"http/1.1"]);
    pinned.connect(ip.clone(), tcp).await.unwrap();
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let wrong = common::tls_connector(key::generate().unwrap().public(), &[b"http/1.1"]);
    assert!(wrong.connect(ip, tcp).await.is_err());
}

#[tokio::test]
async fn the_name_decides_not_the_client() {
    let s = start().await;
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let web_name = ServerName::try_from("localhost").unwrap();
    let pinned = common::tls_connector(s.public, &[b"http/1.1"]);
    assert!(pinned.connect(web_name, tcp).await.is_err());
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let other = ServerName::try_from("elsewhere.example").unwrap();
    let browser = TlsConnector::from(Arc::new(browser(s.roots.clone(), &[b"http/1.1"])));
    assert!(browser.connect(other, tcp).await.is_err());
}

#[tokio::test]
async fn the_web_certificate_is_replaced_on_reload() {
    let s = start().await;
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let connect = |roots: RootCertStore, addr| async move {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        TlsConnector::from(Arc::new(browser(roots, &[b"http/1.1"])))
            .connect(name, tcp)
            .await
            .map(|_| ())
    };
    connect(s.roots.clone(), s.addr).await.unwrap();
    assert!(connect(roots.clone(), s.addr).await.is_err());

    std::fs::write(s.dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(s.dir.join("key.pem"), key_pair.serialize_pem()).unwrap();
    s.switch.file_certificate().unwrap().reload().unwrap();
    connect(roots, s.addr).await.unwrap();
    assert!(connect(s.roots.clone(), s.addr).await.is_err());
}

#[tokio::test]
async fn quic_makes_the_same_choice() {
    let s = start().await;
    let crypto = QuicClientConfig::try_from(browser(s.roots.clone(), &[b"h3"])).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let conn = endpoint
        .connect(s.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let req = Request::builder()
        .uri("https://localhost/v0/info")
        .body(())
        .unwrap();
    let mut stream = send.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    assert_eq!(
        stream.recv_response().await.unwrap().status(),
        StatusCode::OK
    );
    let mut body = 0;
    while let Some(chunk) = stream.recv_data().await.unwrap() {
        body += chunk.remaining();
    }
    assert!(body > 0);
}

#[test]
fn a_missing_certificate_file_is_an_error() {
    let mut config = Config::new(vec!["127.0.0.1:0".parse().unwrap()], "unused".into());
    config.certificate = Some(Certificate::Files {
        cert_file: "/nonexistent/cert.pem".into(),
        key_file: "/nonexistent/key.pem".into(),
        names: vec!["localhost".to_owned()],
    });
    assert!(Switch::new(&config, key::generate().unwrap()).is_err());
}

#[tokio::test]
async fn quic_presents_the_pinned_key_to_any_other_name_and_to_none() {
    let s = start().await;
    let connect = |expect: SwitchPublic, name: &'static str| async move {
        let crypto = QuicClientConfig::try_from(common::client_config(expect, &[b"h3"])).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        endpoint.connect(s.addr, name).unwrap().await.map(|_| ())
    };
    connect(s.public, "switch.invalid").await.unwrap();
    assert!(
        connect(key::generate().unwrap().public(), "switch.invalid")
            .await
            .is_err()
    );
    assert!(connect(s.public, "localhost").await.is_err());
}

/// The hybrid key exchange (vv-04 §2.3 SHOULD) with both certificates, over TCP and QUIC. The
/// ClientHello with an ML-KEM share does not fit one QUIC Initial packet.
mod post_quantum {
    use super::*;
    use rustls::NamedGroup;

    fn pq() -> Arc<rustls::crypto::CryptoProvider> {
        vardevall_tls_pq::shared_provider()
    }

    fn browser_pq(roots: RootCertStore, alpn: &[&[u8]]) -> ClientConfig {
        let mut config = ClientConfig::builder_with_provider(pq())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        config
    }

    async fn group(config: ClientConfig, addr: SocketAddr, name: &'static str) -> NamedGroup {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let tls = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(name).unwrap(), tcp)
            .await
            .unwrap();
        tls.get_ref()
            .1
            .negotiated_key_exchange_group()
            .unwrap()
            .name()
    }

    #[tokio::test]
    async fn tcp_negotiates_x25519mlkem768_with_either_certificate() {
        let s = start().await;
        let raw = common::client_config_with(pq(), s.public, &[b"h2"]);
        assert_eq!(
            group(raw, s.addr, "switch.invalid").await,
            NamedGroup::X25519MLKEM768
        );
        let x509 = browser_pq(s.roots.clone(), &[b"h2"]);
        assert_eq!(
            group(x509, s.addr, "localhost").await,
            NamedGroup::X25519MLKEM768
        );
    }

    #[tokio::test]
    async fn quic_completes_with_either_certificate() {
        let s = start().await;
        let raw = common::client_config_with(pq(), s.public, &[b"h3"]);
        let x509 = browser_pq(s.roots.clone(), &[b"h3"]);
        for (config, name) in [(raw, "switch.invalid"), (x509, "localhost")] {
            let crypto = QuicClientConfig::try_from(config).unwrap();
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
            endpoint.connect(s.addr, name).unwrap().await.unwrap();
        }
    }
}
