//! Web addresses (vv-04 §2.1, §2.3, §4.1): the switch is authenticated through the Web PKI, its
//! key comes from `/v0/info`, and the binding is the one it advertises.

mod common;

use std::future::pending;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use common::{Setup, SwitchUse, ipv6};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use vardevall::{NodeEvent, SwitchAuth, SwitchFailure, SwitchSpec, SwitchState, os_rng};
use vardevall_proto::keys::{NetworkSecret, SwitchSecret};
use vardevall_switch::config::{Binding, Certificate, Config};
use vardevall_switch::{Switch, key};

/// A certificate for `localhost` that a node can be told to trust.
struct Authority {
    der: CertificateDer<'static>,
    pem: String,
    key_pem: String,
    key_der: Vec<u8>,
}

fn authority() -> Authority {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    Authority {
        der: cert.der().clone(),
        pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        key_der: key_pair.serialize_der(),
    }
}

struct Running {
    spec: SwitchSpec,
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
    let dir = std::env::temp_dir().join(format!("vv-web-{}", u64::from_be_bytes(random)));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn web_spec(auth: &Authority, port: u16) -> SwitchSpec {
    SwitchSpec {
        auth: SwitchAuth::Web {
            extra_roots: vec![auth.der.to_vec()],
        },
        host: "localhost".to_owned(),
        port,
        token: None,
    }
}

/// A switch that serves `localhost` with `auth` as a web address.
async fn web_switch(
    auth: &Authority,
    secret: SwitchSecret,
    port: u16,
    binding: Binding,
) -> Running {
    let dir = temp_dir();
    std::fs::write(dir.join("cert.pem"), &auth.pem).unwrap();
    std::fs::write(dir.join("key.pem"), &auth.key_pem).unwrap();
    let mut config = Config::new(vec!["127.0.0.1:0".parse().unwrap()], "unused".into());
    config.certificate = Some(Certificate::Files {
        cert_file: dir.join("cert.pem"),
        key_file: dir.join("key.pem"),
        names: vec!["localhost".to_owned()],
    });
    config.binding = binding;
    let switch = Arc::new(Switch::new(&config, secret).unwrap());
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move { switch.run(vec![listener], pending()).await });
    Running {
        spec: web_spec(auth, port),
        dir,
        task,
    }
}

fn registered(e: &NodeEvent) -> bool {
    matches!(
        e,
        NodeEvent::Switch {
            state: SwitchState::Registered,
            ..
        }
    )
}

fn failure(e: NodeEvent) -> Option<SwitchFailure> {
    match e {
        NodeEvent::Switch {
            state: SwitchState::Disconnected(f),
            ..
        } => Some(f),
        _ => None,
    }
}

#[tokio::test]
async fn nodes_register_at_a_web_address_and_exchange_packets_through_it() {
    let auth = authority();
    let sw = web_switch(&auth, key::generate().unwrap(), 0, Binding::Exporter).await;
    let net = NetworkSecret::generate(&mut os_rng());
    let (a_setup, b_setup) = (Setup::new(&net), Setup::new(&net));
    let (a_key, b_key) = (a_setup.public(), b_setup.public());
    let mut b = b_setup
        .peer(a_key, None)
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();
    let mut a = a_setup
        .peer(b_key, None)
        .switch(sw.spec.clone(), SwitchUse::Data)
        .start();
    a.next(|e| registered(&e).then_some(())).await;
    b.next(|e| registered(&e).then_some(())).await;
    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"through the web switch");
    let mut sent = 0;
    let got = loop {
        assert!(a.handle.send_packet(&b_key, &packet));
        sent += 1;
        if let Ok(p) = tokio::time::timeout(Duration::from_millis(500), b.packet()).await {
            break p;
        }
        assert!(sent < 20, "no packet arrived");
    };
    assert_eq!(got, (a_key, packet));
}

#[tokio::test]
async fn a_web_address_behind_a_terminating_proxy_registers_with_a_challenge() {
    let auth = authority();
    let sw = web_switch(&auth, key::generate().unwrap(), 0, Binding::Challenge).await;
    let net = NetworkSecret::generate(&mut os_rng());
    let mut node = Setup::new(&net)
        .switch(sw.spec.clone(), SwitchUse::Handshake)
        .start();
    node.next(|e| registered(&e).then_some(())).await;
}

#[tokio::test]
async fn a_certificate_the_web_pki_refuses_is_untrusted() {
    let auth = authority();
    let sw = web_switch(&auth, key::generate().unwrap(), 0, Binding::Exporter).await;
    let mut spec = sw.spec.clone();
    spec.auth = SwitchAuth::Web {
        extra_roots: Vec::new(),
    };
    let net = NetworkSecret::generate(&mut os_rng());
    let mut node = Setup::new(&net).switch(spec, SwitchUse::Handshake).start();
    assert_eq!(node.next(failure).await, SwitchFailure::Untrusted);
}

#[tokio::test]
async fn a_new_key_at_the_same_web_address_takes_effect_at_the_next_registration() {
    let auth = authority();
    let sw = web_switch(&auth, key::generate().unwrap(), 0, Binding::Exporter).await;
    let port = sw.spec.port;
    let net = NetworkSecret::generate(&mut os_rng());
    let mut node = Setup::new(&net)
        .switch(sw.spec.clone(), SwitchUse::Handshake)
        .start();
    node.next(|e| registered(&e).then_some(())).await;
    drop(sw);
    node.next(|e| failure(e).map(|_| ())).await;
    let _rotated = web_switch(&auth, key::generate().unwrap(), port, Binding::Exporter).await;
    node.next(|e| registered(&e).then_some(())).await;
}

/// A TLS server for `localhost` that answers every request with `body` as `200 OK`.
async fn fixed_reply_server(auth: &Authority, body: &'static str) -> u16 {
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(auth.key_der.clone()));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![auth.der.clone()], key)
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if tls.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn a_web_switch_whose_info_names_no_key_is_refused() {
    let auth = authority();
    let port = fixed_reply_server(
        &auth,
        r#"{"versions":["v0"],"token_required":false,"max_forward_size":4096,"stun":[],"turn":false}"#,
    )
    .await;
    let net = NetworkSecret::generate(&mut os_rng());
    let mut node = Setup::new(&net)
        .switch(web_spec(&auth, port), SwitchUse::Handshake)
        .start();
    assert_eq!(node.next(failure).await, SwitchFailure::Untrusted);
}

#[tokio::test]
async fn the_refusal_comes_from_the_missing_key_and_not_from_the_connection() {
    let auth = authority();
    let key = key::generate().unwrap().public();
    let body: &'static str = Box::leak(
        format!(
            r#"{{"versions":["v0"],"key":"{key}","token_required":false,"max_forward_size":4096,"stun":[],"turn":false}}"#
        )
        .into_boxed_str(),
    );
    let port = fixed_reply_server(&auth, body).await;
    let net = NetworkSecret::generate(&mut os_rng());
    let mut node = Setup::new(&net)
        .switch(web_spec(&auth, port), SwitchUse::Handshake)
        .start();
    assert_eq!(node.next(failure).await, SwitchFailure::Protocol);
}
