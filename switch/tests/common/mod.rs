#![allow(dead_code)]

use std::future::pending;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as provider;
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use vardevall_proto::keys::{
    NetworkSecret, NodePublic, NodeSecret, SwitchPublic, SwitchSecret, base32,
};
use vardevall_switch::config::Config;
use vardevall_switch::{Switch, key};
use vardevall_switch_proto::api::{
    Binding, EXPORTER_LABEL, bound_data, client_proofs, parse_register_response, register_request,
};

/// A TCP listener on loopback and a UDP socket on the same port. A free TCP port can be taken
/// in UDP by another test, so the pair is retried.
pub async fn tcp_and_udp() -> (TcpListener, tokio::net::UdpSocket) {
    loop {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        if let Ok(udp) = tokio::net::UdpSocket::bind(tcp.local_addr().unwrap()).await {
            return (tcp, udp);
        }
    }
}

#[derive(Debug)]
struct Pin(SwitchPublic);

impl ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if spki_of(end_entity).and_then(|spki| SwitchPublic::from_spki(spki.as_ref()))
            == Some(self.0)
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let spki = spki_of(cert).ok_or(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ))?;
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &spki,
            dss,
            &provider::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// The SubjectPublicKeyInfo of a certificate; a pinned client looks at nothing else (vv-04 §2.3).
fn spki_of(cert: &CertificateDer<'_>) -> Option<SubjectPublicKeyInfoDer<'static>> {
    Some(
        webpki::EndEntityCert::try_from(cert)
            .ok()?
            .subject_public_key_info(),
    )
}

pub struct TestSwitch {
    pub addr: SocketAddr,
    pub public: SwitchPublic,
    pub switch: Arc<Switch>,
    task: JoinHandle<()>,
}

impl Drop for TestSwitch {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub const HOST: &str = "switch.test";

pub fn config() -> Config {
    let mut config = Config::new(vec!["127.0.0.1:0".parse().unwrap()], "unused.key".into());
    config.names = vec![HOST.to_owned()];
    config
}

pub async fn start(config: Config) -> TestSwitch {
    let secret = key::generate().unwrap();
    start_with(config, secret).await
}

pub async fn start_with(config: Config, secret: SwitchSecret) -> TestSwitch {
    let public = secret.public();
    let switch = Arc::new(Switch::new(&config, secret).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let s = switch.clone();
    let task = tokio::spawn(async move { s.run(vec![listener], pending()).await });
    TestSwitch {
        addr,
        public,
        switch,
        task,
    }
}

enum Sender {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
}

pub struct Client {
    sender: Sender,
    pub exporter: [u8; 32],
    pub alpn: Vec<u8>,
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Reply {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }

    pub fn error_code(&self) -> String {
        self.json()["type"].as_str().unwrap_or_default().to_owned()
    }
}

pub fn tls_connector(expect: SwitchPublic, alpn: &[&[u8]]) -> TlsConnector {
    TlsConnector::from(Arc::new(client_config(expect, alpn)))
}

pub fn client_config(expect: SwitchPublic, alpn: &[&[u8]]) -> ClientConfig {
    client_config_with(Arc::new(provider::default_provider()), expect, alpn)
}

pub fn client_config_with(
    provider: Arc<rustls::crypto::CryptoProvider>,
    expect: SwitchPublic,
    alpn: &[&[u8]],
) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pin(expect)))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

impl Client {
    pub async fn connect(addr: SocketAddr, expect: SwitchPublic) -> Client {
        Client::try_connect(addr, expect, &[b"h2", b"http/1.1"])
            .await
            .unwrap()
    }

    pub async fn connect_alpn(addr: SocketAddr, expect: SwitchPublic, alpn: &[&[u8]]) -> Client {
        Client::try_connect(addr, expect, alpn).await.unwrap()
    }

    pub async fn try_connect(
        addr: SocketAddr,
        expect: SwitchPublic,
        alpn: &[&[u8]],
    ) -> std::io::Result<Client> {
        let tcp = TcpStream::connect(addr).await?;
        let name = ServerName::try_from("switch.invalid").unwrap();
        let tls = tls_connector(expect, alpn).connect(name, tcp).await?;
        let (_, session) = tls.get_ref();
        let exporter = session
            .export_keying_material([0u8; 32], EXPORTER_LABEL.as_bytes(), None)
            .unwrap();
        let negotiated = session.alpn_protocol().unwrap_or_default().to_vec();
        let io = TokioIo::new(tls);
        let sender = if negotiated == b"h2" {
            let (s, c) = http2::handshake(TokioExecutor::new(), io)
                .await
                .map_err(std::io::Error::other)?;
            tokio::spawn(c);
            Sender::H2(s)
        } else {
            let (s, c) = http1::handshake(io).await.map_err(std::io::Error::other)?;
            tokio::spawn(c);
            Sender::H1(s)
        };
        Ok(Client {
            sender,
            exporter,
            alpn: negotiated,
        })
    }

    fn build(
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Request<Full<Bytes>> {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("https://switch.invalid{path}"));
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Full::new(Bytes::from(body.to_owned()))).unwrap()
    }

    pub async fn send_raw(&mut self, req: Request<Full<Bytes>>) -> Response {
        match &mut self.sender {
            Sender::H1(s) => s.send_request(req).await.unwrap(),
            Sender::H2(s) => s.send_request(req).await.unwrap(),
        }
    }

    pub async fn try_send(&mut self, req: Request<Full<Bytes>>) -> Result<Response, hyper::Error> {
        match &mut self.sender {
            Sender::H1(s) => s.send_request(req).await,
            Sender::H2(s) => s.send_request(req).await,
        }
    }

    pub async fn request(
        &mut self,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Reply {
        let resp = self
            .send_raw(Self::build(method, path, headers, body))
            .await;
        let (parts, body) = resp.into_parts();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes(),
        }
    }

    pub async fn get(&mut self, path: &str, session: Option<&str>) -> Reply {
        let h: Vec<(&str, &str)> = session.map(|s| ("vv-session", s)).into_iter().collect();
        self.request(Method::GET, path, &h, "").await
    }

    pub async fn open_events(&mut self, session: &str) -> Events {
        let req = Self::build(
            Method::GET,
            "/v0/events",
            &[("vv-session", session), ("accept", "text/event-stream")],
            "",
        );
        let resp = self.send_raw(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        Events {
            body: resp.into_body(),
            buf: String::new(),
        }
    }
}

type Response = hyper::Response<Incoming>;

pub struct Events {
    body: Incoming,
    buf: String,
}

pub struct Event {
    pub name: String,
    pub data: serde_json::Value,
}

impl Events {
    pub async fn next(&mut self) -> Option<Event> {
        loop {
            while let Some(end) = self.buf.find("\n\n") {
                let chunk: String = self.buf.drain(..end + 2).collect();
                let mut name = String::new();
                let mut data = String::new();
                for line in chunk.lines() {
                    if let Some(v) = line.strip_prefix("event: ") {
                        name = v.to_owned();
                    } else if let Some(v) = line.strip_prefix("data: ") {
                        data = v.to_owned();
                    }
                }
                if !name.is_empty() {
                    return Some(Event {
                        name,
                        data: serde_json::from_str(&data).unwrap(),
                    });
                }
            }
            let frame = tokio::time::timeout(Duration::from_secs(10), self.body.frame())
                .await
                .expect("timed out waiting for an event")?
                .ok()?;
            if let Ok(d) = frame.into_data() {
                self.buf.push_str(std::str::from_utf8(&d).unwrap());
            }
        }
    }

    pub async fn expect(&mut self, name: &str) -> Event {
        let e = self.next().await.expect("stream ended");
        assert_eq!(e.name, name);
        e
    }
}

pub struct Member {
    pub node: NodeSecret,
    pub net: NetworkSecret,
    pub session: String,
}

impl Member {
    pub fn public(&self) -> NodePublic {
        self.node.public()
    }
}

pub fn node_key(n: u8) -> NodeSecret {
    NodeSecret::from_bytes([n; 32])
}

pub fn net_secret(n: u8) -> NetworkSecret {
    NetworkSecret::from_bytes([n; 32])
}

pub fn register_body(
    client: &Client,
    switch: &SwitchPublic,
    node: &NodeSecret,
    net: &NetworkSecret,
) -> String {
    register_body_for(client, switch, HOST, node, net)
}

pub fn register_body_for(
    client: &Client,
    switch: &SwitchPublic,
    host: &str,
    node: &NodeSecret,
    net: &NetworkSecret,
) -> String {
    let binding = Binding::Exporter(client.exporter);
    let b = bound_data(&binding, host, &node.public(), &net.public(), switch).unwrap();
    let proofs = client_proofs(node, net, switch, &b).unwrap();
    register_request(&node.public(), &net.public(), &binding, host, &proofs)
}

pub async fn register(
    client: &mut Client,
    switch: &SwitchPublic,
    node: NodeSecret,
    net: NetworkSecret,
) -> Member {
    let binding = Binding::Exporter(client.exporter);
    let b = bound_data(&binding, HOST, &node.public(), &net.public(), switch).unwrap();
    let proofs = client_proofs(&node, &net, switch, &b).unwrap();
    let body = register_request(&node.public(), &net.public(), &binding, HOST, &proofs);
    let reply = client
        .request(Method::POST, "/v0/register", &[], &body)
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    let parsed = parse_register_response(&reply.body).unwrap();
    assert_eq!(parsed.switch_proof, proofs.switch_proof);
    Member {
        node,
        net,
        session: base32::encode(&parsed.session),
    }
}
