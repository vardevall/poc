//! The embedded TURN server (vv-04 §4.5, §2.3) driven by a minimal client over UDP and over TLS
//! with ALPN `stun.turn`.

#![cfg(feature = "stun-turn")]

mod common;

use std::future::pending;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::{Client as Http, net_secret, node_key, register_body, tls_connector};
use http::Method;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use vardevall_proto::keys::SwitchPublic;
use vardevall_switch::config::{Config, Turn, TurnServer};
use vardevall_switch::{Sockets, Switch, key};
use vardevall_switch_proto::api::turn_credential;
use vardevall_switch_proto::stun::{
    Builder, Class, Message, attr, encode_xor_addr, long_term_key, method,
};

const SECRET: &str = "turn test secret";

fn unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn server_config(f: impl FnOnce(&mut Turn, &mut TurnServer)) -> Config {
    let mut c = common::config();
    let mut server = TurnServer {
        listen: vec!["127.0.0.1:0".parse().unwrap()],
        relay_ipv4: Some("127.0.0.1".parse().unwrap()),
        relay_ipv6: None,
        relay_ipv4_public: None,
        relay_ipv6_public: None,
        relay_ports: (40000, 40999),
        realm: "vv.test".to_owned(),
        max_allocations: 100,
        allocations_per_credential: 4,
        allocations_per_ip: 100,
        allow_private_peers: true,
        tls: true,
    };
    let mut turn = Turn {
        urls: vec!["turn:127.0.0.1:3478".to_owned()],
        secret: SECRET.to_owned(),
        ttl: Duration::from_secs(3600),
        bits_per_second: None,
        bytes: None,
        silent: false,
        server: None,
    };
    f(&mut turn, &mut server);
    turn.server = Some(server);
    c.turn = Some(turn);
    c
}

struct Running {
    addr: SocketAddr,
    public: SwitchPublic,
    switch: Arc<Switch>,
    udp: SocketAddr,
    stun: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start(config: Config) -> Running {
    let secret = key::generate().unwrap();
    let public = secret.public();
    let switch = Arc::new(Switch::new(&config, secret).unwrap());
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp = udp_socket.local_addr().unwrap();
    let stun_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stun = stun_socket.local_addr().unwrap();
    let s = switch.clone();
    let task = tokio::spawn(async move {
        let sockets = Sockets {
            tcp: vec![tcp],
            turn: vec![udp_socket],
            stun: vec![stun_socket],
            ..Default::default()
        };
        s.run_with(sockets, pending()).await;
    });
    Running {
        addr,
        public,
        switch,
        udp,
        stun,
        task,
    }
}

fn credentials(expiry: u64) -> (String, String) {
    let username = format!("{expiry}:testid");
    let password = turn_credential(SECRET, &username);
    (username, password)
}

struct Client {
    sock: UdpSocket,
    server: SocketAddr,
    user: String,
    password: String,
    realm: Vec<u8>,
    nonce: Vec<u8>,
}

impl Client {
    async fn new(server: SocketAddr, creds: (String, String)) -> Client {
        Client {
            sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            server,
            user: creds.0,
            password: creds.1,
            realm: Vec::new(),
            nonce: Vec::new(),
        }
    }

    async fn exchange(&self, req: &[u8]) -> Message {
        self.sock.send_to(req, self.server).await.unwrap();
        let mut buf = [0u8; 2048];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), self.sock.recv(&mut buf))
                .await
                .expect("no response")
                .unwrap();
            let m = Message::parse(&buf[..n]).unwrap();
            if m.class != Class::Indication {
                return m;
            }
        }
    }

    fn authed(&self, m: u16, id: u8, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut b = Builder::new(m, Class::Request, &[id; 12]);
        for (t, v) in attrs {
            b = b.attr(*t, v);
        }
        let key = long_term_key(self.user.as_bytes(), &self.realm, self.password.as_bytes());
        b.attr(attr::USERNAME, self.user.as_bytes())
            .attr(attr::REALM, &self.realm)
            .attr(attr::NONCE, &self.nonce)
            .finish_with_integrity(&key)
    }

    async fn learn_realm(&mut self) {
        let first = Builder::new(method::ALLOCATE, Class::Request, &[1; 12])
            .attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0])
            .finish();
        let r = self.exchange(&first).await;
        assert_eq!(r.error_code(), Some(401));
        self.realm = r.get(attr::REALM).unwrap().to_vec();
        self.nonce = r.get(attr::NONCE).unwrap().to_vec();
    }

    /// Allocates, and returns the relayed address.
    async fn allocate(&mut self) -> Result<SocketAddr, u16> {
        if self.realm.is_empty() {
            self.learn_realm().await;
        }
        let req = self.authed(
            method::ALLOCATE,
            2,
            &[(attr::REQUESTED_TRANSPORT, vec![17, 0, 0, 0])],
        );
        let r = self.exchange(&req).await;
        match r.class {
            Class::Success => Ok(r.xor_addr(attr::XOR_RELAYED_ADDRESS).unwrap()),
            _ => Err(r.error_code().unwrap()),
        }
    }

    async fn permit(&self, peer: SocketAddr) -> Result<(), u16> {
        let mut req = Builder::new(method::CREATE_PERMISSION, Class::Request, &[3; 12])
            .attr(attr::XOR_PEER_ADDRESS, &encode_xor_addr(peer, &[3; 12]));
        let key = long_term_key(self.user.as_bytes(), &self.realm, self.password.as_bytes());
        req = req
            .attr(attr::USERNAME, self.user.as_bytes())
            .attr(attr::REALM, &self.realm)
            .attr(attr::NONCE, &self.nonce);
        let r = self.exchange(&req.finish_with_integrity(&key)).await;
        match r.class {
            Class::Success => Ok(()),
            _ => Err(r.error_code().unwrap()),
        }
    }
}

#[tokio::test]
async fn allocate_permit_and_relay_both_ways_with_indications_and_channels() {
    let s = start(server_config(|_, _| {})).await;
    let mut c = Client::new(s.udp, credentials(unix() + 3600)).await;
    let relayed = c.allocate().await.unwrap();
    assert_eq!(relayed.ip().to_string(), "127.0.0.1");
    assert!((40000..=40999).contains(&relayed.port()));

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    c.permit(peer_addr).await.unwrap();

    let txid = [9u8; 12];
    let ind = Builder::new(method::SEND, Class::Indication, &txid)
        .attr(attr::XOR_PEER_ADDRESS, &encode_xor_addr(peer_addr, &txid))
        .attr(attr::DATA, b"hello peer")
        .finish();
    c.sock.send_to(&ind, s.udp).await.unwrap();
    let mut buf = [0u8; 2048];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"hello peer");
    assert_eq!(from, relayed);

    peer.send_to(b"hello client", relayed).await.unwrap();
    let n = c.sock.recv(&mut buf).await.unwrap();
    let m = Message::parse(&buf[..n]).unwrap();
    assert_eq!((m.method, m.class), (method::DATA, Class::Indication));
    assert_eq!(m.get(attr::DATA), Some(&b"hello client"[..]));
    assert_eq!(m.xor_addr(attr::XOR_PEER_ADDRESS), Some(peer_addr));

    let bind = c.authed(
        method::CHANNEL_BIND,
        4,
        &[
            (attr::CHANNEL_NUMBER, vec![0x40, 0x01, 0, 0]),
            (attr::XOR_PEER_ADDRESS, encode_xor_addr(peer_addr, &[4; 12])),
        ],
    );
    assert_eq!(c.exchange(&bind).await.class, Class::Success);
    let mut data = vec![0x40, 0x01, 0, 2];
    data.extend_from_slice(b"hi");
    c.sock.send_to(&data, s.udp).await.unwrap();
    let (n, _) = peer.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hi");
    peer.send_to(b"yo", relayed).await.unwrap();
    let n = c.sock.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], &[0x40, 0x01, 0, 2, b'y', b'o']);
}

fn behind_nat(_: &mut Turn, srv: &mut TurnServer) {
    srv.relay_ipv4_public = Some("9.9.9.9".parse().unwrap());
    srv.allow_private_peers = false;
}

fn send_indication(peer: SocketAddr, data: &[u8]) -> Vec<u8> {
    let txid = [8u8; 12];
    Builder::new(method::SEND, Class::Indication, &txid)
        .attr(attr::XOR_PEER_ADDRESS, &encode_xor_addr(peer, &txid))
        .attr(attr::DATA, data)
        .finish()
}

#[tokio::test]
async fn behind_a_nat_the_public_address_is_reported_and_the_local_one_bound() {
    let s = start(server_config(|t, srv| {
        behind_nat(t, srv);
        srv.allow_private_peers = true;
        // Keeps the peer's ephemeral port out of the relay range, as it is on the relay's address.
        srv.relay_ports = (40000, 40009);
    }))
    .await;
    let mut c = Client::new(s.udp, credentials(unix() + 3600)).await;
    let relayed = c.allocate().await.unwrap();
    assert_eq!(relayed.ip().to_string(), "9.9.9.9");
    assert!((40000..=40009).contains(&relayed.port()));

    // The relay socket is on 127.0.0.1: a peer reaches it there, not at the public address.
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    c.permit(peer_addr).await.unwrap();
    peer.send_to(b"in", ("127.0.0.1", relayed.port()))
        .await
        .unwrap();
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(5), c.sock.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let m = Message::parse(&buf[..n]).unwrap();
    assert_eq!(m.get(attr::DATA), Some(&b"in"[..]));
    assert_eq!(m.xor_addr(attr::XOR_PEER_ADDRESS), Some(peer_addr));
    c.sock
        .send_to(&send_indication(peer_addr, b"out"), s.udp)
        .await
        .unwrap();
    let (n, from) = peer.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"out");
    assert_eq!(from.port(), relayed.port());
}

#[tokio::test]
async fn behind_a_nat_two_allocations_reach_each_other_at_their_public_addresses() {
    let s = start(server_config(behind_nat)).await;
    let creds = credentials(unix() + 3600);
    let mut a = Client::new(s.udp, creds.clone()).await;
    let mut b = Client::new(s.udp, creds).await;
    let ra = a.allocate().await.unwrap();
    let rb = b.allocate().await.unwrap();
    assert_eq!(ra.ip(), rb.ip());
    assert_eq!(ra.ip().to_string(), "9.9.9.9");
    a.permit(rb).await.unwrap();
    b.permit(ra).await.unwrap();

    a.sock
        .send_to(&send_indication(rb, b"a to b"), s.udp)
        .await
        .unwrap();
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(5), b.sock.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let m = Message::parse(&buf[..n]).unwrap();
    assert_eq!(m.get(attr::DATA), Some(&b"a to b"[..]));
    assert_eq!(m.xor_addr(attr::XOR_PEER_ADDRESS), Some(ra));

    let bind = b.authed(
        method::CHANNEL_BIND,
        4,
        &[
            (attr::CHANNEL_NUMBER, vec![0x40, 0x01, 0, 0]),
            (attr::XOR_PEER_ADDRESS, encode_xor_addr(ra, &[4; 12])),
        ],
    );
    assert_eq!(b.exchange(&bind).await.class, Class::Success);
    let mut data = vec![0x40, 0x01, 0, 2];
    data.extend_from_slice(b"hi");
    b.sock.send_to(&data, s.udp).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(5), a.sock.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let m = Message::parse(&buf[..n]).unwrap();
    assert_eq!(m.get(attr::DATA), Some(&b"hi"[..]));
    assert_eq!(m.xor_addr(attr::XOR_PEER_ADDRESS), Some(rb));
}

#[tokio::test]
async fn behind_a_nat_only_relay_ports_of_the_public_address_are_peers() {
    let s = start(server_config(behind_nat)).await;
    let mut c = Client::new(s.udp, credentials(unix() + 3600)).await;
    c.allocate().await.unwrap();
    for port in [3478, 443, 39999, 41000] {
        let peer: SocketAddr = format!("9.9.9.9:{port}").parse().unwrap();
        assert_eq!(c.permit(peer).await, Err(403), "{peer}");
    }
    c.permit("9.9.9.9:40500".parse().unwrap()).await.unwrap();
    // A permission for the address does not extend to other ports of it.
    let local = UdpSocket::bind("127.0.0.1:3478").await;
    if let Ok(local) = local {
        c.sock
            .send_to(
                &send_indication("9.9.9.9:3478".parse().unwrap(), b"x"),
                s.udp,
            )
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), local.recv(&mut buf))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn unpermitted_peers_get_nothing_and_the_relay_is_closed_on_release() {
    let s = start(server_config(|_, _| {})).await;
    let mut c = Client::new(s.udp, credentials(unix() + 3600)).await;
    let relayed = c.allocate().await.unwrap();
    let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    stranger.send_to(b"x", relayed).await.unwrap();
    let mut buf = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(300), c.sock.recv(&mut buf))
            .await
            .is_err()
    );
    let api = s.switch.api().turn_server().unwrap().clone();
    assert_eq!(api.allocations(), 1);
    let release = c.authed(
        method::REFRESH,
        5,
        &[(attr::LIFETIME, 0u32.to_be_bytes().to_vec())],
    );
    assert_eq!(c.exchange(&release).await.class, Class::Success);
    assert_eq!(api.allocations(), 0);
}

#[tokio::test]
async fn bad_expired_and_missing_credentials_are_refused() {
    let s = start(server_config(|_, _| {})).await;
    let mut ok = Client::new(s.udp, credentials(unix() + 3600)).await;
    ok.learn_realm().await;

    let mut wrong = Client::new(s.udp, credentials(unix() + 3600)).await;
    wrong.password = "wrong".to_owned();
    wrong.realm = ok.realm.clone();
    wrong.nonce = ok.nonce.clone();
    assert_eq!(wrong.allocate().await, Err(401));

    let mut expired = Client::new(s.udp, credentials(unix() - 10)).await;
    expired.realm = ok.realm.clone();
    expired.nonce = ok.nonce.clone();
    assert_eq!(expired.allocate().await, Err(401));

    let mut stale = Client::new(s.udp, credentials(unix() + 3600)).await;
    stale.realm = ok.realm.clone();
    stale.nonce = b"AAAA".to_vec();
    let req = stale.authed(
        method::ALLOCATE,
        2,
        &[(attr::REQUESTED_TRANSPORT, vec![17, 0, 0, 0])],
    );
    assert_eq!(stale.exchange(&req).await.error_code(), Some(438));
}

#[tokio::test]
async fn private_peers_are_refused_by_default_and_quotas_apply() {
    let s = start(server_config(|_, srv| {
        srv.allow_private_peers = false;
        srv.allocations_per_credential = 1;
    }))
    .await;
    let creds = credentials(unix() + 3600);
    let mut a = Client::new(s.udp, creds.clone()).await;
    a.allocate().await.unwrap();
    assert_eq!(a.permit("127.0.0.1:9".parse().unwrap()).await, Err(403));
    assert_eq!(a.permit("10.0.0.1:9".parse().unwrap()).await, Err(403));
    assert_eq!(a.permit("[::1]:9".parse().unwrap()).await, Err(443));
    for documentation in [
        "192.0.2.1:9",
        "198.51.100.1:9",
        "203.0.113.5:9",
        "[2001:db8::1]:9",
    ] {
        let expected = if documentation.starts_with('[') {
            Err(443)
        } else {
            Err(403)
        };
        assert_eq!(a.permit(documentation.parse().unwrap()).await, expected);
    }
    a.permit("8.8.8.8:9".parse().unwrap()).await.unwrap();

    let mut b = Client::new(s.udp, creds).await;
    b.realm = a.realm.clone();
    b.nonce = a.nonce.clone();
    assert_eq!(b.allocate().await, Err(486));
    assert_eq!(a.allocate().await, Err(437));
}

#[tokio::test]
async fn the_byte_quota_per_credential_stops_relaying() {
    let s = start(server_config(|t, _| t.bytes = Some(10))).await;
    let mut c = Client::new(s.udp, credentials(unix() + 3600)).await;
    let relayed = c.allocate().await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.permit(peer.local_addr().unwrap()).await.unwrap();
    peer.send_to(b"123456", relayed).await.unwrap();
    let mut buf = [0u8; 64];
    assert!(c.sock.recv(&mut buf).await.is_ok());
    peer.send_to(b"123456", relayed).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), c.sock.recv(&mut buf))
            .await
            .is_err(),
        "over the quota"
    );
}

#[tokio::test]
async fn the_rate_limit_per_allocation_drops_bursts() {
    let s = start(server_config(|t, _| t.bits_per_second = Some(8 * 4096))).await;
    let mut c = Client::new(s.udp, credentials(unix() + 3600)).await;
    let relayed = c.allocate().await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.permit(peer.local_addr().unwrap()).await.unwrap();
    for _ in 0..20 {
        peer.send_to(&[0u8; 1000], relayed).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut got = 0;
    let mut buf = [0u8; 2048];
    while tokio::time::timeout(Duration::from_millis(100), c.sock.recv(&mut buf))
        .await
        .is_ok()
    {
        got += 1;
    }
    assert!((3..20).contains(&got), "{got} packets passed");
}

#[tokio::test]
async fn binding_requests_are_answered_on_the_turn_port() {
    let s = start(server_config(|_, _| {})).await;
    let c = Client::new(s.udp, credentials(0)).await;
    let req = Builder::new(method::BINDING, Class::Request, &[7; 12]).finish();
    let r = c.exchange(&req).await;
    assert_eq!(
        r.xor_addr(attr::XOR_MAPPED_ADDRESS),
        Some(c.sock.local_addr().unwrap())
    );
}

#[tokio::test]
async fn udp_requests_beyond_the_per_address_limit_get_no_answer() {
    let mut config = server_config(|_, _| {});
    config.limits.stun_burst = 3.0;
    config.limits.stun_rate = 0.01;
    let s = start(config).await;
    let c = Client::new(s.udp, credentials(0)).await;
    let req = Builder::new(method::BINDING, Class::Request, &[7; 12]).finish();
    let mut answered = 0;
    for _ in 0..8 {
        c.sock.send_to(&req, c.server).await.unwrap();
        let mut buf = [0u8; 256];
        if tokio::time::timeout(Duration::from_millis(200), c.sock.recv(&mut buf))
            .await
            .is_ok()
        {
            answered += 1;
        }
    }
    assert_eq!(answered, 3);
}

#[tokio::test]
async fn turn_over_tls_shares_the_https_port_by_alpn() {
    let s = start(server_config(|_, _| {})).await;
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("switch.invalid").unwrap();
    let mut tls = tls_connector(s.public, &[b"stun.turn"])
        .connect(name, tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"stun.turn"[..]));

    let first = Builder::new(method::ALLOCATE, Class::Request, &[1; 12])
        .attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0])
        .finish();
    tls.write_all(&first).await.unwrap();
    let mut head = [0u8; 20];
    tls.read_exact(&mut head).await.unwrap();
    let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
    let mut body = vec![0u8; len];
    tls.read_exact(&mut body).await.unwrap();
    let mut raw = head.to_vec();
    raw.extend(body);
    let m = Message::parse(&raw).unwrap();
    assert_eq!(m.error_code(), Some(401));

    let creds = credentials(unix() + 3600);
    let key = long_term_key(
        creds.0.as_bytes(),
        m.get(attr::REALM).unwrap(),
        creds.1.as_bytes(),
    );
    let req = Builder::new(method::ALLOCATE, Class::Request, &[2; 12])
        .attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0])
        .attr(attr::USERNAME, creds.0.as_bytes())
        .attr(attr::REALM, m.get(attr::REALM).unwrap())
        .attr(attr::NONCE, m.get(attr::NONCE).unwrap())
        .finish_with_integrity(&key);
    tls.write_all(&req).await.unwrap();
    let mut head = [0u8; 20];
    tls.read_exact(&mut head).await.unwrap();
    let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
    let mut body = vec![0u8; len];
    tls.read_exact(&mut body).await.unwrap();
    let mut raw = head.to_vec();
    raw.extend(body);
    let m = Message::parse(&raw).unwrap();
    assert_eq!(m.class, Class::Success);
    assert!(m.xor_addr(attr::XOR_RELAYED_ADDRESS).is_some());
    let api = s.switch.api().turn_server().unwrap().clone();
    assert_eq!(api.allocations(), 1);
    drop(tls);
    for _ in 0..50 {
        if api.allocations() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the allocation outlived its connection");
}

#[tokio::test]
async fn https_still_works_next_to_turn() {
    let s = start(server_config(|_, _| {})).await;
    let mut c = common::Client::connect(s.addr, s.public).await;
    let r = c.get("/v0/info", None).await;
    assert_eq!(r.json()["turn"], true);
}

/// Registers with `token` and returns the `turn` object of the response and of `POST /v0/turn`.
async fn issue(s: &Running, token: &str, n: u8) -> (serde_json::Value, serde_json::Value) {
    let mut http = Http::connect(s.addr, s.public).await;
    let body = register_body(&http, &s.public, &node_key(n), &net_secret(n));
    let auth = format!("Bearer {token}");
    let reply = http
        .request(
            Method::POST,
            "/v0/register",
            &[("authorization", &auth)],
            &body,
        )
        .await;
    assert_eq!(reply.status, 200, "{:?}", reply.body);
    let json = reply.json();
    let session = json["session"].as_str().unwrap().to_owned();
    let again = http
        .request(Method::POST, "/v0/turn", &[("vv-session", &session)], "")
        .await
        .json();
    (json["turn"].clone(), again)
}

/// Relays 6-byte datagrams one by one through an allocation of the credentials in `turn`, and
/// returns how many came through.
async fn relayed_datagrams(s: &Running, turn: &serde_json::Value, sent: usize) -> usize {
    let creds = (
        turn["username"].as_str().unwrap().to_owned(),
        turn["credential"].as_str().unwrap().to_owned(),
    );
    let mut c = Client::new(s.udp, creds).await;
    let relayed = c.allocate().await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.permit(peer.local_addr().unwrap()).await.unwrap();
    let mut got = 0;
    for _ in 0..sent {
        peer.send_to(b"123456", relayed).await.unwrap();
        let mut buf = [0u8; 64];
        if tokio::time::timeout(Duration::from_millis(200), c.sock.recv(&mut buf))
            .await
            .is_ok()
        {
            got += 1;
        }
    }
    got
}

#[tokio::test]
async fn the_server_enforces_the_limits_each_token_advertises() {
    use vardevall_switch::config::TokenTurn;
    let mut config = server_config(|t, _| t.bytes = Some(100));
    config.tokens = vec!["plain".into(), "bronze".into(), "gold".into()];
    config.token_turn = vec![
        TokenTurn {
            token: "bronze".into(),
            bits_per_second: None,
            bytes: Some(20),
        },
        TokenTurn {
            token: "gold".into(),
            bits_per_second: Some(80_000_000),
            bytes: Some(0),
        },
    ];
    let s = start(config).await;
    let expected = [
        ("plain", Some(100), 16),
        ("bronze", Some(20), 3),
        ("gold", None, 20),
    ];
    for (n, (token, bytes, passes)) in (1u8..).zip(expected) {
        let (at_register, at_turn) = issue(&s, token, n).await;
        for turn in [&at_register, &at_turn] {
            assert_eq!(
                turn["limits"].get("bytes").and_then(|b| b.as_u64()),
                bytes,
                "{token}"
            );
        }
        assert_eq!(
            at_register["limits"]["bits_per_second"].as_u64(),
            (token == "gold").then_some(80_000_000)
        );
        assert_eq!(
            relayed_datagrams(&s, &at_turn, 20).await,
            passes,
            "{token} may relay {passes} datagrams"
        );
    }
}

/// Registers a node and returns the JSON of the response.
async fn register_json(s: &Running, n: u8) -> serde_json::Value {
    let mut http = Http::connect(s.addr, s.public).await;
    let body = register_body(&http, &s.public, &node_key(n), &net_secret(n));
    let reply = http.request(Method::POST, "/v0/register", &[], &body).await;
    assert_eq!(reply.status, 200, "{:?}", reply.body);
    reply.json()
}

/// A client that uses the realm and nonce of the credentials, as a node does.
async fn supplied(s: &Running, turn: &serde_json::Value) -> Client {
    let mut c = Client::new(
        s.udp,
        (
            turn["username"].as_str().unwrap().to_owned(),
            turn["credential"].as_str().unwrap().to_owned(),
        ),
    )
    .await;
    c.realm = turn["realm"].as_str().unwrap().as_bytes().to_vec();
    c.nonce = turn["nonce"].as_str().unwrap().as_bytes().to_vec();
    c
}

async fn is_silent(c: &Client, req: &[u8]) -> bool {
    c.sock.send_to(req, c.server).await.unwrap();
    let mut buf = [0u8; 2048];
    tokio::time::timeout(Duration::from_millis(300), c.sock.recv(&mut buf))
        .await
        .is_err()
}

fn allocate_request(id: u8) -> Vec<u8> {
    Builder::new(method::ALLOCATE, Class::Request, &[id; 12])
        .attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0])
        .finish()
}

#[tokio::test]
async fn credentials_carry_the_realm_and_nonce_for_an_authenticated_first_allocate() {
    for silent in [false, true] {
        let s = start(server_config(|t, _| t.silent = silent)).await;
        let json = register_json(&s, 1).await;
        let turn = &json["turn"];
        assert_eq!(turn["realm"], "vv.test");
        assert!(!turn["nonce"].as_str().unwrap().is_empty());
        let mut c = supplied(&s, turn).await;
        assert!(c.allocate().await.is_ok(), "silent: {silent}");

        let again = {
            let mut http = Http::connect(s.addr, s.public).await;
            let session = json["session"].as_str().unwrap();
            http.request(Method::POST, "/v0/turn", &[("vv-session", session)], "")
                .await
                .json()
        };
        assert_eq!(again["realm"], "vv.test");
        assert_ne!(again["username"], turn["username"]);
        assert!(supplied(&s, &again).await.allocate().await.is_ok());
    }
}

#[tokio::test]
async fn a_silent_server_answers_only_authenticated_requests() {
    let s = start(server_config(|t, _| t.silent = true)).await;
    let json = register_json(&s, 1).await;
    let turn = &json["turn"];
    let mut c = supplied(&s, turn).await;

    assert!(is_silent(&c, &allocate_request(1)).await, "no credentials");
    let api = s.switch.api().turn_server().unwrap().clone();
    assert_eq!(api.allocations(), 0);

    let mut wrong_key = supplied(&s, turn).await;
    wrong_key.password = "wrong".to_owned();
    assert!(
        is_silent(
            &wrong_key,
            &wrong_key.authed(
                method::ALLOCATE,
                2,
                &[(attr::REQUESTED_TRANSPORT, vec![17, 0, 0, 0])]
            )
        )
        .await
    );

    let mut wrong_nonce = supplied(&s, turn).await;
    wrong_nonce.nonce = b"AAAA".to_vec();
    assert!(
        is_silent(
            &wrong_nonce,
            &wrong_nonce.authed(
                method::ALLOCATE,
                3,
                &[(attr::REQUESTED_TRANSPORT, vec![17, 0, 0, 0])]
            )
        )
        .await
    );

    let mut other_realm = supplied(&s, turn).await;
    other_realm.realm = b"elsewhere".to_vec();
    assert!(
        is_silent(
            &other_realm,
            &other_realm.authed(
                method::ALLOCATE,
                4,
                &[(attr::REQUESTED_TRANSPORT, vec![17, 0, 0, 0])]
            )
        )
        .await
    );

    let mut expired = Client::new(s.udp, credentials(unix() - 10)).await;
    expired.realm = c.realm.clone();
    expired.nonce = c.nonce.clone();
    assert!(
        is_silent(
            &expired,
            &expired.authed(
                method::ALLOCATE,
                5,
                &[(attr::REQUESTED_TRANSPORT, vec![17, 0, 0, 0])]
            )
        )
        .await
    );

    let mut refresh = c.authed(method::REFRESH, 6, &[]);
    refresh[8] ^= 1;
    assert!(is_silent(&c, &refresh).await, "a tampered message");

    c.allocate().await.unwrap();
    assert_eq!(api.allocations(), 1);
    let unsupported = c.authed(method::CREATE_PERMISSION, 7, &[]);
    assert_eq!(
        c.exchange(&unsupported).await.error_code(),
        Some(400),
        "errors go to authenticated requests"
    );
}

#[tokio::test]
async fn a_server_that_is_not_silent_still_challenges() {
    let s = start(server_config(|_, _| {})).await;
    let mut c = Client::new(s.udp, credentials(unix() + 3600)).await;
    c.learn_realm().await;
    assert!(c.allocate().await.is_ok());
}

#[tokio::test]
async fn attributes_after_message_integrity_are_not_trusted() {
    let s = start(server_config(|_, _| {})).await;
    let mut c = Client::new(s.udp, credentials(unix() + 3600)).await;
    c.learn_realm().await;

    let mut forged = c.authed(method::ALLOCATE, 2, &[]);
    forged.extend_from_slice(&[0x00, 0x19, 0x00, 0x04, 17, 0, 0, 0]);
    let len = u16::from_be_bytes([forged[2], forged[3]]) + 8;
    forged[2..4].copy_from_slice(&len.to_be_bytes());
    assert_eq!(c.exchange(&forged).await.error_code(), Some(442));

    assert!(c.allocate().await.is_ok());
}

#[tokio::test]
async fn concurrent_allocations_cannot_exceed_the_credential_quota() {
    let s = start(server_config(|_, srv| srv.allocations_per_credential = 1)).await;
    let creds = credentials(unix() + 3600);
    let mut clients = Vec::new();
    for _ in 0..8 {
        let mut c = Client::new(s.udp, creds.clone()).await;
        c.learn_realm().await;
        clients.push(c);
    }
    let attempts: Vec<_> = clients
        .into_iter()
        .map(|mut c| tokio::spawn(async move { c.allocate().await }))
        .collect();
    let mut won = 0;
    for a in attempts {
        if a.await.unwrap().is_ok() {
            won += 1;
        }
    }
    assert_eq!(won, 1);
    assert_eq!(s.switch.api().turn_server().unwrap().allocations(), 1);
}

fn stun_auth_config() -> Config {
    let mut c = server_config(|t, _| t.silent = true);
    c.stun.auth = true;
    c
}

fn binding(creds: &(String, String), sha256: bool) -> Vec<u8> {
    let b = Builder::new(method::BINDING, Class::Request, &[7; 12])
        .attr(attr::USERNAME, creds.0.as_bytes());
    if sha256 {
        b.finish_with_integrity_sha256(creds.1.as_bytes())
    } else {
        b.finish_with_integrity(creds.1.as_bytes())
    }
}

async fn binding_reply(sock: &UdpSocket, to: SocketAddr, req: &[u8]) -> Option<Vec<u8>> {
    sock.send_to(req, to).await.unwrap();
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_millis(300), sock.recv(&mut buf))
        .await
        .ok()?
        .unwrap();
    Some(buf[..n].to_vec())
}

#[tokio::test]
async fn stun_credentials_open_the_binding_servers_and_nothing_else_does() {
    let s = start(stun_auth_config()).await;
    let info = Http::connect(s.addr, s.public)
        .await
        .get("/v0/info", None)
        .await
        .json();
    assert_eq!(info["stun_auth"], true);

    let json = register_json(&s, 1).await;
    let stun = &json["stun"];
    assert_eq!(stun["ttl"], 3600);
    assert!(stun.get("realm").is_none() && stun.get("limits").is_none());
    let creds = (
        stun["username"].as_str().unwrap().to_owned(),
        stun["credential"].as_str().unwrap().to_owned(),
    );
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let me = sock.local_addr().unwrap();

    for to in [s.stun, s.udp] {
        for sha256 in [false, true] {
            let reply = binding_reply(&sock, to, &binding(&creds, sha256))
                .await
                .expect("a registered node gets an answer");
            let m = Message::parse(&reply).unwrap();
            assert_eq!((m.method, m.class), (method::BINDING, Class::Success));
            assert_eq!(m.xor_addr(attr::XOR_MAPPED_ADDRESS), Some(me));
            assert!(vardevall_switch_proto::stun::verify_integrity(
                &reply,
                creds.1.as_bytes()
            ));
            assert_eq!(m.get(attr::INTEGRITY_SHA256).is_some(), sha256);
        }

        let plain = Builder::new(method::BINDING, Class::Request, &[7; 12]).finish();
        assert!(
            binding_reply(&sock, to, &plain).await.is_none(),
            "no credential"
        );
        let mut wrong = creds.clone();
        wrong.1 = "wrong".to_owned();
        assert!(
            binding_reply(&sock, to, &binding(&wrong, false))
                .await
                .is_none()
        );
        let expired = credentials(unix() - 10);
        assert!(
            binding_reply(&sock, to, &binding(&expired, false))
                .await
                .is_none()
        );
        let unsigned_username = Builder::new(method::BINDING, Class::Request, &[7; 12])
            .finish_with_integrity(creds.1.as_bytes());
        assert!(binding_reply(&sock, to, &unsigned_username).await.is_none());
        let mut late_username = Builder::new(method::BINDING, Class::Request, &[7; 12])
            .finish_with_integrity(creds.1.as_bytes());
        let tail = [
            &[0x00, 0x06, 0x00, creds.0.len() as u8][..],
            creds.0.as_bytes(),
        ]
        .concat();
        let padded = tail.len().div_ceil(4) * 4;
        late_username.extend_from_slice(&tail);
        late_username.resize(20 + 24 + padded, 0);
        let len = (late_username.len() - 20) as u16;
        late_username[2..4].copy_from_slice(&len.to_be_bytes());
        assert!(
            binding_reply(&sock, to, &late_username).await.is_none(),
            "a USERNAME that the integrity does not cover"
        );
    }
}

#[tokio::test]
async fn post_stun_issues_a_fresh_credential_to_sessions() {
    let s = start(stun_auth_config()).await;
    let json = register_json(&s, 1).await;
    let session = json["session"].as_str().unwrap();
    let mut http = Http::connect(s.addr, s.public).await;
    let r = http
        .request(Method::POST, "/v0/stun", &[("vv-session", session)], "")
        .await;
    assert_eq!(r.status, 200);
    let fresh = r.json();
    assert_ne!(fresh["username"], json["stun"]["username"]);
    let creds = (
        fresh["username"].as_str().unwrap().to_owned(),
        fresh["credential"].as_str().unwrap().to_owned(),
    );
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert!(
        binding_reply(&sock, s.stun, &binding(&creds, false))
            .await
            .is_some()
    );

    assert_eq!(
        http.request(Method::POST, "/v0/stun", &[], "").await.status,
        401
    );
    assert_eq!(
        http.request(Method::GET, "/v0/stun", &[("vv-session", session)], "")
            .await
            .status,
        405
    );
}

#[tokio::test]
async fn without_stun_auth_there_are_no_stun_credentials() {
    let s = start(server_config(|_, _| {})).await;
    let json = register_json(&s, 1).await;
    assert!(json.get("stun").is_none());
    let session = json["session"].as_str().unwrap();
    let mut http = Http::connect(s.addr, s.public).await;
    let r = http
        .request(Method::POST, "/v0/stun", &[("vv-session", session)], "")
        .await;
    assert_eq!(r.status, 404);
    assert_eq!(r.error_code(), "urn:vardevall:error:not-found");
    let info = http.get("/v0/info", None).await.json();
    assert_eq!(info["stun_auth"], false);
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let plain = Builder::new(method::BINDING, Class::Request, &[7; 12]).finish();
    assert!(binding_reply(&sock, s.stun, &plain).await.is_some());
}

#[tokio::test]
async fn requests_over_tls_are_limited_per_address_too() {
    let mut config = server_config(|_, _| {});
    config.limits.stun_burst = 3.0;
    config.limits.stun_rate = 0.01;
    let s = start(config).await;
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("switch.invalid").unwrap();
    let mut tls = tls_connector(s.public, &[b"stun.turn"])
        .connect(name, tcp)
        .await
        .unwrap();
    let mut answered = 0;
    for _ in 0..8 {
        tls.write_all(&allocate_request(1)).await.unwrap();
        let mut head = [0u8; 20];
        if tokio::time::timeout(Duration::from_millis(300), tls.read_exact(&mut head))
            .await
            .is_err()
        {
            continue;
        }
        let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let mut body = vec![0u8; len];
        tls.read_exact(&mut body).await.unwrap();
        answered += 1;
    }
    assert_eq!(answered, 3);
}

#[tokio::test]
async fn message_integrity_sha256_is_accepted_answered_in_kind_and_checked() {
    let s = start(server_config(|_, _| {})).await;
    let mut c = Client::new(s.udp, credentials(unix() + 3600)).await;
    c.learn_realm().await;
    let key = long_term_key(c.user.as_bytes(), &c.realm, c.password.as_bytes());
    let request = |id: u8, key: &[u8]| {
        Builder::new(method::ALLOCATE, Class::Request, &[id; 12])
            .attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0])
            .attr(attr::USERNAME, c.user.as_bytes())
            .attr(attr::REALM, &c.realm)
            .attr(attr::NONCE, &c.nonce)
            .finish_with_integrity_sha256(key)
    };
    let mut tampered = request(2, &key);
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(c.exchange(&tampered).await.error_code(), Some(401));

    let ok = c.exchange(&request(3, &key)).await;
    assert_eq!(ok.class, Class::Success);
    assert!(ok.get(attr::INTEGRITY_SHA256).is_some() && ok.get(attr::INTEGRITY).is_none());
    assert_eq!(
        c.exchange(&request(4, b"wrong key")).await.error_code(),
        Some(401)
    );
}
