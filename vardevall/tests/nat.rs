//! STUN, punching, TURN and the relay fallback with nodes that know each other only through a
//! switch (vv-05 §3, §4.2 to §4.5). Everything runs on loopback; the TURN server is a stand-in
//! that checks the REST credentials of vv-04 §4.5.

mod common;

use std::collections::HashSet;
use std::future::pending;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{STEP, Setup, SwitchUse, TestNode, ipv6, run_for};
use tokio::net::{TcpListener, UdpSocket};
use vardevall::view::{Nat, Route, View};
use vardevall::{LogLevel, NodeEvent, PeerSpec, StunSpec, SwitchSpec, os_rng};
use vardevall_proto::keys::{NetworkSecret, NodePublic, PairPsk};
use vardevall_switch::config::{Config, Turn, TurnServer};
use vardevall_switch::{Sockets, Switch, key};

const SECRET: &str = "vardevall test turn secret";

struct Infra {
    spec: SwitchSpec,
    switch: Arc<Switch>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Infra {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// A STUN server that reports another port than the client's, as a symmetric NAT would.
async fn skewed_stun() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 576];
        loop {
            let Ok((n, client)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            let mut seen = client;
            seen.set_port(client.port().wrapping_add(1));
            if let Some(r) = vardevall_switch::stun::respond(&buf[..n], seen) {
                let _ = socket.send_to(&r, client).await;
            }
        }
    });
    (addr, task)
}

/// A STUN server that ignores requests until `after` has passed, like a network still coming up.
async fn late_stun(after: Duration) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let ready = tokio::time::Instant::now() + after;
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 576];
        loop {
            let Ok((n, client)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            if tokio::time::Instant::now() < ready {
                continue;
            }
            if let Some(r) = vardevall_switch::stun::respond(&buf[..n], client) {
                let _ = socket.send_to(&r, client).await;
            }
        }
    });
    (addr, task)
}

/// A STUN server that reports `wrong` as the client's address until `after` has passed and the
/// client's own address from then on, like a mapping that moved under a socket that kept
/// sending.
async fn moving_stun(
    wrong: SocketAddr,
    after: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let moved = tokio::time::Instant::now() + after;
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 576];
        loop {
            let Ok((n, client)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            let seen = if tokio::time::Instant::now() < moved {
                wrong
            } else {
                client
            };
            if let Some(r) = vardevall_switch::stun::respond(&buf[..n], seen) {
                let _ = socket.send_to(&r, client).await;
            }
        }
    });
    (addr, task)
}

#[derive(Clone, Copy, Default)]
struct Options {
    /// A STUN server that only answers after a few seconds.
    late: bool,
    stun: bool,
    skewed: bool,
    turn: bool,
    short_ttl: bool,
    /// TURN only over TLS on the HTTPS port, after a UDP URL nobody answers.
    turn_tls: bool,
    /// STUN answers only requests with the registration's credential (vv-04 §4.7).
    stun_auth: bool,
    /// The TURN server answers nothing without a valid credential (vv-04 §4.5).
    silent_turn: bool,
    /// The volume per TURN credential the switch states.
    turn_bytes: Option<u64>,
}

async fn infra(o: Options) -> Infra {
    let secret = key::generate().unwrap();
    let public = secret.public();
    let mut config = Config::new(vec!["127.0.0.1:0".parse().unwrap()], "unused".into());
    config.names = vec!["127.0.0.1".to_owned()];
    config.timeouts.reconnect_grace = Duration::from_secs(5);
    let mut tasks = Vec::new();
    let mut sockets = Sockets::default();
    let mut uris = Vec::new();
    if o.stun {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        uris.push(format!("stun:127.0.0.1:{}", s.local_addr().unwrap().port()));
        sockets.stun.push(s);
    }
    if o.skewed {
        let (addr, task) = skewed_stun().await;
        uris.push(format!("stun:127.0.0.1:{}", addr.port()));
        tasks.push(task);
    }
    if o.late {
        let (addr, task) = late_stun(Duration::from_secs(4)).await;
        uris.push(format!("stun:127.0.0.1:{}", addr.port()));
        tasks.push(task);
    }
    config.stun.uris = uris;
    config.stun.auth = o.stun_auth;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    if o.turn || o.turn_tls {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp = socket.local_addr().unwrap().port();
        let urls = if o.turn_tls {
            tasks.push(tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                while socket.recv_from(&mut buf).await.is_ok() {}
            }));
            vec![
                format!("turn:127.0.0.1:{udp}?transport=udp"),
                format!("turns:127.0.0.1:{port}?transport=tcp"),
            ]
        } else {
            sockets.turn.push(socket);
            vec![
                format!("turn:127.0.0.1:{udp}?transport=udp"),
                "turns:127.0.0.1:1?transport=tcp".to_owned(),
            ]
        };
        config.turn = Some(Turn {
            urls,
            silent: o.silent_turn,
            secret: SECRET.to_owned(),
            ttl: Duration::from_secs(if o.short_ttl { 60 } else { 3600 }),
            bits_per_second: Some(1_000_000),
            bytes: o.turn_bytes,
            server: Some(TurnServer {
                listen: Vec::new(),
                relay_ipv4: Some("127.0.0.1".parse().unwrap()),
                relay_ipv4_public: None,
                relay_ipv6: None,
                relay_ipv6_public: None,
                relay_ports: (41000, 41999),
                realm: "vv.test".to_owned(),
                max_allocations: 100,
                allocations_per_credential: 4,
                allocations_per_ip: 100,
                allow_private_peers: true,
                tls: o.turn_tls,
            }),
        });
    }
    let switch = Arc::new(Switch::new(&config, secret).unwrap());
    let running = switch.clone();
    sockets.tcp.push(listener);
    tasks.push(tokio::spawn(async move {
        switch.run_with(sockets, pending()).await;
    }));
    Infra {
        spec: SwitchSpec::pinned(public, "127.0.0.1", port, None),
        switch: running,
        tasks,
    }
}

fn live(infra: &Infra) -> usize {
    infra.switch.api().turn_server().unwrap().allocations()
}

struct Pair {
    a: TestNode,
    b: TestNode,
    a_key: NodePublic,
    b_key: NodePublic,
    /// The latest view `a` reported, as of the end of the last [`exchange`].
    a_view: Option<View>,
}

impl Pair {
    /// What `a` believes about its route to `b`.
    fn route(&self) -> Option<Route> {
        let v = self.a_view.as_ref().expect("a reported no view");
        v.peers
            .iter()
            .find(|p| p.peer == self.b_key)
            .expect("b not in a's view")
            .route
    }
}

fn pair(infra: &Infra, fallback_delay: Duration) -> Pair {
    let net = NetworkSecret::generate(&mut os_rng());
    let mut sa = Setup::new(&net);
    let mut sb = Setup::new(&net);
    sa.fallback_delay = fallback_delay;
    sb.fallback_delay = fallback_delay;
    let (a_key, b_key) = (sa.public(), sb.public());
    let b = sb
        .peer(a_key, None)
        .switch(infra.spec.clone(), SwitchUse::Handshake)
        .start();
    let a = sa
        .peer(b_key, None)
        .switch(infra.spec.clone(), SwitchUse::Handshake)
        .start();
    Pair {
        a,
        b,
        a_key,
        b_key,
        a_view: None,
    }
}

/// Sends from `a` until `b` receives, and returns the path events `a` saw meanwhile.
async fn exchange(p: &mut Pair, deadline: Duration) -> Vec<Route> {
    let packet = ipv6(p.a.overlay.ula, p.b.overlay.ula, b"through the nat");
    let b_key = p.b_key;
    let a_key = p.a_key;
    let run = async {
        loop {
            p.a.handle.send_packet(&b_key, &packet);
            if let Ok((from, got)) =
                tokio::time::timeout(Duration::from_millis(300), p.b.packet()).await
            {
                assert_eq!(from, a_key);
                assert_eq!(got, packet);
                return;
            }
        }
    };
    if tokio::time::timeout(deadline, run).await.is_err() {
        let mut seen = Vec::new();
        while let Ok(e) = p.a.events.try_recv() {
            seen.push(format!("{e:?}"));
        }
        panic!("no packet arrived; the sender saw:\n{}", seen.join("\n"));
    }
    // Views are throttled: wait for the one that reflects the path.
    tokio::time::sleep(vardevall::view::VIEW_INTERVAL * 2).await;
    let mut states = Vec::new();
    while let Ok(e) = p.a.events.try_recv() {
        match e {
            NodeEvent::Route {
                route: Some(route), ..
            } => states.push(route),
            NodeEvent::View(v) => p.a_view = Some(v),
            _ => {}
        }
    }
    states
}

async fn log_contains(n: &mut TestNode, needle: &str) {
    log_contains_within(n, needle, Duration::from_secs(10)).await;
}

async fn log_contains_within(n: &mut TestNode, needle: &str, limit: Duration) {
    n.next_within(limit, |e| match e {
        NodeEvent::Log {
            level: LogLevel::Info | LogLevel::Warn,
            message,
        } if message.contains(needle) => Some(()),
        _ => None,
    })
    .await;
}

/// [`log_contains`] for paused time.
async fn log_stepped(n: &mut TestNode, needle: &str) {
    n.next_stepped(Duration::from_secs(60), |e| match e {
        NodeEvent::Log {
            level: LogLevel::Info | LogLevel::Warn,
            message,
        } if message.contains(needle) => Some(()),
        _ => None,
    })
    .await;
}

/// Sends from `a` until `b` receives, in paused time.
async fn deliver(p: &mut Pair, deadline: Duration) {
    let packet = ipv6(p.a.overlay.ula, p.b.overlay.ula, b"through the nat");
    let mut theirs = Vec::new();
    let mut waited = Duration::ZERO;
    while waited < deadline {
        p.a.handle.send_packet(&p.b_key, &packet);
        for _ in 0..3 {
            run_for(STEP).await;
            waited += STEP;
            while let Ok(e) = p.b.events.try_recv() {
                if let NodeEvent::Packet { peer, packet: got } = e {
                    assert_eq!((peer, got), (p.a_key, packet));
                    return;
                }
                theirs.push(format!("{e:?}"));
            }
        }
    }
    let mut seen = Vec::new();
    while let Ok(e) = p.a.events.try_recv() {
        seen.push(format!("{e:?}"));
    }
    panic!(
        "no packet arrived; the sender saw:\n{}\nthe receiver saw:\n{}",
        seen.join("\n"),
        theirs.join("\n")
    );
}

#[tokio::test]
async fn stun_candidates_let_two_nodes_punch_through() {
    let infra = infra(Options {
        stun: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, vardevall::FALLBACK_DELAY);
    let b_port = p.b.handle.local_addr().port();
    let states = exchange(&mut p, Duration::from_secs(15)).await;
    let direct = SocketAddr::from(([127, 0, 0, 1], b_port));
    assert!(
        states.contains(&Route::Internet(direct)),
        "no direct path in {states:?}"
    );
    assert!(!states.iter().any(|s| matches!(s, Route::OwnRelay(_))));
    assert_eq!(
        p.route(),
        Some(Route::Internet(direct)),
        "a punch candidate is internet class, whatever its address"
    );
    let local = &p.a_view.as_ref().unwrap().local;
    assert!(matches!(local.v4, Nat::Punchable(_)), "{local:?}");
    assert!(!p.route().is_some_and(|r| r.metered()));
}

#[tokio::test]
async fn a_path_change_regathers_the_punch_candidate() {
    let infra = infra(Options {
        stun: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, vardevall::FALLBACK_DELAY);
    log_contains(&mut p.a, "ipv4 punchable").await;
    for _ in 0..3 {
        p.a.handle.path_changed();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let result =
        p.a.next(|e| match e {
            NodeEvent::Log { message, .. } if message.starts_with("STUN: ") => Some(message),
            _ => None,
        })
        .await;
    assert!(result.contains("ipv4 punchable"), "{result}");
}

#[tokio::test(start_paused = true)]
async fn a_burst_of_path_changes_settles_into_one_change_and_one_round() {
    let infra = infra(Options {
        stun: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, vardevall::FALLBACK_DELAY);
    log_stepped(&mut p.a, "ipv4 punchable").await;
    while p.a.events.try_recv().is_ok() {}
    for _ in 0..5 {
        p.a.handle.path_changed();
        run_for(Duration::from_millis(100)).await;
    }
    run_for(Duration::from_millis(1500)).await;
    let (mut settled, mut rounds) = (0, 0);
    while let Ok(e) = p.a.events.try_recv() {
        if let NodeEvent::Log { message, .. } = e {
            settled += usize::from(message == "local path changed");
            rounds += usize::from(message.starts_with("STUN: "));
        }
    }
    assert_eq!((settled, rounds), (1, 1));
}

#[tokio::test]
#[ignore = "waits 30 s for the first retry"]
async fn an_unreachable_stun_server_is_retried_until_it_answers() {
    let infra = infra(Options {
        late: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, vardevall::FALLBACK_DELAY);
    log_contains(&mut p.a, "ipv4 udp-blocked").await;
    log_contains_within(&mut p.a, "ipv4 punchable", Duration::from_secs(40)).await;
}

#[tokio::test]
async fn a_stun_server_that_wants_the_registration_credential_is_asked_with_it() {
    let infra = infra(Options {
        stun: true,
        turn: true,
        stun_auth: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, vardevall::FALLBACK_DELAY);
    log_contains(&mut p.a, "ipv4 punchable").await;
    let b_port = p.b.handle.local_addr().port();
    let states = exchange(&mut p, Duration::from_secs(15)).await;
    assert!(!states.is_empty(), "the nodes connected");
    let _ = b_port;
}

#[tokio::test]
async fn a_silent_turn_server_allocates_for_a_credential_with_realm_and_nonce() {
    let infra = infra(Options {
        turn: true,
        silent_turn: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, Duration::from_millis(400));
    let states = exchange(&mut p, Duration::from_secs(20)).await;
    assert!(
        states.iter().any(|s| !matches!(s, Route::Switch(_))),
        "no path in {states:?}"
    );
    assert!(live(&infra) >= 1);
}

#[tokio::test]
async fn two_stun_servers_that_disagree_mean_symmetric_and_no_punch_candidate() {
    let infra = infra(Options {
        stun: true,
        skewed: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, vardevall::FALLBACK_DELAY);
    log_contains(&mut p.a, "ipv4 symmetric").await;
    log_contains(&mut p.b, "ipv4 symmetric").await;
    drop(p);
}

#[tokio::test]
async fn symmetric_nats_with_turn_go_straight_to_the_relay() {
    let infra = infra(Options {
        stun: true,
        skewed: true,
        turn: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, vardevall::FALLBACK_DELAY);
    let states = exchange(&mut p, Duration::from_secs(15)).await;
    let b_port = p.b.handle.local_addr().port();
    let direct = SocketAddr::from(([127, 0, 0, 1], b_port));
    assert!(
        states.iter().any(|s| !matches!(s, Route::Switch(_))),
        "no path in {states:?}"
    );
    assert!(
        !states.contains(&Route::Internet(direct)),
        "went direct: {states:?}"
    );
    assert_eq!(live(&infra), 2);
    assert!(p.route().is_some_and(|r| r.metered()), "{:?}", p.route());
    let local = &p.a_view.as_ref().unwrap().local;
    assert_eq!(local.v4, Nat::Symmetric);
    assert!(local.relay.is_some(), "{local:?}");
}

#[tokio::test]
async fn relay_first_with_a_zero_fallback_delay() {
    let infra = infra(Options {
        stun: true,
        turn: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, Duration::ZERO);
    let states = exchange(&mut p, Duration::from_secs(15)).await;
    assert!(
        states.iter().any(|s| !matches!(s, Route::Switch(_))),
        "no path in {states:?}"
    );
    assert_eq!(live(&infra), 2);
}

#[tokio::test]
async fn an_allocation_is_budgeted_with_the_volume_of_its_credential() {
    let infra = infra(Options {
        stun: true,
        turn: true,
        turn_bytes: Some(5_000_000),
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, Duration::ZERO);
    exchange(&mut p, Duration::from_secs(15)).await;
    let view = p.a_view.as_ref().expect("a reported a view");
    let turn = view
        .local
        .transports
        .iter()
        .find(|t| t.name == "turn")
        .expect("a turn transport");
    let budget = turn.budget.expect("the volume of the credential");
    assert_eq!(
        (budget.total, budget.source, budget.received),
        (5_000_000, vardevall::BudgetSource::Relay, true)
    );
    assert!(budget.remaining <= budget.total);
    assert!(turn.usable);
}

#[tokio::test]
async fn the_relay_fallback_connects_nodes_that_have_no_candidates() {
    let infra = infra(Options {
        turn: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, Duration::from_millis(400));
    let states = exchange(&mut p, Duration::from_secs(20)).await;
    let b_port = p.b.handle.local_addr().port();
    let direct = SocketAddr::from(([127, 0, 0, 1], b_port));
    assert!(
        states.iter().any(|s| !matches!(s, Route::Switch(_))),
        "no path in {states:?}"
    );
    assert!(
        !states.contains(&Route::Internet(direct)),
        "went direct: {states:?}"
    );
    assert!(live(&infra) >= 1);
}

#[tokio::test(start_paused = true)]
async fn an_idle_allocation_is_released_after_a_minute() {
    let infra = infra(Options {
        turn: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, Duration::from_millis(400));
    deliver(&mut p, Duration::from_secs(60)).await;
    let before = live(&infra);
    assert!(before >= 1);
    let mut idle = Duration::ZERO;
    while live(&infra) >= before {
        assert!(
            idle < Duration::from_secs(120),
            "the allocation was not released"
        );
        run_for(STEP).await;
        idle += STEP;
    }
    assert!(
        idle >= Duration::from_secs(45),
        "released after {idle:?} of idleness"
    );
}

#[tokio::test]
#[ignore = "waits 30 s for half of a 60 s credential"]
async fn turn_credentials_are_refreshed_halfway_through_their_validity() {
    let infra = infra(Options {
        turn: true,
        short_ttl: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, vardevall::FALLBACK_DELAY);
    log_contains(&mut p.a, "TURN credentials issued").await;
    let wait = async {
        while let Some(e) = p.a.events.recv().await {
            if matches!(&e, NodeEvent::Log { message, .. }
                if message.contains("TURN credentials refreshed"))
            {
                return;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(45), wait)
        .await
        .expect("no refresh");
}

#[tokio::test]
async fn turn_falls_back_from_udp_to_tls_on_the_https_port() {
    let infra = infra(Options {
        turn_tls: true,
        ..Default::default()
    })
    .await;
    let mut p = pair(&infra, Duration::ZERO);
    let states = exchange(&mut p, Duration::from_secs(40)).await;
    assert!(
        states.iter().any(|s| !matches!(s, Route::Switch(_))),
        "no path in {states:?}"
    );
    assert_eq!(live(&infra), 2);
}

/// A STUN server on `bind` that notes the transactions of the Binding requests it receives
/// (a retransmission repeats its transaction) and, if `answers`, replies to them.
async fn counting_stun(bind: &str, answers: bool) -> (SocketAddr, Arc<Mutex<HashSet<[u8; 12]>>>) {
    let socket = UdpSocket::bind(bind).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(HashSet::new()));
    let noted = seen.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 576];
        loop {
            let Ok((n, client)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            if let Some(txid) = buf.get(8..20).and_then(|t| <[u8; 12]>::try_from(t).ok()) {
                noted.lock().unwrap().insert(txid);
            }
            if answers && let Some(r) = vardevall_switch::stun::respond(&buf[..n], client) {
                let _ = socket.send_to(&r, client).await;
            }
        }
    });
    (addr, seen)
}

/// An idle peer that a switch reports reachable but whose handshakes never complete (the pair
/// PSKs differ), with a packet to it every 30 s for 10 minutes. IPv6 is silent, IPv4 answers.
/// Returns the STUN requests, as transactions, that each family received after the first round.
async fn stun_requests_for_an_idle_peer() -> (usize, usize) {
    let infra = infra(Options::default()).await;
    let (v4_addr, v4) = counting_stun("127.0.0.1:0", true).await;
    let (v6_addr, v6) = counting_stun("[::1]:0", false).await;
    let net = NetworkSecret::generate(&mut os_rng());
    let mut sa = Setup::new(&net);
    let mut sb = Setup::new(&net);
    let (a_key, b_key) = (sa.public(), sb.public());
    let psk = |n: u8| Some(PairPsk::from([n; 32]));
    sa.peers.push(PeerSpec {
        public: b_key,
        psk: psk(1),
        endpoints: Vec::new(),
        endpoints_local: false,
    });
    sb.peers.push(PeerSpec {
        public: a_key,
        psk: psk(2),
        endpoints: Vec::new(),
        endpoints_local: false,
    });
    sa.stun = vec![StunSpec {
        urls: vec![
            format!("stun:127.0.0.1:{}", v4_addr.port()),
            format!("stun:[::1]:{}", v6_addr.port()),
        ],
        username: None,
        credential: None,
    }];
    let mut a = sa.switch(infra.spec.clone(), SwitchUse::Handshake).start();
    let b = sb.switch(infra.spec.clone(), SwitchUse::Handshake).start();
    let (mut gathered, mut online) = (false, false);
    a.next_stepped(Duration::from_secs(60), |e| {
        if let NodeEvent::Log { message, .. } = e {
            gathered |= message.starts_with("STUN: ipv6 udp-blocked, ipv4 punchable");
            online |= message.ends_with("online on switch 0");
        }
        (gathered && online).then_some(())
    })
    .await;
    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"idle");
    let count = || (v4.lock().unwrap().len(), v6.lock().unwrap().len());
    let first = count();
    for _ in 0..20 {
        a.handle.send_packet(&b_key, &packet);
        run_for(Duration::from_secs(30)).await;
    }
    let last = count();
    (last.0 - first.0, last.1 - first.1)
}

/// The handshake attempt to the idle peer lasts 90 s, so a packet finds the peer
/// without a link every fourth time (at 120 s, 240 s, 360 s and 480 s) and refreshes the result
/// of IPv4, which answered; IPv6 is asked on its own backoff only: after 30 s, 60 s, 120 s and
/// 240 s.
#[tokio::test(start_paused = true)]
async fn an_idle_peer_behind_a_switch_costs_few_stun_requests() {
    let (v4, v6) = stun_requests_for_an_idle_peer().await;
    assert_eq!((v4, v6), (4, 4));
}

/// Both nodes first learn a reflexive address that leads nowhere, and their sockets
/// keep sending, so the result never ages; once the mapping is right again, a direct route that
/// keeps failing has the node ask STUN again and the corrected candidates make the route direct.
#[tokio::test(start_paused = true)]
async fn a_direct_route_that_keeps_failing_asks_stun_again() {
    let infra = infra(Options::default()).await;
    let hole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (stun, task) = moving_stun(hole.local_addr().unwrap(), Duration::from_secs(20)).await;
    let net = NetworkSecret::generate(&mut os_rng());
    let mut sa = Setup::new(&net);
    let mut sb = Setup::new(&net);
    let (a_key, b_key) = (sa.public(), sb.public());
    for s in [&mut sa, &mut sb] {
        s.stun = vec![StunSpec {
            urls: vec![format!("stun:127.0.0.1:{}", stun.port())],
            username: None,
            credential: None,
        }];
    }
    let b = sb
        .peer(a_key, None)
        .switch(infra.spec.clone(), SwitchUse::Handshake)
        .start();
    let a = sa
        .peer(b_key, None)
        .switch(infra.spec.clone(), SwitchUse::Handshake)
        .start();
    let mut p = Pair {
        a,
        b,
        a_key,
        b_key,
        a_view: None,
    };
    let wrong = format!("ipv4 punchable {}", hole.local_addr().unwrap());
    log_stepped(&mut p.a, &wrong).await;
    deliver(&mut p, Duration::from_secs(30)).await;
    let direct = SocketAddr::from(([127, 0, 0, 1], p.b.handle.local_addr().port()));
    p.a.next_stepped(Duration::from_secs(180), |e| match e {
        NodeEvent::Route {
            peer,
            route: Some(r),
        } if peer == b_key && r == Route::Internet(direct) => Some(()),
        _ => None,
    })
    .await;
    task.abort();
}
