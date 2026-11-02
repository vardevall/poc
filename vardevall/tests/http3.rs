//! HTTP/3 towards the switch with the fall back to TCP after 300 ms (vv-04 §2.2).

mod common;

use std::future::pending;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Setup, SwitchUse};
use tokio::net::{TcpListener, UdpSocket};
use vardevall::{NodeEvent, SwitchSpec, SwitchState, os_rng};
use vardevall_proto::keys::NetworkSecret;
use vardevall_switch::config::Config;
use vardevall_switch::{Sockets, Switch, key};

#[derive(Clone, Copy)]
enum Udp {
    Serves,
    Silent,
    Closed,
}

struct Running {
    spec: SwitchSpec,
    task: tokio::task::JoinHandle<()>,
    _silent: Option<UdpSocket>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn switch(udp: Udp) -> Running {
    let secret = key::generate().unwrap();
    let public = secret.public();
    let mut config = Config::new(vec!["127.0.0.1:0".parse().unwrap()], "unused".into());
    config.names = vec!["127.0.0.1".to_owned()];
    let switch = Arc::new(Switch::new(&config, secret).unwrap());
    let (tcp, udp_socket) = loop {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        if let Ok(udp) = UdpSocket::bind(tcp.local_addr().unwrap()).await {
            break (tcp, udp);
        }
    };
    let addr = tcp.local_addr().unwrap();
    let mut sockets = Sockets {
        tcp: vec![tcp],
        ..Default::default()
    };
    let mut silent = None;
    match udp {
        Udp::Serves => sockets.h3.push(udp_socket),
        Udp::Silent => silent = Some(udp_socket),
        Udp::Closed => drop(udp_socket),
    }
    let task = tokio::spawn(async move { switch.run_with(sockets, pending()).await });
    Running {
        spec: SwitchSpec::pinned(public, "127.0.0.1", addr.port(), None),
        task,
        _silent: silent,
    }
}

/// Starts a node and returns how long it took to register and the transport it logged.
async fn register_with(sw: &Running) -> (Duration, String) {
    let net = NetworkSecret::generate(&mut os_rng());
    let mut node = Setup::new(&net)
        .switch(sw.spec.clone(), SwitchUse::Handshake)
        .start();
    let start = Instant::now();
    let mut transport = String::new();
    let wait = async {
        while let Some(e) = node.events.recv().await {
            match e {
                NodeEvent::Log { message, .. } if message.starts_with("switch 0: ") => {
                    transport = message["switch 0: ".len()..].to_owned();
                }
                NodeEvent::Switch {
                    state: SwitchState::Registered,
                    ..
                } => return,
                _ => {}
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .expect("did not register");
    (start.elapsed(), transport)
}

#[tokio::test]
async fn a_switch_with_http3_is_reached_over_quic() {
    let (_, transport) = register_with(&switch(Udp::Serves).await).await;
    assert_eq!(transport, "Http3");
}

#[tokio::test]
async fn a_switch_without_udp_is_reached_over_tcp() {
    let (_, transport) = register_with(&switch(Udp::Closed).await).await;
    assert_eq!(transport, "Http2");
}

#[tokio::test]
async fn a_silent_udp_port_costs_about_300_ms_before_tcp_wins() {
    let (took, transport) = register_with(&switch(Udp::Silent).await).await;
    assert_eq!(transport, "Http2");
    assert!(took < Duration::from_secs(3), "{took:?}");
}
