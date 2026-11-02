#![allow(dead_code)]

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use vardevall::{
    Endpoint, Handle, MdnsEvent, MdnsMode, MdnsRequest, Node, NodeConfig, NodeEvent, PeerSpec,
    os_rng,
};
use vardevall_proto::addr::OverlayAddrs;
use vardevall_proto::keys::{NetworkId, NetworkSecret, NodePublic, NodeSecret};

pub struct TestNode {
    pub public: NodePublic,
    pub handle: Handle,
    pub events: mpsc::UnboundedReceiver<NodeEvent>,
    pub overlay: OverlayAddrs,
    pub task: tokio::task::JoinHandle<()>,
}

/// What a test node lets its switches carry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SwitchUse {
    /// Handshakes and control messages; the `tun` class does not degrade.
    Handshake,
    /// Also `tun` traffic when nothing else reaches the peer.
    Data,
}

pub struct Setup {
    pub secret: NodeSecret,
    pub network: NetworkSecret,
    pub peers: Vec<PeerSpec>,
    pub accept_members: bool,
    pub mdns: MdnsMode,
    pub switches: Vec<vardevall::SwitchSpec>,
    pub switch_use: SwitchUse,
    pub detect_timeout: Option<Duration>,
    pub fallback_delay: Duration,
    pub stun: Vec<vardevall::StunSpec>,
    pub services: Vec<vardevall::Service>,
    pub dns_servers: Vec<SocketAddr>,
}

impl Setup {
    pub fn new(network: &NetworkSecret) -> Self {
        Setup {
            secret: NodeSecret::generate(&mut os_rng()),
            network: network.clone(),
            peers: Vec::new(),
            accept_members: false,
            mdns: MdnsMode::Off,
            switches: Vec::new(),
            switch_use: SwitchUse::Handshake,
            detect_timeout: None,
            fallback_delay: vardevall::FALLBACK_DELAY,
            stun: Vec::new(),
            services: Vec::new(),
            dns_servers: Vec::new(),
        }
    }

    pub fn public(&self) -> NodePublic {
        self.secret.public()
    }

    pub fn peer(mut self, public: NodePublic, endpoint: Option<SocketAddr>) -> Self {
        self.peers.push(PeerSpec {
            public,
            psk: None,
            endpoints: endpoint.into_iter().map(Endpoint::Addr).collect(),
            endpoints_local: false,
        });
        self
    }

    /// A peer whose endpoint is known to be on this link (`endpoint_local`).
    pub fn peer_local(mut self, public: NodePublic, endpoint: SocketAddr) -> Self {
        self.peers.push(PeerSpec {
            public,
            psk: None,
            endpoints: vec![Endpoint::Addr(endpoint)],
            endpoints_local: true,
        });
        self
    }

    pub fn endpoint(mut self, public: NodePublic, endpoint: Endpoint) -> Self {
        self.peers.push(PeerSpec {
            public,
            psk: None,
            endpoints: vec![endpoint],
            endpoints_local: false,
        });
        self
    }

    pub fn switch(mut self, spec: vardevall::SwitchSpec, usage: SwitchUse) -> Self {
        self.switches.push(spec);
        self.switch_use = usage;
        self
    }

    pub fn start(self) -> TestNode {
        let (tx, events) = mpsc::unbounded_channel();
        let network_id: NetworkId = self.network.default_network_id();
        let public = self.secret.public();
        let config = NodeConfig {
            secret: self.secret,
            network_secret: self.network,
            network_id: None,
            listen_port: 0,
            mtu: 1280,
            accept_members: self.accept_members,
            mdns: self.mdns,
            peers: self.peers,
            switches: self.switches,
            turn: Vec::new(),
            switch_path: vardevall::SwitchPath::On,
            tun_class: vardevall::DeliveryClass {
                degrade: self.switch_use == SwitchUse::Data,
                ..vardevall::DeliveryClass::default()
            },
            detect_timeout: self.detect_timeout,
            fallback_delay: self.fallback_delay,
            stun: self.stun,
            services: self.services,
            dns_servers: self.dns_servers,
            watch_exclude: Vec::new(),
            watch_network: false,
            discovery: Vec::new(),
            exit: None,
            socket_mark: vardevall::SocketMark::NONE,
        };
        let (node, handle) = Node::new(config, move |e| {
            let _ = tx.send(e);
        })
        .unwrap();
        TestNode {
            public,
            handle,
            events,
            overlay: OverlayAddrs::derive(&network_id, &public),
            task: tokio::spawn(node.run()),
        }
    }
}

impl TestNode {
    pub fn loopback(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.handle.local_addr().port()))
    }

    pub async fn next<T>(&mut self, f: impl FnMut(NodeEvent) -> Option<T>) -> T {
        self.next_within(Duration::from_secs(10), f).await
    }

    pub async fn next_within<T>(
        &mut self,
        limit: Duration,
        mut f: impl FnMut(NodeEvent) -> Option<T>,
    ) -> T {
        let wait = async {
            loop {
                let e = self.events.recv().await.expect("node ended");
                if std::env::var_os("VV_TEST_LOG").is_some() {
                    eprintln!("{e:?}");
                }
                if let Some(v) = f(e) {
                    return v;
                }
            }
        };
        tokio::time::timeout(limit, wait)
            .await
            .expect("timed out waiting for an event")
    }

    /// Like [`TestNode::next_within`] for paused time: polls the events in steps of [`STEP`]
    /// and gives up after `limit` of virtual time.
    pub async fn next_stepped<T>(
        &mut self,
        limit: Duration,
        mut f: impl FnMut(NodeEvent) -> Option<T>,
    ) -> T {
        let mut left = limit;
        loop {
            while let Ok(e) = self.events.try_recv() {
                if std::env::var_os("VV_TEST_LOG").is_some() {
                    eprintln!("{e:?}");
                }
                if let Some(v) = f(e) {
                    return v;
                }
            }
            assert!(!left.is_zero(), "timed out waiting for an event");
            let part = STEP.min(left);
            tick(part).await;
            left -= part;
        }
    }

    /// The next packet delivered to the embedder, for paused time.
    pub async fn packet_stepped(&mut self) -> (NodePublic, Vec<u8>) {
        self.next_stepped(Duration::from_secs(60), |e| match e {
            NodeEvent::Packet { peer, packet } => Some((peer, packet)),
            _ => None,
        })
        .await
    }

    pub async fn packet(&mut self) -> (NodePublic, Vec<u8>) {
        self.next(|e| match e {
            NodeEvent::Packet { peer, packet } => Some((peer, packet)),
            _ => None,
        })
        .await
    }
}

/// The virtual time of one step of [`run_for`] and [`TestNode::next_stepped`].
pub const STEP: Duration = Duration::from_millis(100);

/// Lets `part` of paused time pass, then gives other threads a moment.
///
/// With paused time tokio advances the clock whenever the runtime is idle, even if a datagram
/// was just sent over loopback and has not reached the receiving socket yet (macOS delivers
/// loopback datagrams on another thread). Steps bound each jump, and the blocking sleep gives
/// that thread time to deliver before the next jump, so that a protocol timer fires only when
/// its answer is really missing. Needs `start_paused`.
async fn tick(part: Duration) {
    tokio::time::sleep(part).await;
    std::thread::sleep(Duration::from_millis(1));
}

/// Lets `span` of paused time pass, in steps of [`STEP`].
pub async fn run_for(span: Duration) {
    let mut left = span;
    while !left.is_zero() {
        let part = STEP.min(left);
        tick(part).await;
        left -= part;
    }
}

/// An IPv6 packet with a no-next-header payload.
pub fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    p.push(59);
    p.push(64);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

/// A stand-in for a platform DNS-SD service connecting several nodes.
#[derive(Default, Clone)]
pub struct FakeBonjour {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    nodes: Vec<(usize, Option<Handle>, bool)>,
    registered: Vec<(usize, MdnsRequest)>,
    log: Vec<(usize, MdnsRequest)>,
}

impl FakeBonjour {
    /// A request sink for the node with index `id`.
    pub fn sink(&self, id: usize) -> MdnsMode {
        let inner = self.inner.clone();
        inner.lock().unwrap().nodes.push((id, None, false));
        MdnsMode::External(Box::new(move |r: MdnsRequest| {
            let mut g = inner.lock().unwrap();
            g.log.push((id, r.clone()));
            match &r {
                MdnsRequest::Register { instance, .. } => {
                    g.registered.retain(|(_, q)| !matches!(q, MdnsRequest::Register { instance: i, .. } if i == instance));
                    g.registered.push((id, r.clone()));
                }
                MdnsRequest::Unregister { instance } => {
                    g.registered.retain(|(_, q)| !matches!(q, MdnsRequest::Register { instance: i, .. } if i == instance));
                    for (n, h, browsing) in &g.nodes {
                        if *n != id
                            && *browsing
                            && let Some(h) = h
                        {
                            h.mdns_event(MdnsEvent::Lost {
                                instance: instance.clone(),
                            });
                        }
                    }
                }
                MdnsRequest::Browse => {
                    let mut handle = None;
                    for n in g.nodes.iter_mut() {
                        if n.0 == id {
                            n.2 = true;
                            handle = n.1.clone();
                        }
                    }
                    if let Some(h) = handle {
                        deliver_existing(&g, id, &h);
                    }
                }
                MdnsRequest::StopBrowse => {}
            }
            if let MdnsRequest::Register { .. } = &r {
                for (n, h, browsing) in &g.nodes {
                    if *n != id
                        && *browsing
                        && let Some(h) = h
                    {
                        h.mdns_event(found(&r));
                    }
                }
            }
        }))
    }

    pub fn attach(&self, id: usize, handle: Handle) {
        let mut g = self.inner.lock().unwrap();
        for n in g.nodes.iter_mut() {
            if n.0 == id {
                n.1 = Some(handle.clone());
            }
        }
        if g.nodes.iter().any(|n| n.0 == id && n.2) {
            deliver_existing(&g, id, &handle);
        }
    }

    pub fn requests(&self, id: usize) -> Vec<MdnsRequest> {
        let g = self.inner.lock().unwrap();
        g.log
            .iter()
            .filter(|(n, _)| *n == id)
            .map(|(_, r)| r.clone())
            .collect()
    }
}

fn found(r: &MdnsRequest) -> MdnsEvent {
    let MdnsRequest::Register {
        instance,
        port,
        txt,
        ..
    } = r
    else {
        unreachable!()
    };
    MdnsEvent::Found(vardevall::Found {
        instance: instance.clone(),
        txt: txt.clone(),
        port: *port,
        addrs: vec!["127.0.0.1".parse().unwrap()],
        ifindex: 1,
    })
}

fn deliver_existing(g: &Inner, id: usize, handle: &Handle) {
    for (n, r) in &g.registered {
        if *n != id {
            handle.mdns_event(found(r));
        }
    }
}
