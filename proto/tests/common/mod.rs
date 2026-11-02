#![allow(dead_code)]

use serde_json::Value;

pub fn load(name: &str) -> Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap()
}

pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn h32(v: &Value) -> [u8; 32] {
    hex(v.as_str().unwrap()).try_into().unwrap()
}

pub fn hv(v: &Value) -> Vec<u8> {
    hex(v.as_str().unwrap())
}

pub fn group<'a>(doc: &'a Value, name: &str) -> &'a Vec<Value> {
    doc[name]
        .as_array()
        .unwrap_or_else(|| panic!("no group {name}"))
}

/// An RNG that replays fixed bytes, for vectors with fixed randomness.
pub struct ScriptedRng {
    data: Vec<u8>,
    pos: usize,
}

impl ScriptedRng {
    pub fn new(parts: &[&[u8]]) -> Self {
        ScriptedRng {
            data: parts.concat(),
            pos: 0,
        }
    }

    pub fn exhausted(&self) -> bool {
        self.pos == self.data.len()
    }
}

impl rand_core::TryRng for ScriptedRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.pos + dst.len();
        assert!(end <= self.data.len(), "scripted rng exhausted");
        dst.copy_from_slice(&self.data[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for ScriptedRng {}

pub mod sim {
    use std::net::{Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use vardevall_proto::discovery::candidate::Candidate;
    use vardevall_proto::keys::*;
    use vardevall_proto::node::{Config, Event, Node as Core, Output, PeerConfig, PeerState};
    use vardevall_proto::peer::{Found, Group};
    use vardevall_proto::route::{DeliveryClass, WantBand};
    use vardevall_proto::time::{Instant, Now};
    use vardevall_proto::transport::{Path, Remote, TransportId};

    pub use vardevall_proto::sim::{MediumKind, SimMedium, SimRng};

    pub const UNIX_BASE: u64 = 1_789_300_000_000_000_000;

    /// Milliseconds, rounded up so that the timer is due at that millisecond.
    pub fn ms_ceil(t: Instant) -> u64 {
        (t.as_duration().as_micros() as u64).div_ceil(1000)
    }

    pub fn now_at(ms: u64) -> Now {
        Now::new(Instant::from_millis(ms), UNIX_BASE + ms * 1_000_000)
    }

    pub struct Node {
        pub node: Core,
        pub rng: SimRng,
        pub addr: SocketAddr,
        pub events: Vec<Event>,
        pub demands: Vec<(TransportId, bool)>,
        pub udp: TransportId,
        pub sw: TransportId,
        pub secret: NodeSecret,
    }

    impl Node {
        pub fn public(&self) -> NodePublic {
            *self.node.public()
        }

        pub fn ula(&self) -> Ipv6Addr {
            self.node.overlay_addrs().ula
        }

        pub fn packets(&self) -> Vec<Vec<u8>> {
            self.events
                .iter()
                .filter_map(|e| match e {
                    Event::Packet { packet, .. } => Some(packet.clone()),
                    _ => None,
                })
                .collect()
        }

        pub fn count(&self, f: impl Fn(&Event) -> bool) -> usize {
            self.events.iter().filter(|e| f(e)).count()
        }

        /// The states reported for `peer`, in order.
        pub fn states(&self, peer: &NodePublic) -> Vec<PeerState> {
            self.events
                .iter()
                .filter_map(|e| match e {
                    Event::Peer { peer: p, state } if p == peer => Some(*state),
                    _ => None,
                })
                .collect()
        }

        /// How many times the node reported any peer up.
        pub fn ups(&self) -> usize {
            self.count(|e| {
                matches!(
                    e,
                    Event::Peer {
                        state: PeerState::Up { .. },
                        ..
                    }
                )
            })
        }
    }

    /// A datagram in flight, as the receiver will see it.
    #[derive(Clone, Debug)]
    pub struct Wire {
        pub from: usize,
        pub to: usize,
        pub path: Path,
        pub data: Vec<u8>,
    }

    pub struct Pair {
        pub nodes: [Node; 2],
        pub now: Now,
        pub ms: u64,
        pub network: NetworkSecret,
        pub class: DeliveryClass,
    }

    pub fn new_node(
        seed: u64,
        network: &NetworkSecret,
        port: u16,
        now: Now,
        tweak: impl FnOnce(&mut Config),
    ) -> Node {
        let mut rng = SimRng::new(seed);
        let secret = NodeSecret::generate(&mut rng);
        let mut cfg = Config::new(secret.clone(), network.clone());
        tweak(&mut cfg);
        let mut node = Core::new(cfg, now, &mut rng);
        let udp = node.add_transport(Arc::new(SimMedium(MediumKind::Udp)));
        let sw = node.add_transport(Arc::new(SimMedium(MediumKind::Switch)));
        node.set_ready(now, &mut rng, sw, false);
        let addr = SocketAddr::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, port).into(),
            51820,
        );
        Node {
            node,
            rng,
            addr,
            events: Vec::new(),
            demands: Vec::new(),
            udp,
            sw,
            secret,
        }
    }

    pub fn static_group() -> Group {
        Group {
            source: "static",
            name: String::new(),
        }
    }

    impl Node {
        /// Tells the node where `other` is, as a configured endpoint would.
        pub fn know(&mut self, now: Now, other: &Node) {
            let found = Found {
                offered: vec![Candidate::static_(other.addr)],
                spare: Vec::new(),
            };
            self.node
                .set_candidates(now, &mut self.rng, &other.public(), static_group(), found)
                .unwrap();
        }

        pub fn forget(&mut self, now: Now, other: &NodePublic) {
            self.node
                .set_candidates(now, &mut self.rng, other, static_group(), Found::default())
                .unwrap();
        }
    }

    impl Pair {
        /// Two nodes that know each other's key only.
        pub fn bare(ta: impl FnOnce(&mut Config), tb: impl FnOnce(&mut Config)) -> Self {
            let network = NetworkSecret::from_bytes([42; 32]);
            let now = now_at(0);
            let mut a = new_node(1, &network, 1, now, ta);
            let mut b = new_node(2, &network, 2, now, tb);
            let (pa, pb) = (a.public(), b.public());
            a.node.add_peer(PeerConfig::new(pb), now.instant);
            b.node.add_peer(PeerConfig::new(pa), now.instant);
            Pair {
                nodes: [a, b],
                now,
                ms: 0,
                network,
                class: DeliveryClass::default(),
            }
        }

        /// Two nodes that know each other's address.
        pub fn with(ta: impl FnOnce(&mut Config), tb: impl FnOnce(&mut Config)) -> Self {
            let mut p = Self::bare(ta, tb);
            p.know_each_other();
            p
        }

        pub fn new() -> Self {
            Self::with(|_| {}, |_| {})
        }

        pub fn know_each_other(&mut self) {
            let now = self.now;
            let [a, b] = &mut self.nodes;
            a.know(now, b);
            b.know(now, a);
        }

        /// Lets the nodes reach each other through the switch as well.
        pub fn add_switch(&mut self) {
            let now = self.now;
            let [a, b] = &mut self.nodes;
            let (pa, pb) = (a.public(), b.public());
            for (n, other) in [(&mut *a, pb), (&mut *b, pa)] {
                n.node.set_ready(now, &mut n.rng, n.sw, true);
                n.node.set_reachable(now, &mut n.rng, n.sw, &other, true);
            }
            self.class = DeliveryClass {
                band: WantBand::Any,
                ..DeliveryClass::default()
            };
        }

        /// Forgets the addresses and lets the nodes reach each other through the switch only.
        pub fn switch_mode(&mut self) {
            let now = self.now;
            let [a, b] = &mut self.nodes;
            let (pa, pb) = (a.public(), b.public());
            a.forget(now, &pb);
            b.forget(now, &pa);
            self.add_switch();
        }

        pub fn a(&mut self) -> &mut Node {
            &mut self.nodes[0]
        }

        pub fn b(&mut self) -> &mut Node {
            &mut self.nodes[1]
        }

        fn index_of(&self, addr: SocketAddr) -> Option<usize> {
            self.nodes.iter().position(|n| n.addr == addr)
        }

        fn index_of_key(&self, key: &NodePublic) -> Option<usize> {
            self.nodes.iter().position(|n| n.public() == *key)
        }

        /// Drains both nodes' outputs into wires and records events.
        pub fn collect(&mut self) -> Vec<Wire> {
            let mut wires = Vec::new();
            for from in 0..2 {
                while let Some(out) = self.nodes[from].node.poll_output() {
                    match out {
                        Output::Transmit { path, data, .. } => {
                            let (to, recv) = match path.to {
                                Remote::Addr(dst) => {
                                    let Some(to) = self.index_of(dst) else {
                                        continue;
                                    };
                                    (
                                        to,
                                        Path {
                                            via: self.nodes[to].udp,
                                            to: Remote::Addr(self.nodes[from].addr),
                                        },
                                    )
                                }
                                Remote::Peer(key) => {
                                    let Some(to) = self.index_of_key(&key) else {
                                        continue;
                                    };
                                    (
                                        to,
                                        Path {
                                            via: self.nodes[to].sw,
                                            to: Remote::Peer(self.nodes[from].public()),
                                        },
                                    )
                                }
                            };
                            wires.push(Wire {
                                from,
                                to,
                                path: recv,
                                data,
                            });
                        }
                        Output::Demand { via, on } => self.nodes[from].demands.push((via, on)),
                        Output::Event(e) => self.nodes[from].events.push(e),
                    }
                }
            }
            wires
        }

        pub fn deliver(&mut self, w: Wire) {
            let now = self.now;
            let n = &mut self.nodes[w.to];
            n.node.handle_datagram(now, &mut n.rng, w.path, &w.data);
        }

        /// Delivers everything until the network is quiet.
        pub fn pump(&mut self) {
            self.pump_with(|_| true);
        }

        /// Like `pump`, dropping wires for which `keep` returns false.
        pub fn pump_with(&mut self, mut keep: impl FnMut(&Wire) -> bool) {
            for _ in 0..200 {
                let wires = self.collect();
                if wires.is_empty() {
                    return;
                }
                for w in wires {
                    if keep(&w) {
                        self.deliver(w);
                    }
                }
            }
            panic!("network did not quiesce");
        }

        pub fn set_time(&mut self, ms: u64) {
            self.ms = ms;
            self.now = now_at(ms);
        }

        /// Advances time in steps no larger than the next timer, running timers, then pumps.
        pub fn advance(&mut self, d: Duration) {
            self.advance_with(d, |_| true);
        }

        pub fn advance_with(&mut self, d: Duration, mut keep: impl FnMut(&Wire) -> bool) {
            let end = self.ms + d.as_millis() as u64;
            self.pump_with(&mut keep);
            loop {
                let next = self
                    .nodes
                    .iter()
                    .filter_map(|n| n.node.poll_timeout())
                    .map(ms_ceil)
                    .min();
                let step = match next {
                    Some(t) if t <= end => t.max(self.ms),
                    _ => end,
                };
                self.set_time(step);
                let now = self.now;
                for n in &mut self.nodes {
                    n.node.handle_timeout(now, &mut n.rng);
                    let left = n.node.poll_timeout().map(ms_ceil);
                    assert!(
                        left.is_none_or(|t| t > step),
                        "a timer due at {left:?} ms was not consumed at {step} ms"
                    );
                }
                self.pump_with(&mut keep);
                if step == end {
                    return;
                }
            }
        }

        pub fn send(&mut self, from: usize, packet: &[u8]) {
            let now = self.now;
            let to = self.nodes[1 - from].public();
            let class = self.class;
            let n = &mut self.nodes[from];
            n.node
                .send(now, &mut n.rng, &to, class, packet)
                .expect("send");
        }
    }

    /// An IPv4 packet with no header checksum, enough for the engine.
    pub fn ipv4(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut p = vec![0x45, 0];
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    pub fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        p.extend_from_slice(&[59, 64]);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }
}
