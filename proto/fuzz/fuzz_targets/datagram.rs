#![no_main]

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use rand_free::SeqRng;
use vardevall_proto::keys::{NetworkSecret, NodeSecret};
use vardevall_proto::node::{Config, Node, PeerConfig};
use vardevall_proto::route::{Band, Latency, RouteClass};
use vardevall_proto::time::{Instant, Now};
use vardevall_proto::transport::{Framing, Medium, Path, Reachability, Remote};

struct Udp;

impl Medium for Udp {
    fn name(&self) -> &str {
        "udp"
    }
    fn class(&self) -> RouteClass {
        RouteClass {
            band: Band::High,
            latency: Latency::High,
            metered: false,
        }
    }
    fn reaches(&self, to: &Remote, _: bool) -> bool {
        matches!(to, Remote::Addr(_))
    }
    fn reachability(&self) -> Reachability {
        Reachability::Probe
    }
    fn framing(&self) -> Framing {
        Framing::Fragmented { max: 1200 }
    }
    fn on_demand(&self) -> bool {
        false
    }
}

struct Switch;

impl Medium for Switch {
    fn name(&self) -> &str {
        "switch"
    }
    fn class(&self) -> RouteClass {
        RouteClass {
            band: Band::Low,
            latency: Latency::High,
            metered: true,
        }
    }
    fn reaches(&self, to: &Remote, _: bool) -> bool {
        matches!(to, Remote::Peer(_))
    }
    fn reachability(&self) -> Reachability {
        Reachability::Reported
    }
    fn framing(&self) -> Framing {
        Framing::Whole
    }
    fn on_demand(&self) -> bool {
        false
    }
}

mod rand_free {
    pub struct SeqRng(pub u64);

    impl rand_core::TryRng for SeqRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64()? as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            Ok(self.0)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for c in dst.chunks_mut(8) {
                let v = self.try_next_u64()?.to_le_bytes();
                c.copy_from_slice(&v[..c.len()]);
            }
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for SeqRng {}
}

fn peer() -> &'static vardevall_proto::keys::NodePublic {
    static PEER: OnceLock<vardevall_proto::keys::NodePublic> = OnceLock::new();
    PEER.get_or_init(|| NodeSecret::from_bytes([9; 32]).public())
}

fuzz_target!(|data: &[u8]| {
    let mut rng = SeqRng(1);
    let now = Now::new(Instant::from_millis(1000), 1_789_300_000_000_000_000);
    let mut cfg = Config::new(NodeSecret::from_bytes([5; 32]), NetworkSecret::from_bytes([6; 32]));
    cfg.accept_members = data.first().is_some_and(|b| b & 1 == 1);
    cfg.load_threshold = u32::from(data.first().copied().unwrap_or(0) >> 1 & 1) * 255;
    let mut node = Node::new(cfg, now, &mut rng);
    let udp = node.add_transport(Arc::new(Udp));
    let switch = node.add_transport(Arc::new(Switch));
    node.add_peer(PeerConfig::new(*peer()), now.instant);
    let on_udp = Path {
        via: udp,
        to: Remote::Addr(SocketAddr::from(([192, 0, 2, 1], 51820))),
    };
    let on_switch = Path {
        via: switch,
        to: Remote::Peer(*peer()),
    };
    for chunk in data.chunks(1300) {
        node.handle_datagram(now, &mut rng, on_udp, chunk);
        node.handle_datagram(now, &mut rng, on_switch, chunk);
        while node.poll_output().is_some() {}
    }
    node.handle_timeout(Now::new(Instant::from_millis(200_000), now.unix_nanos), &mut rng);
});
