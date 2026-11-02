//! The event pump: the node's events and the tunnel's own replies, delivered to the host's
//! callbacks.
//!
//! Everything that is ready is taken without waiting. Packets are collected, up to [`BATCH`], and
//! handed to the packet callback in one call; any other event first hands over the packets
//! collected before it, so packets and events keep the order they came in.

use std::sync::{Arc, PoisonError};
use std::time::Instant;

use tokio::sync::mpsc;
use vardevall::{NodeEvent, PeerState, Status as NodeStatus, Trust};
use vardevall_proto::addr::OverlayAddrs;
use vardevall_proto::keys::{NetworkId, NodePublic};

use super::guard::Guard;
use super::{Done, Event, QUEUE, Shared, Status, SwitchKind};
use crate::router::{Chosen, Inbound};

/// Most packets handed to the packet callback in one call.
const BATCH: usize = 64;

#[allow(clippy::large_enum_variant)]
enum Item {
    Event(NodeEvent),
    Local(Vec<u8>),
}

#[derive(PartialEq, Eq)]
enum Flow {
    Go,
    Stop,
}

struct Pump {
    shared: Arc<Shared>,
    guard: Arc<Guard>,
    network: Arc<str>,
    network_id: NetworkId,
    batch: Vec<Vec<u8>>,
}

pub(super) async fn pump(
    shared: Arc<Shared>,
    guard: Arc<Guard>,
    done: Arc<Done>,
    mut events: mpsc::Receiver<NodeEvent>,
    mut local: mpsc::Receiver<Vec<u8>>,
    network: Arc<str>,
    network_id: NetworkId,
) {
    let mut pump = Pump {
        shared,
        guard,
        network,
        network_id,
        batch: Vec::with_capacity(BATCH),
    };
    'outer: loop {
        let mut next = Some(tokio::select! {
            ev = events.recv() => match ev {
                Some(ev) => Item::Event(ev),
                None => break,
            },
            Some(p) = local.recv() => Item::Local(p),
        });
        let mut taken = 0;
        while let Some(item) = next {
            if pump.take(item) == Flow::Stop {
                break 'outer;
            }
            taken += 1;
            next = if taken < QUEUE {
                events
                    .try_recv()
                    .ok()
                    .map(Item::Event)
                    .or_else(|| local.try_recv().ok().map(Item::Local))
            } else {
                None
            };
        }
        pump.flush();
    }
    pump.flush();
    done.finish();
}

impl Pump {
    fn take(&mut self, item: Item) -> Flow {
        match item {
            Item::Local(packet) => {
                self.push(packet);
                Flow::Go
            }
            Item::Event(NodeEvent::Packet { peer, packet }) => {
                let inbound = self
                    .shared
                    .router
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .inbound(&peer, &packet);
                match inbound {
                    Inbound::Deliver(p) => {
                        let own = self.shared.responder.own_addrs().ula;
                        let reply = self
                            .shared
                            .relays
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .finish(Instant::now(), &own, &p);
                        self.push(reply.unwrap_or(p));
                    }
                    Inbound::Return(p) => (self.shared.to_peer)(&peer, &p),
                    Inbound::Drop => {}
                }
                Flow::Go
            }
            Item::Event(event) => {
                self.flush();
                self.event(event)
            }
        }
    }

    fn push(&mut self, packet: Vec<u8>) {
        self.batch.push(packet);
        if self.batch.len() >= BATCH {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.batch.is_empty() {
            return;
        }
        let packets: Vec<&[u8]> = self.batch.iter().map(Vec::as_slice).collect();
        self.guard.with(|cb| (cb.packets)(&packets));
        self.batch.clear();
    }

    fn emit(&self, event: &Event) {
        self.guard.with(|cb| (cb.event)(&self.network, event));
    }

    fn name_of(&self, key: &NodePublic) -> Option<String> {
        self.shared
            .config_peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, n)| n.clone())
    }

    /// The name a peer had, also after a configuration read again took it away.
    fn name_of_removed(&self, key: &NodePublic) -> Option<String> {
        let mut gone = self
            .shared
            .gone_peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let at = gone.iter().position(|(k, _)| k == key);
        let name = at.and_then(|i| gone.remove(i).1);
        drop(gone);
        name.or_else(|| self.name_of(key))
    }

    fn addr_of(&self, key: &NodePublic) -> std::net::Ipv6Addr {
        OverlayAddrs::derive(&self.network_id, key).ula
    }

    fn switch_kind(&self, index: u32) -> SwitchKind {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.shared.switch_kinds.get(i))
            .copied()
            .unwrap_or(SwitchKind::Pinned)
    }

    fn event(&mut self, event: NodeEvent) -> Flow {
        let s = &self.shared;
        let event = match event {
            NodeEvent::Packet { .. } => return Flow::Go,
            NodeEvent::Added { peer, trust } => {
                {
                    let mut router = s.router.lock().unwrap_or_else(PoisonError::into_inner);
                    let _ = router.add_peer(peer);
                    if trust == Trust::Key {
                        router.set_keyed(peer);
                    }
                }
                s.responder.add_key(peer);
                Event::Added {
                    key: peer,
                    addr: self.addr_of(&peer),
                    name: self.name_of(&peer),
                    trust,
                }
            }
            NodeEvent::Removed { peer } => {
                s.router
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove_peer(&peer);
                s.responder.remove_key(&peer);
                Event::Removed {
                    key: peer,
                    addr: self.addr_of(&peer),
                    name: self.name_of_removed(&peer),
                }
            }
            NodeEvent::Peer { peer, state } => {
                s.router
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .set_live(peer, matches!(state, PeerState::Up { .. }));
                Event::Peer {
                    key: peer,
                    addr: self.addr_of(&peer),
                    name: self.name_of(&peer),
                    state,
                }
            }
            NodeEvent::Route { peer, route } => Event::Route {
                key: peer,
                addr: self.addr_of(&peer),
                name: self.name_of(&peer),
                route,
            },
            NodeEvent::Sites { sites } => {
                s.router
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .set_known_sites(sites);
                return Flow::Go;
            }
            NodeEvent::Exit {
                site,
                via,
                addr,
                ipv4,
            } => {
                let mut router = s.router.lock().unwrap_or_else(PoisonError::into_inner);
                router.set_exit_peer(site.clone(), via.map(|peer| Chosen { peer, ipv4 }));
                s.responder
                    .set_exit(router.exit_in_use().map(|(_, via)| via).as_ref());
                drop(router);
                Event::Exit {
                    site,
                    via,
                    addr,
                    ipv4,
                }
            }
            NodeEvent::ExitClient { peer, ipv4 } => {
                s.router
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .set_exit_client(peer, ipv4);
                return Flow::Go;
            }
            NodeEvent::Remembered { offers } => Event::Exits { offers },
            NodeEvent::Status(NodeStatus::Started { listen }) => Event::Status(Status::Started {
                listen_port: listen.port(),
            }),
            NodeEvent::Status(NodeStatus::Stopped) => {
                self.emit(&Event::Status(Status::Stopped));
                return Flow::Stop;
            }
            NodeEvent::Switch { id, address, state } => Event::Switch {
                address,
                kind: self.switch_kind(id.0),
                state,
            },
            NodeEvent::Budget { transport, budget } => Event::Budget { transport, budget },
            NodeEvent::View(view) => {
                let peers = view
                    .peers
                    .iter()
                    .map(|p| (self.addr_of(&p.peer), self.name_of(&p.peer)))
                    .collect();
                let switches = view
                    .local
                    .switches
                    .iter()
                    .map(|s| self.switch_kind(s.id.0))
                    .collect();
                let exit = s
                    .router
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .exit_in_use()
                    .map(|(site, via)| (site.clone(), via));
                Event::View {
                    view,
                    peers,
                    switches,
                    exit,
                }
            }
            NodeEvent::Log { level, message } => Event::Log { level, message },
        };
        self.emit(&event);
        Flow::Go
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::sync::Mutex;
    use std::time::Duration;

    use serde_json::json;
    use tokio::runtime::Handle;
    use vardevall::LogLevel;

    use super::super::relay::Relays;
    use super::super::{Callbacks, Done};
    use super::*;
    use crate::config::{Config, Context};
    use crate::dns::{Forwarder, Responder};
    use crate::router::Router;
    use crate::{keys, packet};

    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        Packets(Vec<u8>),
        Event(serde_json::Value),
    }

    struct Rig {
        events: mpsc::Sender<NodeEvent>,
        local: mpsc::Sender<Vec<u8>>,
        seen: Arc<Mutex<Vec<Seen>>>,
        done: Arc<Done>,
        event_rx: mpsc::Receiver<NodeEvent>,
        local_rx: mpsc::Receiver<Vec<u8>>,
        shared: Arc<Shared>,
        guard: Arc<Guard>,
        network_id: NetworkId,
    }

    /// A pump that has not started yet, whose callbacks note what they get: for packets, the
    /// first byte of the echo body of each one in the call. Starting it drops the senders of the
    /// events, so that it ends once it has taken what was sent.
    fn rig() -> Rig {
        let text = format!(
            "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{}\"\nlisten_port = 0\n",
            keys::generate_node_key(),
            keys::generate_network_secret()
        );
        let ctx = Context {
            interface_name: "test".into(),
            hostname: None,
        };
        let config = Config::parse(&text, &ctx).unwrap();
        let (events, event_rx) = mpsc::channel(QUEUE);
        let (local, local_rx) = mpsc::channel(QUEUE);
        let shared = Arc::new(Shared {
            router: Mutex::new(Router::new(config.network_id, config.public_key)),
            responder: Arc::new(Responder::from_config(&config)),
            forwarder: Forwarder::new(config.forward.clone(), Handle::current()),
            host_dns: None,
            relays: Mutex::new(Relays::new()),
            local: local.clone(),
            to_peer: Box::new(|_, _| {}),
            intercept_dns: false,
            resolver_alias: None,
            config_peers: Mutex::default(),
            gone_peers: Mutex::default(),
            switch_kinds: Vec::new(),
        });
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (for_packets, for_events) = (seen.clone(), seen.clone());
        let guard = Arc::new(Guard::new(Callbacks {
            packets: Box::new(move |packets| {
                let ids = packets.iter().map(|p| p[44]);
                for_packets
                    .lock()
                    .unwrap()
                    .push(Seen::Packets(ids.collect()));
            }),
            event: Box::new(move |network, e| {
                let mut json: serde_json::Value =
                    serde_json::from_str(&e.to_json(network)).unwrap();
                assert_eq!(json["network"], "test");
                json.as_object_mut().unwrap().remove("network");
                for_events.lock().unwrap().push(Seen::Event(json))
            }),
            mdns: None,
        }));
        Rig {
            events,
            local,
            seen,
            done: Arc::new(Done::default()),
            event_rx,
            local_rx,
            shared,
            guard,
            network_id: config.network_id,
        }
    }

    impl Rig {
        fn start(self) -> (Arc<Mutex<Vec<Seen>>>, Arc<Done>) {
            tokio::spawn(pump(
                self.shared,
                self.guard,
                self.done.clone(),
                self.event_rx,
                self.local_rx,
                "test".into(),
                self.network_id,
            ));
            (self.seen, self.done)
        }
    }

    fn echo(id: u8) -> Vec<u8> {
        let a: Ipv6Addr = "fd00::1".parse().unwrap();
        let b: Ipv6Addr = "fd00::2".parse().unwrap();
        packet::build_icmpv6(&a, &b, 128, 0, &[id, 1, 0, 1], 64)
    }

    const PEER: [u8; 32] = [7; 32];

    impl Rig {
        /// A packet from the peer, from its overlay address.
        fn arrives(&self, id: u8) -> NodeEvent {
            let peer = NodePublic::from_bytes(PEER);
            let src = OverlayAddrs::derive(&self.network_id, &peer).ula;
            let dst: Ipv6Addr = "fd00::2".parse().unwrap();
            NodeEvent::Packet {
                peer,
                packet: packet::build_icmpv6(&src, &dst, 128, 0, &[id, 1, 0, 1], 64),
            }
        }
    }

    async fn finished(done: &Done) {
        done.wait(Duration::from_secs(5)).await;
        assert!(done.is_finished());
    }

    #[tokio::test]
    async fn a_burst_is_one_call_and_an_event_keeps_its_place() {
        let rig = rig();
        for id in 0..3 {
            rig.events.try_send(rig.arrives(id)).unwrap();
        }
        let log = NodeEvent::Log {
            level: LogLevel::Info,
            message: "between".into(),
        };
        rig.events.try_send(log).unwrap();
        for id in 3..5 {
            rig.events.try_send(rig.arrives(id)).unwrap();
        }
        rig.events
            .try_send(NodeEvent::Status(NodeStatus::Stopped))
            .unwrap();
        let (seen, done) = rig.start();
        finished(&done).await;
        assert_eq!(
            *seen.lock().unwrap(),
            [
                Seen::Packets(vec![0, 1, 2]),
                Seen::Event(json!({"type": "log", "level": "info", "message": "between"})),
                Seen::Packets(vec![3, 4]),
                Seen::Event(json!({"type": "status", "state": "stopped"})),
            ]
        );
    }

    #[tokio::test]
    async fn a_batch_holds_at_most_batch_packets() {
        let rig = rig();
        let ids: Vec<u8> = (0..150).collect();
        for id in &ids {
            rig.events.try_send(rig.arrives(*id)).unwrap();
        }
        rig.events
            .try_send(NodeEvent::Status(NodeStatus::Stopped))
            .unwrap();
        let (seen, done) = rig.start();
        finished(&done).await;
        let seen = seen.lock().unwrap();
        let batches: Vec<&Vec<u8>> = seen
            .iter()
            .filter_map(|s| match s {
                Seen::Packets(ids) => Some(ids),
                Seen::Event(_) => None,
            })
            .collect();
        assert_eq!(
            batches.iter().map(|b| b.len()).collect::<Vec<_>>(),
            [BATCH, BATCH, 150 - 2 * BATCH]
        );
        assert_eq!(
            batches.into_iter().flatten().copied().collect::<Vec<_>>(),
            ids
        );
    }

    #[tokio::test]
    async fn the_tunnels_own_replies_join_the_batch() {
        let rig = rig();
        rig.events.try_send(rig.arrives(0)).unwrap();
        rig.events.try_send(rig.arrives(1)).unwrap();
        for id in 2..5 {
            rig.local.try_send(echo(id)).unwrap();
        }
        let (seen, done) = rig.start();
        finished(&done).await;
        let seen = seen.lock().unwrap();
        let [Seen::Packets(ids)] = &seen[..] else {
            panic!("{seen:?}")
        };
        let mut ids = ids.clone();
        ids.sort();
        assert_eq!(ids, [0, 1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn packets_the_router_refuses_are_not_delivered() {
        let rig = rig();
        let ns = packet::build_icmpv6(
            &"fe80::1".parse().unwrap(),
            &"ff02::1:ff00:2".parse().unwrap(),
            135,
            0,
            &[9; 20],
            255,
        );
        rig.events.try_send(rig.arrives(0)).unwrap();
        rig.events
            .try_send(NodeEvent::Packet {
                peer: NodePublic::from_bytes([7; 32]),
                packet: ns,
            })
            .unwrap();
        rig.events
            .try_send(NodeEvent::Packet {
                peer: NodePublic::from_bytes(PEER),
                packet: echo(9),
            })
            .unwrap();
        rig.events.try_send(rig.arrives(1)).unwrap();
        rig.events
            .try_send(NodeEvent::Status(NodeStatus::Stopped))
            .unwrap();
        let (seen, done) = rig.start();
        finished(&done).await;
        assert_eq!(seen.lock().unwrap()[0], Seen::Packets(vec![0, 1]));
    }
}
