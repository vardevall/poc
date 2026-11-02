//! Carrying out what `proto`'s node asks for (vv-05 §4.1, §4.8).

use std::net::SocketAddr;

use vardevall_proto::discovery::candidate::Candidate;
use vardevall_proto::keys::NodePublic;
use vardevall_proto::node::{Event, Output};
use vardevall_proto::transport::{Path, Remote, TransportId};

use super::Node;
use crate::event::{LogLevel, NodeEvent};
use crate::switch::{SwitchId, Traffic};

impl Node {
    /// Sends from the interface socket. The send counts for the freshness of the STUN result
    ///.
    pub(super) fn send_to(&mut self, to: SocketAddr, data: &[u8]) {
        let now = self.clock.now().instant;
        if self.udp.send(now, to, data) {
            self.stun.sent(now, to);
        }
        self.flush_udp_log();
    }

    /// Makes sure an allocation exists or is being made; returns whether it is usable now
    /// (vv-05 §3.3).
    pub(super) fn ensure_relay(&mut self) -> bool {
        let now = self.clock.now().instant;
        let up = self.turn.ensure(now, &mut self.rng, self.udp.reach());
        self.turn_flush();
        up
    }

    /// The node no longer needs the allocation.
    pub(super) fn release_relay(&mut self) {
        if self.turn.relayed().is_none() {
            return;
        }
        let now = self.clock.now().instant;
        self.turn.release(now, &mut self.rng);
        self.turn_flush();
        self.refresh_hello();
        self.clear_budget(self.media.turn);
        self.log(LogLevel::Info, "TURN: allocation released".to_owned());
    }

    /// Sends `data` to `to` through the allocation, if there is one.
    fn relay_send(&mut self, to: SocketAddr, data: &[u8]) -> bool {
        let now = self.clock.now().instant;
        let sent = self.turn.send(now, &mut self.rng, to, data);
        self.turn_flush();
        sent
    }

    /// Creates permissions for the addresses of a peer's candidates (vv-05 §3.3).
    fn permit_relay(&mut self, addrs: &[SocketAddr]) {
        let now = self.clock.now().instant;
        self.turn.permit(now, &mut self.rng, addrs);
        self.turn_flush();
    }

    /// Sends what the allocation queued and handles what happened to it.
    pub(super) fn turn_flush(&mut self) {
        loop {
            let datagrams = self.turn.take_datagrams();
            let events = self.turn.take_events();
            if datagrams.is_empty() && events.is_empty() {
                break;
            }
            for (to, data) in datagrams {
                self.send_to(to, &data);
            }
            for event in events {
                self.on_turn_event(event);
            }
        }
        self.turn.close_idle_link();
    }

    /// Reports what the socket logged.
    pub(super) fn flush_udp_log(&mut self) {
        for (level, message) in self.udp.take_log() {
            self.log(level, message);
        }
    }

    pub(super) fn switch_send(
        &mut self,
        id: SwitchId,
        to: &NodePublic,
        data: &[u8],
        traffic: Traffic,
    ) {
        let now = self.clock.now().instant;
        if !self.switches.forward(now, id, to, data, traffic) {
            self.log(
                LogLevel::Debug,
                format!("switch {}: datagram for {to} dropped", id.0),
            );
        }
    }

    /// Sends a datagram on a path (vv-05 §4.8).
    fn transmit(&mut self, path: Path, data: &[u8], signal: bool) {
        match path.to {
            Remote::Addr(addr) if path.via == self.media.udp => self.send_to(addr, data),
            Remote::Addr(addr) if path.via == self.media.turn => {
                self.relay_send(addr, data);
            }
            Remote::Peer(peer) => {
                if let Some(id) = self.media.switch_id(path.via) {
                    let traffic = if signal {
                        Traffic::Signal
                    } else {
                        Traffic::Data
                    };
                    self.switch_send(id, &peer, data, traffic);
                }
            }
            Remote::Addr(_) => {}
        }
    }

    /// Carries out every pending output of the node.
    pub(super) fn drain(&mut self) {
        while let Some(output) = self.core.poll_output() {
            match output {
                Output::Transmit { path, data, signal } => self.transmit(path, &data, signal),
                Output::Demand { via, on } => self.on_demand(via, on),
                Output::Event(e) => self.on_event(e),
            }
        }
    }

    fn on_demand(&mut self, via: TransportId, on: bool) {
        if via != self.media.turn {
            return;
        }
        if on {
            self.ensure_relay();
        } else {
            self.release_relay();
        }
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Added { peer, trust } => self.sink.event(NodeEvent::Added { peer, trust }),
            Event::Removed { peer } => self.sink.event(NodeEvent::Removed { peer }),
            Event::Peer { peer, state } => self.sink.event(NodeEvent::Peer { peer, state }),
            Event::Active { peer, route } => {
                let route = route.and_then(|r| self.route(&r));
                self.sink.event(NodeEvent::Route { peer, route });
            }
            Event::Packet { peer, packet } => self.sink.event(NodeEvent::Packet { peer, packet }),
            Event::Sites { sites } => self.sink.event(NodeEvent::Sites { sites }),
            Event::Remembered { offers } => self.sink.event(NodeEvent::Remembered { offers }),
            Event::Exit { site, via, ipv4 } => {
                let addr = self.core.site_addr(&site);
                self.sink.event(NodeEvent::Exit {
                    site,
                    via,
                    addr,
                    ipv4,
                });
            }
            Event::ExitClient { peer, ipv4 } => {
                self.sink.event(NodeEvent::ExitClient { peer, ipv4 })
            }
            Event::ExitCollision { first, second } => self.log(
                LogLevel::Warn,
                format!("sites {first} and {second} have the same prefix: both are ignored"),
            ),
            Event::Initiation { peer } => {
                for s in &mut self.sources {
                    s.needs_path(&peer);
                }
                let parked = self.core.peer_view(&peer).is_some_and(|v| {
                    v.targets.is_empty() && v.reporting.is_empty() && v.active.is_none()
                });
                if parked {
                    self.log(
                        LogLevel::Debug,
                        format!("no candidate for {peer} yet, handshake parked"),
                    );
                }
            }
            Event::Candidates { peer, candidates } => {
                let addrs: Vec<_> = candidates.iter().map(|c| c.addr).collect();
                if self.turn.relayed().is_some() {
                    self.permit_relay(&addrs);
                }
                self.log(
                    LogLevel::Debug,
                    format!("{peer}: candidates {}", describe(&candidates)),
                );
            }
            Event::RouteFailed { peer, addr } => {
                for s in &mut self.sources {
                    s.route_failed(&peer, addr);
                }
                self.doubt_reflexive();
            }
            Event::Services => self.publish_services(),
            Event::Budget { via, budget } => {
                let transport = self.core.transport(via).map(|t| t.name).unwrap_or_default();
                self.sink.event(NodeEvent::Budget { transport, budget });
            }
        }
    }
}

fn describe(list: &[Candidate]) -> String {
    list.iter()
        .map(|c| format!("{} {}", c.label, c.addr))
        .collect::<Vec<_>>()
        .join(", ")
}
