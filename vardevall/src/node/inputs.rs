//! Handling of everything that enters the engine.

use std::net::SocketAddr;

use vardevall_proto::discovery::candidate::Candidate;
use vardevall_proto::keys::NodePublic;
use vardevall_proto::meter::{Budget, BudgetSource};
use vardevall_proto::peer::{Found, Group};
use vardevall_proto::plane::frame::{self, Class};
use vardevall_proto::transport::{Path, Remote, TransportId};

use super::Node;
use crate::candidates::{SourceKey, Update};
use crate::event::{LogLevel, NodeEvent};
use crate::net::resolver::Resolved;
use crate::net::socket::canonical;
use crate::switch::{Inbound, SwitchId};
use crate::turn::{self, LinkEvent};
use crate::udp::{Datagram, Udp};
use vardevall_switch_proto::origin::Origin;
use vardevall_switch_proto::stun::Message;
use vardevall_switch_proto::turn::TurnOffer;

impl Node {
    pub(super) fn on_datagram(&mut self, n: usize, from: SocketAddr) {
        if n == 0 {
            return;
        }
        let turn = self.turn.udp_server();
        let mut kind = Udp::sort(&self.buf[..n], from, turn);
        if matches!(kind, Datagram::TurnServer) {
            let now = self.clock.now().instant;
            if self
                .turn
                .handle_datagram(now, &mut self.rng, &self.buf[..n])
            {
                self.turn_flush();
                return;
            }
            kind = Udp::sort(&self.buf[..n], from, None);
        }
        match kind {
            Datagram::Frame => {
                let now = self.clock.now();
                let path = Path {
                    via: self.media.udp,
                    to: Remote::Addr(from),
                };
                self.core
                    .handle_datagram(now, &mut self.rng, path, &self.buf[..n]);
                self.drain();
            }
            Datagram::Stun(msg) => {
                let raw = self.buf[..n].to_vec();
                self.on_stun_response(from, &msg, &raw);
            }
            Datagram::TurnServer | Datagram::Ignored => {}
        }
    }

    /// Gives transport `via` a budget, or none.
    pub(super) fn set_budget(&mut self, via: TransportId, budget: Option<Budget>) {
        let now = self.clock.now();
        self.core.set_budget(now, &mut self.rng, via, budget);
        self.drain();
    }

    /// Removes the budget of `via` if it has one.
    pub(super) fn clear_budget(&mut self, via: TransportId) {
        if self.core.transport(via).is_some_and(|t| t.budget.is_some()) {
            self.set_budget(via, None);
        }
    }

    /// Hands the servers that can be asked now to the gathering; `gather` starts a round if they
    /// differ from before.
    pub(super) fn update_stun(&mut self, gather: bool) {
        let now = self.clock.now().instant;
        if self.stun.update(now, self.udp.reach()) && gather {
            self.gather();
        }
    }

    /// Starts a gathering round of Binding requests (vv-05 §3.1).
    fn gather(&mut self) {
        let now = self.clock.now().instant;
        for (to, data) in self.stun.start(now, &mut self.rng) {
            self.send_to(to, &data);
        }
    }

    /// Feeds a STUN message from the interface socket to the gathering; `raw` is its bytes.
    fn on_stun_response(&mut self, from: SocketAddr, msg: &Message, raw: &[u8]) {
        let now = self.clock.now().instant;
        self.stun.handle(now, from, msg, raw);
        self.reflexive_done();
    }

    /// TURN credentials arrived (vv-04 §4.4, §4.5).
    fn on_turn_offer(&mut self, origin: Origin, offer: TurnOffer) {
        let what = if self.turn.offer(origin, offer) {
            "issued"
        } else {
            "refreshed"
        };
        self.log(
            LogLevel::Info,
            format!("TURN credentials {what} by {origin}"),
        );
    }

    /// Something happened on the TLS connection of the TURN client.
    pub(super) fn on_link_event(&mut self, event: LinkEvent) {
        let now = self.clock.now().instant;
        self.turn.handle_link(now, &mut self.rng, event);
        self.turn_flush();
    }

    pub(super) fn on_turn_event(&mut self, event: turn::Event) {
        match event {
            turn::Event::Allocated(relayed) => {
                self.log(LogLevel::Info, format!("TURN: relayed address {relayed}"));
                let budget = self
                    .turn
                    .bytes()
                    .map(|b| Budget::new(b, BudgetSource::Relay, true));
                self.set_budget(self.media.turn, budget);
                self.refresh_hello();
                self.release_held_if_ready();
            }
            turn::Event::Lost(failure) => {
                self.log(
                    LogLevel::Warn,
                    format!("TURN: allocation lost ({failure:?})"),
                );
                let lost = self.turn.lost(failure, self.udp.reach());
                if let Some(origin) = lost.refresh {
                    self.switches.refresh_turn(origin);
                }
                self.refresh_hello();
                self.clear_budget(self.media.turn);
                self.release_held_if_ready();
                if lost.retry {
                    self.ensure_relay();
                }
            }
            turn::Event::Data { from, payload } => self.on_relayed(from, &payload),
        }
    }

    /// A datagram a peer sent to this node's relayed address (vv-05 §3.3, §4.4).
    pub(super) fn on_relayed(&mut self, from: SocketAddr, payload: &[u8]) {
        let from = canonical(from);
        let Some(&first) = payload.first() else {
            return;
        };
        if let Class::HandshakeFragment | Class::CookieReply | Class::DataFrame =
            frame::classify(first, false)
        {
            let now = self.clock.now();
            let path = Path {
                via: self.media.turn,
                to: Remote::Addr(from),
            };
            self.core.handle_datagram(now, &mut self.rng, path, payload);
            self.drain();
        }
    }

    pub(super) fn on_switch_msg(&mut self, msg: Inbound) {
        match msg {
            Inbound::State(id, state, retry_at) => {
                let address = self.switches.address(id);
                self.view
                    .switches
                    .set_state(id, address.clone(), state, retry_at);
                self.sink.event(NodeEvent::Switch { id, address, state });
                if let Some(via) = self.media.switch(id) {
                    let now = self.clock.now();
                    let ready = state == crate::event::SwitchState::Registered;
                    self.core.set_ready(now, &mut self.rng, via, ready);
                    self.drain();
                }
            }
            Inbound::Budget { id, bytes } => {
                if let Some(via) = self.media.switch(id) {
                    let budget = bytes.map(|b| Budget::new(b, BudgetSource::Reported, false));
                    self.set_budget(via, budget);
                }
            }
            Inbound::Presence { id, node, online } => self.on_presence(id, node, online),
            Inbound::Forward { id, from, msg } => {
                if let Some(via) = self.media.switch(id) {
                    let now = self.clock.now();
                    let path = Path {
                        via,
                        to: Remote::Peer(from),
                    };
                    self.core.handle_datagram(now, &mut self.rng, path, &msg);
                    self.drain();
                }
            }
            Inbound::Transport { id, transport } => {
                self.view.switches.set_transport(id, transport);
                self.log(LogLevel::Info, format!("switch {}: {transport:?}", id.0));
            }
            Inbound::Stun {
                origin,
                servers,
                required,
            } => {
                self.stun.set_servers(origin, servers, required);
                self.update_stun(true);
            }
            Inbound::StunCredentials {
                origin,
                username,
                key,
                ttl,
            } => {
                let now = self.clock.now().instant;
                self.stun.set_credential(now, origin, username, key, ttl);
                self.update_stun(true);
            }
            Inbound::Turn { origin, offer } => self.on_turn_offer(origin, offer),
        }
    }

    /// The configured servers of an entry were resolved (vv-07 §3.4, §3.6).
    pub(super) fn on_resolved(&mut self, resolved: Resolved) {
        match resolved {
            Resolved::Stun {
                origin,
                servers,
                credential,
            } => {
                let now = self.clock.now().instant;
                self.stun.set_servers(origin, servers, credential.is_some());
                if let Some((username, key)) = credential {
                    self.stun.set_credential(now, origin, username, key, None);
                }
                self.update_stun(true);
            }
            Resolved::Turn { origin, offer } => self.on_turn_offer(origin, offer),
        }
    }

    /// A member came online or went offline on switch `id` (vv-04 §5, §7; vv-05 §4.7). Only a
    /// configured peer counts, or any member if member trust is on (vv-09 §2.2 step 3 applies to
    /// switch listings alike).
    pub(super) fn on_presence(&mut self, id: SwitchId, node: NodePublic, online: bool) {
        self.note_presence(id, node, online);
        let Some(via) = self.media.switch(id) else {
            return;
        };
        if !self.accept_members && !self.core.peers().any(|p| *p == node) {
            return;
        }
        let now = self.clock.now();
        let changed = self
            .core
            .set_reachable(now, &mut self.rng, via, &node, online);
        self.drain();
        if changed {
            let state = if online { "online" } else { "offline" };
            self.log(
                LogLevel::Info,
                format!("{}: {state} on switch {}", &node.to_base32()[..8], id.0),
            );
        }
    }

    pub(super) fn on_packet(&mut self, peer: NodePublic, packet: Vec<u8>) {
        if self.held.holds(&peer) || self.needs_prep(&peer) {
            let now = self.clock.now().instant;
            self.held.hold(now, peer, packet);
            return;
        }
        self.send_to_core(peer, &packet);
    }

    /// Hands a packet of the embedder to the node.
    pub(super) fn send_to_core(&mut self, peer: NodePublic, packet: &[u8]) {
        let now = self.clock.now();
        let class = self.tun_class;
        if let Err(e) = self.core.send(now, &mut self.rng, &peer, class, packet) {
            self.log(LogLevel::Debug, format!("packet to {peer} dropped: {e}"));
        }
    }

    pub(super) fn on_timeout(&mut self) {
        let now = self.clock.now();
        self.core.handle_timeout(now, &mut self.rng);
        self.drain();
        self.stun_timeout(now.instant);
        self.turn.handle_timeout(now.instant, &mut self.rng);
        self.turn_flush();
        self.held_timeout(now.instant);
        self.changes_timeout();
    }

    pub(super) fn on_update(&mut self, update: Update) {
        let now = self.clock.now();
        let peer = update.peer;
        let group = match &update.source {
            SourceKey::Static => Group {
                source: "static",
                name: String::new(),
            },
            SourceKey::Discovery { source, group } => Group {
                source,
                name: group.clone(),
            },
        };
        let found = Found {
            offered: update.candidates.clone(),
            spare: update.spare.clone(),
        };
        let changed = self
            .core
            .set_candidates(now, &mut self.rng, &peer, group, found)
            .unwrap_or(false);
        self.drain();
        if changed {
            self.log(LogLevel::Info, describe(&update));
        }
    }
}

/// One log line for a candidate update.
fn describe(update: &Update) -> String {
    let key = update.peer.to_base32();
    let source = match &update.source {
        SourceKey::Static => "static".to_owned(),
        SourceKey::Discovery { source, group } => format!("{source} {group}"),
    };
    if update.candidates.is_empty() {
        return format!("{}: {source} candidates withdrawn", &key[..8]);
    }
    let addrs: Vec<String> = update
        .candidates
        .iter()
        .map(|c: &Candidate| c.addr.to_string())
        .collect();
    format!("{}: {source} candidates {}", &key[..8], addrs.join(", "))
}
