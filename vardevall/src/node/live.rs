//! Changing the peers, the exit served and the configured servers of a running node
//!.

use vardevall_proto::keys::NodePublic;
use vardevall_proto::node::PeerConfig;
use vardevall_switch_proto::origin::Origin;

use super::Node;
use crate::config::{PeerSpec, StunSpec, TurnSpec};
use crate::switch::SwitchId;

/// Most presence reports kept for peers added later.
const MAX_ONLINE: usize = 256;

impl Node {
    /// Takes the replacement the embedder handed over, if there is one.
    pub(super) fn sync_update(&mut self) {
        let Some(update) = self.shared_services().update.take() else {
            return;
        };
        self.update_peers(update.peers);
        if update.exit != self.serving {
            let now = self.clock.now();
            self.core.set_exit(now, &mut self.rng, update.exit.clone());
            self.serving = update.exit;
        }
        self.update_servers(&update.stun, &update.turn);
        self.drain();
    }

    fn update_peers(&mut self, peers: Vec<PeerSpec>) {
        let own = *self.core.public();
        let peers: Vec<PeerSpec> = peers.into_iter().filter(|p| p.public != own).collect();
        let old = std::mem::replace(&mut self.specs, peers.clone());
        let now = self.clock.now();
        for o in &old {
            if !peers.iter().any(|p| p.public == o.public) {
                self.core.remove_peer(&o.public);
            }
        }
        let mut added = Vec::new();
        for p in &peers {
            let before = old.iter().find(|o| o.public == p.public);
            if before.is_some_and(|o| o.same_as(p)) {
                continue;
            }
            let rekey = before.is_some_and(|o| !o.same_psk(p));
            if rekey {
                self.core.remove_peer(&p.public);
            }
            if before.is_none() || rekey {
                let mut pc = PeerConfig::new(p.public);
                if let Some(psk) = &p.psk {
                    pc.psk = psk.clone();
                }
                self.core.add_peer(pc, now.instant);
                added.push(p.public);
            }
        }
        for s in &mut self.sources {
            s.peers_changed(&peers);
        }
        self.drain();
        let seen: Vec<(SwitchId, NodePublic)> = self
            .online
            .iter()
            .filter(|(_, n)| added.contains(n))
            .copied()
            .collect();
        for (id, node) in seen {
            self.on_presence(id, node, true);
        }
    }

    fn update_servers(&mut self, stun: &[StunSpec], turn: &[TurnSpec]) {
        if self.resolver.is(stun, turn) {
            return;
        }
        let (stuns, turns) = self.resolver.counts();
        for i in 0..turns {
            self.turn
                .forget(Origin::Config(u16::try_from(i).unwrap_or(u16::MAX)));
        }
        for i in 0..stuns {
            self.stun
                .forget(Origin::Config(u16::try_from(i).unwrap_or(u16::MAX)));
        }
        self.update_stun(true);
        self.resolver.replace(stun, turn);
    }

    /// Remembers who a switch reported online, so that a peer added later finds it out.
    pub(super) fn note_presence(&mut self, id: SwitchId, node: NodePublic, online: bool) {
        self.online.retain(|(i, n)| (*i, *n) != (id, node));
        if online && self.online.len() < MAX_ONLINE {
            self.online.push((id, node));
        }
    }
}
