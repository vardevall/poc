//! The peer table and its indices, kept consistent in one place.

use std::collections::{BTreeMap, HashMap};

use rand_core::CryptoRng;

use crate::keys::NodePublic;
use crate::node::Event;
use crate::peer::{Peer, Trust};
use crate::time::Instant;

/// Idle member entries kept (vv-02 §4.3).
pub(crate) const MEMBER_CACHE: usize = 4096;
/// Entries above the cache size that trigger an eviction pass.
pub(crate) const MEMBER_SLACK: usize = 256;
/// Unconfirmed responder sessions kept across all peers (vv-02 §4.3).
pub(crate) const UNCONFIRMED_LIMIT: usize = 1024;

/// Receiver indices and the order of unconfirmed sessions, borrowed into
/// [`crate::peer::Ctx`] so that a peer can allocate and free its own indices.
#[derive(Default)]
pub(crate) struct Indices {
    by_index: HashMap<u32, NodePublic>,
    unconfirmed: BTreeMap<u64, NodePublic>,
    seq: u64,
}

impl Indices {
    /// A fresh random index, recorded as belonging to `peer`.
    pub(crate) fn alloc<R: CryptoRng>(&mut self, rng: &mut R, peer: NodePublic) -> u32 {
        loop {
            let i = rng.next_u32();
            if let std::collections::hash_map::Entry::Vacant(e) = self.by_index.entry(i) {
                e.insert(peer);
                return i;
            }
        }
    }

    pub(crate) fn free(&mut self, index: u32) {
        self.by_index.remove(&index);
    }

    pub(crate) fn peer(&self, index: u32) -> Option<NodePublic> {
        self.by_index.get(&index).copied()
    }

    /// Records an unconfirmed responder session of `peer`; returns its sequence number.
    pub(crate) fn push_unconfirmed(&mut self, peer: NodePublic) -> u64 {
        self.seq += 1;
        self.unconfirmed.insert(self.seq, peer);
        self.seq
    }

    pub(crate) fn drop_unconfirmed(&mut self, seq: u64) {
        self.unconfirmed.remove(&seq);
    }

    pub(crate) fn unconfirmed_len(&self) -> usize {
        self.unconfirmed.len()
    }

    pub(crate) fn len(&self) -> usize {
        self.by_index.len()
    }

    #[cfg(test)]
    pub(crate) fn record(&mut self, index: u32, peer: NodePublic) {
        self.by_index.insert(index, peer);
    }

    fn pop_oldest_unconfirmed(&mut self) -> Option<(u64, NodePublic)> {
        self.unconfirmed.pop_first()
    }
}

/// Every peer, by key, by receiver index and by interface identifier.
#[derive(Default)]
pub(crate) struct Peers {
    map: HashMap<NodePublic, Peer>,
    pub(crate) indices: Indices,
    by_iid: HashMap<[u8; 8], NodePublic>,
    /// [`Event::Added`] and [`Event::Removed`] not yet handed on.
    pub(crate) events: Vec<Event>,
}

impl Peers {
    pub(crate) fn get(&self, key: &NodePublic) -> Option<&Peer> {
        self.map.get(key)
    }

    pub(crate) fn get_mut(&mut self, key: &NodePublic) -> Option<&mut Peer> {
        self.map.get_mut(key)
    }

    pub(crate) fn contains(&self, key: &NodePublic) -> bool {
        self.map.contains_key(key)
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = &NodePublic> {
        self.map.keys()
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &Peer> {
        self.map.values()
    }

    /// The peer and the indices together, for a call that takes a [`crate::peer::Ctx`].
    pub(crate) fn split(&mut self, key: &NodePublic) -> Option<(&mut Peer, &mut Indices)> {
        self.map.get_mut(key).map(|p| (p, &mut self.indices))
    }

    /// The peer owning receiver index `index`.
    pub(crate) fn by_index(&self, index: u32) -> Option<NodePublic> {
        self.indices.peer(index)
    }

    /// The peer whose interface identifier is `iid`.
    pub(crate) fn by_iid(&self, iid: &[u8; 8]) -> Option<&Peer> {
        self.by_iid.get(iid).and_then(|k| self.map.get(k))
    }

    /// Inserts a peer; a member insert may evict idle members (vv-02 §4.3).
    pub(crate) fn insert(&mut self, peer: Peer) {
        let (key, trust) = (*peer.key(), peer.trust());
        self.by_iid.entry(peer.addrs().iid).or_insert(key);
        self.map.insert(key, peer);
        self.events.push(Event::Added { peer: key, trust });
        if trust == Trust::Member && self.map.len() >= MEMBER_CACHE + MEMBER_SLACK {
            self.evict_members();
        }
    }

    /// Removes a peer and frees its indices and its interface identifier.
    pub(crate) fn remove(&mut self, key: &NodePublic) -> Option<Peer> {
        let p = self.map.remove(key)?;
        for i in p.indices() {
            self.indices.free(i);
        }
        if let Some(seq) = p.unconfirmed_seq() {
            self.indices.drop_unconfirmed(seq);
        }
        if self.by_iid.get(&p.addrs().iid) == Some(key) {
            self.by_iid.remove(&p.addrs().iid);
        }
        self.events.push(Event::Removed { peer: *key });
        Some(p)
    }

    /// Removes a member that never completed a handshake and holds nothing, after a rejected
    /// message 1.
    pub(crate) fn drop_idle_member(&mut self, key: &NodePublic) {
        if self
            .map
            .get(key)
            .is_some_and(|p| p.trust() == Trust::Member && p.is_idle() && !p.ever_heard())
        {
            self.remove(key);
        }
    }

    /// Drops the oldest unconfirmed responder sessions above [`UNCONFIRMED_LIMIT`]; returns the
    /// peers that lost one.
    pub(crate) fn enforce_unconfirmed_limit(&mut self) -> Vec<NodePublic> {
        let mut touched = Vec::new();
        while self.indices.unconfirmed_len() > UNCONFIRMED_LIMIT {
            let Some((seq, oldest)) = self.indices.pop_oldest_unconfirmed() else {
                break;
            };
            if let Some(p) = self.map.get_mut(&oldest) {
                if let Some(index) = p.drop_unconfirmed(seq) {
                    self.indices.free(index);
                }
                touched.push(oldest);
            }
        }
        touched
    }

    /// Removes idle members above [`MEMBER_CACHE`], least recently used first.
    fn evict_members(&mut self) {
        let mut idle: Vec<(Instant, NodePublic)> = self
            .map
            .values()
            .filter(|p| p.trust() == Trust::Member && p.is_idle())
            .map(|p| (p.last_used(), *p.key()))
            .collect();
        if idle.len() <= MEMBER_CACHE {
            return;
        }
        idle.sort();
        let excess = idle.len() - MEMBER_CACHE;
        for (_, key) in idle.into_iter().take(excess) {
            self.remove(&key);
        }
    }
}
