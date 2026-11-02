//! Reassembly of handshake fragments (vv-02 §5.3).

use std::collections::HashMap;
use std::time::Duration;

use crate::handshake::message::MessageNumber;
use crate::time::Instant;

/// Entries kept per interface (vv-02 §5.3).
pub const MAX_ENTRIES: usize = 256;
/// Lifetime of an entry after its first fragment (vv-02 §5.3).
pub const ENTRY_LIFETIME: Duration = Duration::from_secs(2);

struct Entry {
    first_seen: Instant,
    parts: [Option<Vec<u8>>; 2],
}

/// A bounded table of partially received messages keyed by source.
pub struct Reassembly<S> {
    entries: HashMap<(S, MessageNumber, u32), Entry>,
}

impl<S: std::hash::Hash + Eq + Clone> Default for Reassembly<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: std::hash::Hash + Eq + Clone> Reassembly<S> {
    /// An empty table.
    pub fn new() -> Self {
        Reassembly {
            entries: HashMap::new(),
        }
    }

    /// Number of partial messages held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no partial message is held.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Stores a verified fragment; returns the whole message once both parts are present.
    pub fn insert(
        &mut self,
        now: Instant,
        source: S,
        number: MessageNumber,
        sender_index: u32,
        index: u8,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let key = (source, number, sender_index);
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_ENTRIES {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.first_seen)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.entries.remove(&k);
            }
        }
        let entry = self.entries.entry(key.clone()).or_insert_with(|| Entry {
            first_seen: now,
            parts: [None, None],
        });
        entry.parts[usize::from(index & 1)] = Some(data.to_vec());
        if entry.parts.iter().all(Option::is_some) {
            let entry = self.entries.remove(&key)?;
            let [a, b] = entry.parts;
            let mut message = a?;
            message.extend_from_slice(&b?);
            return Some(message);
        }
        None
    }

    /// Discards entries older than [`ENTRY_LIFETIME`].
    pub fn expire(&mut self, now: Instant) {
        self.entries
            .retain(|_, e| now < e.first_seen + ENTRY_LIFETIME);
    }

    /// When the oldest entry expires.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.entries
            .values()
            .map(|e| e.first_seen + ENTRY_LIFETIME)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_in_either_order_and_replaces_duplicates() {
        let mut r = Reassembly::new();
        let t = Instant::ZERO;
        assert!(
            r.insert(t, 1u8, MessageNumber::One, 7, 1, b"world")
                .is_none()
        );
        assert!(
            r.insert(t, 1u8, MessageNumber::One, 7, 1, b"WORLD")
                .is_none()
        );
        assert_eq!(
            r.insert(t, 1u8, MessageNumber::One, 7, 0, b"hello ")
                .unwrap(),
            b"hello WORLD"
        );
        assert!(r.is_empty());
    }

    #[test]
    fn expires_and_bounds() {
        let mut r = Reassembly::new();
        for i in 0..(MAX_ENTRIES as u32 + 50) {
            r.insert(
                Instant::from_millis(u64::from(i)),
                0u8,
                MessageNumber::Two,
                i,
                0,
                b"x",
            );
        }
        assert_eq!(r.len(), MAX_ENTRIES);
        assert!(
            r.insert(
                Instant::from_millis(500),
                0u8,
                MessageNumber::Two,
                0,
                1,
                b"y"
            )
            .is_none()
        );
        r.expire(Instant::from_millis(2_100));
        assert!(r.len() < MAX_ENTRIES);
        r.expire(Instant::from_millis(10_000));
        assert!(r.is_empty());
        assert!(r.next_expiry().is_none());
    }

    #[test]
    fn sources_do_not_mix() {
        let mut r = Reassembly::new();
        let t = Instant::ZERO;
        r.insert(t, 1u8, MessageNumber::One, 7, 0, b"a");
        assert!(r.insert(t, 2u8, MessageNumber::One, 7, 1, b"b").is_none());
        assert!(r.insert(t, 1u8, MessageNumber::Two, 7, 1, b"b").is_none());
    }
}
