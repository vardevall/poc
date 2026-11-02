//! A bounded map of token buckets.

use std::collections::HashMap;
use std::hash::Hash;

use tokio::time::Instant;

use super::Exceeded;
use super::bucket::TokenBucket;

/// One bucket per key with a common rate; the map never holds more than `max_keys` entries.
pub struct KeyedLimiter<K> {
    rate: f64,
    burst: f64,
    max_keys: usize,
    buckets: HashMap<K, TokenBucket>,
}

impl<K: Hash + Eq> KeyedLimiter<K> {
    /// A limiter with `rate` tokens per second and `burst` capacity per key.
    pub fn new(rate: f64, burst: f64, max_keys: usize) -> Self {
        KeyedLimiter {
            rate,
            burst,
            max_keys,
            buckets: HashMap::new(),
        }
    }

    /// Charges `cost` to `key`. When the map is full of active keys, a new key is refused.
    pub fn check(&mut self, key: K, cost: f64, now: Instant) -> Result<(), Exceeded> {
        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.max_keys {
            self.sweep(now);
            if self.buckets.len() >= self.max_keys {
                return Err(Exceeded::after(std::time::Duration::from_secs(1)));
            }
        }
        let (rate, burst) = (self.rate, self.burst);
        self.buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::full(burst, now))
            .take(cost, rate, burst, now)
    }

    /// Drops buckets that have refilled completely.
    pub fn sweep(&mut self, now: Instant) {
        let (rate, burst) = (self.rate, self.burst);
        self.buckets.retain(|_, b| !b.is_full(rate, burst, now));
    }

    /// Number of buckets held.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Whether no bucket is held.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn full_map_refuses_new_keys_until_buckets_refill() {
        let t0 = Instant::now();
        let mut l = KeyedLimiter::new(1.0, 2.0, 2);
        assert!(l.check(1u8, 1.0, t0).is_ok());
        assert!(l.check(2u8, 1.0, t0).is_ok());
        assert!(l.check(3u8, 1.0, t0).is_err());
        assert!(l.check(1u8, 1.0, t0).is_ok());
        let later = t0 + Duration::from_secs(10);
        assert!(l.check(3u8, 1.0, later).is_ok());
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn sweep_removes_idle_keys() {
        let t0 = Instant::now();
        let mut l = KeyedLimiter::new(1.0, 2.0, 10);
        for k in 0..5u8 {
            assert!(l.check(k, 1.0, t0).is_ok());
        }
        l.sweep(t0);
        assert_eq!(l.len(), 5);
        l.sweep(t0 + Duration::from_secs(5));
        assert!(l.is_empty());
    }
}
