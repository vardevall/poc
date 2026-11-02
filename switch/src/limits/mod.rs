//! Rate limiting and caps (vv-04 §8).
//!
//! Limiters take the current time as an argument, so tests need no sleeping.

mod bucket;
mod keyed;

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;
use vardevall_proto::keys::NetworkPublic;

pub use bucket::TokenBucket;
pub use keyed::KeyedLimiter;

use crate::config::Limits;

/// A request that exceeded a limit; the client may retry after the given time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exceeded {
    /// Value for `Retry-After`, in seconds, at least 1.
    pub retry_after: u64,
}

impl Exceeded {
    pub(crate) fn after(wait: Duration) -> Self {
        Exceeded {
            retry_after: wait.as_secs_f64().ceil().max(1.0) as u64,
        }
    }
}

/// A client address as a rate-limit key: IPv6 addresses count per /64.
pub fn ip_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(o.into())
        }
        v4 => v4,
    }
}

/// The limiters keyed by network key or client address.
pub struct Limiters {
    per_ip: Mutex<KeyedLimiter<IpAddr>>,
    stun: Mutex<KeyedLimiter<IpAddr>>,
    register: Mutex<KeyedLimiter<NetworkPublic>>,
    members: Mutex<KeyedLimiter<NetworkPublic>>,
    forwards: Mutex<KeyedLimiter<NetworkPublic>>,
    network_bytes: Mutex<KeyedLimiter<NetworkPublic>>,
}

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn keyed<K: std::hash::Hash + Eq>(
    max_keys: usize,
    rate: f64,
    burst: f64,
) -> Mutex<KeyedLimiter<K>> {
    Mutex::new(KeyedLimiter::new(rate, burst, max_keys))
}

impl Limiters {
    /// Limiters with the rates of `limits`; each holds at most `max_keys` buckets.
    pub fn new(limits: &Limits, max_keys: usize) -> Self {
        Limiters {
            per_ip: keyed(max_keys, limits.per_ip_rate, limits.per_ip_burst),
            stun: keyed(max_keys, limits.stun_rate, limits.stun_burst),
            register: keyed(max_keys, limits.register_rate, limits.register_burst),
            members: keyed(max_keys, limits.members_rate, limits.members_burst),
            forwards: keyed(max_keys, limits.forwards_per_second, limits.forwards_burst),
            network_bytes: keyed(
                max_keys,
                limits.network_bytes_per_second,
                limits.network_bytes_burst,
            ),
        }
    }

    /// Charges a `register` or `challenge` request to the client address.
    pub fn ip(&self, ip: IpAddr, now: Instant) -> Result<(), Exceeded> {
        locked(&self.per_ip).check(ip_key(ip), 1.0, now)
    }

    /// Charges a STUN or TURN request on a UDP port to the client address.
    pub fn stun(&self, ip: IpAddr, now: Instant) -> Result<(), Exceeded> {
        locked(&self.stun).check(ip_key(ip), 1.0, now)
    }

    /// Charges a registration to the network.
    pub fn register(&self, net: &NetworkPublic, now: Instant) -> Result<(), Exceeded> {
        locked(&self.register).check(*net, 1.0, now)
    }

    /// Charges a `members` request to the network.
    pub fn members(&self, net: &NetworkPublic, now: Instant) -> Result<(), Exceeded> {
        locked(&self.members).check(*net, 1.0, now)
    }

    /// Charges a forwarded message of `len` bytes to the network.
    pub fn forward(&self, net: &NetworkPublic, len: usize, now: Instant) -> Result<(), Exceeded> {
        locked(&self.forwards).check(*net, 1.0, now)?;
        locked(&self.network_bytes).check(*net, len as f64, now)
    }

    /// Drops buckets that have refilled completely.
    pub fn sweep(&self, now: Instant) {
        locked(&self.per_ip).sweep(now);
        locked(&self.stun).sweep(now);
        locked(&self.register).sweep(now);
        locked(&self.members).sweep(now);
        locked(&self.forwards).sweep(now);
        locked(&self.network_bytes).sweep(now);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn ipv6_counts_per_slash_64() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b));
        assert_ne!(ip_key(a), ip_key(c));
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(ip_key(mapped), "192.0.2.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn stun_requests_are_limited_per_address_and_refill() {
        let limits = Limits {
            stun_rate: 1.0,
            stun_burst: 2.0,
            ..Limits::default()
        };
        let l = Limiters::new(&limits, 100);
        let now = Instant::now();
        let a: IpAddr = "192.0.2.7".parse().unwrap();
        let b: IpAddr = "192.0.2.8".parse().unwrap();
        assert!(l.stun(a, now).is_ok());
        assert!(l.stun(a, now).is_ok());
        assert!(l.stun(a, now).is_err());
        assert!(l.stun(b, now).is_ok());
        assert!(l.stun(a, now + Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn per_ip_limit_applies_before_anything_else() {
        let limits = Limits {
            per_ip_burst: 3.0,
            ..Limits::default()
        };
        let l = Limiters::new(&limits, 100);
        let now = Instant::now();
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        for _ in 0..3 {
            assert!(l.ip(ip, now).is_ok());
        }
        let e = l.ip(ip, now).unwrap_err();
        assert!(e.retry_after >= 1);
        assert!(l.ip("192.0.2.8".parse().unwrap(), now).is_ok());
    }

    #[test]
    fn forward_charges_messages_and_bytes() {
        let limits = Limits {
            forwards_burst: 5.0,
            network_bytes_burst: 10_000.0,
            ..Limits::default()
        };
        let l = Limiters::new(&limits, 100);
        let net = NetworkPublic::from_bytes([1; 32]);
        let now = Instant::now();
        assert!(l.forward(&net, 4096, now).is_ok());
        assert!(l.forward(&net, 4096, now).is_ok());
        assert!(l.forward(&net, 4096, now).is_err());
        let other = NetworkPublic::from_bytes([2; 32]);
        assert!(l.forward(&other, 4096, now).is_ok());
        for _ in 0..4 {
            let _ = l.forward(&other, 1, now);
        }
        assert!(l.forward(&other, 1, now).is_err());
    }
}
