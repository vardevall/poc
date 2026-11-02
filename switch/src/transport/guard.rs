//! Connection caps (vv-04 §8).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::limits::ip_key;

struct Counts {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// Caps on open connections, in total and per client address.
pub struct ConnLimits {
    max_total: usize,
    max_per_ip: usize,
    counts: Mutex<Counts>,
}

/// A connection slot; dropping it frees the slot.
pub struct ConnPermit {
    limits: Arc<ConnLimits>,
    ip: Option<IpAddr>,
}

impl ConnLimits {
    /// Caps of `max_total` connections and `max_per_ip` per client address.
    pub fn new(max_total: usize, max_per_ip: usize) -> Self {
        ConnLimits {
            max_total,
            max_per_ip,
            counts: Mutex::new(Counts {
                total: 0,
                per_ip: HashMap::new(),
            }),
        }
    }

    fn counts(&self) -> std::sync::MutexGuard<'_, Counts> {
        self.counts.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes a slot for `ip`, or `None` if a cap is reached. Without an address only the total
    /// is counted, until [`ConnPermit::attach`] names the client.
    pub fn acquire(self: &Arc<Self>, ip: Option<IpAddr>) -> Option<ConnPermit> {
        let mut c = self.counts();
        if c.total >= self.max_total {
            return None;
        }
        let ip = match ip {
            Some(ip) => {
                let ip = ip_key(ip);
                let n = c.per_ip.entry(ip).or_insert(0);
                if *n >= self.max_per_ip {
                    return None;
                }
                *n += 1;
                Some(ip)
            }
            None => None,
        };
        c.total += 1;
        Some(ConnPermit {
            limits: self.clone(),
            ip,
        })
    }
}

impl ConnPermit {
    /// Counts the slot against the client `ip` as well; `false` if that address is at its cap.
    /// Does nothing if the slot already belongs to an address.
    pub fn attach(&mut self, ip: IpAddr) -> bool {
        if self.ip.is_some() {
            return true;
        }
        let ip = ip_key(ip);
        let mut c = self.limits.counts();
        let n = c.per_ip.entry(ip).or_insert(0);
        if *n >= self.limits.max_per_ip {
            return false;
        }
        *n += 1;
        self.ip = Some(ip);
        true
    }
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut c = self.limits.counts();
        c.total = c.total.saturating_sub(1);
        let Some(ip) = self.ip else { return };
        if let Some(n) = c.per_ip.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                c.per_ip.remove(&ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_apply_in_total_and_per_address() {
        let l = Arc::new(ConnLimits::new(3, 2));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let p1 = l.acquire(Some(a)).unwrap();
        let _p2 = l.acquire(Some(a)).unwrap();
        assert!(l.acquire(Some(a)).is_none());
        let _p3 = l.acquire(Some(b)).unwrap();
        assert!(l.acquire(Some(b)).is_none());
        drop(p1);
        let _p4 = l.acquire(Some(b)).unwrap();
        assert!(l.acquire(Some(a)).is_none());
    }

    #[test]
    fn a_slot_without_an_address_counts_in_total_until_attached() {
        let l = Arc::new(ConnLimits::new(3, 1));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let mut p1 = l.acquire(None).unwrap();
        let mut p2 = l.acquire(None).unwrap();
        assert!(p1.attach(a));
        assert!(!p2.attach(a));
        let _p3 = l.acquire(None).unwrap();
        assert!(l.acquire(None).is_none());
        drop(p1);
        assert!(p2.attach(a));
    }
}
