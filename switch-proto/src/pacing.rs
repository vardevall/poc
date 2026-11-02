//! Pacing of the switch path by the rate a switch advertises (vv-04 §3.4
//! `forward_limits`, vv-05 §4.7). The volume is a budget of `proto`.

use vardevall_proto::time::Instant;

use crate::api::Limits;

/// Smallest burst allowed, so that a handshake message fits in it.
const MIN_BURST: f64 = 8192.0;

/// What a datagram is, for pacing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Traffic {
    /// Tunnel data, which is dropped when the rate is used up.
    Data,
    /// Handshake messages and control messages, which go regardless but count.
    Signal,
}

/// A token bucket for the rate of one switch session.
#[derive(Debug)]
pub struct Pacer {
    rate: Option<f64>,
    burst: f64,
    tokens: f64,
    last: Option<Instant>,
}

impl Pacer {
    /// A pacer without limits.
    pub fn new() -> Self {
        Pacer {
            rate: None,
            burst: MIN_BURST,
            tokens: MIN_BURST,
            last: None,
        }
    }

    /// Takes the limits the switch advertises, of which the rate counts; `fresh` starts a new
    /// session, which has its whole burst again.
    pub fn set(&mut self, limits: Option<Limits>, fresh: bool) {
        self.rate = limits
            .and_then(|l| l.bits_per_second)
            .map(|b| b as f64 / 8.0);
        self.burst = self.rate.map_or(MIN_BURST, |r| r.max(MIN_BURST));
        self.tokens = self.tokens.min(self.burst);
        if fresh {
            self.tokens = self.burst;
        }
    }

    fn refill(&mut self, now: Instant) {
        if let (Some(rate), Some(last)) = (self.rate, self.last) {
            let dt = now.saturating_duration_since(last);
            self.tokens = (self.tokens + rate * dt.as_secs_f64()).min(self.burst);
        }
        self.last = Some(now);
    }

    /// Whether a datagram of `len` bytes may go now; if it does, it is counted.
    pub fn allow(&mut self, now: Instant, len: usize, traffic: Traffic) -> bool {
        self.refill(now);
        let len_f = len as f64;
        if traffic == Traffic::Data && self.rate.is_some() && self.tokens < len_f {
            return false;
        }
        if self.rate.is_some() {
            self.tokens = (self.tokens - len_f).max(-self.burst);
        }
        true
    }
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn limits(bps: Option<u64>, bytes: Option<u64>) -> Option<Limits> {
        Some(Limits {
            bits_per_second: bps,
            bytes,
        })
    }

    #[test]
    fn data_is_held_to_the_rate_and_signals_are_not() {
        let mut p = Pacer::new();
        p.set(limits(Some(64_000), None), true);
        let t0 = Instant::from_millis(1000);
        assert!(p.allow(t0, 8000, Traffic::Data));
        assert!(!p.allow(t0, 1200, Traffic::Data));
        assert!(p.allow(t0, 1200, Traffic::Signal));
        let soon = t0 + Duration::from_millis(100);
        assert!(
            !p.allow(soon, 1200, Traffic::Data),
            "the signal was paid for"
        );
        let later = t0 + Duration::from_millis(300);
        assert!(p.allow(later, 1200, Traffic::Data));
    }

    #[test]
    fn the_volume_is_not_the_pacers_business() {
        let mut p = Pacer::new();
        p.set(limits(None, Some(2000)), true);
        let t = Instant::from_millis(1000);
        for _ in 0..10 {
            assert!(p.allow(t, 1200, Traffic::Data));
        }
    }

    #[test]
    fn a_new_session_has_its_whole_burst_again() {
        let mut p = Pacer::new();
        p.set(limits(Some(64_000), None), true);
        let t = Instant::from_millis(1000);
        assert!(p.allow(t, 8000, Traffic::Data));
        assert!(!p.allow(t, 1200, Traffic::Data));
        p.set(limits(Some(64_000), None), false);
        assert!(!p.allow(t, 1200, Traffic::Data));
        p.set(limits(Some(64_000), None), true);
        assert!(p.allow(t, 1200, Traffic::Data));
    }

    #[test]
    fn no_limits_means_no_pacing() {
        let mut p = Pacer::new();
        p.set(None, true);
        let t = Instant::from_millis(1000);
        for _ in 0..100 {
            assert!(p.allow(t, 4000, Traffic::Data));
        }
    }
}
