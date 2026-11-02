//! A token bucket.

use std::time::Duration;

use tokio::time::Instant;

use super::Exceeded;

/// Tokens refill at `rate` per second up to `burst`.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket.
    pub fn full(burst: f64, now: Instant) -> Self {
        TokenBucket {
            tokens: burst,
            last: now,
        }
    }

    fn refill(&mut self, rate: f64, burst: f64, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * rate).min(burst);
        self.last = self.last.max(now);
    }

    /// Takes `cost` tokens, or reports how long until they are available.
    pub fn take(&mut self, cost: f64, rate: f64, burst: f64, now: Instant) -> Result<(), Exceeded> {
        self.refill(rate, burst, now);
        if cost > burst {
            return Err(Exceeded::after(Duration::from_secs(1)));
        }
        if self.tokens >= cost {
            self.tokens -= cost;
            return Ok(());
        }
        let missing = cost - self.tokens;
        Err(Exceeded::after(Duration::from_secs_f64(missing / rate)))
    }

    /// Whether the bucket is full as of `now`, so that dropping it changes nothing.
    pub fn is_full(&mut self, rate: f64, burst: f64, now: Instant) -> bool {
        self.refill(rate, burst, now);
        self.tokens >= burst
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refills_over_time_and_caps_at_burst() {
        let t0 = Instant::now();
        let mut b = TokenBucket::full(4.0, t0);
        for _ in 0..4 {
            assert!(b.take(1.0, 2.0, 4.0, t0).is_ok());
        }
        let e = b.take(1.0, 2.0, 4.0, t0).unwrap_err();
        assert_eq!(e.retry_after, 1);
        let later = t0 + Duration::from_millis(500);
        assert!(b.take(1.0, 2.0, 4.0, later).is_ok());
        assert!(b.take(1.0, 2.0, 4.0, later).is_err());
        let much_later = t0 + Duration::from_secs(60);
        assert!(b.is_full(2.0, 4.0, much_later));
    }

    #[test]
    fn a_cost_above_the_burst_never_passes() {
        let t0 = Instant::now();
        let mut b = TokenBucket::full(4.0, t0);
        assert!(b.take(5.0, 2.0, 4.0, t0).is_err());
        assert!(b.take(4.0, 2.0, 4.0, t0).is_ok());
    }

    #[test]
    fn retry_after_tracks_the_missing_tokens() {
        let t0 = Instant::now();
        let mut b = TokenBucket::full(10.0, t0);
        assert!(b.take(10.0, 1.0, 10.0, t0).is_ok());
        assert_eq!(b.take(5.0, 1.0, 10.0, t0).unwrap_err().retry_after, 5);
    }
}
