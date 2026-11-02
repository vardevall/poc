//! The retransmission timer of pings, as TCP's (RFC 6298).

use std::time::Duration;

/// Lower bound of an RTO.
pub const MIN_RTO: Duration = Duration::from_millis(200);
/// RTO before the first sample.
pub const INITIAL_RTO: Duration = Duration::from_secs(1);
/// Upper bound of an RTO, the RFC 6298 §2.5 minimum for a maximum.
pub const MAX_RTO: Duration = Duration::from_secs(60);
/// Clock granularity term of the RTO.
const GRANULARITY: Duration = Duration::from_millis(10);

/// Smoothed round-trip time and variation of one route.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rtt {
    smoothed: Option<(Duration, Duration)>,
}

impl Rtt {
    /// An estimator without samples.
    pub const fn new() -> Self {
        Rtt { smoothed: None }
    }

    /// Adds a sample (RFC 6298 §2.2, §2.3).
    pub fn sample(&mut self, r: Duration) {
        self.smoothed = Some(match self.smoothed {
            None => (r, r / 2),
            Some((srtt, var)) => {
                let delta = srtt.abs_diff(r);
                let var = var * 3 / 4 + delta / 4;
                let srtt = srtt * 7 / 8 + r / 8;
                (srtt, var)
            }
        });
    }

    /// The smoothed round-trip time, if any sample exists.
    pub fn srtt(&self) -> Option<Duration> {
        self.smoothed.map(|(s, _)| s)
    }

    /// `SRTT + max(4 × RTTVAR, 10 ms)`, at least 200 ms; 1 s before the first sample.
    pub fn rto(&self) -> Duration {
        match self.smoothed {
            None => INITIAL_RTO,
            Some((srtt, var)) => (srtt + (var * 4).max(GRANULARITY))
                .max(MIN_RTO)
                .min(MAX_RTO),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn one_second_before_the_first_sample() {
        assert_eq!(Rtt::new().rto(), INITIAL_RTO);
    }

    #[test]
    fn the_first_sample_sets_variation_to_half() {
        let mut r = Rtt::new();
        r.sample(ms(100));
        assert_eq!(r.srtt(), Some(ms(100)));
        assert_eq!(r.rto(), ms(100 + 200));
    }

    #[test]
    fn later_samples_are_smoothed() {
        let mut r = Rtt::new();
        r.sample(ms(80));
        r.sample(ms(160));
        assert_eq!(r.srtt(), Some(ms(90)));
        // RTTVAR = 3/4 * 40 + 1/4 * 80 = 50 ms
        assert_eq!(r.rto(), ms(90 + 200));
    }

    #[test]
    fn bounded_below_and_above() {
        let mut r = Rtt::new();
        for _ in 0..64 {
            r.sample(ms(0));
        }
        assert_eq!(r.rto(), MIN_RTO);
        let mut r = Rtt::new();
        r.sample(Duration::from_secs(120));
        assert_eq!(r.rto(), MAX_RTO);
    }
}
