//! Pausing after a failing system call, so that a persistent error does not spin the CPU.

use std::time::Duration;

const FIRST: Duration = Duration::from_millis(10);
const LONGEST: Duration = Duration::from_secs(1);

/// The pause after consecutive failures: none for the first, then 10 ms doubling to 1 s.
#[derive(Debug, Default)]
pub(crate) struct Backoff {
    failures: u32,
}

impl Backoff {
    /// The pause after one more failure.
    pub(crate) fn next(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        match self.failures {
            1 => Duration::ZERO,
            n => FIRST.saturating_mul(1 << (n - 2).min(10)).min(LONGEST),
        }
    }

    /// Sleeps for the pause after one more failure.
    pub(crate) async fn wait(&mut self) {
        let pause = self.next();
        if !pause.is_zero() {
            tokio::time::sleep(pause).await;
        }
    }

    /// Forgets the failures after a success.
    pub(crate) fn reset(&mut self) {
        self.failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pause_grows_to_a_second_and_resets() {
        let mut b = Backoff::default();
        let pauses: Vec<u64> = (0..12).map(|_| b.next().as_millis() as u64).collect();
        assert_eq!(pauses[..4], [0, 10, 20, 40]);
        assert_eq!(pauses[11], 1000);
        assert!(pauses.windows(2).all(|w| w[0] <= w[1]));
        b.reset();
        assert_eq!(b.next(), Duration::ZERO);
    }
}
