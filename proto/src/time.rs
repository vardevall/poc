//! Caller-supplied time (vv-00 §8).

use core::ops::{Add, Sub};
use core::time::Duration;

/// A monotonic instant, as a duration since an arbitrary epoch chosen by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(Duration);

impl Instant {
    /// The epoch.
    pub const ZERO: Instant = Instant(Duration::ZERO);

    /// An instant `d` after the epoch.
    pub const fn from_duration(d: Duration) -> Self {
        Instant(d)
    }

    /// An instant `ms` milliseconds after the epoch.
    pub const fn from_millis(ms: u64) -> Self {
        Instant(Duration::from_millis(ms))
    }

    /// Time since the epoch.
    pub const fn as_duration(self) -> Duration {
        self.0
    }

    /// `self - earlier`, or zero if `earlier` is later.
    pub fn saturating_duration_since(self, earlier: Instant) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, rhs: Duration) -> Instant {
        Instant(self.0.saturating_add(rhs))
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;
    fn sub(self, rhs: Instant) -> Duration {
        self.saturating_duration_since(rhs)
    }
}

/// The caller's clocks at one moment: monotonic for timers, wall-clock for handshake timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    /// Monotonic time.
    pub instant: Instant,
    /// Nanoseconds since the Unix epoch (vv-02 §3.3 `ts`).
    pub unix_nanos: u64,
}

impl Now {
    /// A pair of clock readings.
    pub const fn new(instant: Instant, unix_nanos: u64) -> Self {
        Now {
            instant,
            unix_nanos,
        }
    }

    /// Whole seconds since the Unix epoch.
    pub const fn unix_seconds(self) -> u64 {
        self.unix_nanos / 1_000_000_000
    }
}
