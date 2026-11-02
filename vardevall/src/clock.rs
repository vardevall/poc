//! Mapping of tokio time to `proto`'s caller-supplied clocks.

use std::time::{SystemTime, UNIX_EPOCH};

use tokio::time::Instant as TokioInstant;
use vardevall_proto::time::{Instant, Now};

/// Monotonic and wall-clock readings relative to the node's start.
#[derive(Clone, Copy)]
pub(crate) struct Clock {
    start: TokioInstant,
}

/// Nanoseconds since the Unix epoch.
pub(crate) fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Whole seconds since the Unix epoch.
pub(crate) fn unix_seconds() -> u64 {
    unix_nanos() / 1_000_000_000
}

impl Clock {
    /// A clock whose epoch is now.
    pub(crate) fn new() -> Self {
        Clock {
            start: TokioInstant::now(),
        }
    }

    /// Both readings at this moment.
    pub(crate) fn now(&self) -> Now {
        Now::new(Instant::from_duration(self.start.elapsed()), unix_nanos())
    }

    /// The tokio instant of a core instant.
    pub(crate) fn tokio_instant(&self, at: Instant) -> TokioInstant {
        self.start + at.as_duration()
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}
