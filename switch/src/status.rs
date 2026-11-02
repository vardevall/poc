//! The status line: counts only, never a node, network or address (vv-04 §8).

use std::sync::atomic::{AtomicU64, Ordering};

/// Requests refused since the last status line.
#[derive(Debug, Default)]
pub struct Counters {
    rate_limited: AtomicU64,
    token_required: AtomicU64,
    invalid_proof: AtomicU64,
    unanswered: AtomicU64,
}

/// What [`Counters::take`] read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rejections {
    /// API requests answered `rate-limited`, caps included.
    pub rate_limited: u64,
    /// API requests answered `token-required`.
    pub token_required: u64,
    /// API requests answered `invalid-proof`.
    pub invalid_proof: u64,
    /// STUN and TURN requests that got no reply: over a limit, or not authenticated on a server
    /// that stays silent.
    pub unanswered: u64,
}

impl Counters {
    /// Counts an API error, if it is a refusal.
    pub(crate) fn api_error(&self, error: &crate::api::ApiError) {
        use crate::api::ApiError;
        let counter = match error {
            ApiError::RateLimited(_) => &self.rate_limited,
            ApiError::TokenRequired => &self.token_required,
            ApiError::InvalidProof => &self.invalid_proof,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a STUN or TURN request that got no reply.
    #[cfg(feature = "stun-turn")]
    pub(crate) fn unanswered(&self) {
        self.unanswered.fetch_add(1, Ordering::Relaxed);
    }

    /// The counts since the last call, which start again from zero.
    pub fn take(&self) -> Rejections {
        let take = |c: &AtomicU64| c.swap(0, Ordering::Relaxed);
        Rejections {
            rate_limited: take(&self.rate_limited),
            token_required: take(&self.token_required),
            invalid_proof: take(&self.invalid_proof),
            unanswered: take(&self.unanswered),
        }
    }
}

/// The status line for the tables `registry` and `allocations` (if the switch relays) and the
/// refusals since the last line.
pub fn line(
    registry: crate::registry::Stats,
    allocations: Option<usize>,
    rejected: Rejections,
) -> String {
    let allocations = allocations.map_or(String::new(), |n| format!(", {n} allocations"));
    format!(
        "vv-switch: status: {} registrations in {} networks, {} event streams{allocations}; \
         since the last line: {} rate-limited, {} token-required, {} invalid-proof, \
         {} STUN or TURN requests unanswered",
        registry.registrations,
        registry.networks,
        registry.streams,
        rejected.rate_limited,
        rejected.token_required,
        rejected.invalid_proof,
        rejected.unanswered,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ApiError;
    use crate::limits::Exceeded;
    use crate::registry::Stats;

    #[test]
    fn counts_refusals_and_starts_again_after_a_line() {
        let c = Counters::default();
        c.api_error(&ApiError::RateLimited(Exceeded { retry_after: 1 }));
        c.api_error(&ApiError::RateLimited(Exceeded { retry_after: 1 }));
        c.api_error(&ApiError::TokenRequired);
        c.api_error(&ApiError::InvalidProof);
        c.api_error(&ApiError::NotFound);
        #[cfg(feature = "stun-turn")]
        c.unanswered();
        let r = c.take();
        assert_eq!(
            (
                r.rate_limited,
                r.token_required,
                r.invalid_proof,
                r.unanswered
            ),
            (2, 1, 1, u64::from(cfg!(feature = "stun-turn")))
        );
        assert_eq!(c.take(), Rejections::default());
    }

    #[test]
    fn the_line_has_counts_only() {
        let stats = Stats {
            registrations: 12,
            networks: 3,
            streams: 11,
        };
        let r = Rejections {
            rate_limited: 4,
            unanswered: 9,
            ..Rejections::default()
        };
        assert_eq!(
            line(stats, Some(2), r),
            "vv-switch: status: 12 registrations in 3 networks, 11 event streams, 2 allocations; \
             since the last line: 4 rate-limited, 0 token-required, 0 invalid-proof, \
             9 STUN or TURN requests unanswered"
        );
        assert!(!line(stats, None, r).contains("allocations"));
    }
}
