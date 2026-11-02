//! Bytes per transport and per route, and the budgets of metered transports.

/// Bytes sent and received: the datagrams of `proto`, without the framing of the transport.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Meter {
    /// Bytes of every `Transmit`.
    pub sent: u64,
    /// Bytes of every datagram handed to the node.
    pub received: u64,
}

impl Meter {
    /// Counts `len` bytes sent.
    pub fn add_sent(&mut self, len: usize) {
        self.sent = self.sent.saturating_add(len as u64);
    }

    /// Counts `len` bytes received.
    pub fn add_received(&mut self, len: usize) {
        self.received = self.received.saturating_add(len as u64);
    }
}

/// The kind of route whose transport stated a budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetSource {
    /// A route to a peer reported reachable: the volume the transport states per
    /// session.
    Reported,
    /// A relay route (label `relay`): the volume the relay states per credential.
    Relay,
}

/// How much of a budget is left, in steps that are reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Half or more.
    Plenty,
    /// Under half.
    Half,
    /// Under a tenth.
    Low,
    /// Nothing: the transport is unusable.
    Exhausted,
}

/// What a transport may still carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// The volume stated.
    pub total: u64,
    /// What is left of it.
    pub remaining: u64,
    /// Who stated it.
    pub source: BudgetSource,
    /// Whether received bytes are charged too: a TURN server charges both directions, a switch
    /// charges a forward to its sender.
    pub received: bool,
}

impl Budget {
    /// A full budget of `total` bytes.
    pub fn new(total: u64, source: BudgetSource, received: bool) -> Self {
        Budget {
            total,
            remaining: total,
            source,
            received,
        }
    }

    /// The step `remaining` is in.
    pub fn level(&self) -> Level {
        if self.remaining == 0 {
            Level::Exhausted
        } else if self.remaining.saturating_mul(10) < self.total {
            Level::Low
        } else if self.remaining.saturating_mul(2) < self.total {
            Level::Half
        } else {
            Level::Plenty
        }
    }

    /// Whether nothing is left.
    pub fn exhausted(&self) -> bool {
        self.remaining == 0
    }

    /// Charges `len` bytes; returns the new level if the charge crossed into one.
    pub fn spend(&mut self, len: usize) -> Option<Level> {
        let before = self.level();
        self.remaining = self.remaining.saturating_sub(len as u64);
        let after = self.level();
        (after != before).then_some(after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_budget_reports_each_level_once_on_the_way_down() {
        let mut b = Budget::new(1000, BudgetSource::Relay, true);
        assert_eq!(b.level(), Level::Plenty);
        assert_eq!(b.spend(500), None);
        assert_eq!(b.spend(1), Some(Level::Half));
        assert_eq!(b.spend(398), None);
        assert_eq!(b.spend(2), Some(Level::Low));
        assert_eq!(b.spend(98), None);
        assert!(!b.exhausted());
        assert_eq!(b.spend(5000), Some(Level::Exhausted));
        assert!(b.exhausted());
        assert_eq!(b.spend(1), None);
    }

    #[test]
    fn a_single_charge_may_skip_levels() {
        let mut b = Budget::new(100, BudgetSource::Reported, false);
        assert_eq!(b.spend(95), Some(Level::Low));
        let mut b = Budget::new(100, BudgetSource::Reported, false);
        assert_eq!(b.spend(100), Some(Level::Exhausted));
    }

    #[test]
    fn a_zero_budget_is_exhausted_from_the_start() {
        let b = Budget::new(0, BudgetSource::Reported, false);
        assert!(b.exhausted());
        assert_eq!(b.level(), Level::Exhausted);
    }

    #[test]
    fn meters_saturate() {
        let mut m = Meter {
            sent: u64::MAX - 1,
            received: 0,
        };
        m.add_sent(10);
        m.add_received(3);
        assert_eq!((m.sent, m.received), (u64::MAX, 3));
    }
}
