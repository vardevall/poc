//! Sliding replay window for data counters (vv-03 §3.3).

/// `REJECT_AFTER_MESSAGES` (vv-02 §6.4).
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

const BLOCK_BITS: u64 = 64;
const RING_BLOCKS: u64 = 256;
/// Counters this far below the highest one are rejected; at least 8192 (vv-03 §3.3).
pub const WINDOW_SIZE: u64 = (RING_BLOCKS - 1) * BLOCK_BITS;

/// A replay window in the style of RFC 6479.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    last: u64,
    ring: [u64; RING_BLOCKS as usize],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// An empty window.
    pub const fn new() -> Self {
        ReplayWindow {
            last: 0,
            ring: [0; RING_BLOCKS as usize],
        }
    }

    /// Whether `counter` may still be accepted; does not record it.
    pub fn check(&self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        if counter > self.last {
            return true;
        }
        if self.last - counter > WINDOW_SIZE {
            return false;
        }
        let (block, bit) = Self::position(counter);
        self.ring[block] & (1 << bit) == 0
    }

    /// Whether `counter`, which [`ReplayWindow::check`] accepted, is above every counter
    /// recorded so far.
    pub fn is_newest(&self, counter: u64) -> bool {
        counter > self.last || (counter == 0 && self.last == 0)
    }

    /// Records `counter` after its tag verified.
    pub fn update(&mut self, counter: u64) {
        if counter >= REJECT_AFTER_MESSAGES {
            return;
        }
        let block_index = counter / BLOCK_BITS;
        if counter > self.last {
            let current = self.last / BLOCK_BITS;
            let diff = (block_index - current).min(RING_BLOCKS);
            for i in 1..=diff {
                self.ring[((current + i) % RING_BLOCKS) as usize] = 0;
            }
            self.last = counter;
        } else if self.last - counter > WINDOW_SIZE {
            return;
        }
        let (block, bit) = Self::position(counter);
        self.ring[block] |= 1 << bit;
    }

    fn position(counter: u64) -> (usize, u32) {
        (
            ((counter / BLOCK_BITS) % RING_BLOCKS) as usize,
            (counter % BLOCK_BITS) as u32,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn accept(w: &mut ReplayWindow, c: u64) -> bool {
        let ok = w.check(c);
        if ok {
            w.update(c);
        }
        ok
    }

    #[test]
    fn rejects_duplicates_and_old() {
        let mut w = ReplayWindow::new();
        assert!(accept(&mut w, 0));
        assert!(!accept(&mut w, 0));
        assert!(accept(&mut w, 5));
        assert!(accept(&mut w, 3));
        assert!(!accept(&mut w, 3));
        assert!(accept(&mut w, 100_000));
        assert!(!accept(&mut w, 100_000 - WINDOW_SIZE - 1));
        assert!(accept(&mut w, 100_000 - 8192));
    }

    #[test]
    fn newest_is_above_everything_received() {
        let mut w = ReplayWindow::new();
        assert!(w.is_newest(0), "the first frame is the newest");
        assert!(accept(&mut w, 0));
        assert!(w.is_newest(1));
        assert!(accept(&mut w, 5));
        assert!(!w.is_newest(3));
        assert!(!w.is_newest(5));
        assert!(w.is_newest(6));
    }

    #[test]
    fn rejects_at_the_message_limit() {
        let mut w = ReplayWindow::new();
        assert!(!w.check(REJECT_AFTER_MESSAGES));
        assert!(accept(&mut w, REJECT_AFTER_MESSAGES - 1));
        assert!(!w.check(u64::MAX));
    }

    proptest! {
        #[test]
        fn never_accepts_a_counter_twice(counters in proptest::collection::vec(0u64..40_000, 1..400)) {
            let mut w = ReplayWindow::new();
            let mut seen = std::collections::HashSet::new();
            for c in counters {
                if accept(&mut w, c) {
                    prop_assert!(seen.insert(c), "accepted {c} twice");
                }
            }
        }

        #[test]
        fn accepts_everything_inside_the_window_once(base in 10_000u64..1_000_000, offsets in proptest::collection::vec(0u64..8000, 1..200)) {
            let mut w = ReplayWindow::new();
            prop_assert!(accept(&mut w, base));
            let mut seen = std::collections::HashSet::new();
            seen.insert(base);
            for o in offsets {
                let c = base - o;
                prop_assert_eq!(accept(&mut w, c), seen.insert(c));
            }
        }
    }
}
