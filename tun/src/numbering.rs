//! The numbers a Linux host needs for one interface: firewall mark, routing table, `ip rule`
//! priorities and nftables table names.
//!
//! Every number follows from the interface, so that two interfaces with exits live in one network
//! namespace without sharing a table, a rule or a ruleset. The interface name gives a slot; a
//! flag can choose the slot when two names land on the same one.

use std::ops::Range;

/// How many slots there are; the slot of an interface is in `0..SLOTS`.
pub const SLOTS: u16 = 1000;
/// The mark of slot 0; the slot is in the low 16 bits.
const MARK_BASE: u32 = 0x7664_0000;
/// The bits of a mark that say it is the engine's, whatever the interface.
const MARK_MASK: u32 = 0xffff_0000;
/// The table of slot 0.
const TABLE_BASE: u32 = 30_000;
/// The first `ip rule` priority of slot 0, above the host's usual rules and below `main`'s 32766.
const PRIORITY_BASE: u32 = 20_000;
/// The priorities each slot owns.
const PRIORITY_COUNT: u32 = 8;

/// The numbers of one interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Numbering {
    slot: u16,
}

fn fnv1a(text: &str) -> u32 {
    text.bytes().fold(0x811c_9dc5, |h, b| {
        (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
    })
}

impl Numbering {
    /// The numbers derived from the name of `interface`.
    pub fn for_interface(interface: &str) -> Self {
        Numbering {
            slot: u16::try_from(fnv1a(interface) % u32::from(SLOTS)).unwrap_or(0),
        }
    }

    /// The numbers of `slot`; `None` outside `0..SLOTS`.
    pub fn from_slot(slot: u16) -> Option<Self> {
        (slot < SLOTS).then_some(Numbering { slot })
    }

    /// The slot.
    pub fn slot(self) -> u16 {
        self.slot
    }

    /// The firewall mark of the engine's sockets.
    pub fn mark(self) -> u32 {
        MARK_BASE | u32::from(self.slot)
    }

    /// The bits of a mark that every interface's marked sockets share: a rule that matches them
    /// leaves the traffic of all the engines out of every table of an exit in use.
    pub const fn mark_mask() -> u32 {
        MARK_MASK
    }

    /// The routing table of the default routes of an exit in use.
    pub fn table(self) -> u32 {
        TABLE_BASE + u32::from(self.slot)
    }

    /// The priority of the rule that keeps the `i`-th private IPv4 range on the main table.
    pub fn private_priority(self, i: u32) -> u32 {
        self.first() + i.min(3)
    }

    /// The priority of the rule that lets the main table answer for all but its default route.
    pub fn suppress_priority(self) -> u32 {
        self.first() + 4
    }

    /// The priority of the rule that sends unmarked traffic to the table.
    pub fn table_priority(self) -> u32 {
        self.first() + 5
    }

    /// The priorities this interface owns; the sweep removes rules in this range only.
    pub fn priorities(self) -> Range<u32> {
        self.first()..self.first() + PRIORITY_COUNT
    }

    fn first(self) -> u32 {
        PRIORITY_BASE + u32::from(self.slot) * PRIORITY_COUNT
    }

    /// The names of the nftables tables of the exit served on `device`, as `(family, name)`.
    pub fn nft_tables(device: &str) -> [(&'static str, String); 3] {
        let base = nft_base(device);
        [
            ("inet", base.clone()),
            ("ip6", format!("{base}_nat6")),
            ("ip", format!("{base}_nat4")),
        ]
    }
}

/// The name nftables tables of `device` start with.
pub fn nft_base(device: &str) -> String {
    let safe: String = device
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("vv_{safe}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slot_follows_the_name_and_the_numbers_follow_the_slot() {
        let a = Numbering::for_interface("home");
        assert_eq!(a, Numbering::for_interface("home"));
        assert!(a.slot() < SLOTS);
        assert_eq!(a.mark() & MARK_MASK, MARK_BASE);
        assert_eq!(a.mark() & !MARK_MASK, u32::from(a.slot()));
        assert_eq!(a.table(), 30_000 + u32::from(a.slot()));
        let names = ["home", "work", "lab", "aion", "vv0", "vv1", "a", "b"];
        let slots: Vec<u16> = names
            .iter()
            .map(|n| Numbering::for_interface(n).slot())
            .collect();
        let mut distinct = slots.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), slots.len(), "{slots:?}");
    }

    #[test]
    fn two_slots_share_no_priority_table_or_mark() {
        let a = Numbering::from_slot(0).unwrap();
        let b = Numbering::from_slot(1).unwrap();
        assert!(a.priorities().end <= b.priorities().start);
        assert_ne!(a.table(), b.table());
        assert_ne!(a.mark(), b.mark());
        assert_eq!(a.mark() & MARK_MASK, b.mark() & MARK_MASK);
        let last = Numbering::from_slot(SLOTS - 1).unwrap();
        assert!(
            last.priorities().end < 32_766,
            "below the main table's rule"
        );
        assert!(Numbering::from_slot(SLOTS).is_none());
    }

    #[test]
    fn the_rules_come_in_the_order_the_exit_needs() {
        let n = Numbering::from_slot(7).unwrap();
        let private: Vec<u32> = (0..4).map(|i| n.private_priority(i)).collect();
        assert!(private.windows(2).all(|w| w[0] < w[1]));
        assert!(private[3] < n.suppress_priority());
        assert!(n.suppress_priority() < n.table_priority());
        assert!(n.priorities().contains(&n.table_priority()));
        assert!(!n.priorities().contains(&n.priorities().end));
    }

    #[test]
    fn nft_tables_are_per_device_and_safe() {
        let t = Numbering::nft_tables("vv-home.1");
        assert_eq!(t[0], ("inet", "vv_vv_home_1".to_owned()));
        assert_eq!(t[1].1, "vv_vv_home_1_nat6");
        assert_eq!(t[2], ("ip", "vv_vv_home_1_nat4".to_owned()));
    }
}
