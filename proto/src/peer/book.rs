//! The candidates the caller's sources found for one peer, per source group: ranked for direct
//! attempts (vv-05 §2.1, §4.1) and listed in the order they were found for routes.

use crate::discovery::candidate::Candidate;

/// Most candidates a direct attempt uses (vv-05 §4.1).
pub const MAX_TARGETS: usize = 4;
const MAX_PER_PEER: usize = 32;

/// One group of candidates of one source: the configured endpoints, one mDNS service
/// instance (vv-09 §2.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Group {
    /// The source, for logs.
    pub source: &'static str,
    /// The group inside the source; empty for a source with one group.
    pub name: String,
}

/// The complete set of candidates of one group; an empty one withdraws the group.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    /// The routes the group offers.
    pub offered: Vec<Candidate>,
    /// Addresses held back as fallbacks: a direct handshake attempt tries them, a route is made
    /// of one when an offered route fails (vv-09 §2.3).
    pub spare: Vec<Candidate>,
}

impl Found {
    fn len(&self) -> usize {
        self.offered.len() + self.spare.len()
    }

    fn is_empty(&self) -> bool {
        self.offered.is_empty() && self.spare.is_empty()
    }
}

/// Candidates per source group, the groups in the order they first appeared.
#[derive(Default)]
pub(crate) struct Book {
    groups: Vec<(Group, Found)>,
}

impl Book {
    /// Replaces one group, which keeps its place in the order; returns whether anything changed.
    pub(crate) fn apply(&mut self, group: Group, found: Found) -> bool {
        let at = self.groups.iter().position(|(g, _)| *g == group);
        if found.is_empty() {
            return at.is_some_and(|i| {
                self.groups.remove(i);
                true
            });
        }
        let total: usize = self
            .groups
            .iter()
            .filter(|(g, _)| *g != group)
            .map(|(_, v)| v.len())
            .sum();
        let room = MAX_PER_PEER.saturating_sub(total);
        let offered: Vec<Candidate> = found.offered.iter().take(room).copied().collect();
        let spare: Vec<Candidate> = found
            .spare
            .iter()
            .take(room - offered.len())
            .copied()
            .collect();
        let new = Found { offered, spare };
        match at {
            Some(i) if self.groups[i].1 == new => false,
            Some(i) => {
                self.groups[i].1 = new;
                true
            }
            None => {
                self.groups.push((group, new));
                true
            }
        }
    }

    /// The best addresses for a direct attempt, spare ones included: local ones first, IPv6
    /// before IPv4, otherwise in the order the sources found them.
    pub(crate) fn targets(&self) -> Vec<Candidate> {
        let mut all: Vec<Candidate> = self
            .groups
            .iter()
            .flat_map(|(_, g)| g.offered.iter().chain(&g.spare))
            .copied()
            .collect();
        all.sort_by_key(|c| (!c.local, c.addr.is_ipv4()));
        let mut out: Vec<Candidate> = Vec::new();
        for c in all {
            if !out.iter().any(|o| o.addr == c.addr) {
                out.push(c);
            }
            if out.len() == MAX_TARGETS {
                break;
            }
        }
        out
    }

    /// Every offered candidate in the order the sources found them (the groups in the order they
    /// first appeared, each group's own order), without duplicate addresses.
    pub(crate) fn candidates(&self) -> Vec<Candidate> {
        let mut out: Vec<Candidate> = Vec::new();
        for c in self.groups.iter().flat_map(|(_, g)| g.offered.iter()) {
            if !out.iter().any(|o| o.addr == c.addr) {
                out.push(*c);
            }
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn cand(make: fn(SocketAddr) -> Candidate, addr: &str) -> Candidate {
        make(addr.parse().unwrap())
    }

    fn group(source: &'static str, name: &str) -> Group {
        Group {
            source,
            name: name.to_owned(),
        }
    }

    fn offered(offered: Vec<Candidate>) -> Found {
        Found {
            offered,
            spare: Vec::new(),
        }
    }

    fn addrs(list: &[Candidate]) -> Vec<SocketAddr> {
        list.iter().map(|c| c.addr).collect()
    }

    #[test]
    fn ranks_local_first_then_family_then_the_order_found() {
        let mut b = Book::default();
        b.apply(
            group("static", ""),
            offered(vec![cand(Candidate::static_, "203.0.113.7:1")]),
        );
        b.apply(
            group("mdns", "a"),
            offered(vec![
                cand(Candidate::lan, "192.168.1.5:2"),
                cand(Candidate::lan, "[2001:db8::5]:2"),
                cand(Candidate::same_host, "127.0.0.1:3"),
            ]),
        );
        assert_eq!(
            addrs(&b.targets()),
            vec![
                "[2001:db8::5]:2".parse().unwrap(),
                "192.168.1.5:2".parse().unwrap(),
                "127.0.0.1:3".parse().unwrap(),
                "203.0.113.7:1".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn candidates_keep_the_order_the_sources_found_them() {
        let mut b = Book::default();
        b.apply(
            group("mdns", "a"),
            offered(vec![
                cand(Candidate::punch, "203.0.113.9:9"),
                cand(Candidate::lan, "192.168.1.5:2"),
            ]),
        );
        b.apply(
            group("static", ""),
            offered(vec![
                cand(Candidate::static_, "198.51.100.1:1"),
                cand(Candidate::lan, "192.168.1.5:2"),
            ]),
        );
        let addrs = |b: &Book| -> Vec<String> {
            b.candidates().iter().map(|c| c.addr.to_string()).collect()
        };
        let order = ["203.0.113.9:9", "192.168.1.5:2", "198.51.100.1:1"];
        assert_eq!(addrs(&b), order);
        b.apply(
            group("mdns", "a"),
            offered(vec![
                cand(Candidate::lan, "192.168.1.5:2"),
                cand(Candidate::punch, "203.0.113.9:9"),
            ]),
        );
        assert_eq!(
            addrs(&b),
            ["192.168.1.5:2", "203.0.113.9:9", "198.51.100.1:1"],
            "a group keeps its place when it is replaced"
        );
    }

    #[test]
    fn empty_found_removes_group() {
        let mut b = Book::default();
        let c = vec![cand(Candidate::lan, "192.168.1.5:2")];
        assert!(b.apply(group("mdns", "a"), offered(c.clone())));
        assert!(!b.apply(group("mdns", "a"), offered(c)));
        assert!(b.apply(group("mdns", "a"), Found::default()));
        assert!(b.is_empty());
    }

    #[test]
    fn spare_addresses_are_targets_of_a_handshake_but_not_offered() {
        let mut b = Book::default();
        let mut f = offered(vec![cand(Candidate::lan, "[fd00::5]:2")]);
        f.spare = vec![cand(Candidate::lan, "192.168.1.5:2")];
        assert!(b.apply(group("mdns", "a"), f.clone()));
        assert_eq!(b.candidates().len(), 1);
        assert_eq!(b.targets().len(), 2);
        f.spare.clear();
        assert!(b.apply(group("mdns", "a"), f));
        assert_eq!(b.targets().len(), 1);
    }

    #[test]
    fn at_most_four_targets() {
        let mut b = Book::default();
        let c: Vec<Candidate> = (1..=8)
            .map(|i| cand(Candidate::lan, &format!("192.168.1.{i}:2")))
            .collect();
        b.apply(group("mdns", "a"), offered(c));
        assert_eq!(b.targets().len(), MAX_TARGETS);
    }
}
