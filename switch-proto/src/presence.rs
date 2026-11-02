//! A client's view of member presence on one switch (vv-04 §7.4).

use std::collections::HashMap;

use crate::api::{MembersPage, SwitchEvent};
use vardevall_proto::keys::NodePublic;

/// Most members kept only for their high-water mark, which are not in the online set.
pub const MAX_OFFLINE_MARKS: usize = 4096;

/// What the client knows of one member: whether it is in the online set, and the high-water mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    online: bool,
    generation: u64,
    seen_offline: bool,
    last_event: u64,
    touched: u64,
}

/// Identifies the moment a list request was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListToken {
    epoch: u64,
    events: u64,
}

/// Presence of the other members of the network on one switch.
///
/// Holds the online set and, for each member seen, a high-water mark: the greatest `gen` seen and
/// whether it came in an `offline` event. Leaving the set because a listing omits a member does
/// not change its mark.
#[derive(Debug, Default)]
pub struct Presence {
    members: HashMap<NodePublic, State>,
    epoch: u64,
    events: u64,
    clock: u64,
}

impl Presence {
    /// An empty view.
    pub fn new() -> Self {
        Self::default()
    }

    /// Notes a new registration: the online set is emptied, high-water marks are kept because
    /// `gen` keeps increasing across registrations (vv-04 §4.4), and earlier list requests are
    /// discarded.
    pub fn on_registered(&mut self) {
        self.epoch += 1;
        for s in self.members.values_mut() {
            s.online = false;
        }
        self.prune();
    }

    /// Notes that the events stream was (re)opened; the caller then lists members.
    pub fn on_stream_opened(&mut self) {
        self.epoch += 1;
    }

    /// Marks a list request as sent now.
    pub fn begin_list(&self) -> ListToken {
        ListToken {
            epoch: self.epoch,
            events: self.events,
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn apply(&mut self, node: NodePublic, online: bool, generation: u64, from_event: bool) {
        let touched = self.tick();
        let event = if from_event {
            self.events += 1;
            self.events
        } else {
            0
        };
        match self.members.get_mut(&node) {
            None => {
                self.members.insert(
                    node,
                    State {
                        online,
                        generation,
                        seen_offline: !online,
                        last_event: event,
                        touched,
                    },
                );
            }
            Some(s) => {
                let accepted = if online {
                    generation > s.generation || (generation == s.generation && !s.seen_offline)
                } else {
                    generation >= s.generation
                };
                if accepted {
                    s.online = online;
                    s.seen_offline = !online;
                    s.last_event = s.last_event.max(event);
                }
                s.generation = s.generation.max(generation);
                s.touched = touched;
            }
        }
        self.prune();
    }

    fn prune(&mut self) {
        if self.members.len() <= MAX_OFFLINE_MARKS {
            return;
        }
        let offline = self.members.values().filter(|s| !s.online).count();
        if offline <= MAX_OFFLINE_MARKS {
            return;
        }
        let mut marks: Vec<(u64, NodePublic)> = self
            .members
            .iter()
            .filter(|(_, s)| !s.online)
            .map(|(k, s)| (s.touched, *k))
            .collect();
        marks.sort_unstable();
        for (_, key) in marks.into_iter().take(offline - MAX_OFFLINE_MARKS) {
            self.members.remove(&key);
        }
    }

    /// Applies an `online` or `offline` event; other events are ignored.
    pub fn on_event(&mut self, event: &SwitchEvent) {
        match event {
            SwitchEvent::Online { node, generation } => self.apply(*node, true, *generation, true),
            SwitchEvent::Offline { node, generation } => {
                self.apply(*node, false, *generation, true)
            }
            SwitchEvent::Forward { .. } | SwitchEvent::Replaced => {}
        }
    }

    /// Applies one page of a listing requested with cursor `after`; returns whether it was used.
    pub fn on_list_page(
        &mut self,
        token: ListToken,
        after: Option<&NodePublic>,
        page: &MembersPage,
    ) -> bool {
        if token.epoch != self.epoch {
            return false;
        }
        for m in &page.members {
            self.apply(m.node, true, m.generation, false);
        }
        let last = if page.truncated {
            page.members.last().map(|m| m.node)
        } else {
            None
        };
        let listed: std::collections::HashSet<NodePublic> =
            page.members.iter().map(|m| m.node).collect();
        for (node, state) in &mut self.members {
            let in_range = after.is_none_or(|a| node > a) && last.is_none_or(|l| *node <= l);
            if in_range && !listed.contains(node) && state.last_event <= token.events {
                state.online = false;
            }
        }
        self.prune();
        true
    }

    /// Whether `node` is currently believed online.
    pub fn is_online(&self, node: &NodePublic) -> bool {
        self.members.get(node).is_some_and(|s| s.online)
    }

    /// The members believed online.
    pub fn online(&self) -> impl Iterator<Item = &NodePublic> {
        self.members
            .iter()
            .filter(|(_, s)| s.online)
            .map(|(k, _)| k)
    }

    /// The high-water mark of `node`: the greatest `gen` seen and whether it was seen in an
    /// `offline` event.
    pub fn high_water_mark(&self, node: &NodePublic) -> Option<(u64, bool)> {
        self.members
            .get(node)
            .map(|s| (s.generation, s.seen_offline))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::MemberEntry;

    fn key(n: u8) -> NodePublic {
        NodePublic::from_bytes([n; 32])
    }

    fn page(entries: &[(u8, u64)], truncated: bool) -> MembersPage {
        MembersPage {
            members: entries
                .iter()
                .map(|(n, generation)| MemberEntry {
                    node: key(*n),
                    online_since: 0,
                    generation: *generation,
                })
                .collect(),
            truncated,
        }
    }

    #[test]
    fn a_stale_list_does_not_override_a_newer_offline_event() {
        let mut p = Presence::new();
        p.on_stream_opened();
        let token = p.begin_list();
        p.on_event(&SwitchEvent::Online {
            node: key(1),
            generation: 3,
        });
        p.on_event(&SwitchEvent::Offline {
            node: key(1),
            generation: 3,
        });
        p.on_list_page(token, None, &page(&[(1, 3)], false));
        assert!(!p.is_online(&key(1)), "equal generation: offline wins");
    }

    #[test]
    fn absent_members_go_offline_unless_an_event_set_them() {
        let mut p = Presence::new();
        p.on_stream_opened();
        let token = p.begin_list();
        p.on_list_page(token, None, &page(&[(1, 1), (2, 1)], false));
        assert!(p.is_online(&key(1)) && p.is_online(&key(2)));
        p.on_stream_opened();
        let token = p.begin_list();
        p.on_event(&SwitchEvent::Online {
            node: key(3),
            generation: 1,
        });
        p.on_list_page(token, None, &page(&[(1, 1)], false));
        assert!(p.is_online(&key(1)));
        assert!(!p.is_online(&key(2)));
        assert!(
            p.is_online(&key(3)),
            "set by an event on the current stream"
        );
    }

    #[test]
    fn a_response_to_a_request_before_the_stream_reopened_is_discarded() {
        let mut p = Presence::new();
        p.on_stream_opened();
        let token = p.begin_list();
        p.on_event(&SwitchEvent::Online {
            node: key(1),
            generation: 1,
        });
        p.on_stream_opened();
        assert!(!p.on_list_page(token, None, &page(&[], false)));
        assert!(p.is_online(&key(1)));
    }

    #[test]
    fn pages_only_judge_the_range_they_cover() {
        let mut p = Presence::new();
        p.on_stream_opened();
        let t = p.begin_list();
        p.on_list_page(t, None, &page(&[(1, 1), (5, 1), (9, 1)], false));
        p.on_stream_opened();
        let t = p.begin_list();
        p.on_list_page(t, None, &page(&[(1, 1)], true));
        assert!(
            p.is_online(&key(5)) && p.is_online(&key(9)),
            "beyond the first page"
        );
        let t = p.begin_list();
        p.on_list_page(t, Some(&key(1)), &page(&[(9, 1)], false));
        assert!(!p.is_online(&key(5)));
        assert!(p.is_online(&key(9)));
    }

    #[test]
    fn registering_again_empties_the_set_but_keeps_the_marks() {
        let mut p = Presence::new();
        p.on_event(&SwitchEvent::Online {
            node: key(1),
            generation: 7,
        });
        p.on_registered();
        assert_eq!(p.online().count(), 0);
        p.on_event(&SwitchEvent::Online {
            node: key(1),
            generation: 1,
        });
        assert!(!p.is_online(&key(1)), "below the high-water mark");
        p.on_event(&SwitchEvent::Online {
            node: key(1),
            generation: 8,
        });
        assert!(p.is_online(&key(1)));
    }

    #[test]
    fn absence_leaves_the_mark_and_the_same_gen_puts_the_member_back() {
        let mut p = Presence::new();
        p.on_stream_opened();
        let t = p.begin_list();
        p.on_list_page(t, None, &page(&[(1, 5)], false));
        let t = p.begin_list();
        p.on_list_page(t, None, &page(&[], false));
        assert!(!p.is_online(&key(1)));
        assert_eq!(p.high_water_mark(&key(1)), Some((5, false)));
        let t = p.begin_list();
        p.on_list_page(t, None, &page(&[(1, 5)], false));
        assert!(p.is_online(&key(1)), "same gen, never seen offline");
        p.on_event(&SwitchEvent::Online {
            node: key(1),
            generation: 5,
        });
        assert!(p.is_online(&key(1)));
    }

    #[test]
    fn an_offline_event_fixes_its_gen_against_online_at_the_same_gen() {
        let mut p = Presence::new();
        p.on_event(&SwitchEvent::Online {
            node: key(1),
            generation: 5,
        });
        p.on_event(&SwitchEvent::Offline {
            node: key(1),
            generation: 4,
        });
        assert!(p.is_online(&key(1)), "an older offline is ignored");
        p.on_event(&SwitchEvent::Offline {
            node: key(1),
            generation: 5,
        });
        assert_eq!(p.high_water_mark(&key(1)), Some((5, true)));
        p.on_event(&SwitchEvent::Online {
            node: key(1),
            generation: 5,
        });
        assert!(!p.is_online(&key(1)));
        p.on_event(&SwitchEvent::Online {
            node: key(1),
            generation: 6,
        });
        assert!(p.is_online(&key(1)));
        assert_eq!(p.high_water_mark(&key(1)), Some((6, false)));
    }

    #[test]
    fn an_event_before_the_list_request_does_not_shield_a_member_from_absence() {
        let mut p = Presence::new();
        p.on_stream_opened();
        p.on_event(&SwitchEvent::Online {
            node: key(1),
            generation: 1,
        });
        let t = p.begin_list();
        p.on_list_page(t, None, &page(&[], false));
        assert!(!p.is_online(&key(1)));
    }

    #[test]
    fn marks_of_absent_members_are_bounded_and_the_oldest_go_first() {
        let mut p = Presence::new();
        let id = |n: usize| {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(n as u64).to_le_bytes());
            NodePublic::from_bytes(k)
        };
        p.on_event(&SwitchEvent::Online {
            node: id(1_000_000),
            generation: 9,
        });
        for n in 0..MAX_OFFLINE_MARKS + 10 {
            p.on_event(&SwitchEvent::Offline {
                node: id(n),
                generation: 1,
            });
        }
        assert!(p.is_online(&id(1_000_000)), "members in the set are kept");
        assert_eq!(p.high_water_mark(&id(0)), None);
        assert_eq!(p.high_water_mark(&id(9)), None);
        assert!(p.high_water_mark(&id(10)).is_some());
        assert!(p.high_water_mark(&id(MAX_OFFLINE_MARKS + 9)).is_some());
        assert_eq!(p.members.len(), MAX_OFFLINE_MARKS + 1);
    }
}
