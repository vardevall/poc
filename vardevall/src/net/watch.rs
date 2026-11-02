//! Detection of local changes by polling the addresses of the host's interfaces (vv-05 §4.6),
//! for platforms and embedders without a notification of their own.
//!
//! A change is an address that appeared or went away, or an interface that went up or down. Such
//! a change is reported as the address families it touches, to be settled with others
//! (`CHANGE_SETTLE`) by the engine. The overlay's own addresses, loopback, IPv6 link-local
//! addresses and the point-to-point interfaces macOS keeps for itself do not count.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::time::{Interval, MissedTickBehavior, interval};
use vardevall_proto::route::Families;

/// How often the interfaces are read.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Interface name prefixes that never carry traffic to a peer.
const IGNORED: &[&str] = &["awdl", "llw", "anpi"];

/// One address of an interface, and whether the interface is up.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Entry {
    /// The interface name.
    pub name: String,
    /// The address.
    pub ip: IpAddr,
    /// Whether the interface is operational.
    pub up: bool,
}

type Source = Box<dyn FnMut() -> BTreeSet<Entry> + Send>;

/// Polls the interfaces and reports what changed.
pub(crate) struct NetworkWatch {
    known: Option<BTreeSet<Entry>>,
    source: Source,
    tick: Interval,
}

fn in_overlay(ip: &IpAddr, prefix: &[u8; 8]) -> bool {
    matches!(ip, IpAddr::V6(a) if a.octets()[..8] == prefix[..])
}

fn is_link_local_v6(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80)
}

/// The addresses of the host that matter for reaching peers, outside the overlay prefix.
fn read(overlay: [u8; 8], exclude: &[String]) -> BTreeSet<Entry> {
    let Ok(all) = if_addrs::get_if_addrs() else {
        return BTreeSet::new();
    };
    all.into_iter()
        .filter(|i| {
            !i.is_loopback()
                && !IGNORED.iter().any(|p| i.name.starts_with(p))
                && !exclude.contains(&i.name)
        })
        .map(|i| Entry {
            up: !matches!(
                i.oper_status,
                if_addrs::IfOperStatus::Down
                    | if_addrs::IfOperStatus::NotPresent
                    | if_addrs::IfOperStatus::LowerLayerDown
            ),
            ip: i.ip(),
            name: i.name,
        })
        .filter(|e| !is_link_local_v6(&e.ip) && !in_overlay(&e.ip, &overlay))
        .collect()
}

/// The address families in which `old` and `new` differ.
pub(crate) fn changed(old: &BTreeSet<Entry>, new: &BTreeSet<Entry>) -> Families {
    old.symmetric_difference(new)
        .fold(Families::NONE, |acc, e| {
            acc.union(if e.ip.is_ipv4() {
                Families::V4
            } else {
                Families::V6
            })
        })
}

impl NetworkWatch {
    /// A watch on the host's interfaces, leaving out the overlay's `/64` and the interfaces named
    /// in `exclude`, such as the tunnel's own device, whose addresses a host tool changes when an
    /// exit goes in or out of use. Must be created inside a tokio runtime.
    pub(crate) fn new(overlay_prefix: [u8; 8], exclude: Vec<String>) -> Self {
        Self::with_source(
            Box::new(move || read(overlay_prefix, &exclude)),
            POLL_INTERVAL,
        )
    }

    /// A watch on addresses read by `source`, every `period`.
    pub(crate) fn with_source(source: Source, period: Duration) -> Self {
        let mut tick = interval(period);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        NetworkWatch {
            known: None,
            source,
            tick,
        }
    }

    /// Polls for the next change; the first reading is the baseline and reports nothing.
    pub(crate) fn poll_change(&mut self, cx: &mut Context<'_>) -> Poll<Families> {
        loop {
            std::task::ready!(self.tick.poll_tick(cx));
            let now = (self.source)();
            let Some(before) = self.known.replace(now.clone()) else {
                continue;
            };
            let families = changed(&before, &now);
            if !families.is_empty() {
                return Poll::Ready(families);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::sync::{Arc, Mutex};

    use super::*;

    async fn next(watch: &mut NetworkWatch) -> Families {
        poll_fn(|cx| watch.poll_change(cx)).await
    }

    fn entry(name: &str, ip: &str, up: bool) -> Entry {
        Entry {
            name: name.to_owned(),
            ip: ip.parse().unwrap(),
            up,
        }
    }

    #[test]
    fn families_follow_the_addresses_that_differ() {
        let a: BTreeSet<Entry> = [entry("en0", "192.0.2.1", true)].into();
        let b: BTreeSet<Entry> = [
            entry("en0", "192.0.2.1", true),
            entry("en0", "2001:db8::1", true),
        ]
        .into();
        assert_eq!(changed(&a, &a), Families::NONE);
        assert_eq!(changed(&a, &b), Families::V6);
        let down: BTreeSet<Entry> = [entry("en0", "192.0.2.1", false)].into();
        assert_eq!(changed(&a, &down), Families::V4);
        assert_eq!(changed(&a, &BTreeSet::new()), Families::V4);
    }

    #[test]
    fn an_excluded_interface_does_not_count() {
        let names: Vec<String> = if_addrs::get_if_addrs()
            .unwrap()
            .into_iter()
            .map(|i| i.name)
            .collect();
        assert!(read([0; 8], &names).is_empty());
    }

    #[test]
    fn the_overlay_and_link_local_addresses_do_not_count() {
        let prefix = [0xfd, 0x91, 0, 0, 0, 0, 0, 1];
        assert!(in_overlay(&"fd91::1:0:0:0:5".parse().unwrap(), &prefix));
        assert!(!in_overlay(&"fd91::2:0:0:0:5".parse().unwrap(), &prefix));
        assert!(is_link_local_v6(&"fe80::1".parse().unwrap()));
        assert!(!is_link_local_v6(&"fec0::1".parse().unwrap()));
        assert!(!is_link_local_v6(&"169.254.1.1".parse().unwrap()));
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_between_two_readings_is_reported_once() {
        let state: Arc<Mutex<BTreeSet<Entry>>> =
            Arc::new(Mutex::new([entry("en0", "192.0.2.1", true)].into()));
        let shared = state.clone();
        let mut watch = NetworkWatch::with_source(
            Box::new(move || shared.lock().unwrap().clone()),
            Duration::from_secs(1),
        );
        let quiet = tokio::time::timeout(Duration::from_secs(5), next(&mut watch)).await;
        assert!(quiet.is_err(), "nothing changed");
        state
            .lock()
            .unwrap()
            .insert(entry("en1", "2001:db8::7", true));
        let got = tokio::time::timeout(Duration::from_secs(5), next(&mut watch))
            .await
            .unwrap();
        assert_eq!(got, Families::V6);
        let again = tokio::time::timeout(Duration::from_secs(5), next(&mut watch)).await;
        assert!(again.is_err(), "the new state is the baseline");
    }
}
