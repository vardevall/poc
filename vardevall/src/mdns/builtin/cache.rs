//! Browse results with expiry: instances learnt from announcements and answers (vv-09 §2.2).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use tokio::time::Instant;

use super::wire::Parsed;
use crate::mdns::{Found, MdnsEvent};

/// Most instances kept.
const MAX_ENTRIES: usize = 256;

#[derive(Default)]
struct Entry {
    target: Option<String>,
    port: Option<u16>,
    txt: Option<Vec<(String, String)>>,
    /// The addresses of the instance. An address awaiting re-confirmation carries the instant
    /// by which an answer must repeat it.
    addrs: HashMap<IpAddr, Option<Instant>>,
    expires: Option<Instant>,
    emitted: Option<Found>,
}

/// Instances seen on the link.
#[derive(Default)]
pub(super) struct Cache {
    entries: HashMap<String, Entry>,
}

fn deadline(now: Instant, ttl: u32) -> Instant {
    now + Duration::from_secs(u64::from(ttl))
}

impl Cache {
    /// An empty cache.
    pub(super) fn new() -> Self {
        Self::default()
    }

    fn entry(&mut self, instance: &str) -> Option<&mut Entry> {
        if !self.entries.contains_key(instance) && self.entries.len() >= MAX_ENTRIES {
            return None;
        }
        Some(self.entries.entry(instance.to_owned()).or_default())
    }

    /// Merges the records of one message; returns the resulting events. An address the message
    /// repeats is confirmed.
    pub(super) fn ingest(
        &mut self,
        parsed: &Parsed,
        now: Instant,
        ignore: Option<&str>,
    ) -> Vec<MdnsEvent> {
        let mut events = Vec::new();
        let mut touched: Vec<String> = Vec::new();
        let skip = |i: &str| ignore == Some(i);
        for (instance, ttl) in &parsed.ptrs {
            if skip(instance) {
                continue;
            }
            if *ttl == 0 {
                if let Some(e) = self.entries.remove(instance)
                    && e.emitted.is_some()
                {
                    events.push(MdnsEvent::Lost {
                        instance: instance.clone(),
                    });
                }
                continue;
            }
            if let Some(e) = self.entry(instance) {
                e.expires = Some(deadline(now, *ttl));
                touched.push(instance.clone());
            }
        }
        for (instance, target, port, ttl) in &parsed.srvs {
            if skip(instance) || *ttl == 0 {
                continue;
            }
            if let Some(e) = self.entry(instance) {
                e.target = Some(target.clone());
                e.port = Some(*port);
                e.expires = Some(deadline(now, *ttl));
                touched.push(instance.clone());
            }
        }
        for (instance, txt, ttl) in &parsed.txts {
            if skip(instance) || *ttl == 0 {
                continue;
            }
            if let Some(e) = self.entry(instance) {
                e.txt = Some(txt.clone());
                touched.push(instance.clone());
            }
        }
        for (host, ip, ttl) in &parsed.addrs {
            for (instance, e) in &mut self.entries {
                if e.target.as_deref() == Some(host.as_str()) {
                    if *ttl == 0 {
                        e.addrs.remove(ip);
                    } else if e.addrs.len() < 16 || e.addrs.contains_key(ip) {
                        e.addrs.insert(*ip, None);
                    }
                    touched.push(instance.clone());
                }
            }
        }
        touched.sort();
        touched.dedup();
        for instance in touched {
            if let Some(ev) = self.complete(&instance) {
                events.push(ev);
            }
        }
        events
    }

    fn complete(&mut self, instance: &str) -> Option<MdnsEvent> {
        let e = self.entries.get_mut(instance)?;
        let (port, txt) = (e.port?, e.txt.clone()?);
        if e.addrs.is_empty() {
            return None;
        }
        let mut addrs: Vec<IpAddr> = e.addrs.keys().copied().collect();
        addrs.sort();
        let found = Found {
            instance: instance.to_owned(),
            txt,
            port,
            addrs,
            ifindex: 0,
        };
        if e.emitted.as_ref() == Some(&found) {
            return None;
        }
        e.emitted = Some(found.clone());
        Some(MdnsEvent::Found(found))
    }

    /// Removes instances whose records expired, and the addresses that were not re-confirmed by
    /// their deadline. An instance left without addresses is lost like one whose records
    /// expired; one with some left is reported again with them.
    pub(super) fn expire(&mut self, now: Instant) -> Vec<MdnsEvent> {
        let gone: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.expires.is_some_and(|t| t <= now))
            .map(|(k, _)| k.clone())
            .collect();
        let mut events = Vec::new();
        for g in gone {
            if let Some(e) = self.entries.remove(&g)
                && e.emitted.is_some()
            {
                events.push(MdnsEvent::Lost { instance: g });
            }
        }
        let mut touched: Vec<String> = Vec::new();
        for (instance, e) in &mut self.entries {
            let before = e.addrs.len();
            e.addrs.retain(|_, by| by.is_none_or(|t| t > now));
            if e.addrs.len() != before {
                touched.push(instance.clone());
            }
        }
        touched.sort();
        for instance in touched {
            let emptied = self
                .entries
                .get(&instance)
                .is_some_and(|e| e.addrs.is_empty());
            if emptied {
                if let Some(e) = self.entries.remove(&instance)
                    && e.emitted.is_some()
                {
                    events.push(MdnsEvent::Lost { instance });
                }
            } else if let Some(ev) = self.complete(&instance) {
                events.push(ev);
            }
        }
        events
    }

    /// Marks every address as awaiting re-confirmation until `by`; a message that repeats it
    /// before then confirms it.
    pub(super) fn unconfirm(&mut self, by: Instant) {
        for e in self.entries.values_mut() {
            for pending in e.addrs.values_mut() {
                *pending = Some(by);
            }
        }
    }

    /// When the next record expires or the next re-confirmation falls due.
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.entries
            .values()
            .flat_map(|e| {
                e.expires
                    .into_iter()
                    .chain(e.addrs.values().flatten().copied())
            })
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mdns::builtin::wire::{self, Registration};

    fn reg(instance: &str) -> Registration {
        Registration {
            instance: instance.into(),
            port: 4242,
            txt: vec![("v".into(), "0".into())],
        }
    }

    fn parsed(instance: &str, ttl: u32) -> Parsed {
        let addrs = ["10.0.0.7".parse().unwrap()];
        wire::parse(&wire::build_announcement(&reg(instance), &addrs, ttl).unwrap()).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn found_once_then_lost_on_goodbye() {
        let mut c = Cache::new();
        let now = Instant::now();
        let ev = c.ingest(&parsed("aaaa", 120), now, None);
        assert_eq!(ev.len(), 1);
        let MdnsEvent::Found(f) = &ev[0] else {
            panic!()
        };
        assert_eq!(f.port, 4242);
        assert_eq!(f.addrs, vec!["10.0.0.7".parse::<IpAddr>().unwrap()]);
        assert!(c.ingest(&parsed("aaaa", 120), now, None).is_empty());
        let ev = c.ingest(&parsed("aaaa", 0), now, None);
        assert_eq!(
            ev,
            vec![MdnsEvent::Lost {
                instance: "aaaa".into()
            }]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn expires_after_ttl_and_renews() {
        let mut c = Cache::new();
        let t0 = Instant::now();
        c.ingest(&parsed("aaaa", 120), t0, None);
        c.ingest(&parsed("aaaa", 120), t0 + Duration::from_secs(60), None);
        assert!(c.expire(t0 + Duration::from_secs(150)).is_empty());
        assert_eq!(c.next_deadline(), Some(t0 + Duration::from_secs(180)));
        let ev = c.expire(t0 + Duration::from_secs(181));
        assert_eq!(
            ev,
            vec![MdnsEvent::Lost {
                instance: "aaaa".into()
            }]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ignores_own_instance() {
        let mut c = Cache::new();
        let ev = c.ingest(&parsed("mine", 120), Instant::now(), Some("mine"));
        assert!(ev.is_empty());
    }

    fn parsed_at(instance: &str, addr: &str) -> Parsed {
        let addrs = [addr.parse().unwrap()];
        wire::parse(&wire::build_announcement(&reg(instance), &addrs, 120).unwrap()).unwrap()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[tokio::test(start_paused = true)]
    async fn a_repeated_address_is_confirmed_silently() {
        let mut c = Cache::new();
        let t0 = Instant::now();
        c.ingest(&parsed_at("aaaa", "10.0.0.7"), t0, None);
        c.unconfirm(t0 + secs(4));
        assert_eq!(c.next_deadline(), Some(t0 + secs(4)));
        assert!(
            c.ingest(&parsed_at("aaaa", "10.0.0.7"), t0 + secs(1), None)
                .is_empty()
        );
        assert!(c.expire(t0 + secs(5)).is_empty());
        assert_eq!(c.next_deadline(), Some(t0 + secs(121)));
    }

    #[tokio::test(start_paused = true)]
    async fn an_unconfirmed_address_is_dropped_at_its_deadline() {
        let mut c = Cache::new();
        let t0 = Instant::now();
        c.ingest(&parsed_at("aaaa", "10.0.0.7"), t0, None);
        c.unconfirm(t0 + secs(4));
        assert!(c.expire(t0 + secs(3)).is_empty());
        assert_eq!(
            c.expire(t0 + secs(4)),
            vec![MdnsEvent::Lost {
                instance: "aaaa".into()
            }]
        );
        assert_eq!(c.next_deadline(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn an_instance_keeps_the_addresses_that_answered() {
        let mut c = Cache::new();
        let t0 = Instant::now();
        c.ingest(&parsed_at("aaaa", "10.0.0.7"), t0, None);
        c.ingest(&parsed_at("aaaa", "172.16.0.7"), t0, None);
        c.unconfirm(t0 + secs(4));
        c.ingest(&parsed_at("aaaa", "172.16.0.7"), t0 + secs(1), None);
        let ev = c.expire(t0 + secs(4));
        let [MdnsEvent::Found(f)] = &ev[..] else {
            panic!("{ev:?}")
        };
        assert_eq!(f.addrs, vec!["172.16.0.7".parse::<IpAddr>().unwrap()]);
        assert!(c.expire(t0 + secs(5)).is_empty());
    }
}
