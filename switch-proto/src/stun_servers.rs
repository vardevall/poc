//! The STUN servers to ask and the credentials some of them need (vv-05 §3.1).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use vardevall_proto::time::Instant;

use crate::origin::Origin;
use crate::reflexive::{Auth, Server};

/// The servers of one origin.
#[derive(Debug, Default)]
struct Source {
    servers: Vec<SocketAddr>,
    /// Whether the servers answer only requests with a credential (vv-04 §4.7).
    required: bool,
    creds: Option<Auth>,
}

/// The STUN servers of each origin and the credentials of those that need one.
#[derive(Debug, Default)]
pub struct StunServers {
    sources: BTreeMap<Origin, Source>,
}

impl StunServers {
    /// Replaces the servers of `origin`; an empty list removes it. `required` says they answer
    /// only requests with a credential; servers that do not require one drop the credential.
    pub fn set(&mut self, origin: Origin, servers: Vec<SocketAddr>, required: bool) {
        if servers.is_empty() {
            self.sources.remove(&origin);
            return;
        }
        let source = self.sources.entry(origin).or_default();
        source.servers = servers;
        source.required = required;
        if !required {
            source.creds = None;
        }
    }

    /// Stores the credential of `origin`, valid for `ttl` from `now` (always, if `None`); ignored
    /// while the origin has no servers.
    pub fn set_credential(
        &mut self,
        now: Instant,
        origin: Origin,
        username: String,
        key: Vec<u8>,
        ttl: Option<Duration>,
    ) {
        if let Some(source) = self.sources.get_mut(&origin) {
            source.creds = Some(Auth {
                username,
                key,
                until: ttl.map(|t| now + t),
            });
        }
    }

    /// The servers to ask at `now`, each with its credential if it needs one: a server whose
    /// credential is missing or has run out is left out, since its silence says nothing about
    /// UDP (vv-04 §4.7). `reachable` says which addresses the interface socket can send to.
    /// Credentials that ran out are dropped.
    pub fn servers(&mut self, now: Instant, reachable: impl Fn(SocketAddr) -> bool) -> Vec<Server> {
        for source in self.sources.values_mut() {
            if source.creds.as_ref().is_some_and(|c| !c.current(now)) {
                source.creds = None;
            }
        }
        let mut out: Vec<Server> = Vec::new();
        for source in self.sources.values() {
            let auth = match (&source.creds, source.required) {
                (_, false) => None,
                (Some(c), true) => Some(c.clone()),
                (None, true) => continue,
            };
            for a in &source.servers {
                if reachable(*a) && !out.iter().any(|s| s.addr == *a) {
                    out.push(Server {
                        addr: *a,
                        auth: auth.clone(),
                    });
                }
            }
        }
        out
    }

    /// When the earliest credential in use runs out.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.sources
            .values()
            .filter(|s| s.required)
            .filter_map(|s| s.creds.as_ref()?.until)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::SwitchId;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn any(_: SocketAddr) -> bool {
        true
    }

    fn switch(i: u32) -> Origin {
        Origin::Switch(SwitchId(i))
    }

    #[test]
    fn a_server_that_needs_a_credential_waits_for_it() {
        let mut s = StunServers::default();
        let t0 = Instant::from_millis(0);
        s.set(switch(0), vec![addr("192.0.2.1:3478")], true);
        s.set(Origin::Config(0), vec![addr("192.0.2.2:3478")], false);
        let list = s.servers(t0, any);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].addr, addr("192.0.2.2:3478"));
        s.set_credential(t0, switch(0), "u".to_owned(), b"k".to_vec(), None);
        let list = s.servers(t0, any);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].auth.as_ref().unwrap().username, "u");
        assert!(list[1].auth.is_none());
    }

    #[test]
    fn an_expiring_credential_removes_the_servers_that_require_it() {
        let mut s = StunServers::default();
        let t0 = Instant::from_millis(1000);
        s.set(switch(0), vec![addr("192.0.2.1:3478")], true);
        s.set(Origin::Config(0), vec![addr("192.0.2.2:3478")], false);
        let ttl = Duration::from_secs(10);
        s.set_credential(t0, switch(0), "u".to_owned(), b"k".to_vec(), Some(ttl));
        let until = t0 + ttl;
        assert_eq!(s.next_expiry(), Some(until));
        assert_eq!(s.servers(t0 + Duration::from_secs(9), any).len(), 2);
        let list = s.servers(until, any);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].addr, addr("192.0.2.2:3478"));
        assert_eq!(s.next_expiry(), None);
    }

    #[test]
    fn a_renewed_credential_brings_the_servers_back() {
        let mut s = StunServers::default();
        let t0 = Instant::from_millis(0);
        let ttl = Some(Duration::from_secs(5));
        s.set(switch(0), vec![addr("192.0.2.1:3478")], true);
        s.set_credential(t0, switch(0), "u".to_owned(), b"k".to_vec(), ttl);
        let t1 = t0 + Duration::from_secs(6);
        assert!(s.servers(t1, any).is_empty());
        s.set_credential(t1, switch(0), "u2".to_owned(), b"k".to_vec(), ttl);
        assert_eq!(s.servers(t1, any).len(), 1);
    }

    #[test]
    fn a_list_replaces_the_old_one_and_an_empty_list_removes_the_origin() {
        let mut s = StunServers::default();
        let t0 = Instant::from_millis(0);
        s.set(switch(0), vec![addr("192.0.2.1:3478")], false);
        s.set(switch(0), vec![addr("192.0.2.3:3478")], false);
        assert_eq!(s.servers(t0, any)[0].addr, addr("192.0.2.3:3478"));
        s.set(switch(0), Vec::new(), false);
        assert!(s.servers(t0, any).is_empty());
    }

    #[test]
    fn unreachable_and_duplicate_addresses_are_left_out() {
        let mut s = StunServers::default();
        let t0 = Instant::from_millis(0);
        s.set(
            switch(0),
            vec![addr("[2001:db8::1]:3478"), addr("192.0.2.1:3478")],
            false,
        );
        s.set(Origin::Config(0), vec![addr("192.0.2.1:3478")], false);
        let list = s.servers(t0, |a| a.is_ipv4());
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].addr, addr("192.0.2.1:3478"));
    }

    #[test]
    fn servers_that_stop_requiring_a_credential_forget_it() {
        let mut s = StunServers::default();
        let t0 = Instant::from_millis(0);
        s.set(switch(0), vec![addr("192.0.2.1:3478")], true);
        s.set_credential(t0, switch(0), "u".to_owned(), b"k".to_vec(), None);
        s.set(switch(0), vec![addr("192.0.2.1:3478")], false);
        s.set(switch(0), vec![addr("192.0.2.1:3478")], true);
        assert!(s.servers(t0, any).is_empty());
    }
}
