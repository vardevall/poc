//! The `static` candidate source: `endpoint` entries of the configuration (vv-05 §2.1,
//! vv-07 §3.5).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::Instant;
use vardevall_proto::discovery::candidate::Candidate;
use vardevall_proto::keys::NodePublic;

use super::{CandidateSource, SourceKey, Update};
use crate::config::{Endpoint, PeerSpec};
use crate::net::mark::SocketMark;

/// Least time between two lookups of the same peer's names.
const RESOLVE_INTERVAL: Duration = Duration::from_secs(5);
/// Most SRV targets looked up for one name.
const MAX_SRV_TARGETS: usize = 4;

#[derive(PartialEq)]
struct Entry {
    /// Whether the candidates are `local`.
    local: bool,
    fixed: Vec<Candidate>,
    hosts: Vec<(String, u16)>,
    /// Names whose SRV records give the hosts and ports (vv-07 §3.5).
    services: Vec<String>,
}

/// Candidates from configured endpoints; DNS names are resolved at start, on a local address
/// change and when a handshake finds the previous addresses unusable (vv-07 §3.5).
pub(crate) struct StaticSource {
    entries: HashMap<NodePublic, Entry>,
    ready: VecDeque<Update>,
    resolving: JoinSet<(NodePublic, Vec<SocketAddr>)>,
    inflight: HashSet<NodePublic>,
    last: HashMap<NodePublic, Instant>,
    resolvers: Vec<SocketAddr>,
    mark: SocketMark,
}

fn candidate(addr: SocketAddr, local: bool) -> Candidate {
    if local {
        Candidate::static_local(addr)
    } else {
        Candidate::static_(addr)
    }
}

impl StaticSource {
    /// Builds the source for `peers` and starts the first lookups; `resolvers` are asked for SRV
    /// records, the system's if empty.
    ///
    /// Must be called inside a tokio runtime.
    pub(crate) fn new(peers: &[PeerSpec], resolvers: Vec<SocketAddr>, mark: SocketMark) -> Self {
        let mut s = StaticSource {
            entries: HashMap::new(),
            ready: VecDeque::new(),
            resolving: JoinSet::new(),
            inflight: HashSet::new(),
            last: HashMap::new(),
            resolvers,
            mark,
        };
        s.set_peers(peers);
        s
    }

    /// Brings the entries in line with `peers`: those of other peers go, a changed entry is
    /// replaced and its fixed candidates reported again, an unchanged one is left alone.
    pub(crate) fn set_peers(&mut self, peers: &[PeerSpec]) {
        self.entries
            .retain(|k, _| peers.iter().any(|p| p.public == *k));
        for p in peers {
            let mut fixed = Vec::new();
            let mut hosts = Vec::new();
            let mut services = Vec::new();
            for e in &p.endpoints {
                match e {
                    Endpoint::Addr(a) => fixed.push(candidate(*a, p.endpoints_local)),
                    Endpoint::Host { host, port } => hosts.push((host.clone(), *port)),
                    Endpoint::Srv(name) => services.push(name.clone()),
                }
            }
            let entry = Entry {
                local: p.endpoints_local,
                fixed,
                hosts,
                services,
            };
            let empty =
                entry.fixed.is_empty() && entry.hosts.is_empty() && entry.services.is_empty();
            let before = self.entries.get(&p.public);
            let had = before.is_some();
            if before == Some(&entry) || (empty && !had) {
                continue;
            }
            if empty {
                self.entries.remove(&p.public);
                self.ready.push_back(update(p.public, Vec::new()));
                continue;
            }
            if !entry.fixed.is_empty() || had {
                self.ready.push_back(update(p.public, entry.fixed.clone()));
            }
            let lookups = !entry.hosts.is_empty() || !entry.services.is_empty();
            self.entries.insert(p.public, entry);
            if lookups {
                self.resolve(p.public);
            }
        }
    }

    fn resolve(&mut self, peer: NodePublic) {
        let Some(entry) = self.entries.get(&peer) else {
            return;
        };
        if (entry.hosts.is_empty() && entry.services.is_empty()) || !self.inflight.insert(peer) {
            return;
        }
        self.last.insert(peer, Instant::now());
        let hosts = entry.hosts.clone();
        let services = entry.services.clone();
        let resolvers = self.resolvers.clone();
        let mark = self.mark;
        self.resolving.spawn(async move {
            let mut hosts = hosts;
            for name in services {
                hosts.extend(
                    crate::net::dns::srv(&resolvers, &name, mark)
                        .await
                        .into_iter()
                        .take(MAX_SRV_TARGETS),
                );
            }
            let mut out = Vec::new();
            for (host, port) in hosts {
                if let Ok(found) = crate::net::lookup::host(&host, port, mark, &resolvers).await {
                    out.extend(found);
                }
            }
            (peer, out)
        });
    }
}

fn update(peer: NodePublic, candidates: Vec<Candidate>) -> Update {
    Update {
        peer,
        source: SourceKey::Static,
        candidates,
        spare: Vec::new(),
    }
}

impl CandidateSource for StaticSource {
    fn name(&self) -> &'static str {
        "static"
    }

    fn poll_update(&mut self, cx: &mut Context<'_>) -> Poll<Update> {
        if let Some(u) = self.ready.pop_front() {
            return Poll::Ready(u);
        }
        while let Poll::Ready(Some(joined)) = self.resolving.poll_join_next(cx) {
            let Ok((peer, addrs)) = joined else { continue };
            self.inflight.remove(&peer);
            let Some(entry) = self.entries.get(&peer) else {
                continue;
            };
            let mut all = entry.fixed.clone();
            for a in addrs {
                let c = candidate(a, entry.local);
                if !all.contains(&c) {
                    all.push(c);
                }
            }
            return Poll::Ready(update(peer, all));
        }
        Poll::Pending
    }

    fn peers_changed(&mut self, peers: &[PeerSpec]) {
        self.set_peers(peers);
    }

    fn path_changed(&mut self) {
        let peers: Vec<NodePublic> = self.entries.keys().copied().collect();
        for p in peers {
            self.resolve(p);
        }
    }

    fn needs_path(&mut self, peer: &NodePublic) {
        let due = self
            .last
            .get(peer)
            .is_none_or(|t| t.elapsed() >= RESOLVE_INTERVAL);
        if due {
            self.resolve(*peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;

    use vardevall_proto::discovery::candidate::label;
    use vardevall_proto::keys::NodePublic;

    use super::*;

    fn spec(endpoints: Vec<Endpoint>) -> PeerSpec {
        PeerSpec {
            public: NodePublic::from_bytes([3; 32]),
            psk: None,
            endpoints,
            endpoints_local: false,
        }
    }

    #[tokio::test]
    async fn endpoints_are_internet_class_unless_the_peer_says_they_are_local() {
        for local in [false, true] {
            let mut peer = spec(vec![
                Endpoint::Addr("192.0.2.1:5".parse().unwrap()),
                Endpoint::Host {
                    host: "localhost".into(),
                    port: 9,
                },
            ]);
            peer.endpoints_local = local;
            let mut s = StaticSource::new(&[peer], Vec::new(), SocketMark::NONE);
            let first = poll_fn(|cx| s.poll_update(cx)).await;
            let second = poll_fn(|cx| s.poll_update(cx)).await;
            let all = first.candidates.iter().chain(&second.candidates);
            assert!(all.clone().count() >= 3);
            for c in all {
                assert_eq!((c.local, c.label), (local, label::STATIC));
                assert!(!c.shared && !c.metered);
            }
        }
    }

    #[tokio::test]
    async fn ip_and_dns_endpoints() {
        let mut s = StaticSource::new(
            &[spec(vec![
                Endpoint::Addr("192.0.2.1:5".parse().unwrap()),
                Endpoint::Host {
                    host: "localhost".into(),
                    port: 9,
                },
            ])],
            Vec::new(),
            SocketMark::NONE,
        );
        let first = poll_fn(|cx| s.poll_update(cx)).await;
        assert_eq!(first.candidates.len(), 1);
        let second = poll_fn(|cx| s.poll_update(cx)).await;
        assert!(second.candidates.len() >= 2);
        assert!(second.candidates.iter().all(|c| c.label == label::STATIC));
        assert!(
            second
                .candidates
                .iter()
                .any(|c| c.addr.port() == 9 && c.addr.ip().is_loopback())
        );
    }
}
