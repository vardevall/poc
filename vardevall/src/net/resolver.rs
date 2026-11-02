//! Resolution of the STUN and TURN servers of the configuration (vv-07 §3.4, §3.6).
//!
//! One task per configured entry resolves its URIs and reports the result on a bounded channel,
//! under the entry's [`Origin::Config`]. The STUN entries are resolved again after a settled
//! local change (vv-05 §4.6).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use vardevall_switch_proto::origin::Origin;
use vardevall_switch_proto::turn::{Server, TurnOffer};
use vardevall_switch_proto::uri::{HostPort, parse_stun, parse_turn_udp};

use crate::config::{StunSpec, TurnSpec};
use crate::net::lookup;
use crate::net::mark::SocketMark;

/// Time to resolve one name.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Most STUN or TURN URIs resolved per entry.
pub(crate) const MAX_URIS: usize = 4;
/// Results waiting for the node.
const RESULT_QUEUE: usize = 16;

/// The addresses of `target`, IPv6 first.
pub(crate) async fn resolve(target: &HostPort, mark: SocketMark) -> Vec<SocketAddr> {
    let found = tokio::time::timeout(
        RESOLVE_TIMEOUT,
        lookup::host(target.host.as_str(), target.port, mark, &[]),
    )
    .await;
    let Ok(Ok(addrs)) = found else {
        return Vec::new();
    };
    let mut out: Vec<SocketAddr> = addrs.iter().copied().filter(SocketAddr::is_ipv6).collect();
    out.extend(addrs.iter().copied().filter(SocketAddr::is_ipv4));
    out.dedup();
    out
}

/// What a resolution found.
#[derive(Debug)]
pub(crate) enum Resolved {
    /// The STUN servers of an entry, and the short-term credential (username and key) if the
    /// entry has one.
    Stun {
        origin: Origin,
        servers: Vec<SocketAddr>,
        credential: Option<(String, Vec<u8>)>,
    },
    /// The TURN servers of an entry with its long-term credential.
    Turn { origin: Origin, offer: TurnOffer },
}

/// The tasks resolving the configured servers.
pub(crate) struct Resolver {
    stun_specs: Vec<StunSpec>,
    turn_specs: Vec<TurnSpec>,
    mark: SocketMark,
    tx: mpsc::Sender<Resolved>,
    rx: mpsc::Receiver<Resolved>,
    stun: JoinSet<()>,
    turn: JoinSet<()>,
}

fn origin(i: usize) -> Origin {
    Origin::Config(u16::try_from(i).unwrap_or(u16::MAX))
}

impl Resolver {
    /// Starts resolving `stun` and `turn`. Must be called inside a tokio runtime.
    pub(crate) fn start(stun: &[StunSpec], turn: &[TurnSpec], mark: SocketMark) -> Self {
        let (tx, rx) = mpsc::channel(RESULT_QUEUE);
        let mut r = Resolver {
            stun_specs: stun.to_vec(),
            turn_specs: turn.to_vec(),
            mark,
            tx,
            rx,
            stun: JoinSet::new(),
            turn: JoinSet::new(),
        };
        r.resolve_stun();
        for (i, spec) in turn.iter().enumerate() {
            r.turn
                .spawn(resolve_turn(r.tx.clone(), origin(i), spec.clone(), mark));
        }
        r
    }

    /// The number of configured STUN and TURN entries, which are the positions of their origins.
    pub(crate) fn counts(&self) -> (usize, usize) {
        (self.stun_specs.len(), self.turn_specs.len())
    }

    /// Whether these are the entries being resolved.
    pub(crate) fn is(&self, stun: &[StunSpec], turn: &[TurnSpec]) -> bool {
        self.stun_specs == stun && self.turn_specs == turn
    }

    /// Resolves `stun` and `turn` instead of the entries given before, abandoning lookups still
    /// running. The origins are positions, so the caller forgets what the old ones reported.
    pub(crate) fn replace(&mut self, stun: &[StunSpec], turn: &[TurnSpec]) {
        self.turn.abort_all();
        self.stun_specs = stun.to_vec();
        self.turn_specs = turn.to_vec();
        self.resolve_stun();
        for (i, spec) in turn.iter().enumerate() {
            self.turn.spawn(resolve_turn(
                self.tx.clone(),
                origin(i),
                spec.clone(),
                self.mark,
            ));
        }
    }

    /// Resolves the STUN entries again, abandoning lookups still running.
    pub(crate) fn resolve_stun(&mut self) {
        self.stun.abort_all();
        for (i, spec) in self.stun_specs.iter().enumerate() {
            self.stun.spawn(resolve_stun(
                self.tx.clone(),
                origin(i),
                spec.clone(),
                self.mark,
            ));
        }
    }

    /// The next result; pending while there is none.
    pub(crate) async fn recv(&mut self) -> Option<Resolved> {
        self.rx.recv().await
    }

    /// Abandons every lookup.
    pub(crate) fn stop(&mut self) {
        self.stun.abort_all();
        self.turn.abort_all();
    }
}

async fn resolve_stun(
    tx: mpsc::Sender<Resolved>,
    origin: Origin,
    spec: StunSpec,
    mark: SocketMark,
) {
    let mut servers = Vec::new();
    for t in spec
        .urls
        .iter()
        .filter_map(|u| parse_stun(u))
        .take(MAX_URIS)
    {
        for a in resolve(&t, mark).await {
            if !servers.contains(&a) {
                servers.push(a);
            }
        }
    }
    let credential = spec
        .username
        .zip(spec.credential)
        .map(|(u, p)| (u, p.into_bytes()));
    let _ = tx
        .send(Resolved::Stun {
            origin,
            servers,
            credential,
        })
        .await;
}

async fn resolve_turn(
    tx: mpsc::Sender<Resolved>,
    origin: Origin,
    spec: TurnSpec,
    mark: SocketMark,
) {
    let mut servers = Vec::new();
    for t in spec
        .urls
        .iter()
        .filter_map(|u| parse_turn_udp(u))
        .take(MAX_URIS)
    {
        servers.extend(resolve(&t, mark).await.into_iter().map(Server::udp));
    }
    if servers.is_empty() {
        return;
    }
    let offer = TurnOffer {
        servers,
        username: spec.username,
        password: spec.credential,
        ttl: Duration::MAX,
        bits_per_second: None,
        bytes: None,
        realm: None,
        nonce: None,
        priority: spec.priority,
    };
    let _ = tx.send(Resolved::Turn { origin, offer }).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hp(host: &str, port: u16) -> HostPort {
        HostPort {
            host: host.to_owned(),
            port,
        }
    }

    #[tokio::test]
    async fn literals_resolve_without_dns() {
        assert_eq!(
            resolve(&hp("127.0.0.1", 9), SocketMark::NONE).await,
            vec!["127.0.0.1:9".parse().unwrap()]
        );
        assert_eq!(
            resolve(&hp("::1", 9), SocketMark::NONE).await,
            vec!["[::1]:9".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn an_entry_is_reported_under_its_position() {
        let stun = vec![
            StunSpec {
                urls: vec!["stun:127.0.0.1:3478".to_owned()],
                username: None,
                credential: None,
            },
            StunSpec {
                urls: vec!["stun:127.0.0.2:3478".to_owned()],
                username: Some("u".to_owned()),
                credential: Some("p".to_owned()),
            },
        ];
        let turn = vec![TurnSpec {
            urls: vec!["turn:127.0.0.3:3478".to_owned()],
            username: "u".to_owned(),
            credential: "p".to_owned(),
            priority: 5,
        }];
        let mut r = Resolver::start(&stun, &turn, SocketMark::NONE);
        let mut seen = Vec::new();
        for _ in 0..3 {
            seen.push(r.recv().await.unwrap());
        }
        let stun_of = |o: Origin| {
            seen.iter().find_map(|s| match s {
                Resolved::Stun {
                    origin,
                    servers,
                    credential,
                } if *origin == o => Some((servers.clone(), credential.clone())),
                _ => None,
            })
        };
        let (servers, cred) = stun_of(Origin::Config(0)).unwrap();
        assert_eq!(servers, vec!["127.0.0.1:3478".parse().unwrap()]);
        assert!(cred.is_none());
        let (_, cred) = stun_of(Origin::Config(1)).unwrap();
        assert_eq!(cred, Some(("u".to_owned(), b"p".to_vec())));
        assert!(seen.iter().any(|s| matches!(
            s,
            Resolved::Turn { origin: Origin::Config(0), offer } if offer.priority == 5
        )));
        r.resolve_stun();
        assert!(r.recv().await.is_some());
        r.stop();
    }
}
