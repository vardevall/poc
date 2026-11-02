//! The overlay DNS responder (vv-06 §4, vve-14 §3).
//!
//! [`Responder`] decides queries with the [`NameTable`] of `proto` and speaks DNS on the wire.
//! [`serve`] runs it on sockets; [`intercept`] lets an embedder without a local socket answer
//! queries found in the packet stream of the tunnel.

mod forward;
mod intercept;
mod names;
mod serve;
mod wire;

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use vardevall_proto::addr::{self, NameTable, OverlayAddrs};
use vardevall_proto::keys::{NetworkId, NodePublic};

pub(crate) use forward::{ATTEMPT_TIMEOUT, MAX_IN_FLIGHT};
pub use forward::{Forwarder, Relay};
pub use intercept::{Query, intercept, intercept_at, reply_packet};
pub use names::{Providers, SERVICE_TTL};
pub use serve::{serve_tcp, serve_udp};

use crate::config::Config;

/// The DNS port.
const DNS_PORT: u16 = 53;

/// What to do with a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Send this response.
    Answer(Vec<u8>),
    /// Relay this query to the `forward` upstreams (vv-06 §4.5).
    Forward(Vec<u8>),
    /// Relay this query for a name outside every overlay domain.
    Relay(Relay),
    /// Send nothing.
    Drop,
}

/// `<label>.<domain>`.
pub fn fqdn(label: &str, domain: &str) -> String {
    format!("{label}.{domain}")
}

/// What a node that serves an exit relays for its peers.
struct Serving {
    /// The interface identifiers of the peers held by key, the only ones relayed for.
    peers: Vec<[u8; 8]>,
}

/// Answers queries for one interface's domain.
pub struct Responder {
    table: Mutex<NameTable>,
    own: OverlayAddrs,
    network_id: NetworkId,
    domain: Mutex<String>,
    services: Option<Arc<dyn Providers>>,
    forward: AtomicBool,
    serving: Mutex<Option<Serving>>,
    exit_resolver: Mutex<Option<Ipv6Addr>>,
}

impl Responder {
    /// A responder for `domain` with the node's own name and the configured peers (vv-06 §4.1).
    pub fn new(
        network_id: NetworkId,
        domain: &str,
        own: NodePublic,
        own_name: Option<&str>,
        peers: &[(Option<&str>, NodePublic)],
        forward: bool,
    ) -> Self {
        let mut table = NameTable::new(network_id, domain, forward);
        table.add_key(own);
        if let Some(n) = own_name {
            table.add_name(n, own);
        }
        for (name, key) in peers {
            match name {
                Some(n) => {
                    table.add_name(n, *key);
                }
                None => table.add_key(*key),
            }
        }
        Responder {
            table: Mutex::new(table),
            own: OverlayAddrs::derive(&network_id, &own),
            network_id,
            domain: Mutex::new(domain.trim_end_matches('.').to_ascii_lowercase()),
            services: None,
            forward: AtomicBool::new(forward),
            serving: Mutex::new(None),
            exit_resolver: Mutex::new(None),
        }
    }

    /// Lets the resolver answer service names from `providers` (vve-14 §3).
    pub fn with_services(mut self, providers: Arc<dyn Providers>) -> Self {
        self.services = Some(providers);
        self
    }

    /// The responder of an interface file.
    pub fn from_config(config: &Config) -> Self {
        let peers: Vec<(Option<&str>, NodePublic)> = config
            .peers
            .iter()
            .map(|p| (p.name.as_deref(), p.public_key))
            .collect();
        let mut responder = Responder::new(
            config.network_id,
            &config.domain,
            config.public_key,
            config.own_name.as_deref(),
            &peers,
            !config.forward.is_empty(),
        );
        responder.serving = Mutex::new(Responder::serving_of(config));
        responder
    }

    fn serving_of(config: &Config) -> Option<Serving> {
        config.exit.as_ref().map(|_| Serving {
            peers: config
                .peers
                .iter()
                .map(|p| addr::iid(&config.network_id, &p.public_key))
                .collect(),
        })
    }

    /// Takes the names, the domain, `forward` and the exit served from `config` while the
    /// responder runs. Keys of members found later stay known.
    pub fn reconfigure(&self, config: &Config) {
        if let Ok(mut t) = self.table.lock() {
            t.set_domain(&config.domain);
            t.set_forward(!config.forward.is_empty());
            t.clear_label(&config.public_key);
            for p in &config.peers {
                t.clear_label(&p.public_key);
            }
            if let Some(n) = &config.own_name {
                t.add_name(n, config.public_key);
            }
            for p in &config.peers {
                match &p.name {
                    Some(n) => {
                        t.add_name(n, p.public_key);
                    }
                    None => t.add_key(p.public_key),
                }
            }
        }
        if let Ok(mut d) = self.domain.lock() {
            *d = config.domain.trim_end_matches('.').to_ascii_lowercase();
        }
        self.forward
            .store(!config.forward.is_empty(), Ordering::Relaxed);
        if let Ok(mut s) = self.serving.lock() {
            *s = Responder::serving_of(config);
        }
    }

    fn domain(&self) -> String {
        self.domain.lock().map(|d| d.clone()).unwrap_or_default()
    }

    /// Says which exit this node uses, if any: while there is one, and the interface file has no
    /// `forward`, queries for names outside every overlay domain that this host makes are
    /// relayed to that exit's resolver.
    pub fn set_exit(&self, exit: Option<&NodePublic>) {
        let ula = exit.map(|k| OverlayAddrs::derive(&self.network_id, k).ula);
        if let Ok(mut r) = self.exit_resolver.lock() {
            *r = ula;
        }
    }

    /// The node's own overlay addresses, where the resolver listens (vv-06 §4.4).
    pub fn own_addrs(&self) -> &OverlayAddrs {
        &self.own
    }

    /// Makes `key` known for reverse lookups, as for a member found later (vv-06 §4.1).
    pub fn add_key(&self, key: NodePublic) {
        if let Ok(mut t) = self.table.lock() {
            t.add_key(key);
        }
    }

    /// Forgets `key`, as for a member that was evicted.
    pub fn remove_key(&self, key: &NodePublic) {
        if let Ok(mut t) = self.table.lock() {
            t.remove_key(key);
        }
    }

    /// `resolve(name) → key` (vv-06 §4.6).
    pub fn resolve(&self, name: &str) -> Option<NodePublic> {
        self.table.lock().ok()?.resolve(name)
    }

    /// `name(key) → label or none` (vv-06 §4.6).
    pub fn name(&self, key: &NodePublic) -> Option<String> {
        self.table.lock().ok()?.name(key).map(str::to_owned)
    }

    /// The length of the zone of this responder, its domain or its reverse zone, that the name of
    /// `query` is in; `None` if the name is in neither or the message is not a one-question query.
    /// The longer match is the more specific.
    pub fn zone_len(&self, query: &[u8]) -> Option<usize> {
        let name = wire::question_name(query)?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let within = |zone: &str| {
            let tail = name.strip_suffix(zone)?;
            (tail.is_empty() || tail.ends_with('.')).then_some(zone.len())
        };
        let reverse = vardevall_proto::addr::reverse_zone(&self.network_id);
        within(&self.domain()).max(within(&reverse))
    }

    /// Whether `query` is a standard query for a name in none of the zones of this responder,
    /// which [`Responder::respond`] refuses.
    pub fn is_outside(&self, query: &[u8]) -> bool {
        wire::question_name(query).is_some() && self.zone_len(query).is_none()
    }

    /// Whether `addr` is in the network and has the interface identifier of `iid`.
    fn has_iid(&self, addr: &Ipv6Addr, iid: &[u8; 8]) -> bool {
        let o = addr.octets();
        o[..6] == addr::ula_prefix(&self.network_id)[..6] && o[8..] == iid[..]
    }

    /// The relay of a query for a name outside every overlay domain: a peer held by key of a
    /// node that serves an exit gets it relayed to the upstreams; this host gets it relayed to
    /// the exit in use.
    fn relay(&self, query: &[u8], from: Option<&Ipv6Addr>) -> Option<Relay> {
        wire::question_name(query)?;
        if self.zone_len(query).is_some() {
            return None;
        }
        let held_by_key = from.is_some_and(|from| {
            self.serving
                .lock()
                .ok()
                .and_then(|s| s.as_ref().map(|s| s.peers.clone()))
                .is_some_and(|peers| peers.iter().any(|iid| self.has_iid(from, iid)))
        });
        if held_by_key {
            return Some(Relay {
                query: query.to_vec(),
                via: None,
            });
        }
        let local = from.is_none_or(|a| a.is_loopback() || self.has_iid(a, &self.own.iid));
        let exit = (*self.exit_resolver.lock().ok()?)
            .filter(|_| local && !self.forward.load(Ordering::Relaxed))?;
        Some(Relay {
            query: query.to_vec(),
            via: Some(SocketAddr::new(exit.into(), DNS_PORT)),
        })
    }

    /// Decides one query message from `from`, `None` for this host (vv-06 §4.3).
    pub fn respond_from(&self, query: &[u8], from: Option<&Ipv6Addr>) -> Reply {
        match self.relay(query, from) {
            Some(r) => Reply::Relay(r),
            None => self.respond(query),
        }
    }

    /// Decides one query message (vv-06 §4.3); names outside the overlay domains are refused.
    pub fn respond(&self, query: &[u8]) -> Reply {
        let domain = self.domain();
        match self.table.lock() {
            Ok(t) => wire::respond(&self.names(&t, &domain), query),
            Err(_) => Reply::Drop,
        }
    }

    /// The response to a forwarded `query` given the upstream's `response`: an NXDOMAIN gives way
    /// to a service name (vv-06 §4.3).
    pub fn after_forward(&self, query: &[u8], response: Vec<u8>) -> Vec<u8> {
        let domain = self.domain();
        match self.table.lock() {
            Ok(t) => wire::after_forward(&self.names(&t, &domain), query, response),
            Err(_) => response,
        }
    }

    fn names<'a>(&'a self, table: &'a NameTable, domain: &'a str) -> names::Names<'a> {
        names::Names {
            table,
            network_id: &self.network_id,
            domain,
            services: self.services.as_deref(),
        }
    }
}

#[cfg(test)]
mod relay_tests;
#[cfg(test)]
mod tests;
