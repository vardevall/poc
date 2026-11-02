//! What a query for a name of the overlay domain gets (vv-06 §4.3, vve-14 §3).

use std::net::Ipv6Addr;

use vardevall::Handle;
use vardevall_proto::addr::{ANSWER_TTL, Answer, NameTable, OverlayAddrs, QueryType};
use vardevall_proto::ip::service::{Proto, Provider};
use vardevall_proto::keys::{NetworkId, NodePublic};

/// TTL of the answers an extension gives (vve-14 §3).
pub const SERVICE_TTL: u32 = 10;

/// The providers of services, as vve-14 §3 asks for them.
pub trait Providers: Send + Sync {
    /// The providers of `service`, at most 8, in answer order; `proto` restricts them to one
    /// transport.
    fn providers(&self, service: &str, proto: Option<Proto>) -> Vec<Provider>;
}

impl Providers for Handle {
    fn providers(&self, service: &str, proto: Option<Proto>) -> Vec<Provider> {
        match proto {
            Some(p) => self.providers_for(service, p),
            None => Handle::providers(self, service),
        }
    }
}

/// The record types the resolver tells apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Aaaa,
    Ptr,
    Srv,
    Other,
}

/// One record of an SRV answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv {
    pub priority: u16,
    pub port: u16,
    pub target: String,
    pub addr: Ipv6Addr,
}

/// The decision for one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Addrs { addrs: Vec<Ipv6Addr>, ttl: u32 },
    Ptr(String),
    Srv(Vec<Srv>),
    NoData,
    NxDomain,
    Refused,
    Forward,
}

/// The name table of an interface with the extension that reads service providers.
pub struct Names<'a> {
    pub table: &'a NameTable,
    pub network_id: &'a NetworkId,
    pub domain: &'a str,
    pub services: Option<&'a dyn Providers>,
}

impl Names<'_> {
    /// Decides a query for `qname` (vv-06 §4.3). A miss that `forward` is to answer is
    /// [`Decision::Forward`]; [`Names::extension`] then applies to its NXDOMAIN.
    pub fn decide(&self, qname: &str, kind: Kind) -> Decision {
        let name = qname.trim_end_matches('.').to_ascii_lowercase();
        let base = self.table.answer(
            &name,
            match kind {
                Kind::Aaaa => QueryType::Aaaa,
                Kind::Ptr => QueryType::Ptr,
                Kind::Srv | Kind::Other => QueryType::Other,
            },
        );
        match base {
            Answer::Aaaa(ip) => Decision::Addrs {
                addrs: vec![ip],
                ttl: ANSWER_TTL,
            },
            Answer::Ptr(target) => Decision::Ptr(target),
            Answer::NoData => Decision::NoData,
            Answer::Refused => Decision::Refused,
            Answer::Forward | Answer::NxDomain => {
                if let Some(key) = self.under_node(&name) {
                    return match kind {
                        Kind::Aaaa => Decision::Addrs {
                            addrs: vec![OverlayAddrs::derive(self.network_id, &key).ula],
                            ttl: ANSWER_TTL,
                        },
                        _ => Decision::NoData,
                    };
                }
                if base == Answer::Forward {
                    return Decision::Forward;
                }
                self.extension(&name, kind).unwrap_or(Decision::NxDomain)
            }
        }
    }

    /// The node `name` is under: `<labels>.<name>.<domain>` for a name or key-id of the table.
    fn under_node(&self, name: &str) -> Option<NodePublic> {
        let (rest, _) = self.relative(name)?;
        let (_, last) = rest.rsplit_once('.')?;
        self.table.resolve(last)
    }

    /// The part of `name` before the domain, and whether it is a single label.
    fn relative<'n>(&self, name: &'n str) -> Option<(&'n str, bool)> {
        let rest = name.strip_suffix(self.domain)?.strip_suffix('.')?;
        (!rest.is_empty()).then_some((rest, !rest.contains('.')))
    }

    /// The answer of the service extension for a name nobody else answers (vve-14 §3); `None` if
    /// it is not a service name or has no provider.
    pub fn extension(&self, qname: &str, kind: Kind) -> Option<Decision> {
        let services = self.services?;
        let name = qname.trim_end_matches('.').to_ascii_lowercase();
        let (rest, single) = self.relative(&name)?;
        if single {
            let providers = services.providers(rest, None);
            if providers.is_empty() {
                return None;
            }
            return Some(match kind {
                Kind::Aaaa => Decision::Addrs {
                    addrs: providers
                        .iter()
                        .map(|p| OverlayAddrs::derive(self.network_id, &p.key).ula)
                        .collect(),
                    ttl: SERVICE_TTL,
                },
                _ => Decision::NoData,
            });
        }
        let (service, proto) = srv_name(rest)?;
        let providers = services.providers(service, Some(proto));
        if providers.is_empty() {
            return None;
        }
        Some(match kind {
            Kind::Srv => Decision::Srv(
                providers
                    .iter()
                    .map(|p| Srv {
                        priority: u16::from(!p.live),
                        port: p.port,
                        target: self.target(&p.key),
                        addr: OverlayAddrs::derive(self.network_id, &p.key).ula,
                    })
                    .collect(),
            ),
            _ => Decision::NoData,
        })
    }

    fn target(&self, key: &NodePublic) -> String {
        let label = self
            .table
            .name(key)
            .map_or_else(|| key.key_id(), str::to_owned);
        format!("{label}.{}", self.domain)
    }
}

/// `_<service>._<proto>` as the service and the transport.
fn srv_name(rest: &str) -> Option<(&str, Proto)> {
    let (service, proto) = rest.split_once('.')?;
    let service = service.strip_prefix('_')?;
    let proto = match proto.strip_prefix('_')? {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        _ => return None,
    };
    (!service.is_empty()).then_some((service, proto))
}
