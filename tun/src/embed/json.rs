//! The JSON of events and views (`vv_event_cb`): types that mirror what
//! `apple/include/vardevall.h` documents, converted from the lib's events and views. The order of
//! the members of an object is not part of the contract.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Serialize, Serializer};
use tokio::time::Instant;
use vardevall::view::{
    ExitSite, Local, Nat, Peer, PeerNat, PeerRoute, Route, RouteNext, Switch, Transport, View,
};
use vardevall::{
    Budget, BudgetSource, Level, LogLevel, Meter, PeerState, Provider, Reason, SwitchFailure,
    SwitchState, Trust,
};
use vardevall_proto::discovery::candidate::Candidate;
use vardevall_proto::ip::site::Site;
use vardevall_proto::keys::NodePublic;
use vardevall_proto::route::Status as RouteStatus;

use super::{Event, Status, SwitchKind};

/// The JSON object of an event, or an empty string if it could not be written, which these types
/// cannot cause.
pub(super) fn render(network: &str, event: &Event) -> String {
    serde_json::to_string(&Tagged {
        network,
        event: EventJson::from(event),
    })
    .unwrap_or_default()
}

/// An event with the name of the network it belongs to.
#[derive(Serialize)]
struct Tagged<'a> {
    network: &'a str,
    #[serde(flatten)]
    event: EventJson<'a>,
}

/// The JSON array of `vv_providers`; each entry is a provider with its overlay `ula` and name.
pub(super) fn providers(list: &[(&Provider, Ipv6Addr, Option<String>)]) -> String {
    let list: Vec<_> = list
        .iter()
        .map(|(p, addr, name)| ProviderJson {
            key: p.key.to_base32(),
            addr: *addr,
            name,
            port: p.port,
            proto: p.proto.name(),
            live: p.live,
        })
        .collect();
    serde_json::to_string(&list).unwrap_or_default()
}

#[derive(Serialize)]
#[serde(remote = "Trust", rename_all = "snake_case")]
enum TrustDef {
    Key,
    Member,
}

#[derive(Serialize)]
#[serde(remote = "Reason", rename_all = "snake_case")]
enum ReasonDef {
    Idle,
    Unreachable,
}

#[derive(Serialize)]
#[serde(remote = "SwitchFailure", rename_all = "snake_case")]
enum FailureDef {
    Unreachable,
    Untrusted,
    TokenRejected,
    Rejected,
    RateLimited,
    Replaced,
    Protocol,
}

#[derive(Serialize)]
#[serde(remote = "BudgetSource")]
enum SourceDef {
    #[serde(rename = "switch")]
    Reported,
    #[serde(rename = "turn")]
    Relay,
}

#[derive(Serialize)]
#[serde(remote = "Level", rename_all = "snake_case")]
enum LevelDef {
    Plenty,
    Half,
    Low,
    Exhausted,
}

#[derive(Serialize)]
#[serde(remote = "LogLevel", rename_all = "snake_case")]
enum LogLevelDef {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Serialize)]
#[serde(remote = "PeerNat", rename_all = "snake_case")]
enum PeerNatDef {
    Unknown,
    Punchable,
    RelayOnly,
}

#[derive(Serialize)]
#[serde(remote = "Meter")]
struct MeterDef {
    sent: u64,
    received: u64,
}

fn meter<S: Serializer>(m: &Option<Meter>, s: S) -> Result<S::Ok, S::Error> {
    match m {
        Some(m) => MeterDef::serialize(m, s),
        None => s.serialize_none(),
    }
}

fn key<S: Serializer>(k: &NodePublic, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&k.to_base32())
}

/// A remembered offer: `{"key":"<base32>","site":"it/home"}`.
#[derive(Serialize)]
struct OfferJson {
    #[serde(serialize_with = "key")]
    key: NodePublic,
    site: String,
}

fn opt_key<S: Serializer>(k: &Option<NodePublic>, s: S) -> Result<S::Ok, S::Error> {
    match k {
        Some(k) => key(k, s),
        None => s.serialize_none(),
    }
}

/// The name of a link state, without what goes with it.
fn state_name<S: Serializer>(state: &PeerState, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(match state {
        PeerState::Idle => "idle",
        PeerState::Connecting => "connecting",
        PeerState::Up { .. } => "up",
        PeerState::Down(_) => "down",
    })
}

/// How the peer of an event is named.
#[derive(Serialize)]
struct Ids<'a> {
    #[serde(serialize_with = "key")]
    key: NodePublic,
    addr: Ipv6Addr,
    name: Option<&'a str>,
}

impl<'a> Ids<'a> {
    fn new(key: NodePublic, addr: Ipv6Addr, name: &'a Option<String>) -> Self {
        Ids {
            key,
            addr,
            name: name.as_deref(),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum EventJson<'a> {
    Status(Status),
    Added {
        #[serde(flatten)]
        peer: Ids<'a>,
        #[serde(serialize_with = "TrustDef::serialize")]
        trust: Trust,
    },
    Removed {
        #[serde(flatten)]
        peer: Ids<'a>,
    },
    Peer {
        #[serde(flatten)]
        peer: Ids<'a>,
        #[serde(flatten)]
        state: LinkJson,
    },
    Route {
        #[serde(flatten)]
        peer: Ids<'a>,
        route: Option<RouteJson>,
    },
    Exit {
        site: String,
        #[serde(serialize_with = "opt_key")]
        via: Option<NodePublic>,
        addr: Ipv6Addr,
        ipv4: Option<Ipv4Addr>,
    },
    Exits {
        offers: Vec<OfferJson>,
    },
    Switch {
        address: &'a str,
        auth: SwitchKind,
        #[serde(flatten)]
        state: SwitchStateJson,
    },
    #[serde(rename = "budget")]
    BudgetSet {
        transport: &'a str,
        #[serde(flatten)]
        budget: BudgetJson,
    },
    #[serde(rename = "budget")]
    BudgetRemoved {
        transport: &'a str,
        budget: (),
    },
    View(ViewJson<'a>),
    Log {
        #[serde(serialize_with = "LogLevelDef::serialize")]
        level: LogLevel,
        message: &'a str,
    },
}

impl<'a> From<&'a Event> for EventJson<'a> {
    fn from(event: &'a Event) -> Self {
        match event {
            Event::Status(s) => EventJson::Status(*s),
            Event::Added {
                key,
                addr,
                name,
                trust,
            } => EventJson::Added {
                peer: Ids::new(*key, *addr, name),
                trust: *trust,
            },
            Event::Removed { key, addr, name } => EventJson::Removed {
                peer: Ids::new(*key, *addr, name),
            },
            Event::Peer {
                key,
                addr,
                name,
                state,
            } => EventJson::Peer {
                peer: Ids::new(*key, *addr, name),
                state: (*state).into(),
            },
            Event::Route {
                key,
                addr,
                name,
                route,
            } => EventJson::Route {
                peer: Ids::new(*key, *addr, name),
                route: route.map(Into::into),
            },
            Event::Exit {
                site,
                via,
                addr,
                ipv4,
            } => EventJson::Exit {
                site: site.to_string(),
                via: *via,
                addr: *addr,
                ipv4: *ipv4,
            },
            Event::Exits { offers } => EventJson::Exits {
                offers: offers
                    .iter()
                    .map(|(key, site)| OfferJson {
                        key: *key,
                        site: site.to_string(),
                    })
                    .collect(),
            },
            Event::Switch {
                address,
                kind,
                state,
            } => EventJson::Switch {
                address,
                auth: *kind,
                state: state.into(),
            },
            Event::Budget {
                transport,
                budget: Some(b),
            } => EventJson::BudgetSet {
                transport,
                budget: b.into(),
            },
            Event::Budget {
                transport,
                budget: None,
            } => EventJson::BudgetRemoved {
                transport,
                budget: (),
            },
            Event::View {
                view,
                peers,
                switches,
                exit,
            } => EventJson::View(ViewJson::new(view, peers, switches, exit.as_ref())),
            Event::Log { level, message } => EventJson::Log {
                level: *level,
                message,
            },
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum LinkJson {
    Idle,
    Connecting,
    Up {
        initiator: bool,
    },
    Down {
        #[serde(serialize_with = "ReasonDef::serialize")]
        reason: Reason,
    },
}

impl From<PeerState> for LinkJson {
    fn from(s: PeerState) -> Self {
        match s {
            PeerState::Idle => LinkJson::Idle,
            PeerState::Connecting => LinkJson::Connecting,
            PeerState::Up { initiator } => LinkJson::Up { initiator },
            PeerState::Down(reason) => LinkJson::Down { reason },
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RouteJson {
    Lan { addr: SocketAddr },
    Internet { addr: SocketAddr },
    PeerRelay { addr: SocketAddr },
    OwnRelay { addr: SocketAddr },
    Switch { switch: u32 },
}

impl From<Route> for RouteJson {
    fn from(r: Route) -> Self {
        match r {
            Route::Lan(addr) => RouteJson::Lan { addr },
            Route::Internet(addr) => RouteJson::Internet { addr },
            Route::PeerRelay(addr) => RouteJson::PeerRelay { addr },
            Route::OwnRelay(addr) => RouteJson::OwnRelay { addr },
            Route::Switch(id) => RouteJson::Switch { switch: id.0 },
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum SwitchStateJson {
    Connecting,
    Registered,
    Disconnected {
        #[serde(serialize_with = "FailureDef::serialize")]
        reason: SwitchFailure,
    },
}

impl From<&SwitchState> for SwitchStateJson {
    fn from(s: &SwitchState) -> Self {
        match s {
            SwitchState::Connecting => SwitchStateJson::Connecting,
            SwitchState::Registered => SwitchStateJson::Registered,
            SwitchState::Disconnected(reason) => SwitchStateJson::Disconnected { reason: *reason },
        }
    }
}

#[derive(Serialize)]
struct BudgetJson {
    total: u64,
    remaining: u64,
    #[serde(serialize_with = "SourceDef::serialize")]
    source: BudgetSource,
    #[serde(serialize_with = "LevelDef::serialize")]
    level: Level,
}

impl From<&Budget> for BudgetJson {
    fn from(b: &Budget) -> Self {
        BudgetJson {
            total: b.total,
            remaining: b.remaining,
            source: b.source,
            level: b.level(),
        }
    }
}

#[derive(Serialize)]
struct ViewJson<'a> {
    local: LocalJson<'a>,
    peers: Vec<ViewPeerJson<'a>>,
    sites: Vec<SiteJson>,
    exit: Option<ExitUseJson>,
}

impl<'a> ViewJson<'a> {
    fn new(
        view: &'a View,
        peers: &'a [(Ipv6Addr, Option<String>)],
        kinds: &[SwitchKind],
        exit: Option<&(Site, NodePublic)>,
    ) -> Self {
        ViewJson {
            local: LocalJson::new(&view.local, kinds),
            peers: view
                .peers
                .iter()
                .zip(peers)
                .map(|(p, (addr, name))| ViewPeerJson::new(p, *addr, name))
                .collect(),
            sites: view.sites.iter().map(Into::into).collect(),
            exit: exit.map(|(site, via)| ExitUseJson {
                site: site.to_string(),
                via: via.to_base32(),
            }),
        }
    }
}

#[derive(Serialize)]
struct SiteJson {
    site: String,
    peers: Vec<String>,
    down: Vec<String>,
    chosen: Option<String>,
    addr: Ipv6Addr,
}

impl From<&ExitSite> for SiteJson {
    fn from(s: &ExitSite) -> Self {
        SiteJson {
            site: s.site.to_string(),
            peers: s
                .peers
                .iter()
                .filter(|p| p.live)
                .map(|p| p.peer.to_base32())
                .collect(),
            down: s
                .peers
                .iter()
                .filter(|p| !p.live)
                .map(|p| p.peer.to_base32())
                .collect(),
            chosen: s.chosen.as_ref().map(NodePublic::to_base32),
            addr: s.addr,
        }
    }
}

#[derive(Serialize)]
struct ExitUseJson {
    site: String,
    via: String,
}

#[derive(Serialize)]
struct LocalJson<'a> {
    ipv6: NatJson,
    ipv4: NatJson,
    relay: Option<RelayJson>,
    switches: Vec<SwitchJson<'a>>,
    transports: Vec<TransportJson<'a>>,
}

impl<'a> LocalJson<'a> {
    fn new(l: &'a Local, kinds: &[SwitchKind]) -> Self {
        LocalJson {
            ipv6: l.v6.into(),
            ipv4: l.v4.into(),
            relay: l.relay.map(|r| RelayJson {
                addr: r.addr,
                server: r.server,
                transport: if r.tls { "tls" } else { "udp" },
            }),
            switches: l
                .switches
                .iter()
                .zip(kinds)
                .map(|(s, kind)| SwitchJson::new(s, *kind))
                .collect(),
            transports: l.transports.iter().map(Into::into).collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "nat", rename_all = "snake_case")]
enum NatJson {
    Unknown,
    Punchable { addr: SocketAddr },
    Symmetric,
    UdpBlocked,
}

impl From<Nat> for NatJson {
    fn from(n: Nat) -> Self {
        match n {
            Nat::Unknown => NatJson::Unknown,
            Nat::Punchable(addr) => NatJson::Punchable { addr },
            Nat::Symmetric => NatJson::Symmetric,
            Nat::Blocked => NatJson::UdpBlocked,
        }
    }
}

#[derive(Serialize)]
struct RelayJson {
    addr: SocketAddr,
    server: SocketAddr,
    transport: &'static str,
}

#[derive(Serialize)]
struct SwitchJson<'a> {
    index: u32,
    address: &'a str,
    auth: SwitchKind,
    #[serde(flatten)]
    state: SwitchStateJson,
    transport: Option<&'static str>,
    retry_in_ms: Option<u64>,
}

impl<'a> SwitchJson<'a> {
    fn new(s: &'a Switch, auth: SwitchKind) -> Self {
        SwitchJson {
            index: s.id.0,
            address: &s.address,
            auth,
            state: (&s.state).into(),
            transport: s.transport,
            retry_in_ms: s.retry_at.map(ms_until),
        }
    }
}

#[derive(Serialize)]
struct TransportJson<'a> {
    name: &'a str,
    usable: bool,
    #[serde(serialize_with = "MeterDef::serialize")]
    meter: Meter,
    budget: Option<BudgetJson>,
}

impl<'a> From<&'a Transport> for TransportJson<'a> {
    fn from(t: &'a Transport) -> Self {
        TransportJson {
            name: &t.name,
            usable: t.usable,
            meter: t.meter,
            budget: t.budget.as_ref().map(Into::into),
        }
    }
}

#[derive(Serialize)]
struct ViewPeerJson<'a> {
    #[serde(serialize_with = "key")]
    key: NodePublic,
    addr: Ipv6Addr,
    name: Option<&'a str>,
    #[serde(serialize_with = "state_name")]
    state: PeerState,
    route: Option<PeerRouteJson>,
    #[serde(serialize_with = "PeerNatDef::serialize")]
    nat: PeerNat,
    candidates: Vec<CandidateJson>,
    switches: Vec<u32>,
    probing: bool,
    fallback: bool,
    #[serde(serialize_with = "meter")]
    meter: Option<Meter>,
    rtt_ms: Option<u64>,
    routes: Vec<TraceRouteJson>,
}

impl<'a> ViewPeerJson<'a> {
    fn new(p: &Peer, addr: Ipv6Addr, name: &'a Option<String>) -> Self {
        ViewPeerJson {
            key: p.peer,
            addr,
            name: name.as_deref(),
            state: p.state,
            route: p.route.map(|r| PeerRouteJson {
                route: r.into(),
                metered: p.metered,
                degraded: p.degraded,
            }),
            nat: p.nat,
            candidates: p.candidates.iter().map(Into::into).collect(),
            switches: p.switches.iter().map(|s| s.0).collect(),
            probing: p.probing,
            fallback: p.fallback,
            meter: p.meter,
            rtt_ms: p.rtt.map(ms),
            routes: p.routes.iter().map(Into::into).collect(),
        }
    }
}

fn ms(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// The milliseconds from now to `at`, zero once it has passed.
fn ms_until(at: Instant) -> u64 {
    ms(at.saturating_duration_since(Instant::now()))
}

#[derive(Serialize)]
struct TraceRouteJson {
    #[serde(flatten)]
    route: RouteJson,
    status: &'static str,
    rtt_ms: Option<u64>,
    active: bool,
    metered: bool,
    retry_in_ms: Option<u64>,
    forget_in_ms: Option<u64>,
}

impl From<&PeerRoute> for TraceRouteJson {
    fn from(r: &PeerRoute) -> Self {
        TraceRouteJson {
            route: r.route.into(),
            status: match r.status {
                RouteStatus::Dormant => "dormant",
                RouteStatus::Candidate => "candidate",
                RouteStatus::Verified => "verified",
                RouteStatus::Suspect => "suspect",
                RouteStatus::Failed => "failed",
            },
            rtt_ms: r.rtt.map(ms),
            active: r.active,
            metered: r.metered,
            retry_in_ms: match r.next {
                Some(RouteNext::Retry(at)) => Some(ms_until(at)),
                _ => None,
            },
            forget_in_ms: match r.next {
                Some(RouteNext::Forget(at)) => Some(ms_until(at)),
                _ => None,
            },
        }
    }
}

#[derive(Serialize)]
struct PeerRouteJson {
    #[serde(flatten)]
    route: RouteJson,
    metered: bool,
    degraded: bool,
}

#[derive(Serialize)]
struct CandidateJson {
    kind: &'static str,
    addr: SocketAddr,
    local: bool,
    metered: bool,
}

impl From<&Candidate> for CandidateJson {
    fn from(c: &Candidate) -> Self {
        CandidateJson {
            kind: c.label,
            addr: c.addr,
            local: c.local,
            metered: c.metered,
        }
    }
}

#[derive(Serialize)]
struct ProviderJson<'a> {
    key: String,
    addr: Ipv6Addr,
    name: &'a Option<String>,
    port: u16,
    proto: &'static str,
    live: bool,
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use vardevall::Proto;

    use super::*;

    #[test]
    fn providers_keep_their_order_and_members() {
        let key = NodePublic::from_bytes([1; 32]);
        let p = |port, proto, live| Provider {
            key,
            port,
            proto,
            live,
        };
        let (tcp, udp) = (p(8080, Proto::Tcp, true), p(53, Proto::Udp, false));
        let list = [
            (&tcp, "fd00::1".parse().unwrap(), Some("nas".to_owned())),
            (&udp, "fd00::2".parse().unwrap(), None),
        ];
        let k = key.to_base32();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&providers(&list)).unwrap(),
            json!([
                {"key": k, "addr": "fd00::1", "name": "nas", "port": 8080, "proto": "tcp", "live": true},
                {"key": k, "addr": "fd00::2", "name": null, "port": 53, "proto": "udp", "live": false},
            ])
        );
        assert_eq!(providers(&[]), "[]");
    }
}
