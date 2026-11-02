//! Interface files: parsing and validation (vv-07 §2, §3).

mod diff;
#[cfg(test)]
mod diff_tests;
mod edit;
mod raw;
mod summary;
pub mod value;

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use thiserror::Error;
use vardevall::{
    AddressError, DeliveryClass, Endpoint, ExitServe, MdnsMode, NodeConfig, PeerSpec, StunSpec,
    SwitchSpec, WantBand, WantLatency,
};
use vardevall_proto::addr::{self, OverlayAddrs};
use vardevall_proto::ip::service::{MAX_SERVICES, Proto, Service};
use vardevall_proto::keys::{NetworkId, NetworkSecret, NodePublic, NodeSecret, PairPsk};
use vardevall_proto::session::KEEPALIVE_TIMEOUT;

pub use vardevall::SwitchPath;

pub use self::diff::{ConfigDiff, Rename};
pub use self::edit::{Field, PeerChange};

use self::raw::{Raw, RawDuration};

/// The default interface MTU (vv-07 §3.2).
pub const DEFAULT_MTU: u16 = 1280;
/// An interface file was rejected.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Not valid TOML, or an unknown key, wrong type or missing required key (vv-07 §2.2).
    #[error("{0}")]
    Syntax(#[from] toml::de::Error),
    /// A key or secret that does not decode (vv-01 §3.2).
    #[error("{field}: not a valid base32 key")]
    Key {
        /// The offending key.
        field: &'static str,
    },
    /// A value outside its domain.
    #[error("{field}: {reason}")]
    Invalid {
        /// The offending key.
        field: &'static str,
        /// What is wrong.
        reason: String,
    },
    /// A key that is recognised but not implemented (vv-07 §2.2).
    #[error("{0} is reserved and not implemented")]
    Reserved(&'static str),
    /// A switch address that does not parse (vv-04 §2.1).
    #[error("switch.address: {0}")]
    Switch(#[from] AddressError),
    /// A `[[stun]]` entry that is not valid (vv-07 §3.6).
    #[error("stun: {0}")]
    Stun(String),
    /// A `[[service]]` error listed in vv-07 §3.7.
    #[error("service: {0}")]
    Service(String),
    /// The node key has a reserved interface identifier in this network (vv-06 §2.2).
    #[error(
        "the node key has a reserved interface identifier in this network; use another key or network_id (vv-06 §2.2)"
    )]
    ReservedIid,
    /// The `[exit]` table is not valid.
    #[error("exit: {0}")]
    Exit(String),
    /// A `[[peer]]` error listed in vv-07 §3.5.
    #[error("peer: {0}")]
    Peer(String),
    /// The interface name violates vv-07 §2.1.
    #[error("interface name {0:?} must match [a-z0-9][a-z0-9_-]{{0,14}}")]
    InterfaceName(String),
}

fn invalid(field: &'static str, reason: &str) -> ConfigError {
    ConfigError::Invalid {
        field,
        reason: reason.to_owned(),
    }
}

/// Facts the file itself does not contain.
#[derive(Debug, Clone)]
pub struct Context {
    /// The interface name: the file stem (vv-07 §2.1).
    pub interface_name: String,
    /// The OS host name, for the default own name (vv-06 §4.2).
    pub hostname: Option<String>,
}

impl Default for Context {
    fn default() -> Self {
        Context {
            interface_name: "vardevall".to_owned(),
            hostname: None,
        }
    }
}

/// Credentials of a `[[turn]]` entry (vv-07 §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnCredentials {
    /// Static `username` and `credential`.
    Static {
        /// The user name.
        username: String,
        /// The credential.
        credential: String,
    },
    /// A command printing credentials as JSON.
    Command(String),
}

/// A `[[turn]]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnConfig {
    /// The server URIs.
    pub urls: Vec<String>,
    /// How to authenticate.
    pub credentials: TurnCredentials,
    /// Higher is tried first.
    pub priority: i32,
}

/// A `[[peer]]` entry.
#[derive(Clone)]
pub struct PeerEntry {
    /// The peer's key.
    pub public_key: NodePublic,
    /// Its DNS name.
    pub name: Option<String>,
    /// Its `static` candidates.
    pub endpoints: Vec<Endpoint>,
    /// Whether the endpoints are known to be on this link (`endpoint_local`).
    pub endpoint_local: bool,
    /// The pair PSK.
    pub preshared_key: Option<PairPsk>,
}

/// A validated interface file.
#[derive(Clone)]
pub struct Config {
    /// The interface name.
    pub name: String,
    /// The node key.
    pub private_key: NodeSecret,
    /// The public half of the node key.
    pub public_key: NodePublic,
    /// The network secret.
    pub network_secret: NetworkSecret,
    /// The network ID in effect.
    pub network_id: NetworkId,
    /// The own DNS name, if any.
    pub own_name: Option<String>,
    /// The UDP port, 0 for random.
    pub listen_port: u16,
    /// The tunnel MTU.
    pub mtu: u16,
    /// The overlay DNS domain, lowercase without trailing dot.
    pub domain: String,
    /// Upstreams for in-domain misses.
    pub forward: Vec<SocketAddr>,
    /// The resolvers of the host, which an exit relays its peers' queries to when `forward` is
    /// empty. The file does not hold them: the host sets them, and the library
    /// never reads them from the system.
    pub system_resolvers: Vec<SocketAddr>,
    /// Time the direct routes get before a metered route is used.
    pub fallback_delay: Duration,
    /// Accept any member of the network.
    pub accept_members: bool,
    /// mDNS announce and discovery.
    pub mdns: bool,
    /// Whether a switch may carry data (vv-05 §4.7).
    pub switch_path: SwitchPath,
    /// The delivery class of the `tun` plane (vv-05 §4.7).
    pub tun_class: DeliveryClass,
    /// Unreported data before the active route is probed (vv-05 §4.9); `None` is off.
    pub detect_timeout: Option<Duration>,
    /// Switches.
    pub switches: Vec<SwitchSpec>,
    /// TURN servers.
    pub turns: Vec<TurnConfig>,
    /// STUN servers in addition to the switches' (vv-05 §3.1).
    pub stun: Vec<StunSpec>,
    /// Services announced to the peers (vve-14).
    pub services: Vec<Service>,
    /// Key-trusted peers.
    pub peers: Vec<PeerEntry>,
    /// The exit this node offers to its key-trusted peers.
    pub exit: Option<ExitServe>,
}

fn key<T: FromStr>(field: &'static str, text: &str) -> Result<T, ConfigError> {
    text.parse().map_err(|_| ConfigError::Key { field })
}

fn valid_interface_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 15
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

fn duration(field: &'static str, raw: RawDuration) -> Result<Duration, ConfigError> {
    match raw {
        RawDuration::Int(0) => Ok(Duration::ZERO),
        RawDuration::Int(_) => Err(invalid(field, "give a duration string such as \"3s\"")),
        RawDuration::Text(t) => value::duration(&t).ok_or_else(|| {
            invalid(
                field,
                "expected e.g. \"3s\", \"250ms\", \"2m\", \"1h\" or 0",
            )
        }),
    }
}

fn parse_turn(t: raw::RawTurn) -> Result<TurnConfig, ConfigError> {
    if t.urls.is_empty()
        || !t
            .urls
            .iter()
            .all(|u| u.starts_with("turn:") || u.starts_with("turns:"))
    {
        return Err(invalid("turn.urls", "expected turn: or turns: URIs"));
    }
    let credentials = match (t.username, t.credential, t.credentials_command) {
        (Some(username), Some(credential), None) => TurnCredentials::Static {
            username,
            credential,
        },
        (None, None, Some(c)) if !c.trim().is_empty() => TurnCredentials::Command(c),
        _ => {
            return Err(invalid(
                "turn",
                "give either username and credential, or credentials_command",
            ));
        }
    };
    Ok(TurnConfig {
        urls: t.urls,
        credentials,
        priority: t.priority.unwrap_or(1),
    })
}

fn parse_stun(s: raw::RawStun) -> Result<StunSpec, ConfigError> {
    let bad = |r: &str| ConfigError::Stun(r.to_owned());
    if s.urls.is_empty()
        || !s
            .urls
            .iter()
            .all(|u| u.starts_with("stun:") || u.starts_with("stuns:"))
    {
        return Err(bad("expected stun: or stuns: URIs"));
    }
    if s.username.is_some() != s.credential.is_some() {
        return Err(bad("give username and credential together"));
    }
    Ok(StunSpec {
        urls: s.urls,
        username: s.username,
        credential: s.credential,
    })
}

fn parse_services(raw: Vec<raw::RawService>) -> Result<Vec<Service>, ConfigError> {
    let bad = |r: String| ConfigError::Service(r);
    if raw.len() > MAX_SERVICES {
        return Err(bad(format!("more than {MAX_SERVICES} entries")));
    }
    let mut out: Vec<Service> = Vec::new();
    for s in raw {
        let proto = match s.proto.as_deref() {
            None | Some("tcp") => Proto::Tcp,
            Some("udp") => Proto::Udp,
            Some(_) => return Err(bad(format!("{}: proto must be \"tcp\" or \"udp\"", s.name))),
        };
        let service =
            Service::new(&s.name, s.port, proto).map_err(|e| bad(format!("{}: {e}", s.name)))?;
        if out.iter().any(|o| o.name() == service.name()) {
            return Err(bad(format!("duplicate name {:?}", s.name)));
        }
        out.push(service);
    }
    Ok(out)
}

fn parse_tun_class(raw: Option<raw::RawTunClass>) -> Result<DeliveryClass, ConfigError> {
    let mut class = DeliveryClass::default();
    let Some(r) = raw else { return Ok(class) };
    match r.band.as_deref() {
        None => {}
        Some("high") => class.band = WantBand::High,
        Some("any") => class.band = WantBand::Any,
        Some(_) => return Err(invalid("tun_class.band", "expected \"high\" or \"any\"")),
    }
    match r.latency.as_deref() {
        None => {}
        Some("low") => class.latency = WantLatency::Low,
        Some("any") => class.latency = WantLatency::Any,
        Some(_) => return Err(invalid("tun_class.latency", "expected \"low\" or \"any\"")),
    }
    if let Some(d) = r.degrade {
        class.degrade = d;
    }
    Ok(class)
}

fn parse_exit(e: raw::RawExit) -> Result<ExitServe, ConfigError> {
    let site = e
        .site
        .parse()
        .map_err(|err| ConfigError::Exit(format!("site {:?}: {err}", e.site)))?;
    Ok(ExitServe {
        site,
        ipv4: e.ipv4.unwrap_or(true),
    })
}

fn parse_peer(p: raw::RawPeer) -> Result<PeerEntry, ConfigError> {
    let public_key = key("peer.public_key", &p.public_key)?;
    if let Some(n) = &p.name
        && !value::name_label(n)
    {
        return Err(ConfigError::Peer(format!(
            "name {n:?} is not a valid label"
        )));
    }
    let endpoints = match &p.endpoint {
        None => Vec::new(),
        Some(t) => vec![
            value::endpoint(t)
                .ok_or_else(|| invalid("peer.endpoint", &format!("{t:?} is not valid")))?,
        ],
    };
    let endpoint_local = p.endpoint_local.unwrap_or(false);
    if endpoint_local && endpoints.is_empty() {
        return Err(invalid("peer.endpoint_local", "the peer has no endpoint"));
    }
    let preshared_key = p
        .preshared_key
        .map(|s| key::<PairPsk>("peer.preshared_key", &s))
        .transpose()?;
    Ok(PeerEntry {
        public_key,
        name: p.name,
        endpoints,
        endpoint_local,
        preshared_key,
    })
}

impl Config {
    /// The resolvers queries are relayed to: `forward`, else, for a node that serves an exit,
    /// the resolvers of the host.
    pub fn upstreams(&self) -> Vec<SocketAddr> {
        if !self.forward.is_empty() {
            self.forward.clone()
        } else if self.exit.is_some() {
            self.system_resolvers.clone()
        } else {
            Vec::new()
        }
    }

    /// Parses and validates an interface file (vv-07 §3).
    pub fn parse(text: &str, ctx: &Context) -> Result<Config, ConfigError> {
        if !valid_interface_name(&ctx.interface_name) {
            return Err(ConfigError::InterfaceName(ctx.interface_name.clone()));
        }
        let raw: Raw = toml::from_str(text)?;
        let i = raw.interface;
        for (set, name) in [
            (i.roster.is_some(), "roster"),
            (i.roster_key.is_some(), "roster_key"),
        ] {
            if set {
                return Err(ConfigError::Reserved(name));
            }
        }
        let private_key: NodeSecret = key("private_key", &i.private_key)?;
        let network_secret: NetworkSecret = key("network_secret", &i.network_secret)?;
        let network_id = match &i.network_id {
            Some(s) => key("network_id", s)?,
            None => network_secret.default_network_id(),
        };
        let public_key = private_key.public();
        if addr::is_reserved_iid(&OverlayAddrs::derive(&network_id, &public_key).iid) {
            return Err(ConfigError::ReservedIid);
        }

        let own_name = match &i.name {
            Some(n) if value::name_label(n) => Some(n.clone()),
            Some(_) => return Err(invalid("name", "not a valid label (vv-06 §4.2)")),
            None => ctx.hostname.as_deref().and_then(addr::sanitise_hostname),
        };
        let mtu = match i.mtu {
            None => DEFAULT_MTU,
            Some(m) if (1280..=65_000).contains(&m) => u16::try_from(m).unwrap_or(DEFAULT_MTU),
            Some(_) => return Err(invalid("mtu", "must be between 1280 and 65000")),
        };
        let domain = match &i.domain {
            Some(d) => value::domain(d).ok_or_else(|| invalid("domain", "not a valid DNS name"))?,
            None => format!("{}.internal", ctx.interface_name),
        };
        let forward = i
            .forward
            .unwrap_or_default()
            .iter()
            .map(|s| {
                s.parse::<SocketAddr>()
                    .map_err(|_| invalid("forward", &format!("{s:?} is not a socket address")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let fallback_delay = match i.fallback_delay {
            None => vardevall::FALLBACK_DELAY,
            Some(d) => duration("fallback_delay", d)?,
        };
        let switch_path = match i.switch_path.as_deref() {
            None | Some("on") => SwitchPath::On,
            Some("off") => SwitchPath::Off,
            Some(_) => return Err(invalid("switch_path", "expected \"on\" or \"off\"")),
        };
        let tun_class = parse_tun_class(i.tun_class)?;
        let detect_timeout = match i.detect_timeout {
            None => None,
            Some(d) => {
                let d = duration("detect_timeout", d)?;
                if d.is_zero() || d > KEEPALIVE_TIMEOUT {
                    return Err(invalid(
                        "detect_timeout",
                        "must be above 0 and at most KEEPALIVE_TIMEOUT (10s); omit it for DETECT_TIMEOUT (2s)",
                    ));
                }
                Some(d)
            }
        };

        let switches = raw
            .switch
            .into_iter()
            .map(|s| SwitchSpec::parse(&s.address, s.token).map_err(ConfigError::from))
            .collect::<Result<_, _>>()?;
        let stun = raw
            .stun
            .into_iter()
            .map(parse_stun)
            .collect::<Result<_, _>>()?;
        let services = parse_services(raw.service)?;
        let turns = raw
            .turn
            .into_iter()
            .map(parse_turn)
            .collect::<Result<_, _>>()?;
        let exit = raw.exit.map(parse_exit).transpose()?;
        let peers: Vec<PeerEntry> = raw
            .peer
            .into_iter()
            .map(parse_peer)
            .collect::<Result<_, _>>()?;

        let mut seen: Vec<&NodePublic> = Vec::new();
        let mut names: Vec<&str> = own_name.iter().map(String::as_str).collect();
        for p in &peers {
            if p.public_key == public_key {
                return Err(ConfigError::Peer(
                    "a peer has the interface's own key".into(),
                ));
            }
            if seen.contains(&&p.public_key) {
                return Err(ConfigError::Peer(format!("duplicate key {}", p.public_key)));
            }
            seen.push(&p.public_key);
            if let Some(n) = &p.name {
                if names.contains(&n.as_str()) {
                    return Err(ConfigError::Peer(format!("duplicate name {n:?}")));
                }
                names.push(n);
            }
        }

        Ok(Config {
            name: ctx.interface_name.clone(),
            private_key,
            public_key,
            network_secret,
            network_id,
            own_name,
            listen_port: i.listen_port.unwrap_or(0),
            mtu,
            domain,
            forward,
            system_resolvers: Vec::new(),
            fallback_delay,
            accept_members: i.accept_members.unwrap_or(false),
            mdns: i.mdns.unwrap_or(true),
            switch_path,
            tun_class,
            detect_timeout,
            switches,
            turns,
            stun,
            services,
            peers,
            exit,
        })
    }

    /// The node's own overlay addresses (vv-06 §2.1).
    pub fn own_addrs(&self) -> OverlayAddrs {
        OverlayAddrs::derive(&self.network_id, &self.public_key)
    }

    /// The key-trusted peers as the engine takes them.
    pub fn peer_specs(&self) -> Vec<PeerSpec> {
        self.peers
            .iter()
            .map(|p| PeerSpec {
                public: p.public_key,
                psk: p.preshared_key.clone(),
                endpoints: p.endpoints.clone(),
                endpoints_local: p.endpoint_local,
            })
            .collect()
    }

    /// The `[[turn]]` entries the engine can use, those with static credentials.
    pub fn turn_specs(&self) -> Vec<vardevall::TurnSpec> {
        self.turns
            .iter()
            .filter_map(|t| match &t.credentials {
                TurnCredentials::Static {
                    username,
                    credential,
                } => Some(vardevall::TurnSpec {
                    urls: t.urls.clone(),
                    username: username.clone(),
                    credential: credential.clone(),
                    priority: t.priority,
                }),
                TurnCredentials::Command(_) => None,
            })
            .collect()
    }

    /// The settings for [`vardevall::Node`].
    pub fn node_config(&self, mdns: MdnsMode) -> NodeConfig {
        NodeConfig {
            secret: self.private_key.clone(),
            network_secret: self.network_secret.clone(),
            network_id: Some(self.network_id),
            listen_port: self.listen_port,
            mtu: usize::from(self.mtu),
            accept_members: self.accept_members,
            fallback_delay: self.fallback_delay,
            mdns,
            peers: self.peer_specs(),
            switches: self.switches.clone(),
            turn: self.turn_specs(),
            switch_path: self.switch_path,
            tun_class: self.tun_class,
            detect_timeout: self.detect_timeout,
            stun: self.stun.clone(),
            services: self.services.clone(),
            dns_servers: Vec::new(),
            watch_network: false,
            watch_exclude: Vec::new(),
            discovery: Vec::new(),
            exit: self.exit.clone(),
            socket_mark: vardevall::SocketMark::NONE,
        }
    }
}
