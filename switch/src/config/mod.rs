//! The switch configuration file (vv-07 §6).

mod raw;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use http::HeaderName;
use ipnet::IpNet;
use thiserror::Error;
use vardevall_switch_proto::api::normalize_host;

use self::raw::{Raw, RawDuration};

/// A configuration file was rejected.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Not valid TOML, or an unknown key or wrong type. Quoted values are left out of the text
    /// (they may be tokens or secrets).
    #[error("line {line}: {message}")]
    Syntax {
        /// The line of the error, from 1.
        line: usize,
        /// What is wrong, without quoted values.
        message: String,
    },
    /// A value outside its domain.
    #[error("{field}: {reason}")]
    Invalid {
        /// The offending key.
        field: &'static str,
        /// What is wrong.
        reason: String,
    },
    /// The TURN secret file could not be read.
    #[error("reading the TURN secret file {path}: {source}")]
    SecretFile {
        /// The path.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// The configuration file could not be read.
    #[error("reading {path}: {source}")]
    File {
        /// The path.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// The token file could not be read.
    #[error("reading the token file {path}: {source}")]
    TokenFile {
        /// The path.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
}

fn syntax(text: &str, e: &toml::de::Error) -> ConfigError {
    let line = e.span().map_or(1, |s| {
        text.as_bytes()[..s.start.min(text.len())]
            .iter()
            .filter(|&&b| b == b'\n')
            .count()
            + 1
    });
    let mut message = String::new();
    let mut quoted = false;
    for c in e.message().chars() {
        match (c, quoted) {
            ('"', false) => {
                quoted = true;
                message.push_str("\"…\"");
            }
            ('"', true) => quoted = false,
            (_, false) => message.push(c),
            _ => {}
        }
    }
    ConfigError::Syntax { line, message }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        field,
        reason: reason.into(),
    }
}

/// Rates and caps (vv-04 §8); every value is a conservative default unless the file sets it.
#[derive(Debug, Clone, PartialEq)]
pub struct Limits {
    /// Largest decoded forwarded message, at least 4096 (vv-04 §3.4).
    pub max_forward_size: usize,
    /// Registrations held at once.
    pub max_registrations: usize,
    /// Networks held at once.
    pub max_networks: usize,
    /// Members of one network held at once.
    pub registrations_per_network: usize,
    /// Open events streams.
    pub max_event_streams: usize,
    /// Open connections.
    pub max_connections: usize,
    /// Open connections from one client address.
    pub max_connections_per_ip: usize,
    /// Sustained `register` and `challenge` requests per second from one client address (IPv6 per
    /// /64).
    pub per_ip_rate: f64,
    /// Burst of the per-address limit.
    pub per_ip_burst: f64,
    /// Sustained STUN and TURN requests per second from one client address (IPv6 per /64), on the
    /// UDP ports of the embedded servers.
    pub stun_rate: f64,
    /// Burst of the per-address STUN limit.
    pub stun_burst: f64,
    /// Sustained registrations per second of one network.
    pub register_rate: f64,
    /// Burst of the per-network registration limit.
    pub register_burst: f64,
    /// Sustained `members` requests per second of one network.
    pub members_rate: f64,
    /// Burst of the per-network `members` limit.
    pub members_burst: f64,
    /// Sustained `forward` requests per second of one network.
    pub forwards_per_second: f64,
    /// Burst of the per-network `forward` limit.
    pub forwards_burst: f64,
    /// Sustained forwarded bytes per second of one sender (vv-04 §3.4 `forward_limits`).
    pub sender_bytes_per_second: f64,
    /// Burst of the per-sender byte limit.
    pub sender_bytes_burst: f64,
    /// Sustained forwarded bytes per second of one network.
    pub network_bytes_per_second: f64,
    /// Burst of the per-network byte limit.
    pub network_bytes_burst: f64,
    /// Bytes one session may forward in total (vv-04 §3.4 `forward_limits`).
    pub session_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_forward_size: 4096,
            max_registrations: 10_000,
            max_networks: 2_000,
            registrations_per_network: 256,
            max_event_streams: 10_000,
            max_connections: 20_000,
            max_connections_per_ip: 256,
            per_ip_rate: 0.5,
            per_ip_burst: 20.0,
            stun_rate: 20.0,
            stun_burst: 100.0,
            register_rate: 2.0,
            register_burst: 30.0,
            members_rate: 5.0,
            members_burst: 30.0,
            forwards_per_second: 20.0,
            forwards_burst: 100.0,
            sender_bytes_per_second: 8_000.0,
            sender_bytes_burst: 32_768.0,
            network_bytes_per_second: 65_536.0,
            network_bytes_burst: 262_144.0,
            session_bytes: 50_000_000,
        }
    }
}

/// Time limits that bound slow clients.
#[derive(Debug, Clone, PartialEq)]
pub struct Timeouts {
    /// From accept to the end of the TLS handshake.
    pub tls_handshake: Duration,
    /// From the first byte of a request to the end of its headers.
    pub request_header: Duration,
    /// To read a request body.
    pub request_body: Duration,
    /// Silence on a connection with no open request before it is closed.
    pub idle: Duration,
    /// Time a client has to open the events stream after registering (vv-04 §7.3).
    pub reconnect_grace: Duration,
    /// Longest gap between two writes on an events stream (vv-04 §7.1).
    pub keepalive: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            tls_handshake: Duration::from_secs(10),
            request_header: Duration::from_secs(10),
            request_body: Duration::from_secs(10),
            idle: Duration::from_secs(120),
            reconnect_grace: Duration::from_secs(30),
            keepalive: Duration::from_secs(10),
        }
    }
}

/// Embedded STUN server and the STUN URIs advertised in `/v0/info` (vv-04 §3.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stun {
    /// UDP addresses of the embedded Binding server; empty runs none.
    pub listen: Vec<SocketAddr>,
    /// STUN URIs [RFC 7064] listed in `stun`.
    pub uris: Vec<String>,
    /// Whether the STUN servers answer only requests with a credential of vv-04 §4.7
    /// (`stun_auth` in `/v0/info`).
    pub auth: bool,
}

/// How registrations are bound (vv-04 §4.1), as advertised in `/v0/info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Binding {
    /// The TLS exporter: TLS ends at the switch.
    #[default]
    Exporter,
    /// A switch challenge: a terminating proxy sits in front (vv-04 §2.5).
    Challenge,
}

impl Binding {
    /// The value of `binding` in `/v0/info`.
    pub fn as_str(self) -> &'static str {
        match self {
            Binding::Exporter => "exporter",
            Binding::Challenge => "challenge",
        }
    }
}

/// A header that carries the client address, accepted only from `from` (vv-04 §2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedHeader {
    /// The header name: `Forwarded` [RFC 7239], `X-Forwarded-For`, or a proxy's own, such as
    /// `CF-Connecting-IP`.
    pub name: HeaderName,
    /// The connection peers whose header is believed.
    pub from: Vec<IpNet>,
}

/// The embedded TURN server [RFC 8656], which accepts the credentials of vv-04 §4.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnServer {
    /// UDP addresses; each also answers STUN Binding requests.
    pub listen: Vec<SocketAddr>,
    /// The local IPv4 address relayed transport addresses are bound to; reported to clients
    /// unless `relay_ipv4_public` is set.
    pub relay_ipv4: Option<std::net::Ipv4Addr>,
    /// The local IPv6 address relayed transport addresses are bound to; reported to clients
    /// unless `relay_ipv6_public` is set.
    pub relay_ipv6: Option<std::net::Ipv6Addr>,
    /// The IPv4 address clients reach `relay_ipv4` at, when a 1:1 NAT maps it to the local one.
    pub relay_ipv4_public: Option<std::net::Ipv4Addr>,
    /// The IPv6 address clients reach `relay_ipv6` at, when a 1:1 NAT maps it to the local one.
    pub relay_ipv6_public: Option<std::net::Ipv6Addr>,
    /// Ports of relayed transport addresses, inclusive.
    pub relay_ports: (u16, u16),
    /// The realm of long-term credentials.
    pub realm: String,
    /// Allocations held at once.
    pub max_allocations: usize,
    /// Allocations one credential may hold.
    pub allocations_per_credential: usize,
    /// Allocations one client address may hold.
    pub allocations_per_ip: usize,
    /// Whether peers in private, loopback and link-local ranges are allowed.
    pub allow_private_peers: bool,
    /// Whether TURN over TLS is accepted on the HTTPS listeners, selected by ALPN `stun.turn`
    /// (vv-04 §2.3).
    pub tls: bool,
}

/// Advertised and enforced rate per allocation when the embedded server is run without one
/// configured, in bits per second.
pub const DEFAULT_TURN_BITS_PER_SECOND: u64 = 10_000_000;
/// Advertised and enforced volume per credential when the embedded server is run without one
/// configured, in bytes.
pub const DEFAULT_TURN_BYTES: u64 = 10_000_000_000;

/// TURN credentials issued to members (vv-04 §4.5). With `server` the switch relays itself;
/// otherwise `urls` name an external TURN server, such as coturn, that shares the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Turn {
    /// TURN URIs [RFC 7065] sent to clients.
    pub urls: Vec<String>,
    /// The shared secret (coturn `static-auth-secret`).
    pub secret: String,
    /// Validity of one credential.
    pub ttl: Duration,
    /// Advertised sustained rate per allocation, bits per second.
    pub bits_per_second: Option<u64>,
    /// Advertised volume per credential, bytes.
    pub bytes: Option<u64>,
    /// Whether the embedded server stays silent to requests without valid credentials
    /// (vv-04 §4.5). Credentials then always carry `realm` and `nonce`.
    pub silent: bool,
    /// The embedded server, if the operator runs one; it enforces `bits_per_second` and `bytes`.
    pub server: Option<TurnServer>,
}

impl std::fmt::Debug for Turn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Turn")
            .field("urls", &self.urls)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

/// TURN limits of the holders of one operator token (vv-04 §4.5 "per operator token"). A field
/// left out inherits the value of `[turn]`; `0` means unlimited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenTurn {
    /// The operator token, as listed in `tokens`.
    pub token: String,
    /// Sustained rate per allocation, bits per second.
    pub bits_per_second: Option<u64>,
    /// Volume per credential, bytes.
    pub bytes: Option<u64>,
}

impl TokenTurn {
    /// The limits of this token over the defaults `base` of `[turn]`.
    pub fn limits_over(&self, base: TurnLimits) -> TurnLimits {
        let pick = |v: Option<u64>, d: Option<u64>| match v {
            Some(0) => None,
            Some(v) => Some(v),
            None => d,
        };
        TurnLimits {
            bits_per_second: pick(self.bits_per_second, base.bits_per_second),
            bytes: pick(self.bytes, base.bytes),
        }
    }
}

/// The settings a reload re-reads (`[tokens]` and the token file): the accepted operator tokens
/// and the TURN limits of some of them. Nothing else in the file is applied after start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenSettings {
    /// Accepted operator tokens; empty means open registration (vv-04 §3.4).
    pub tokens: Vec<String>,
    /// TURN limits that differ per operator token.
    pub token_turn: Vec<TokenTurn>,
    /// Whether the file names a source of tokens (`accepted` or `file`), even an empty one.
    pub configured: bool,
}

impl TokenSettings {
    /// The token settings of the configuration `text`; relative paths are taken relative to
    /// `base`. The whole file must still have the shape of a configuration file, but values
    /// outside `[tokens]` are not checked and no other file is read.
    pub fn parse(text: &str, base: &Path) -> Result<TokenSettings, ConfigError> {
        let raw: Raw = toml::from_str(text).map_err(|e| syntax(text, &e))?;
        Self::from_raw(raw.tokens, base)
    }

    /// The token settings of the configuration file `path`, resolved as at start.
    pub fn load(path: &Path) -> Result<TokenSettings, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::File {
            path: path.to_owned(),
            source,
        })?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::parse(&text, base)
    }

    fn from_raw(raw: raw::RawTokens, base: &Path) -> Result<TokenSettings, ConfigError> {
        let configured = raw.accepted.is_some() || raw.file.is_some();
        let mut tokens = raw.accepted.unwrap_or_default();
        if let Some(file) = raw.file {
            let path = base.join(file);
            let text = std::fs::read_to_string(&path)
                .map_err(|source| ConfigError::TokenFile { path, source })?;
            tokens.extend(
                text.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_owned),
            );
        }
        if tokens.iter().any(|t| t.is_empty() || !t.is_ascii()) {
            return Err(invalid("tokens", "tokens must be non-empty ASCII"));
        }
        let token_turn: Vec<TokenTurn> = raw
            .turn
            .into_iter()
            .map(|t| TokenTurn {
                token: t.token,
                bits_per_second: t.bits_per_second,
                bytes: t.bytes,
            })
            .collect();
        for t in &token_turn {
            if !tokens.contains(&t.token) {
                return Err(invalid(
                    "tokens.turn",
                    "a token with TURN limits must also be accepted (tokens.accepted or tokens.file)",
                ));
            }
        }
        if token_turn.len() > 250 {
            return Err(invalid("tokens.turn", "at most 250 entries"));
        }
        Ok(TokenSettings {
            tokens,
            token_turn,
            configured,
        })
    }
}

/// The TURN limits of one credential: what the switch advertises and the TURN server enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TurnLimits {
    /// Sustained rate per allocation, bits per second.
    pub bits_per_second: Option<u64>,
    /// Volume per credential, bytes.
    pub bytes: Option<u64>,
}

/// Where the X.509 certificate for browsers comes from (vv-04 §2.3, vv-07 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Certificate {
    /// A PEM certificate chain, leaf first, and its PEM private key. The files are read again on
    /// SIGHUP and when they change.
    Files {
        /// The certificate chain.
        cert_file: PathBuf,
        /// The private key.
        key_file: PathBuf,
        /// The DNS names served as web addresses with this certificate (vv-04 §2.3).
        names: Vec<String>,
    },
    /// A certificate from an ACME CA, obtained and renewed with TLS-ALPN-01 on the HTTPS port.
    Acme(Acme),
}

impl Certificate {
    /// The names that get this certificate; every other name gets the pinned one.
    pub fn names(&self) -> Vec<String> {
        match self {
            Certificate::Files { names, .. } => names.clone(),
            Certificate::Acme(a) => vec![a.domain.clone()],
        }
    }
}

/// The ACME form of `certificate` (vv-07 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acme {
    /// The DNS name to certify; the switch must answer on port 443 at this name.
    pub domain: String,
    /// Contact URI for the CA (`mailto:...`).
    pub contact: Option<String>,
    /// The ACME directory URL; Let's Encrypt production if `None`.
    pub directory: Option<String>,
    /// Where the account key and the certificate are kept between runs. Without it nothing is
    /// written to disk and a certificate is requested at every start.
    pub cache_dir: Option<PathBuf>,
    /// PEM roots to trust for the directory instead of the Web PKI (a private CA or a test CA).
    pub ca_file: Option<PathBuf>,
}

/// How often the status line is logged unless the file says otherwise.
pub const DEFAULT_STATUS_INTERVAL: Option<Duration> = Some(Duration::from_secs(600));

/// A validated switch configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Addresses to listen on for TLS: TCP, and UDP for HTTP/3.
    pub listen: Vec<SocketAddr>,
    /// Loopback addresses that serve plain HTTP, for a tunnel daemon that terminates TLS
    /// (vv-04 §2.5).
    pub plain_listen: Vec<SocketAddr>,
    /// The file holding the Ed25519 seed, base32.
    pub key_file: PathBuf,
    /// The Web PKI certificate for web addresses and browsers (vv-04 §2.3), if any.
    pub certificate: Option<Certificate>,
    /// Hosts, besides the web names, that registrations may name (vv-04 §4.3, §4.4 step 3), in
    /// normal form: the host of every pinned address and, behind a proxy, the public names.
    pub names: Vec<String>,
    /// The binding advertised in `/v0/info` (vv-04 §3.4).
    pub binding: Binding,
    /// Connection peers that send the PROXY protocol, version 2, first (vv-04 §2.5).
    pub proxy_protocol: Vec<IpNet>,
    /// The header that carries the client address, and the peers it is believed from.
    pub forwarded_header: Option<ForwardedHeader>,
    /// How often the status line is logged; `None` logs none.
    pub status_interval: Option<Duration>,
    /// Accepted operator tokens; empty means open registration (vv-04 §3.4).
    pub tokens: Vec<String>,
    /// TURN limits that differ per operator token; the credentials of their holders carry the
    /// class `index + 1` (0 is the default of `[turn]`).
    pub token_turn: Vec<TokenTurn>,
    /// Rates and caps.
    pub limits: Limits,
    /// Time limits.
    pub timeouts: Timeouts,
    /// STUN.
    pub stun: Stun,
    /// TURN credentials, if the operator offers TURN.
    pub turn: Option<Turn>,
}

impl Config {
    /// A configuration for tests and embedding: no tokens, default limits.
    pub fn new(listen: Vec<SocketAddr>, key_file: PathBuf) -> Self {
        Config {
            listen,
            plain_listen: Vec::new(),
            key_file,
            certificate: None,
            names: Vec::new(),
            binding: Binding::default(),
            proxy_protocol: Vec::new(),
            forwarded_header: None,
            status_interval: DEFAULT_STATUS_INTERVAL,
            tokens: Vec::new(),
            token_turn: Vec::new(),
            limits: Limits::default(),
            timeouts: Timeouts::default(),
            stun: Stun::default(),
            turn: None,
        }
    }

    /// The DNS names served as web addresses (vv-04 §2.3).
    pub fn web_names(&self) -> Vec<String> {
        self.certificate
            .as_ref()
            .map(Certificate::names)
            .unwrap_or_default()
    }

    /// Every host a registration may name, in normal form: the web names and `names`.
    pub fn served_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .web_names()
            .iter()
            .chain(&self.names)
            .filter_map(|n| normalize_host(n))
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// The TURN limits of credential class `class`: 0 is the default of `[turn]`, `n` the entry
    /// `n - 1` of `token_turn` over it.
    pub fn turn_limits(&self, class: u8) -> TurnLimits {
        let base = TurnLimits {
            bits_per_second: self.turn.as_ref().and_then(|t| t.bits_per_second),
            bytes: self.turn.as_ref().and_then(|t| t.bytes),
        };
        let Some(t) = usize::from(class)
            .checked_sub(1)
            .and_then(|i| self.token_turn.get(i))
        else {
            return base;
        };
        t.limits_over(base)
    }

    /// Parses a configuration; relative `key_file` and `tokens.file` paths are taken relative to
    /// `base`.
    pub fn parse(text: &str, base: &Path) -> Result<Config, ConfigError> {
        let raw: Raw = toml::from_str(text).map_err(|e| syntax(text, &e))?;
        let addresses = |v: Vec<String>, field| {
            v.iter()
                .map(|a| {
                    a.parse::<SocketAddr>()
                        .map_err(|_| invalid(field, format!("{a:?} is not a socket address")))
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let plain_listen = addresses(raw.plain_listen.unwrap_or_default(), "plain_listen")?;
        if plain_listen.iter().any(|a| !a.ip().is_loopback()) {
            return Err(invalid(
                "plain_listen",
                "plain HTTP may only listen on loopback addresses",
            ));
        }
        let listen = match raw.listen {
            Some(v) => addresses(v, "listen")?,
            None if plain_listen.is_empty() => {
                vec![SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 443))]
            }
            None => Vec::new(),
        };
        if listen.is_empty() && plain_listen.is_empty() {
            return Err(invalid("listen", "at least one address is required"));
        }
        let key_file = base.join(&raw.key_file);
        let certificate = raw
            .certificate
            .map(|c| parse_certificate(c, base))
            .transpose()?;
        if certificate.is_some() && listen.is_empty() {
            return Err(invalid(
                "certificate",
                "needs a TLS listener: listen is empty",
            ));
        }
        let names = raw
            .names
            .unwrap_or_default()
            .iter()
            .map(|n| {
                normalize_host(n).ok_or_else(|| {
                    invalid(
                        "names",
                        "expected DNS names, IPv4 or IPv6 addresses, without port",
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let binding = match raw.binding.as_deref() {
            None | Some("exporter") => Binding::Exporter,
            Some("challenge") => Binding::Challenge,
            Some(_) => return Err(invalid("binding", "expected \"exporter\" or \"challenge\"")),
        };
        let networks = |v: Vec<String>, field| {
            v.iter()
                .map(|n| {
                    n.parse::<IpNet>()
                        .or_else(|_| n.parse::<std::net::IpAddr>().map(IpNet::from))
                        .map_err(|_| invalid(field, format!("{n:?} is not an address or range")))
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let proxy_protocol = networks(raw.proxy_protocol.unwrap_or_default(), "proxy_protocol")?;
        let forwarded_header = raw
            .forwarded_header
            .map(|f| {
                let name = HeaderName::from_bytes(f.name.to_ascii_lowercase().as_bytes())
                    .map_err(|_| invalid("forwarded_header.name", "not a header name"))?;
                if f.from.is_empty() {
                    return Err(invalid(
                        "forwarded_header.from",
                        "at least one source is required",
                    ));
                }
                Ok(ForwardedHeader {
                    name,
                    from: networks(f.from, "forwarded_header.from")?,
                })
            })
            .transpose()?;
        let status_interval = match raw.log.status_interval {
            None => DEFAULT_STATUS_INTERVAL,
            Some(v) => {
                let d = v.parse().ok_or_else(|| {
                    invalid("log.status_interval", "expected a duration such as \"10m\"")
                })?;
                (!d.is_zero()).then_some(d)
            }
        };

        let TokenSettings {
            tokens, token_turn, ..
        } = TokenSettings::from_raw(raw.tokens, base)?;

        let mut limits = Limits::default();
        let l = raw.limits;
        let size = |v: Option<u64>, field, min: u64, d: usize| -> Result<usize, ConfigError> {
            match v {
                None => Ok(d),
                Some(v) if v >= min => {
                    usize::try_from(v).map_err(|_| invalid(field, "out of range"))
                }
                Some(_) => Err(invalid(field, format!("must be at least {min}"))),
            }
        };
        limits.max_forward_size = size(l.max_forward_size, "max_forward_size", 4096, 4096)?;
        limits.max_registrations = size(
            l.max_registrations,
            "max_registrations",
            1,
            limits.max_registrations,
        )?;
        limits.max_networks = size(l.max_networks, "max_networks", 1, limits.max_networks)?;
        limits.registrations_per_network = size(
            l.registrations_per_network,
            "registrations_per_network",
            1,
            limits.registrations_per_network,
        )?;
        limits.max_event_streams = size(
            l.max_event_streams,
            "max_event_streams",
            1,
            limits.max_event_streams,
        )?;
        limits.max_connections = size(
            l.max_connections,
            "max_connections",
            1,
            limits.max_connections,
        )?;
        limits.max_connections_per_ip = size(
            l.max_connections_per_ip,
            "max_connections_per_ip",
            1,
            limits.max_connections_per_ip,
        )?;
        let rate = |v: Option<f64>, field, d: f64| -> Result<f64, ConfigError> {
            match v {
                None => Ok(d),
                Some(v) if v.is_finite() && v > 0.0 => Ok(v),
                Some(_) => Err(invalid(field, "must be a positive number")),
            }
        };
        limits.stun_rate = rate(
            l.stun_per_ip_per_second,
            "stun_per_ip_per_second",
            limits.stun_rate,
        )?;
        limits.stun_burst = rate(l.stun_per_ip_burst, "stun_per_ip_burst", limits.stun_burst)?;
        limits.per_ip_rate = rate(
            l.register_per_ip_per_second,
            "register_per_ip_per_second",
            limits.per_ip_rate,
        )?;
        limits.per_ip_burst = rate(
            l.register_per_ip_burst,
            "register_per_ip_burst",
            limits.per_ip_burst,
        )?;
        limits.register_rate = rate(
            l.register_per_network_per_second,
            "register_per_network_per_second",
            limits.register_rate,
        )?;
        limits.register_burst = rate(
            l.register_per_network_burst,
            "register_per_network_burst",
            limits.register_burst,
        )?;
        limits.members_rate = rate(
            l.members_per_second,
            "members_per_second",
            limits.members_rate,
        )?;
        limits.members_burst = rate(l.members_burst, "members_burst", limits.members_burst)?;
        limits.forwards_per_second = rate(
            l.forwards_per_second,
            "forwards_per_second",
            limits.forwards_per_second,
        )?;
        limits.forwards_burst = rate(l.forwards_burst, "forwards_burst", limits.forwards_burst)?;
        limits.sender_bytes_per_second = rate(
            l.sender_bytes_per_second,
            "sender_bytes_per_second",
            limits.sender_bytes_per_second,
        )?;
        limits.sender_bytes_burst = rate(
            l.sender_bytes_burst,
            "sender_bytes_burst",
            limits.sender_bytes_burst,
        )?;
        limits.network_bytes_per_second = rate(
            l.network_bytes_per_second,
            "network_bytes_per_second",
            limits.network_bytes_per_second,
        )?;
        limits.network_bytes_burst = rate(
            l.network_bytes_burst,
            "network_bytes_burst",
            limits.network_bytes_burst,
        )?;
        limits.session_bytes = l.session_bytes.unwrap_or(limits.session_bytes);
        let floor = limits.max_forward_size as f64;
        if limits.sender_bytes_burst < floor || limits.network_bytes_burst < floor {
            return Err(invalid(
                "sender_bytes_burst",
                "byte bursts must hold at least one max_forward_size message",
            ));
        }

        let mut timeouts = Timeouts::default();
        let t = raw.timeouts;
        let dur = |v: Option<RawDuration>, field, d: Duration| -> Result<Duration, ConfigError> {
            match v {
                None => Ok(d),
                Some(v) => v
                    .parse()
                    .filter(|d| !d.is_zero())
                    .ok_or_else(|| invalid(field, "expected a duration such as \"10s\"")),
            }
        };
        timeouts.tls_handshake = dur(t.tls_handshake, "tls_handshake", timeouts.tls_handshake)?;
        timeouts.request_header = dur(t.request_header, "request_header", timeouts.request_header)?;
        timeouts.request_body = dur(t.request_body, "request_body", timeouts.request_body)?;
        timeouts.idle = dur(t.idle, "idle", timeouts.idle)?;
        timeouts.reconnect_grace = dur(
            t.reconnect_grace,
            "reconnect_grace",
            timeouts.reconnect_grace,
        )?;
        timeouts.keepalive = dur(t.keepalive, "keepalive", timeouts.keepalive)?;
        if timeouts.keepalive > Duration::from_secs(15) {
            return Err(invalid("keepalive", "vv-04 §7.1 requires at most 15 s"));
        }

        let stun = parse_stun(raw.stun)?;
        let turn = raw.turn.map(|t| parse_turn(t, base)).transpose()?;
        #[cfg(not(feature = "stun-turn"))]
        if !stun.listen.is_empty() || turn.as_ref().is_some_and(|t| t.server.is_some()) {
            return Err(invalid(
                "stun",
                "this build has no embedded STUN or TURN server (feature stun-turn)",
            ));
        }
        if stun.auth && turn.is_none() {
            return Err(invalid(
                "stun.auth",
                "needs [turn]: STUN credentials are made with its secret",
            ));
        }

        let config = Config {
            listen,
            plain_listen,
            key_file,
            certificate,
            names,
            binding,
            proxy_protocol,
            forwarded_header,
            status_interval,
            tokens,
            token_turn,
            limits,
            timeouts,
            stun,
            turn,
        };
        if config.served_hosts().is_empty() {
            return Err(invalid(
                "names",
                "list the hosts clients register with: the host of the pinned address, \
                 `<key>@host`, or the public name behind a proxy (vv-04 §4.4); a web \
                 certificate names its own",
            ));
        }
        Ok(config)
    }
}

fn parse_certificate(c: raw::RawCertificate, base: &Path) -> Result<Certificate, ConfigError> {
    let acme_only = c.contact.is_some()
        || c.directory.is_some()
        || c.cache_dir.is_some()
        || c.ca_file.is_some();
    match (c.cert_file, c.key_file, c.acme) {
        (Some(cert_file), Some(key_file), None) if !acme_only => {
            let names = c
                .names
                .unwrap_or_default()
                .iter()
                .map(|n| {
                    dns_name(n).ok_or_else(|| invalid("certificate.names", "expected DNS names"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if names.is_empty() {
                return Err(invalid(
                    "certificate.names",
                    "list the DNS names that get this certificate; every other name gets the pinned one",
                ));
            }
            Ok(Certificate::Files {
                cert_file: base.join(cert_file),
                key_file: base.join(key_file),
                names,
            })
        }
        (None, None, Some(domain)) if c.names.is_none() => {
            let name = dns_name(&domain)
                .ok_or_else(|| invalid("certificate.acme", "expected a DNS name"))?;
            let contact = c.contact.map(|m| {
                if m.contains(':') {
                    m
                } else {
                    format!("mailto:{m}")
                }
            });
            if let Some(d) = &c.directory
                && !d.starts_with("https://")
            {
                return Err(invalid("certificate.directory", "expected an https URL"));
            }
            Ok(Certificate::Acme(Acme {
                domain: name,
                contact,
                directory: c.directory,
                cache_dir: c.cache_dir.map(|d| base.join(d)),
                ca_file: c.ca_file.map(|f| base.join(f)),
            }))
        }
        _ => Err(invalid(
            "certificate",
            "expected cert_file, key_file and names, or acme with contact, directory, cache_dir, ca_file",
        )),
    }
}

fn dns_name(text: &str) -> Option<String> {
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    let name = text.trim_end_matches('.');
    (name.len() <= 253
        && name.parse::<std::net::IpAddr>().is_err()
        && name.split('.').all(label_ok))
    .then(|| name.to_ascii_lowercase())
}

fn uri_ok(uri: &str, schemes: &[&str]) -> bool {
    schemes.iter().any(|s| {
        uri.strip_prefix(s).is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
        })
    })
}

fn parse_stun(raw: raw::RawStun) -> Result<Stun, ConfigError> {
    let listen = raw
        .listen
        .unwrap_or_default()
        .iter()
        .map(|a| {
            a.parse::<SocketAddr>()
                .map_err(|_| invalid("stun.listen", format!("{a:?} is not a socket address")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let uris = raw.uris.unwrap_or_default();
    if let Some(u) = uris.iter().find(|u| !uri_ok(u, &["stun:", "stuns:"])) {
        return Err(invalid("stun.uris", format!("{u:?} is not a stun: URI")));
    }
    Ok(Stun {
        listen,
        uris,
        auth: raw.auth.unwrap_or(false),
    })
}

fn parse_turn(raw: raw::RawTurn, base: &Path) -> Result<Turn, ConfigError> {
    if raw.urls.is_empty() {
        return Err(invalid("turn.urls", "at least one URI is required"));
    }
    if let Some(u) = raw.urls.iter().find(|u| !uri_ok(u, &["turn:", "turns:"])) {
        return Err(invalid("turn.urls", format!("{u:?} is not a turn: URI")));
    }
    let secret = match (raw.secret, raw.secret_file) {
        (Some(s), None) => s,
        (None, Some(f)) => {
            let path = base.join(f);
            std::fs::read_to_string(&path)
                .map_err(|source| ConfigError::SecretFile { path, source })?
                .trim()
                .to_owned()
        }
        _ => {
            return Err(invalid(
                "turn.secret",
                "exactly one of secret and secret_file is required",
            ));
        }
    };
    if secret.is_empty() {
        return Err(invalid("turn.secret", "must not be empty"));
    }
    let ttl = match raw.ttl {
        None => Duration::from_secs(24 * 3600),
        Some(v) => v
            .parse()
            .filter(|d| *d >= Duration::from_secs(60))
            .ok_or_else(|| invalid("turn.ttl", "expected a duration of at least \"1m\""))?,
    };
    if raw.bits_per_second == Some(0) || raw.bytes == Some(0) {
        return Err(invalid("turn", "limits must be positive"));
    }
    let server = raw.server.map(parse_turn_server).transpose()?;
    let silent = raw.silent.unwrap_or(false);
    if silent && server.is_none() {
        return Err(invalid("turn.silent", "needs [turn.server]"));
    }
    let default = |v: Option<u64>, d: u64| v.or(server.as_ref().map(|_| d));
    Ok(Turn {
        urls: raw.urls,
        secret,
        ttl,
        bits_per_second: default(raw.bits_per_second, DEFAULT_TURN_BITS_PER_SECOND),
        bytes: default(raw.bytes, DEFAULT_TURN_BYTES),
        silent,
        server,
    })
}

fn parse_turn_server(raw: raw::RawTurnServer) -> Result<TurnServer, ConfigError> {
    let listen = raw
        .listen
        .unwrap_or_default()
        .iter()
        .map(|a| {
            a.parse::<SocketAddr>().map_err(|_| {
                invalid(
                    "turn.server.listen",
                    format!("{a:?} is not a socket address"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let relay_ipv4: Option<std::net::Ipv4Addr> = raw
        .relay_ipv4
        .map(|a| {
            a.parse()
                .map_err(|_| invalid("turn.server.relay_ipv4", "not an IPv4 address"))
        })
        .transpose()?;
    let relay_ipv6: Option<std::net::Ipv6Addr> = raw
        .relay_ipv6
        .map(|a| {
            a.parse()
                .map_err(|_| invalid("turn.server.relay_ipv6", "not an IPv6 address"))
        })
        .transpose()?;
    if relay_ipv4.is_none() && relay_ipv6.is_none() {
        return Err(invalid(
            "turn.server.relay_ipv4",
            "relay_ipv4 or relay_ipv6 is required: it is the address clients are given",
        ));
    }
    let relay_ipv4_public: Option<std::net::Ipv4Addr> = raw
        .relay_ipv4_public
        .map(|a| {
            a.parse()
                .map_err(|_| invalid("turn.server.relay_ipv4_public", "not an IPv4 address"))
        })
        .transpose()?;
    let relay_ipv6_public: Option<std::net::Ipv6Addr> = raw
        .relay_ipv6_public
        .map(|a| {
            a.parse()
                .map_err(|_| invalid("turn.server.relay_ipv6_public", "not an IPv6 address"))
        })
        .transpose()?;
    if relay_ipv4_public.is_some() && relay_ipv4.is_none() {
        return Err(invalid(
            "turn.server.relay_ipv4_public",
            "requires relay_ipv4, the local address the relay sockets bind to",
        ));
    }
    if relay_ipv6_public.is_some() && relay_ipv6.is_none() {
        return Err(invalid(
            "turn.server.relay_ipv6_public",
            "requires relay_ipv6, the local address the relay sockets bind to",
        ));
    }
    if relay_ipv4.is_some_and(|a| a.is_unspecified()) {
        return Err(invalid(
            "turn.server.relay_ipv4",
            "must be a specific address: clients are given it (or relay_ipv4_public)",
        ));
    }
    if relay_ipv6.is_some_and(|a| a.is_unspecified()) {
        return Err(invalid(
            "turn.server.relay_ipv6",
            "must be a specific address: clients are given it (or relay_ipv6_public)",
        ));
    }
    let relay_ports = match raw.relay_ports.as_deref() {
        None => (49152, 65535),
        Some(t) => t
            .split_once('-')
            .and_then(|(a, b)| Some((a.trim().parse().ok()?, b.trim().parse().ok()?)))
            .filter(|(a, b): &(u16, u16)| *a >= 1024 && a <= b)
            .ok_or_else(|| {
                invalid(
                    "turn.server.relay_ports",
                    "expected a range such as \"49152-65535\"",
                )
            })?,
    };
    let count = |v: Option<u64>, field, d: usize| -> Result<usize, ConfigError> {
        match v {
            None => Ok(d),
            Some(v) if v >= 1 => usize::try_from(v).map_err(|_| invalid(field, "out of range")),
            Some(_) => Err(invalid(field, "must be at least 1")),
        }
    };
    Ok(TurnServer {
        listen,
        relay_ipv4,
        relay_ipv6,
        relay_ipv4_public,
        relay_ipv6_public,
        relay_ports,
        realm: raw.realm.unwrap_or_else(|| "vardevall".to_owned()),
        max_allocations: count(raw.max_allocations, "turn.server.max_allocations", 5000)?,
        allocations_per_credential: count(
            raw.allocations_per_credential,
            "turn.server.allocations_per_credential",
            4,
        )?,
        allocations_per_ip: count(raw.allocations_per_ip, "turn.server.allocations_per_ip", 16)?,
        allow_private_peers: raw.allow_private_peers.unwrap_or(false),
        tls: raw.tls.unwrap_or(true),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "key_file = \"switch.key\"\nnames = [\"switch.example.org\"]\n";

    #[test]
    fn tokens_can_carry_their_own_turn_limits() {
        let text = format!(
            "{BASE}[tokens]\naccepted = [\"a\", \"b\"]\n\
             [[tokens.turn]]\ntoken = \"a\"\nbytes = 5\n\
             [[tokens.turn]]\ntoken = \"b\"\nbits_per_second = 0\nbytes = 0\n\
             [turn]\nurls = [\"turn:t.example\"]\nsecret = \"s\"\nbits_per_second = 1000\nbytes = 9\n"
        );
        let c = Config::parse(&text, Path::new("/")).unwrap();
        let l = |class| {
            let l = c.turn_limits(class);
            (l.bits_per_second, l.bytes)
        };
        assert_eq!(l(0), (Some(1000), Some(9)));
        assert_eq!(l(1), (Some(1000), Some(5)));
        assert_eq!(l(2), (None, None));
        assert_eq!(l(9), (Some(1000), Some(9)));
        let unlisted = text.replace("accepted = [\"a\", \"b\"]", "accepted = [\"a\"]");
        assert!(Config::parse(&unlisted, Path::new("/")).is_err());
    }

    #[test]
    fn stun_limits_can_be_set_and_must_be_positive() {
        let ok = format!("{BASE}[limits]\nstun_per_ip_per_second = 3.0\nstun_per_ip_burst = 9\n");
        let c = Config::parse(&ok, Path::new("/")).unwrap();
        assert_eq!((c.limits.stun_rate, c.limits.stun_burst), (3.0, 9.0));
        let bad = format!("{BASE}[limits]\nstun_per_ip_per_second = 0\n");
        assert!(Config::parse(&bad, Path::new("/")).is_err());
    }

    #[test]
    fn names_are_normalized_and_join_the_web_names() {
        let text = "key_file = \"k\"\n\
                    names = [\"Switch.Example.org.\", \"[2001:DB8:0::1]\", \"192.0.2.7\"]\n\
                    certificate = { acme = \"vv.example.org\" }\n";
        let c = Config::parse(text, Path::new("/")).unwrap();
        assert_eq!(c.names, ["switch.example.org", "2001:db8::1", "192.0.2.7"]);
        assert_eq!(
            c.served_hosts(),
            [
                "192.0.2.7",
                "2001:db8::1",
                "switch.example.org",
                "vv.example.org"
            ]
        );

        let web_only = "key_file = \"k\"\ncertificate = { acme = \"VV.example.org\" }\n";
        let c = Config::parse(web_only, Path::new("/")).unwrap();
        assert!(c.names.is_empty());
        assert_eq!(c.served_hosts(), ["vv.example.org"]);
    }

    #[test]
    fn a_switch_with_no_name_to_serve_is_refused() {
        let e = Config::parse("key_file = \"k\"\n", Path::new("/")).unwrap_err();
        assert!(
            matches!(e, ConfigError::Invalid { field: "names", .. }),
            "{e}"
        );
        let empty = "key_file = \"k\"\nnames = []\n";
        assert!(Config::parse(empty, Path::new("/")).is_err());
        for bad in [
            "\"switch.example.org:443\"",
            "\"key@switch.example.org\"",
            "\"\"",
            "\"a b\"",
            "\"https://x.example\"",
            "\"[192.0.2.1]\"",
        ] {
            let text = format!("key_file = \"k\"\nnames = [{bad}]\n");
            let e = Config::parse(&text, Path::new("/")).unwrap_err();
            assert!(
                matches!(e, ConfigError::Invalid { field: "names", .. }),
                "{bad}"
            );
        }
    }

    #[test]
    fn acme_certificate() {
        let text = format!(
            "{BASE}certificate = {{ acme = \"Switch.Example.org\", contact = \"ops@example.org\", \
             cache_dir = \"acme\" }}\n"
        );
        let c = Config::parse(&text, Path::new("/etc/vv")).unwrap();
        assert_eq!(
            c.certificate,
            Some(Certificate::Acme(Acme {
                domain: "switch.example.org".into(),
                contact: Some("mailto:ops@example.org".into()),
                directory: None,
                cache_dir: Some("/etc/vv/acme".into()),
                ca_file: None,
            }))
        );
        for bad in [
            "acme = \"192.0.2.1\"",
            "acme = \"a b.example\"",
            "acme = \"x.example\", cert_file = \"c\"",
            "acme = \"x.example\", directory = \"http://ca\"",
            "cert_file = \"c\", key_file = \"k\", contact = \"m\"",
        ] {
            let text = format!("{BASE}certificate = {{ {bad} }}\n");
            assert!(Config::parse(&text, Path::new("/")).is_err(), "{bad}");
        }
    }

    #[test]
    fn certificate_paths() {
        let text = format!(
            "{BASE}certificate = {{ cert_file = \"c.pem\", key_file = \"/k.pem\", names = [\"VV.example.org.\"] }}\n"
        );
        let c = Config::parse(&text, Path::new("/etc/vv")).unwrap();
        assert_eq!(
            c.certificate,
            Some(Certificate::Files {
                cert_file: "/etc/vv/c.pem".into(),
                key_file: "/k.pem".into(),
                names: vec!["vv.example.org".into()],
            })
        );
        assert!(
            Config::parse(BASE, Path::new("/"))
                .unwrap()
                .certificate
                .is_none()
        );
        for bad in [
            "cert_file = \"c.pem\"",
            "cert_file = \"c.pem\", key_file = \"k.pem\"",
            "cert_file = \"c.pem\", key_file = \"k.pem\", names = []",
            "cert_file = \"c.pem\", key_file = \"k.pem\", names = [\"192.0.2.1\"]",
            "acme = \"x.example\", names = [\"x.example\"]",
        ] {
            let text = format!("{BASE}certificate = {{ {bad} }}\n");
            assert!(Config::parse(&text, Path::new("/")).is_err(), "{bad}");
        }
    }

    #[test]
    fn defaults_and_paths() {
        let c = Config::parse(BASE, Path::new("/etc/vv")).unwrap();
        assert_eq!(c.key_file, Path::new("/etc/vv/switch.key"));
        assert_eq!(c.listen, vec!["[::]:443".parse::<SocketAddr>().unwrap()]);
        assert!(c.tokens.is_empty());
        assert_eq!(c.limits, Limits::default());
        assert_eq!(c.timeouts, Timeouts::default());
    }

    #[test]
    fn overrides_apply() {
        let text = format!(
            "{BASE}listen = [\"127.0.0.1:8443\"]\n[tokens]\naccepted = [\"a\", \"b\"]\n\
             [limits]\nmax_networks = 7\nforwards_per_second = 3.5\n[timeouts]\nidle = \"2m\"\n"
        );
        let c = Config::parse(&text, Path::new(".")).unwrap();
        assert_eq!(c.tokens, ["a", "b"]);
        assert_eq!(c.limits.max_networks, 7);
        assert_eq!(c.limits.forwards_per_second, 3.5);
        assert_eq!(c.timeouts.idle, Duration::from_secs(120));
    }

    #[test]
    fn rejects_bad_values() {
        for extra in [
            "listen = [\"nope\"]",
            "unknown = 1",
            "[limits]\nmax_forward_size = 100",
            "[limits]\nforwards_per_second = 0",
            "[limits]\nmax_networks = 0",
            "[timeouts]\nkeepalive = \"20s\"",
            "[timeouts]\nidle = \"soon\"",
            "[tokens]\naccepted = [\"\"]",
            "[stun]\nuris = [\"http://x\"]",
            "[stun]\nlisten = [\"nope\"]",
            "[turn]\nurls = []\nsecret = \"s\"",
            "[turn]\nurls = [\"turn:x\"]",
            "[turn]\nurls = [\"turn:x\"]\nsecret = \"\"",
            "[turn]\nurls = [\"stun:x\"]\nsecret = \"s\"",
            "[turn]\nurls = [\"turn:x\"]\nsecret = \"s\"\nttl = \"5s\"",
        ] {
            assert!(
                Config::parse(&format!("{BASE}{extra}\n"), Path::new(".")).is_err(),
                "{extra}"
            );
        }
        assert!(Config::parse("listen = [\"[::]:1\"]", Path::new(".")).is_err());
    }

    #[cfg(feature = "stun-turn")]
    #[test]
    fn embedded_turn_server() {
        let text = format!(
            "{BASE}[turn]\nurls = [\"turn:s.example\"]\nsecret = \"x\"\n[turn.server]\n\
             listen = [\"[::]:3478\"]\nrelay_ipv4 = \"192.0.2.1\"\nrelay_ports = \"50000-50100\"\n"
        );
        let t = Config::parse(&text, Path::new(".")).unwrap().turn.unwrap();
        let s = t.server.unwrap();
        assert_eq!(s.relay_ports, (50000, 50100));
        assert_eq!(s.allocations_per_credential, 4);
        assert!(s.tls && !s.allow_private_peers);
        assert_eq!((s.relay_ipv4_public, s.relay_ipv6_public), (None, None));
        let text = format!(
            "{BASE}[turn]\nurls = [\"turn:s.example\"]\nsecret = \"x\"\n[turn.server]\n\
             relay_ipv4 = \"10.0.0.54\"\nrelay_ipv4_public = \"203.0.113.9\"\n\
             relay_ipv6 = \"fd00::54\"\nrelay_ipv6_public = \"2001:db8::9\"\n"
        );
        let s = Config::parse(&text, Path::new("."))
            .unwrap()
            .turn
            .unwrap()
            .server
            .unwrap();
        assert_eq!(s.relay_ipv4_public, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(s.relay_ipv6_public, Some("2001:db8::9".parse().unwrap()));
        for bad in [
            "relay_ipv4_public = \"203.0.113.9\"",
            "relay_ipv4 = \"10.0.0.54\"\nrelay_ipv6_public = \"2001:db8::9\"",
            "relay_ipv6 = \"fd00::54\"\nrelay_ipv6_public = \"2001:db8::9\"\nrelay_ipv4_public = \"203.0.113.9\"",
            "relay_ipv4 = \"10.0.0.54\"\nrelay_ipv4_public = \"x\"",
            "relay_ipv4 = \"10.0.0.54\"\nrelay_ipv4_public = \"2001:db8::9\"",
            "relay_ipv4 = \"0.0.0.0\"\nrelay_ipv4_public = \"203.0.113.9\"",
        ] {
            let text = format!(
                "{BASE}[turn]\nurls = [\"turn:s.example\"]\nsecret = \"x\"\n[turn.server]\n{bad}\n"
            );
            assert!(Config::parse(&text, Path::new(".")).is_err(), "{bad}");
        }
        for bad in [
            "listen = [\"[::]:3478\"]",
            "relay_ipv4 = \"x\"",
            "relay_ipv4 = \"192.0.2.1\"\nrelay_ports = \"9-5\"",
            "relay_ipv4 = \"192.0.2.1\"\nmax_allocations = 0",
            "relay_ipv4 = \"0.0.0.0\"",
            "relay_ipv6 = \"::\"",
        ] {
            let text = format!(
                "{BASE}[turn]\nurls = [\"turn:s.example\"]\nsecret = \"x\"\n[turn.server]\n{bad}\n"
            );
            assert!(Config::parse(&text, Path::new(".")).is_err(), "{bad}");
        }
    }

    #[test]
    fn behind_a_proxy() {
        let text = format!(
            "{BASE}binding = \"challenge\"\nlisten = []\nplain_listen = [\"127.0.0.1:8080\", \"[::1]:8080\"]\n\
             proxy_protocol = [\"10.0.0.0/8\", \"2001:db8::1\"]\n\
             forwarded_header = {{ name = \"CF-Connecting-IP\", from = [\"127.0.0.1/32\"] }}\n"
        );
        let c = Config::parse(&text, Path::new(".")).unwrap();
        assert_eq!(c.binding, Binding::Challenge);
        assert!(c.listen.is_empty());
        assert_eq!(c.plain_listen.len(), 2);
        assert_eq!(c.proxy_protocol[0], "10.0.0.0/8".parse().unwrap());
        assert_eq!(c.proxy_protocol[1], "2001:db8::1/128".parse().unwrap());
        let h = c.forwarded_header.unwrap();
        assert_eq!(h.name.as_str(), "cf-connecting-ip");
        assert_eq!(h.from, ["127.0.0.1/32".parse().unwrap()]);

        let defaults = Config::parse(BASE, Path::new(".")).unwrap();
        assert_eq!(defaults.binding, Binding::Exporter);
        assert!(defaults.proxy_protocol.is_empty() && defaults.forwarded_header.is_none());
        let only_plain = format!("{BASE}plain_listen = [\"127.0.0.1:8080\"]\n");
        assert!(
            Config::parse(&only_plain, Path::new("."))
                .unwrap()
                .listen
                .is_empty()
        );

        for bad in [
            "binding = \"proxy\"",
            "plain_listen = [\"0.0.0.0:8080\"]",
            "plain_listen = [\"[::]:8080\"]",
            "plain_listen = [\"nope\"]",
            "listen = []",
            "proxy_protocol = [\"10.0.0.0/33\"]",
            "proxy_protocol = [\"proxy.example\"]",
            "forwarded_header = { name = \"X-Real-IP\", from = [] }",
            "forwarded_header = { name = \"bad name\", from = [\"127.0.0.1\"] }",
            "forwarded_header = { name = \"X-Real-IP\" }",
            "listen = []\ncertificate = { acme = \"x.example\" }",
        ] {
            assert!(
                Config::parse(&format!("{BASE}{bad}\n"), Path::new(".")).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn durations_accept_hours_and_the_integer_zero() {
        let hours = format!("{BASE}[timeouts]\nidle = \"1h\"\n[log]\nstatus_interval = \"2h\"\n");
        let c = Config::parse(&hours, Path::new(".")).unwrap();
        assert_eq!(c.timeouts.idle, Duration::from_secs(3600));
        assert_eq!(c.status_interval, Some(Duration::from_secs(7200)));
        for off in ["0", "\"0s\""] {
            let text = format!("{BASE}[log]\nstatus_interval = {off}\n");
            assert_eq!(
                Config::parse(&text, Path::new("."))
                    .unwrap()
                    .status_interval,
                None
            );
        }
        assert_eq!(
            Config::parse(BASE, Path::new(".")).unwrap().status_interval,
            DEFAULT_STATUS_INTERVAL
        );
        for bad in ["5", "\"5\"", "\"5d\"", "\"h\"", "\"-1s\"", "\"1.5h\""] {
            let text = format!("{BASE}[log]\nstatus_interval = {bad}\n");
            assert!(Config::parse(&text, Path::new(".")).is_err(), "{bad}");
        }
        let zero_timeout = format!("{BASE}[timeouts]\nidle = 0\n");
        assert!(Config::parse(&zero_timeout, Path::new(".")).is_err());
    }

    #[cfg(feature = "stun-turn")]
    #[test]
    fn stun_auth_and_silent_turn() {
        let turn = "[turn]\nurls = [\"turn:s.example\"]\nsecret = \"x\"\n";
        let text = format!("{BASE}[stun]\nauth = true\n{turn}");
        assert!(Config::parse(&text, Path::new(".")).unwrap().stun.auth);
        let no_secret = format!("{BASE}[stun]\nauth = true\n");
        assert!(Config::parse(&no_secret, Path::new(".")).is_err());
        let silent_alone = format!("{BASE}{turn}silent = true\n");
        assert!(Config::parse(&silent_alone, Path::new(".")).is_err());
        let silent = format!("{silent_alone}[turn.server]\nrelay_ipv4 = \"192.0.2.1\"\n");
        assert!(
            Config::parse(&silent, Path::new("."))
                .unwrap()
                .turn
                .unwrap()
                .silent
        );
    }

    #[cfg(feature = "stun-turn")]
    #[test]
    fn the_embedded_server_has_default_limits() {
        let turn = "[turn]\nurls = [\"turn:s.example\"]\nsecret = \"x\"\n";
        let external = Config::parse(&format!("{BASE}{turn}"), Path::new(".")).unwrap();
        let t = external.turn.unwrap();
        assert_eq!((t.bits_per_second, t.bytes), (None, None));
        let embedded = format!("{BASE}{turn}[turn.server]\nrelay_ipv4 = \"192.0.2.1\"\n");
        let t = Config::parse(&embedded, Path::new("."))
            .unwrap()
            .turn
            .unwrap();
        assert_eq!(t.bits_per_second, Some(DEFAULT_TURN_BITS_PER_SECOND));
        assert_eq!(t.bytes, Some(DEFAULT_TURN_BYTES));
        let set = format!("{BASE}{turn}bytes = 5\n[turn.server]\nrelay_ipv4 = \"192.0.2.1\"\n");
        let t = Config::parse(&set, Path::new(".")).unwrap().turn.unwrap();
        assert_eq!(
            (t.bits_per_second, t.bytes),
            (Some(DEFAULT_TURN_BITS_PER_SECOND), Some(5))
        );
    }

    #[cfg(feature = "stun-turn")]
    #[test]
    fn stun_and_turn() {
        let text = format!(
            "{BASE}[stun]\nlisten = [\"[::]:3478\"]\nuris = [\"stun:s.example:3478\"]\n\
             [turn]\nurls = [\"turn:s.example:3478?transport=udp\"]\nsecret = \"x\"\n\
             ttl = \"1h\"\nbits_per_second = 1000\n"
        );
        let c = Config::parse(&text, Path::new(".")).unwrap();
        assert_eq!(c.stun.listen.len(), 1);
        assert_eq!(c.stun.uris, ["stun:s.example:3478"]);
        let t = c.turn.unwrap();
        assert_eq!(t.ttl, Duration::from_secs(3600));
        assert_eq!((t.bits_per_second, t.bytes), (Some(1000), None));
        assert!(Config::parse(BASE, Path::new(".")).unwrap().turn.is_none());
    }

    #[cfg(not(feature = "stun-turn"))]
    #[test]
    fn without_the_feature_the_embedded_servers_are_refused() {
        let turn = "[turn]\nurls = [\"turn:s.example\"]\nsecret = \"x\"\n";
        assert!(Config::parse(&format!("{BASE}{turn}"), Path::new(".")).is_ok());
        let server = format!("{BASE}{turn}[turn.server]\nrelay_ipv4 = \"192.0.2.1\"\n");
        assert!(Config::parse(&server, Path::new(".")).is_err());
        let stun = format!("{BASE}[stun]\nlisten = [\"[::]:3478\"]\n");
        assert!(Config::parse(&stun, Path::new(".")).is_err());
    }
}
