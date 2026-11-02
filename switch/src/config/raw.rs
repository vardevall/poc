//! The TOML shape of the configuration file; unknown keys are rejected (vv-07 §2.2).

use std::time::Duration;

use serde::Deserialize;

/// A duration: `"250ms"`, `"3s"`, `"2m"`, `"24h"`, or the integer `0` (vv-07 §2.2).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RawDuration {
    Text(String),
    Number(u64),
}

impl RawDuration {
    pub fn parse(&self) -> Option<Duration> {
        let t = match self {
            RawDuration::Text(t) => t.as_str(),
            RawDuration::Number(0) => return Some(Duration::ZERO),
            RawDuration::Number(_) => return None,
        };
        let (digits, unit) = t.split_at(t.find(|c: char| !c.is_ascii_digit())?);
        let n: u64 = digits.parse().ok()?;
        match unit {
            "ms" => Some(Duration::from_millis(n)),
            "s" => Some(Duration::from_secs(n)),
            "m" => Some(Duration::from_secs(n.checked_mul(60)?)),
            "h" => Some(Duration::from_secs(n.checked_mul(3600)?)),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Raw {
    pub listen: Option<Vec<String>>,
    pub plain_listen: Option<Vec<String>>,
    pub key_file: String,
    pub certificate: Option<RawCertificate>,
    pub names: Option<Vec<String>>,
    pub binding: Option<String>,
    pub proxy_protocol: Option<Vec<String>>,
    pub forwarded_header: Option<RawForwarded>,
    #[serde(default)]
    pub tokens: RawTokens,
    #[serde(default)]
    pub limits: RawLimits,
    #[serde(default)]
    pub timeouts: RawTimeouts,
    #[serde(default)]
    pub stun: RawStun,
    pub turn: Option<RawTurn>,
    #[serde(default)]
    pub log: RawLog,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawForwarded {
    pub name: String,
    pub from: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawLog {
    pub status_interval: Option<RawDuration>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCertificate {
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub names: Option<Vec<String>>,
    pub acme: Option<String>,
    pub contact: Option<String>,
    pub directory: Option<String>,
    pub cache_dir: Option<String>,
    pub ca_file: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawStun {
    pub listen: Option<Vec<String>>,
    pub uris: Option<Vec<String>>,
    pub auth: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTurn {
    pub urls: Vec<String>,
    pub secret: Option<String>,
    pub secret_file: Option<String>,
    pub ttl: Option<RawDuration>,
    pub bits_per_second: Option<u64>,
    pub bytes: Option<u64>,
    pub silent: Option<bool>,
    pub server: Option<RawTurnServer>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTurnServer {
    pub listen: Option<Vec<String>>,
    pub relay_ipv4: Option<String>,
    pub relay_ipv6: Option<String>,
    pub relay_ipv4_public: Option<String>,
    pub relay_ipv6_public: Option<String>,
    pub relay_ports: Option<String>,
    pub realm: Option<String>,
    pub max_allocations: Option<u64>,
    pub allocations_per_credential: Option<u64>,
    pub allocations_per_ip: Option<u64>,
    pub allow_private_peers: Option<bool>,
    pub tls: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTokens {
    pub accepted: Option<Vec<String>>,
    pub file: Option<String>,
    #[serde(default)]
    pub turn: Vec<RawTokenTurn>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTokenTurn {
    pub token: String,
    pub bits_per_second: Option<u64>,
    pub bytes: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawLimits {
    pub max_forward_size: Option<u64>,
    pub max_registrations: Option<u64>,
    pub max_networks: Option<u64>,
    pub registrations_per_network: Option<u64>,
    pub max_event_streams: Option<u64>,
    pub max_connections: Option<u64>,
    pub max_connections_per_ip: Option<u64>,
    pub stun_per_ip_per_second: Option<f64>,
    pub stun_per_ip_burst: Option<f64>,
    pub register_per_ip_per_second: Option<f64>,
    pub register_per_ip_burst: Option<f64>,
    pub register_per_network_per_second: Option<f64>,
    pub register_per_network_burst: Option<f64>,
    pub members_per_second: Option<f64>,
    pub members_burst: Option<f64>,
    pub forwards_per_second: Option<f64>,
    pub forwards_burst: Option<f64>,
    pub sender_bytes_per_second: Option<f64>,
    pub sender_bytes_burst: Option<f64>,
    pub network_bytes_per_second: Option<f64>,
    pub network_bytes_burst: Option<f64>,
    pub session_bytes: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTimeouts {
    pub tls_handshake: Option<RawDuration>,
    pub request_header: Option<RawDuration>,
    pub request_body: Option<RawDuration>,
    pub idle: Option<RawDuration>,
    pub reconnect_grace: Option<RawDuration>,
    pub keepalive: Option<RawDuration>,
}
