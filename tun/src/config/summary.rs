//! The JSON summary of a validated file, without secrets (`vv_validate_config`).

use serde_json::{Value, json};
use vardevall::{Endpoint, SwitchAuth};

use super::Config;
use crate::dns::fqdn;

impl Config {
    /// A JSON description of the configuration that never contains a secret.
    pub fn summary(&self) -> Value {
        let addrs = self.own_addrs();
        let peers: Vec<Value> = self
            .peers
            .iter()
            .map(|p| {
                let a =
                    vardevall_proto::addr::OverlayAddrs::derive(&self.network_id, &p.public_key);
                json!({
                    "public_key": p.public_key.to_base32(),
                    "name": p.name,
                    "fqdn": p.name.as_deref().map(|n| fqdn(n, &self.domain)),
                    "addr": a.ula.to_string(),
                    "endpoints": p.endpoints.iter().map(|e| match e {
                        Endpoint::Addr(a) => a.to_string(),
                        Endpoint::Host { host, port } => format!("{host}:{port}"),
                        Endpoint::Srv(n) => n.clone(),
                    }).collect::<Vec<_>>(),
                    "endpoint_local": p.endpoint_local,
                })
            })
            .collect();
        json!({
            "interface": self.name,
            "public_key": self.public_key.to_base32(),
            "network_id": self.network_id.to_base32(),
            "name": self.own_name,
            "addrs": {"ula": addrs.ula.to_string(), "link_local": addrs.link_local.to_string()},
            "listen_port": self.listen_port,
            "mtu": self.mtu,
            "domain": self.domain,
            "accept_members": self.accept_members,
            "mdns": self.mdns,
            "fallback_delay_ms": u64::try_from(self.fallback_delay.as_millis()).unwrap_or(u64::MAX),
            "switches": self.switches.iter().map(|s| json!({
                "address": s.label(),
                "auth": match s.auth {
                    SwitchAuth::Pinned(_) => "pinned",
                    SwitchAuth::Web { .. } => "web",
                },
            })).collect::<Vec<_>>(),
            "turn_servers": self.turns.len(),
            "stun_servers": self.stun.len(),
            "services": self.services.iter().map(|s| json!({
                "name": s.name(),
                "port": s.port(),
                "proto": s.proto().name(),
            })).collect::<Vec<_>>(),
            "peers": peers,
            "forward": !self.forward.is_empty(),
            "exit": self.exit.as_ref().map(|e| e.site.to_string()),
            "ipv4_home": vardevall::home_ipv4(&self.network_id, &self.public_key).to_string(),
        })
    }
}
