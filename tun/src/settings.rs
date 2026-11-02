//! Tunnel settings derived from a configuration (vv-06 §2.1, §4.4, vv-07 §3.2), as returned by
//! `vv_tunnel_settings`.

use std::net::Ipv6Addr;

use serde_json::json;
use vardevall_proto::addr::{self, ula_prefix};

use crate::config::Config;

/// An address and prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrSetting {
    /// The address.
    pub addr: Ipv6Addr,
    /// The prefix length.
    pub prefix: u8,
}

/// Resolver settings of the tunnel (vv-06 §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettings {
    /// The resolver address: the node's own `ula`.
    pub servers: Vec<Ipv6Addr>,
    /// Domains routed to the resolver: the overlay domain and its reverse zone.
    pub match_domains: Vec<String>,
}

/// What an operating system must configure for the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSettings {
    /// Addresses of the interface: `ula/64` and `link_local/64`.
    pub addrs: Vec<AddrSetting>,
    /// Prefixes to route into the tunnel: the network's `ula/64`.
    pub routes: Vec<AddrSetting>,
    /// The tunnel MTU.
    pub mtu: u16,
    /// Resolver settings.
    pub dns: DnsSettings,
}

impl TunnelSettings {
    /// The settings for `config`.
    pub fn for_config(config: &Config) -> Self {
        let own = config.own_addrs();
        let mut prefix = [0u8; 16];
        prefix[..8].copy_from_slice(&ula_prefix(&config.network_id));
        let reverse = addr::reverse_zone(&config.network_id);
        TunnelSettings {
            addrs: vec![
                AddrSetting {
                    addr: own.ula,
                    prefix: 64,
                },
                AddrSetting {
                    addr: own.link_local,
                    prefix: 64,
                },
            ],
            routes: vec![AddrSetting {
                addr: Ipv6Addr::from(prefix),
                prefix: 64,
            }],
            mtu: config.mtu,
            dns: DnsSettings {
                servers: vec![own.ula],
                match_domains: vec![config.domain.clone(), reverse],
            },
        }
    }

    /// The settings of several networks in one tunnel: every network's addresses and
    /// routes in order, the smallest MTU, the first network's resolver and every network's match
    /// domains. `None` for no networks.
    pub fn merged(sets: &[TunnelSettings]) -> Option<Self> {
        let mut it = sets.iter();
        let mut out = it.next()?.clone();
        for s in it {
            out.addrs.extend_from_slice(&s.addrs);
            out.routes.extend_from_slice(&s.routes);
            out.mtu = out.mtu.min(s.mtu);
            out.dns
                .match_domains
                .extend_from_slice(&s.dns.match_domains);
        }
        Some(out)
    }

    /// The JSON of `vv_tunnel_settings`; `routes` is an addition for platforms that need an
    /// explicit route to the overlay prefix.
    pub fn to_json(&self) -> String {
        let a = |s: &[AddrSetting]| -> Vec<serde_json::Value> {
            s.iter()
                .map(|x| json!({"addr": x.addr.to_string(), "prefix": x.prefix}))
                .collect()
        };
        json!({
            "addrs": a(&self.addrs),
            "routes": a(&self.routes),
            "mtu": self.mtu,
            "dns": {
                "servers": self.dns.servers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "match_domains": self.dns.match_domains,
            },
        })
        .to_string()
    }
}
