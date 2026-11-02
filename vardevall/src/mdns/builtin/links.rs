//! The physical links the built-in transport runs on (vv-09 §2.1).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::config::BuiltinMdns;

/// Interface name prefixes that are never physical links.
const VIRTUAL: &[&str] = &[
    "lo", "utun", "tun", "tap", "wg", "awdl", "llw", "ipsec", "gif", "stf", "anpi", "docker",
    "br-", "veth", "virbr", "vv", "ap",
];

/// One link and its addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    /// The interface name.
    pub name: String,
    /// The interface index.
    pub index: u32,
    /// IPv4 addresses.
    pub v4: Vec<Ipv4Addr>,
    /// IPv6 addresses, link-local included.
    pub v6: Vec<Ipv6Addr>,
}

fn is_link_local(a: &Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

impl Link {
    /// The IPv6 addresses worth announcing: not link-local, which receivers cannot scope.
    pub(crate) fn announced_v6(&self) -> impl Iterator<Item = &Ipv6Addr> {
        self.v6.iter().filter(|a| !is_link_local(a))
    }
}

/// Whether the named interface may carry mDNS under `config`.
pub(crate) fn eligible(name: &str, config: &BuiltinMdns) -> bool {
    if config.exclude.iter().any(|e| e == name) {
        return false;
    }
    match &config.interfaces {
        Some(list) => list.iter().any(|e| e == name),
        None => !VIRTUAL.iter().any(|p| name.starts_with(p)),
    }
}

fn in_prefix(a: &Ipv6Addr, prefix: &[u8; 8]) -> bool {
    a.octets()[..8] == prefix[..]
}

/// The eligible links of this host; links carrying an address of the overlay prefix are skipped.
pub(crate) fn enumerate(config: &BuiltinMdns, overlay_prefix: &[u8; 8]) -> Vec<Link> {
    let Ok(all) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let overlay: Vec<String> = all
        .iter()
        .filter_map(|i| match i.ip() {
            std::net::IpAddr::V6(a) if in_prefix(&a, overlay_prefix) => Some(i.name.clone()),
            _ => None,
        })
        .collect();
    let mut links: Vec<Link> = Vec::new();
    for i in all {
        if i.is_loopback()
            || !eligible(&i.name, config)
            || overlay.contains(&i.name)
            || matches!(
                i.oper_status,
                if_addrs::IfOperStatus::Down | if_addrs::IfOperStatus::NotPresent
            )
        {
            continue;
        }
        let Some(index) = i.index else { continue };
        let pos = match links.iter().position(|l| l.name == i.name) {
            Some(p) => p,
            None => {
                links.push(Link {
                    name: i.name.clone(),
                    index,
                    v4: Vec::new(),
                    v6: Vec::new(),
                });
                links.len() - 1
            }
        };
        match i.ip() {
            std::net::IpAddr::V4(a) => links[pos].v4.push(a),
            std::net::IpAddr::V6(a) => links[pos].v6.push(a),
        }
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_selection_skips_virtual_links() {
        let c = BuiltinMdns::default();
        assert!(eligible("en0", &c));
        assert!(eligible("eth0", &c));
        assert!(eligible("wlan0", &c));
        for n in [
            "lo0", "utun4", "awdl0", "tun0", "wg0", "docker0", "veth12", "vv0",
        ] {
            assert!(!eligible(n, &c), "{n}");
        }
    }

    #[test]
    fn allow_and_deny_lists() {
        let c = BuiltinMdns {
            interfaces: Some(vec!["utun9".into(), "en1".into()]),
            exclude: vec!["en1".into()],
        };
        assert!(eligible("utun9", &c));
        assert!(!eligible("en1", &c));
        assert!(!eligible("en0", &c));
    }

    #[test]
    fn link_local_v6_is_not_announced() {
        let l = Link {
            name: "en0".into(),
            index: 1,
            v4: vec![],
            v6: vec!["fe80::1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
        };
        assert_eq!(l.announced_v6().count(), 1);
    }
}
