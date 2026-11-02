//! Candidate addresses and their JSON encoding (vv-05 §2).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::ParseError;
use crate::json::{self, Value};

/// Most entries of `cand` that a receiver considers (vv-05 §2.2).
pub const MAX_CANDIDATES: usize = 8;

/// The provider labels of candidates.
pub mod label {
    /// Same-host discovery.
    pub const LOCAL: &str = "local";
    /// A local registry on the same link.
    pub const LAN: &str = "lan";
    /// A configured endpoint.
    pub const STATIC: &str = "static";
    /// A server-reflexive address from STUN.
    pub const PUNCH: &str = "punch";
    /// A TURN relayed address.
    pub const RELAY: &str = "relay";
}

/// An address a peer might be reachable at, with what its provider asserts of it.
/// Only `shared` candidates travel to the peer; the others come from the caller's local sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Candidate {
    /// The transport address.
    pub addr: SocketAddr,
    /// Whether it was found on this link or host: LAN class.
    pub local: bool,
    /// Whether the address was gathered on an expensive or constrained interface, or is a relay
    /// (vv-05 §2.2).
    pub metered: bool,
    /// Whether it goes to the peer in handshake payloads and `cand` messages.
    pub shared: bool,
    /// The provider, for views and logs.
    pub label: &'static str,
}

impl Candidate {
    const fn make(
        addr: SocketAddr,
        local: bool,
        metered: bool,
        shared: bool,
        label: &'static str,
    ) -> Self {
        Candidate {
            addr,
            local,
            metered,
            shared,
            label,
        }
    }

    /// A peer found on this host.
    pub const fn same_host(addr: SocketAddr) -> Self {
        Self::make(addr, true, false, false, label::LOCAL)
    }

    /// A peer found by a local registry on this link.
    pub const fn lan(addr: SocketAddr) -> Self {
        Self::make(addr, true, false, false, label::LAN)
    }

    /// A configured endpoint: internet class.
    pub const fn static_(addr: SocketAddr) -> Self {
        Self::make(addr, false, false, false, label::STATIC)
    }

    /// A configured endpoint known to be on this link (`endpoint_local`): LAN class.
    pub const fn static_local(addr: SocketAddr) -> Self {
        Self::make(addr, true, false, false, label::STATIC)
    }

    /// A server-reflexive address, shared with the peer.
    pub const fn punch(addr: SocketAddr) -> Self {
        Self::make(addr, false, false, true, label::PUNCH)
    }

    /// A TURN relayed address, shared with the peer and metered.
    pub const fn relay(addr: SocketAddr) -> Self {
        Self::make(addr, false, true, true, label::RELAY)
    }

    /// The same candidate, metered if it was or `metered` says so.
    pub const fn with_metered(mut self, metered: bool) -> Self {
        self.metered |= metered;
        self
    }

    /// Whether this is a TURN relayed address.
    pub fn is_relay(&self) -> bool {
        self.label == label::RELAY
    }

    /// Appends the JSON object of this candidate (vv-05 §2.2).
    pub(crate) fn write_json(&self, out: &mut String) {
        out.push_str("{\"kind\":");
        json::write_string(out, self.label);
        out.push_str(",\"addr\":");
        json::write_string(out, &format_addr(&self.addr));
        if self.metered && !self.is_relay() {
            out.push_str(",\"metered\":true");
        }
        out.push('}');
    }
}

/// The `addr` text of a socket address: dotted decimal, or bracketed RFC 5952 IPv6.
pub fn format_addr(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(a) => format!("{}:{}", a.ip(), a.port()),
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    }
}

/// Encodes candidates as the JSON array of vv-05 §2.2.
pub fn encode_list(candidates: &[Candidate]) -> String {
    let mut out = String::from("[");
    for (i, c) in candidates.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        c.write_json(&mut out);
    }
    out.push(']');
    out
}

fn parse_port(s: &str) -> Option<u16> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 5 || b[0] == b'0' || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    s.parse::<u16>().ok().filter(|p| *p != 0)
}

fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for o in &mut octets {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if p.len() > 1 && p.starts_with('0') {
            return None;
        }
        *o = p.parse().ok()?;
    }
    parts.next().is_none().then(|| Ipv4Addr::from(octets))
}

/// Parses the `addr` form of vv-05 §2.2.
pub fn parse_addr(s: &str) -> Option<SocketAddr> {
    if let Some(rest) = s.strip_prefix('[') {
        let (ip, port) = rest.split_once("]:")?;
        if ip.contains('%') {
            return None;
        }
        let ip: Ipv6Addr = ip.parse().ok()?;
        Some(SocketAddr::new(ip.into(), parse_port(port)?))
    } else {
        let (ip, port) = s.split_once(':')?;
        Some(SocketAddr::new(parse_ipv4(ip)?.into(), parse_port(port)?))
    }
}

/// Parses a JSON `cand` array and returns its usable entries (vv-05 §2.2).
pub fn decode_list(json_text: &[u8]) -> Result<Vec<Candidate>, ParseError> {
    json::parse(json_text).map(|v| usable(&v))
}

/// Extracts the usable candidates of a `cand` array (vv-05 §2.2).
pub(crate) fn usable(value: &Value) -> Vec<Candidate> {
    let Some(items) = value.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .take(MAX_CANDIDATES)
        .filter_map(|item| {
            let kind = item.get("kind")?.as_str()?;
            let addr = parse_addr(item.get("addr")?.as_str()?)?;
            let metered = matches!(item.get("metered"), Some(Value::Bool(true)));
            let c = match kind {
                label::PUNCH => Candidate::punch(addr),
                label::RELAY => Candidate::relay(addr),
                _ => return None,
            };
            Some(c.with_metered(metered))
        })
        .collect()
}

/// Most candidates a first direct handshake goes to (vv-05 §4.1).
pub const MAX_DIRECT_TARGETS: usize = 4;

/// The candidates that are not shared to send message 1 to: local ones first, IPv6 before IPv4,
/// otherwise in the order given (vv-05 §4.1).
pub fn direct_targets(candidates: &[Candidate]) -> Vec<Candidate> {
    let mut v: Vec<Candidate> = candidates.iter().copied().filter(|c| !c.shared).collect();
    v.sort_by_key(|c| (!c.local, c.addr.is_ipv4()));
    v.dedup();
    v.truncate(MAX_DIRECT_TARGETS);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_targets_are_ordered_and_bounded() {
        let a = |addr: &str| -> SocketAddr { addr.parse().unwrap() };
        let list = [
            Candidate::punch(a("203.0.113.1:1")),
            Candidate::static_(a("203.0.113.2:2")),
            Candidate::lan(a("192.168.1.2:3")),
            Candidate::lan(a("[fd00::2]:3")),
            Candidate::same_host(a("127.0.0.1:4")),
            Candidate::relay(a("203.0.113.9:9")),
        ];
        let t = direct_targets(&list);
        let labels: Vec<_> = t.iter().map(|c| c.label).collect();
        assert_eq!(labels, ["lan", "lan", "local", "static"]);
        assert!(t[0].addr.is_ipv6(), "IPv6 first within the local ones");
    }

    #[test]
    fn constructors_say_what_the_provider_asserts() {
        let addr: SocketAddr = "203.0.113.1:1".parse().unwrap();
        for (c, local, metered, shared, name) in [
            (Candidate::same_host(addr), true, false, false, "local"),
            (Candidate::lan(addr), true, false, false, "lan"),
            (Candidate::static_(addr), false, false, false, "static"),
            (Candidate::static_local(addr), true, false, false, "static"),
            (Candidate::punch(addr), false, false, true, "punch"),
            (Candidate::relay(addr), false, true, true, "relay"),
        ] {
            assert_eq!(
                (c.local, c.metered, c.shared, c.label),
                (local, metered, shared, name)
            );
        }
        assert!(Candidate::relay(addr).with_metered(false).metered);
        assert!(Candidate::punch(addr).with_metered(true).metered);
    }

    #[test]
    fn address_forms() {
        assert!(parse_addr("203.0.113.9:80").is_some());
        assert!(parse_addr("203.0.113.009:80").is_none());
        assert!(parse_addr("203.0.113.9:080").is_none());
        assert!(parse_addr("[2001:db8::7]:65535").is_some());
        assert!(parse_addr("[2001:db8::7]:65536").is_none());
        assert!(parse_addr("[fe80::1%eth0]:1").is_none());
        assert!(parse_addr("2001:db8::7:51820").is_none());
        assert!(parse_addr("").is_none());
    }
}
