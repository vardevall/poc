//! Overlay addresses and the DNS name table (vv-01 §5.6–§5.8, vv-06).

use std::collections::HashMap;
use std::net::Ipv6Addr;

use crate::keys::crypto;
use crate::keys::{NetworkId, NodePublic, ctx};

/// The `/64` ULA prefix of a network (vv-01 §5.6).
pub fn ula_prefix(network_id: &NetworkId) -> [u8; 8] {
    let global_id: [u8; 5] = crypto::kdf(ctx::ULA_PREFIX, &[network_id.as_bytes()]);
    let mut p = [0u8; 8];
    p[0] = 0xfd;
    p[1..6].copy_from_slice(&global_id);
    p
}

/// The interface identifier of a node in a network (vv-01 §5.7).
pub fn iid(network_id: &NetworkId, node: &NodePublic) -> [u8; 8] {
    crypto::kdf(ctx::IID, &[network_id.as_bytes(), node.as_bytes()])
}

/// The overlay addresses of one node (vv-06 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OverlayAddrs {
    /// Interface identifier.
    pub iid: [u8; 8],
    /// `ula_prefix ‖ iid`.
    pub ula: Ipv6Addr,
    /// `fe80:: ‖ iid`.
    pub link_local: Ipv6Addr,
}

impl OverlayAddrs {
    /// Derives the addresses of `node` in `network_id`.
    pub fn derive(network_id: &NetworkId, node: &NodePublic) -> Self {
        let iid = iid(network_id, node);
        let mut ula = [0u8; 16];
        ula[..8].copy_from_slice(&ula_prefix(network_id));
        ula[8..].copy_from_slice(&iid);
        let mut ll = [0u8; 16];
        ll[0] = 0xfe;
        ll[1] = 0x80;
        ll[8..].copy_from_slice(&iid);
        OverlayAddrs {
            iid,
            ula: Ipv6Addr::from(ula),
            link_local: Ipv6Addr::from(ll),
        }
    }

    /// Whether `addr` is one of the two addresses.
    pub fn contains(&self, addr: &Ipv6Addr) -> bool {
        *addr == self.ula || *addr == self.link_local
    }
}

/// Whether `iid` falls in a reserved range of RFC 5453 (vv-06 §2.2).
pub fn is_reserved_iid(iid: &[u8; 8]) -> bool {
    let v = u64::from_be_bytes(*iid);
    v == 0
        || (0x0200_5eff_fe00_0000..=0x0200_5eff_feff_ffff).contains(&v)
        || (0xfdff_ffff_ffff_ff80..=0xfdff_ffff_ffff_ffff).contains(&v)
}

/// Sanitises an OS hostname into a DNS label, or `None` if nothing remains (vv-06 §4.2).
pub fn sanitise_hostname(hostname: &str) -> Option<String> {
    let first = hostname.split('.').next().unwrap_or("");
    let mut out = String::with_capacity(first.len());
    for c in first.chars() {
        let c = c.to_ascii_lowercase();
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
            c
        } else {
            '-'
        };
        if c == '-' && out.ends_with('-') {
            continue;
        }
        out.push(c);
    }
    let trimmed = out.trim_matches('-');
    let truncated: String = trimmed.chars().take(51).collect();
    let result = truncated.trim_matches('-');
    (!result.is_empty()).then(|| result.to_owned())
}

/// Whether `label` is a valid configured name (vv-06 §4.2).
pub fn is_valid_label(label: &str) -> bool {
    let b = label.as_bytes();
    if b.is_empty() || b.len() > 63 || b.len() == 52 {
        return false;
    }
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    alnum(b[0]) && alnum(b[b.len() - 1]) && b.iter().all(|&c| alnum(c) || c == b'-')
}

/// The `ip6.arpa` name of an address (vv-06 §4.3).
pub fn ptr_name(addr: &Ipv6Addr) -> String {
    let mut s = String::with_capacity(73);
    for byte in addr.octets().iter().rev() {
        for nibble in [byte & 0xf, byte >> 4] {
            s.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
            s.push('.');
        }
    }
    s.push_str("ip6.arpa");
    s
}

/// The reverse zone of a network's ULA `/64` (vv-06 §4.4).
pub fn reverse_zone(network_id: &NetworkId) -> String {
    let prefix = ula_prefix(network_id);
    let mut s = String::with_capacity(41);
    for byte in prefix.iter().rev() {
        for nibble in [byte & 0xf, byte >> 4] {
            s.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
            s.push('.');
        }
    }
    s.push_str("ip6.arpa");
    s
}

/// Parses an `ip6.arpa` name of a full address.
pub fn parse_ptr_name(name: &str) -> Option<Ipv6Addr> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let body = name.strip_suffix(".ip6.arpa")?;
    let nibbles: Vec<&str> = body.split('.').collect();
    if nibbles.len() != 32 || nibbles.iter().any(|n| n.len() != 1) {
        return None;
    }
    let mut octets = [0u8; 16];
    for (i, n) in nibbles.iter().enumerate() {
        let v = u8::from_str_radix(n, 16).ok()?;
        let pos = 31 - i;
        octets[pos / 2] |= if pos % 2 == 0 { v << 4 } else { v };
    }
    Some(Ipv6Addr::from(octets))
}

/// TTL of every positive answer (vv-06 §4.3).
pub const ANSWER_TTL: u32 = 300;

/// A query type the overlay resolver distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    /// `AAAA`.
    Aaaa,
    /// `PTR`.
    Ptr,
    /// Any other type.
    Other,
}

/// The resolver's decision on a query (vv-06 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// An `AAAA` record.
    Aaaa(Ipv6Addr),
    /// A `PTR` record.
    Ptr(String),
    /// NOERROR without answers.
    NoData,
    /// Forward to the configured upstream.
    Forward,
    /// NXDOMAIN.
    NxDomain,
    /// REFUSED.
    Refused,
}

/// The per-interface name table (vv-06 §4.1).
#[derive(Debug, Clone)]
pub struct NameTable {
    network_id: NetworkId,
    domain: String,
    forward: bool,
    names: HashMap<String, NodePublic>,
    labels: HashMap<NodePublic, String>,
    known: Vec<NodePublic>,
}

impl NameTable {
    /// An empty table for `domain` (without trailing dot); `forward` enables §4.5.
    pub fn new(network_id: NetworkId, domain: &str, forward: bool) -> Self {
        NameTable {
            network_id,
            domain: domain.trim_end_matches('.').to_ascii_lowercase(),
            forward,
            names: HashMap::new(),
            labels: HashMap::new(),
            known: Vec::new(),
        }
    }

    /// Registers a key as known without a name, for `PTR` answers.
    pub fn add_key(&mut self, key: NodePublic) {
        if !self.known.contains(&key) {
            self.known.push(key);
        }
    }

    /// Forgets `key`: its reverse record and its label, if it had one.
    pub fn remove_key(&mut self, key: &NodePublic) {
        self.known.retain(|k| k != key);
        if let Some(label) = self.labels.remove(key) {
            self.names.remove(&label);
        }
    }

    /// Changes the domain, as a file that is read again may (without trailing dot).
    pub fn set_domain(&mut self, domain: &str) {
        self.domain = domain.trim_end_matches('.').to_ascii_lowercase();
    }

    /// Changes whether names of the domain that are not known are forwarded (vv-06 §4.5).
    pub fn set_forward(&mut self, forward: bool) {
        self.forward = forward;
    }

    /// Takes away the label of `key`, if it has one.
    pub fn clear_label(&mut self, key: &NodePublic) {
        if let Some(label) = self.labels.remove(key) {
            self.names.remove(&label);
        }
    }

    /// Registers `label` for `key`; returns `false` for an invalid or duplicate label.
    pub fn add_name(&mut self, label: &str, key: NodePublic) -> bool {
        if !is_valid_label(label) || self.names.contains_key(label) {
            return false;
        }
        self.names.insert(label.to_owned(), key);
        self.labels.entry(key).or_insert_with(|| label.to_owned());
        self.add_key(key);
        true
    }

    /// `resolve(name) → key` of the library API (vv-06 §4.6).
    pub fn resolve(&self, name: &str) -> Option<NodePublic> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let label = match name.strip_suffix(&self.domain) {
            Some(rest) if rest.ends_with('.') => &rest[..rest.len() - 1],
            _ => name.as_str(),
        };
        if label.contains('.') {
            return None;
        }
        if let Some(k) = self.names.get(label) {
            return Some(*k);
        }
        label.parse::<NodePublic>().ok()
    }

    /// `name(key) → label or none` of the library API (vv-06 §4.6).
    pub fn name(&self, key: &NodePublic) -> Option<&str> {
        self.labels.get(key).map(String::as_str)
    }

    /// Decides a query for `qname` of type `qtype` (vv-06 §4.3).
    pub fn answer(&self, qname: &str, qtype: QueryType) -> Answer {
        let qname = qname.trim_end_matches('.').to_ascii_lowercase();
        let reverse = reverse_zone(&self.network_id);
        if qname == reverse || qname.ends_with(&format!(".{reverse}")) {
            return match (qtype, parse_ptr_name(&qname)) {
                (QueryType::Ptr, Some(addr)) => match self.key_for_ula(&addr) {
                    Some(key) => Answer::Ptr(self.ptr_target(&key)),
                    None => self.unknown_in_domain(),
                },
                _ => self.unknown_in_domain(),
            };
        }
        let Some(label) = qname
            .strip_suffix(&self.domain)
            .and_then(|r| r.strip_suffix('.'))
            .filter(|l| !l.contains('.'))
        else {
            return if qname == self.domain || qname.ends_with(&format!(".{}", self.domain)) {
                self.unknown_in_domain()
            } else {
                Answer::Refused
            };
        };
        let key = self
            .names
            .get(label)
            .copied()
            .or_else(|| label.parse().ok());
        match (key, qtype) {
            (Some(k), QueryType::Aaaa) => {
                Answer::Aaaa(OverlayAddrs::derive(&self.network_id, &k).ula)
            }
            (Some(_), _) => Answer::NoData,
            (None, _) => self.unknown_in_domain(),
        }
    }

    fn unknown_in_domain(&self) -> Answer {
        if self.forward {
            Answer::Forward
        } else {
            Answer::NxDomain
        }
    }

    fn key_for_ula(&self, addr: &Ipv6Addr) -> Option<NodePublic> {
        self.known
            .iter()
            .find(|k| OverlayAddrs::derive(&self.network_id, k).ula == *addr)
            .copied()
    }

    fn ptr_target(&self, key: &NodePublic) -> String {
        let label = self
            .labels
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.key_id());
        format!("{label}.{}", self.domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptr_round_trip() {
        let a: Ipv6Addr = "fdef:813d:8791:0:6d0a:8bf2:5ecf:91dd".parse().unwrap();
        assert_eq!(parse_ptr_name(&ptr_name(&a)), Some(a));
    }

    #[test]
    fn a_removed_key_loses_its_label_and_reverse_record() {
        let nid = NetworkId::from_bytes([2; 32]);
        let key = NodePublic::from_bytes([7; 32]);
        let mut t = NameTable::new(nid, "home.internal", false);
        assert!(t.add_name("nas", key));
        t.remove_key(&key);
        assert_eq!(t.name(&key), None);
        assert_eq!(
            t.answer("nas.home.internal", QueryType::Aaaa),
            Answer::NxDomain
        );
        let ptr = ptr_name(&OverlayAddrs::derive(&nid, &key).ula);
        assert_eq!(t.answer(&ptr, QueryType::Ptr), Answer::NxDomain);
        assert!(t.add_name("nas", key), "the label is free again");
    }

    #[test]
    fn hostname_edge_cases() {
        assert_eq!(sanitise_hostname(""), None);
        assert_eq!(sanitise_hostname("-.x"), None);
        assert_eq!(sanitise_hostname("Ab"), Some("ab".into()));
    }

    #[test]
    fn a_label_can_be_cleared_and_given_again_and_the_domain_changed() {
        let nid = NetworkId::from_bytes([2; 32]);
        let key = NodePublic::from_bytes([7; 32]);
        let mut t = NameTable::new(nid, "home.internal", false);
        assert!(t.add_name("old", key));
        t.clear_label(&key);
        assert_eq!(t.name(&key), None);
        assert_eq!(t.resolve("old"), None);
        assert!(t.add_name("new", key));
        assert_eq!(t.resolve("new.home.internal"), Some(key));
        t.set_domain("Lab.Internal.");
        assert_eq!(t.resolve("new.lab.internal"), Some(key));
        assert_eq!(
            t.answer("zzz.lab.internal", QueryType::Aaaa),
            Answer::NxDomain
        );
        t.set_forward(true);
        assert_eq!(
            t.answer("zzz.lab.internal", QueryType::Aaaa),
            Answer::Forward
        );
    }
}
