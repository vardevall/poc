//! mDNS announcements and tag matching (vv-09), and same-host registry entries (vv-10).

use std::collections::HashMap;

use crate::error::ParseError;
use crate::json::{self, Value};
use crate::keys::base32;
use crate::keys::crypto::{self, XNONCE_LEN};
use crate::keys::{NetworkSecret, NodePublic, ctx};

/// Length of the window in seconds (vv-01 §5.4).
pub const WINDOW_SECONDS: u64 = 3600;
/// DNS-SD service type without the `.local` suffix (vv-09 §2.1); the SRV name of a peer's host
/// is `<SERVICE_TYPE>.<name>`.
pub const SERVICE_TYPE: &str = "_vardevall._udp";
/// Length of a tag.
pub const TAG_LEN: usize = 16;
/// Number of characters of the instance name.
pub const INSTANCE_LEN: usize = 16;

/// The window of a Unix time (vv-01 §5.4).
pub const fn window(unix_seconds: u64) -> u64 {
    unix_seconds / WINDOW_SECONDS
}

/// `net_tag` of a window (vv-01 §5.4).
pub fn net_tag(network: &NetworkSecret, window: u64) -> [u8; TAG_LEN] {
    crypto::mac(&network.mdns_key(), &[&window.to_le_bytes()])
}

/// `node_tag` of a node and window (vv-01 §5.4).
pub fn node_tag(network: &NetworkSecret, node: &NodePublic, window: u64) -> [u8; TAG_LEN] {
    let key: [u8; 32] = crypto::kdf(ctx::MDNS_NODE, &[&*network.mdns_key(), node.as_bytes()]);
    crypto::mac(&key, &[&window.to_le_bytes()])
}

fn seal(
    network: &NetworkSecret,
    node: &NodePublic,
    window: u64,
    nonce: &[u8; XNONCE_LEN],
) -> Vec<u8> {
    let mut v = nonce.to_vec();
    v.extend(crypto::xaead_seal(
        &network.mdns_key(),
        nonce,
        &window.to_le_bytes(),
        node.as_bytes(),
    ));
    v
}

/// Opens a sealed node key `p` for `window` (vv-09 §2.2).
pub fn open_sealed(network: &NetworkSecret, window: u64, sealed: &[u8]) -> Option<NodePublic> {
    if sealed.len() != XNONCE_LEN + 32 + crypto::TAG_LEN {
        return None;
    }
    let (nonce, ct) = sealed.split_at(XNONCE_LEN);
    let nonce: [u8; XNONCE_LEN] = nonce.try_into().ok()?;
    let pt = crypto::xaead_open(&network.mdns_key(), &nonce, &window.to_le_bytes(), ct).ok()?;
    Some(NodePublic::from_bytes(pt.try_into().ok()?))
}

/// The announced fields of one interface in one window (vv-09 §2.1, vv-10 §2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    /// The window the tags belong to.
    pub window: u64,
    /// `net_tag`.
    pub net_tag: [u8; TAG_LEN],
    /// `node_tag`.
    pub node_tag: [u8; TAG_LEN],
    /// `nonce ‖ XAEAD(node_pk)`.
    pub sealed: Vec<u8>,
    /// The interface's UDP port.
    pub port: u16,
}

impl Announcement {
    /// Builds the announcement of `node` at `unix_seconds`, sealing with `nonce`.
    pub fn new(
        network: &NetworkSecret,
        node: &NodePublic,
        unix_seconds: u64,
        nonce: &[u8; XNONCE_LEN],
        port: u16,
    ) -> Self {
        let w = window(unix_seconds);
        Announcement {
            window: w,
            net_tag: net_tag(network, w),
            node_tag: node_tag(network, node, w),
            sealed: seal(network, node, w, nonce),
            port,
        }
    }

    /// The instance name: the first 16 characters of `base32(node_tag)`.
    pub fn instance(&self) -> String {
        base32::encode(&self.node_tag)[..INSTANCE_LEN].to_owned()
    }

    /// `<instance>._vardevall._udp.local`.
    pub fn service_instance_name(&self) -> String {
        format!("{}.{SERVICE_TYPE}.local", self.instance())
    }

    /// The four TXT strings, in the order of vv-09 §2.1.
    pub fn txt_strings(&self) -> [String; 4] {
        [
            "v=0".to_owned(),
            format!("n={}", base32::encode(&self.net_tag)),
            format!("k={}", base32::encode(&self.node_tag)),
            format!("p={}", base32::encode(&self.sealed)),
        ]
    }

    /// The TXT RDATA: each string preceded by its length.
    pub fn txt_rdata(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for s in self.txt_strings() {
            out.push(s.len() as u8);
            out.extend_from_slice(s.as_bytes());
        }
        out
    }

    /// The same-host registry entry (vv-10 §2.2).
    pub fn registry_entry(&self) -> RegistryEntry {
        RegistryEntry {
            window: self.window,
            n: base32::encode(&self.net_tag),
            k: base32::encode(&self.node_tag),
            p: base32::encode(&self.sealed),
            port: self.port,
        }
    }
}

/// The fields a receiver matches: from a TXT record or a registry file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tags {
    /// `n`, base32.
    pub n: String,
    /// `k`, base32.
    pub k: String,
    /// `p`, base32.
    pub p: String,
}

/// Parses the TXT strings of an announcement; `None` unless `v=0` and `n`, `k`, `p` are present.
pub fn parse_txt<S: AsRef<str>>(strings: &[S]) -> Option<Tags> {
    let (mut v, mut n, mut k, mut p) = (None, None, None, None);
    for s in strings {
        let (key, value) = s.as_ref().split_once('=')?;
        let slot = match key {
            "v" => &mut v,
            "n" => &mut n,
            "k" => &mut k,
            "p" => &mut p,
            _ => continue,
        };
        slot.get_or_insert(value.to_owned());
    }
    (v.as_deref() == Some("0")).then_some(())?;
    Some(Tags {
        n: n?,
        k: k?,
        p: p?,
    })
}

/// A same-host registry file (vv-10 §2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    /// The window of the tags.
    pub window: u64,
    /// `net_tag`, base32.
    pub n: String,
    /// `node_tag`, base32.
    pub k: String,
    /// Sealed node key, base32.
    pub p: String,
    /// The interface's UDP port.
    pub port: u16,
}

impl RegistryEntry {
    /// The file name: `<instance>.json`.
    pub fn file_name(&self) -> String {
        format!("{}.json", &self.k[..INSTANCE_LEN.min(self.k.len())])
    }

    /// The file content.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"v\":0,\"window\":{},\"n\":\"{}\",\"k\":\"{}\",\"p\":\"{}\",\"port\":{}}}",
            self.window, self.n, self.k, self.p, self.port
        )
    }

    /// Parses a file; unknown members are ignored and a missing or non-zero `v`, or a `k` outside
    /// the base32 alphabet, is rejected.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let v = json::parse(bytes)?;
        let string = |name: &str| -> Result<String, ParseError> {
            v.get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(ParseError::Field)
        };
        if v.get("v").and_then(Value::as_u64) != Some(0) {
            return Err(ParseError::Field);
        }
        let k = string("k")?;
        if !k.bytes().all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7')) {
            return Err(ParseError::Field);
        }
        Ok(RegistryEntry {
            window: v
                .get("window")
                .and_then(Value::as_u64)
                .ok_or(ParseError::Field)?,
            n: string("n")?,
            k,
            p: string("p")?,
            port: v
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())
                .ok_or(ParseError::Field)?,
        })
    }

    /// Whether readers use the entry at window `current` (vv-10 §2.2).
    pub fn is_current(&self, current: u64) -> bool {
        self.window.saturating_add(1) >= current && self.window <= current.saturating_add(1)
    }

    /// The tags to match.
    pub fn tags(&self) -> Tags {
        Tags {
            n: self.n.clone(),
            k: self.k.clone(),
            p: self.p.clone(),
        }
    }
}

/// The result of matching an announcement (vv-09 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// A configured peer.
    Peer(NodePublic),
    /// A member whose key was revealed by `p`.
    Member(NodePublic),
}

impl Match {
    /// The matched key.
    pub fn node(&self) -> &NodePublic {
        match self {
            Match::Peer(k) | Match::Member(k) => k,
        }
    }
}

/// Precomputed tags of one interface for windows `w − 1`, `w` and `w + 1` (vv-09 §2.2).
pub struct TagTable {
    network: NetworkSecret,
    accept_members: bool,
    windows: [u64; 3],
    net_tags: [[u8; TAG_LEN]; 3],
    nodes: HashMap<[u8; TAG_LEN], NodePublic>,
}

impl TagTable {
    /// Computes the tables at `unix_seconds` for the key-trusted `peers`.
    pub fn new(
        network: &NetworkSecret,
        peers: &[NodePublic],
        accept_members: bool,
        unix_seconds: u64,
    ) -> Self {
        let w = window(unix_seconds);
        let windows = [w.saturating_sub(1), w, w + 1];
        let net_tags = windows.map(|w| net_tag(network, w));
        let mut nodes = HashMap::with_capacity(peers.len() * 3);
        for peer in peers {
            for w in windows {
                nodes.insert(node_tag(network, peer, w), *peer);
            }
        }
        TagTable {
            network: network.clone(),
            accept_members,
            windows,
            net_tags,
            nodes,
        }
    }

    /// This interface's `net_tag` values for the three windows.
    pub fn net_tags(&self) -> &[[u8; TAG_LEN]; 3] {
        &self.net_tags
    }

    /// Matches an announcement's tags; `None` if it is not for this network or unknown.
    pub fn matches(&self, tags: &Tags) -> Option<Match> {
        let n: [u8; TAG_LEN] = base32::decode_array(&tags.n).ok()?;
        let slot = self.net_tags.iter().position(|t| crypto::ct_eq(t, &n))?;
        if let Ok(k) = base32::decode_array::<TAG_LEN>(&tags.k)
            && let Some(peer) = self.nodes.get(&k)
        {
            return Some(Match::Peer(*peer));
        }
        if !self.accept_members {
            return None;
        }
        let sealed = base32::decode(&tags.p).ok()?;
        open_sealed(&self.network, self.windows[slot], &sealed).map(Match::Member)
    }
}
