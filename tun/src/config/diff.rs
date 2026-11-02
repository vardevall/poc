//! The difference between the file an interface runs with and a file read again, and which of it
//! a running interface can take.
//!
//! A running interface takes live: the peers (added, removed, renamed, their endpoints and PSK),
//! its own name, the domain and `forward`, the STUN and TURN servers, the services and the
//! `[exit]` it serves. The rest needs a restart, and the diff names those fields.

use vardevall_proto::keys::{NodePublic, crypto::ct_eq};

use super::{Config, PeerEntry};

/// A change to one peer's name: the key, the name before and the name after.
pub type Rename = (NodePublic, Option<String>, Option<String>);

/// What differs between two configurations of one interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigDiff {
    /// The fields that differ and cannot change on a running interface.
    pub restart: Vec<&'static str>,
    /// Peers in the new file only, with their names.
    pub peers_added: Vec<(NodePublic, Option<String>)>,
    /// Peers in the old file only, with their names.
    pub peers_removed: Vec<(NodePublic, Option<String>)>,
    /// Peers in both whose name differs.
    pub peers_renamed: Vec<Rename>,
    /// Peers in both whose endpoint or PSK differs.
    pub peers_changed: Vec<NodePublic>,
    /// The node's own name differs.
    pub own_name: bool,
    /// The domain differs.
    pub domain: bool,
    /// `forward` differs.
    pub forward: bool,
    /// The `[[stun]]` entries differ.
    pub stun: bool,
    /// The `[[turn]]` entries differ.
    pub turn: bool,
    /// The `[[service]]` entries differ.
    pub services: bool,
    /// The `[exit]` differs.
    pub exit: bool,
}

fn secrets_differ(a: &[u8; 32], b: &[u8; 32]) -> bool {
    !ct_eq(a, b)
}

fn same_peer(a: &PeerEntry, b: &PeerEntry) -> bool {
    let psk = |p: &PeerEntry| {
        p.preshared_key
            .as_ref()
            .map_or([0u8; 32], |k| *k.as_bytes())
    };
    a.endpoints == b.endpoints
        && a.endpoint_local == b.endpoint_local
        && !secrets_differ(&psk(a), &psk(b))
}

impl ConfigDiff {
    /// The difference from `old` to `new`.
    pub fn between(old: &Config, new: &Config) -> ConfigDiff {
        let mut d = ConfigDiff::default();
        let restart = [
            (
                "private_key",
                secrets_differ(old.private_key.as_bytes(), new.private_key.as_bytes()),
            ),
            (
                "network_secret",
                secrets_differ(old.network_secret.as_bytes(), new.network_secret.as_bytes()),
            ),
            ("network_id", old.network_id != new.network_id),
            ("listen_port", old.listen_port != new.listen_port),
            ("mtu", old.mtu != new.mtu),
            ("mdns", old.mdns != new.mdns),
            ("accept_members", old.accept_members != new.accept_members),
            ("fallback_delay", old.fallback_delay != new.fallback_delay),
            ("switch_path", old.switch_path != new.switch_path),
            ("tun_class", old.tun_class != new.tun_class),
            ("detect_timeout", old.detect_timeout != new.detect_timeout),
            ("switch", old.switches != new.switches),
        ];
        d.restart = restart
            .into_iter()
            .filter_map(|(name, differs)| differs.then_some(name))
            .collect();

        for p in &new.peers {
            match old.peers.iter().find(|o| o.public_key == p.public_key) {
                None => d.peers_added.push((p.public_key, p.name.clone())),
                Some(o) => {
                    if o.name != p.name {
                        d.peers_renamed
                            .push((p.public_key, o.name.clone(), p.name.clone()));
                    }
                    if !same_peer(o, p) {
                        d.peers_changed.push(p.public_key);
                    }
                }
            }
        }
        for o in &old.peers {
            if !new.peers.iter().any(|p| p.public_key == o.public_key) {
                d.peers_removed.push((o.public_key, o.name.clone()));
            }
        }
        d.own_name = old.own_name != new.own_name;
        d.domain = old.domain != new.domain;
        d.forward = old.forward != new.forward;
        d.stun = old.stun != new.stun;
        d.turn = old.turns != new.turns;
        d.services = old.services != new.services;
        d.exit = old.exit != new.exit;
        d
    }

    /// Whether nothing differs.
    pub fn is_empty(&self) -> bool {
        *self == ConfigDiff::default()
    }

    /// Whether some difference needs a restart.
    pub fn needs_restart(&self) -> bool {
        !self.restart.is_empty()
    }

    /// One line for each difference, for a person to read; no secret appears in it.
    pub fn lines(&self) -> Vec<String> {
        fn who(key: &NodePublic, name: &Option<String>) -> String {
            let short = key.to_base32();
            match name {
                Some(n) => format!("{n} ({})", &short[..8]),
                None => short[..8].to_owned(),
            }
        }
        let mut out = Vec::new();
        for (k, n) in &self.peers_added {
            out.push(format!("peer added: {}", who(k, n)));
        }
        for (k, n) in &self.peers_removed {
            out.push(format!("peer removed: {}", who(k, n)));
        }
        for (k, from, to) in &self.peers_renamed {
            let name = |n: &Option<String>| n.clone().unwrap_or_else(|| "(no name)".to_owned());
            out.push(format!(
                "peer {} renamed: {} -> {}",
                &k.to_base32()[..8],
                name(from),
                name(to)
            ));
        }
        for k in &self.peers_changed {
            out.push(format!(
                "peer {} changed: endpoint or PSK",
                &k.to_base32()[..8]
            ));
        }
        for (differs, what) in [
            (self.own_name, "own name changed"),
            (self.domain, "domain changed"),
            (self.forward, "forward changed"),
            (self.stun, "STUN servers changed"),
            (self.turn, "TURN servers changed"),
            (self.services, "services changed"),
            (self.exit, "exit changed"),
        ] {
            if differs {
                out.push(what.to_owned());
            }
        }
        out
    }
}
