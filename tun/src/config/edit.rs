//! Changes to the peers of a configuration that are not in the file (`vv set`).

use vardevall_proto::keys::NodePublic;

use super::{Config, ConfigError, PeerEntry, invalid, value};

/// What to do with one field of a peer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Field {
    /// Leave it as it is.
    #[default]
    Keep,
    /// Take it away.
    Clear,
    /// Give it this text.
    Set(String),
}

/// A change to one peer: it is added when the configuration has no such key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerChange {
    /// The peer's key.
    pub key: NodePublic,
    /// Its DNS name.
    pub name: Field,
    /// Its `endpoint`, as `host:port`.
    pub endpoint: Field,
    /// Remove the peer; the other fields must then be left alone.
    pub remove: bool,
}

impl PeerChange {
    /// A change of `key` that does nothing yet.
    pub fn new(key: NodePublic) -> Self {
        PeerChange {
            key,
            name: Field::Keep,
            endpoint: Field::Keep,
            remove: false,
        }
    }
}

fn peer_error(reason: String) -> ConfigError {
    ConfigError::Peer(reason)
}

impl Config {
    /// This configuration with `changes` made to its peers, validated as a file would be.
    pub fn with_peer_changes(&self, changes: &[PeerChange]) -> Result<Config, ConfigError> {
        let mut out = self.clone();
        for c in changes {
            if c.key == out.public_key {
                return Err(peer_error("a peer has the interface's own key".into()));
            }
            if c.remove {
                if c.name != Field::Keep || c.endpoint != Field::Keep {
                    return Err(peer_error("remove takes no other change".into()));
                }
                let before = out.peers.len();
                out.peers.retain(|p| p.public_key != c.key);
                if out.peers.len() == before {
                    return Err(peer_error(format!("no peer {}", c.key)));
                }
                continue;
            }
            let at = match out.peers.iter().position(|p| p.public_key == c.key) {
                Some(i) => i,
                None => {
                    out.peers.push(PeerEntry {
                        public_key: c.key,
                        name: None,
                        endpoints: Vec::new(),
                        endpoint_local: false,
                        preshared_key: None,
                    });
                    out.peers.len() - 1
                }
            };
            let peer = &mut out.peers[at];
            match &c.name {
                Field::Keep => {}
                Field::Clear => peer.name = None,
                Field::Set(n) if value::name_label(n) => peer.name = Some(n.clone()),
                Field::Set(n) => {
                    return Err(peer_error(format!("name {n:?} is not a valid label")));
                }
            }
            match &c.endpoint {
                Field::Keep => {}
                Field::Clear => {
                    peer.endpoints.clear();
                    peer.endpoint_local = false;
                }
                Field::Set(t) => {
                    let e = value::endpoint(t)
                        .ok_or_else(|| invalid("peer.endpoint", &format!("{t:?} is not valid")))?;
                    peer.endpoints = vec![e];
                }
            }
        }
        let mut names: Vec<&str> = out.own_name.iter().map(String::as_str).collect();
        for p in &out.peers {
            if let Some(n) = &p.name {
                if names.contains(&n.as_str()) {
                    return Err(peer_error(format!("duplicate name {n:?}")));
                }
                names.push(n);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Context;
    use crate::keys;

    fn config(peers: &str) -> Config {
        let text = format!(
            "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{}\"\nname = \"me\"\n{peers}",
            keys::generate_node_key(),
            keys::generate_network_secret()
        );
        Config::parse(
            &text,
            &Context {
                interface_name: "home".into(),
                hostname: None,
            },
        )
        .unwrap()
    }

    fn key() -> NodePublic {
        keys::public_key(&keys::generate_node_key())
            .unwrap()
            .parse()
            .unwrap()
    }

    #[test]
    fn a_peer_is_added_named_moved_cleared_and_removed() {
        let base = config("");
        let k = key();
        let mut add = PeerChange::new(k);
        add.name = Field::Set("lab".into());
        add.endpoint = Field::Set("192.0.2.1:4455".into());
        let c = base.with_peer_changes(&[add]).unwrap();
        assert_eq!(c.peers.len(), 1);
        assert_eq!(c.peers[0].name.as_deref(), Some("lab"));
        assert_eq!(c.peers[0].endpoints.len(), 1);
        assert!(base.peers.is_empty(), "the original is untouched");

        let mut rename = PeerChange::new(k);
        rename.name = Field::Set("bench".into());
        rename.endpoint = Field::Clear;
        let c = c.with_peer_changes(&[rename]).unwrap();
        assert_eq!(c.peers[0].name.as_deref(), Some("bench"));
        assert!(c.peers[0].endpoints.is_empty());

        let mut clear = PeerChange::new(k);
        clear.name = Field::Clear;
        let c = c.with_peer_changes(&[clear]).unwrap();
        assert_eq!(c.peers[0].name, None);

        let mut gone = PeerChange::new(k);
        gone.remove = true;
        assert!(
            c.with_peer_changes(&[gone.clone()])
                .unwrap()
                .peers
                .is_empty()
        );
        let empty = base.with_peer_changes(&[]).unwrap();
        assert!(empty.with_peer_changes(&[gone]).is_err(), "no such peer");
    }

    #[test]
    fn invalid_changes_are_refused_like_a_file() {
        let base = config("");
        let (a, b) = (key(), key());
        let named = |k, n: &str| {
            let mut c = PeerChange::new(k);
            c.name = Field::Set(n.into());
            c
        };
        assert!(base.with_peer_changes(&[named(a, "Not Valid")]).is_err());
        assert!(
            base.with_peer_changes(&[named(a, "me")]).is_err(),
            "own name"
        );
        assert!(
            base.with_peer_changes(&[named(a, "x"), named(b, "x")])
                .is_err(),
            "duplicate"
        );
        let mut bad = PeerChange::new(a);
        bad.endpoint = Field::Set("192.0.2.1:0".into());
        assert!(base.with_peer_changes(&[bad]).is_err());
        let mut own = PeerChange::new(base.public_key);
        own.name = Field::Set("y".into());
        assert!(base.with_peer_changes(&[own]).is_err());
        let mut both = PeerChange::new(a);
        both.remove = true;
        both.name = Field::Set("y".into());
        assert!(base.with_peer_changes(&[both]).is_err());
    }
}
