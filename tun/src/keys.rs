//! Key generation and derivation helpers for the CLI and app UIs (vv-01 §3.2, vv-07 §5.1).

use thiserror::Error;
use vardevall::os_rng;
use vardevall_proto::addr::OverlayAddrs;
use vardevall_proto::keys::{NetworkId, NetworkSecret, NodePublic, NodeSecret};

/// A key argument did not decode.
#[derive(Debug, Error)]
#[error("not a valid base32 key")]
pub struct KeyError;

/// A new node private key in base32.
pub fn generate_node_key() -> String {
    NodeSecret::generate(&mut os_rng()).to_base32().to_string()
}

/// The public key of a node private key (also its key-id).
pub fn public_key(secret: &str) -> Result<String, KeyError> {
    let s: NodeSecret = secret.trim().parse().map_err(|_| KeyError)?;
    Ok(s.public().to_base32())
}

/// A new network secret in base32.
pub fn generate_network_secret() -> String {
    NetworkSecret::generate(&mut os_rng())
        .to_base32()
        .to_string()
}

/// The default network ID of a network secret: its public half.
pub fn network_id(secret: &str) -> Result<String, KeyError> {
    let s: NetworkSecret = secret.trim().parse().map_err(|_| KeyError)?;
    Ok(s.default_network_id().to_base32())
}

/// The overlay addresses of `key` in network `network_id`.
pub fn overlay_addrs(key: &str, network_id: &str) -> Result<OverlayAddrs, KeyError> {
    let k: NodePublic = key.trim().parse().map_err(|_| KeyError)?;
    let n: NetworkId = network_id.trim().parse().map_err(|_| KeyError)?;
    Ok(OverlayAddrs::derive(&n, &k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_round_trip() {
        let k = generate_node_key();
        assert_eq!(k.len(), 52);
        let p = public_key(&k).unwrap();
        assert_eq!(p.len(), 52);
        assert_ne!(p, k);
        let n = generate_network_secret();
        let id = network_id(&format!("{n}\n")).unwrap();
        let a = overlay_addrs(&p, &id).unwrap();
        assert_eq!(a.ula.octets()[0], 0xfd);
        assert!(public_key("nope").is_err());
    }
}
