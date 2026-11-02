//! TURN and STUN credentials (vv-04 §4.5, §4.7): the `turn` and `stun` objects of a registration,
//! `POST /v0/turn` and `POST /v0/stun`.

use http::StatusCode;
use tokio::time::Instant;
use vardevall_proto::keys::{base32, crypto};
use vardevall_switch_proto::api::turn_credential;

use crate::api::{Api, ApiError, ApiRequest, ApiResponse, unix_now};
use crate::config::{Turn, TurnLimits};

/// Random bytes of the opaque id, 16 base32 characters.
const ID_BYTES: usize = 10;

/// The opaque id of a credential: random, except for the last byte, which names the TURN class of
/// the operator token (0 without one) so that the TURN server enforces the same limits without
/// any state (vv-04 §4.5). The id says nothing about the node or the network.
pub(crate) fn credential_id(class: u8) -> Option<[u8; ID_BYTES]> {
    let mut id = [0u8; ID_BYTES];
    getrandom::fill(&mut id[..ID_BYTES - 1]).ok()?;
    id[ID_BYTES - 1] = class;
    Some(id)
}

/// The class named by the opaque id of `username` (`<expiry>:<id>`); 0 if it names none.
#[cfg(feature = "stun-turn")]
pub(crate) fn credential_class(username: &str) -> u8 {
    username
        .split_once(':')
        .and_then(|(_, id)| base32::decode_array::<ID_BYTES>(id).ok())
        .map_or(0, |id| id[ID_BYTES - 1])
}

/// The NONCE that the embedded TURN server accepts with the credentials expiring at `expiry`, for
/// their whole `ttl` (vv-04 §4.5): a MAC of the expiry under a key derived from the shared secret,
/// so the server keeps no state.
pub(crate) fn credential_nonce(secret: &str, expiry: u64) -> String {
    let key: [u8; 32] = crypto::kdf("vardevall switch turn nonce", &[secret.as_bytes()]);
    base32::encode(&crypto::mac::<16>(&key, &[&expiry.to_be_bytes()]))
}

/// The JSON `stun` object for a credential issued at `unix` with the random id `id`
/// (vv-04 §4.7): built as a TURN credential, from the same secret.
pub(crate) fn stun_credentials_json(turn: &Turn, unix: u64, id: &[u8; ID_BYTES]) -> String {
    let ttl = turn.ttl.as_secs();
    let username = format!("{}:{}", unix.saturating_add(ttl), base32::encode(id));
    format!(
        "{{\"username\":\"{username}\",\"credential\":\"{}\",\"ttl\":{ttl}}}",
        turn_credential(&turn.secret, &username),
    )
}

/// The JSON `turn` object for a credential issued at `unix` with the random id `id`.
pub(crate) fn credentials_json(
    turn: &Turn,
    limits: TurnLimits,
    unix: u64,
    id: &[u8; ID_BYTES],
) -> String {
    let ttl = turn.ttl.as_secs();
    let expiry = unix.saturating_add(ttl);
    let username = format!("{expiry}:{}", base32::encode(id));
    let urls: Vec<String> = turn.urls.iter().map(|u| format!("\"{u}\"")).collect();
    let mut parts = Vec::new();
    if let Some(b) = limits.bits_per_second {
        parts.push(format!("\"bits_per_second\":{b}"));
    }
    if let Some(b) = limits.bytes {
        parts.push(format!("\"bytes\":{b}"));
    }
    let limits = if parts.is_empty() {
        String::new()
    } else {
        format!(",\"limits\":{{{}}}", parts.join(","))
    };
    let server = turn
        .server
        .as_ref()
        .map(|s| {
            format!(
                ",\"realm\":\"{}\",\"nonce\":\"{}\"",
                s.realm,
                credential_nonce(&turn.secret, expiry)
            )
        })
        .unwrap_or_default();
    format!(
        "{{\"urls\":[{}],\"username\":\"{username}\",\"credential\":\"{}\",\"ttl\":{ttl}{limits}{server}}}",
        urls.join(","),
        turn_credential(&turn.secret, &username),
    )
}

impl Api {
    /// A fresh `turn` object, or `None` if the operator offers no TURN.
    pub(crate) fn issue_turn(&self, class: u8) -> Option<String> {
        let turn = self.config.turn.as_ref()?;
        let id = credential_id(class)?;
        let limits = self.tokens.limits(class);
        Some(credentials_json(turn, limits, unix_now(), &id))
    }

    /// A fresh `stun` object, or `None` if the STUN servers need no credential.
    pub(crate) fn issue_stun(&self) -> Option<String> {
        let turn = self
            .config
            .turn
            .as_ref()
            .filter(|_| self.config.stun.auth)?;
        let id = credential_id(0)?;
        Some(stun_credentials_json(turn, unix_now(), &id))
    }

    pub(crate) fn stun(&self, req: &ApiRequest, now: Instant) -> Result<ApiResponse, ApiError> {
        let session = self.session(req)?;
        let (net, _) = self.registry.lookup(&session)?;
        self.limiters.members(&net, now)?;
        self.tokens
            .renew(self.registry.token(&session))
            .ok_or(ApiError::TokenRequired)?;
        let body = self.issue_stun().ok_or(ApiError::NotFound)?;
        Ok(ApiResponse::json(StatusCode::OK, body))
    }

    pub(crate) fn turn(&self, req: &ApiRequest, now: Instant) -> Result<ApiResponse, ApiError> {
        let session = self.session(req)?;
        let (net, _) = self.registry.lookup(&session)?;
        self.limiters.members(&net, now)?;
        let class = self
            .tokens
            .renew(self.registry.token(&session))
            .ok_or(ApiError::TokenRequired)?;
        let body = self.issue_turn(class).ok_or(ApiError::NotFound)?;
        Ok(ApiResponse::json(StatusCode::OK, body))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[cfg(feature = "stun-turn")]
    #[test]
    fn the_class_travels_in_the_last_byte_of_the_id() {
        for class in [0, 1, 7, 250] {
            let id = credential_id(class).unwrap();
            let username = format!("123:{}", base32::encode(&id));
            assert_eq!(credential_class(&username), class);
        }
        assert_eq!(credential_class("123:not-base32"), 0);
        assert_eq!(credential_class("nocolon"), 0);
    }

    #[test]
    fn matches_the_vector() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/vectors/04-switch-api.json"))
                .unwrap();
        let v = &doc["turn_credentials"][0];
        let secret = v["input"]["turn_secret_string"].as_str().unwrap();
        let expiry = v["input"]["expiry"].as_u64().unwrap();
        let ttl = v["output"]["ttl"].as_u64().unwrap();
        let turn = Turn {
            urls: vec!["turn:s.example:3478?transport=udp".to_owned()],
            secret: secret.to_owned(),
            ttl: Duration::from_secs(ttl),
            bits_per_second: Some(10_000_000),
            bytes: None,
            silent: false,
            server: None,
        };
        let id_text = v["input"]["opaque_id"].as_str().unwrap();
        let id: [u8; ID_BYTES] = base32::decode_array(id_text).unwrap();
        let limits = TurnLimits {
            bits_per_second: turn.bits_per_second,
            bytes: turn.bytes,
        };
        let json = credentials_json(&turn, limits, expiry - ttl, &id);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["username"], v["output"]["username"]);
        assert_eq!(parsed["credential"], v["output"]["credential"]);
        assert_eq!(parsed["ttl"], ttl);
        assert_eq!(parsed["limits"]["bits_per_second"], 10_000_000);
        assert!(parsed["limits"].get("bytes").is_none());
        assert!(parsed.get("nonce").is_none() && parsed.get("realm").is_none());

        let stun: serde_json::Value =
            serde_json::from_str(&stun_credentials_json(&turn, expiry - ttl, &id)).unwrap();
        assert_eq!(stun["username"], v["output"]["username"]);
        assert_eq!(stun["credential"], v["output"]["credential"]);
        assert_eq!(stun["ttl"], ttl);
        assert!(stun.get("limits").is_none());
    }

    #[test]
    fn the_nonce_depends_on_the_secret_and_the_expiry() {
        let n = credential_nonce("secret", 1000);
        assert_eq!(n, credential_nonce("secret", 1000));
        assert_ne!(n, credential_nonce("secret", 1001));
        assert_ne!(n, credential_nonce("other", 1000));
        assert_eq!(n.len(), 26);
    }
}
