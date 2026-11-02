//! Resolving the host and port of a `stun:` or `turn:` URI to socket addresses.

use std::net::SocketAddr;
use std::time::Duration;

use vardevall_switch_proto::api::TurnCredentials;
use vardevall_switch_proto::turn::{Server, TurnOffer, TurnTransport};
use vardevall_switch_proto::uri::{parse_stun, parse_turn_udp, parse_turns};

use crate::config::SwitchAuth;
use crate::net::mark::SocketMark;
use crate::net::resolver::{MAX_URIS, resolve};

/// The resolved STUN servers of the `stun:` URIs a switch advertises (vv-04 §3.4).
pub(super) async fn stun_servers(uris: &[String], mark: SocketMark) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for target in uris.iter().filter_map(|u| parse_stun(u)).take(MAX_URIS) {
        for a in resolve(&target, mark).await {
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }
    out
}

/// The TURN servers of the credentials a switch issued; `None` if no URI resolves.
pub(super) async fn turn_offer(
    creds: &TurnCredentials,
    auth: &SwitchAuth,
    mark: SocketMark,
) -> Option<TurnOffer> {
    let mut servers: Vec<Server> = Vec::new();
    for target in creds
        .urls
        .iter()
        .filter_map(|u| parse_turn_udp(u))
        .take(MAX_URIS)
    {
        for a in resolve(&target, mark).await {
            let s = Server::udp(a);
            if !servers.contains(&s) {
                servers.push(s);
            }
        }
    }
    for target in creds
        .urls
        .iter()
        .filter_map(|u| parse_turns(u))
        .take(MAX_URIS)
    {
        for addr in resolve(&target, mark).await {
            let s = Server {
                addr,
                transport: TurnTransport::Tls {
                    host: target.host.clone(),
                    auth: auth.clone(),
                },
            };
            if !servers.contains(&s) {
                servers.push(s);
            }
        }
    }
    if servers.is_empty() {
        return None;
    }
    Some(TurnOffer {
        servers,
        username: creds.username.clone(),
        password: creds.credential.clone(),
        ttl: Duration::from_secs(creds.ttl),
        bits_per_second: creds.bits_per_second,
        bytes: creds.bytes,
        realm: creds.realm.clone(),
        nonce: creds.nonce.clone(),
        priority: 0,
    })
}
