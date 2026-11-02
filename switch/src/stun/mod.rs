//! An embedded STUN Binding server [RFC 8489], on the codec of [`vardevall_switch_proto::stun`], for the `stun` URIs of `/v0/info` (vv-04 §3.4).
//!
//! It answers Binding requests with the client's XOR-MAPPED-ADDRESS and nothing else, keeps no
//! state and logs nothing (vv-04 §8). With `stun_auth` it answers only requests that carry a
//! credential of vv-04 §4.7 (USERNAME and MESSAGE-INTEGRITY under the short-term mechanism) and
//! stays silent otherwise. Allocation and relaying are left to the TURN server, or to coturn.

use std::net::SocketAddr;

use tokio::net::UdpSocket;
use vardevall_switch_proto::api::turn_credential;
use vardevall_switch_proto::stun::{
    Builder, Class, Message, attr, encode_xor_addr, method, verify_integrity,
};

use crate::backoff::Backoff;

/// The Binding success response to `request` for a client at `from`, or `None` if `request` is not
/// a Binding request.
pub fn respond(request: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    let m = Message::parse(request)?;
    if m.method != method::BINDING || m.class != Class::Request {
        return None;
    }
    let from = SocketAddr::new(from.ip().to_canonical(), from.port());
    Some(
        Builder::new(method::BINDING, Class::Success, &m.txid)
            .attr(attr::XOR_MAPPED_ADDRESS, &encode_xor_addr(from, &m.txid))
            .finish(),
    )
}

/// A request and the part of it that its MESSAGE-INTEGRITY covers.
pub(crate) struct Signed {
    /// The message up to its first MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256; attributes after
    /// it are not authenticated and are left out.
    pub message: Message,
    /// Whether that attribute is MESSAGE-INTEGRITY-SHA256.
    pub sha256: bool,
}

/// The authenticated part of `m`, or `None` if it has no MESSAGE-INTEGRITY. Whether the tag is
/// right is for [`verify_integrity`] to say; it looks at the same attribute.
pub(crate) fn signed(m: &Message) -> Option<Signed> {
    let at = m
        .attrs
        .iter()
        .position(|(t, _)| *t == attr::INTEGRITY || *t == attr::INTEGRITY_SHA256)?;
    Some(Signed {
        sha256: m.attrs[at].0 == attr::INTEGRITY_SHA256,
        message: Message {
            attrs: m.attrs[..at].to_vec(),
            ..m.clone()
        },
    })
}

/// The Binding success response to `request` if it carries the credential of vv-04 §4.7 at the
/// Unix time `unix`: a USERNAME `<expiry>:<id>` that has not expired and a MESSAGE-INTEGRITY, or
/// MESSAGE-INTEGRITY-SHA256, keyed by the credential of that username under `secret` (the
/// short-term mechanism, RFC 8489 §9.1). The response carries a MESSAGE-INTEGRITY of the same
/// kind. `None` for anything else: such a server sends no reply.
pub fn respond_authenticated(
    request: &[u8],
    from: SocketAddr,
    secret: &str,
    unix: u64,
) -> Option<Vec<u8>> {
    let m = Message::parse(request)?;
    if m.method != method::BINDING || m.class != Class::Request {
        return None;
    }
    let signed = signed(&m)?;
    let username = std::str::from_utf8(signed.message.get(attr::USERNAME)?).ok()?;
    let expiry: u64 = username.split_once(':')?.0.parse().ok()?;
    if expiry <= unix {
        return None;
    }
    let key = turn_credential(secret, username);
    if !verify_integrity(request, key.as_bytes()) {
        return None;
    }
    let from = SocketAddr::new(from.ip().to_canonical(), from.port());
    let reply = Builder::new(method::BINDING, Class::Success, &m.txid)
        .attr(attr::XOR_MAPPED_ADDRESS, &encode_xor_addr(from, &m.txid));
    Some(if signed.sha256 {
        reply.finish_with_integrity_sha256(key.as_bytes())
    } else {
        reply.finish_with_integrity(key.as_bytes())
    })
}

/// Answers Binding requests on `socket` until the future is dropped; a client address over its
/// limit (`stun_per_ip_per_second`) gets no answer, nor does a request without the credential
/// when `stun_auth` is on.
pub async fn serve(socket: UdpSocket, api: std::sync::Arc<crate::api::Api>) {
    let mut buf = [0u8; 576];
    let mut failing = Backoff::default();
    loop {
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(_) => {
                failing.wait().await;
                continue;
            }
        };
        failing.reset();
        if !api.allow_stun(from.ip()) {
            continue;
        }
        if let Some(reply) = api.stun_response(&buf[..n], from) {
            let _ = socket.send_to(&reply, from).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(txid: [u8; 12]) -> Vec<u8> {
        Builder::new(method::BINDING, Class::Request, &txid).finish()
    }

    fn mapped(reply: &[u8]) -> Option<SocketAddr> {
        Message::parse(reply)?.xor_addr(attr::XOR_MAPPED_ADDRESS)
    }

    #[test]
    fn reports_the_client_address() {
        for a in ["192.0.2.1:32853", "[2001:db8::1]:4000"] {
            let a: SocketAddr = a.parse().unwrap();
            assert_eq!(mapped(&respond(&request([7; 12]), a).unwrap()), Some(a));
        }
        let mapped_v4: SocketAddr = "[::ffff:192.0.2.1]:5".parse().unwrap();
        let r = respond(&request([7; 12]), mapped_v4).unwrap();
        assert_eq!(mapped(&r), Some("192.0.2.1:5".parse().unwrap()));
    }

    #[test]
    fn rfc5769_sample_address_bytes() {
        let txid = [
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ];
        let r = respond(&request(txid), "192.0.2.1:32853".parse().unwrap()).unwrap();
        assert_eq!(&r[20..24], &[0x00, 0x20, 0x00, 0x08]);
        assert_eq!(&r[24..], &[0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]);
    }

    #[test]
    fn rejects_everything_else() {
        let ok = request([1; 12]);
        let from: SocketAddr = "192.0.2.1:1".parse().unwrap();
        assert!(respond(&ok[..19], from).is_none());
        let mut bad = ok.clone();
        bad[4] ^= 1;
        assert!(respond(&bad, from).is_none());
        let mut bad = ok.clone();
        bad[3] = 4;
        assert!(respond(&bad, from).is_none());
        let mut response = ok;
        response[0] = 1;
        assert!(respond(&response, from).is_none());
    }
}
