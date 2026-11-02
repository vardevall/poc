//! STUN messages [RFC 8489] with the TURN methods and attributes of [RFC 8656] (vv-04 §3.4,
//! vv-05 §3), shared by the STUN and TURN clients of the node and the server of the switch.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rand_core::CryptoRng;
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// The magic cookie.
pub const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
/// Length of the header.
pub const HEADER: usize = 20;
/// Length of a MESSAGE-INTEGRITY attribute with its header.
const INTEGRITY_ATTR: usize = 24;
/// Length of a MESSAGE-INTEGRITY-SHA256 attribute with its header.
const INTEGRITY256_ATTR: usize = 36;
/// Length of a FINGERPRINT attribute with its header.
const FINGERPRINT_ATTR: usize = 8;

/// Attribute types.
pub mod attr {
    /// USERNAME.
    pub const USERNAME: u16 = 0x0006;
    /// MESSAGE-INTEGRITY.
    pub const INTEGRITY: u16 = 0x0008;
    /// MESSAGE-INTEGRITY-SHA256.
    pub const INTEGRITY_SHA256: u16 = 0x001c;
    /// FINGERPRINT.
    pub const FINGERPRINT: u16 = 0x8028;
    /// REQUESTED-ADDRESS-FAMILY.
    pub const REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
    /// DONT-FRAGMENT.
    pub const DONT_FRAGMENT: u16 = 0x001a;
    /// ERROR-CODE.
    pub const ERROR_CODE: u16 = 0x0009;
    /// CHANNEL-NUMBER.
    pub const CHANNEL_NUMBER: u16 = 0x000c;
    /// LIFETIME.
    pub const LIFETIME: u16 = 0x000d;
    /// XOR-PEER-ADDRESS.
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    /// DATA.
    pub const DATA: u16 = 0x0013;
    /// REALM.
    pub const REALM: u16 = 0x0014;
    /// NONCE.
    pub const NONCE: u16 = 0x0015;
    /// XOR-RELAYED-ADDRESS.
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    /// REQUESTED-TRANSPORT.
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    /// XOR-MAPPED-ADDRESS.
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
}

/// Methods.
pub mod method {
    /// Binding.
    pub const BINDING: u16 = 0x001;
    /// Allocate.
    pub const ALLOCATE: u16 = 0x003;
    /// Refresh.
    pub const REFRESH: u16 = 0x004;
    /// Send.
    pub const SEND: u16 = 0x006;
    /// Data.
    pub const DATA: u16 = 0x007;
    /// CreatePermission.
    pub const CREATE_PERMISSION: u16 = 0x008;
    /// ChannelBind.
    pub const CHANNEL_BIND: u16 = 0x009;
}

/// The class of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// A request.
    Request,
    /// An indication.
    Indication,
    /// A success response.
    Success,
    /// An error response.
    Error,
}

/// A parsed message; attribute values are copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The method.
    pub method: u16,
    /// The class.
    pub class: Class,
    /// The transaction id.
    pub txid: [u8; 12],
    /// Attributes in order of appearance.
    pub attrs: Vec<(u16, Vec<u8>)>,
}

fn type_of(method: u16, class: Class) -> u16 {
    let c = match class {
        Class::Request => 0b00,
        Class::Indication => 0b01,
        Class::Success => 0b10,
        Class::Error => 0b11,
    };
    ((method & 0x0f80) << 2)
        | ((method & 0x0070) << 1)
        | (method & 0x000f)
        | ((c & 2) << 7)
        | ((c & 1) << 4)
}

fn split_type(t: u16) -> (u16, Class) {
    let method = ((t & 0x3e00) >> 2) | ((t & 0x00e0) >> 1) | (t & 0x000f);
    let class = match ((t >> 7) & 2) | ((t >> 4) & 1) {
        0 => Class::Request,
        1 => Class::Indication,
        2 => Class::Success,
        _ => Class::Error,
    };
    (method, class)
}

impl Message {
    /// Parses a message, or `None` if `buf` is not a well-formed STUN message. Integrity is not
    /// checked: a response is matched to its request by the random transaction id.
    pub fn parse(buf: &[u8]) -> Option<Message> {
        if buf.len() < HEADER || buf[0] & 0xc0 != 0 || buf[4..8] != COOKIE {
            return None;
        }
        let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        if len % 4 != 0 || buf.len() != HEADER + len {
            return None;
        }
        let (method, class) = split_type(u16::from_be_bytes([buf[0], buf[1]]));
        let mut txid = [0u8; 12];
        txid.copy_from_slice(&buf[8..HEADER]);
        let mut attrs = Vec::new();
        let mut rest = &buf[HEADER..];
        while !rest.is_empty() {
            if rest.len() < 4 {
                return None;
            }
            let t = u16::from_be_bytes([rest[0], rest[1]]);
            let l = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
            let padded = l.div_ceil(4) * 4;
            if rest.len() < 4 + padded {
                return None;
            }
            attrs.push((t, rest[4..4 + l].to_vec()));
            rest = &rest[4 + padded..];
        }
        Some(Message {
            method,
            class,
            txid,
            attrs,
        })
    }

    /// The value of the first attribute of type `t`.
    pub fn get(&self, t: u16) -> Option<&[u8]> {
        self.attrs
            .iter()
            .find(|(a, _)| *a == t)
            .map(|(_, v)| v.as_slice())
    }

    /// An address attribute that is XORed with the cookie and transaction id.
    pub fn xor_addr(&self, t: u16) -> Option<SocketAddr> {
        decode_xor_addr(self.get(t)?, &self.txid)
    }

    /// The code of an ERROR-CODE attribute, for example 401.
    pub fn error_code(&self) -> Option<u16> {
        let v = self.get(attr::ERROR_CODE)?;
        (v.len() >= 4).then(|| u16::from(v[2] & 7) * 100 + u16::from(v[3]))
    }

    /// LIFETIME in seconds.
    pub fn lifetime(&self) -> Option<u32> {
        let v: [u8; 4] = self.get(attr::LIFETIME)?.try_into().ok()?;
        Some(u32::from_be_bytes(v))
    }
}

fn decode_xor_addr(v: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if v.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes([v[2], v[3]]) ^ 0x2112;
    let mut mask = COOKIE.to_vec();
    mask.extend_from_slice(txid);
    match v[1] {
        1 if v.len() == 8 => {
            let o: Vec<u8> = v[4..8].iter().zip(&mask).map(|(a, m)| a ^ m).collect();
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])),
                port,
            ))
        }
        2 if v.len() == 20 => {
            let o: Vec<u8> = v[4..20].iter().zip(&mask).map(|(a, m)| a ^ m).collect();
            let octets: [u8; 16] = o.try_into().ok()?;
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

/// The value of an XOR address attribute.
pub fn encode_xor_addr(addr: SocketAddr, txid: &[u8; 12]) -> Vec<u8> {
    let port = (addr.port() ^ 0x2112).to_be_bytes();
    let mut mask = COOKIE.to_vec();
    mask.extend_from_slice(txid);
    let (family, octets) = match addr.ip() {
        IpAddr::V4(a) => (1u8, a.octets().to_vec()),
        IpAddr::V6(a) => (2u8, a.octets().to_vec()),
    };
    let mut v = vec![0, family, port[0], port[1]];
    v.extend(octets.iter().zip(&mask).map(|(a, m)| a ^ m));
    v
}

/// Builds a message.
pub struct Builder {
    buf: Vec<u8>,
}

impl Builder {
    /// A message without attributes.
    pub fn new(method: u16, class: Class, txid: &[u8; 12]) -> Self {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&type_of(method, class).to_be_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&COOKIE);
        buf.extend_from_slice(txid);
        Builder { buf }
    }

    /// Appends an attribute.
    pub fn attr(mut self, t: u16, value: &[u8]) -> Self {
        self.buf.extend_from_slice(&t.to_be_bytes());
        self.buf
            .extend_from_slice(&u16::try_from(value.len()).unwrap_or(0).to_be_bytes());
        self.buf.extend_from_slice(value);
        self.buf.resize(self.buf.len().div_ceil(4) * 4, 0);
        self
    }

    fn set_len(&mut self, extra: usize) {
        let len = u16::try_from(self.buf.len() - HEADER + extra).unwrap_or(0);
        self.buf[2..4].copy_from_slice(&len.to_be_bytes());
    }

    /// The message without MESSAGE-INTEGRITY.
    pub fn finish(mut self) -> Vec<u8> {
        self.set_len(0);
        self.buf
    }

    /// The message with MESSAGE-INTEGRITY computed under `key` (RFC 8489 §14.5).
    pub fn finish_with_integrity(mut self, key: &[u8]) -> Vec<u8> {
        self.set_len(INTEGRITY_ATTR);
        let tag = hmac_sha1(key, &self.buf);
        self.buf.extend_from_slice(&attr::INTEGRITY.to_be_bytes());
        self.buf.extend_from_slice(&20u16.to_be_bytes());
        self.buf.extend_from_slice(&tag);
        self.buf
    }

    /// The message with MESSAGE-INTEGRITY-SHA256 computed under `key` (RFC 8489 §14.6).
    pub fn finish_with_integrity_sha256(mut self, key: &[u8]) -> Vec<u8> {
        self.set_len(INTEGRITY256_ATTR);
        let tag = hmac_sha256(key, &self.buf);
        self.buf
            .extend_from_slice(&attr::INTEGRITY_SHA256.to_be_bytes());
        self.buf.extend_from_slice(&32u16.to_be_bytes());
        self.buf.extend_from_slice(&tag);
        self.buf
    }

    /// The message with a FINGERPRINT (RFC 8489 §14.7), for demultiplexing on a shared port.
    pub fn finish_with_fingerprint(mut self) -> Vec<u8> {
        self.set_len(FINGERPRINT_ATTR);
        let crc = crc32(&self.buf) ^ 0x5354_554e;
        self.buf.extend_from_slice(&attr::FINGERPRINT.to_be_bytes());
        self.buf.extend_from_slice(&4u16.to_be_bytes());
        self.buf.extend_from_slice(&crc.to_be_bytes());
        self.buf
    }
}

fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

fn hmac<M: Mac + KeyInit, const N: usize>(key: &[u8], data: &[u8]) -> [u8; N] {
    let Ok(mut mac) = <M as KeyInit>::new_from_slice(key) else {
        return [0; N];
    };
    mac.update(data);
    <[u8; N]>::try_from(mac.finalize().into_bytes().as_slice()).unwrap_or([0; N])
}

/// `HMAC-SHA1`.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    hmac::<Hmac<Sha1>, 20>(key, data)
}

/// `HMAC-SHA256`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac::<Hmac<Sha256>, 32>(key, data)
}

/// The long-term credential key `MD5(username ":" realm ":" password)` (RFC 8489 §9.2.2).
pub fn long_term_key(username: &[u8], realm: &[u8], password: &[u8]) -> [u8; 16] {
    let mut input = username.to_vec();
    input.push(b':');
    input.extend_from_slice(realm);
    input.push(b':');
    input.extend_from_slice(password);
    Md5::digest(&input).into()
}

/// A random transaction id.
pub fn new_txid(rng: &mut impl CryptoRng) -> [u8; 12] {
    let mut t = [0u8; 12];
    rng.fill_bytes(&mut t);
    t
}

/// Whether the first byte of a datagram marks it as STUN or TURN signalling (vv-03 §2.1).
pub fn looks_like_stun(first: u8) -> bool {
    first <= 3
}

/// Whether `raw` carries a valid MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 under `key`; the
/// FINGERPRINT that may follow is not covered (RFC 8489 §14.5).
pub fn verify_integrity(raw: &[u8], key: &[u8]) -> bool {
    let mut off = HEADER;
    while off + 4 <= raw.len() {
        let t = u16::from_be_bytes([raw[off], raw[off + 1]]);
        let l = usize::from(u16::from_be_bytes([raw[off + 2], raw[off + 3]]));
        let padded = l.div_ceil(4) * 4;
        if t == attr::INTEGRITY || t == attr::INTEGRITY_SHA256 {
            let Some(tag) = raw.get(off + 4..off + 4 + l) else {
                return false;
            };
            let mut head = raw[..off].to_vec();
            let len = u16::try_from(off - HEADER + 4 + padded).unwrap_or(0);
            head[2..4].copy_from_slice(&len.to_be_bytes());
            let expected: Vec<u8> = if t == attr::INTEGRITY {
                hmac_sha1(key, &head).to_vec()
            } else {
                hmac_sha256(key, &head).to_vec()
            };
            return tag.len() == expected.len() && bool::from(tag.ct_eq(&expected));
        }
        off += 4 + padded;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_round_trip() {
        for (m, c) in [
            (method::BINDING, Class::Request),
            (method::BINDING, Class::Success),
            (method::ALLOCATE, Class::Error),
            (method::SEND, Class::Indication),
            (method::DATA, Class::Indication),
            (method::CHANNEL_BIND, Class::Success),
        ] {
            assert_eq!(split_type(type_of(m, c)), (m, c));
        }
        assert_eq!(type_of(method::BINDING, Class::Request), 0x0001);
        assert_eq!(type_of(method::BINDING, Class::Success), 0x0101);
        assert_eq!(type_of(method::ALLOCATE, Class::Error), 0x0113);
        assert_eq!(type_of(method::SEND, Class::Indication), 0x0016);
    }

    #[test]
    fn rfc5769_binding_response() {
        // RFC 5769 §2.2 (IPv4), without SOFTWARE and FINGERPRINT.
        let txid = [
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ];
        let msg = Builder::new(method::BINDING, Class::Success, &txid)
            .attr(
                attr::XOR_MAPPED_ADDRESS,
                &[0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43],
            )
            .finish();
        let m = Message::parse(&msg).unwrap();
        assert_eq!((m.method, m.class), (method::BINDING, Class::Success));
        assert_eq!(
            m.xor_addr(attr::XOR_MAPPED_ADDRESS),
            Some("192.0.2.1:32853".parse().unwrap())
        );
    }

    #[test]
    fn long_term_key_and_integrity() {
        // The key was computed with Python's hashlib over the same string.
        let user = "\u{30de}\u{30c8}\u{30ea}\u{30c3}\u{30af}\u{30b9}";
        let key = long_term_key(user.as_bytes(), b"example.org", b"TheMatrIX");
        assert_eq!(
            key,
            [
                0xe8, 0xca, 0x7a, 0xd5, 0x9d, 0x5e, 0xb0, 0x51, 0x8e, 0x31, 0x29, 0x11, 0xd2, 0xda,
                0xb2, 0xa9
            ]
        );
        let txid = [7u8; 12];
        let raw = Builder::new(method::ALLOCATE, Class::Request, &txid)
            .attr(attr::USERNAME, b"u")
            .finish_with_integrity(&key);
        assert!(verify_integrity(&raw, &key));
        let mut bad = raw.clone();
        bad[HEADER + 4] ^= 1;
        assert!(!verify_integrity(&bad, &key));
    }

    #[test]
    fn hmac_known_answers() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&hmac_sha1(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn xor_addresses_round_trip() {
        let txid = [3u8; 12];
        for a in ["192.0.2.9:1", "[2001:db8::5]:65535"] {
            let a: SocketAddr = a.parse().unwrap();
            let m = Builder::new(method::BINDING, Class::Success, &txid)
                .attr(attr::XOR_MAPPED_ADDRESS, &encode_xor_addr(a, &txid))
                .finish();
            assert_eq!(
                Message::parse(&m)
                    .unwrap()
                    .xor_addr(attr::XOR_MAPPED_ADDRESS),
                Some(a)
            );
        }
    }

    #[test]
    fn malformed_messages_are_rejected() {
        let ok = Builder::new(method::BINDING, Class::Request, &[1; 12])
            .attr(attr::USERNAME, b"abc")
            .finish();
        assert!(Message::parse(&ok).is_some());
        assert!(Message::parse(&ok[..ok.len() - 1]).is_none());
        let mut bad = ok.clone();
        bad[4] = 0;
        assert!(Message::parse(&bad).is_none());
        let mut bad = ok.clone();
        bad[0] |= 0x80;
        assert!(Message::parse(&bad).is_none());
        let mut bad = ok;
        bad[HEADER + 3] = 200;
        assert!(Message::parse(&bad).is_none());
        assert!(Message::parse(&[]).is_none());
    }

    #[test]
    fn error_codes_and_lifetimes() {
        let m = Message {
            method: method::ALLOCATE,
            class: Class::Error,
            txid: [0; 12],
            attrs: vec![
                (attr::ERROR_CODE, vec![0, 0, 4, 1, b'x']),
                (attr::LIFETIME, 600u32.to_be_bytes().to_vec()),
            ],
        };
        assert_eq!(m.error_code(), Some(401));
        assert_eq!(m.lifetime(), Some(600));
    }

    #[test]
    fn sha256_integrity_and_fingerprint() {
        let raw = Builder::new(method::ALLOCATE, Class::Request, &[2; 12])
            .attr(attr::USERNAME, b"u")
            .finish_with_integrity_sha256(b"k");
        assert!(verify_integrity(&raw, b"k"));
        assert!(!verify_integrity(&raw, b"x"));
        let fp = Builder::new(method::BINDING, Class::Success, &[2; 12]).finish_with_fingerprint();
        assert!(
            Message::parse(&fp)
                .unwrap()
                .get(attr::FINGERPRINT)
                .is_some()
        );
        // RFC 5769 §2.1 sample request: the FINGERPRINT of the whole message.
        let sample = [
            0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
            0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e,
            0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24,
            0x00, 0x04, 0x6e, 0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1,
            0x51, 0x26, 0x3b, 0x36, 0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68,
            0x36, 0x76, 0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c,
            0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5,
            0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf,
        ];
        assert_eq!(
            crc32(&sample[..sample.len() - 8]) ^ 0x5354_554e,
            0xe57a_3bcf
        );
    }
}
