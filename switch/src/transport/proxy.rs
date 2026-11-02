//! The client address behind a proxy (vv-04 §2.5): the PROXY protocol, version 2 [PROXY], and a
//! forwarding header [RFC 7239]. The caller decides from which peers it believes them.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use http::{HeaderMap, HeaderName};
use tokio::io::{AsyncRead, AsyncReadExt};

const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// Longest address block accepted: the largest address family plus room for TLVs.
const MAX_BLOCK: usize = 512;

fn bad(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// Reads a PROXY protocol v2 header from the start of `r` and returns the client's source
/// address; `None` if the header carries none (`LOCAL`, or an address family not used on TCP), in
/// which case the connection's own peer is the client. Reads exactly the header.
pub(super) async fn read_v2<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<SocketAddr>> {
    let mut head = [0u8; 16];
    r.read_exact(&mut head).await?;
    if head[..12] != SIGNATURE || head[12] >> 4 != 2 {
        return Err(bad("not a PROXY protocol v2 header"));
    }
    let len = usize::from(u16::from_be_bytes([head[14], head[15]]));
    if len > MAX_BLOCK {
        return Err(bad("PROXY protocol header too long"));
    }
    let mut block = vec![0u8; len];
    r.read_exact(&mut block).await?;
    match (head[12] & 0x0f, head[13]) {
        (0, _) => Ok(None),
        (1, 0x11) if len >= 12 => {
            let ip = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
            Ok(Some(SocketAddr::new(
                ip.into(),
                u16::from_be_bytes([block[8], block[9]]),
            )))
        }
        (1, 0x21) if len >= 36 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&block[..16]);
            let ip = Ipv6Addr::from(octets).to_canonical();
            Ok(Some(SocketAddr::new(
                ip,
                u16::from_be_bytes([block[32], block[33]]),
            )))
        }
        (1, 0x00) => Ok(None),
        (1, f) if f >> 4 > 3 || f & 0x0f > 2 => Err(bad("unknown PROXY protocol family")),
        (1, 0x11 | 0x21) => Err(bad("short PROXY protocol address block")),
        (1, _) => Ok(None),
        _ => Err(bad("unknown PROXY protocol command")),
    }
}

fn node(text: &str) -> Option<IpAddr> {
    let text = text.trim().trim_matches('"');
    let host = if let Some(rest) = text.strip_prefix('[') {
        rest.split_once(']')?.0
    } else if text.bytes().filter(|b| *b == b':').count() == 1 {
        text.split_once(':')?.0
    } else {
        text
    };
    host.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

fn forwarded_for(element: &str) -> Option<IpAddr> {
    element.split(';').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("for")
            .then(|| node(value))?
    })
}

/// The client address a proxy put in the header `name`: for `Forwarded` the `for` parameter of
/// its last element, for any other header (`X-Forwarded-For`, `CF-Connecting-IP`) the last entry
/// of its comma-separated list. The last entry is the one the nearest proxy appended; entries
/// before it are what the client claimed. `None` if the header is absent or holds no address
/// (an obfuscated `Forwarded` identifier, for instance).
pub(super) fn client_address(name: &HeaderName, headers: &HeaderMap) -> Option<IpAddr> {
    let joined = headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    let last = joined.rsplit(',').next()?;
    if name.as_str() == "forwarded" {
        forwarded_for(last)
    } else {
        node(last)
    }
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn v2(command: u8, family: u8, block: &[u8]) -> Vec<u8> {
        let mut out = SIGNATURE.to_vec();
        out.extend([0x20 | command, family]);
        out.extend((block.len() as u16).to_be_bytes());
        out.extend(block);
        out
    }

    async fn parse(bytes: &[u8]) -> io::Result<Option<SocketAddr>> {
        let mut r = bytes;
        read_v2(&mut r).await
    }

    #[tokio::test]
    async fn proxy_v2_addresses() {
        let mut v4 = vec![192, 0, 2, 7, 10, 0, 0, 1, 0x30, 0x39, 0x01, 0xbb];
        assert_eq!(
            parse(&v2(1, 0x11, &v4)).await.unwrap(),
            Some("192.0.2.7:12345".parse().unwrap())
        );
        v4.extend([0, 3, 0, 1, 0xff]);
        assert_eq!(
            parse(&v2(1, 0x11, &v4)).await.unwrap(),
            Some("192.0.2.7:12345".parse().unwrap()),
            "TLVs are skipped"
        );
        let mut v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9)
            .octets()
            .to_vec();
        v6.extend([0u8; 16]);
        v6.extend([0x1f, 0x90, 0x01, 0xbb]);
        assert_eq!(
            parse(&v2(1, 0x21, &v6)).await.unwrap(),
            Some("[2001:db8::9]:8080".parse().unwrap())
        );
        assert_eq!(parse(&v2(0, 0x00, &[])).await.unwrap(), None);
        assert_eq!(parse(&v2(1, 0x00, &[])).await.unwrap(), None);
    }

    #[tokio::test]
    async fn proxy_v2_reads_only_its_header() {
        let mut bytes = v2(0, 0x00, &[]);
        bytes.extend(b"\x16\x03\x01");
        let mut r = &bytes[..];
        read_v2(&mut r).await.unwrap();
        assert_eq!(r, b"\x16\x03\x01");
    }

    #[tokio::test]
    async fn proxy_v2_rejects_what_it_does_not_understand() {
        assert!(parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.is_err());
        assert!(
            parse(b"PROXY TCP4 192.0.2.1 10.0.0.1 1 2\r\n")
                .await
                .is_err()
        );
        let mut v1 = v2(1, 0x11, &[0; 12]);
        v1[12] = 0x11;
        assert!(parse(&v1).await.is_err());
        assert!(parse(&v2(2, 0x11, &[0; 12])).await.is_err());
        assert!(parse(&v2(1, 0x11, &[0; 4])).await.is_err());
        assert!(parse(&v2(1, 0x11, &[0; 12])[..20]).await.is_err());
        let mut long = v2(1, 0x11, &[]);
        long[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(parse(&long).await.is_err());
        assert!(parse(&[]).await.is_err());
    }

    fn headers(name: &'static str, values: &[&str]) -> (HeaderName, HeaderMap) {
        let name = HeaderName::from_static(name);
        let mut h = HeaderMap::new();
        for v in values {
            h.append(name.clone(), HeaderValue::from_str(v).unwrap());
        }
        (name, h)
    }

    fn address(name: &'static str, values: &[&str]) -> Option<IpAddr> {
        let (name, h) = headers(name, values);
        client_address(&name, &h)
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn forwarded_header() {
        assert_eq!(address("forwarded", &["for=192.0.2.43"]), ip("192.0.2.43"));
        assert_eq!(
            address(
                "forwarded",
                &["for=198.51.100.17;proto=https;by=203.0.113.43"]
            ),
            ip("198.51.100.17")
        );
        assert_eq!(
            address("forwarded", &["For=\"[2001:db8:cafe::17]:4711\""]),
            ip("2001:db8:cafe::17")
        );
        assert_eq!(
            address("forwarded", &["for=1.1.1.1, for=192.0.2.60;proto=http"]),
            ip("192.0.2.60")
        );
        assert_eq!(
            address("forwarded", &["for=1.1.1.1", "for=192.0.2.61"]),
            ip("192.0.2.61")
        );
        assert_eq!(address("forwarded", &["for=_hidden"]), None);
        assert_eq!(address("forwarded", &["for=unknown"]), None);
        assert_eq!(address("forwarded", &["by=192.0.2.1"]), None);
        assert_eq!(address("forwarded", &[]), None);
    }

    #[test]
    fn other_headers_take_the_last_entry() {
        assert_eq!(
            address("x-forwarded-for", &["203.0.113.9, 198.51.100.4"]),
            ip("198.51.100.4")
        );
        assert_eq!(
            address("x-forwarded-for", &["a", "192.0.2.1:99"]),
            ip("192.0.2.1")
        );
        assert_eq!(
            address("cf-connecting-ip", &["2001:db8::5"]),
            ip("2001:db8::5")
        );
        assert_eq!(
            address("cf-connecting-ip", &["::ffff:192.0.2.5"]),
            ip("192.0.2.5")
        );
        assert_eq!(address("cf-connecting-ip", &["not an address"]), None);
        assert_eq!(address("cf-connecting-ip", &[""]), None);
    }
}
