//! Which peer addresses an allocation may reach (RFC 8656 §21 on relaying to private networks).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn v4_private(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

fn v6_private(a: Ipv6Addr) -> bool {
    let s = a.segments();
    a.is_loopback()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        || (s[..6] == [0, 0, 0, 0, 0, 0])
        || (s[0] == 0x64 && s[1] == 0xff9b && (s[2..6] == [0, 0, 0, 0] || s[2] == 1))
        || (s[0] == 0x100 && s[1..4] == [0, 0, 0])
        || s[0] == 0x2002
        || (s[0] == 0x2001 && (s[1] == 0 || s[1] == 0xdb8))
        || (s[0] == 0x3fff && s[1] < 0x1000)
}

/// Whether a peer at `ip` may be reached. Unspecified, multicast and broadcast addresses never
/// may; loopback, private, link-local, site-local, shared (RFC 6598), documentation, transition
/// (NAT64, 6to4, Teredo) and similar ranges may only if `allow_private`. IPv4-mapped IPv6
/// addresses count as the IPv4 address.
pub fn allowed(ip: IpAddr, allow_private: bool) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(a) => {
            if a.is_unspecified() || a.is_multicast() || a.is_broadcast() {
                return false;
            }
            allow_private || !v4_private(a)
        }
        IpAddr::V6(a) => {
            if a.is_unspecified() || a.is_multicast() {
                return false;
            }
            allow_private || !v6_private(a)
        }
    }
}

/// [`allowed`] for a transport address.
pub fn allowed_addr(addr: SocketAddr, allow_private: bool) -> bool {
    addr.port() != 0 && allowed(addr.ip(), allow_private)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn private_ranges_are_denied_by_default() {
        for a in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.1.2.3",
            "192.0.0.9",
            "198.18.0.1",
            "192.0.2.1",
            "198.51.100.7",
            "203.0.113.5",
            "192.88.99.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "fec0::1",
            "64:ff9b::808:808",
            "64:ff9b:1::1",
            "2002:c000:204::1",
            "2001::1",
            "2001:db8::1",
            "3fff::1",
            "100::1",
            "::5",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:203.0.113.5",
        ] {
            assert!(!allowed(ip(a), false), "{a}");
            assert!(allowed(ip(a), true) || a == "0.1.2.3", "{a}");
        }
    }

    #[test]
    fn public_addresses_pass_and_special_ones_never() {
        for a in [
            "8.8.8.8",
            "1.1.1.1",
            "198.51.101.1",
            "203.0.114.1",
            "2606:4700::1111",
            "2001:4860:4860::8888",
            "2a00:1450::1",
            "64:ff9a::1",
            "2001:1::1",
            "3fff:1000::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(allowed(ip(a), false), "{a}");
        }
        for a in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "ff02::1"] {
            assert!(!allowed(ip(a), true), "{a}");
        }
        assert!(!allowed_addr("8.8.8.8:0".parse().unwrap(), false));
    }
}
