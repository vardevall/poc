//! The resolvers of the underlying network, as the host lists them.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

const DNS_PORT: u16 = 53;

/// A resolver as `LinkProperties` gives it: `192.0.2.1`, `2001:db8::1`, or a link-local address
/// with the index of its interface, `fe80::1%23`, without which it cannot be reached. Anything
/// else, such as a link-local address without an index, is `None`.
pub fn parse(text: &str) -> Option<SocketAddr> {
    let (ip, scope) = match text.split_once('%') {
        Some((ip, scope)) => (ip, Some(scope.parse::<u32>().ok()?)),
        None => (text, None),
    };
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => Some(SocketAddr::new(v4.into(), DNS_PORT)),
        IpAddr::V6(v6) => {
            let scope = scope.unwrap_or(0);
            if scope == 0 && is_link_local(&v6) {
                return None;
            }
            Some(SocketAddrV6::new(v6, DNS_PORT, 0, scope).into())
        }
    }
}

fn is_link_local(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forms_link_properties_give() {
        assert_eq!(parse("10.0.2.3"), Some("10.0.2.3:53".parse().unwrap()));
        assert_eq!(
            parse("2001:db8::1"),
            Some("[2001:db8::1]:53".parse().unwrap())
        );
        assert_eq!(
            parse("fe80::1%7"),
            Some(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 7).into())
        );
        assert_eq!(
            parse("2001:db8::1%7"),
            Some(SocketAddrV6::new("2001:db8::1".parse().unwrap(), 53, 0, 7).into())
        );
    }

    #[test]
    fn what_cannot_be_reached_is_left_out() {
        assert_eq!(parse("fe80::1"), None);
        assert_eq!(parse("fe80::1%0"), None);
        assert_eq!(parse("fe80::1%wlan0"), None);
        assert_eq!(parse("not an address"), None);
        assert_eq!(parse(""), None);
    }
}
