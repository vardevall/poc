//! The `stun:` and `turn:` URIs of vv-04 §3.4 and §4.4 [RFC 7064, RFC 7065], read to a host and
//! port.

/// Default port of `stun:` and `turn:` URIs.
const DEFAULT_PORT: u16 = 3478;

/// A host and port from a URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    /// A DNS name or an IP literal, without brackets.
    pub host: String,
    /// The port.
    pub port: u16,
}

fn host_port(rest: &str) -> Option<HostPort> {
    host_port_or(rest, DEFAULT_PORT)
}

fn host_port_or(rest: &str, default: u16) -> Option<HostPort> {
    let rest = rest.split('?').next()?;
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (host, tail) = v6.split_once(']')?;
        match tail.strip_prefix(':') {
            Some(p) => (host, Some(p)),
            None if tail.is_empty() => (host, None),
            None => return None,
        }
    } else {
        match rest.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        Some(p) => p.parse().ok().filter(|p| *p != 0)?,
        None => default,
    };
    Some(HostPort {
        host: host.to_owned(),
        port,
    })
}

/// A `stun:` URI; `stuns:` is not supported.
pub fn parse_stun(uri: &str) -> Option<HostPort> {
    host_port(uri.strip_prefix("stun:")?)
}

/// A `turn:` URI for UDP: `transport=udp` or none. `turns:` and other transports are not
/// supported.
pub fn parse_turn_udp(uri: &str) -> Option<HostPort> {
    let rest = uri.strip_prefix("turn:")?;
    let query = rest.split_once('?').map(|(_, q)| q);
    let udp = query.is_none_or(|q| q.split('&').any(|p| p == "transport=udp"));
    if !udp {
        return None;
    }
    host_port(rest)
}

/// A `turns:` URI: TURN over TLS on TCP (`transport=tcp` or none) [RFC 7065 §3.1]. The default
/// port is 5349.
pub fn parse_turns(uri: &str) -> Option<HostPort> {
    let rest = uri.strip_prefix("turns:")?;
    let query = rest.split_once('?').map(|(_, q)| q);
    let tcp = query.is_none_or(|q| q.split('&').any(|p| p == "transport=tcp"));
    if !tcp {
        return None;
    }
    host_port_or(rest, 5349)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hp(host: &str, port: u16) -> Option<HostPort> {
        Some(HostPort {
            host: host.to_owned(),
            port,
        })
    }

    #[test]
    fn stun_uris() {
        assert_eq!(parse_stun("stun:s.example"), hp("s.example", 3478));
        assert_eq!(parse_stun("stun:s.example:19302"), hp("s.example", 19302));
        assert_eq!(
            parse_stun("stun:[2001:db8::1]:3479"),
            hp("2001:db8::1", 3479)
        );
        assert_eq!(parse_stun("stun:[2001:db8::1]"), hp("2001:db8::1", 3478));
        assert_eq!(parse_stun("stuns:s.example"), None);
        assert_eq!(parse_stun("stun:"), None);
        assert_eq!(parse_stun("stun:s:0"), None);
        assert_eq!(parse_stun("stun:s:x"), None);
        assert_eq!(parse_stun("stun:[::1"), None);
    }

    #[test]
    fn turn_uris_use_udp_only() {
        assert_eq!(parse_turn_udp("turn:t.example"), hp("t.example", 3478));
        assert_eq!(
            parse_turn_udp("turn:t.example:3478?transport=udp"),
            hp("t.example", 3478)
        );
        assert_eq!(parse_turn_udp("turn:t.example:3478?transport=tcp"), None);
        assert_eq!(parse_turn_udp("turns:t.example:443?transport=tcp"), None);
        assert_eq!(
            parse_turns("turns:t.example:443?transport=tcp"),
            hp("t.example", 443)
        );
        assert_eq!(parse_turns("turns:t.example"), hp("t.example", 5349));
        assert_eq!(parse_turns("turns:t.example:443?transport=udp"), None);
        assert_eq!(parse_turns("turn:t.example:443?transport=tcp"), None);
    }
}
