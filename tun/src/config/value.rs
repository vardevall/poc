//! Parsers for the value types of interface files (vv-07 §2.2, §3).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use vardevall::Endpoint;
use vardevall_proto::addr::is_valid_label;

/// Parses a duration: a non-negative integer followed by `ms`, `s`, `m` or `h`, or `"0"` (vv-07 §2.2).
pub fn duration(text: &str) -> Option<Duration> {
    if text == "0" {
        return Some(Duration::ZERO);
    }
    let (digits, unit) = if let Some(d) = text.strip_suffix("ms") {
        (d, 1u64)
    } else if let Some(d) = text.strip_suffix('s') {
        (d, 1000)
    } else if let Some(d) = text.strip_suffix('m') {
        (d, 60_000)
    } else if let Some(d) = text.strip_suffix('h') {
        (d, 3_600_000)
    } else {
        return None;
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    Some(Duration::from_millis(n.checked_mul(unit)?))
}

fn is_dns_label(l: &str) -> bool {
    let b = l.as_bytes();
    let alnum = |c: u8| c.is_ascii_alphanumeric();
    !b.is_empty()
        && b.len() <= 63
        && alnum(b[0])
        && alnum(b[b.len() - 1])
        && b.iter().all(|&c| alnum(c) || c == b'-')
}

/// Whether `name` is a DNS host name made of letters, digits and hyphens.
pub fn is_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty() && name.len() <= 253 && name.split('.').all(is_dns_label)
}

/// Normalises an overlay domain: lowercase, no trailing dot; `None` if invalid.
pub fn domain(text: &str) -> Option<String> {
    let d = text.strip_suffix('.').unwrap_or(text).to_ascii_lowercase();
    (is_dns_name(&d) && d.split('.').all(|l| !l.is_empty())).then_some(d)
}

fn port(text: &str) -> Option<u16> {
    text.parse::<u16>().ok().filter(|p| *p != 0)
}

/// Parses an `endpoint` (vv-07 §3.5).
pub fn endpoint(text: &str) -> Option<Endpoint> {
    if let Some(rest) = text.strip_prefix('[') {
        let (ip, p) = rest.split_once("]:")?;
        let ip: std::net::Ipv6Addr = ip.parse().ok()?;
        return Some(Endpoint::Addr(SocketAddr::new(IpAddr::V6(ip), port(p)?)));
    }
    if text.parse::<IpAddr>().is_ok() {
        return None;
    }
    match text.rsplit_once(':') {
        Some((host, p)) => {
            let p = port(p)?;
            match host.parse::<std::net::Ipv4Addr>() {
                Ok(ip) => Some(Endpoint::Addr(SocketAddr::new(IpAddr::V4(ip), p))),
                Err(_) if is_dns_name(host) => Some(Endpoint::Host {
                    host: host.to_owned(),
                    port: p,
                }),
                Err(_) => None,
            }
        }
        None => is_dns_name(text).then(|| Endpoint::Srv(text.to_owned())),
    }
}

/// Whether `label` is acceptable as a configured name (vv-06 §4.2).
pub fn name_label(label: &str) -> bool {
    is_valid_label(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(duration("0"), Some(Duration::ZERO));
        assert_eq!(duration("3s"), Some(Duration::from_secs(3)));
        assert_eq!(duration("250ms"), Some(Duration::from_millis(250)));
        assert_eq!(duration("2m"), Some(Duration::from_secs(120)));
        assert_eq!(duration("24h"), Some(Duration::from_secs(86_400)));
        for bad in [
            "",
            "s",
            "3",
            "-1s",
            "1.5s",
            "3 s",
            "3d",
            "h",
            "99999999999999999999s",
        ] {
            assert_eq!(duration(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn endpoints() {
        assert_eq!(
            endpoint("203.0.113.7:51820"),
            Some(Endpoint::Addr("203.0.113.7:51820".parse().unwrap()))
        );
        assert_eq!(
            endpoint("[2001:db8::1]:7"),
            Some(Endpoint::Addr("[2001:db8::1]:7".parse().unwrap()))
        );
        assert_eq!(
            endpoint("nas.example.org:51820"),
            Some(Endpoint::Host {
                host: "nas.example.org".into(),
                port: 51820
            })
        );
        assert_eq!(
            endpoint("nas.example.org"),
            Some(Endpoint::Srv("nas.example.org".into()))
        );
        for bad in [
            "",
            "203.0.113.7",
            "2001:db8::1",
            "host:0",
            "host:70000",
            "[::1]",
            "a b:5",
            ":5",
        ] {
            assert_eq!(endpoint(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn domains() {
        assert_eq!(domain("Home.Internal."), Some("home.internal".into()));
        assert_eq!(domain("a..b"), None);
        assert_eq!(domain(""), None);
        assert_eq!(domain("-a.b"), None);
    }
}
