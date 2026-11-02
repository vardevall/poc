//! The resolvers of the host, read once from `/etc/resolv.conf`.

use std::net::{IpAddr, SocketAddr};

const PATH: &str = "/etc/resolv.conf";
const MAX: usize = 3;

/// The `nameserver` addresses of the host on port 53; none if the file cannot be read.
pub fn system_resolvers() -> Vec<SocketAddr> {
    std::fs::read_to_string(PATH)
        .map(|text| parse(&text))
        .unwrap_or_default()
}

/// The first few `nameserver` lines: addresses with a zone (`fe80::1%eth0`) are skipped.
fn parse(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == "nameserver").then_some(())?;
            let ip: IpAddr = words.next()?.parse().ok()?;
            Some(SocketAddr::new(ip, 53))
        })
        .take(MAX)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameserver_lines_give_addresses_on_port_53() {
        let text = "# managed\nsearch lan\nnameserver 192.0.2.1\nnameserver 2001:db8::53\n\
                    nameserver fe80::1%eth0\nnameserver not-an-address\noptions edns0\n\
                    nameserver 192.0.2.2\nnameserver 192.0.2.3\nnameserver 192.0.2.4\n";
        let got = parse(text);
        assert_eq!(
            got,
            vec![
                "192.0.2.1:53".parse().unwrap(),
                "[2001:db8::53]:53".parse().unwrap(),
                "192.0.2.2:53".parse().unwrap(),
            ]
        );
        assert!(parse("").is_empty());
    }
}
