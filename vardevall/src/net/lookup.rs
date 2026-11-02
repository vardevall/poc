//! Host name lookups whose sockets carry the node's mark.
//!
//! The system resolver opens sockets that cannot be marked, so once the host sends unmarked
//! traffic into the tunnel its lookups would enter it. With a mark the names are asked directly
//! with marked sockets; the system's lookup remains the fallback for names only it knows, such
//! as those of `/etc/hosts`.

use std::io;
use std::net::{IpAddr, SocketAddr};

use super::dns;
use super::mark::SocketMark;
use super::socket::canonical;

/// The addresses of `host` on `port`. `resolvers` empty asks those of the system.
pub(crate) async fn host(
    host: &str,
    port: u16,
    mark: SocketMark,
    resolvers: &[SocketAddr],
) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if mark.value().is_some() {
        let found = dns::addresses(resolvers, host, mark).await;
        if !found.is_empty() {
            return Ok(found
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect());
        }
    }
    Ok(tokio::net::lookup_host((host, port))
        .await?
        .map(canonical)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn literals_need_no_lookup() {
        let got = host("192.0.2.1", 9, SocketMark::new(7), &[]).await.unwrap();
        assert_eq!(got, vec!["192.0.2.1:9".parse().unwrap()]);
        let got = host("::1", 9, SocketMark::NONE, &[]).await.unwrap();
        assert_eq!(got, vec!["[::1]:9".parse().unwrap()]);
    }

    #[tokio::test]
    async fn without_a_mark_the_system_answers() {
        let got = host("localhost", 9, SocketMark::NONE, &[]).await.unwrap();
        assert!(!got.is_empty());
    }
}
