//! The node's UDP socket and address normalisation (vv-03 §2).

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

use socket2::{Domain, Protocol, Socket, Type};

use super::mark::SocketMark;

/// The bound socket and whether it is an IPv6 dual-stack socket.
pub(crate) struct Bound {
    /// The socket, non-blocking.
    pub socket: std::net::UdpSocket,
    /// Whether IPv4 peers are addressed as IPv4-mapped IPv6 addresses.
    pub dual_stack: bool,
}

/// Binds the interface socket on `port`, dual-stack when the system allows it.
pub(crate) fn bind(port: u16, mark: SocketMark) -> io::Result<Bound> {
    match bind_v6(port, mark) {
        Ok(socket) => Ok(Bound {
            socket,
            dual_stack: true,
        }),
        Err(_) => {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            mark.apply(&socket)?;
            socket.set_nonblocking(true)?;
            socket.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
            Ok(Bound {
                socket: socket.into(),
                dual_stack: false,
            })
        }
    }
}

/// A non-blocking UDP socket on the wildcard address of `family_of`'s family and an ephemeral
/// port, carrying `mark`, for a client that talks to one server.
pub(crate) fn client_udp(
    family_of: SocketAddr,
    mark: SocketMark,
) -> io::Result<std::net::UdpSocket> {
    let (domain, wildcard) = if family_of.is_ipv6() {
        (Domain::IPV6, SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
    } else {
        (Domain::IPV4, SocketAddr::from(([0, 0, 0, 0], 0)))
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    mark.apply(&socket)?;
    if family_of.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&wildcard.into())?;
    Ok(socket.into())
}

fn bind_v6(port: u16, mark: SocketMark) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    mark.apply(&socket)?;
    socket.set_only_v6(false)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    Ok(socket.into())
}

/// The address as seen by the protocol: IPv4-mapped addresses become IPv4.
pub(crate) fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

/// The address to pass to `send_to` on a socket of the given kind, or `None` if it cannot reach it.
pub(crate) fn for_socket(addr: SocketAddr, dual_stack: bool) -> Option<SocketAddr> {
    match (addr, dual_stack) {
        (SocketAddr::V4(a), true) => Some(SocketAddr::V6(SocketAddrV6::new(
            a.ip().to_ipv6_mapped(),
            a.port(),
            0,
            0,
        ))),
        (SocketAddr::V6(_), false) => None,
        (a, _) => Some(a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_addresses_round_trip() {
        let v4: SocketAddr = "192.0.2.1:7".parse().unwrap();
        let mapped = for_socket(v4, true).unwrap();
        assert!(mapped.is_ipv6());
        assert_eq!(canonical(mapped), v4);
        assert_eq!(for_socket(v4, false), Some(v4));
        let v6: SocketAddr = "[2001:db8::1]:7".parse().unwrap();
        assert_eq!(for_socket(v6, false), None);
        assert_eq!(canonical(v6), v6);
    }

    #[test]
    fn binds_an_ephemeral_port() {
        let b = bind(0, SocketMark::NONE).unwrap();
        assert_ne!(b.socket.local_addr().unwrap().port(), 0);
    }
}
