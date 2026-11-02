//! The firewall mark of the sockets that must not enter the tunnel.
//!
//! A host that routes its default traffic into the tunnel marks every socket the engine opens,
//! as `wg-quick` does, and sends marked packets by the main routing table. Marking is `SO_MARK`,
//! which only Linux has; the call is made when the `fwmark` feature is on.

use std::io;

/// Whether this build can mark sockets.
pub(crate) const SUPPORTED: bool = cfg!(all(feature = "fwmark", target_os = "linux"));

/// The mark to put on a socket, or none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SocketMark(Option<u32>);

impl SocketMark {
    /// No mark.
    pub const NONE: SocketMark = SocketMark(None);

    /// A socket mark of `value`.
    pub const fn new(value: u32) -> Self {
        SocketMark(Some(value))
    }

    /// The mark, if there is one.
    pub const fn value(self) -> Option<u32> {
        self.0
    }

    /// Marks `socket`; does nothing for [`SocketMark::NONE`]. Without the `fwmark` feature, or off
    /// Linux, a mark is an error.
    #[cfg(unix)]
    pub fn apply(self, socket: &impl std::os::fd::AsFd) -> io::Result<()> {
        let Some(value) = self.0 else {
            return Ok(());
        };
        set(socket, value)
    }
}

#[cfg(all(unix, feature = "fwmark", target_os = "linux"))]
fn set(socket: &impl std::os::fd::AsFd, value: u32) -> io::Result<()> {
    socket2::SockRef::from(socket).set_mark(value)
}

#[cfg(all(unix, not(all(feature = "fwmark", target_os = "linux"))))]
fn set(_: &impl std::os::fd::AsFd, _: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "socket marks need Linux and the fwmark feature",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_mark_is_always_fine() {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(SocketMark::NONE.apply(&s).is_ok());
        assert_eq!(SocketMark::default(), SocketMark::NONE);
        assert_eq!(SocketMark::new(7).value(), Some(7));
    }

    #[cfg(not(all(feature = "fwmark", target_os = "linux")))]
    #[test]
    fn a_mark_needs_the_feature() {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(SocketMark::new(7).apply(&s).is_err());
    }

    #[cfg(all(feature = "fwmark", target_os = "linux"))]
    #[test]
    fn a_mark_without_privilege_fails_or_sticks() {
        use std::os::fd::AsFd;
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        match SocketMark::new(7).apply(&s) {
            Ok(()) => assert_eq!(socket2::SockRef::from(&s.as_fd()).mark().unwrap(), 7),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
        }
    }
}
