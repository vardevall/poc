//! TCP connections that carry the node's socket mark.

use std::io;
use std::net::SocketAddr;

use tokio::net::{TcpSocket, TcpStream};

use super::mark::SocketMark;

/// Connects to `addr` from a socket carrying `mark`.
pub(crate) async fn connect_marked(addr: SocketAddr, mark: SocketMark) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    mark.apply(&socket)?;
    socket.connect(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connects_without_a_mark() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (a, b) = tokio::join!(connect_marked(addr, SocketMark::NONE), listener.accept());
        assert!(a.is_ok() && b.is_ok());
    }
}
