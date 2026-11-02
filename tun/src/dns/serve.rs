//! The resolver on UDP and TCP port 53 of the overlay address (vv-06 §4.4).

use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;

use super::{Forwarder, Reply, Responder};

const MAX_CONNECTIONS: usize = 16;
const IDLE: Duration = Duration::from_secs(5);

/// The IPv6 address a query came from; an IPv4 source is this host.
fn source(from: SocketAddr) -> Option<Ipv6Addr> {
    match from {
        SocketAddr::V6(a) => Some(*a.ip()),
        SocketAddr::V4(_) => None,
    }
}

/// Serves queries on a bound UDP socket until an I/O error occurs.
pub async fn serve_udp(
    responder: Arc<Responder>,
    forwarder: Arc<Forwarder>,
    sock: UdpSocket,
) -> io::Result<()> {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        let source = source(from);
        match responder.respond_from(&buf[..n], source.as_ref()) {
            Reply::Answer(a) => {
                let _ = sock.send_to(&a, from).await;
            }
            Reply::Relay(r) => {
                let sock = sock.clone();
                forwarder.relay(r, move |a| {
                    let _ = sock.try_send_to(&a, from);
                });
            }
            Reply::Forward(q) => {
                let (sock, responder, query) = (sock.clone(), responder.clone(), q.clone());
                forwarder.spawn(q, move |r| {
                    let r = responder.after_forward(&query, r);
                    let _ = sock.try_send_to(&r, from);
                });
            }
            Reply::Drop => {}
        }
    }
}

async fn connection(
    mut stream: tokio::net::TcpStream,
    source: Option<Ipv6Addr>,
    responder: Arc<Responder>,
    forwarder: Arc<Forwarder>,
) {
    loop {
        let mut len = [0u8; 2];
        let read = tokio::time::timeout(IDLE, stream.read_exact(&mut len)).await;
        if !matches!(read, Ok(Ok(_))) {
            return;
        }
        let mut msg = vec![0u8; usize::from(u16::from_be_bytes(len))];
        if !matches!(
            tokio::time::timeout(IDLE, stream.read_exact(&mut msg)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        let answer = match responder.respond_from(&msg, source.as_ref()) {
            Reply::Answer(a) => a,
            Reply::Relay(r) => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                if !forwarder.relay(r, move |a| {
                    let _ = tx.send(a);
                }) {
                    return;
                }
                match tokio::time::timeout(IDLE, rx).await {
                    Ok(Ok(r)) => r,
                    _ => return,
                }
            }
            Reply::Forward(q) => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let (responder, query) = (responder.clone(), q.clone());
                if !forwarder.spawn(q, move |r| {
                    let _ = tx.send(responder.after_forward(&query, r));
                }) {
                    return;
                }
                match tokio::time::timeout(IDLE, rx).await {
                    Ok(Ok(r)) => r,
                    _ => return,
                }
            }
            Reply::Drop => return,
        };
        let Ok(l) = u16::try_from(answer.len()) else {
            return;
        };
        if stream.write_all(&l.to_be_bytes()).await.is_err()
            || stream.write_all(&answer).await.is_err()
        {
            return;
        }
    }
}

/// Serves queries on a bound TCP listener until an I/O error occurs.
pub async fn serve_tcp(
    responder: Arc<Responder>,
    forwarder: Arc<Forwarder>,
    listener: TcpListener,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, from) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let (r, f) = (responder.clone(), forwarder.clone());
        tokio::spawn(async move {
            connection(stream, source(from), r, f).await;
            drop(permit);
        });
    }
}
