//! The stream transport of the TURN client: TCP, TLS 1.3 with ALPN `stun.turn` and the framing of
//! STUN messages and ChannelData on a byte stream [RFC 8656 §12.5, RFC 7443].

use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::config::SwitchAuth;
use crate::net::mark::SocketMark;
use crate::net::tcp::connect_marked;
use crate::switch::tls::client_config;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use vardevall_switch_proto::turn::frame_len;

/// ALPN of TURN over TLS [RFC 7443].
const ALPN_TURN: &[u8] = b"stun.turn";
/// Time to connect and finish the TLS handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Messages queued in each direction.
const QUEUE: usize = 256;

/// What a [`Link`] reports.
#[derive(Debug)]
pub(crate) enum LinkEvent {
    /// One STUN message or ChannelData message, padding included.
    Frame(Vec<u8>),
    /// The connection failed or ended.
    Closed,
}

/// A TLS connection to a TURN server, run by a task.
pub(crate) struct Link {
    out: mpsc::Sender<Vec<u8>>,
    events: mpsc::Receiver<LinkEvent>,
    task: JoinHandle<()>,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Link {
    /// Connects to `addr` in the background; messages sent meanwhile wait in a queue.
    pub(crate) fn connect(
        addr: SocketAddr,
        host: String,
        auth: SwitchAuth,
        mark: SocketMark,
    ) -> Link {
        let (out, out_rx) = mpsc::channel(QUEUE);
        let (events_tx, events) = mpsc::channel(QUEUE);
        let task = tokio::spawn(async move {
            let _ = run(addr, host, auth, mark, out_rx, &events_tx).await;
            let _ = events_tx.send(LinkEvent::Closed).await;
        });
        Link { out, events, task }
    }

    /// Queues a message; `false` if the queue is full or the connection is gone.
    pub(crate) fn send(&self, message: Vec<u8>) -> bool {
        self.out.try_send(message).is_ok()
    }

    /// The next event.
    pub(crate) fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<LinkEvent> {
        match self.events.poll_recv(cx) {
            Poll::Ready(Some(e)) => Poll::Ready(e),
            Poll::Ready(None) => Poll::Ready(LinkEvent::Closed),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn run(
    addr: SocketAddr,
    host: String,
    auth: SwitchAuth,
    mark: SocketMark,
    mut out: mpsc::Receiver<Vec<u8>>,
    events: &mpsc::Sender<LinkEvent>,
) -> std::io::Result<()> {
    let config = client_config(&auth, &[ALPN_TURN]).map_err(std::io::Error::other)?;
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(host).map_err(std::io::Error::other)?;
    let tls = tokio::time::timeout(CONNECT_TIMEOUT, async {
        let tcp = connect_marked(addr, mark).await?;
        let _ = tcp.set_nodelay(true);
        connector.connect(name, tcp).await
    })
    .await
    .map_err(|_| std::io::ErrorKind::TimedOut)??;
    let (mut read, mut write) = tokio::io::split(tls);
    let reader = async {
        loop {
            let frame = read_frame(&mut read).await?;
            if events.send(LinkEvent::Frame(frame)).await.is_err() {
                return Ok::<(), std::io::Error>(());
            }
        }
    };
    let writer = async {
        while let Some(message) = out.recv().await {
            write.write_all(&message).await?;
            write.flush().await?;
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::select! {
        r = reader => r,
        r = writer => r,
    }
}

/// Reads one message from a stream, split by [`frame_len`].
async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head).await?;
    let total = frame_len(head).ok_or(std::io::ErrorKind::InvalidData)?;
    let mut frame = vec![0u8; total];
    frame[..4].copy_from_slice(&head);
    r.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_are_split_by_their_length() {
        let mut stun = vec![0x00, 0x01, 0x00, 0x04];
        stun.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        stun.extend_from_slice(&[7u8; 12]);
        stun.extend_from_slice(&[1, 2, 3, 4]);
        let channel = [0x40, 0x01, 0x00, 0x03, 9, 9, 9, 0];
        let mut stream = stun.clone();
        stream.extend_from_slice(&channel);
        stream.extend_from_slice(&stun);
        let mut r = &stream[..];
        assert_eq!(read_frame(&mut r).await.unwrap(), stun);
        assert_eq!(read_frame(&mut r).await.unwrap(), channel);
        assert_eq!(read_frame(&mut r).await.unwrap(), stun);
        assert!(read_frame(&mut r).await.is_err());
        let mut bad = &[0xc0u8, 0, 0, 0][..];
        assert!(read_frame(&mut bad).await.is_err());
    }
}
