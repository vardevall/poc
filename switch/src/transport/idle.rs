//! Closing connections that stay silent.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep};

/// Fails reads once nothing has been read or written for `idle`.
pub struct IdleTimeout<T> {
    inner: T,
    idle: Duration,
    timer: Pin<Box<Sleep>>,
}

impl<T> IdleTimeout<T> {
    /// Wraps `inner`.
    pub fn new(inner: T, idle: Duration) -> Self {
        IdleTimeout {
            inner,
            idle,
            timer: Box::pin(sleep(idle)),
        }
    }

    fn touch(&mut self) {
        self.timer.as_mut().reset(Instant::now() + self.idle);
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleTimeout<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(r) => {
                self.touch();
                Poll::Ready(r)
            }
            Poll::Pending => match self.timer.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::ErrorKind::TimedOut.into())),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleTimeout<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if r.is_ready() {
            self.touch();
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn silent_connections_time_out_and_activity_extends_them() {
        let (a, mut b) = duplex(64);
        let mut io = IdleTimeout::new(a, Duration::from_secs(10));
        tokio::time::advance(Duration::from_secs(8)).await;
        b.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 1];
        io.read_exact(&mut buf).await.unwrap();
        tokio::time::advance(Duration::from_secs(8)).await;
        io.write_all(b"y").await.unwrap();
        let r = tokio::time::timeout(Duration::from_secs(9), io.read(&mut buf)).await;
        assert!(r.is_err());
        let r = io.read(&mut buf).await;
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
