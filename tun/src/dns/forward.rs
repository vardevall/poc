//! Relaying queries to upstream resolvers: in-domain misses (vv-06 §4.5) and the queries of an
//! exit.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use vardevall::SocketMark;

/// Queries relayed at once; more are dropped, and the client retries.
pub(crate) const MAX_IN_FLIGHT: usize = 8;
/// How long one query waits for an answer from one resolver.
pub(crate) const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1500);

/// A query for a name outside every overlay domain, to relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    /// The query message.
    pub query: Vec<u8>,
    /// The resolver to ask instead of the upstreams: the resolver of the exit in use, on its
    /// overlay address. An embedder sends the query as a packet of its own through the router
    /// and the node, because its sockets may not enter the tunnel; the
    /// [`Forwarder`] of a host whose default route leads into the tunnel asks it with an OS
    /// socket.
    pub via: Option<SocketAddr>,
}

/// Relays queries to upstream resolvers without more than a few in flight.
pub struct Forwarder {
    upstreams: Mutex<Vec<SocketAddr>>,
    mark: SocketMark,
    permits: Arc<Semaphore>,
    runtime: Handle,
}

async fn ask(query: &[u8], upstream: SocketAddr, mark: SocketMark) -> io::Result<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let sock = UdpSocket::bind(bind).await?;
    mark.apply(&sock)?;
    sock.connect(upstream).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        if n >= 12 && buf[..2] == query[..2] {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

impl Forwarder {
    /// A forwarder to `upstreams`, spawning on `runtime`.
    pub fn new(upstreams: Vec<SocketAddr>, runtime: Handle) -> Self {
        Forwarder {
            upstreams: Mutex::new(upstreams),
            mark: SocketMark::NONE,
            permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            runtime,
        }
    }

    /// The resolvers queries are relayed to.
    pub fn upstreams(&self) -> Vec<SocketAddr> {
        self.upstreams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replaces the resolvers; queries already being relayed keep the ones they started with.
    pub fn set_upstreams(&self, upstreams: Vec<SocketAddr>) {
        *self
            .upstreams
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = upstreams;
    }

    /// Puts `mark` on the sockets that ask the upstreams, so that a host that routes its default
    /// traffic into the tunnel sends them outside it. The queries to the resolver
    /// of the exit in use ([`Relay::via`]) are not marked: they enter the tunnel.
    pub fn with_mark(mut self, mark: SocketMark) -> Self {
        self.mark = mark;
        self
    }

    /// Relays `query` and passes the response to `done`; returns `false` if the query was
    /// dropped because too many are in flight or no upstream is configured.
    pub fn spawn<F>(&self, query: Vec<u8>, done: F) -> bool
    where
        F: FnOnce(Vec<u8>) + Send + 'static,
    {
        self.relay_to(self.upstreams(), self.mark, query, done)
    }

    /// As [`Forwarder::spawn`], for a query of an exit.
    pub fn relay<F>(&self, relay: Relay, done: F) -> bool
    where
        F: FnOnce(Vec<u8>) + Send + 'static,
    {
        let (upstreams, mark) = match relay.via {
            Some(v) => (vec![v], SocketMark::NONE),
            None => (self.upstreams(), self.mark),
        };
        self.relay_to(upstreams, mark, relay.query, done)
    }

    fn relay_to<F>(
        &self,
        upstreams: Vec<SocketAddr>,
        mark: SocketMark,
        query: Vec<u8>,
        done: F,
    ) -> bool
    where
        F: FnOnce(Vec<u8>) + Send + 'static,
    {
        if upstreams.is_empty() {
            return false;
        }
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            return false;
        };
        self.runtime.spawn(async move {
            let _permit = permit;
            for u in upstreams {
                if let Some(r) = attempt(&query, u, mark).await {
                    done(r);
                    return;
                }
            }
        });
        true
    }
}

/// The response of `upstream` to `query`, or `None` if it did not answer in time.
async fn attempt(query: &[u8], upstream: SocketAddr, mark: SocketMark) -> Option<Vec<u8>> {
    tokio::time::timeout(ATTEMPT_TIMEOUT, ask(query, upstream, mark))
        .await
        .ok()?
        .ok()
}
