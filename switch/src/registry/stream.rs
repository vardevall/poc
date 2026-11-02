//! The server side of one events stream (vv-04 §7.1).

use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::{Instant, Interval, MissedTickBehavior};
use vardevall_proto::keys::{NetworkPublic, NodePublic};

use super::Registry;

/// Starts a stream so that clients see it open before the first event.
const OPENING: &str = ": vv-switch\n\n";
const KEEPALIVE: &str = ": keepalive\n\n";

/// Starts the reconnect grace period of a node when its stream is dropped (vv-04 §7.3).
pub(super) struct StreamGuard {
    registry: Arc<Registry>,
    net: NetworkPublic,
    node: NodePublic,
    id: u64,
}

impl StreamGuard {
    pub(super) fn new(
        registry: Arc<Registry>,
        net: NetworkPublic,
        node: NodePublic,
        id: u64,
    ) -> Self {
        StreamGuard {
            registry,
            net,
            node,
            id,
        }
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.registry
            .stream_closed(&self.net, &self.node, self.id, Instant::now());
    }
}

/// A source of SSE bytes: the opening comment, events, and keepalive comments while idle.
///
/// The stream ends when the registry closes it. Dropping it starts the node's grace period.
pub struct EventStream {
    rx: mpsc::Receiver<Bytes>,
    opening: bool,
    keepalive: Option<Interval>,
    _guard: StreamGuard,
}

impl EventStream {
    pub(super) fn new(rx: mpsc::Receiver<Bytes>, guard: StreamGuard) -> Self {
        EventStream {
            rx,
            opening: true,
            keepalive: None,
            _guard: guard,
        }
    }

    /// Sets the longest idle gap before a keepalive comment (vv-04 §7.1).
    pub fn with_keepalive(mut self, period: Duration) -> Self {
        let mut i = tokio::time::interval_at(Instant::now() + period, period);
        i.set_missed_tick_behavior(MissedTickBehavior::Delay);
        self.keepalive = Some(i);
        self
    }

    /// The next chunk to write, or `None` when the stream is over.
    pub fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        if self.opening {
            self.opening = false;
            return Poll::Ready(Some(Bytes::from_static(OPENING.as_bytes())));
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(item) => {
                if let Some(k) = &mut self.keepalive {
                    k.reset();
                }
                return Poll::Ready(item);
            }
            Poll::Pending => {}
        }
        if let Some(k) = &mut self.keepalive
            && k.poll_tick(cx).is_ready()
        {
            return Poll::Ready(Some(Bytes::from_static(KEEPALIVE.as_bytes())));
        }
        Poll::Pending
    }

    /// The next chunk to write, or `None` when the stream is over.
    pub async fn next(&mut self) -> Option<Bytes> {
        std::future::poll_fn(|cx| self.poll_next(cx)).await
    }
}
