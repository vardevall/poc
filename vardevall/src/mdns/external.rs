//! The external mDNS transport: requests go to the embedder, results come back through the
//! engine's command channel (vv-09 §2).

use std::task::{Context, Poll};

use super::{MdnsEvent, MdnsRequest, MdnsRequestSink, MdnsTransport};

/// Forwards requests to an embedder-supplied sink.
pub(crate) struct ExternalMdns {
    sink: Box<dyn MdnsRequestSink>,
}

impl ExternalMdns {
    /// Wraps `sink`.
    pub(crate) fn new(sink: Box<dyn MdnsRequestSink>) -> Self {
        ExternalMdns { sink }
    }
}

impl MdnsTransport for ExternalMdns {
    fn request(&mut self, request: MdnsRequest) {
        self.sink.request(request);
    }

    fn poll_event(&mut self, _cx: &mut Context<'_>) -> Poll<MdnsEvent> {
        Poll::Pending
    }
}
