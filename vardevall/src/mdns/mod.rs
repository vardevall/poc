//! mDNS discovery (vv-09): shared logic and the two transports.
//!
//! [`Discovery`] builds announcements, rotates them per window and matches results; a
//! [`MdnsTransport`] only carries [`MdnsRequest`]s out and [`MdnsEvent`]s in. The built-in
//! transport speaks multicast DNS on its own sockets; the external one hands requests to the
//! embedder (a platform DNS-SD service) and takes results from [`crate::Handle::mdns_event`].

pub(crate) mod builtin;
mod discovery;
pub(crate) mod external;

use std::net::IpAddr;
use std::task::{Context, Poll};

pub(crate) use discovery::Discovery;

pub(crate) use vardevall_proto::discovery::mdns::SERVICE_TYPE;

/// A request from the engine to the mDNS transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdnsRequest {
    /// Announce a service instance; repeating an instance re-announces it.
    Register {
        /// The instance label.
        instance: String,
        /// The service type, [`SERVICE_TYPE`].
        service_type: String,
        /// The UDP port of the interface socket.
        port: u16,
        /// The TXT strings as `key`, `value` pairs, in announcement order.
        txt: Vec<(String, String)>,
    },
    /// Withdraw an instance with a goodbye (vv-09 §2.1).
    Unregister {
        /// The instance label.
        instance: String,
    },
    /// Start browsing for the service.
    Browse,
    /// Stop browsing.
    StopBrowse,
}

/// A browse result from the mDNS transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdnsEvent {
    /// An instance was found or changed.
    Found(Found),
    /// An instance disappeared: goodbye or TTL expiry.
    Lost {
        /// The instance label.
        instance: String,
    },
}

/// A resolved service instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The instance label.
    pub instance: String,
    /// The TXT strings as `key`, `value` pairs.
    pub txt: Vec<(String, String)>,
    /// The SRV port.
    pub port: u16,
    /// The A and AAAA addresses.
    pub addrs: Vec<IpAddr>,
    /// The interface the result arrived on, or 0 if unknown; scopes link-local addresses.
    pub ifindex: u32,
}

/// The carrier of mDNS requests and results.
pub(crate) trait MdnsTransport: Send {
    /// Carries out a request without blocking.
    fn request(&mut self, request: MdnsRequest);

    /// Polls for the next result; the transport wakes the task when one is ready.
    fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<MdnsEvent>;

    /// Called when the usable local paths changed (vv-05 §4.6).
    fn path_changed(&mut self) {}
}

/// Receives requests of the external transport.
pub trait MdnsRequestSink: Send {
    /// Handles one request; must not block.
    fn request(&mut self, request: MdnsRequest);
}

impl<F: FnMut(MdnsRequest) + Send> MdnsRequestSink for F {
    fn request(&mut self, request: MdnsRequest) {
        self(request)
    }
}
