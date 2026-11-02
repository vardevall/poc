//! Runtime of vardevall (`vv`): the interface socket, candidate sources and mDNS around the
//! sans-IO [`vardevall_proto`].
//!
//! A [`Node`] owns one UDP socket (vv-03 §2) and drives a
//! [`proto::node::Node`](vardevall_proto::node::Node) from a single task. The embedder
//! feeds IPv6 packets through a [`Handle`] and receives [`NodeEvent`]s through an
//! [`EventSink`]. It works on a current-thread tokio runtime.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

mod candidates;
mod clock;
mod config;
mod error;
mod event;
mod handle;
mod mdns;
mod net;
mod node;
mod stun;
mod switch;
mod turn;
mod udp;
pub mod view;

pub use candidates::{CandidateSource, SourceInput, SourceKey, Update};
pub use config::{
    AddressError, BuiltinMdns, Endpoint, LiveUpdate, MdnsMode, NodeConfig, PeerSpec, StunSpec,
    SwitchAuth, SwitchPath, SwitchSpec, TurnSpec,
};
pub use error::NodeError;
pub use event::{EventSink, LogLevel, NodeEvent, Status, SwitchFailure, SwitchState};
pub use handle::Handle;
pub use mdns::{Found, MdnsEvent, MdnsRequest, MdnsRequestSink};
pub use net::mark::SocketMark;
pub use net::rng::{OsRng, SysRng, os_rng};
pub use node::Node;
pub use switch::SwitchId;
pub use vardevall_proto::ip::exit::{
    EXIT_IPV4, ExitOffer, ExitServe, ExitUse, IPV4_POOL, home_ipv4, in_ipv4_pool, is_client_ipv4,
};
pub use vardevall_proto::ip::service::{Proto, Provider, Service, ServiceError};
pub use vardevall_proto::meter::{Budget, BudgetSource, Level, Meter};
pub use vardevall_proto::node::{PeerState, Reason, Trust};
pub use vardevall_proto::route::FALLBACK_DELAY;
pub use vardevall_proto::route::{DeliveryClass, Families, WantBand, WantLatency};
