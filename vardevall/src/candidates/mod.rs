//! Candidate sources (vv-05 §2, §4.1).
//!
//! A [`CandidateSource`] reports the addresses it knows for peers as [`Update`]s, which the
//! node hands to `proto`. New kinds (BLE) join by implementing the trait.

mod mdns_source;
mod static_source;

use std::net::SocketAddr;
use std::task::{Context, Poll};

pub(crate) use mdns_source::{MdnsSource, NAME as MDNS_SOURCE};
pub(crate) use static_source::StaticSource;

use vardevall_proto::discovery::candidate::Candidate;
use vardevall_proto::keys::NodePublic;

use crate::config::PeerSpec;
use crate::mdns::MdnsEvent;

/// Identifies one group of candidates of a peer inside the book.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceKey {
    /// The `endpoint` entries of the configuration (vv-07 §3.5).
    Static,
    /// One group of a local discovery source (vv-05 §2.3): for mDNS, a service instance
    /// (vv-09 §2.2).
    Discovery {
        /// The source, as [`CandidateSource::name`] gives it.
        source: &'static str,
        /// The group inside the source.
        group: String,
    },
}

/// The complete set of candidates of one source group for a peer; an empty set removes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// The peer the candidates belong to.
    pub peer: NodePublic,
    /// The group being replaced.
    pub source: SourceKey,
    /// The new candidates: the routes the group offers the controller.
    pub candidates: Vec<Candidate>,
    /// Addresses held back as fallbacks: a direct handshake attempt tries them, the controller
    /// gets one when an offered route fails (vv-09 §2.3).
    pub spare: Vec<Candidate>,
}

/// Input that the engine routes to sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceInput {
    /// A browse result of the external mDNS transport (vv-09 §2).
    Mdns(MdnsEvent),
}

/// A producer of candidates (vv-05 §2.1).
pub trait CandidateSource: Send {
    /// A short name for logs.
    fn name(&self) -> &'static str;

    /// Polls for the next update; the source wakes the task when one is ready.
    fn poll_update(&mut self, cx: &mut Context<'_>) -> Poll<Update>;

    /// Delivers external input; a source ignores input that is not for it.
    fn input(&mut self, _input: SourceInput) {}

    /// The usable local paths changed (vv-05 §4.6): regather.
    fn path_changed(&mut self) {}

    /// A route to `addr` of `peer` failed (vv-05 §4.9): a source that holds fallbacks offers the
    /// next one.
    fn route_failed(&mut self, _peer: &NodePublic, _addr: SocketAddr) {}

    /// A handshake with `peer` is being started and its candidates may be stale (vv-05 §4.6).
    fn needs_path(&mut self, _peer: &NodePublic) {}

    /// The key-trusted peers changed while the node runs; `peers` is the whole set now.
    fn peers_changed(&mut self, _peers: &[PeerSpec]) {}

    /// The node is stopping.
    fn stop(&mut self) {}
}
