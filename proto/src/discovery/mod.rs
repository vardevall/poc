//! Candidates (vv-05), mDNS discovery (vve-09) and the same-host registry (vve-10).
//!
//! Local discovery (vv-05 §2.3) is a hook: any source, mDNS or another, finds peers on the host or
//! the link and hands the node the candidates it offers with
//! [`Node::set_candidates`](crate::node::Node::set_candidates). `proto` does not depend on how a
//! source works.

pub mod candidate;
pub mod mdns;
