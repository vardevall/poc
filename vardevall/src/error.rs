//! Errors of the node engine.

use std::io;

use thiserror::Error;

/// A node could not be created.
#[derive(Debug, Error)]
pub enum NodeError {
    /// The UDP socket could not be bound (vv-03 §2).
    #[error("binding the UDP socket: {0}")]
    Bind(#[source] io::Error),
    /// The configuration is unusable.
    #[error("invalid node configuration: {0}")]
    Config(&'static str),
}
