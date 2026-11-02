//! The vardevall switch (vv-04): an untrusted HTTPS service for admission, presence, listing and
//! forwarding between members of a network.
//!
//! All state lives in memory (vv-04 §8). The protocol logic in [`api`] is independent of the
//! transport; [`transport`] carries it over TLS with HTTP/2 and HTTP/1.1, and the embedded STUN and
//! TURN servers (feature `stun-turn`, on by default) answer on UDP.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod api;
#[cfg(feature = "stun-turn")]
mod backoff;
pub mod config;
pub mod key;
pub mod limits;
pub mod registry;
pub mod reload;
pub mod status;
#[cfg(feature = "stun-turn")]
pub mod stun;
pub mod tls;
pub mod transport;
#[cfg(feature = "stun-turn")]
pub mod turn;
pub use transport::{Sockets, Switch, SwitchError};
