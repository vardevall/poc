//! Sans-IO protocol crate of vardevall (`vv`).
//!
//! Implements the keys, handshake, sessions, data frames, paths and selection, candidates and
//! local registries of the specification; the caller supplies time, randomness and datagrams and
//! carries out the returned actions. It knows no concrete transport and no switch: those are in
//! `vardevall-switch-proto` and `vardevall`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod addr;
pub mod discovery;
pub mod error;
pub mod handshake;
pub mod ip;
pub mod json;
pub mod keys;
pub mod meter;
pub mod node;
pub mod peer;
pub mod plane;
pub mod route;
pub mod session;
#[cfg(feature = "sim")]
pub mod sim;
pub mod time;
pub mod transport;
