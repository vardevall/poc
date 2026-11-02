//! Interface mode of vardevall (`vv`): the packet router between a tunnel and `vardevall`,
//! the overlay DNS responder, interface files and tunnel settings.
//!
//! The library has no operating-system dependencies; the `vv` binary (feature `cli`) adds the
//! `utun`/`tun` plumbing. [`embed::Tunnel`] is the entry point for embedders that own the tunnel
//! themselves, such as a platform packet-tunnel extension.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
#[cfg(feature = "cli")]
pub mod control_client;
pub mod dns;
pub mod embed;
#[cfg(feature = "cli")]
pub mod files;
pub mod keys;
pub mod numbering;
pub mod packet;
pub mod router;
pub mod settings;
