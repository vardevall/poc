//! Interface mode: what exists only for peers that carry IP packets.
//!
//! The exit protocol of §15 ([`exit`], [`site`]), the source check of the packets a peer sends
//! ([`source`]) and the services of §3.6 ([`service`]). Nothing here is sent or read on a session
//! without `ip`.

pub mod exit;
pub mod private;
pub mod service;
pub mod site;
pub mod source;
