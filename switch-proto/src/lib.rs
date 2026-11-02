//! Sans-IO switch crate of vardevall (`vv`): the pure parts of talking to a switch.
//!
//! Switch API types and encodings, registration proofs, the Server-Sent Events parser, switch
//! addresses, the STUN/TURN codec, the TURN allocation, STUN gathering, pacing and the switch
//! session, and the choice of STUN servers and TURN credentials. It performs no I/O: no sockets,
//! async, threads or clocks; time and randomness are passed in by the caller.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod address;
pub mod api;
pub mod origin;
pub mod pacing;
pub mod presence;
pub mod reflexive;
pub mod session;
pub mod sse;
pub mod stun;
pub mod stun_servers;
pub mod turn;
pub mod turn_offers;
pub mod uri;
