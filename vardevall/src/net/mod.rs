//! Operating-system facilities: the UDP socket, randomness, DNS and the watch on the host's
//! addresses.

pub(crate) mod dns;
pub(crate) mod lookup;
pub(crate) mod mark;
pub(crate) mod resolver;
pub(crate) mod rng;
pub(crate) mod socket;
pub(crate) mod tcp;
pub(crate) mod watch;
