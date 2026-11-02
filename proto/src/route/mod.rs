//! Routes to a peer: classes, control messages, the round-trip estimator and the per-peer
//! [`paths::Paths`].
//!
//! Everything here is sans-IO: the peer reports frames and instants, and carries out the
//! [`paths::Do`]s it polls.

pub mod change;
pub mod class;
pub mod control;
pub mod paths;
pub mod rtt;

pub use change::{CHANGE_SETTLE, ChangeAction, Families, LocalChanges, RoundId};
pub use class::{Band, DeliveryClass, Latency, RouteClass, WantBand, WantLatency};
pub use control::{Control, encode_control, parse_control};
pub use paths::{
    Active, Config, DETECT_TIMEOUT, Delivery, FALLBACK_DELAY, Next, Origin, RouteInfo, Spec, Status,
};
pub use rtt::Rtt;
