//! Where STUN servers and TURN credentials come from.

use std::fmt;

/// A configured switch, by its position in the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SwitchId(pub u32);

/// The source of a STUN server list or of TURN credentials.
///
/// Ordered with every switch before every configured entry, each by position: where the order
/// breaks a tie, the earliest switch wins, then the earliest configured entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// A switch, which issues the credentials with its registration.
    Switch(SwitchId),
    /// An entry of the node's own configuration, by position.
    Config(u16),
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Switch(id) => write!(f, "switch {}", id.0),
            Origin::Config(i) => write!(f, "config {i}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_switch_precedes_every_configured_entry() {
        let mut v = vec![
            Origin::Config(0),
            Origin::Switch(SwitchId(7)),
            Origin::Config(1),
            Origin::Switch(SwitchId(2)),
        ];
        v.sort();
        assert_eq!(
            v,
            [
                Origin::Switch(SwitchId(2)),
                Origin::Switch(SwitchId(7)),
                Origin::Config(0),
                Origin::Config(1),
            ]
        );
    }
}
