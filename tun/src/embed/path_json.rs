//! The JSON of `vv_path_changed` (vv-05 §2.2, §4.6, vardevall.h).

use serde::Deserialize;
use thiserror::Error;
use vardevall::Families;

/// A description that is not valid JSON of the documented shape.
#[derive(Debug, Error)]
#[error("invalid path update: {0}")]
pub struct PathJsonError(#[from] serde_json::Error);

/// What the platform reports about the local paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathUpdate {
    /// Whether the set of usable local paths changed (vv-05 §4.6).
    pub changed: bool,
    /// Whether the interface in use is expensive or constrained.
    pub metered: Option<bool>,
    /// The same, per interface name; ignored by the engine for now.
    pub interfaces: Vec<(String, bool)>,
    /// The address families whose addresses changed; both unless the platform says otherwise.
    pub families: Families,
}

#[derive(Deserialize)]
struct Wire {
    changed: Option<bool>,
    metered: Option<bool>,
    interfaces: Option<Vec<Interface>>,
    families: Option<Vec<Family>>,
}

#[derive(Deserialize)]
struct Interface {
    name: String,
    metered: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Family {
    V4,
    V6,
}

/// Parses
/// `{"changed":bool,"metered":bool,"interfaces":[{"name":"…","metered":bool},…],"families":["v4","v6"]}`;
/// every member is optional (and `null` counts as absent), `changed` defaults to true and
/// `families` to both. Unknown members are ignored.
pub fn path_update_from_json(text: &str) -> Result<PathUpdate, PathJsonError> {
    let w: Wire = serde_json::from_str(text)?;
    let families = w.families.map_or(Families::BOTH, |list| {
        list.iter().fold(Families::NONE, |f, x| match x {
            Family::V4 => Families { v4: true, ..f },
            Family::V6 => Families { v6: true, ..f },
        })
    });
    Ok(PathUpdate {
        changed: w.changed.unwrap_or(true),
        metered: w.metered,
        interfaces: w
            .interfaces
            .unwrap_or_default()
            .into_iter()
            .map(|i| (i.name, i.metered))
            .collect(),
        families,
    })
}
