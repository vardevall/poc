//! The JSON of remembered offers (vardevall.h `vv_remember_exits`).

use serde::Deserialize;
use thiserror::Error;
use vardevall_proto::ip::site::Site;
use vardevall_proto::keys::NodePublic;

/// Remembered offers that are not the documented JSON.
#[derive(Debug, Error)]
pub enum ExitsJsonError {
    /// Not a JSON array of `{"key","site"}` objects.
    #[error("invalid remembered exits: {0}")]
    Json(#[from] serde_json::Error),
    /// A key or a site that does not parse.
    #[error("invalid remembered exit: {0}")]
    Field(String),
}

#[derive(Deserialize)]
struct Wire {
    key: String,
    site: String,
}

/// Parses `[{"key":"<base32>","site":"it/home"},…]`, the `offers` of an `exits` event.
pub fn exits_from_json(json: &str) -> Result<Vec<(NodePublic, Site)>, ExitsJsonError> {
    let wire: Vec<Wire> = serde_json::from_str(json)?;
    wire.into_iter()
        .map(|w| {
            let key = w
                .key
                .parse()
                .map_err(|_| ExitsJsonError::Field(format!("key {:?}", w.key)))?;
            let site = w
                .site
                .parse()
                .map_err(|_| ExitsJsonError::Field(format!("site {:?}", w.site)))?;
            Ok((key, site))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embed::Event;

    #[test]
    fn the_offers_of_an_exits_event_parse_back() {
        let key = NodePublic::from_bytes([3; 32]);
        let site: Site = "it/home".parse().unwrap();
        let event = Event::Exits {
            offers: vec![(key, site.clone())],
        };
        let json: serde_json::Value = serde_json::from_str(&event.to_json("home")).unwrap();
        assert_eq!(json["type"], "exits");
        let offers = json["offers"].to_string();
        assert_eq!(exits_from_json(&offers).unwrap(), [(key, site)]);
        assert_eq!(exits_from_json("[]").unwrap(), []);
    }

    #[test]
    fn a_bad_key_or_site_fails_the_whole_list() {
        assert!(exits_from_json(r#"[{"key":"x","site":"it"}]"#).is_err());
        let key = NodePublic::from_bytes([3; 32]).to_string();
        let bad = format!(r#"[{{"key":"{key}","site":"italy"}}]"#);
        assert!(exits_from_json(&bad).is_err());
        assert!(exits_from_json(r#"{"offers":[]}"#).is_err());
    }
}
