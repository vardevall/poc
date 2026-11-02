//! Sites and their addresses.

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use thiserror::Error;

use crate::addr::{self, is_valid_label};
use crate::keys::crypto;
use crate::keys::{NetworkId, NodePublic, ctx};

/// The longest name of a site, in characters.
pub const SITE_NAME_MAX: usize = 31;

/// A site that an exit serves: a country and an optional name.
///
/// The text form is `it` or `it/home`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Site {
    /// Two lowercase ASCII letters.
    pub country: [u8; 2],
    /// A label of at most [`SITE_NAME_MAX`] characters.
    pub name: Option<String>,
}

/// A site that does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SiteError {
    /// The country is not two ASCII letters.
    #[error("the country must be two letters")]
    Country,
    /// The name is not a label of at most 31 characters.
    #[error("the site name must be a label of at most 31 characters")]
    Name,
}

impl Site {
    /// The site of a country without a name.
    pub fn country(code: &str) -> Result<Site, SiteError> {
        code.parse()
    }

    /// The country as text.
    pub fn country_str(&self) -> &str {
        std::str::from_utf8(&self.country).unwrap_or("")
    }
}

impl FromStr for Site {
    type Err = SiteError;

    fn from_str(s: &str) -> Result<Site, SiteError> {
        let (country, name) = match s.split_once('/') {
            Some((c, n)) => (c, Some(n)),
            None => (s, None),
        };
        let c = country.as_bytes();
        if c.len() != 2 || !c.iter().all(u8::is_ascii_alphabetic) {
            return Err(SiteError::Country);
        }
        let name = match name {
            Some(n) if n.len() <= SITE_NAME_MAX && is_valid_label(n) => Some(n.to_owned()),
            Some(_) => return Err(SiteError::Name),
            None => None,
        };
        Ok(Site {
            country: [c[0].to_ascii_lowercase(), c[1].to_ascii_lowercase()],
            name,
        })
    }
}

impl fmt::Display for Site {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.country_str())?;
        if let Some(n) = &self.name {
            write!(f, "/{n}")?;
        }
        Ok(())
    }
}

/// The 16-bit id of a site in a network, never 0.
pub fn site_id(network_id: &NetworkId, site: &Site) -> u16 {
    let name = site.name.as_deref().unwrap_or("");
    let h = u32::from_be_bytes(crypto::kdf(
        ctx::SITE,
        &[network_id.as_bytes(), &site.country, name.as_bytes()],
    ));
    1 + (h % 65535) as u16
}

/// The `/64` of a site: the first six bytes of the network's prefix, then the site id.
pub fn site_prefix(network_id: &NetworkId, site: &Site) -> [u8; 8] {
    let mut p = addr::ula_prefix(network_id);
    p[6..].copy_from_slice(&site_id(network_id, site).to_be_bytes());
    p
}

/// The address of `node` in a site: the site prefix, then the node's interface identifier.
pub fn site_addr(network_id: &NetworkId, site: &Site, node: &NodePublic) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a[..8].copy_from_slice(&site_prefix(network_id, site));
    a[8..].copy_from_slice(&addr::iid(network_id, node));
    Ipv6Addr::from(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{iid, ula_prefix};

    fn site(s: &str) -> Site {
        s.parse().unwrap()
    }

    #[test]
    fn site_text_form() {
        assert_eq!(site("IT").to_string(), "it");
        assert_eq!(site("it/home").to_string(), "it/home");
        assert_eq!(
            site("IT/home"),
            site("it/home"),
            "the country is lowercased"
        );
        assert!(
            "it/Home".parse::<Site>().is_err(),
            "a name is a lowercase label"
        );
        for bad in [
            "",
            "i",
            "ita",
            "i1",
            "it/",
            "it/-a",
            "it/a_b",
            "it/home/x",
            "/home",
        ] {
            assert!(bad.parse::<Site>().is_err(), "{bad:?}");
        }
        assert_eq!("it/".parse::<Site>(), Err(SiteError::Name));
        assert_eq!("i1".parse::<Site>(), Err(SiteError::Country));
        let long = format!("it/{}", "a".repeat(32));
        assert_eq!(long.parse::<Site>(), Err(SiteError::Name));
        assert!(format!("it/{}", "a".repeat(31)).parse::<Site>().is_ok());
    }

    #[test]
    fn site_prefix_properties() {
        let nid = NetworkId::from_bytes([2; 32]);
        let other = NetworkId::from_bytes([3; 32]);
        let home = site("it/home");
        assert_eq!(
            site_prefix(&nid, &home),
            site_prefix(&nid, &site("it/home"))
        );
        assert_ne!(
            site_prefix(&nid, &home),
            site_prefix(&nid, &site("it/work"))
        );
        assert_ne!(site_prefix(&nid, &home), site_prefix(&nid, &site("it")));
        assert_ne!(site_prefix(&nid, &home), site_prefix(&other, &home));
        let ula = ula_prefix(&nid);
        for name in ["a", "b", "c", "home", "work"] {
            let s = site(&format!("de/{name}"));
            let p = site_prefix(&nid, &s);
            assert_eq!(p[..6], ula[..6], "inside the network's /48");
            assert_ne!(p[6..], [0, 0], "never subnet 0");
        }
        let node = NodePublic::from_bytes([7; 32]);
        let a = site_addr(&nid, &home, &node).octets();
        assert_eq!(a[..8], site_prefix(&nid, &home));
        assert_eq!(a[8..], iid(&nid, &node));
    }

    #[test]
    fn site_prefix_is_pinned() {
        let nid = NetworkId::from_bytes([2; 32]);
        assert_eq!(site_id(&nid, &site("it/home")), 0xcc8f);
        assert_eq!(
            site_prefix(&nid, &site("it/home")),
            [0xfd, 0xc6, 0xa2, 0x4b, 0xee, 0x63, 0xcc, 0x8f]
        );
    }
}
