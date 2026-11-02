//! Switch addresses and how a switch is authenticated (vv-04 §2.1, §2.3).

use std::str::FromStr;

use thiserror::Error;
use vardevall_proto::keys::SwitchPublic;

use crate::api::normalize_host;

/// How a switch is authenticated (vv-04 §2.1, §2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchAuth {
    /// A pinned address: the switch must present a certificate whose key is `A`, and nothing
    /// else about the certificate is checked.
    Pinned(SwitchPublic),
    /// A web address: the switch must present a certificate valid in the Web PKI for its host,
    /// and `A` comes from `/v0/info`.
    Web {
        /// DER certificates trusted in addition to the built-in Web PKI roots, for a private
        /// certificate authority.
        extra_roots: Vec<Vec<u8>>,
    },
}

/// A switch address could not be read (vv-04 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AddressError {
    /// The part before `@` is not a base32 switch key.
    #[error("the switch key before @ is not valid")]
    Key,
    /// The host is empty or neither a DNS name nor an IP literal.
    #[error("the switch host is not a DNS name or an IP literal")]
    Host,
    /// The port is not a number from 1 to 65535.
    #[error("the switch port is not valid")]
    Port,
    /// A web address names a DNS name, which an IP literal is not.
    #[error("a web address needs a DNS name; pin the key to use an IP address")]
    WebLiteral,
}

/// A configured switch (vv-07 §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchSpec {
    /// How the switch is authenticated.
    pub auth: SwitchAuth,
    /// A DNS name or an IP literal, without brackets.
    pub host: String,
    /// The TCP and UDP port.
    pub port: u16,
    /// The operator token, sent only to this switch.
    pub token: Option<String>,
}

impl SwitchSpec {
    /// A switch at a pinned address `base32(key)@host:port`.
    pub fn pinned(key: SwitchPublic, host: &str, port: u16, token: Option<String>) -> Self {
        SwitchSpec {
            auth: SwitchAuth::Pinned(key),
            host: host.to_owned(),
            port,
            token,
        }
    }

    /// A switch at a web address `host:port`.
    pub fn web(host: &str, port: u16, token: Option<String>) -> Self {
        SwitchSpec {
            auth: SwitchAuth::Web {
                extra_roots: Vec::new(),
            },
            host: host.to_owned(),
            port,
            token,
        }
    }

    /// Reads a switch address of vv-04 §2.1: `base32(A)@host[:port]` or `host[:port]`, an IPv6
    /// literal in brackets, the port defaulting to 443.
    pub fn parse(address: &str, token: Option<String>) -> Result<Self, AddressError> {
        let (key, hostport) = match address.split_once('@') {
            Some((k, rest)) => (
                Some(SwitchPublic::from_str(k).map_err(|_| AddressError::Key)?),
                rest,
            ),
            None => (None, address),
        };
        let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
            let (h, tail) = rest.split_once(']').ok_or(AddressError::Host)?;
            match tail.strip_prefix(':') {
                Some(p) => (h, parse_port(p)?),
                None if tail.is_empty() => (h, 443),
                None => return Err(AddressError::Host),
            }
        } else if hostport.matches(':').count() == 1 {
            let (h, p) = hostport.split_once(':').ok_or(AddressError::Host)?;
            (h, parse_port(p)?)
        } else {
            (hostport, 443)
        };
        if normalize_host(host).is_none() {
            return Err(AddressError::Host);
        }
        match key {
            Some(key) => Ok(Self::pinned(key, host, port, token)),
            None if host.parse::<std::net::IpAddr>().is_ok() => Err(AddressError::WebLiteral),
            None => Ok(Self::web(host, port, token)),
        }
    }

    /// `host:port`, with an IPv6 literal in brackets.
    pub fn label(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The host in the normal form registrations carry (vv-04 §4.3); `None` if it has none.
    pub fn normal_host(&self) -> Option<String> {
        normalize_host(&self.host)
    }
}

fn parse_port(p: &str) -> Result<u16, AddressError> {
    p.parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or(AddressError::Port)
}
