//! Key types and derivations (vv-01 §4, §5).

pub mod base32;
pub mod crypto;

use core::fmt;
use core::str::FromStr;

use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::EncodingError;

/// `KDF` context strings (vv-01 §5.9).
pub mod ctx {
    /// vv-01 §4.2.
    pub const NETWORK_DH: &str = "vardevall v0 network dh";
    /// vv-01 §5.2.
    pub const NETWORK_PSK: &str = "vardevall v0 network psk";
    /// vv-01 §5.3.
    pub const MAC1: &str = "vardevall v0 mac1";
    /// vv-01 §5.3.
    pub const COOKIE: &str = "vardevall v0 cookie";
    /// vv-01 §5.4.
    pub const MDNS: &str = "vardevall v0 mdns";
    /// vv-01 §5.4.
    pub const MDNS_NODE: &str = "vardevall v0 mdns node";
    /// vv-01 §5.5.
    pub const REGISTER_NODE: &str = "vardevall v0 register node";
    /// vv-01 §5.5.
    pub const REGISTER_NETWORK: &str = "vardevall v0 register network";
    /// vv-01 §5.5.
    pub const REGISTER_SWITCH: &str = "vardevall v0 register switch";
    /// vv-01 §5.6.
    pub const ULA_PREFIX: &str = "vardevall v0 ula prefix";
    /// vv-01 §5.7.
    pub const IID: &str = "vardevall v0 iid";
    /// The id of a site ([`crate::ip::site::site_id`]).
    pub const SITE: &str = "vardevall v0 site";
    /// A node's IPv4 address behind every exit ([`crate::ip::exit::home_ipv4`]).
    pub const EXIT_IPV4: &str = "vardevall v0 exit ipv4";
    /// vv-02 §6.1.
    pub const FRAME: &str = "vardevall v0 frame";
}

macro_rules! public_key {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wraps raw bytes.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// The raw bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            /// The base32 text form (vv-01 §3.2).
            pub fn to_base32(&self) -> String {
                base32::encode(&self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_base32())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_base32())
            }
        }

        impl FromStr for $name {
            type Err = EncodingError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                base32::decode_array(s).map(Self)
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }
    };
}

macro_rules! secret_key {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wraps raw bytes.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// The raw bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            /// The base32 text form (vv-01 §3.2).
            pub fn to_base32(&self) -> Zeroizing<String> {
                Zeroizing::new(base32::encode(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(..)", stringify!($name))
            }
        }

        impl FromStr for $name {
            type Err = EncodingError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                base32::decode_array(s).map(Self)
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }
    };
}

public_key! {
    /// A node's X25519 public key, its identity (vv-01 §4.1).
    NodePublic
}
public_key! {
    /// A network's public key `net_pk` (vv-01 §4.2).
    NetworkPublic
}
public_key! {
    /// A network ID (vv-01 §4.3).
    NetworkId
}
public_key! {
    /// A switch's Ed25519 public key `A` (vv-01 §4.4).
    SwitchPublic
}

secret_key! {
    /// A node's X25519 private key (vv-01 §4.1).
    NodeSecret
}
secret_key! {
    /// A network secret `net_sk`, used only as `KDF` key material (vv-01 §4.2).
    NetworkSecret
}
secret_key! {
    /// A switch's Ed25519 seed (vv-01 §4.4).
    SwitchSecret
}
secret_key! {
    /// A manually configured pair PSK, the Noise `psk2` (vv-02 §2.1).
    PairPsk
}

impl NodeSecret {
    /// A new clamped key.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        Self(k)
    }

    /// `DH_PUB(sk)`.
    pub fn public(&self) -> NodePublic {
        NodePublic(crypto::dh_pub(&self.0))
    }
}

impl NodePublic {
    /// The key-id: the base32 text of the key (vv-01 §5.8).
    pub fn key_id(&self) -> String {
        self.to_base32()
    }
}

impl NetworkSecret {
    /// 32 random bytes.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        Self(k)
    }

    /// `net_dh_sk` (vv-01 §4.2).
    pub fn dh_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(crypto::kdf(ctx::NETWORK_DH, &[&self.0]))
    }

    /// `net_pk` (vv-01 §4.2).
    pub fn public(&self) -> NetworkPublic {
        NetworkPublic(crypto::dh_pub(&self.dh_secret()))
    }

    /// The default network ID, `net_pk` (vv-01 §4.3).
    pub fn default_network_id(&self) -> NetworkId {
        NetworkId(self.public().0)
    }

    /// The network PSK `psk1`, the Noise psk0 (vv-01 §5.2).
    pub fn psk(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(crypto::kdf(ctx::NETWORK_PSK, &[&self.0]))
    }

    /// `mac1_key` for messages towards `recipient` (vv-01 §5.3).
    pub fn mac1_key(&self, recipient: &NodePublic) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(crypto::kdf(ctx::MAC1, &[&self.0, &recipient.0]))
    }

    /// `cookie_key` for cookies issued by `replier` (vv-01 §5.3).
    pub fn cookie_key(&self, replier: &NodePublic) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(crypto::kdf(ctx::COOKIE, &[&self.0, &replier.0]))
    }

    /// `mdns_key` (vv-01 §5.4).
    pub fn mdns_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(crypto::kdf(ctx::MDNS, &[&self.0]))
    }
}

impl SwitchSecret {
    /// The Ed25519 public key of this seed.
    pub fn public(&self) -> SwitchPublic {
        SwitchPublic(crypto::ed_public(&self.0))
    }

    /// `ED_TO_X_SEC` (vv-01 §2.3).
    pub fn dh_secret(&self) -> Zeroizing<[u8; 32]> {
        crypto::ed_to_x_sec(&self.0)
    }
}

/// DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410), followed by the 32-byte key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

impl SwitchPublic {
    /// The `SubjectPublicKeyInfo` that carries this key as a TLS raw public key (vv-04 §2.3).
    pub fn to_spki(&self) -> [u8; 44] {
        let mut out = [0u8; 44];
        out[..12].copy_from_slice(&ED25519_SPKI_PREFIX);
        out[12..].copy_from_slice(&self.0);
        out
    }

    /// The key of an Ed25519 `SubjectPublicKeyInfo`; `None` for anything else.
    pub fn from_spki(spki: &[u8]) -> Option<Self> {
        let key = spki.strip_prefix(&ED25519_SPKI_PREFIX[..])?;
        <[u8; 32]>::try_from(key).ok().map(Self)
    }

    /// `ED_TO_X_PUB` (vv-01 §2.3).
    pub fn dh_public(&self) -> Result<[u8; 32], crate::error::CryptoError> {
        crypto::ed_to_x_pub(&self.0)
    }
}

impl PairPsk {
    /// The `zeros(32)` PSK used when none is configured (vv-02 §2.1).
    pub const fn none() -> Self {
        Self([0u8; 32])
    }
}

impl Default for PairPsk {
    fn default() -> Self {
        Self::none()
    }
}
