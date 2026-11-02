//! Cookie secrets and mac2 verification (vv-02 §4.2).

use std::time::Duration;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::handshake::message::Fragment;
use crate::keys::crypto;
use crate::time::Instant;

/// Rotation period of the cookie secret and lifetime of a stored cookie (vv-02 §4.2).
pub const COOKIE_LIFETIME: Duration = Duration::from_secs(120);

/// The responder's cookie secrets: the current one and the one before.
pub struct CookieJar {
    current: Zeroizing<[u8; 32]>,
    previous: Option<Zeroizing<[u8; 32]>>,
    rotated_at: Instant,
}

impl CookieJar {
    /// A jar with a fresh secret.
    pub fn new<R: CryptoRng>(rng: &mut R, now: Instant) -> Self {
        let mut s = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut s[..]);
        CookieJar {
            current: s,
            previous: None,
            rotated_at: now,
        }
    }

    /// Replaces the secret once [`COOKIE_LIFETIME`] has passed.
    pub fn rotate<R: CryptoRng>(&mut self, rng: &mut R, now: Instant) {
        if now >= self.rotated_at + COOKIE_LIFETIME {
            let mut s = Zeroizing::new([0u8; 32]);
            rng.fill_bytes(&mut s[..]);
            self.previous = Some(core::mem::replace(&mut self.current, s));
            self.rotated_at = now;
        }
    }

    fn cookie_with(secret: &[u8; 32], source: &[u8]) -> [u8; 32] {
        crypto::mac(secret, &[source])
    }

    /// The cookie for a source address: `ip ‖ port` with the port big-endian.
    pub fn cookie(&self, source: &[u8]) -> [u8; 32] {
        Self::cookie_with(&self.current, source)
    }

    /// Whether the fragment's mac2 matches a cookie of the current or previous secret.
    pub fn mac2_valid(&self, fragment: &Fragment<'_>, source: &[u8]) -> bool {
        let cur = fragment.mac2_valid(&self.cookie(source));
        let prev = self
            .previous
            .as_ref()
            .is_some_and(|p| fragment.mac2_valid(&Self::cookie_with(p, source)));
        cur | prev
    }
}
