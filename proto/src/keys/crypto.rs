//! Primitive wrappers (vv-01 §2).

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, XChaCha20Poly1305};
use curve25519_dalek::EdwardsPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

/// Size of keys, hashes and Diffie-Hellman outputs.
pub const KEY_LEN: usize = 32;
/// AEAD tag size.
pub const TAG_LEN: usize = 16;
/// XAEAD nonce size.
pub const XNONCE_LEN: usize = 24;
/// HMAC block size over `HASH` (vv-01 §2.1).
const BLOCK_LEN: usize = 64;

/// `HASH` over the concatenation of `parts`.
pub fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// `MAC(key, parts, N)`.
pub fn mac<const N: usize>(key: &[u8; 32], parts: &[&[u8]]) -> [u8; N] {
    let mut h = blake3::Hasher::new_keyed(key);
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; N];
    h.finalize_xof().fill(&mut out);
    out
}

/// `KDF(ctx, parts, N)`.
pub fn kdf<const N: usize>(ctx: &str, parts: &[&[u8]]) -> [u8; N] {
    let mut h = blake3::Hasher::new_derive_key(ctx);
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; N];
    h.finalize_xof().fill(&mut out);
    out
}

/// Constant-time equality of two byte strings.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// `HMAC` over `HASH` with a key of at most 64 bytes.
pub fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut ipad = Zeroizing::new([0x36u8; BLOCK_LEN]);
    let mut opad = Zeroizing::new([0x5cu8; BLOCK_LEN]);
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let mut inner = blake3::Hasher::new();
    inner.update(&ipad[..]);
    for p in parts {
        inner.update(p);
    }
    let inner = inner.finalize();
    let mut outer = blake3::Hasher::new();
    outer.update(&opad[..]);
    outer.update(inner.as_bytes());
    *outer.finalize().as_bytes()
}

/// Noise `HKDF` with two outputs (\[Noise\] §4.3).
pub fn hkdf2(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut temp = Zeroizing::new(hmac(ck, &[ikm]));
    let o1 = hmac(&temp, &[&[1]]);
    let o2 = hmac(&temp, &[&o1, &[2]]);
    temp.zeroize();
    (o1, o2)
}

/// Noise `HKDF` with three outputs.
pub fn hkdf3(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut temp = Zeroizing::new(hmac(ck, &[ikm]));
    let o1 = hmac(&temp, &[&[1]]);
    let o2 = hmac(&temp, &[&o1, &[2]]);
    let o3 = hmac(&temp, &[&o2, &[3]]);
    temp.zeroize();
    (o1, o2, o3)
}

/// `AEAD` seal with the nonce `zeros(4) ‖ counter` (little-endian counter).
pub fn aead_seal(key: &[u8; 32], counter: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(&(*key).into());
    cipher
        .encrypt(
            &aead_nonce(counter).into(),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("ChaCha20-Poly1305 encryption of a bounded message cannot fail")
}

/// `AEAD` open; `ciphertext` includes the tag.
pub fn aead_open(
    key: &[u8; 32],
    counter: u64,
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(&(*key).into());
    cipher
        .decrypt(
            &aead_nonce(counter).into(),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| CryptoError::Authentication)
}

/// The 12-byte data-frame and Noise nonce for `counter`.
pub fn aead_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

/// `XAEAD` seal.
pub fn xaead_seal(
    key: &[u8; 32],
    nonce: &[u8; XNONCE_LEN],
    ad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    cipher
        .encrypt(
            &(*nonce).into(),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption of a bounded message cannot fail")
}

/// `XAEAD` open; `ciphertext` includes the tag.
pub fn xaead_open(
    key: &[u8; 32],
    nonce: &[u8; XNONCE_LEN],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    cipher
        .decrypt(
            &(*nonce).into(),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| CryptoError::Authentication)
}

/// `DH_PUB(sk)`.
pub fn dh_pub(sk: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*sk).to_bytes()
}

/// `DH(sk, pk)`, failing on an all-zero output (vv-01 §2.2).
pub fn dh(sk: &[u8; 32], pk: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let out = Zeroizing::new(MontgomeryPoint(*pk).mul_clamped(*sk).to_bytes());
    if out.ct_eq(&[0u8; 32]).into() {
        return Err(CryptoError::DegenerateDh);
    }
    Ok(out)
}

/// `ED_TO_X_PUB(A)` (vv-01 §2.3).
pub fn ed_to_x_pub(a: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let compressed = CompressedEdwardsY(*a);
    let point = compressed
        .decompress()
        .ok_or(CryptoError::InvalidEdwardsKey)?;
    if point.compress().0 != *a || point.is_small_order() || !point.is_torsion_free() {
        return Err(CryptoError::InvalidEdwardsKey);
    }
    Ok(point.to_montgomery().to_bytes())
}

/// `ED_TO_X_SEC(seed)`: the clamped first half of `SHA-512(seed)`.
pub fn ed_to_x_sec(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut digest = Sha512::digest(seed);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest[..32]);
    digest.zeroize();
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

/// The Ed25519 public key of `seed` (RFC 8032 §5.1.5).
pub fn ed_public(seed: &[u8; 32]) -> [u8; 32] {
    let scalar = ed_to_x_sec(seed);
    EdwardsPoint::mul_base_clamped(*scalar).compress().0
}
