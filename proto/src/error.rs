//! Error types shared by the modules of this crate.

use thiserror::Error;

/// A text or byte encoding was rejected (vv-01 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EncodingError {
    /// A character outside the base32 alphabet, including padding and whitespace.
    #[error("invalid base32 character")]
    InvalidCharacter,
    /// A length that no byte count produces.
    #[error("invalid base32 length")]
    InvalidLength,
    /// Non-zero unused bits in the final character.
    #[error("non-zero trailing bits")]
    TrailingBits,
    /// A fixed-size field of another size.
    #[error("unexpected value size")]
    WrongSize,
}

/// A cryptographic check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// An AEAD tag or a MAC did not verify.
    #[error("authentication failed")]
    Authentication,
    /// A Diffie-Hellman output was all zeros (vv-01 §2.2).
    #[error("degenerate Diffie-Hellman output")]
    DegenerateDh,
    /// An Ed25519 key that cannot be converted to X25519 (vv-01 §2.3).
    #[error("invalid Ed25519 public key")]
    InvalidEdwardsKey,
    /// A KEM public key that does not decode.
    #[error("invalid KEM public key")]
    InvalidKemKey,
}

/// A datagram or message could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ParseError {
    /// Shorter or longer than the format allows.
    #[error("invalid length")]
    Length,
    /// A type byte that does not belong to the format.
    #[error("unexpected type")]
    Type,
    /// A JSON document that violates vv-01 §3.3.
    #[error("invalid JSON")]
    Json,
    /// A member with a missing or malformed value.
    #[error("invalid field")]
    Field,
}

/// A handshake message was dropped (vv-02 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HandshakeError {
    /// The message does not parse.
    #[error("malformed message")]
    Malformed,
    /// mac1 or mac2 did not verify.
    #[error("invalid mac")]
    Mac,
    /// The Noise handshake failed to authenticate.
    #[error("noise authentication failed")]
    Noise,
    /// The initiator key is neither configured nor accepted as a member.
    #[error("initiator not accepted")]
    NotAccepted,
    /// The timestamp is not greater than the last one accepted.
    #[error("replayed timestamp")]
    Replay,
    /// More than the allowed message 1 rate from one initiator.
    #[error("rate limited")]
    RateLimited,
    /// The payload does not parse.
    #[error("invalid payload")]
    Payload,
}

/// An operation on a peer could not be carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PeerError {
    /// The peer is not configured and member trust is off.
    #[error("unknown peer")]
    Unknown,
    /// No usable session and the data could not be queued.
    #[error("no session")]
    NoSession,
    /// The packet exceeds the interface MTU.
    #[error("packet too large")]
    TooLarge,
}
