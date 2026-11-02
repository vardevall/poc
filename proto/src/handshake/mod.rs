//! Handshake building blocks: one initiation and one response (vv-02 §2–§4, §6.1).

pub mod cookie;
pub mod message;
mod noise;
pub mod payload;
pub mod reassembly;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::error::{CryptoError, HandshakeError, ParseError};
use crate::handshake::noise::{InitiatorHandshake, ResponderHandshake, SplitKeys};
use crate::keys::crypto;
use crate::keys::{NetworkSecret, NodePublic, NodeSecret, PairPsk, ctx};

/// The long-term keys of one interface with the values derived from them.
pub struct LocalKeys {
    secret: NodeSecret,
    public: NodePublic,
    network: NetworkSecret,
    psk0: Zeroizing<[u8; 32]>,
    mac1_key: Zeroizing<[u8; 32]>,
    cookie_key: Zeroizing<[u8; 32]>,
}

impl LocalKeys {
    /// Derives the interface's handshake keys.
    pub fn new(secret: NodeSecret, network: NetworkSecret) -> Self {
        let public = secret.public();
        LocalKeys {
            psk0: network.psk(),
            mac1_key: network.mac1_key(&public),
            cookie_key: network.cookie_key(&public),
            secret,
            public,
            network,
        }
    }

    /// The node's public key.
    pub fn public(&self) -> &NodePublic {
        &self.public
    }

    /// The node's private key.
    pub fn secret(&self) -> &NodeSecret {
        &self.secret
    }

    /// The network secret.
    pub fn network(&self) -> &NetworkSecret {
        &self.network
    }

    /// `mac1_key` for messages received by this node (vv-01 §5.3).
    pub fn mac1_key_in(&self) -> &[u8; 32] {
        &self.mac1_key
    }

    /// `cookie_key` for cookies issued by this node (vv-01 §5.3).
    pub fn cookie_key_own(&self) -> &[u8; 32] {
        &self.cookie_key
    }

    /// The network PSK.
    pub fn psk0(&self) -> &[u8; 32] {
        &self.psk0
    }
}

/// Session keys from `Split()` and their derivations (vv-02 §6.1).
pub struct SessionKeys {
    k_i2r: Zeroizing<[u8; 32]>,
    k_r2i: Zeroizing<[u8; 32]>,
}

impl SessionKeys {
    /// Wraps the raw Noise `Split()` keys, for a session known only by them.
    pub fn from_noise_keys(k_i2r: [u8; 32], k_r2i: [u8; 32]) -> Self {
        SessionKeys {
            k_i2r: Zeroizing::new(k_i2r),
            k_r2i: Zeroizing::new(k_r2i),
        }
    }

    fn from_split(s: SplitKeys) -> (Self, [u8; 32]) {
        (
            SessionKeys {
                k_i2r: s.k_i2r,
                k_r2i: s.k_r2i,
            },
            s.handshake_hash,
        )
    }

    /// The raw Noise key, initiator to responder.
    pub fn k_i2r(&self) -> &[u8; 32] {
        &self.k_i2r
    }

    /// The raw Noise key, responder to initiator.
    pub fn k_r2i(&self) -> &[u8; 32] {
        &self.k_r2i
    }

    /// `frame_i2r`.
    pub fn frame_i2r(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(crypto::kdf(ctx::FRAME, &[&*self.k_i2r]))
    }

    /// `frame_r2i`.
    pub fn frame_r2i(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(crypto::kdf(ctx::FRAME, &[&*self.k_r2i]))
    }
}

/// A finished handshake as seen by one side.
pub struct Completed {
    /// The session keys.
    pub keys: SessionKeys,
    /// The peer's decrypted payload.
    pub payload: Vec<u8>,
    /// The Noise handshake hash after `Split()`.
    pub handshake_hash: [u8; 32],
}

/// An initiation awaiting message 2 (vv-02 §3.1).
pub struct Initiator {
    hs: InitiatorHandshake,
    sender_index: u32,
    peer: NodePublic,
}

impl Initiator {
    /// Writes message 1 to `peer` with `payload`, drawing `e` then the KEM seed from `rng`.
    pub fn start<R: CryptoRng>(
        rng: &mut R,
        local: &LocalKeys,
        peer: &NodePublic,
        sender_index: u32,
        payload: &[u8],
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        let (hs, noise1) =
            InitiatorHandshake::write_msg1(rng, &local.secret, peer, &local.psk0, payload)
                .map_err(|_| HandshakeError::Noise)?;
        let mac1_key = local.network.mac1_key(peer);
        let message = message::build_message1(sender_index, &noise1, &mac1_key);
        Ok((
            Initiator {
                hs,
                sender_index,
                peer: *peer,
            },
            message,
        ))
    }

    /// The index chosen for message 1.
    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }

    /// The responder this initiation is addressed to.
    pub fn peer(&self) -> &NodePublic {
        &self.peer
    }

    /// Verifies and reads message 2 (vv-02 §3.2).
    pub fn finish(
        &self,
        local: &LocalKeys,
        psk2: &PairPsk,
        message2: &[u8],
    ) -> Result<(Completed, u32), HandshakeError> {
        let m = message::parse_message2(message2).map_err(|_| HandshakeError::Malformed)?;
        if !message::verify_mac1(message2, &local.mac1_key) {
            return Err(HandshakeError::Mac);
        }
        if m.receiver_index != self.sender_index {
            return Err(HandshakeError::Malformed);
        }
        let (payload, split) = self
            .hs
            .read_msg2(&local.secret, m.noise2, psk2.as_bytes())
            .map_err(|_| HandshakeError::Noise)?;
        let (keys, handshake_hash) = SessionKeys::from_split(split);
        Ok((
            Completed {
                keys,
                payload,
                handshake_hash,
            },
            m.sender_index,
        ))
    }
}

/// A message 1 that decrypted, before the initiator is accepted (vv-02 §4.4 steps 1–2).
pub struct Responder {
    hs: ResponderHandshake,
    initiator_index: u32,
    payload: Vec<u8>,
    mac1_key_out: Zeroizing<[u8; 32]>,
}

impl Responder {
    /// Verifies mac1 and reads message 1.
    pub fn read(local: &LocalKeys, message1: &[u8]) -> Result<Self, HandshakeError> {
        let m = message::parse_message1(message1).map_err(|_| HandshakeError::Malformed)?;
        if !message::verify_mac1(message1, &local.mac1_key) {
            return Err(HandshakeError::Mac);
        }
        let (hs, payload) = ResponderHandshake::read_msg1(&local.secret, &local.psk0, m.noise1)
            .map_err(|e| match e {
                CryptoError::InvalidKemKey => HandshakeError::Malformed,
                _ => HandshakeError::Noise,
            })?;
        let mac1_key_out = local.network.mac1_key(hs.initiator());
        Ok(Responder {
            hs,
            initiator_index: m.sender_index,
            payload,
            mac1_key_out,
        })
    }

    /// The authenticated initiator key.
    pub fn initiator(&self) -> &NodePublic {
        self.hs.initiator()
    }

    /// The initiator's `sender_index`.
    pub fn initiator_index(&self) -> u32 {
        self.initiator_index
    }

    /// The decrypted message 1 payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Writes message 2, drawing `e` then the KEM randomness from `rng`.
    pub fn respond<R: CryptoRng>(
        self,
        rng: &mut R,
        psk2: &PairPsk,
        sender_index: u32,
        payload: &[u8],
    ) -> Result<(Vec<u8>, Completed), HandshakeError> {
        let (noise2, split) = self
            .hs
            .write_msg2(rng, psk2.as_bytes(), payload)
            .map_err(|_| HandshakeError::Noise)?;
        let message = message::build_message2(
            sender_index,
            self.initiator_index,
            &noise2,
            &self.mac1_key_out,
        );
        let (keys, handshake_hash) = SessionKeys::from_split(split);
        Ok((
            message,
            Completed {
                keys,
                payload: self.payload,
                handshake_hash,
            },
        ))
    }
}

impl From<ParseError> for HandshakeError {
    fn from(_: ParseError) -> Self {
        HandshakeError::Malformed
    }
}
