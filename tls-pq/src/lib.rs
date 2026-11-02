//! The `X25519MLKEM768` hybrid key exchange [draft-ietf-tls-ecdhe-mlkem] for rustls on the ring
//! provider, which has no post-quantum group of its own.
//!
//! rustls ships the group only for its aws-lc-rs provider, which costs a C library and about two
//! megabytes of binary. This composes ring's X25519 with the ML-KEM-768 of the `ml-kem` crate,
//! which the vardevall handshake already links (vv-02 uses ML-KEM-1024). The key shares are
//! `mlkem768_encapsulation_key || x25519_public` from the client and
//! `mlkem768_ciphertext || x25519_public` from the server; the secret is
//! `mlkem768_secret || x25519_secret`.
//!
//! The group is independent of the certificate type, so raw public keys (RFC 7250) and QUIC work
//! unchanged. Use [`provider`] in place of `rustls::crypto::ring::default_provider()`.

use std::sync::Arc;

use ml_kem::ml_kem_768::{DecapsulationKey, EncapsulationKey};
use ml_kem::{Ciphertext, Decapsulate, Encapsulate, KeyExport, MlKem768, Seed};
use rand_core::UnwrapErr;
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};
use zeroize::Zeroizing;

const ENCAPSULATION_KEY_LEN: usize = 1184;
const CIPHERTEXT_LEN: usize = 1088;
const X25519_LEN: usize = 32;
const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

/// The `X25519MLKEM768` group.
pub static X25519MLKEM768: &dyn SupportedKxGroup = &Hybrid;

/// The ring provider with [`X25519MLKEM768`] preferred, then ring's own groups.
pub fn provider() -> CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups.insert(0, X25519MLKEM768);
    provider
}

/// [`provider`] in an `Arc`, as the config builders take it.
pub fn shared_provider() -> Arc<CryptoProvider> {
    Arc::new(provider())
}

fn classical() -> &'static dyn SupportedKxGroup {
    rustls::crypto::ring::kx_group::X25519
}

#[derive(Debug)]
struct Hybrid;

impl SupportedKxGroup for Hybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = classical().start()?;
        let mut seed = Zeroizing::new([0u8; 64]);
        getrandom::fill(seed.as_mut_slice())
            .map_err(|_| Error::General("key generation failed".into()))?;
        let dk = DecapsulationKey::from_seed(Seed::from(*seed));
        let mut pub_key = dk.encapsulation_key().to_bytes().to_vec();
        pub_key.extend_from_slice(classical.pub_key());
        Ok(Box::new(Active {
            classical,
            dk: Box::new(dk),
            pub_key,
        }))
    }

    /// The server side: encapsulate to the client's key, answer with the ciphertext.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != ENCAPSULATION_KEY_LEN + X25519_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (pq_share, x_share) = client_share.split_at(ENCAPSULATION_KEY_LEN);
        let key =
            ml_kem::Key::<EncapsulationKey>::try_from(pq_share).map_err(|_| INVALID_KEY_SHARE)?;
        let ek = EncapsulationKey::new(&key).map_err(|_| INVALID_KEY_SHARE)?;
        let (ct, pq_secret) = ek.encapsulate_with_rng(&mut UnwrapErr(getrandom::SysRng));
        let pq_secret = Zeroizing::new(pq_secret);
        let cl = classical().start_and_complete(x_share)?;

        let mut pub_key = ct.to_vec();
        pub_key.extend_from_slice(&cl.pub_key);
        let secret = Zeroizing::new([pq_secret.as_slice(), cl.secret.secret_bytes()].concat());
        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key,
            secret: SharedSecret::from(secret.as_slice()),
        })
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct Active {
    classical: Box<dyn ActiveKeyExchange>,
    dk: Box<DecapsulationKey>,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != CIPHERTEXT_LEN + X25519_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (ct, x_share) = peer_pub_key.split_at(CIPHERTEXT_LEN);
        let ct = Ciphertext::<MlKem768>::try_from(ct).map_err(|_| INVALID_KEY_SHARE)?;
        let pq_secret = Zeroizing::new(self.dk.decapsulate(&ct));
        let cl = self.classical.complete(x_share)?;
        let secret = Zeroizing::new([pq_secret.as_slice(), cl.secret_bytes()].concat());
        Ok(SharedSecret::from(secret.as_slice()))
    }

    /// Lets the client offer the classical share on its own, so that a server without the hybrid
    /// group answers without a HelloRetryRequest.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}
