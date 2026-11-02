//! The hybrid Noise handshake `IKhfs+psk0+psk2` (vv-02 §2).

use ml_kem::ml_kem_1024::{DecapsulationKey, EncapsulationKey};
use ml_kem::{Ciphertext, Decapsulate, Encapsulate, KeyExport, MlKem1024, Seed};
use rand_core::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;
use crate::keys::crypto::{self, TAG_LEN};
use crate::keys::{NodePublic, NodeSecret};

/// vv-02 §2.1.
const PROTOCOL_NAME: &[u8] = b"Noise_IKhfs+psk0+psk2_25519+MLKEM1024_ChaChaPoly_BLAKE3";
/// vv-02 §2.1.
const PROLOGUE: &[u8] = b"vardevall v0";
/// ML-KEM-1024 encapsulation key and ciphertext sizes (FIPS 203).
const KEM_LEN: usize = 1568;

/// Noise message 1 without its payload (vv-02 §2.3).
pub(crate) const NOISE1_OVERHEAD: usize = 32 + KEM_LEN + TAG_LEN + 32 + TAG_LEN + TAG_LEN;
/// Noise message 2 without its payload (vv-02 §2.3).
pub(crate) const NOISE2_OVERHEAD: usize = 32 + KEM_LEN + TAG_LEN + TAG_LEN;

/// The two transport keys left by `Split()` (vv-02 §6.1).
pub(crate) struct SplitKeys {
    pub(crate) k_i2r: Zeroizing<[u8; 32]>,
    pub(crate) k_r2i: Zeroizing<[u8; 32]>,
    pub(crate) handshake_hash: [u8; 32],
}

#[derive(Clone)]
struct SymmetricState {
    ck: Zeroizing<[u8; 32]>,
    h: [u8; 32],
    k: Option<Zeroizing<[u8; 32]>>,
    n: u64,
}

impl SymmetricState {
    fn initialize(responder_static: &NodePublic) -> Self {
        let h = crypto::hash(&[PROTOCOL_NAME]);
        let mut s = SymmetricState {
            ck: Zeroizing::new(h),
            h,
            k: None,
            n: 0,
        };
        s.mix_hash(PROLOGUE);
        s.mix_hash(responder_static.as_bytes());
        s
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = crypto::hash(&[&self.h, data]);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = crypto::hkdf2(&self.ck, ikm);
        self.ck = Zeroizing::new(ck);
        self.k = Some(Zeroizing::new(k));
        self.n = 0;
    }

    fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let (ck, temp_h, k) = crypto::hkdf3(&self.ck, ikm);
        self.ck = Zeroizing::new(ck);
        self.mix_hash(&temp_h);
        self.k = Some(Zeroizing::new(k));
        self.n = 0;
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ct = match &self.k {
            Some(k) => {
                let ct = crypto::aead_seal(k, self.n, &self.h, plaintext);
                self.n += 1;
                ct
            }
            None => plaintext.to_vec(),
        };
        self.mix_hash(&ct);
        ct
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pt = match &self.k {
            Some(k) => {
                let pt = crypto::aead_open(k, self.n, &self.h, ciphertext)?;
                self.n += 1;
                pt
            }
            None => ciphertext.to_vec(),
        };
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    fn split(&self) -> SplitKeys {
        let (k1, k2) = crypto::hkdf2(&self.ck, &[]);
        SplitKeys {
            k_i2r: Zeroizing::new(k1),
            k_r2i: Zeroizing::new(k2),
            handshake_hash: self.h,
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CryptoError> {
        if self.0.len() < n {
            return Err(CryptoError::Authentication);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
}

fn random_array<const N: usize, R: CryptoRng>(rng: &mut R) -> Zeroizing<[u8; N]> {
    let mut a = Zeroizing::new([0u8; N]);
    rng.fill_bytes(&mut a[..]);
    a
}

/// The initiator's state between writing message 1 and reading message 2.
pub(crate) struct InitiatorHandshake {
    ss: SymmetricState,
    e: Zeroizing<[u8; 32]>,
    dk: DecapsulationKey,
}

impl InitiatorHandshake {
    /// Writes Noise message 1 (vv-02 §3.1 `noise1`).
    pub(crate) fn write_msg1<R: CryptoRng>(
        rng: &mut R,
        static_secret: &NodeSecret,
        responder: &NodePublic,
        psk0: &[u8; 32],
        payload: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        let mut ss = SymmetricState::initialize(responder);
        let mut out = Vec::with_capacity(NOISE1_OVERHEAD + payload.len());
        ss.mix_key_and_hash(psk0);

        let e = random_array::<32, _>(rng);
        let e_pub = crypto::dh_pub(&e);
        out.extend_from_slice(&e_pub);
        ss.mix_hash(&e_pub);
        ss.mix_key(&e_pub);

        ss.mix_key(&*crypto::dh(&e, responder.as_bytes())?);

        let seed = random_array::<64, _>(rng);
        let dk = DecapsulationKey::from_seed(Seed::from(*seed));
        let e1_pk = dk.encapsulation_key().to_bytes();
        out.extend_from_slice(&ss.encrypt_and_hash(e1_pk.as_slice()));

        out.extend_from_slice(&ss.encrypt_and_hash(static_secret.public().as_bytes()));
        ss.mix_key(&*crypto::dh(
            static_secret.as_bytes(),
            responder.as_bytes(),
        )?);

        out.extend_from_slice(&ss.encrypt_and_hash(payload));
        Ok((InitiatorHandshake { ss, e, dk }, out))
    }

    /// Reads Noise message 2 and splits (vv-02 §3.2 `noise2`).
    pub(crate) fn read_msg2(
        &self,
        static_secret: &NodeSecret,
        noise2: &[u8],
        psk2: &[u8; 32],
    ) -> Result<(Vec<u8>, SplitKeys), CryptoError> {
        let mut ss = self.ss.clone();
        let mut r = Reader(noise2);
        let re: [u8; 32] = r
            .take(32)?
            .try_into()
            .map_err(|_| CryptoError::Authentication)?;
        ss.mix_hash(&re);
        ss.mix_key(&re);

        ss.mix_key(&*crypto::dh(&self.e, &re)?);

        let ct_bytes = ss.decrypt_and_hash(r.take(KEM_LEN + TAG_LEN)?)?;
        let ct = Ciphertext::<MlKem1024>::try_from(ct_bytes.as_slice())
            .map_err(|_| CryptoError::Authentication)?;
        let shared = Zeroizing::new(self.dk.decapsulate(&ct));
        ss.mix_key(shared.as_slice());

        ss.mix_key(&*crypto::dh(static_secret.as_bytes(), &re)?);

        ss.mix_key_and_hash(psk2);
        let payload = ss.decrypt_and_hash(r.0)?;
        Ok((payload, ss.split()))
    }
}

/// The responder's state between reading message 1 and writing message 2.
pub(crate) struct ResponderHandshake {
    ss: SymmetricState,
    initiator: NodePublic,
    re: [u8; 32],
    re1: EncapsulationKey,
}

impl ResponderHandshake {
    /// Reads Noise message 1; the initiator key is authenticated but not yet accepted.
    pub(crate) fn read_msg1(
        static_secret: &NodeSecret,
        psk0: &[u8; 32],
        noise1: &[u8],
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        let own = static_secret.public();
        let mut ss = SymmetricState::initialize(&own);
        ss.mix_key_and_hash(psk0);
        let mut r = Reader(noise1);

        let re: [u8; 32] = r
            .take(32)?
            .try_into()
            .map_err(|_| CryptoError::Authentication)?;
        ss.mix_hash(&re);
        ss.mix_key(&re);
        ss.mix_key(&*crypto::dh(static_secret.as_bytes(), &re)?);

        let e1_bytes = ss.decrypt_and_hash(r.take(KEM_LEN + TAG_LEN)?)?;
        let initiator: [u8; 32] = ss
            .decrypt_and_hash(r.take(32 + TAG_LEN)?)?
            .try_into()
            .map_err(|_| CryptoError::Authentication)?;
        let initiator = NodePublic::from_bytes(initiator);
        ss.mix_key(&*crypto::dh(
            static_secret.as_bytes(),
            initiator.as_bytes(),
        )?);

        let payload = ss.decrypt_and_hash(r.0)?;
        let key = ml_kem::Key::<EncapsulationKey>::try_from(e1_bytes.as_slice())
            .map_err(|_| CryptoError::InvalidKemKey)?;
        let re1 = EncapsulationKey::new(&key).map_err(|_| CryptoError::InvalidKemKey)?;
        Ok((
            ResponderHandshake {
                ss,
                initiator,
                re,
                re1,
            },
            payload,
        ))
    }

    /// The authenticated initiator key.
    pub(crate) fn initiator(&self) -> &NodePublic {
        &self.initiator
    }

    /// Writes Noise message 2 and splits; runs `KEM.Encaps` (vv-02 §4.4).
    pub(crate) fn write_msg2<R: CryptoRng>(
        mut self,
        rng: &mut R,
        psk2: &[u8; 32],
        payload: &[u8],
    ) -> Result<(Vec<u8>, SplitKeys), CryptoError> {
        let mut out = Vec::with_capacity(NOISE2_OVERHEAD + payload.len());

        let e = random_array::<32, _>(rng);
        let e_pub = crypto::dh_pub(&e);
        out.extend_from_slice(&e_pub);
        self.ss.mix_hash(&e_pub);
        self.ss.mix_key(&e_pub);

        self.ss.mix_key(&*crypto::dh(&e, &self.re)?);

        let (ct, shared) = self.re1.encapsulate_with_rng(rng);
        let shared = Zeroizing::new(shared);
        out.extend_from_slice(&self.ss.encrypt_and_hash(ct.as_slice()));
        self.ss.mix_key(shared.as_slice());

        self.ss
            .mix_key(&*crypto::dh(&e, self.initiator.as_bytes())?);

        self.ss.mix_key_and_hash(psk2);
        out.extend_from_slice(&self.ss.encrypt_and_hash(payload));
        Ok((out, self.ss.split()))
    }
}

impl Drop for SymmetricState {
    fn drop(&mut self) {
        self.h.zeroize();
        self.n = 0;
    }
}
