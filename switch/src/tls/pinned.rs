//! The pinned certificate (vv-04 §2.3, vv-01 §4.4): a self-signed X.509 certificate whose subject
//! public key is the switch key `A`.
//!
//! Clients compare that key with `A` and look at nothing else, so the certificate only carries
//! the key: the subject says nothing and the validity covers any date a clock can show.

use std::sync::Arc;

use rcgen::{DistinguishedName, DnType, KeyPair, PKCS_ED25519};
use rustls::crypto::ring as provider;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::sign::CertifiedKey;
use vardevall_proto::keys::SwitchSecret;
use zeroize::Zeroizing;

use super::TlsError;

const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The pinned certificate of `key` with its signing key.
pub(super) fn certified_key(key: &SwitchSecret) -> Result<Arc<CertifiedKey>, TlsError> {
    let mut pkcs8 = Zeroizing::new(ED25519_PKCS8_PREFIX.to_vec());
    pkcs8.extend_from_slice(key.as_bytes());
    let der = PrivatePkcs8KeyDer::from(pkcs8.as_slice());
    let signer = provider::sign::any_eddsa_type(&der)?;
    let fail = |e: rcgen::Error| TlsError::Pinned(e.to_string());
    let pair = KeyPair::from_pkcs8_der_and_sign_algo(&der, &PKCS_ED25519).map_err(fail)?;
    let mut params = rcgen::CertificateParams::new(Vec::new()).map_err(fail)?;
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, "vardevall switch");
    params.distinguished_name = subject;
    params.not_before = rcgen::date_time_ymd(1975, 1, 1);
    params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    let cert = params.self_signed(&pair).map_err(fail)?;
    Ok(Arc::new(CertifiedKey::new(
        vec![cert.der().clone()],
        signer,
    )))
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::CertificateDer;

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_certificate_carries_the_key_of_the_vector() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/04-switch-api.json")).unwrap();
        let seed = hex(doc["registration"][0]["input"]["switch_seed"]
            .as_str()
            .unwrap());
        let key = SwitchSecret::from_bytes(seed.try_into().unwrap());
        let v = &doc["pinned_certificate"][0];
        assert_eq!(
            key.public().as_bytes().to_vec(),
            hex(v["input"]["A"].as_str().unwrap())
        );

        let certified = certified_key(&key).unwrap();
        certified.keys_match().unwrap();
        let der: &CertificateDer<'_> = certified.end_entity_cert().unwrap();
        let cert = webpki::EndEntityCert::try_from(der).unwrap();
        assert_eq!(
            cert.subject_public_key_info().as_ref(),
            hex(v["output"]["subject_public_key_info_der"].as_str().unwrap())
        );
    }

    #[test]
    fn the_certificate_is_the_same_at_every_start() {
        let key = SwitchSecret::from_bytes([3; 32]);
        let a = certified_key(&key).unwrap();
        let b = certified_key(&key).unwrap();
        assert_eq!(a.end_entity_cert().unwrap(), b.end_entity_cert().unwrap());
    }
}
