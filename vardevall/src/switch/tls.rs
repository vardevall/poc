//! TLS 1.3 towards a switch (vv-04 §2.3): a pinned key for pinned addresses, the Web PKI for web
//! addresses.
//!
//! The Web PKI roots are the bundled Mozilla set of `webpki-roots` plus the roots of the switch's
//! configuration. The bundle is a few hundred kilobytes of static data and the same on every
//! platform, where a platform verifier would add a binding to each one; the cost is that a root
//! store changes with the application and not with the system.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring as provider};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use tokio_rustls::TlsConnector;
use vardevall_proto::keys::SwitchPublic;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::config::SwitchAuth;

/// ALPN protocols offered, in preference order (vv-04 §2.2).
const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

fn bad_encoding() -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::BadEncoding)
}

/// The `SubjectPublicKeyInfo` of a certificate; nothing else of it is looked at (vv-04 §2.3).
fn spki(cert: &CertificateDer<'_>) -> Result<SubjectPublicKeyInfoDer<'static>, rustls::Error> {
    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).map_err(|_| bad_encoding())?;
    Ok(SubjectPublicKeyInfoDer::from(
        parsed.tbs_certificate.subject_pki.raw.to_vec(),
    ))
}

/// Accepts a certificate if its subject key is the pinned one: no issuer, chain, validity, name
/// or extension is checked, and the handshake signature must verify under that key.
#[derive(Debug)]
struct Pinned(SwitchPublic);

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if SwitchPublic::from_spki(spki(end_entity)?.as_ref()) == Some(self.0) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &spki(cert)?,
            dss,
            &provider::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// The Web PKI roots: the bundled ones and `extra` (DER certificates).
fn roots(extra: &[Vec<u8>]) -> Result<RootCertStore, rustls::Error> {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for der in extra {
        store
            .add(CertificateDer::from(der.clone()))
            .map_err(|_| bad_encoding())?;
    }
    Ok(store)
}

fn verifier(
    auth: &SwitchAuth,
    provider: &Arc<CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, rustls::Error> {
    match auth {
        SwitchAuth::Pinned(key) => Ok(Arc::new(Pinned(*key))),
        SwitchAuth::Web { extra_roots } => WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots(extra_roots)?),
            provider.clone(),
        )
        .build()
        .map(|v| v as Arc<dyn ServerCertVerifier>)
        .map_err(|e| rustls::Error::General(e.to_string())),
    }
}

/// A client configuration that authenticates the server as `auth` says, offering `alpn`. The
/// server name goes out in the Server Name Indication whenever it is a DNS name (vv-04 §2.3).
pub(crate) fn client_config(
    auth: &SwitchAuth,
    alpn: &[&[u8]],
) -> Result<ClientConfig, rustls::Error> {
    let provider = vardevall_tls_pq::shared_provider();
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier(auth, &provider)?)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.enable_early_data = false;
    config.enable_sni = true;
    Ok(config)
}

/// A connector for HTTP/2 and HTTP/1.1 that authenticates the server as `auth` says.
pub(crate) fn connector(auth: &SwitchAuth) -> Result<TlsConnector, rustls::Error> {
    Ok(TlsConnector::from(Arc::new(client_config(auth, &ALPN)?)))
}

/// The ALPN protocol of HTTP/3.
pub(crate) const ALPN_H3: &[u8] = b"h3";

/// Whether a failed handshake was the certificate check (vv-04 §2.3), found in the error chain.
pub(crate) fn is_key_mismatch(e: &std::io::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = e.get_ref().map(|s| s as _);
    while let Some(err) = source {
        if let Some(rustls::Error::InvalidCertificate(_)) = err.downcast_ref::<rustls::Error>() {
            return true;
        }
        source = err.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

    use super::*;

    fn pinned_certificate() -> (SwitchPublic, CertificateDer<'static>) {
        let pair = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let raw: [u8; 32] = pair.public_key_raw().try_into().unwrap();
        let params = CertificateParams::new(vec!["unrelated.example".to_owned()]).unwrap();
        let cert = params.self_signed(&pair).unwrap();
        (SwitchPublic::from_bytes(raw), cert.der().clone())
    }

    #[test]
    fn the_pinned_verifier_compares_the_subject_key_and_nothing_else() {
        let (key, cert) = pinned_certificate();
        let name = ServerName::try_from("switch.test").unwrap();
        let verify = |pinned: SwitchPublic, cert: &CertificateDer<'_>| {
            Pinned(pinned).verify_server_cert(cert, &[], &name, &[], UnixTime::now())
        };
        assert!(verify(key, &cert).is_ok());
        assert!(verify(SwitchPublic::from_bytes([8; 32]), &cert).is_err());
        assert!(verify(key, &CertificateDer::from(vec![1, 2, 3])).is_err());
    }

    #[test]
    fn the_web_verifier_refuses_a_self_signed_certificate() {
        let (_, cert) = pinned_certificate();
        let config = client_config(
            &SwitchAuth::Web {
                extra_roots: Vec::new(),
            },
            &ALPN,
        );
        assert!(config.is_ok());
        let provider = vardevall_tls_pq::shared_provider();
        let verifier = verifier(
            &SwitchAuth::Web {
                extra_roots: Vec::new(),
            },
            &provider,
        )
        .unwrap();
        let name = ServerName::try_from("unrelated.example").unwrap();
        assert!(
            verifier
                .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .is_err()
        );
    }
}
