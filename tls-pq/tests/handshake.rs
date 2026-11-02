//! The hybrid group inside real TLS 1.3 handshakes, against itself, against rustls' aws-lc-rs
//! implementation of the same group, and against peers without it.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, NamedGroup, RootCertStore, ServerConfig, ServerConnection,
};

fn ring_only() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn aws_hybrid_only() -> Arc<CryptoProvider> {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    p.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    Arc::new(p)
}

fn configs(
    client: Arc<CryptoProvider>,
    server: Arc<CryptoProvider>,
) -> (ClientConfig, ServerConfig) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client = ClientConfig::builder_with_provider(client)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let server = ServerConfig::builder_with_provider(server)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert.cert.der().to_vec())], key)
        .unwrap();
    (client, server)
}

/// Runs a handshake in memory; returns the group each side negotiated.
fn handshake(client: Arc<CryptoProvider>, server: Arc<CryptoProvider>) -> (NamedGroup, NamedGroup) {
    let (client, server) = configs(client, server);
    let mut c = ClientConnection::new(Arc::new(client), ServerName::try_from("localhost").unwrap())
        .unwrap();
    let mut s = ServerConnection::new(Arc::new(server)).unwrap();
    while c.is_handshaking() || s.is_handshaking() {
        let mut buf = Vec::new();
        if c.wants_write() {
            c.write_tls(&mut buf).unwrap();
            s.read_tls(&mut buf.as_slice()).unwrap();
            s.process_new_packets().unwrap();
        }
        let mut buf = Vec::new();
        if s.wants_write() {
            s.write_tls(&mut buf).unwrap();
            c.read_tls(&mut buf.as_slice()).unwrap();
            c.process_new_packets().unwrap();
        }
    }
    (
        c.negotiated_key_exchange_group().unwrap().name(),
        s.negotiated_key_exchange_group().unwrap().name(),
    )
}

const HYBRID: NamedGroup = NamedGroup::X25519MLKEM768;

#[test]
fn two_nodes_of_this_crate_agree_on_the_hybrid_group() {
    let p = vardevall_tls_pq::shared_provider();
    assert_eq!(handshake(p.clone(), p), (HYBRID, HYBRID));
}

#[test]
fn it_interoperates_with_the_aws_lc_rs_implementation_both_ways() {
    let ours = vardevall_tls_pq::shared_provider();
    assert_eq!(handshake(aws_hybrid_only(), ours.clone()), (HYBRID, HYBRID));
    assert_eq!(handshake(ours, aws_hybrid_only()), (HYBRID, HYBRID));
}

#[test]
fn a_peer_without_the_group_gets_x25519() {
    let ours = vardevall_tls_pq::shared_provider();
    let x = NamedGroup::X25519;
    assert_eq!(handshake(ours.clone(), ring_only()), (x, x));
    assert_eq!(handshake(ring_only(), ours), (x, x));
}

#[test]
fn malformed_key_shares_are_refused() {
    use rustls::crypto::SupportedKxGroup;
    let g: &dyn SupportedKxGroup = vardevall_tls_pq::X25519MLKEM768;
    for len in [0, 31, 32, 1184, 1215, 1217, 2000] {
        assert!(g.start_and_complete(&vec![7u8; len]).is_err(), "{len}");
    }
    let kx = g.start().unwrap();
    assert_eq!(kx.pub_key().len(), 1184 + 32);
    assert!(kx.complete(&[0u8; 1088 + 31]).is_err());
}
