//! TLS 1.3 for the switch (vv-04 §2.3): one server configuration whose certificate is chosen by
//! the Server Name Indication.
//!
//! A name configured as a web address gets the Web PKI certificate (PEM files or ACME); every
//! other name, and a connection without SNI, gets the pinned certificate, a self-signed X.509
//! certificate whose subject public key is the switch key `A`.

mod acme;
mod files;
mod pinned;

use std::sync::Arc;

use crate::config::Certificate;
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use vardevall_proto::keys::SwitchSecret;

pub use files::FileCertificate;

/// ALPN protocols offered, in preference order (vv-04 §2.2).
pub const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];
/// ALPN of HTTP/3 [RFC 9114] (vv-04 §2.2).
pub const ALPN_H3: &[u8] = b"h3";
/// ALPN of TURN over TLS [RFC 7443] (vv-04 §2.3).
pub const ALPN_TURN: &[u8] = b"stun.turn";
/// ALPN of the TLS-ALPN-01 challenge [RFC 8737]; such connections end after the handshake.
pub use acme::ALPN_ACME;

/// The TLS stack rejected the switch key or certificate.
#[derive(Debug, Error)]
pub enum TlsError {
    /// rustls refused the key material.
    #[error("building the TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
    /// QUIC does not accept the configuration.
    #[error("building the QUIC configuration: {0}")]
    Quic(String),
    /// The pinned certificate could not be made.
    #[error("making the pinned certificate: {0}")]
    Pinned(String),
    /// The certificate or its key could not be read.
    #[error("reading the certificate {path}: {reason}")]
    Certificate {
        /// The file.
        path: std::path::PathBuf,
        /// What went wrong.
        reason: String,
    },
}

enum Web {
    Acme(Arc<rustls_acme::ResolvesServerCertAcme>),
    Files(Arc<FileCertificate>),
}

/// Picks the certificate by SNI (vv-04 §2.3).
struct Resolver {
    pinned: Arc<CertifiedKey>,
    names: Vec<String>,
    web: Option<Web>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let web = hello.server_name().is_some_and(|sni| {
            let sni = sni.trim_end_matches('.');
            self.names.iter().any(|n| n.eq_ignore_ascii_case(sni))
        });
        match (&self.web, web) {
            (Some(Web::Acme(acme)), true) => acme.resolve(hello),
            (Some(Web::Files(files)), true) => Some(files.current()),
            _ => Some(self.pinned.clone()),
        }
    }
}

/// The TLS setup of the switch: one configuration for TCP and one for QUIC (the ALPN list is all
/// that differs), both with the same certificate choice.
#[derive(Clone)]
pub struct Tls {
    acceptor: TlsAcceptor,
    quic: Arc<dyn quinn::crypto::ServerConfig>,
    acme: Option<Arc<acme::Acme>>,
    files: Option<Arc<FileCertificate>>,
}

impl Tls {
    /// The setup for `key`, with the Web PKI certificate `certificate` for its names, if any.
    /// `alpn` is the list offered over TCP.
    pub fn new(
        key: &SwitchSecret,
        certificate: Option<&Certificate>,
        alpn: &[&[u8]],
    ) -> Result<Tls, TlsError> {
        let (web, acme, files) = match certificate {
            Some(Certificate::Files {
                cert_file,
                key_file,
                ..
            }) => {
                let files = Arc::new(FileCertificate::load(cert_file, key_file)?);
                (Some(Web::Files(files.clone())), None, Some(files))
            }
            Some(Certificate::Acme(settings)) => {
                let acme = Arc::new(acme::start(settings)?);
                (Some(Web::Acme(acme.resolver.clone())), Some(acme), None)
            }
            None => (None, None, None),
        };
        let resolver = Arc::new(Resolver {
            pinned: pinned::certified_key(key)?,
            names: certificate.map(Certificate::names).unwrap_or_default(),
            web,
        });
        let mut tcp_alpn = alpn.to_vec();
        if acme.is_some() {
            tcp_alpn.push(ALPN_ACME);
        }
        let quic = quinn::crypto::rustls::QuicServerConfig::try_from(config(
            resolver.clone(),
            &[ALPN_H3],
        )?)
        .map_err(|e| TlsError::Quic(e.to_string()))?;
        Ok(Tls {
            acceptor: TlsAcceptor::from(config(resolver, &tcp_alpn)?),
            quic: Arc::new(quic),
            acme,
            files,
        })
    }

    /// The task that orders and renews the ACME certificate, if the switch uses one; run it once.
    pub fn acme_task(&self) -> Option<impl std::future::Future<Output = ()> + Send + 'static> {
        self.acme.as_ref()?.take().map(acme::run)
    }

    /// The certificate read from PEM files, if the switch uses one: reload it on SIGHUP.
    pub fn file_certificate(&self) -> Option<&Arc<FileCertificate>> {
        self.files.as_ref()
    }

    /// The QUIC configuration, which makes the same choice as [`Tls::accept`] (vv-04 §2.2, §2.3).
    pub fn quic(&self) -> Arc<dyn quinn::crypto::ServerConfig> {
        self.quic.clone()
    }

    /// Completes a TLS handshake on `tcp`.
    pub async fn accept(&self, tcp: TcpStream) -> std::io::Result<TlsStream<TcpStream>> {
        self.acceptor.accept(tcp).await
    }
}

fn config(
    resolver: Arc<dyn ResolvesServerCert>,
    alpn: &[&[u8]],
) -> Result<Arc<ServerConfig>, TlsError> {
    let mut config = ServerConfig::builder_with_provider(vardevall_tls_pq::shared_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}
