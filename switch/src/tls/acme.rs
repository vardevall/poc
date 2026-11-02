//! ACME for the browser certificate (vv-04 §2.3, vv-07 §6): TLS-ALPN-01 on the HTTPS port.
//!
//! The challenge connection is an ordinary TLS connection to the HTTPS port that offers ALPN
//! `acme-tls/1`; the resolver of [`super::Tls`] answers it with the challenge certificate and the
//! switch closes it after the handshake. Orders and renewals run in a task that polls the state
//! returned by [`start`].

use std::io;
use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeConfig, AcmeState, ResolvesServerCertAcme};

use super::TlsError;
use crate::config::Acme as AcmeSettings;

/// ALPN of the TLS-ALPN-01 challenge [RFC 8737].
pub const ALPN_ACME: &[u8] = b"acme-tls/1";
const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";

type State = AcmeState<io::Error>;

/// The certificate source and the challenge configuration of an ACME-managed certificate.
pub(super) struct Acme {
    /// Serves the certificate once issued, and the challenge certificate during validation.
    pub resolver: Arc<ResolvesServerCertAcme>,
    state: Mutex<Option<State>>,
}

/// Prepares the ACME client for `settings`; nothing happens until [`Acme::take`]n state is run.
pub(super) fn start(settings: &AcmeSettings) -> Result<Acme, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let base = match &settings.ca_file {
        None => AcmeConfig::new_with_provider([&settings.domain], provider.clone()),
        Some(file) => {
            let mut roots = RootCertStore::empty();
            let certs = CertificateDer::pem_file_iter(file)
                .and_then(|it| it.collect::<Result<Vec<_>, _>>())
                .map_err(|e| TlsError::Certificate {
                    path: file.clone(),
                    reason: e.to_string(),
                })?;
            for c in certs {
                roots.add(c)?;
            }
            let client = ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
            AcmeConfig::new_with_client_config([&settings.domain], Arc::new(client))
        }
    };
    let mut config = base.directory(settings.directory.as_deref().unwrap_or(LETS_ENCRYPT));
    if let Some(contact) = &settings.contact {
        config = config.contact_push(contact);
    }
    let state = config
        .cache_option(settings.cache_dir.clone().map(DirCache::new))
        .state();
    Ok(Acme {
        resolver: state.resolver(),
        state: Mutex::new(Some(state)),
    })
}

impl Acme {
    /// The state to drive with [`run`], once.
    pub(super) fn take(&self) -> Option<State> {
        self.state.lock().ok()?.take()
    }
}

/// Orders the certificate and renews it, until dropped. Failures are retried by the client with
/// a backoff; they say nothing about users and are printed for the operator.
pub async fn run(mut state: State) {
    while let Some(event) = state.next().await {
        if let Err(e) = event {
            eprintln!("vv-switch: ACME: {e}");
        }
    }
}
