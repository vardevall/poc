//! Reloading on SIGHUP (`systemctl reload vv-switch`): the operator tokens and, if the switch
//! serves a `cert_file` certificate, that certificate.
//!
//! Only `[tokens]` and the token file are re-read; every other setting keeps its value from
//! start. A reload that fails changes nothing.

use std::path::PathBuf;
use std::sync::Arc;

use crate::api::{Api, ReloadError};
use crate::config::TokenSettings;
use crate::tls::FileCertificate;

/// Re-reads the token settings of the configuration file, and the certificate files, on every
/// SIGHUP.
pub struct Reloader {
    api: Arc<Api>,
    path: PathBuf,
    certificate: Option<Arc<FileCertificate>>,
    #[cfg(unix)]
    hup: tokio::signal::unix::Signal,
}

impl Reloader {
    /// Takes over SIGHUP, so that it no longer ends the process. Call it before the switch
    /// starts to serve, from within the runtime; `path` is the configuration file given at
    /// start.
    pub fn new(api: Arc<Api>, path: PathBuf) -> std::io::Result<Reloader> {
        Ok(Reloader {
            #[cfg(unix)]
            hup: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?,
            api,
            path,
            certificate: None,
        })
    }

    /// Reloads `certificate` too, if there is one ([`crate::Switch::file_certificate`]).
    pub fn with_certificate(mut self, certificate: Option<Arc<FileCertificate>>) -> Self {
        self.certificate = certificate;
        self
    }

    /// Reloads on every SIGHUP and reports each outcome on stderr, forever.
    pub async fn run(mut self) {
        loop {
            #[cfg(unix)]
            if self.hup.recv().await.is_none() {
                return;
            }
            #[cfg(not(unix))]
            std::future::pending::<()>().await;
            let (api, path) = (self.api.clone(), self.path.clone());
            let result = tokio::task::spawn_blocking(move || reload(&api, &path)).await;
            match result {
                Ok(Ok(n)) => eprintln!("{}", reloaded(n)),
                Ok(Err(e)) => eprintln!("{}", failed(&e)),
                Err(_) => {
                    eprintln!("vv-switch: reload failed: aborted, keeping the previous tokens")
                }
            }
            if let Some(certificate) = self.certificate.clone() {
                match tokio::task::spawn_blocking(move || certificate.reload()).await {
                    Ok(Ok(())) => eprintln!("vv-switch: reloaded the certificate"),
                    Ok(Err(e)) => eprintln!(
                        "vv-switch: certificate reload failed: {e}, keeping the previous one"
                    ),
                    Err(_) => eprintln!(
                        "vv-switch: certificate reload failed: aborted, keeping the previous one"
                    ),
                }
            }
        }
    }
}

/// Reads the token settings of the configuration file at `path` and applies them to `api`;
/// returns the number of tokens now accepted.
pub fn reload(api: &Api, path: &std::path::Path) -> Result<usize, ReloadError> {
    api.reload_tokens(&TokenSettings::load(path)?)
}

fn reloaded(n: usize) -> String {
    if n == 0 {
        "vv-switch: reloaded tokens: 0 accepted, registration is open".to_owned()
    } else {
        format!("vv-switch: reloaded tokens: {n} accepted")
    }
}

fn failed(e: &ReloadError) -> String {
    format!("vv-switch: reload failed: {e}, keeping the previous tokens")
}
