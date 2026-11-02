//! A certificate read from PEM files, read again when it is renewed.
//!
//! A renewal replaces the files; the switch picks them up on SIGHUP ([`FileCertificate::reload`])
//! or within [`WATCH_INTERVAL`] of a change ([`FileCertificate::watch`]). A pair that cannot be
//! read, or whose key does not belong to the certificate, leaves the previous certificate in
//! place.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use rustls::crypto::ring as provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;

use super::TlsError;

/// How often the files are looked at for a change.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(30);

type Stamp = (Option<SystemTime>, Option<SystemTime>);

/// The certificate and key in a pair of PEM files.
#[derive(Debug)]
pub struct FileCertificate {
    cert_file: PathBuf,
    key_file: PathBuf,
    current: ArcSwap<CertifiedKey>,
    seen: Mutex<Stamp>,
}

fn stamp(cert_file: &Path, key_file: &Path) -> Stamp {
    let modified = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    (modified(cert_file), modified(key_file))
}

fn read(cert_file: &Path, key_file: &Path) -> Result<Arc<CertifiedKey>, TlsError> {
    let fail = |path: &Path, e: rustls::pki_types::pem::Error| TlsError::Certificate {
        path: path.to_owned(),
        reason: e.to_string(),
    };
    let chain = CertificateDer::pem_file_iter(cert_file)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| fail(cert_file, e))?;
    if chain.is_empty() {
        return Err(TlsError::Certificate {
            path: cert_file.to_owned(),
            reason: "no certificate found".to_owned(),
        });
    }
    let key = PrivateKeyDer::from_pem_file(key_file).map_err(|e| fail(key_file, e))?;
    let signer = provider::default_provider()
        .key_provider
        .load_private_key(key)?;
    let certified = CertifiedKey::new(chain, signer);
    certified.keys_match().map_err(|e| TlsError::Certificate {
        path: key_file.to_owned(),
        reason: e.to_string(),
    })?;
    Ok(Arc::new(certified))
}

impl FileCertificate {
    /// Reads the files for the first time.
    pub fn load(cert_file: &Path, key_file: &Path) -> Result<FileCertificate, TlsError> {
        let seen = stamp(cert_file, key_file);
        Ok(FileCertificate {
            cert_file: cert_file.to_owned(),
            key_file: key_file.to_owned(),
            current: ArcSwap::new(read(cert_file, key_file)?),
            seen: Mutex::new(seen),
        })
    }

    pub(super) fn current(&self) -> Arc<CertifiedKey> {
        self.current.load_full()
    }

    /// Reads the files again and serves what they hold from the next handshake on. On an error
    /// the previous certificate stays.
    pub fn reload(&self) -> Result<(), TlsError> {
        let seen = stamp(&self.cert_file, &self.key_file);
        self.current.store(read(&self.cert_file, &self.key_file)?);
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = seen;
        Ok(())
    }

    fn changed(&self) -> Option<Stamp> {
        let now = stamp(&self.cert_file, &self.key_file);
        (now != *self.seen.lock().unwrap_or_else(|e| e.into_inner())).then_some(now)
    }

    /// Reloads whenever the files change, until dropped. Outcomes are printed for the operator;
    /// they say nothing about users.
    pub async fn watch(self: Arc<Self>) {
        let mut tick = tokio::time::interval(WATCH_INTERVAL);
        let mut failed: Option<Stamp> = None;
        loop {
            tick.tick().await;
            let Some(now) = self.changed() else { continue };
            if failed == Some(now) {
                continue;
            }
            match self.reload() {
                Ok(()) => {
                    failed = None;
                    eprintln!("vv-switch: reloaded the certificate");
                }
                Err(e) => {
                    failed = Some(now);
                    eprintln!(
                        "vv-switch: certificate reload failed: {e}, keeping the previous one"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
        let pair = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        let (c, k) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&c, pair.cert.pem()).unwrap();
        std::fs::write(&k, pair.key_pair.serialize_pem()).unwrap();
        (c, k)
    }

    #[test]
    fn a_renewal_is_picked_up_and_a_broken_pair_is_not() {
        let dir = std::env::temp_dir().join(format!("vv-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = write(&dir, "one.example");
        let files = FileCertificate::load(&cert, &key).unwrap();
        let leaf = || files.current().end_entity_cert().unwrap().as_ref().to_vec();
        let first = leaf();
        assert!(files.changed().is_none());

        std::fs::write(&key, "junk").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&key)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(10))
            .unwrap();
        assert!(files.changed().is_some());
        assert!(files.reload().is_err());
        assert!(files.changed().is_some(), "a failed reload is tried again");
        assert_eq!(leaf(), first);

        write(&dir, "two.example");
        files.reload().unwrap();
        assert_ne!(leaf(), first);
        assert!(files.changed().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
