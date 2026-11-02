//! SIGHUP makes the switch read its certificate files again (vv-04 §2.5: renewal). This file holds
//! one test so that the signal is only ever raised in a process that handles it.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use vardevall_switch::config::{Certificate, Config};
use vardevall_switch::reload::Reloader;
use vardevall_switch::{Switch, key};

fn hangup() {
    let status = std::process::Command::new("kill")
        .args(["-HUP", &std::process::id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

fn write_certificate(dir: &std::path::Path) -> rustls::RootCertStore {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key_pair.serialize_pem()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    roots
}

async fn accepts(addr: std::net::SocketAddr, roots: rustls::RootCertStore) -> bool {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .is_ok()
}

#[tokio::test]
async fn sighup_reloads_the_certificate_files() {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("vv-switch-hup-cert-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let old = write_certificate(&dir);

    let mut config = Config::new(vec!["127.0.0.1:0".parse().unwrap()], "unused".into());
    config.certificate = Some(Certificate::Files {
        cert_file: dir.join("cert.pem"),
        key_file: dir.join("key.pem"),
        names: vec!["localhost".to_owned()],
    });
    let switch = Arc::new(Switch::new(&config, key::generate().unwrap()).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let running = switch.clone();
    let serving = tokio::spawn(async move {
        running.run(vec![listener], std::future::pending()).await;
    });
    let reloader = Reloader::new(switch.api().clone(), dir.join("switch.toml"))
        .unwrap()
        .with_certificate(switch.file_certificate().cloned());
    let reloading = tokio::spawn(reloader.run());
    assert!(accepts(addr, old.clone()).await);

    let new = write_certificate(&dir);
    hangup();
    for _ in 0..100 {
        if accepts(addr, new.clone()).await {
            assert!(!accepts(addr, old).await);
            serving.abort();
            reloading.abort();
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the new certificate was not served after SIGHUP");
}
