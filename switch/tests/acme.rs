//! ACME with TLS-ALPN-01 on the HTTPS port (vv-04 §2.3), against Pebble, the ACME CA of Let's
//! Encrypt for tests. Ignored unless `VV_PEBBLE` names a pebble binary
//! (`go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest`).

mod common;

use std::future::pending;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use vardevall_switch::config::{Acme, Certificate, Config};
use vardevall_switch::{Sockets, Switch, key};

struct Pebble(Child);

impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Accepts any certificate and keeps the one presented.
#[derive(Debug)]
struct Collect(std::sync::Mutex<Vec<u8>>);

impl ServerCertVerifier for Collect {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.0.lock().unwrap() = end_entity.to_vec();
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn presented(addr: SocketAddr) -> Option<Vec<u8>> {
    let verifier = Arc::new(Collect(Default::default()));
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = TcpStream::connect(addr).await.ok()?;
    TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .ok()?;
    let der = verifier.0.lock().unwrap().clone();
    Some(der)
}

#[tokio::test]
#[ignore = "needs VV_PEBBLE"]
async fn the_switch_obtains_and_serves_a_certificate_by_tls_alpn_01() {
    let Some(pebble) = std::env::var_os("VV_PEBBLE") else {
        panic!("set VV_PEBBLE to a pebble binary");
    };
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).unwrap();
    let dir = std::env::temp_dir().join(format!("vv-pebble-{}", u64::from_be_bytes(random)));
    std::fs::create_dir_all(&dir).unwrap();

    let ca = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(dir.join("ca.pem"), ca.cert.pem()).unwrap();
    std::fs::write(dir.join("ca.key"), ca.key_pair.serialize_pem()).unwrap();

    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let (api, mgmt) = (free_port(), free_port());
    std::fs::write(
        dir.join("pebble.json"),
        format!(
            r#"{{"pebble":{{"listenAddress":"127.0.0.1:{api}","managementListenAddress":"127.0.0.1:{mgmt}",
            "certificate":"{d}/ca.pem","privateKey":"{d}/ca.key","httpPort":{h},"tlsPort":{p},
            "ocspResponderURL":"","externalAccountBindingRequired":false}}}}"#,
            d = dir.display(),
            h = free_port(),
            p = addr.port(),
        ),
    )
    .unwrap();
    let _pebble = Pebble(
        Command::new(pebble)
            .arg("-config")
            .arg(dir.join("pebble.json"))
            .env("PEBBLE_VA_NOSLEEP", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let mut config = Config::new(vec![addr], "unused".into());
    config.certificate = Some(Certificate::Acme(Acme {
        domain: "localhost".into(),
        contact: Some("mailto:test@example.org".into()),
        directory: Some(format!("https://localhost:{api}/dir")),
        cache_dir: None,
        ca_file: Some(dir.join("ca.pem")),
    }));
    let switch = Arc::new(Switch::new(&config, key::generate().unwrap()).unwrap());
    let task = tokio::spawn(async move {
        let sockets = Sockets {
            tcp: vec![tcp],
            ..Default::default()
        };
        switch.run_with(sockets, pending()).await;
    });

    let start = Instant::now();
    let issued = loop {
        if let Some(der) = presented(addr).await
            && der.windows(6).any(|w| w == b"Pebble")
        {
            break der;
        }
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "no certificate from Pebble"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert!(issued.windows(9).any(|w| w == b"localhost"));
    task.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
