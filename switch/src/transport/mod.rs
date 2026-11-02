//! Carrying the API over TLS with HTTP/2 and HTTP/1.1, and over QUIC with HTTP/3 (vv-04 §2.2,
//! §2.3).
//!
//! Another transport (HTTP/3, WebTransport) builds an [`crate::api::ApiRequest`] and a
//! [`crate::api::ConnInfo`] and calls [`crate::api::Api::handle`]; it needs nothing from this
//! module.

mod body;
mod conn;
mod guard;
mod h3;
mod idle;
mod proxy;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::Instant;
use vardevall_proto::keys::SwitchSecret;

use self::guard::ConnLimits;
use crate::api::{Api, SetupError};
use crate::config::Config;
use crate::tls::{self, Tls, TlsError};

/// How often the registry and limiters are swept.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// A switch could not be created.
#[derive(Debug, Error)]
pub enum SwitchError {
    /// The key could not be used for TLS.
    #[error(transparent)]
    Tls(#[from] TlsError),
    /// The switch could not be set up.
    #[error(transparent)]
    Setup(#[from] SetupError),
}

/// The sockets a switch serves, bound by the caller.
#[derive(Default)]
pub struct Sockets {
    /// TCP listeners for HTTPS.
    pub tcp: Vec<TcpListener>,
    /// TCP listeners for plain HTTP on loopback, for a tunnel daemon that terminates TLS
    /// (`plain_listen`, vv-04 §2.5).
    pub plain: Vec<TcpListener>,
    /// UDP sockets for HTTP/3, bound to the same addresses as the TCP listeners (vv-04 §2.2).
    pub h3: Vec<UdpSocket>,
    /// UDP sockets for the embedded STUN server (`stun.listen`).
    #[cfg(feature = "stun-turn")]
    pub stun: Vec<UdpSocket>,
    /// UDP sockets for the embedded TURN server (`turn.server.listen`).
    #[cfg(feature = "stun-turn")]
    pub turn: Vec<UdpSocket>,
}

/// A switch: the API and its TCP transport.
pub struct Switch {
    api: Arc<Api>,
    tls: Tls,
    limits: Arc<ConnLimits>,
    edge: Arc<conn::Edge>,
}

impl Switch {
    /// A switch with the key `key` and the settings of `config`.
    pub fn new(config: &Config, key: SwitchSecret) -> Result<Switch, SwitchError> {
        #[allow(unused_mut)]
        let mut alpn: Vec<&[u8]> = tls::ALPN.to_vec();
        #[cfg(feature = "stun-turn")]
        if config
            .turn
            .as_ref()
            .and_then(|t| t.server.as_ref())
            .is_some_and(|s| s.tls)
        {
            alpn.push(tls::ALPN_TURN);
        }
        let tls = Tls::new(&key, config.certificate.as_ref(), &alpn)?;
        let api = Arc::new(Api::new(config, key)?);
        Ok(Switch {
            limits: Arc::new(ConnLimits::new(
                config.limits.max_connections,
                config.limits.max_connections_per_ip,
            )),
            edge: Arc::new(conn::Edge::new(config)),
            api,
            tls,
        })
    }

    /// The certificate read from PEM files, if the switch uses one; reload it on SIGHUP.
    pub fn file_certificate(&self) -> Option<&Arc<crate::tls::FileCertificate>> {
        self.tls.file_certificate()
    }

    /// The API.
    pub fn api(&self) -> &Arc<Api> {
        &self.api
    }

    /// Serves `listeners` until `shutdown` completes; open connections end with it.
    pub async fn run(&self, listeners: Vec<TcpListener>, shutdown: impl Future<Output = ()>) {
        let sockets = Sockets {
            tcp: listeners,
            ..Default::default()
        };
        self.run_with(sockets, shutdown).await;
    }

    /// Serves `sockets` until `shutdown` completes; open connections end with it.
    pub async fn run_with(&self, sockets: Sockets, shutdown: impl Future<Output = ()>) {
        let mut tasks = JoinSet::new();
        let api = self.api.clone();
        tasks.spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                tick.tick().await;
                api.sweep(Instant::now());
            }
        });
        if let Some(order) = self.tls.acme_task() {
            tasks.spawn(order);
        }
        if let Some(files) = self.tls.file_certificate() {
            tasks.spawn(files.clone().watch());
        }
        if let Some(every) = self.api.config().status_interval {
            let api = self.api.clone();
            tasks.spawn(async move {
                let mut tick = tokio::time::interval_at(Instant::now() + every, every);
                loop {
                    tick.tick().await;
                    eprintln!("{}", api.status_line());
                }
            });
        }
        #[cfg(feature = "stun-turn")]
        {
            if let Some(turn) = self.api.turn_server() {
                for socket in sockets.turn {
                    tasks.spawn(crate::turn::serve_udp(turn.clone(), socket));
                }
            }
            for socket in sockets.stun {
                tasks.spawn(crate::stun::serve(socket, self.api.clone()));
            }
        }
        let alt_svc = sockets
            .h3
            .first()
            .and_then(|s| s.local_addr().ok())
            .and_then(|a| conn::alt_svc(a.port()));
        for socket in sockets.h3 {
            match h3::endpoint(socket, self.tls.quic(), &self.api) {
                Ok(endpoint) => {
                    tasks.spawn(h3::accept_loop(
                        endpoint,
                        self.api.clone(),
                        self.limits.clone(),
                    ));
                }
                Err(e) => eprintln!("vv-switch: HTTP/3 disabled on one socket: {e}"),
            }
        }
        for listener in sockets.tcp {
            tasks.spawn(conn::accept_loop(
                listener,
                Some(self.tls.clone()),
                self.api.clone(),
                self.limits.clone(),
                self.edge.clone(),
                alt_svc.clone(),
            ));
        }
        for listener in sockets.plain {
            tasks.spawn(conn::accept_loop(
                listener,
                None,
                self.api.clone(),
                self.limits.clone(),
                self.edge.clone(),
                None,
            ));
        }
        shutdown.await;
        tasks.shutdown().await;
    }
}
