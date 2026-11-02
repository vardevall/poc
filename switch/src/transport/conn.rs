//! Accepting connections and running HTTP over them.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::tls::Tls;
use http::header::{ALT_SVC, HeaderValue};
use http::{HeaderName, Request, Response};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use ipnet::IpNet;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;
use vardevall_switch_proto::api::EXPORTER_LABEL;

use super::body::ResponseBody;
use super::guard::{ConnLimits, ConnPermit};
use super::idle::IdleTimeout;
use super::proxy;
use crate::api::{Api, ApiError, ApiRequest, ConnInfo};
use crate::config::{Config, Timeouts};

/// The proxies the switch sits behind and what it believes from them (vv-04 §2.5).
pub(super) struct Edge {
    proxy_protocol: Vec<IpNet>,
    header: Option<(HeaderName, Vec<IpNet>)>,
}

impl Edge {
    pub(super) fn new(config: &Config) -> Edge {
        Edge {
            proxy_protocol: config.proxy_protocol.clone(),
            header: config
                .forwarded_header
                .as_ref()
                .map(|h| (h.name.clone(), h.from.clone())),
        }
    }

    fn sends_proxy_protocol(&self, peer: IpAddr) -> bool {
        self.proxy_protocol.iter().any(|n| n.contains(&peer))
    }

    fn header_from(&self, peer: IpAddr) -> Option<&HeaderName> {
        let (name, from) = self.header.as_ref()?;
        from.iter().any(|n| n.contains(&peer)).then_some(name)
    }

    fn is_proxy(&self, peer: IpAddr) -> bool {
        self.sends_proxy_protocol(peer) || self.header_from(peer).is_some()
    }
}

/// `Alt-Svc` [RFC 7838]: HTTP/3 on the UDP port, for clients that do not try QUIC on their own.
/// Native clients ignore it; browsers learn of HTTP/3 from it.
pub(super) fn alt_svc(port: u16) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!("h3=\":{port}\"; ma=86400")).ok()
}

/// Most concurrent HTTP/2 streams per connection.
const H2_STREAMS: u32 = 32;
/// Largest header section accepted.
const MAX_HEADER_BYTES: u32 = 16 * 1024;
/// Pause after a failed `accept`, so that running out of descriptors does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Accepts connections on `listener`: TLS if `acceptor` is given, otherwise plain HTTP for a
/// tunnel daemon on loopback (vv-04 §2.5).
pub(super) async fn accept_loop(
    listener: TcpListener,
    acceptor: Option<Tls>,
    api: Arc<Api>,
    limits: Arc<ConnLimits>,
    edge: Arc<Edge>,
    alt_svc: Option<HeaderValue>,
) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((tcp, peer)) => {
                    let ip = (!edge.is_proxy(peer.ip().to_canonical())).then_some(peer.ip());
                    let Some(permit) = limits.acquire(ip) else {
                        continue;
                    };
                    tasks.spawn(serve(
                        tcp,
                        peer,
                        acceptor.clone(),
                        api.clone(),
                        edge.clone(),
                        alt_svc.clone(),
                        permit,
                    ));
                }
                Err(_) => tokio::time::sleep(ACCEPT_BACKOFF).await,
            },
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

fn exporter(tls: &TlsStream<TcpStream>) -> Option<[u8; 32]> {
    tls.get_ref()
        .1
        .export_keying_material([0u8; 32], EXPORTER_LABEL.as_bytes(), None)
        .ok()
}

async fn serve(
    mut tcp: TcpStream,
    peer: SocketAddr,
    acceptor: Option<Tls>,
    api: Arc<Api>,
    edge: Arc<Edge>,
    alt_svc: Option<HeaderValue>,
    mut permit: ConnPermit,
) {
    let timeouts = api.config().timeouts.clone();
    let _ = tcp.set_nodelay(true);
    let mut client = peer;
    if edge.sends_proxy_protocol(peer.ip().to_canonical()) {
        match tokio::time::timeout(timeouts.tls_handshake, proxy::read_v2(&mut tcp)).await {
            Ok(Ok(Some(address))) => client = address,
            Ok(Ok(None)) => {}
            _ => return,
        }
        if !permit.attach(client.ip()) {
            return;
        }
    }
    let trusted = edge.header_from(peer.ip().to_canonical()).cloned();
    let Some(acceptor) = acceptor else {
        let conn = ConnInfo {
            peer: client.ip().to_canonical(),
            exporter: None,
        };
        http(tcp, conn, trusted, api, alt_svc).await;
        return;
    };
    let Ok(Ok(tls)) = tokio::time::timeout(timeouts.tls_handshake, acceptor.accept(tcp)).await
    else {
        return;
    };
    if tls.get_ref().1.alpn_protocol() == Some(crate::tls::ALPN_ACME) {
        return;
    }
    if tls.get_ref().1.alpn_protocol() == Some(crate::tls::ALPN_TURN) {
        #[cfg(feature = "stun-turn")]
        if let Some(turn) = api.turn_server() {
            crate::turn::serve_stream(turn.clone(), tls, client).await;
        }
        return;
    }
    let conn = ConnInfo {
        peer: client.ip().to_canonical(),
        exporter: exporter(&tls),
    };
    http(tls, conn, trusted, api, alt_svc).await;
}

async fn http<T>(
    io: T,
    conn: ConnInfo,
    trusted: Option<HeaderName>,
    api: Arc<Api>,
    alt_svc: Option<HeaderValue>,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let timeouts = api.config().timeouts.clone();
    let idle = timeouts.idle;
    let conn = Arc::new(conn);
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(timeouts.request_header)
        .max_buf_size(MAX_HEADER_BYTES as usize)
        .keep_alive(true);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(H2_STREAMS)
        .max_header_list_size(MAX_HEADER_BYTES)
        .keep_alive_interval(timeouts.idle)
        .keep_alive_timeout(timeouts.request_header);
    let service = service_fn(move |req: Request<Incoming>| {
        let (api, timeouts) = (api.clone(), timeouts.clone());
        let conn = match trusted
            .as_ref()
            .and_then(|name| proxy::client_address(name, req.headers()))
        {
            Some(peer) => Arc::new(ConnInfo {
                peer,
                exporter: conn.exporter,
            }),
            None => conn.clone(),
        };
        let alt_svc = alt_svc.clone();
        async move {
            let mut response = respond(&api, &conn, &timeouts, req).await;
            if let Some(v) = alt_svc {
                response.headers_mut().insert(ALT_SVC, v);
            }
            Ok::<_, Infallible>(response)
        }
    });
    let _ = builder
        .serve_connection(TokioIo::new(IdleTimeout::new(io, idle)), service)
        .await;
}

async fn respond(
    api: &Api,
    conn: &ConnInfo,
    timeouts: &Timeouts,
    req: Request<Incoming>,
) -> Response<ResponseBody> {
    let (parts, body) = req.into_parts();
    let limit = api.body_limit(parts.uri.path());
    let read = async { Limited::new(body, limit).collect().await };
    let body = match tokio::time::timeout(timeouts.request_body, read).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(e))
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some() =>
        {
            return finish(ApiError::TooLarge.into_response());
        }
        Ok(Err(_)) => return finish(ApiError::Malformed.into_response()),
        Err(_) => return finish(ApiError::Timeout.into_response()),
    };
    let request = ApiRequest {
        method: parts.method,
        uri: parts.uri,
        headers: parts.headers,
        body,
    };
    finish(api.handle(conn, request))
}

fn finish(r: crate::api::ApiResponse) -> Response<ResponseBody> {
    let mut response = Response::new(ResponseBody::from(r.body));
    *response.status_mut() = r.status;
    *response.headers_mut() = r.headers;
    response
}
