//! A small HTTP client for the switch API over one connection: HTTP/3 with a fallback to TCP
//! (HTTP/2, then HTTP/1.1 by ALPN) as vv-04 §2.2 prescribes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use vardevall_switch_proto::api::EXPORTER_LABEL;

use crate::net::lookup;
use crate::net::mark::SocketMark;
use crate::net::socket::client_udp;
use crate::net::tcp::connect_marked;

/// Time to connect TCP.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// Time for the TLS handshake and the HTTP handshake together.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time for one request and its response body.
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Time the QUIC handshake has before TCP is tried as well (vv-04 §2.2).
pub(super) const QUIC_HEAD_START: Duration = Duration::from_millis(300);
/// Time QUIC may still take after TCP failed.
const QUIC_AFTER_TCP: Duration = Duration::from_secs(2);
/// Largest response body read whole.
const MAX_BODY: usize = 256 * 1024;
/// Interval of HTTP/2 pings and QUIC keep-alives on an idle connection.
const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// QUIC connections idle for this long are closed.
const QUIC_IDLE: Duration = Duration::from_secs(60);
/// The TLS alerts `bad_certificate` to `access_denied`, which a failed certificate check raises,
/// as QUIC transport error codes.
const QUIC_CERTIFICATE_ALERTS: std::ops::RangeInclusive<u64> = 0x100 + 42..=0x100 + 49;

/// A connection could not be made or broke.
#[derive(Debug)]
pub(super) enum HttpError {
    /// The switch could not be reached.
    Connect,
    /// The switch presented another key, or a certificate the Web PKI refuses (vv-04 §2.3).
    KeyMismatch,
    /// The connection failed or timed out.
    Io,
    /// The response is larger than this client reads.
    TooLarge,
}

/// Which protocol carried a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    /// HTTP/3 over QUIC.
    Http3,
    /// HTTP/2 over TLS.
    Http2,
    /// HTTP/1.1 over TLS.
    Http1,
}

/// What to connect to.
#[derive(Clone)]
pub(super) struct Target {
    /// DNS name or IP literal.
    pub host: String,
    /// The port, for TCP and for UDP.
    pub port: u16,
    /// The connector for TCP, which authenticates the switch.
    pub tls: TlsConnector,
    /// The configuration for QUIC, which authenticates the switch the same way.
    pub quic: quinn::ClientConfig,
    /// The mark of the sockets connecting to the switch.
    pub mark: SocketMark,
}

type H3Send = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3Stream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

enum Sender {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
    H3 {
        send: H3Send,
        _conn: quinn::Connection,
        _endpoint: quinn::Endpoint,
    },
}

/// One HTTP connection.
pub(super) struct Conn {
    sender: Sender,
    authority: String,
}

/// A complete response.
pub(super) struct Reply {
    /// The status.
    pub status: StatusCode,
    /// The headers.
    pub headers: HeaderMap,
    /// The body, at most 256 KiB.
    pub body: Bytes,
}

enum Frames {
    Hyper(Incoming),
    H3(Box<H3Stream>),
}

/// A response whose body is read piece by piece.
pub(super) struct Streaming {
    /// The status.
    pub status: StatusCode,
    /// The headers.
    pub headers: HeaderMap,
    body: Frames,
}

impl Streaming {
    /// The next piece of the body; `None` when it ends or the connection breaks.
    pub(super) async fn chunk(&mut self) -> Option<Bytes> {
        match &mut self.body {
            Frames::Hyper(b) => loop {
                match b.frame().await? {
                    Ok(f) => {
                        if let Ok(d) = f.into_data() {
                            return Some(d);
                        }
                    }
                    Err(_) => return None,
                }
            },
            Frames::H3(s) => {
                let mut buf = s.recv_data().await.ok()??;
                Some(buf.copy_to_bytes(buf.remaining()))
            }
        }
    }
}

async fn resolve(target: &Target) -> Result<Vec<SocketAddr>, HttpError> {
    let addrs: Vec<SocketAddr> = tokio::time::timeout(
        CONNECT_TIMEOUT,
        lookup::host(target.host.as_str(), target.port, target.mark, &[]),
    )
    .await
    .map_err(|_| HttpError::Connect)?
    .map_err(|_| HttpError::Connect)?;
    let mut ordered: Vec<SocketAddr> = addrs.iter().copied().filter(SocketAddr::is_ipv6).collect();
    ordered.extend(addrs.iter().copied().filter(SocketAddr::is_ipv4));
    if ordered.is_empty() {
        return Err(HttpError::Connect);
    }
    Ok(ordered)
}

async fn tcp(addrs: &[SocketAddr], mark: SocketMark) -> Result<TcpStream, HttpError> {
    for addr in addrs.iter().take(4) {
        if let Ok(Ok(s)) = tokio::time::timeout(CONNECT_TIMEOUT, connect_marked(*addr, mark)).await
        {
            let _ = s.set_nodelay(true);
            return Ok(s);
        }
    }
    Err(HttpError::Connect)
}

/// The name TLS verifies and, for a DNS name, sends as the SNI (vv-04 §2.3); an IP literal has
/// no SNI to send.
fn server_name(target: &Target) -> Result<ServerName<'static>, HttpError> {
    ServerName::try_from(target.host.clone()).map_err(|_| HttpError::Connect)
}

fn authority(target: &Target) -> String {
    if target.host.contains(':') {
        format!("[{}]:{}", target.host, target.port)
    } else {
        format!("{}:{}", target.host, target.port)
    }
}

impl Conn {
    /// Connects, authenticates the switch key, and returns the connection with the registration
    /// exporter of this TLS session (vv-04 §4.1).
    ///
    /// QUIC goes first; if its handshake has not completed after [`QUIC_HEAD_START`], TCP starts
    /// too and the first connection to complete is kept (vv-04 §2.2).
    pub(super) async fn connect(target: &Target) -> Result<(Conn, [u8; 32], Transport), HttpError> {
        let addrs = resolve(target).await?;
        let mut quic = Box::pin(Self::connect_quic(target, &addrs));
        match tokio::time::timeout(QUIC_HEAD_START, &mut quic).await {
            Ok(Ok(c)) => return Ok(c),
            Ok(Err(HttpError::KeyMismatch)) => return Err(HttpError::KeyMismatch),
            Ok(Err(_)) => return Self::connect_tcp(target, &addrs).await,
            Err(_) => {}
        }
        let mut tcp = Box::pin(Self::connect_tcp(target, &addrs));
        tokio::select! {
            q = &mut quic => match q {
                Ok(c) => Ok(c),
                Err(HttpError::KeyMismatch) => Err(HttpError::KeyMismatch),
                Err(_) => tcp.await,
            },
            t = &mut tcp => match t {
                Ok(c) => Ok(c),
                Err(HttpError::KeyMismatch) => Err(HttpError::KeyMismatch),
                Err(e) => match tokio::time::timeout(QUIC_AFTER_TCP, quic).await {
                    Ok(Ok(c)) => Ok(c),
                    _ => Err(e),
                },
            },
        }
    }

    /// Connects over TCP only, for a second connection next to an HTTP/1.1 one.
    pub(super) async fn connect_tcp_only(
        target: &Target,
    ) -> Result<(Conn, [u8; 32], Transport), HttpError> {
        let addrs = resolve(target).await?;
        Self::connect_tcp(target, &addrs).await
    }

    async fn connect_quic(
        target: &Target,
        addrs: &[SocketAddr],
    ) -> Result<(Conn, [u8; 32], Transport), HttpError> {
        let addr = *addrs.first().ok_or(HttpError::Connect)?;
        let socket = client_udp(addr, target.mark).map_err(|_| HttpError::Connect)?;
        let runtime = quinn::default_runtime().ok_or(HttpError::Connect)?;
        let mut endpoint =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
                .map_err(|_| HttpError::Connect)?;
        endpoint.set_default_client_config(target.quic.clone());
        let name = server_name(target)?.to_str().into_owned();
        let connecting = endpoint
            .connect(addr, &name)
            .map_err(|_| HttpError::Connect)?;
        let conn = match tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await {
            Ok(Ok(c)) => c,
            Ok(Err(quinn::ConnectionError::TransportError(e)))
                if QUIC_CERTIFICATE_ALERTS.contains(&u64::from(e.code)) =>
            {
                return Err(HttpError::KeyMismatch);
            }
            _ => return Err(HttpError::Io),
        };
        let mut exporter = [0u8; 32];
        conn.export_keying_material(&mut exporter, EXPORTER_LABEL.as_bytes(), &[])
            .map_err(|_| HttpError::Io)?;
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(|_| HttpError::Io)?;
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        Ok((
            Conn {
                sender: Sender::H3 {
                    send,
                    _conn: conn,
                    _endpoint: endpoint,
                },
                authority: authority(target),
            },
            exporter,
            Transport::Http3,
        ))
    }

    async fn connect_tcp(
        target: &Target,
        addrs: &[SocketAddr],
    ) -> Result<(Conn, [u8; 32], Transport), HttpError> {
        let stream = tcp(addrs, target.mark).await?;
        let name = server_name(target)?;
        let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, target.tls.connect(name, stream))
            .await
        {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) if super::tls::is_key_mismatch(&e) => return Err(HttpError::KeyMismatch),
            _ => return Err(HttpError::Io),
        };
        let (_, session) = tls.get_ref();
        let exporter = session
            .export_keying_material([0u8; 32], EXPORTER_LABEL.as_bytes(), None)
            .map_err(|_| HttpError::Io)?;
        let h2 = session.alpn_protocol() == Some(b"h2");
        let io = TokioIo::new(tls);
        let handshake = async {
            if h2 {
                let (s, c) = http2::Builder::new(TokioExecutor::new())
                    .timer(TokioTimer::new())
                    .keep_alive_interval(KEEP_ALIVE * 2)
                    .keep_alive_timeout(REQUEST_TIMEOUT)
                    .keep_alive_while_idle(true)
                    .handshake(io)
                    .await?;
                tokio::spawn(async move {
                    let _ = c.await;
                });
                Ok::<_, hyper::Error>(Sender::H2(s))
            } else {
                let (s, c) = http1::handshake(io).await?;
                tokio::spawn(async move {
                    let _ = c.await;
                });
                Ok(Sender::H1(s))
            }
        };
        let sender = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
            .await
            .map_err(|_| HttpError::Io)?
            .map_err(|_| HttpError::Io)?;
        let transport = if h2 {
            Transport::Http2
        } else {
            Transport::Http1
        };
        Ok((
            Conn {
                sender,
                authority: authority(target),
            },
            exporter,
            transport,
        ))
    }

    /// Another handle on a multiplexed (HTTP/2 or HTTP/3) connection.
    pub(super) fn share(&self) -> Option<Conn> {
        let sender = match &self.sender {
            Sender::H2(s) => Sender::H2(s.clone()),
            Sender::H3 {
                send,
                _conn,
                _endpoint,
            } => Sender::H3 {
                send: send.clone(),
                _conn: _conn.clone(),
                _endpoint: _endpoint.clone(),
            },
            Sender::H1(_) => return None,
        };
        Some(Conn {
            sender,
            authority: self.authority.clone(),
        })
    }

    fn build(
        &self,
        method: Method,
        path: &str,
        headers: &[(HeaderName, HeaderValue)],
        has_body: bool,
    ) -> Result<http::request::Builder, HttpError> {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("https://{}{path}", self.authority));
        for (k, v) in headers {
            b = b.header(k, v);
        }
        if has_body {
            b = b.header(http::header::CONTENT_TYPE, "application/json");
        }
        Ok(b)
    }

    async fn h3_exchange(
        send: &mut H3Send,
        req: http::request::Builder,
        body: Option<String>,
    ) -> Result<(StatusCode, HeaderMap, H3Stream), HttpError> {
        let req = req.body(()).map_err(|_| HttpError::Io)?;
        let mut stream = send.send_request(req).await.map_err(|_| HttpError::Io)?;
        if let Some(b) = body
            && !b.is_empty()
        {
            stream
                .send_data(Bytes::from(b))
                .await
                .map_err(|_| HttpError::Io)?;
        }
        stream.finish().await.map_err(|_| HttpError::Io)?;
        let resp = stream.recv_response().await.map_err(|_| HttpError::Io)?;
        let (parts, ()) = resp.into_parts();
        Ok((parts.status, parts.headers, stream))
    }

    /// Sends a request and returns the response with its body unread.
    pub(super) async fn open(
        &mut self,
        method: Method,
        path: &str,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<Streaming, HttpError> {
        let b = self.build(method, path, headers, false)?;
        let exchange = async {
            match &mut self.sender {
                Sender::H1(s) => {
                    let req = b.body(Full::new(Bytes::new())).map_err(|_| HttpError::Io)?;
                    let r = s.send_request(req).await.map_err(|_| HttpError::Io)?;
                    let (p, body) = r.into_parts();
                    Ok(Streaming {
                        status: p.status,
                        headers: p.headers,
                        body: Frames::Hyper(body),
                    })
                }
                Sender::H2(s) => {
                    let req = b.body(Full::new(Bytes::new())).map_err(|_| HttpError::Io)?;
                    let r = s.send_request(req).await.map_err(|_| HttpError::Io)?;
                    let (p, body) = r.into_parts();
                    Ok(Streaming {
                        status: p.status,
                        headers: p.headers,
                        body: Frames::Hyper(body),
                    })
                }
                Sender::H3 { send, .. } => {
                    let (status, headers, stream) = Self::h3_exchange(send, b, None).await?;
                    Ok(Streaming {
                        status,
                        headers,
                        body: Frames::H3(Box::new(stream)),
                    })
                }
            }
        };
        tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| HttpError::Io)?
    }

    /// Sends a request and reads the whole response.
    pub(super) async fn call(
        &mut self,
        method: Method,
        path: &str,
        headers: &[(HeaderName, HeaderValue)],
        body: Option<String>,
    ) -> Result<Reply, HttpError> {
        let b = self.build(method, path, headers, body.is_some())?;
        let exchange = async {
            match &mut self.sender {
                Sender::H3 { send, .. } => {
                    let (status, headers, mut stream) = Self::h3_exchange(send, b, body).await?;
                    let mut out = Vec::new();
                    while let Some(mut chunk) =
                        stream.recv_data().await.map_err(|_| HttpError::Io)?
                    {
                        if out.len() + chunk.remaining() > MAX_BODY {
                            return Err(HttpError::TooLarge);
                        }
                        out.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                    }
                    Ok(Reply {
                        status,
                        headers,
                        body: Bytes::from(out),
                    })
                }
                tcp => {
                    let req = b
                        .body(Full::new(Bytes::from(body.unwrap_or_default())))
                        .map_err(|_| HttpError::Io)?;
                    let resp = match tcp {
                        Sender::H1(s) => s.send_request(req).await,
                        Sender::H2(s) => s.send_request(req).await,
                        Sender::H3 { .. } => return Err(HttpError::Io),
                    }
                    .map_err(|_| HttpError::Io)?;
                    let (parts, body) = resp.into_parts();
                    let body = Limited::new(body, MAX_BODY)
                        .collect()
                        .await
                        .map_err(|e| {
                            if e.downcast_ref::<http_body_util::LengthLimitError>()
                                .is_some()
                            {
                                HttpError::TooLarge
                            } else {
                                HttpError::Io
                            }
                        })?
                        .to_bytes();
                    Ok(Reply {
                        status: parts.status,
                        headers: parts.headers,
                        body,
                    })
                }
            }
        };
        tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| HttpError::Io)?
    }
}

/// The QUIC client configuration for a switch authenticated as `auth` says.
pub(super) fn quic_config(
    auth: &crate::config::SwitchAuth,
) -> Result<quinn::ClientConfig, rustls::Error> {
    let tls = super::tls::client_config(auth, &[super::tls::ALPN_H3])?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .map_err(|_| rustls::Error::General("no QUIC cipher suite".into()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    if let Ok(idle) = QUIC_IDLE.try_into() {
        transport.max_idle_timeout(Some(idle));
    }
    config.transport_config(Arc::new(transport));
    Ok(config)
}
