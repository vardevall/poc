//! HTTP/3 over QUIC (vv-04 §2.2), on the same port and with the same API as TCP.
//!
//! The QUIC handshake is TLS 1.3 with the same certificate choice as over TCP (vv-04 §2.3), so
//! nodes pin the switch key and bind registrations to the exporter exactly as over TCP. Requests
//! go to [`Api::handle`].

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use http::{Request, Response};
use http_body_util::BodyExt;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use vardevall_switch_proto::api::EXPORTER_LABEL;

use super::body::ResponseBody;
use super::guard::{ConnLimits, ConnPermit};
use crate::api::{Api, ApiError, ApiRequest, ApiResponse, ConnInfo};
use crate::config::Timeouts;

/// Most concurrent request streams per connection.
const STREAMS: u32 = 32;
/// Largest header section accepted.
const MAX_HEADER_BYTES: u64 = 16 * 1024;

/// A QUIC endpoint on `socket` with the switch's TLS configuration.
pub(super) fn endpoint(
    socket: UdpSocket,
    crypto: Arc<dyn quinn::crypto::ServerConfig>,
    api: &Api,
) -> std::io::Result<quinn::Endpoint> {
    let mut config = quinn::ServerConfig::with_crypto(crypto);
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(STREAMS.into());
    transport.max_concurrent_uni_streams(8u32.into());
    if let Ok(idle) = api.config().timeouts.idle.try_into() {
        transport.max_idle_timeout(Some(idle));
    }
    config.transport_config(Arc::new(transport));
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket.into_std()?,
        Arc::new(quinn::TokioRuntime),
    )
}

pub(super) async fn accept_loop(endpoint: quinn::Endpoint, api: Arc<Api>, limits: Arc<ConnLimits>) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { return };
                let Some(permit) = limits.acquire(Some(incoming.remote_address().ip())) else {
                    incoming.refuse();
                    continue;
                };
                tasks.spawn(serve(incoming, api.clone(), permit));
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

async fn serve(incoming: quinn::Incoming, api: Arc<Api>, _permit: ConnPermit) {
    let timeouts = api.config().timeouts.clone();
    let peer: SocketAddr = incoming.remote_address();
    let Ok(Ok(conn)) = tokio::time::timeout(timeouts.tls_handshake, async {
        incoming.accept().map_err(|_| ())?.await.map_err(|_| ())
    })
    .await
    else {
        return;
    };
    let mut exporter = [0u8; 32];
    let exporter = conn
        .export_keying_material(&mut exporter, EXPORTER_LABEL.as_bytes(), &[])
        .ok()
        .map(|()| exporter);
    let info = Arc::new(ConnInfo {
        peer: peer.ip().to_canonical(),
        exporter,
    });
    let Ok(mut h3) = h3::server::builder()
        .max_field_section_size(MAX_HEADER_BYTES)
        .build(h3_quinn::Connection::new(conn))
        .await
    else {
        return;
    };
    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            accepted = h3.accept() => {
                let Ok(Some(resolver)) = accepted else { break };
                let (api, info, timeouts) = (api.clone(), info.clone(), timeouts.clone());
                requests.spawn(async move {
                    if let Ok((req, stream)) = resolver.resolve_request().await {
                        let _ = respond(&api, &info, &timeouts, req, stream).await;
                    }
                });
            }
            Some(_) = requests.join_next(), if !requests.is_empty() => {}
        }
    }
}

async fn respond<S>(
    api: &Api,
    conn: &ConnInfo,
    timeouts: &Timeouts,
    req: Request<()>,
    mut stream: RequestStream<S, Bytes>,
) -> Result<(), h3::error::StreamError>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let (parts, ()) = req.into_parts();
    let limit = api.body_limit(parts.uri.path());
    let read = async {
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.map_err(|_| ApiError::Malformed)? {
            if body.len() + chunk.remaining() > limit {
                return Err(ApiError::TooLarge);
            }
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        Ok(Bytes::from(body))
    };
    let response = match tokio::time::timeout(timeouts.request_body, read).await {
        Ok(Ok(body)) => api.handle(
            conn,
            ApiRequest {
                method: parts.method,
                uri: parts.uri,
                headers: parts.headers,
                body,
            },
        ),
        Ok(Err(e)) => e.into_response(),
        Err(_) => ApiError::Timeout.into_response(),
    };
    write(&mut stream, response).await
}

async fn write<S>(
    stream: &mut RequestStream<S, Bytes>,
    r: ApiResponse,
) -> Result<(), h3::error::StreamError>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let mut head = Response::new(());
    *head.status_mut() = r.status;
    *head.headers_mut() = r.headers;
    stream.send_response(head).await?;
    let mut body = ResponseBody::from(r.body);
    while let Some(Ok(frame)) = body.frame().await {
        if let Ok(data) = frame.into_data() {
            stream.send_data(data).await?;
        }
    }
    stream.finish().await
}
