//! Transport-neutral request and response types.

use std::net::IpAddr;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};

use crate::registry::EventStream;

/// What the transport knows about the connection a request arrived on.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    /// The client's address.
    pub peer: IpAddr,
    /// The TLS exporter of the registration binding, if the transport can read it (vv-04 §4.1).
    pub exporter: Option<[u8; 32]>,
}

/// A request with its body already read.
#[derive(Debug, Clone)]
pub struct ApiRequest {
    /// The method.
    pub method: Method,
    /// The request target.
    pub uri: Uri,
    /// The headers.
    pub headers: HeaderMap,
    /// The body, at most [`crate::api::Api::body_limit`] bytes.
    pub body: Bytes,
}

/// The body of a response.
pub enum ApiBody {
    /// No body.
    Empty,
    /// A complete body.
    Bytes(Bytes),
    /// A Server-Sent Events stream (vv-04 §7.1).
    Events(EventStream),
}

/// A response to write.
pub struct ApiResponse {
    /// The status.
    pub status: StatusCode,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: ApiBody,
}

impl ApiResponse {
    pub(crate) fn new(status: StatusCode, body: ApiBody, content_type: &'static str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        ApiResponse {
            status,
            headers,
            body,
        }
    }

    pub(crate) fn empty(status: StatusCode) -> Self {
        let mut r = ApiResponse::new(status, ApiBody::Empty, "application/json");
        r.headers.remove(header::CONTENT_TYPE);
        r
    }

    pub(crate) fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }
}
