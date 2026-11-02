//! Problem Details responses (vv-04 §3.2).

use http::{HeaderValue, StatusCode, header};

use super::types::{ApiBody, ApiResponse};
use crate::limits::Exceeded;
use crate::registry::{ForwardError, OpenError, SessionInvalid};

/// A request that is refused, with the response it earns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// `malformed`.
    Malformed,
    /// `token-required`.
    TokenRequired,
    /// `session-invalid`.
    SessionInvalid,
    /// `invalid-proof`.
    InvalidProof,
    /// `not-online`.
    NotOnline,
    /// `too-large`.
    TooLarge,
    /// `rate-limited`, with `Retry-After`.
    RateLimited(Exceeded),
    /// An unknown path.
    NotFound,
    /// A known path with another method; the allowed method.
    MethodNotAllowed(&'static str),
    /// A request that took too long to arrive.
    Timeout,
}

impl ApiError {
    /// The status, error code and title.
    pub fn parts(&self) -> (StatusCode, &'static str, &'static str) {
        match self {
            ApiError::Malformed => (StatusCode::BAD_REQUEST, "malformed", "Malformed request"),
            ApiError::TokenRequired => (
                StatusCode::UNAUTHORIZED,
                "token-required",
                "A valid operator token is required",
            ),
            ApiError::SessionInvalid => (
                StatusCode::UNAUTHORIZED,
                "session-invalid",
                "The session is unknown or expired",
            ),
            ApiError::InvalidProof => (
                StatusCode::FORBIDDEN,
                "invalid-proof",
                "Verification failed",
            ),
            ApiError::NotOnline => (StatusCode::NOT_FOUND, "not-online", "Not online"),
            ApiError::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too-large", "Too large"),
            ApiError::RateLimited(_) => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate-limited",
                "A limit was hit",
            ),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not-found", "No such endpoint"),
            ApiError::MethodNotAllowed(_) => (
                StatusCode::METHOD_NOT_ALLOWED,
                "method-not-allowed",
                "Method not allowed",
            ),
            ApiError::Timeout => (
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                "The request took too long",
            ),
        }
    }

    /// The `application/problem+json` response (RFC 9457).
    pub fn into_response(self) -> ApiResponse {
        let (status, code, title) = self.parts();
        let body = format!(
            "{{\"type\":\"urn:vardevall:error:{code}\",\"title\":\"{title}\",\"status\":{}}}",
            status.as_u16()
        );
        let mut r = ApiResponse::new(
            status,
            ApiBody::Bytes(body.into()),
            "application/problem+json",
        );
        match self {
            ApiError::RateLimited(e) => {
                r = r.with_header(header::RETRY_AFTER, HeaderValue::from(e.retry_after));
            }
            ApiError::MethodNotAllowed(m) => {
                r = r.with_header(header::ALLOW, HeaderValue::from_static(m));
            }
            _ => {}
        }
        r
    }
}

impl From<SessionInvalid> for ApiError {
    fn from(_: SessionInvalid) -> Self {
        ApiError::SessionInvalid
    }
}

impl From<Exceeded> for ApiError {
    fn from(e: Exceeded) -> Self {
        ApiError::RateLimited(e)
    }
}

impl From<OpenError> for ApiError {
    fn from(e: OpenError) -> Self {
        match e {
            OpenError::Session => ApiError::SessionInvalid,
            OpenError::Full => ApiError::RateLimited(Exceeded { retry_after: 30 }),
        }
    }
}

impl From<ForwardError> for ApiError {
    fn from(e: ForwardError) -> Self {
        match e {
            ForwardError::Session => ApiError::SessionInvalid,
            ForwardError::NotOnline => ApiError::NotOnline,
            ForwardError::Limit(e) => ApiError::RateLimited(e),
        }
    }
}
