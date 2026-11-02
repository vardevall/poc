//! `GET /v0/events` (vv-04 §7.1).

use http::{HeaderValue, StatusCode};

use crate::api::{Api, ApiBody, ApiError, ApiRequest, ApiResponse};

impl Api {
    pub(crate) fn events(&self, req: &ApiRequest) -> Result<ApiResponse, ApiError> {
        let session = self.session(req)?;
        let stream = self
            .registry
            .open_stream(&session)?
            .with_keepalive(self.config.timeouts.keepalive);
        Ok(
            ApiResponse::new(StatusCode::OK, ApiBody::Events(stream), "text/event-stream")
                .with_header(
                    http::HeaderName::from_static("x-accel-buffering"),
                    HeaderValue::from_static("no"),
                ),
        )
    }
}
