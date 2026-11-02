//! `POST /v0/forward` (vv-04 §6).

use http::StatusCode;
use tokio::time::Instant;
use vardevall_switch_proto::api::parse_forward_request;

use crate::api::{Api, ApiError, ApiRequest, ApiResponse};

impl Api {
    pub(crate) fn forward(&self, req: &ApiRequest, now: Instant) -> Result<ApiResponse, ApiError> {
        let session = self.session(req)?;
        let (net, _) = self.registry.lookup(&session)?;
        let body = parse_forward_request(&req.body).map_err(|_| ApiError::Malformed)?;
        if body.msg.len() > self.config.limits.max_forward_size {
            return Err(ApiError::TooLarge);
        }
        self.limiters.forward(&net, body.msg.len(), now)?;
        self.registry.forward(&session, &body.to, &body.msg, now)?;
        Ok(ApiResponse::empty(StatusCode::ACCEPTED))
    }
}
