//! `DELETE /v0/session` (vv-04 §7.3).

use http::StatusCode;
use tokio::time::Instant;

use crate::api::{Api, ApiError, ApiRequest, ApiResponse};

impl Api {
    pub(crate) fn logout(&self, req: &ApiRequest, now: Instant) -> Result<ApiResponse, ApiError> {
        let session = self.session(req)?;
        if self.registry.logout(&session, now) {
            Ok(ApiResponse::empty(StatusCode::NO_CONTENT))
        } else {
            Err(ApiError::SessionInvalid)
        }
    }
}
