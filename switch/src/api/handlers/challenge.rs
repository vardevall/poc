//! `GET /v0/challenge` (vv-04 §4.2).

use http::StatusCode;
use tokio::time::Instant;
use vardevall_proto::keys::base32;
use vardevall_switch_proto::api::{CHALLENGE_LIFETIME, build_challenge};

use crate::api::{Api, ApiError, ApiResponse, ConnInfo, unix_now};

impl Api {
    pub(crate) fn challenge(&self, conn: &ConnInfo, now: Instant) -> Result<ApiResponse, ApiError> {
        self.limiters.ip(conn.peer, now)?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| ApiError::RateLimited(crate::limits::Exceeded { retry_after: 5 }))?;
        let c = build_challenge(&self.challenge_secret, unix_now(), &nonce);
        Ok(ApiResponse::json(
            StatusCode::OK,
            format!(
                "{{\"challenge\":\"{}\",\"expires_in\":{CHALLENGE_LIFETIME}}}",
                base32::encode(&c)
            ),
        ))
    }
}
