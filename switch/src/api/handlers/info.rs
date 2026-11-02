//! `GET /v0/info` (vv-04 §3.4).

use http::StatusCode;

use crate::api::{Api, ApiResponse};

impl Api {
    pub(crate) fn info(&self) -> ApiResponse {
        let l = &self.config.limits;
        let stun: Vec<String> = self
            .config
            .stun
            .uris
            .iter()
            .map(|u| format!("\"{u}\""))
            .collect();
        let body = format!(
            "{{\"versions\":[\"v0\"],\"key\":\"{}\",\"binding\":\"{}\",\"token_required\":{},\
             \"max_forward_size\":{},\"stun\":[{}],\"stun_auth\":{},\"turn\":{},\
             \"forward_limits\":{{\"bits_per_second\":{},\"bytes\":{}}}}}",
            self.public,
            self.config.binding.as_str(),
            self.tokens.required(),
            l.max_forward_size,
            stun.join(","),
            self.config.stun.auth,
            self.config.turn.is_some(),
            (l.sender_bytes_per_second * 8.0) as u64,
            l.session_bytes,
        );
        ApiResponse::json(StatusCode::OK, body)
    }
}
