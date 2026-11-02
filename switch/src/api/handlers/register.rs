//! `POST /v0/register` (vv-04 §4.3, §4.4).

use http::StatusCode;
use tokio::time::Instant;
use vardevall_proto::keys::base32;
use vardevall_switch_proto::api::{
    Binding, RegisterRequest, RequestBinding, bound_data, normalize_host, parse_register_request,
    verify_challenge, verify_registration,
};

use crate::api::{Api, ApiError, ApiRequest, ApiResponse, ConnInfo, unix_millis, unix_now};
use crate::limits::Exceeded;

/// Retry hint when a cap rather than a rate refuses a registration.
const CAPACITY_RETRY: u64 = 30;

impl Api {
    /// Whether `request` names a host this switch serves (vv-04 §4.4 step 3): a web name or one
    /// of `names` in the configuration, compared in normal form.
    fn serves_host(&self, request: &RegisterRequest) -> bool {
        normalize_host(&request.host).is_some_and(|h| self.hosts.contains(&h))
    }

    /// Registers a node, in the order of vv-04 §4.4: per-address limits, the token, the host
    /// and the proofs, per-network limits, the replacement.
    pub(crate) fn register(
        &self,
        conn: &ConnInfo,
        req: &ApiRequest,
        now: Instant,
    ) -> Result<ApiResponse, ApiError> {
        self.limiters.ip(conn.peer, now)?;
        let admission = self
            .tokens
            .admit(&req.headers)
            .ok_or(ApiError::TokenRequired)?;
        let body = parse_register_request(&req.body).map_err(|_| ApiError::Malformed)?;
        if !self.serves_host(&body) {
            return Err(ApiError::InvalidProof);
        }
        let host = normalize_host(&body.host).ok_or(ApiError::InvalidProof)?;

        let (binding, challenge_ok) = match &body.binding {
            RequestBinding::Exporter => (
                Binding::Exporter(conn.exporter.ok_or(ApiError::Malformed)?),
                true,
            ),
            RequestBinding::Challenge(c) => (
                Binding::Challenge(*c),
                verify_challenge(&self.challenge_secret, c, unix_now()),
            ),
        };
        let b = bound_data(&binding, &host, &body.node, &body.network, &self.public)
            .map_err(|_| ApiError::InvalidProof)?;
        let proof = verify_registration(
            &self.secret,
            &body.node,
            &body.network,
            &b,
            &body.node_proof,
            &body.net_proof,
        );
        let switch_proof = match proof {
            Some(p) if challenge_ok => p,
            _ => return Err(ApiError::InvalidProof),
        };

        self.limiters.register(&body.network, now)?;
        let registered = self
            .registry
            .register(body.network, body.node, now, unix_millis())
            .map_err(|_| {
                ApiError::RateLimited(Exceeded {
                    retry_after: CAPACITY_RETRY,
                })
            })?;
        self.registry
            .set_token(&registered.session, admission.token);
        let turn = self
            .issue_turn(admission.class)
            .map(|t| format!(",\"turn\":{t}"))
            .unwrap_or_default();
        let stun = self
            .issue_stun()
            .map(|t| format!(",\"stun\":{t}"))
            .unwrap_or_default();
        Ok(ApiResponse::json(
            StatusCode::OK,
            format!(
                "{{\"session\":\"{}\",\"switch_proof\":\"{}\"{turn}{stun}}}",
                base32::encode(&registered.session),
                base32::encode(&switch_proof)
            ),
        ))
    }
}
