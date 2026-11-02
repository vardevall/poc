//! The switch API (vv-04 §3 to §7), independent of the transport.
//!
//! A transport turns each request into an [`ApiRequest`] with the facts it knows about the
//! connection in [`ConnInfo`], and writes the [`ApiResponse`] back. Handlers are synchronous and
//! hold no lock across an await.

mod auth;
mod error;
mod handlers;
#[cfg(feature = "stun-turn")]
pub(crate) use handlers::turn::{credential_class, credential_nonce};
mod types;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{Method, StatusCode};
use tokio::time::Instant;
use vardevall_proto::keys::{NodePublic, SwitchPublic, SwitchSecret, base32};

pub use error::ApiError;
pub use types::{ApiBody, ApiRequest, ApiResponse, ConnInfo};

use crate::config::{Config, TokenSettings};
use crate::limits::Limiters;
use crate::registry::Registry;
use crate::status::Counters;
pub use auth::{Admission, ReloadError, Tokens};

/// Largest request body outside `forward`.
const SMALL_BODY: usize = 4096;
/// JSON around the datagram of a `forward` body, in bytes.
const FORWARD_ENVELOPE: usize = 512;
/// Most buckets any limiter keeps.
const LIMITER_KEYS: usize = 100_000;

/// The state and rules of one switch.
pub struct Api {
    secret: SwitchSecret,
    public: SwitchPublic,
    challenge_secret: [u8; 32],
    /// The hosts registrations may name, in normal form (vv-04 §4.4 step 3).
    hosts: HashSet<String>,
    tokens: Arc<Tokens>,
    /// The settings read at start; the token settings in it are replaced by [`Api::reload_tokens`].
    config: Config,
    registry: Arc<Registry>,
    limiters: Arc<Limiters>,
    counters: Arc<Counters>,
    #[cfg(feature = "stun-turn")]
    turn_server: Option<Arc<crate::turn::TurnServer>>,
}

/// The system has no randomness.
#[derive(Debug, thiserror::Error)]
#[error("the system random number generator is unavailable")]
pub struct NoRandomness;

/// A switch could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    /// No randomness is available.
    #[error(transparent)]
    Random(#[from] NoRandomness),
    /// The token settings are unusable.
    #[error(transparent)]
    Tokens(#[from] ReloadError),
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

enum Route {
    Info,
    Challenge,
    Register,
    Members,
    Member(NodePublic),
    Forward,
    Events,
    Logout,
    Turn,
    Stun,
}

impl Api {
    /// A switch with the key `secret` and the settings of `config`.
    pub fn new(config: &Config, secret: SwitchSecret) -> Result<Api, SetupError> {
        let mut challenge_secret = [0u8; 32];
        getrandom::fill(&mut challenge_secret).map_err(|_| NoRandomness)?;
        let limiters = Arc::new(Limiters::new(&config.limits, LIMITER_KEYS));
        let tokens = Arc::new(Tokens::new(
            &TokenSettings {
                tokens: config.tokens.clone(),
                token_turn: config.token_turn.clone(),
                configured: !config.tokens.is_empty(),
            },
            config.turn_limits(0),
        )?);
        let counters = Arc::new(Counters::default());
        #[cfg(feature = "stun-turn")]
        let turn_server = {
            let own: Vec<std::net::IpAddr> = config
                .listen
                .iter()
                .chain(&config.stun.listen)
                .map(|a| a.ip())
                .collect();
            config.turn.as_ref().and_then(|t| {
                crate::turn::TurnServer::new(
                    t,
                    config.stun.auth,
                    &own,
                    tokens.clone(),
                    limiters.clone(),
                    counters.clone(),
                )
            })
        };
        Ok(Api {
            public: secret.public(),
            secret,
            challenge_secret,
            hosts: config.served_hosts().into_iter().collect(),
            tokens: tokens.clone(),
            registry: Registry::new(&config.limits, config.timeouts.reconnect_grace),
            #[cfg(feature = "stun-turn")]
            turn_server,
            counters,
            limiters,
            config: config.clone(),
        })
    }

    /// The switch's public key `A`.
    pub fn public(&self) -> &SwitchPublic {
        &self.public
    }

    /// The registry, for maintenance and monitoring.
    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// The embedded TURN server, if the operator runs one.
    #[cfg(feature = "stun-turn")]
    pub fn turn_server(&self) -> Option<&Arc<crate::turn::TurnServer>> {
        self.turn_server.as_ref()
    }

    /// Charges a STUN or TURN request on a UDP port to the client address; `false` means drop it.
    #[cfg(feature = "stun-turn")]
    pub fn allow_stun(&self, ip: std::net::IpAddr) -> bool {
        let allowed = self.limiters.stun(ip, Instant::now()).is_ok();
        if !allowed {
            self.counters.unanswered();
        }
        allowed
    }

    /// The Binding response for `request` from `from`, or `None` for silence: not a Binding
    /// request, or, when `stun_auth` is on, no valid credential (vv-04 §4.7).
    #[cfg(feature = "stun-turn")]
    pub fn stun_response(&self, request: &[u8], from: std::net::SocketAddr) -> Option<Vec<u8>> {
        let reply = if self.config.stun.auth {
            self.config.turn.as_ref().and_then(|turn| {
                crate::stun::respond_authenticated(request, from, &turn.secret, unix_now())
            })
        } else {
            crate::stun::respond(request, from)
        };
        if reply.is_none() {
            self.counters.unanswered();
        }
        reply
    }

    /// The refusals counted for the status line.
    pub fn counters(&self) -> &Arc<Counters> {
        &self.counters
    }

    /// The status line (see [`crate::status`]), with the refusals since the last call.
    pub fn status_line(&self) -> String {
        #[cfg(feature = "stun-turn")]
        let allocations = self.turn_server.as_ref().map(|t| t.allocations());
        #[cfg(not(feature = "stun-turn"))]
        let allocations = None;
        crate::status::line(self.registry.stats(), allocations, self.counters.take())
    }

    /// The configuration read at start. Its token settings are out of date after a reload.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Replaces the accepted operator tokens and their TURN limits with `settings`, and returns
    /// how many tokens are accepted. Sessions already admitted stay valid; a session whose
    /// token is no longer accepted gets no new TURN credentials while registration needs a
    /// token. On an error the previous tokens stay.
    pub fn reload_tokens(&self, settings: &TokenSettings) -> Result<usize, ReloadError> {
        self.tokens.reload(settings)
    }

    /// Runs the periodic housekeeping: grace periods, old generations and idle limiter buckets.
    pub fn sweep(&self, now: Instant) {
        self.registry.sweep(now);
        self.limiters.sweep(now);
        #[cfg(feature = "stun-turn")]
        if let Some(t) = &self.turn_server {
            t.sweep(now);
        }
    }

    fn route(method: &Method, path: &str) -> Result<Route, ApiError> {
        let rest = path.strip_prefix("/v0/").ok_or(ApiError::NotFound)?;
        let allowed = |m: &'static str, route: Route| {
            if method.as_str() == m {
                Ok(route)
            } else {
                Err(ApiError::MethodNotAllowed(m))
            }
        };
        match rest {
            "info" => allowed("GET", Route::Info),
            "challenge" => allowed("GET", Route::Challenge),
            "register" => allowed("POST", Route::Register),
            "members" => allowed("GET", Route::Members),
            "forward" => allowed("POST", Route::Forward),
            "events" => allowed("GET", Route::Events),
            "session" => allowed("DELETE", Route::Logout),
            "turn" => allowed("POST", Route::Turn),
            "stun" => allowed("POST", Route::Stun),
            _ => match rest.strip_prefix("members/") {
                Some(key) => match key.parse::<NodePublic>() {
                    Ok(node) => allowed("GET", Route::Member(node)),
                    Err(_) => Err(ApiError::NotFound),
                },
                None => Err(ApiError::NotFound),
            },
        }
    }

    /// The most body bytes a request to `path` may carry; the transport enforces it.
    pub fn body_limit(&self, path: &str) -> usize {
        match path {
            "/v0/forward" => {
                (self.config.limits.max_forward_size * 8).div_ceil(5) + FORWARD_ENVELOPE
            }
            _ => SMALL_BODY,
        }
    }

    /// Handles one request.
    pub fn handle(&self, conn: &ConnInfo, req: ApiRequest) -> ApiResponse {
        let now = Instant::now();
        let result = Self::route(&req.method, req.uri.path()).and_then(|route| match route {
            Route::Info => Ok(self.info()),
            Route::Challenge => self.challenge(conn, now),
            Route::Register => self.register(conn, &req, now),
            Route::Members => self.members(&req, now),
            Route::Member(node) => self.member(&req, &node, now),
            Route::Forward => self.forward(&req, now),
            Route::Events => self.events(&req),
            Route::Logout => self.logout(&req, now),
            Route::Turn => self.turn(&req, now),
            Route::Stun => self.stun(&req, now),
        });
        result.unwrap_or_else(|e| {
            self.counters.api_error(&e);
            e.into_response()
        })
    }

    pub(crate) fn session(&self, req: &ApiRequest) -> Result<[u8; 32], ApiError> {
        req.headers
            .get("vv-session")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| base32::decode_array(s).ok())
            .ok_or(ApiError::SessionInvalid)
    }
}

impl ApiResponse {
    pub(crate) fn json(status: StatusCode, body: String) -> Self {
        ApiResponse::new(status, ApiBody::Bytes(body.into()), "application/json")
    }
}
