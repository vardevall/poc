//! Pure parts of the switch API: challenges, registration proofs and TURN credentials (vv-04).

use std::net::{Ipv4Addr, Ipv6Addr};

use data_encoding::BASE64;
use zeroize::Zeroizing;

use vardevall_proto::error::{CryptoError, ParseError};
use vardevall_proto::json::{self, Value};
use vardevall_proto::keys::base32;
use vardevall_proto::keys::crypto;
use vardevall_proto::keys::{
    NetworkPublic, NetworkSecret, NodePublic, NodeSecret, SwitchPublic, SwitchSecret, ctx,
};

/// TLS exporter label of the exporter binding (vv-04 §4.1).
pub const EXPORTER_LABEL: &str = "EXPORTER-vardevall-v0-register";
/// Size of a challenge (vv-04 §4.2).
pub const CHALLENGE_LEN: usize = 40;
/// Seconds a challenge stays valid on the issuing clock (vv-04 §4.2).
pub const CHALLENGE_LIFETIME: u64 = 60;
/// Seconds a challenge may lie in the future (vv-04 §4.2).
pub const CHALLENGE_FUTURE_TOLERANCE: u64 = 5;

/// Builds `t ‖ nonce ‖ MAC(challenge_secret, t ‖ nonce, 16)` (vv-04 §4.2).
pub fn build_challenge(secret: &[u8; 32], t: u64, nonce: &[u8; 16]) -> [u8; CHALLENGE_LEN] {
    let mut c = [0u8; CHALLENGE_LEN];
    c[..8].copy_from_slice(&t.to_le_bytes());
    c[8..24].copy_from_slice(nonce);
    let mac: [u8; 16] = crypto::mac(secret, &[&c[..24]]);
    c[24..].copy_from_slice(&mac);
    c
}

/// Checks a challenge against the switch clock `now`, in Unix seconds (vv-04 §4.2).
pub fn verify_challenge(secret: &[u8; 32], challenge: &[u8], now: u64) -> bool {
    if challenge.len() != CHALLENGE_LEN {
        return false;
    }
    let expect: [u8; 16] = crypto::mac(secret, &[&challenge[..24]]);
    let mut t = [0u8; 8];
    t.copy_from_slice(&challenge[..8]);
    let t = u64::from_le_bytes(t);
    crypto::ct_eq(&expect, &challenge[24..])
        && t <= now.saturating_add(CHALLENGE_FUTURE_TOLERANCE)
        && now <= t.saturating_add(CHALLENGE_LIFETIME)
}

/// What a registration proof is bound to (vv-04 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// The TLS exporter value; native clients.
    Exporter([u8; 32]),
    /// A switch challenge; browsers.
    Challenge([u8; CHALLENGE_LEN]),
}

impl Binding {
    fn value(&self) -> Vec<u8> {
        match self {
            Binding::Exporter(e) => [&[1u8][..], e].concat(),
            Binding::Challenge(c) => [&[2u8][..], c].concat(),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Binding::Exporter(_) => "exporter",
            Binding::Challenge(_) => "challenge",
        }
    }
}

/// Longest `host` of a registration, in bytes (vv-04 §4.3).
pub const MAX_HOST_LEN: usize = 253;

/// The bound data `b` of vv-04 §4.3: `binding_value ‖ len(host) ‖ host ‖ node_pk ‖ net_pk ‖ A`.
///
/// `host` is written as given, so it must already be in normal form (see [`normalize_host`]);
/// it fails with [`ParseError::Length`] unless it is 1 to 253 bytes.
pub fn bound_data(
    binding: &Binding,
    host: &str,
    node: &NodePublic,
    network: &NetworkPublic,
    switch: &SwitchPublic,
) -> Result<Vec<u8>, ParseError> {
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return Err(ParseError::Length);
    }
    let len = u8::try_from(host.len()).map_err(|_| ParseError::Length)?;
    Ok([
        binding.value(),
        vec![len],
        host.as_bytes().to_vec(),
        node.as_bytes().to_vec(),
        network.as_bytes().to_vec(),
        switch.as_bytes().to_vec(),
    ]
    .concat())
}

fn canonical_ipv6(addr: &Ipv6Addr) -> String {
    let groups = addr.segments();
    let (mut best, mut best_len) = (0, 0);
    let mut i = 0;
    while i < groups.len() {
        if groups[i] != 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < groups.len() && groups[i] == 0 {
            i += 1;
        }
        if i - start > best_len {
            (best, best_len) = (start, i - start);
        }
    }
    let hex = |g: &[u16]| {
        g.iter()
            .map(|x| format!("{x:x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    if best_len < 2 {
        return hex(&groups);
    }
    format!(
        "{}::{}",
        hex(&groups[..best]),
        hex(&groups[best + best_len..])
    )
}

/// The normal form of a switch host for the registration body and `b` (vv-04 §4.3): a DNS name in
/// lowercase without a trailing dot, an IPv4 address in dotted decimal, or an IPv6 address in the
/// form of RFC 5952 without brackets. Accepts a bracketed IPv6 literal. Returns `None` for text
/// that is none of these, or longer than [`MAX_HOST_LEN`]; names must already be A-labels.
pub fn normalize_host(host: &str) -> Option<String> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(v6) = bare.parse::<Ipv6Addr>() {
        return Some(canonical_ipv6(&v6));
    }
    if bare.len() == host.len()
        && let Ok(v4) = bare.parse::<Ipv4Addr>()
    {
        return Some(v4.to_string());
    }
    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    let numeric_tld = name
        .rsplit('.')
        .next()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    let valid = !name.is_empty()
        && name.len() <= MAX_HOST_LEN
        && !numeric_tld
        && name.split('.').all(label_ok);
    valid.then_some(name)
}

/// The three proofs over one bound data string (vv-01 §5.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proofs {
    /// Proof of the node key.
    pub node_proof: [u8; 32],
    /// Proof of the network secret.
    pub net_proof: [u8; 32],
    /// The switch's proof, which the client verifies.
    pub switch_proof: [u8; 32],
}

fn proofs_from_dh(
    dh_node: &[u8; 32],
    dh_net: &[u8; 32],
    node: &NodePublic,
    net: &NetworkPublic,
    sw_pk: &[u8; 32],
    b: &[u8],
) -> Proofs {
    let key = |c: &str, dh: &[u8; 32], who: &[u8; 32]| -> Zeroizing<[u8; 32]> {
        Zeroizing::new(crypto::kdf(c, &[dh, who, sw_pk]))
    };
    Proofs {
        node_proof: crypto::mac(&key(ctx::REGISTER_NODE, dh_node, node.as_bytes()), &[b]),
        net_proof: crypto::mac(&key(ctx::REGISTER_NETWORK, dh_net, net.as_bytes()), &[b]),
        switch_proof: crypto::mac(&key(ctx::REGISTER_SWITCH, dh_node, node.as_bytes()), &[b]),
    }
}

/// The proofs a node computes towards `switch` over `b`; `switch_proof` is the expected reply.
pub fn client_proofs(
    node: &NodeSecret,
    network: &NetworkSecret,
    switch: &SwitchPublic,
    b: &[u8],
) -> Result<Proofs, CryptoError> {
    let sw_pk = switch.dh_public()?;
    let dh_node = crypto::dh(node.as_bytes(), &sw_pk)?;
    let net_dh_sk = network.dh_secret();
    let dh_net = crypto::dh(&net_dh_sk, &sw_pk)?;
    Ok(proofs_from_dh(
        &dh_node,
        &dh_net,
        &node.public(),
        &network.public(),
        &sw_pk,
        b,
    ))
}

/// The proofs a switch computes for a registration from `node` in `network` over `b`.
pub fn switch_proofs(
    switch: &SwitchSecret,
    node: &NodePublic,
    network: &NetworkPublic,
    b: &[u8],
) -> Result<Proofs, CryptoError> {
    let sw_sk = switch.dh_secret();
    let sw_pk = crypto::dh_pub(&sw_sk);
    let dh_node = crypto::dh(&sw_sk, node.as_bytes())?;
    let dh_net = crypto::dh(&sw_sk, network.as_bytes())?;
    Ok(proofs_from_dh(&dh_node, &dh_net, node, network, &sw_pk, b))
}

/// Verifies both proofs of a request in constant time and returns the `switch_proof` to answer.
pub fn verify_registration(
    switch: &SwitchSecret,
    node: &NodePublic,
    network: &NetworkPublic,
    b: &[u8],
    node_proof: &[u8; 32],
    net_proof: &[u8; 32],
) -> Option<[u8; 32]> {
    let expect = switch_proofs(switch, node, network, b).ok()?;
    let ok =
        crypto::ct_eq(&expect.node_proof, node_proof) & crypto::ct_eq(&expect.net_proof, net_proof);
    ok.then_some(expect.switch_proof)
}

/// The body of `POST /v0/register` (vv-04 §4.3); `host` is the one `b` was built with.
pub fn register_request(
    node: &NodePublic,
    network: &NetworkPublic,
    binding: &Binding,
    host: &str,
    proofs: &Proofs,
) -> String {
    let mut s = format!(
        "{{\"node\":\"{}\",\"network\":\"{}\",\"binding\":\"{}\",\"host\":",
        node,
        network,
        binding.name(),
    );
    json::write_string(&mut s, host);
    s.push_str(&format!(
        ",\"node_proof\":\"{}\",\"net_proof\":\"{}\"",
        base32::encode(&proofs.node_proof),
        base32::encode(&proofs.net_proof),
    ));
    if let Binding::Challenge(c) = binding {
        s.push_str(&format!(",\"challenge\":\"{}\"", base32::encode(c)));
    }
    s.push('}');
    s
}

/// The binding a registration request names (vv-04 §4.3); the exporter value is not in the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestBinding {
    /// `"binding": "exporter"`.
    Exporter,
    /// `"binding": "challenge"` with the challenge.
    Challenge([u8; CHALLENGE_LEN]),
}

/// The parsed body of `POST /v0/register`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    /// The node key.
    pub node: NodePublic,
    /// The network key.
    pub network: NetworkPublic,
    /// The binding the proofs claim.
    pub binding: RequestBinding,
    /// The host the client registers with, as sent; the switch checks it against the names it
    /// serves (vv-04 §4.4 step 3).
    pub host: String,
    /// Proof of the node key.
    pub node_proof: [u8; 32],
    /// Proof of the network secret.
    pub net_proof: [u8; 32],
}

/// Parses the body of `POST /v0/register` (vv-04 §4.3).
pub fn parse_register_request(body: &[u8]) -> Result<RegisterRequest, ParseError> {
    let v = json::parse(body)?;
    let binding = match field(&v, "binding")?.as_str().ok_or(ParseError::Field)? {
        "exporter" => RequestBinding::Exporter,
        "challenge" => RequestBinding::Challenge(b32_field(&v, "challenge")?),
        _ => return Err(ParseError::Field),
    };
    Ok(RegisterRequest {
        node: node_field(&v, "node")?,
        network: b32_field(&v, "network").map(NetworkPublic::from_bytes)?,
        binding,
        host: field(&v, "host")?
            .as_str()
            .ok_or(ParseError::Field)?
            .to_owned(),
        node_proof: b32_field(&v, "node_proof")?,
        net_proof: b32_field(&v, "net_proof")?,
    })
}

/// The parsed body of `POST /v0/forward`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRequest {
    /// The recipient.
    pub to: NodePublic,
    /// The datagram.
    pub msg: Vec<u8>,
}

/// Parses the body of `POST /v0/forward` (vv-04 §6); the datagram is not inspected.
pub fn parse_forward_request(body: &[u8]) -> Result<ForwardRequest, ParseError> {
    let v = json::parse(body)?;
    let msg = field(&v, "msg")?.as_str().ok_or(ParseError::Field)?;
    Ok(ForwardRequest {
        to: node_field(&v, "to")?,
        msg: base32::decode(msg).map_err(|_| ParseError::Field)?,
    })
}

/// TURN credentials of a registration response (vv-04 §4.4, §4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnCredentials {
    /// TURN URIs.
    pub urls: Vec<String>,
    /// `<expiry>:<opaque id>`.
    pub username: String,
    /// Base64 `HMAC-SHA1`.
    pub credential: String,
    /// Validity in seconds.
    pub ttl: u64,
    /// Advertised sustained rate per allocation, bits per second (vv-04 §4.5 `limits`).
    pub bits_per_second: Option<u64>,
    /// Advertised volume per credential, bytes.
    pub bytes: Option<u64>,
    /// The REALM the TURN server accepts with this credential (vv-04 §4.5).
    pub realm: Option<String>,
    /// The NONCE the TURN server accepts with this credential, opaque to the client.
    pub nonce: Option<String>,
}

/// STUN credentials of a registration response or `POST /v0/stun` (vv-04 §4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunCredentials {
    /// `<expiry>:<opaque id>`, the USERNAME of Binding requests.
    pub username: String,
    /// Base64 `HMAC-SHA1`, the key of the short-term credential mechanism.
    pub credential: String,
    /// Validity in seconds.
    pub ttl: u64,
}

/// The parsed response of `POST /v0/register`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterResponse {
    /// The `Vv-Session` credential.
    pub session: [u8; 32],
    /// The switch's proof, to verify against [`Proofs::switch_proof`].
    pub switch_proof: [u8; 32],
    /// TURN credentials if the operator offers TURN.
    pub turn: Option<TurnCredentials>,
    /// STUN credentials if the switch's `stun_auth` is true (vv-04 §4.7).
    pub stun: Option<StunCredentials>,
}

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a Value, ParseError> {
    v.get(name).ok_or(ParseError::Field)
}

fn b32_field<const N: usize>(v: &Value, name: &str) -> Result<[u8; N], ParseError> {
    let s = field(v, name)?.as_str().ok_or(ParseError::Field)?;
    base32::decode_array(s).map_err(|_| ParseError::Field)
}

fn turn_credentials(t: &Value) -> Result<TurnCredentials, ParseError> {
    let text = |name| -> Result<String, ParseError> {
        Ok(field(t, name)?
            .as_str()
            .ok_or(ParseError::Field)?
            .to_owned())
    };
    let limit = |name| {
        t.get("limits")
            .and_then(|l| l.get(name))
            .and_then(Value::as_u64)
    };
    let optional_text = |name: &str| -> Result<Option<String>, ParseError> {
        match t.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_str()
                .map(|s| Some(s.to_owned()))
                .ok_or(ParseError::Field),
        }
    };
    Ok(TurnCredentials {
        urls: field(t, "urls")?
            .as_array()
            .ok_or(ParseError::Field)?
            .iter()
            .map(|u| u.as_str().map(str::to_owned).ok_or(ParseError::Field))
            .collect::<Result<_, _>>()?,
        username: text("username")?,
        credential: text("credential")?,
        ttl: field(t, "ttl")?.as_u64().ok_or(ParseError::Field)?,
        bits_per_second: limit("bits_per_second"),
        bytes: limit("bytes"),
        realm: optional_text("realm")?,
        nonce: optional_text("nonce")?,
    })
}

fn stun_credentials(t: &Value) -> Result<StunCredentials, ParseError> {
    let text = |name| -> Result<String, ParseError> {
        Ok(field(t, name)?
            .as_str()
            .ok_or(ParseError::Field)?
            .to_owned())
    };
    Ok(StunCredentials {
        username: text("username")?,
        credential: text("credential")?,
        ttl: field(t, "ttl")?.as_u64().ok_or(ParseError::Field)?,
    })
}

/// Parses the body of `POST /v0/stun` (vv-04 §4.7).
pub fn parse_stun_response(body: &[u8]) -> Result<StunCredentials, ParseError> {
    stun_credentials(&json::parse(body)?)
}

/// Parses the body of `POST /v0/turn` (vv-04 §4.5).
pub fn parse_turn_response(body: &[u8]) -> Result<TurnCredentials, ParseError> {
    turn_credentials(&json::parse(body)?)
}

/// Parses a registration response body.
pub fn parse_register_response(body: &[u8]) -> Result<RegisterResponse, ParseError> {
    let v = json::parse(body)?;
    let turn = match v.get("turn") {
        None | Some(Value::Null) => None,
        Some(t) => Some(turn_credentials(t)?),
    };
    let stun = match v.get("stun") {
        None | Some(Value::Null) => None,
        Some(t) => Some(stun_credentials(t)?),
    };
    Ok(RegisterResponse {
        session: b32_field(&v, "session")?,
        switch_proof: b32_field(&v, "switch_proof")?,
        turn,
        stun,
    })
}

/// Parses a challenge response body into the challenge and its `expires_in`.
pub fn parse_challenge_response(body: &[u8]) -> Result<([u8; CHALLENGE_LEN], u64), ParseError> {
    let v = json::parse(body)?;
    let expires = field(&v, "expires_in")?.as_u64().ok_or(ParseError::Field)?;
    Ok((b32_field(&v, "challenge")?, expires))
}

use crate::stun::hmac_sha1;

/// The TURN REST credential for `username` under `secret` (vv-04 §4.5).
pub fn turn_credential(secret: &str, username: &str) -> String {
    BASE64.encode(&hmac_sha1(secret.as_bytes(), username.as_bytes()))
}

/// The advertised policy for forwarding through the switch (vv-04 §3.4 `forward_limits`, §4.5
/// `limits`); either member may be absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Sustained rate, bits per second.
    pub bits_per_second: Option<u64>,
    /// Total volume, bytes.
    pub bytes: Option<u64>,
}

/// The binding a switch advertises in `/v0/info` (vv-04 §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoBinding {
    /// `"exporter"`: TLS ends at the switch.
    Exporter,
    /// `"challenge"`: the switch is behind a terminating proxy.
    Challenge,
}

/// The parsed body of `GET /v0/info` (vv-04 §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchInfo {
    /// API versions served.
    pub versions: Vec<String>,
    /// The switch's public key `A`, for clients of a web address; `None` if the switch sends none.
    pub key: Option<SwitchPublic>,
    /// The binding clients of a web address use; `exporter` if the switch names none.
    pub binding: InfoBinding,
    /// Whether registration needs an operator token.
    pub token_required: bool,
    /// Largest accepted forwarded message.
    pub max_forward_size: u64,
    /// STUN URIs usable without registering.
    pub stun: Vec<String>,
    /// Whether the STUN servers need the credential of vv-04 §4.7; `false` if the switch says
    /// nothing.
    pub stun_auth: bool,
    /// Whether registration responses carry TURN credentials.
    pub turn: bool,
    /// The forwarding the operator allows, if advertised.
    pub forward_limits: Option<Limits>,
}

fn string_list(v: &Value, name: &str) -> Result<Vec<String>, ParseError> {
    field(v, name)?
        .as_array()
        .ok_or(ParseError::Field)?
        .iter()
        .map(|s| s.as_str().map(str::to_owned).ok_or(ParseError::Field))
        .collect()
}

/// Parses the body of `GET /v0/info`.
pub fn parse_info(body: &[u8]) -> Result<SwitchInfo, ParseError> {
    let v = json::parse(body)?;
    let flag = |name: &str| match v.get(name) {
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(ParseError::Field),
    };
    let binding = match v.get("binding") {
        None => InfoBinding::Exporter,
        Some(b) => match b.as_str().ok_or(ParseError::Field)? {
            "exporter" => InfoBinding::Exporter,
            "challenge" => InfoBinding::Challenge,
            _ => return Err(ParseError::Field),
        },
    };
    let stun_auth = match v.get("stun_auth") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(ParseError::Field),
    };
    let forward_limits = match v.get("forward_limits") {
        None | Some(Value::Null) => None,
        Some(l @ Value::Object(_)) => Some(Limits {
            bits_per_second: l.get("bits_per_second").and_then(Value::as_u64),
            bytes: l.get("bytes").and_then(Value::as_u64),
        }),
        Some(_) => return Err(ParseError::Field),
    };
    Ok(SwitchInfo {
        versions: string_list(&v, "versions")?,
        key: match v.get("key") {
            None => None,
            Some(_) => Some(SwitchPublic::from_bytes(b32_field(&v, "key")?)),
        },
        binding,
        token_required: flag("token_required")?,
        max_forward_size: field(&v, "max_forward_size")?
            .as_u64()
            .ok_or(ParseError::Field)?,
        stun: v
            .get("stun")
            .map(|_| string_list(&v, "stun"))
            .transpose()?
            .unwrap_or_default(),
        stun_auth,
        turn: flag("turn")?,
        forward_limits,
    })
}

/// One online member of a listing (vv-04 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberEntry {
    /// The member's node key.
    pub node: NodePublic,
    /// Unix time of registration.
    pub online_since: u64,
    /// The registration generation (vv-04 §4.4).
    pub generation: u64,
}

/// One page of `GET /v0/members`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembersPage {
    /// Members sorted by key.
    pub members: Vec<MemberEntry>,
    /// Whether more members follow.
    pub truncated: bool,
}

fn node_field(v: &Value, name: &str) -> Result<NodePublic, ParseError> {
    b32_field(v, name).map(NodePublic::from_bytes)
}

fn parse_member(v: &Value) -> Result<MemberEntry, ParseError> {
    Ok(MemberEntry {
        node: node_field(v, "node")?,
        online_since: v.get("online_since").and_then(Value::as_u64).unwrap_or(0),
        generation: field(v, "gen")?.as_u64().ok_or(ParseError::Field)?,
    })
}

/// Parses a members page, rejecting one that is not sorted by key (vv-04 §5.1).
pub fn parse_members_page(body: &[u8]) -> Result<MembersPage, ParseError> {
    let v = json::parse(body)?;
    let members: Vec<MemberEntry> = field(&v, "members")?
        .as_array()
        .ok_or(ParseError::Field)?
        .iter()
        .map(parse_member)
        .collect::<Result<_, _>>()?;
    if members.windows(2).any(|w| w[0].node >= w[1].node) {
        return Err(ParseError::Field);
    }
    let truncated = match v.get("truncated") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(ParseError::Field),
    };
    Ok(MembersPage { members, truncated })
}

/// An event of the SSE stream (vv-04 §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchEvent {
    /// A forwarded datagram.
    Forward {
        /// The sender.
        from: NodePublic,
        /// The datagram.
        msg: Vec<u8>,
    },
    /// A member came online.
    Online {
        /// The member.
        node: NodePublic,
        /// Registration generation.
        generation: u64,
    },
    /// A member went offline.
    Offline {
        /// The member.
        node: NodePublic,
        /// Generation of the registration that ended.
        generation: u64,
    },
    /// This session was replaced.
    Replaced,
}

/// Parses an event; `Ok(None)` for an event type this version does not know (vv-04 §7.2).
pub fn parse_event(event: &str, data: &[u8]) -> Result<Option<SwitchEvent>, ParseError> {
    let v = json::parse(data)?;
    Ok(Some(match event {
        "forward" => {
            let msg = field(&v, "msg")?.as_str().ok_or(ParseError::Field)?;
            SwitchEvent::Forward {
                from: node_field(&v, "from")?,
                msg: base32::decode(msg).map_err(|_| ParseError::Field)?,
            }
        }
        "online" => SwitchEvent::Online {
            node: node_field(&v, "node")?,
            generation: field(&v, "gen")?.as_u64().ok_or(ParseError::Field)?,
        },
        "offline" => SwitchEvent::Offline {
            node: node_field(&v, "node")?,
            generation: field(&v, "gen")?.as_u64().ok_or(ParseError::Field)?,
        },
        "replaced" => SwitchEvent::Replaced,
        _ => return Ok(None),
    }))
}

/// The body of `POST /v0/forward` (vv-04 §6).
pub fn forward_request(to: &NodePublic, datagram: &[u8]) -> String {
    format!(
        "{{\"to\":\"{}\",\"msg\":\"{}\"}}",
        to,
        base32::encode(datagram)
    )
}
