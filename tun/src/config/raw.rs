//! The serde schema of an interface file (vv-07 §3). Unknown keys are rejected (vv-07 §2.2).

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Raw {
    pub interface: RawInterface,
    #[serde(default)]
    pub switch: Vec<RawSwitch>,
    #[serde(default)]
    pub turn: Vec<RawTurn>,
    #[serde(default)]
    pub stun: Vec<RawStun>,
    #[serde(default)]
    pub service: Vec<RawService>,
    #[serde(default)]
    pub peer: Vec<RawPeer>,
    pub exit: Option<RawExit>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum RawDuration {
    Int(i64),
    Text(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInterface {
    pub private_key: String,
    pub network_secret: String,
    pub network_id: Option<String>,
    pub name: Option<String>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u32>,
    pub domain: Option<String>,
    pub forward: Option<Vec<String>>,
    pub fallback_delay: Option<RawDuration>,
    pub accept_members: Option<bool>,
    pub mdns: Option<bool>,
    pub tun_class: Option<RawTunClass>,
    pub detect_timeout: Option<RawDuration>,
    pub switch_path: Option<String>,
    pub roster: Option<toml::Value>,
    pub roster_key: Option<toml::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTunClass {
    pub band: Option<String>,
    pub latency: Option<String>,
    pub degrade: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSwitch {
    pub address: String,
    pub token: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTurn {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
    pub credentials_command: Option<String>,
    pub priority: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawStun {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawService {
    pub name: String,
    pub port: u16,
    pub proto: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPeer {
    pub public_key: String,
    pub name: Option<String>,
    pub endpoint: Option<String>,
    pub endpoint_local: Option<bool>,
    pub preshared_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawExit {
    pub site: String,
    pub ipv4: Option<bool>,
}
