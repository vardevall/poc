//! Several networks in one host tunnel.
//!
//! [`Networks`] starts one [`Tunnel`] per network on the same runtime. They share the runtime and
//! the host's callbacks and nothing else: each has its own node, key, sockets, router and
//! responder. What the host sees is one tunnel, so [`Networks`] decides which tunnel a packet or
//! a DNS query belongs to and merges what the tunnels ask of the host.

use std::cmp::Reverse;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::runtime::Handle as Runtime;
use vardevall::{MdnsEvent, MdnsRequest, ServiceError};
use vardevall_proto::addr::is_valid_label;
use vardevall_proto::ip::site::Site;
use vardevall_proto::keys::NodePublic;

use super::guard::{Guard, MdnsFn};
use super::{
    Callbacks, ExitInUse, ExitUse, HostDns, PathUpdate, Proto, STOP_WAIT, StartError, StartOptions,
    Tunnel,
};
use crate::config::{Config, Context};
use crate::packet;
use crate::settings::TunnelSettings;

/// Most networks one host tunnel holds.
pub const MAX_NETWORKS: usize = 8;
/// Longest network name: the longest label whose `<name>.internal` is a valid domain.
const MAX_NAME: usize = 51;

/// A network of the set: the name the host gives it and its interface file.
#[derive(Debug, Clone)]
pub struct NetworkSpec {
    /// A DNS label, unique in the set. It is the interface name of the network, so the default
    /// domain is `<name>.internal`, and it tags the events.
    pub name: String,
    /// The interface file (vv-07 §3).
    pub config_toml: String,
}

/// A call named a network that is not in the set, or failed in it.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// No network has this name.
    #[error("no network named {0:?}")]
    Unknown(String),
    /// The network refused the service.
    #[error("{0}")]
    Service(#[from] ServiceError),
}

struct Member {
    name: String,
    prefix: [u8; 6],
    tunnel: Tunnel,
}

/// Running networks behind one tunnel device.
pub struct Networks {
    members: Vec<Member>,
    guard: Arc<Guard>,
    settings: TunnelSettings,
    intercept_dns: bool,
    /// The index of the network that carries the exit, or [`NO_EXIT`].
    exit: AtomicUsize,
}

const NO_EXIT: usize = usize::MAX;

fn parse_all(specs: &[NetworkSpec], hostname: Option<&str>) -> Result<Vec<Config>, StartError> {
    if specs.is_empty() || specs.len() > MAX_NETWORKS {
        return Err(StartError::Networks(format!(
            "{} networks, between 1 and {MAX_NETWORKS} are allowed",
            specs.len()
        )));
    }
    let mut configs: Vec<Config> = Vec::with_capacity(specs.len());
    for (i, spec) in specs.iter().enumerate() {
        if !is_valid_label(&spec.name) || spec.name.len() > MAX_NAME {
            return Err(StartError::Networks(format!(
                "{:?} is not a valid network name",
                spec.name
            )));
        }
        if specs[..i].iter().any(|s| s.name == spec.name) {
            return Err(StartError::Networks(format!(
                "the name {:?} is used twice",
                spec.name
            )));
        }
        let ctx = Context {
            interface_name: spec.name.clone(),
            hostname: hostname.map(str::to_owned),
        };
        let config = Config::parse(&spec.config_toml, &ctx).map_err(|e| StartError::Network {
            name: spec.name.clone(),
            source: Box::new(e.into()),
        })?;
        if let Some(j) = configs
            .iter()
            .position(|c| prefix48(c) == prefix48(&config))
        {
            return Err(StartError::SameNetwork {
                first: specs[j].name.clone(),
                second: spec.name.clone(),
            });
        }
        configs.push(config);
    }
    Ok(configs)
}

fn prefix48(config: &Config) -> [u8; 6] {
    let p = vardevall_proto::addr::ula_prefix(&config.network_id);
    [p[0], p[1], p[2], p[3], p[4], p[5]]
}

/// Settings for a set of networks without starting anything (`vv_tunnel_settings_networks`).
pub fn tunnel_settings_networks(specs: &[NetworkSpec]) -> Result<TunnelSettings, StartError> {
    let configs = parse_all(specs, None)?;
    let sets: Vec<_> = configs.iter().map(TunnelSettings::for_config).collect();
    TunnelSettings::merged(&sets).ok_or_else(|| StartError::Networks("no networks".to_owned()))
}

/// Passes on the first `browse` and the last `stop_browse` of the networks, and every other
/// request.
fn combine_mdns(mut host: MdnsFn) -> MdnsFn {
    let mut browsing = 0usize;
    Box::new(move |request| match request {
        MdnsRequest::Browse => {
            browsing += 1;
            if browsing == 1 {
                host(request);
            }
        }
        MdnsRequest::StopBrowse => {
            if browsing > 0 {
                browsing -= 1;
                if browsing == 0 {
                    host(request);
                }
            }
        }
        _ => host(request),
    })
}

impl Networks {
    /// Starts every network of `specs` on `runtime`, the first being the one whose resolver
    /// address the host configures.
    ///
    /// `options.interface_name` is not used; each network's name takes its place. Callbacks run on
    /// tasks of the runtime, one at a time, for all networks together.
    pub fn start(
        runtime: &Runtime,
        specs: Vec<NetworkSpec>,
        options: StartOptions,
        callbacks: Callbacks,
    ) -> Result<Networks, StartError> {
        Networks::start_with(runtime, specs, options, HostDns::default(), callbacks)
    }

    /// As [`Networks::start`], for a host that expects the node to serve its DNS as `dns` says.
    pub fn start_with(
        runtime: &Runtime,
        specs: Vec<NetworkSpec>,
        options: StartOptions,
        dns: HostDns,
        callbacks: Callbacks,
    ) -> Result<Networks, StartError> {
        let configs = parse_all(&specs, options.hostname.as_deref())?;
        let sets: Vec<_> = configs.iter().map(TunnelSettings::for_config).collect();
        let settings = TunnelSettings::merged(&sets)
            .ok_or_else(|| StartError::Networks("no networks".to_owned()))?;
        let callbacks = Callbacks {
            mdns: callbacks.mdns.map(combine_mdns),
            ..callbacks
        };
        let guard = Arc::new(Guard::new(callbacks));
        let mut members = Vec::with_capacity(specs.len());
        for (spec, config) in specs.into_iter().zip(configs) {
            let prefix = prefix48(&config);
            let member_options = StartOptions {
                interface_name: spec.name.clone(),
                ..options.clone()
            };
            let tunnel = Tunnel::start_in(runtime, config, &member_options, dns, guard.clone())
                .map_err(|e| StartError::Network {
                    name: spec.name.clone(),
                    source: Box::new(e),
                })?;
            members.push(Member {
                name: spec.name,
                prefix,
                tunnel,
            });
        }
        Ok(Networks {
            members,
            guard,
            settings,
            intercept_dns: options.intercept_dns,
            exit: AtomicUsize::new(NO_EXIT),
        })
    }

    /// The names of the networks, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.members.iter().map(|m| m.name.as_str())
    }

    fn member(&self, network: Option<&str>) -> Result<&Member, NetworkError> {
        match network {
            None => Ok(&self.members[0]),
            Some(n) => self
                .members
                .iter()
                .find(|m| m.name == n)
                .ok_or_else(|| NetworkError::Unknown(n.to_owned())),
        }
    }

    /// The tunnel settings of the set: every network's addresses and routes, the
    /// smallest MTU, the first network's resolver and every network's domains.
    pub fn settings(&self) -> &TunnelSettings {
        &self.settings
    }

    /// The validated configuration of a network; `None` names the first.
    pub fn config(&self, network: Option<&str>) -> Option<Arc<Config>> {
        self.member(network).ok().map(|m| m.tunnel.config())
    }

    /// The UDP port of a network's interface socket; `None` names the first.
    pub fn listen_port(&self, network: Option<&str>) -> Option<u16> {
        self.member(network).ok().map(|m| m.tunnel.listen_port())
    }

    /// The tunnel that answers a query found in the stream to the first network's resolver
    /// address: the one whose domain or reverse zone holds the name, the more specific first,
    /// else the one that carries the exit, else the first.
    fn resolver_for(&self, message: &[u8]) -> &Tunnel {
        self.members
            .iter()
            .enumerate()
            .filter_map(|(i, m)| {
                let zone = m.tunnel.shared.responder.zone_len(message)?;
                Some((zone, Reverse(i), &m.tunnel))
            })
            .max_by_key(|(zone, i, _)| (*zone, *i))
            .map_or_else(|| self.carrier(), |(_, _, t)| t)
    }

    /// The tunnel of the network that carries the exit, else the first.
    fn carrier(&self) -> &Tunnel {
        &self
            .members
            .get(self.exit.load(Ordering::Relaxed))
            .unwrap_or(&self.members[0])
            .tunnel
    }

    /// Makes one network carry the exit, or none. Only that network's tunnel uses
    /// an exit; the others stop using theirs.
    pub fn set_exit(&self, exit: Option<(&str, ExitUse)>) -> Result<(), NetworkError> {
        let chosen = match &exit {
            Some((name, _)) => Some(
                self.members
                    .iter()
                    .position(|m| m.name == *name)
                    .ok_or_else(|| NetworkError::Unknown((*name).to_owned()))?,
            ),
            None => None,
        };
        for (i, m) in self.members.iter().enumerate() {
            m.tunnel.set_exit(
                exit.as_ref()
                    .filter(|_| chosen == Some(i))
                    .map(|(_, using)| using.clone()),
            );
        }
        self.exit
            .store(chosen.unwrap_or(NO_EXIT), Ordering::Relaxed);
        Ok(())
    }

    /// Gives one network back the offers an earlier run reported; `None` is the
    /// first network.
    pub fn remember_exits(
        &self,
        network: Option<&str>,
        offers: Vec<(NodePublic, Site)>,
    ) -> Result<(), NetworkError> {
        self.member(network)?.tunnel.remember_exits(offers);
        Ok(())
    }

    /// The network that carries the exit and the exit it uses, or `None` while the host chose no
    /// network or the site in use has no live exit.
    pub fn exit_in_use(&self) -> Option<(&str, ExitInUse)> {
        let member = self.members.get(self.exit.load(Ordering::Relaxed))?;
        Some((member.name.as_str(), member.tunnel.exit_in_use()?))
    }

    /// [`Networks::exit_in_use`] as the JSON of `vv_exit_in_use`: the string `null`, or
    /// `{"network","site","via","addr","ipv4"}`.
    pub fn exit_in_use_json(&self) -> String {
        match self.exit_in_use() {
            None => serde_json::Value::Null,
            Some((network, used)) => serde_json::json!({
                "network": network,
                "site": used.site.to_string(),
                "via": used.via.to_base32(),
                "addr": used.addr.to_string(),
                "ipv4": used.ipv4.map(|a| a.to_string()),
            }),
        }
        .to_string()
    }

    /// Hands the networks an IP packet read from the operating system: it goes to
    /// the network whose `/48` holds the destination; one that no network holds goes to the
    /// network that carries the exit, else to the first, and so does an IPv4 packet.
    pub fn packet_in(&self, packet: &[u8]) {
        let first = &self.members[0].tunnel;
        if self.intercept_dns
            && let Some(q) = first.intercept(packet)
        {
            self.resolver_for(&q.message).answer_query(q);
            return;
        }
        let owner = packet::parse(packet).and_then(|h| {
            let o = h.dst.octets();
            self.members.iter().find(|m| o[..6] == m.prefix)
        });
        let fallback = self
            .members
            .get(self.exit.load(Ordering::Relaxed))
            .unwrap_or(&self.members[0]);
        owner.unwrap_or(fallback).tunnel.packet_in(packet);
    }

    /// Hands the networks IP packets read from the operating system, in order.
    pub fn packets_in<'a>(&self, packets: impl IntoIterator<Item = &'a [u8]>) {
        for packet in packets {
            self.packet_in(packet);
        }
    }

    /// As [`Tunnel::set_resolvers`], for every network.
    pub fn set_resolvers(&self, resolvers: &[std::net::SocketAddr]) {
        for m in &self.members {
            m.tunnel.set_resolvers(resolvers.to_vec());
        }
    }

    /// Reports that the set of usable local paths changed, to every network.
    pub fn path_changed(&self) {
        for m in &self.members {
            m.tunnel.path_changed();
        }
    }

    /// As [`Tunnel::path_update`], for every network.
    pub fn path_update(&self, update: &PathUpdate) {
        for m in &self.members {
            m.tunnel.path_update(update);
        }
    }

    /// Delivers a browse result of the external mDNS backend to every network, each of which
    /// ignores a result that does not carry its tag.
    pub fn mdns_event(&self, event: MdnsEvent) {
        for m in &self.members {
            m.tunnel.mdns_event(event.clone());
        }
    }

    /// Announces a service in a network; `None` names the first.
    pub fn announce(
        &self,
        network: Option<&str>,
        name: &str,
        port: u16,
        proto: Proto,
    ) -> Result<(), NetworkError> {
        Ok(self.member(network)?.tunnel.announce(name, port, proto)?)
    }

    /// Withdraws every service of that name in a network; false if there was none or the network
    /// is unknown.
    pub fn withdraw(&self, network: Option<&str>, name: &str) -> bool {
        self.member(network).is_ok_and(|m| m.tunnel.withdraw(name))
    }

    /// The providers of service `name` in a network, as [`Tunnel::providers_json`].
    pub fn providers_json(
        &self,
        network: Option<&str>,
        name: &str,
    ) -> Result<String, NetworkError> {
        Ok(self.member(network)?.tunnel.providers_json(name))
    }

    /// Stops every network; after it returns no callback runs.
    ///
    /// The networks say goodbye together, and the wait is bounded as for [`Tunnel::stop`], which
    /// also says where it may be called from.
    pub fn stop(&self) {
        let began = self.begin_stop();
        let deadline = Instant::now() + STOP_WAIT;
        for (m, began) in self.members.iter().zip(began) {
            if began {
                m.tunnel
                    .wait_stopped(deadline.saturating_duration_since(Instant::now()));
            }
        }
        self.guard.close();
    }

    /// As [`Networks::stop`], for use on the runtime that runs the networks.
    pub async fn stop_async(&self) {
        let began = self.begin_stop();
        let deadline = Instant::now() + STOP_WAIT;
        for (m, began) in self.members.iter().zip(began) {
            if began {
                let left: Duration = deadline.saturating_duration_since(Instant::now());
                m.tunnel.wait_stopped_async(left).await;
            }
        }
        self.guard.close();
    }

    fn begin_stop(&self) -> Vec<bool> {
        self.members.iter().map(|m| m.tunnel.begin_stop()).collect()
    }
}

impl Drop for Networks {
    fn drop(&mut self) {
        self.begin_stop();
        self.guard.close();
    }
}
