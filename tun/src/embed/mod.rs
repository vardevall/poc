//! Running an interface inside a host that owns the tunnel (vv-06 §3, vv-07).
//!
//! [`Networks`] runs several of them on one runtime for a host that has a single tunnel device
//!. A [`Tunnel`] wires the router, the overlay DNS responder and a [`vardevall::Node`] to
//! four host operations: [`Tunnel::packet_in`] (or [`Tunnel::packets_in`]), [`Tunnel::path_changed`],
//! [`Tunnel::mdns_event`] and [`Tunnel::stop`], and to the callbacks in [`Callbacks`]. It runs on
//! a tokio runtime that the host owns and drives; nothing here blocks that runtime.
//!
//! Packets are IPv6, except the IPv4 of an exit: an exit in use carries IPv4 from
//! the address it gave this node, and an exit this node serves carries its clients' IPv4. Hosts
//! tell the family from the first nibble.

mod event;
mod exits_json;
mod guard;
mod host;
mod json;
mod mdns_json;
mod networks;
mod path_json;
mod pump;
mod relay;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::runtime::Handle as Runtime;
use tokio::sync::{Notify, mpsc};
use vardevall::{
    BuiltinMdns, Handle, LogLevel, MdnsEvent, MdnsMode, MdnsRequest, Node, NodeError, NodeEvent,
    SocketMark, SwitchAuth,
};
pub use vardevall::{Families, Proto, Provider, ServiceError};

pub use self::event::{Event, Status, SwitchKind};
pub use self::exits_json::{ExitsJsonError, exits_from_json};
use self::guard::Guard;
pub use self::guard::{Callbacks, EventFn, MdnsFn, PacketsFn};
pub use self::host::Host;
pub use self::mdns_json::{MdnsJsonError, event_from_json, request_to_json};
pub use self::networks::{
    MAX_NETWORKS, NetworkError, NetworkSpec, Networks, tunnel_settings_networks,
};
pub use self::path_json::{PathJsonError, PathUpdate, path_update_from_json};
use self::relay::Relays;
use crate::config::{Config, ConfigDiff, ConfigError, Context, TurnCredentials};
use crate::dns::{self, Forwarder, Reply, Responder};
pub use crate::router::ExitUse;
use crate::router::{Rejected, Route, Router};
use crate::settings::TunnelSettings;
use vardevall_proto::keys::NodePublic;

/// Longest [`Tunnel::stop`] waits for the engine to finish its goodbyes.
const STOP_WAIT: Duration = Duration::from_millis(500);
/// Capacity of the queues between the engine, the host's threads and the callbacks.
const QUEUE: usize = 512;
/// Most names kept of peers taken away, in case their `removed` events never come.
const MAX_GONE: usize = 64;

/// A tunnel could not start.
#[derive(Debug, Error)]
pub enum StartError {
    /// The interface file is invalid.
    #[error("configuration: {0}")]
    Config(#[from] ConfigError),
    /// The `vardevall` node could not start.
    #[error("node: {0}")]
    Node(#[from] NodeError),
    /// The set of networks is not acceptable.
    #[error("networks: {0}")]
    Networks(String),
    /// Two networks of a set have the same network id.
    #[error("networks {first:?} and {second:?} are the same network")]
    SameNetwork {
        /// The earlier of the two.
        first: String,
        /// The later of the two.
        second: String,
    },
    /// One network of a set could not start.
    #[error("network {name:?}: {source}")]
    Network {
        /// Its name.
        name: String,
        /// Why.
        source: Box<StartError>,
    },
}

/// How the host wants the tunnel run.
#[derive(Debug, Clone)]
pub struct StartOptions {
    /// The interface name, which gives the default domain `<name>.internal` (vv-07 §2.1) and tags
    /// the events. [`Networks`] takes it from each network's name instead.
    pub interface_name: String,
    /// The OS host name, which gives the default own name (vv-06 §4.2).
    pub hostname: Option<String>,
    /// Answer DNS queries to the node's own overlay address found in the packet stream. Hosts
    /// whose operating system delivers such packets locally run [`dns::serve_udp`] instead.
    pub intercept_dns: bool,
    /// Interfaces the built-in mDNS transport must not use, and the watch on the host's addresses
    /// leaves out, such as the tunnel itself.
    pub mdns_exclude: Vec<String>,
    /// The resolvers of the host, for a node that serves an exit to relay its peers' queries to
    /// when the interface file has no `forward`. The library does not read them
    /// from the system.
    pub resolvers: Vec<std::net::SocketAddr>,
    /// The firewall mark of every socket that must not enter the tunnel: the engine's own and
    /// the forwarder's towards the upstream resolvers. Needs Linux and the
    /// `vardevall` crate's `fwmark` feature, else the tunnel does not start.
    pub fwmark: Option<u32>,
    /// Let the node watch the host's addresses for changes itself (vv-05 §4.6), for hosts without
    /// a path monitor to call [`Tunnel::path_changed`].
    pub watch_network: bool,
}

/// How the host expects the node to serve DNS, for hosts whose resolver is the node and cannot be
/// limited to the overlay domains or sent to the node's own address (Android). The
/// default, both off, is the behaviour of the other hosts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostDns {
    /// Answer the queries the host sends to [`resolver_alias`] of the network's `ula`, as those
    /// sent to the node's own addresses: a host that delivers packets for an address of the
    /// tunnel device locally never sends the latter into the tunnel.
    pub resolver_alias: bool,
    /// Relay the queries for names outside every overlay domain to the resolvers set with
    /// [`Tunnel::set_resolvers`], unless an exit in use takes them, whether or not
    /// the file has `forward`.
    pub relay: bool,
}

impl Default for StartOptions {
    fn default() -> Self {
        StartOptions {
            interface_name: "vardevall".to_owned(),
            hostname: None,
            intercept_dns: true,
            mdns_exclude: Vec::new(),
            resolvers: Vec::new(),
            fwmark: None,
            watch_network: false,
        }
    }
}

/// Sends a packet on the session with a peer.
type ToPeer = Box<dyn Fn(&NodePublic, &[u8]) + Send + Sync>;

struct Shared {
    router: Mutex<Router>,
    responder: Arc<Responder>,
    forwarder: Forwarder,
    host_dns: Option<Forwarder>,
    relays: Mutex<Relays>,
    local: mpsc::Sender<Vec<u8>>,
    to_peer: ToPeer,
    intercept_dns: bool,
    resolver_alias: Option<std::net::Ipv6Addr>,
    config_peers: Mutex<Vec<(NodePublic, Option<String>)>>,
    /// Names of peers a configuration read again took away, until their `removed` event is out.
    gone_peers: Mutex<Vec<(NodePublic, Option<String>)>>,
    switch_kinds: Vec<SwitchKind>,
}

#[derive(Default)]
struct Done {
    finished: Mutex<bool>,
    condvar: Condvar,
    notify: Notify,
}

impl Done {
    fn finish(&self) {
        *self.finished.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.condvar.notify_all();
        self.notify.notify_waiters();
    }

    fn is_finished(&self) -> bool {
        *self.finished.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait_blocking(&self, timeout: Duration) {
        let g = self.finished.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = self
            .condvar
            .wait_timeout_while(g, timeout, |done| !*done)
            .unwrap_or_else(PoisonError::into_inner);
    }

    async fn wait(&self, timeout: Duration) {
        let _ = tokio::time::timeout(timeout, async {
            loop {
                let notified = self.notify.notified();
                if self.is_finished() {
                    return;
                }
                notified.await;
            }
        })
        .await;
    }
}

/// The exit a tunnel uses, as `exit` events announce it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInUse {
    /// The site in use.
    pub site: vardevall_proto::ip::site::Site,
    /// The exit chosen for it.
    pub via: NodePublic,
    /// The exit's overlay address, where its resolver listens.
    pub via_addr: std::net::Ipv6Addr,
    /// This node's address in the site, which the host configures on the device.
    pub addr: std::net::Ipv6Addr,
    /// The IPv4 address the exit gave this node, which the host configures on the device with
    /// the default route; `None`: the exit does not carry IPv4.
    pub ipv4: Option<std::net::Ipv4Addr>,
}

/// A configuration could not be applied to a running interface.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApplyError {
    /// Some fields differ that only a restart can change; the running configuration is
    /// unchanged.
    #[error("needs a restart: {}", .0.join(", "))]
    NeedsRestart(Vec<&'static str>),
}

/// A running interface.
pub struct Tunnel {
    shared: Arc<Shared>,
    node: Handle,
    guard: Arc<Guard>,
    done: Arc<Done>,
    stopping: AtomicBool,
    config: Mutex<Arc<Config>>,
    settings: Mutex<TunnelSettings>,
}

fn log(tx: &mpsc::Sender<NodeEvent>, level: LogLevel, message: String) {
    let _ = tx.try_send(NodeEvent::Log { level, message });
}

impl Tunnel {
    /// Starts the interface described by `config_toml` on `runtime` (vv-07 §3).
    ///
    /// The runtime may be single-threaded but must be driven by the host. Callbacks run on tasks
    /// of that runtime, one at a time.
    pub fn start(
        runtime: &Runtime,
        config_toml: &str,
        options: StartOptions,
        callbacks: Callbacks,
    ) -> Result<Tunnel, StartError> {
        let ctx = Context {
            interface_name: options.interface_name.clone(),
            hostname: options.hostname.clone(),
        };
        let config = Config::parse(config_toml, &ctx)?;
        let guard = Arc::new(Guard::new(callbacks));
        Tunnel::start_in(runtime, config, &options, HostDns::default(), guard)
    }

    /// Starts the interface of `config` with callbacks that other tunnels share.
    fn start_in(
        runtime: &Runtime,
        config: Config,
        options: &StartOptions,
        dns: HostDns,
        guard: Arc<Guard>,
    ) -> Result<Tunnel, StartError> {
        let mut config = config;
        config.system_resolvers = options.resolvers.clone();
        let settings = TunnelSettings::for_config(&config);

        let mdns = if !config.mdns {
            MdnsMode::Off
        } else if guard.has_external_mdns() {
            let g = guard.clone();
            MdnsMode::External(Box::new(move |r: MdnsRequest| {
                g.with(|cb| {
                    if let Some(m) = cb.mdns.as_mut() {
                        m(&r);
                    }
                });
            }))
        } else {
            MdnsMode::Builtin(BuiltinMdns {
                interfaces: None,
                exclude: options.mdns_exclude.clone(),
            })
        };

        let (event_tx, event_rx) = mpsc::channel::<NodeEvent>(QUEUE);
        let (local_tx, local_rx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let _enter = runtime.enter();
        let sink_tx = event_tx.clone();
        let mut node_config = config.node_config(mdns);
        node_config.watch_network = options.watch_network;
        node_config.watch_exclude.clone_from(&options.mdns_exclude);
        let mark = options.fwmark.map_or(SocketMark::NONE, SocketMark::new);
        node_config.socket_mark = mark;
        let (node, handle) = Node::new(node_config, move |e: NodeEvent| {
            let _ = sink_tx.try_send(e);
        })?;
        for t in &config.turns {
            if matches!(t.credentials, TurnCredentials::Command(_)) {
                log(
                    &event_tx,
                    LogLevel::Warn,
                    format!(
                        "turn {:?}: credentials_command is not run yet, the server is not used",
                        t.urls
                    ),
                );
            }
        }

        let mut router = Router::new(config.network_id, config.public_key);
        router.set_serving(config.exit.clone());
        for p in &config.peers {
            router.set_keyed(p.public_key);
            match router.add_peer(p.public_key) {
                Ok(()) => {}
                Err(Rejected::Collision) | Err(Rejected::Reserved) | Err(Rejected::Own) => log(
                    &event_tx,
                    LogLevel::Warn,
                    format!(
                        "peer {} cannot use the tun plane: overlay address collision or reserved",
                        p.public_key
                    ),
                ),
            }
        }
        let responder =
            Arc::new(Responder::from_config(&config).with_services(Arc::new(handle.clone())));
        let shared = Arc::new(Shared {
            router: Mutex::new(router),
            responder,
            forwarder: Forwarder::new(config.upstreams(), runtime.clone()).with_mark(mark),
            host_dns: dns
                .relay
                .then(|| Forwarder::new(Vec::new(), runtime.clone())),
            relays: Mutex::new(Relays::new()),
            local: local_tx,
            to_peer: {
                let node = handle.clone();
                Box::new(move |peer, packet| {
                    node.send_packet(peer, packet);
                })
            },
            intercept_dns: options.intercept_dns,
            resolver_alias: dns
                .resolver_alias
                .then(|| resolver_alias(config.own_addrs().ula)),
            gone_peers: Mutex::default(),
            config_peers: Mutex::new(
                config
                    .peers
                    .iter()
                    .map(|p| (p.public_key, p.name.clone()))
                    .collect(),
            ),
            switch_kinds: config
                .switches
                .iter()
                .map(|s| match s.auth {
                    SwitchAuth::Pinned(_) => SwitchKind::Pinned,
                    SwitchAuth::Web { .. } => SwitchKind::Web,
                })
                .collect(),
        });
        let done = Arc::new(Done::default());
        runtime.spawn(node.run());
        runtime.spawn(pump::pump(
            shared.clone(),
            guard.clone(),
            done.clone(),
            event_rx,
            local_rx,
            options.interface_name.as_str().into(),
            config.network_id,
        ));
        Ok(Tunnel {
            shared,
            node: handle,
            guard,
            done,
            stopping: AtomicBool::new(false),
            config: Mutex::new(Arc::new(config)),
            settings: Mutex::new(settings),
        })
    }

    /// Hands the tunnel an IP packet read from the operating system (vv-06 §3.1); IPv4 is told
    /// from IPv6 by the first nibble and is only carried for an exit.
    pub fn packet_in(&self, packet: &[u8]) {
        let s = &self.shared;
        if s.intercept_dns
            && let Some(q) = self.intercept(packet)
        {
            self.answer_query(q);
            return;
        }
        let route = s
            .router
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .route(packet);
        self.dispatch(route, packet);
    }

    /// The query in `packet` if it is addressed to the node's own address or its resolver alias.
    fn intercept(&self, packet: &[u8]) -> Option<dns::Query> {
        let s = &self.shared;
        dns::intercept(packet, s.responder.own_addrs()).or_else(|| {
            s.resolver_alias
                .and_then(|alias| dns::intercept_at(packet, &alias))
        })
    }

    fn dispatch(&self, route: Route, packet: &[u8]) {
        match route {
            Route::Unicast(peer) => {
                self.node.send_packet(&peer, packet);
            }
            Route::Multicast(peers) => {
                for p in peers {
                    self.node.send_packet(&p, packet);
                }
            }
            Route::Reply(p) => {
                let _ = self.shared.local.try_send(p);
            }
            Route::Drop => {}
        }
    }

    /// Relays the host's query `q` to the resolver at `via` as a packet of the engine's own,
    /// routed like one read from the host; its reply is taken by the pump.
    /// Dropped if too many are pending or the router has no peer for `via`.
    fn relay_through_engine(&self, q: &dns::Query, via: std::net::Ipv6Addr, message: &[u8]) {
        let s = &self.shared;
        let port = s
            .relays
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .start(Instant::now(), via, q, message);
        let Some(port) = port else { return };
        let own = s.responder.own_addrs().ula;
        let packet = crate::packet::build_udp(&own, &via, port, 53, message);
        let route = s
            .router
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .route(&packet);
        match route {
            Route::Unicast(_) => self.dispatch(route, &packet),
            _ => s
                .relays
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .cancel(port),
        }
    }

    /// Answers a DNS query found in the packet stream, with the reply written back to the host.
    fn answer_query(&self, q: dns::Query) {
        let s = &self.shared;
        match s.responder.respond_from(&q.message, None) {
            Reply::Answer(a) => match &s.host_dns {
                Some(host) if s.responder.is_outside(&q.message) => {
                    let tx = s.local.clone();
                    if host.upstreams().is_empty() {
                        let _ = tx.try_send(dns::reply_packet(&q, &server_failure(a)));
                    } else {
                        let reply = q.clone();
                        host.spawn(q.message, move |r| {
                            let _ = tx.try_send(dns::reply_packet(&reply, &r));
                        });
                    }
                }
                _ => {
                    let _ = s.local.try_send(dns::reply_packet(&q, &a));
                }
            },
            Reply::Relay(dns::Relay {
                query,
                via: Some(std::net::SocketAddr::V6(via)),
                ..
            }) => self.relay_through_engine(&q, *via.ip(), &query),
            Reply::Relay(r) => {
                let tx = s.local.clone();
                s.forwarder.relay(r, move |a| {
                    let _ = tx.try_send(dns::reply_packet(&q, &a));
                });
            }
            Reply::Forward(msg) => {
                let tx = s.local.clone();
                let (responder, query) = (s.responder.clone(), msg.clone());
                s.forwarder.spawn(msg, move |r| {
                    let r = responder.after_forward(&query, r);
                    let _ = tx.try_send(dns::reply_packet(&q, &r));
                });
            }
            Reply::Drop => {}
        }
    }

    /// Sets whether this network carries the host's traffic outside the overlay:
    /// `None` is off. Packets whose destination is outside the overlay then go to the exit
    /// chosen for the site in use, announced by the `exit` events. The node also connects to the
    /// peers held by key and keeps the exits of the site connected while the use lasts
    ///.
    pub fn set_exit(&self, using: Option<ExitUse>) {
        let mut router = self
            .shared
            .router
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        router.set_exit_use(using.clone());
        self.shared
            .responder
            .set_exit(router.exit_in_use().map(|(_, via)| via).as_ref());
        drop(router);
        self.node.set_exit(using);
    }

    /// Sets the resolvers of the host that [`HostDns::relay`] relays to, in the order they are
    /// tried, replacing the ones before. The host changes them with its network; the address of
    /// a link-local resolver carries its scope. The sockets that ask them are the engine's own,
    /// so the host keeps them out of the tunnel.
    pub fn set_resolvers(&self, resolvers: Vec<std::net::SocketAddr>) {
        if let Some(host) = &self.shared.host_dns {
            host.set_upstreams(resolvers);
        }
    }

    /// Gives back the offers an earlier run reported in [`Event::Exits`], so that
    /// the exits are known before any handshake and a use reaches them first.
    pub fn remember_exits(&self, offers: Vec<(NodePublic, vardevall_proto::ip::site::Site)>) {
        self.node.remember_exits(offers);
    }

    /// The IPv4 address this node configures before an exit gives one: the one
    /// every exit of the network gives it unless another client holds it.
    pub fn home_ipv4(&self) -> std::net::Ipv4Addr {
        let config = self.config();
        vardevall::home_ipv4(&config.network_id, &config.public_key)
    }

    /// Sets whether the host of the exit this node serves has an IPv6 route to the internet
    ///; on by default and kept across changes of the exit. While it has not, the
    /// router answers its peers' native IPv6 to the internet with "no route". The library does
    /// not detect it: the host decides and calls this at start and when its routes change.
    pub fn set_ipv6_uplink(&self, on: bool) {
        self.shared
            .router
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set_ipv6_uplink(on);
    }

    /// The exit in use and what the host configures for it, or `None` while this network does
    /// not use an exit or has no live one for the site.
    pub fn exit_in_use(&self) -> Option<ExitInUse> {
        let router = self
            .shared
            .router
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (site, chosen) = router.exit_chosen()?;
        let config = self.config();
        Some(ExitInUse {
            site: site.clone(),
            via: chosen.peer,
            via_addr: vardevall_proto::addr::OverlayAddrs::derive(&config.network_id, &chosen.peer)
                .ula,
            addr: router.site_addr(site),
            ipv4: chosen.ipv4,
        })
    }

    /// Hands the tunnel IP packets read from the operating system, in order, each as
    /// [`Tunnel::packet_in`] does.
    pub fn packets_in<'a>(&self, packets: impl IntoIterator<Item = &'a [u8]>) {
        for packet in packets {
            self.packet_in(packet);
        }
    }

    /// Reports that the set of usable local paths changed (vv-05 §4.6).
    pub fn path_changed(&self) {
        self.node.path_changed();
    }

    /// Records which interfaces the platform marks as expensive or constrained (vv-05 §2.2) and,
    /// if `update.changed`, reports a path change as [`Tunnel::path_changed`] does.
    pub fn path_update(&self, update: &PathUpdate) {
        if let Some(m) = update.metered {
            self.node.set_metered(m);
        }
        if update.changed {
            self.node.path_changed_for(update.families);
        }
    }

    /// Announces a service to the peers, replacing one of the same name and transport (vve-14
    /// §2.1). The `[[service]]` entries of the file are announced from the start.
    pub fn announce(&self, name: &str, port: u16, proto: Proto) -> Result<(), ServiceError> {
        self.node.announce(name, port, proto)
    }

    /// Withdraws every service of that name; returns whether there was one.
    pub fn withdraw(&self, name: &str) -> bool {
        self.node.withdraw(name)
    }

    /// The providers of service `name`, in the order of the resolver's answers (vve-14 §3).
    pub fn providers(&self, name: &str) -> Vec<Provider> {
        self.node.providers(name)
    }

    /// [`Tunnel::providers`] as JSON: `[{"key","addr","name","port","proto","live"},…]`.
    pub fn providers_json(&self, name: &str) -> String {
        providers_json(
            &self.config(),
            &self.shared.responder,
            &self.node.providers(name),
        )
    }

    /// Delivers a browse result of the external mDNS backend (vv-09 §2).
    pub fn mdns_event(&self, event: MdnsEvent) {
        self.node.mdns_event(event);
    }

    /// The tunnel settings for the configuration in effect.
    pub fn settings(&self) -> TunnelSettings {
        self.settings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The validated configuration in effect: the one the tunnel started with, or the last that
    /// [`Tunnel::apply`] took.
    pub fn config(&self) -> Arc<Config> {
        self.config
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Takes a configuration read again while the interface runs, keeping the sessions of the
    /// peers whose entries did not change. What differs is in the returned [`ConfigDiff`]. A
    /// difference that needs a restart (the keys, the port, the MTU, the switches, the mDNS and
    /// delivery settings; see [`ConfigDiff`]) refuses the whole configuration with the names
    /// of its fields and leaves the running one as it was.
    ///
    /// The tunnel's addresses, MTU and resolver address cannot change here; a changed domain is
    /// in [`Tunnel::settings`] for the host to apply.
    pub fn apply(&self, new: Config) -> Result<ConfigDiff, ApplyError> {
        let mut new = new;
        let old = self.config();
        new.system_resolvers.clone_from(&old.system_resolvers);
        let diff = ConfigDiff::between(&old, &new);
        if diff.needs_restart() {
            return Err(ApplyError::NeedsRestart(diff.restart));
        }
        if diff.is_empty() {
            return Ok(diff);
        }
        let s = &self.shared;
        {
            let mut gone = s.gone_peers.lock().unwrap_or_else(PoisonError::into_inner);
            for (key, name) in &diff.peers_removed {
                gone.push((*key, name.clone()));
            }
            let excess = gone.len().saturating_sub(MAX_GONE);
            gone.drain(..excess);
        }
        *s.config_peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = new
            .peers
            .iter()
            .map(|p| (p.public_key, p.name.clone()))
            .collect();
        {
            let mut router = s.router.lock().unwrap_or_else(PoisonError::into_inner);
            if diff.exit {
                router.set_serving(new.exit.clone());
            }
            for p in &new.peers {
                router.set_keyed(p.public_key);
            }
        }
        s.responder.reconfigure(&new);
        s.forwarder.set_upstreams(new.upstreams());
        self.apply_services(&old, &new);
        self.node.update(vardevall::LiveUpdate {
            peers: new.peer_specs(),
            exit: new.exit.clone(),
            stun: new.stun.clone(),
            turn: new.turn_specs(),
        });
        *self.settings.lock().unwrap_or_else(PoisonError::into_inner) =
            TunnelSettings::for_config(&new);
        *self.config.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(new);
        Ok(diff)
    }

    fn apply_services(&self, old: &Config, new: &Config) {
        let gone: Vec<&str> = old
            .services
            .iter()
            .filter(|s| !new.services.contains(s))
            .map(|s| s.name())
            .collect();
        for name in &gone {
            self.node.withdraw(name);
        }
        for s in &new.services {
            if !old.services.contains(s) || gone.contains(&s.name()) {
                let _ = self.node.announce(s.name(), s.port(), s.proto());
            }
        }
    }

    /// The overlay DNS responder, for hosts that serve it on a socket themselves.
    pub fn responder(&self) -> Arc<Responder> {
        self.shared.responder.clone()
    }

    /// The UDP port of the interface socket.
    pub fn listen_port(&self) -> u16 {
        self.node.local_addr().port()
    }

    /// Asks the engine to stop; false if it had been asked before.
    fn begin_stop(&self) -> bool {
        if self.stopping.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.node.stop();
        true
    }

    /// Waits up to `timeout` for the engine to finish its goodbyes.
    fn wait_stopped(&self, timeout: Duration) {
        self.done.wait_blocking(timeout);
    }

    /// As [`Tunnel::wait_stopped`], on the runtime.
    async fn wait_stopped_async(&self, timeout: Duration) {
        self.done.wait(timeout).await;
    }

    /// Stops the tunnel; after it returns no callback runs.
    ///
    /// Blocks up to half a second for the engine to withdraw its mDNS announcements, so it must
    /// not be called from a thread that drives the runtime, nor from inside a callback (use
    /// [`Tunnel::stop_async`] on the runtime). Called from inside a callback, it suppresses all
    /// later callbacks without waiting.
    pub fn stop(&self) {
        if self.begin_stop() {
            self.wait_stopped(STOP_WAIT);
        }
        self.guard.close();
    }

    /// As [`Tunnel::stop`], for use on the runtime that runs the tunnel.
    pub async fn stop_async(&self) {
        if self.begin_stop() {
            self.wait_stopped_async(STOP_WAIT).await;
        }
        self.guard.close();
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.begin_stop();
        self.guard.close();
    }
}

/// The address of the overlay `/64` of `ula` where a host that cannot send queries to its own
/// address sends them (see [`HostDns::resolver_alias`]): `<ula /64>::53`.
pub fn resolver_alias(ula: std::net::Ipv6Addr) -> std::net::Ipv6Addr {
    let mut octets = ula.octets();
    octets[8..].fill(0);
    octets[15] = 0x53;
    octets.into()
}

/// `reply`, a refusal, as the answer that tells the resolver the query cannot be served now.
fn server_failure(mut reply: Vec<u8>) -> Vec<u8> {
    if let Some(flags) = reply.get_mut(3) {
        *flags = (*flags & 0xf0) | 2;
    }
    reply
}

/// Parses the transport of a service: `"tcp"` or `"udp"` (vve-14 §2.1).
pub fn proto_from_str(text: &str) -> Option<Proto> {
    match text {
        "tcp" => Some(Proto::Tcp),
        "udp" => Some(Proto::Udp),
        _ => None,
    }
}

fn providers_json(config: &Config, responder: &Responder, providers: &[Provider]) -> String {
    let list: Vec<_> = providers
        .iter()
        .map(|p| {
            let addr = vardevall_proto::addr::OverlayAddrs::derive(&config.network_id, &p.key).ula;
            (p, addr, responder.name(&p.key))
        })
        .collect();
    json::providers(&list)
}

/// Settings for a configuration without starting anything (`vv_tunnel_settings`).
pub fn tunnel_settings(config_toml: &str, ctx: &Context) -> Result<TunnelSettings, ConfigError> {
    Config::parse(config_toml, ctx).map(|c| TunnelSettings::for_config(&c))
}
