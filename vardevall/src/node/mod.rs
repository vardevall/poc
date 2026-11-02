//! The runtime node: one task driving `proto`'s node over the interface socket
//! (vv-03 §2, vv-05 §4).
//!
//! [`Node::run`] owns the owners of the state. It feeds datagrams, timers and embedder packets to
//! [`proto::node::Node`](vardevall_proto::node::Node), carries out its outputs, and hands
//! candidate updates from the [`crate::candidates`] sources to it.

mod changes;
mod exit;
mod held;
mod inputs;
mod live;
mod media;
mod outputs;
mod services;
mod view;

use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::time::{Instant as TokioInstant, sleep_until};
use vardevall_proto::node::{Config, PeerConfig};
use vardevall_proto::plane::frame;
use vardevall_proto::route::{Config as RouteConfig, DeliveryClass, LocalChanges};

use crate::handle::{self, Handle, Receivers};
pub(crate) use exit::ExitShared;
use held::Held;
use media::{Media, SwitchMedium};
pub(crate) use services::Shared;

use crate::candidates::{CandidateSource, MdnsSource, StaticSource, Update};
use crate::clock::{Clock, unix_seconds};
use crate::config::{MdnsMode, NodeConfig, PeerSpec, SwitchPath};
use crate::error::NodeError;
use crate::event::{EventSink, LogLevel, NodeEvent, Status};
use crate::mdns::builtin::BuiltinTransport;
use crate::mdns::external::ExternalMdns;
use crate::mdns::{Discovery, MdnsTransport};
use crate::net::mark;
use crate::net::resolver::Resolver;
use crate::net::rng::{OsRng, os_rng};
use crate::net::watch::NetworkWatch;
use crate::stun::Stun;
use crate::switch::{SwitchId, Switches};
use crate::turn::{Turn, TurnMedium};
use crate::udp::Udp;
use vardevall_proto::ip::exit::ExitServe;
use vardevall_proto::keys::NodePublic;

/// Datagrams handled per wake-up before the other inputs get a turn.
const RECV_BATCH: usize = 32;

/// A node: the core, the transports it carries datagrams over and the candidate sources.
pub struct Node {
    core: vardevall_proto::node::Node,
    media: Media,
    udp: Udp,
    stun: Stun,
    turn: Turn,
    rng: OsRng,
    clock: Clock,
    sink: Box<dyn EventSink>,
    rx: Receivers,
    sources: Vec<Box<dyn CandidateSource>>,
    next_source: usize,
    switches: Switches,
    resolver: Resolver,
    tun_class: DeliveryClass,
    accept_members: bool,
    local_metered: bool,
    changes: LocalChanges,
    shared: Arc<Mutex<Shared>>,
    exit_shared: Arc<Mutex<ExitShared>>,
    watch: Option<NetworkWatch>,
    held: Held,
    view: view::Reporter,
    buf: Vec<u8>,
    specs: Vec<PeerSpec>,
    serving: Option<ExitServe>,
    online: Vec<(SwitchId, NodePublic)>,
}

fn build_transport(
    config: MdnsMode,
    network_id: &vardevall_proto::keys::NetworkId,
    mark: mark::SocketMark,
) -> (Option<Box<dyn MdnsTransport>>, Option<String>) {
    match config {
        MdnsMode::Off => (None, None),
        MdnsMode::External(sink) => (Some(Box::new(ExternalMdns::new(sink))), None),
        MdnsMode::Builtin(b) => {
            let prefix = vardevall_proto::addr::ula_prefix(network_id);
            match BuiltinTransport::new(b, prefix, mark) {
                Ok(t) => (Some(Box::new(t)), None),
                Err(e) => (None, Some(format!("mDNS disabled: {e}"))),
            }
        }
    }
}

impl Node {
    /// Binds the socket and prepares the engine; run it with [`Node::run`].
    ///
    /// Must be called inside a tokio runtime context, which may be single-threaded.
    pub fn new(
        config: NodeConfig,
        sink: impl EventSink + 'static,
    ) -> Result<(Node, Handle), NodeError> {
        if config.mtu < 1280 || config.mtu > 65_535 - frame::FRAME_OVERHEAD {
            return Err(NodeError::Config("mtu out of range"));
        }
        let network_id = config
            .network_id
            .unwrap_or_else(|| config.network_secret.default_network_id());
        if config.socket_mark.value().is_some() && !mark::SUPPORTED {
            return Err(NodeError::Config(
                "socket marks need Linux and the fwmark feature",
            ));
        }
        let udp = Udp::bind(config.listen_port, config.socket_mark).map_err(NodeError::Bind)?;
        let local = udp
            .local_addr()
            .ok_or(NodeError::Config("socket without an address"))?;
        let shared = Arc::new(Mutex::new(Shared::default()));
        let exit_shared = Arc::new(Mutex::new(ExitShared::default()));
        let (handle, rx) = handle::channel(local, shared.clone(), exit_shared.clone());

        let clock = Clock::new();
        let mut rng = os_rng();
        let own = config.secret.public();
        let switch_specs = config.switches.clone();
        let routes = RouteConfig {
            fallback_delay: config.fallback_delay,
            detect_timeout: config.detect_timeout,
            switch_data: config.switch_path == SwitchPath::On,
            ..RouteConfig::default()
        };
        let switches = Switches::start(
            &switch_specs,
            &config.secret,
            &config.network_secret,
            clock,
            config.socket_mark,
        )?;
        let resolver = Resolver::start(&config.stun, &config.turn, config.socket_mark);
        let mut core_config = Config::new(config.secret, config.network_secret.clone());
        core_config.network_id = Some(network_id);
        core_config.accept_members = config.accept_members;
        core_config.mtu = config.mtu;
        core_config.routes = routes;
        core_config.exit = config.exit.clone();
        let now = clock.now();
        let mut core = vardevall_proto::node::Node::new(core_config, now, &mut rng);
        let udp_id = core.add_transport(Arc::new(udp.medium()));
        let turn = core.add_transport(Arc::new(TurnMedium));
        let switch_ids = switch_specs
            .iter()
            .map(|spec| {
                let id = core.add_transport(Arc::new(SwitchMedium::new(spec.label())));
                core.set_ready(now, &mut rng, id, false);
                id
            })
            .collect();
        let media = Media {
            udp: udp_id,
            turn,
            switches: switch_ids,
        };

        let specs: Vec<PeerSpec> = config
            .peers
            .into_iter()
            .filter(|p| p.public != own)
            .collect();
        for p in &specs {
            let mut pc = PeerConfig::new(p.public);
            if let Some(psk) = &p.psk {
                pc.psk = psk.clone();
            }
            core.add_peer(pc, now.instant);
        }

        {
            let mut shared = shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for s in config.services {
                if let Some(i) = shared
                    .own
                    .iter()
                    .position(|x| x.name() == s.name() && x.proto() == s.proto())
                {
                    shared.own[i] = s;
                } else if shared.own.len() < vardevall_proto::ip::service::MAX_SERVICES {
                    shared.own.push(s);
                }
            }
            shared.own_changed = true;
        }
        let mut node = Node {
            core,
            media,
            udp,
            stun: Stun::default(),
            turn: Turn::new(config.fallback_delay, config.socket_mark),
            rng,
            clock,
            sink: Box::new(sink),
            rx,
            sources: vec![Box::new(StaticSource::new(
                &specs,
                config.dns_servers,
                config.socket_mark,
            ))],
            next_source: 0,
            switches,
            resolver,
            tun_class: config.tun_class,
            accept_members: config.accept_members,
            local_metered: false,
            changes: LocalChanges::new(),
            shared,
            exit_shared,
            watch: config.watch_network.then(|| {
                NetworkWatch::new(
                    vardevall_proto::addr::ula_prefix(&network_id),
                    config.watch_exclude,
                )
            }),
            held: Held::default(),
            view: view::Reporter::new(),
            buf: vec![0u8; (config.mtu + 128).max(2048)],
            specs: specs.clone(),
            serving: config.exit,
            online: Vec::new(),
        };
        let (transport, warning) = build_transport(config.mdns, &network_id, config.socket_mark);
        if let Some(w) = warning {
            node.log(LogLevel::Warn, w);
        }
        if let Some(t) = transport {
            let discovery = Discovery::new(
                config.network_secret,
                own,
                local.port(),
                config.accept_members,
                specs.iter().map(|p| p.public).collect(),
                unix_seconds(),
            );
            node.sources.push(Box::new(MdnsSource::new(discovery, t)));
        }
        node.sources.extend(config.discovery);
        Ok((node, handle))
    }

    /// Runs the node until [`Handle::stop`] is called.
    pub async fn run(mut self) {
        let listen = self
            .udp
            .local_addr()
            .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
        self.sink
            .event(NodeEvent::Status(Status::Started { listen }));
        self.drain();
        self.sync_services();
        loop {
            self.drain();
            self.view_tick();
            if self
                .rx
                .signals
                .stop
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                break;
            }
            let wake = self.next_wake();
            tokio::select! {
                r = poll_fn(|cx| self.udp.poll_recv(cx, &mut self.buf)) => {
                    if let Some((n, from)) = r {
                        self.on_datagram(n, from);
                        self.recv_more();
                    }
                }
                Some((peer, packet)) = self.rx.packets.recv() => {
                    self.on_packet(peer, packet);
                }
                event = poll_fn(|cx| self.turn.poll_link(cx)) => {
                    self.on_link_event(event);
                }
                Some(msg) = self.switches.recv() => {
                    self.on_switch_msg(msg);
                }
                Some(resolved) = self.resolver.recv() => {
                    self.on_resolved(resolved);
                }
                Some(input) = self.rx.control.recv() => {
                    for s in &mut self.sources {
                        s.input(input.clone());
                    }
                }
                families = poll_fn(|cx| match self.watch.as_mut() {
                    Some(w) => w.poll_change(cx),
                    None => Poll::Pending,
                }) => {
                    self.on_local_change(families);
                }
                () = self.rx.signals.notify.notified() => {
                    let families = self.rx.signals.take_changed();
                    if !families.is_empty() {
                        self.on_local_change(families);
                    }
                    self.sync_services();
                    self.sync_exit();
                    self.sync_update();
                    if self.rx.signals.metered_changed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                        let metered = self.rx.signals.metered.load(std::sync::atomic::Ordering::SeqCst);
                        self.on_metered(metered);
                    }
                }
                update = poll_fn(|cx| poll_sources(&mut self.sources, &mut self.next_source, cx)) => {
                    self.on_update(update);
                }
                () = sleep_until(wake) => {
                    self.on_timeout();
                }
            }
        }
        self.switches.stop();
        self.resolver.stop();
        for s in &mut self.sources {
            s.stop();
        }
        self.sink.event(NodeEvent::Status(Status::Stopped));
    }

    fn log(&mut self, level: LogLevel, message: String) {
        self.sink.event(NodeEvent::Log { level, message });
    }

    fn next_wake(&self) -> TokioInstant {
        [
            self.core.poll_timeout(),
            self.stun.poll_timeout(),
            self.turn.poll_timeout(),
            self.held.poll_timeout(),
            self.changes.poll_timeout(),
        ]
        .into_iter()
        .flatten()
        .min()
        .map(|t| self.clock.tokio_instant(t))
        .into_iter()
        .chain(self.view.wake())
        .min()
        .unwrap_or_else(|| TokioInstant::now() + std::time::Duration::from_secs(3600))
    }

    fn recv_more(&mut self) {
        for _ in 1..RECV_BATCH {
            match self.udp.try_recv(&mut self.buf) {
                Some((n, from)) => self.on_datagram(n, from),
                None => break,
            }
        }
    }
}

fn poll_sources(
    sources: &mut [Box<dyn CandidateSource>],
    next: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<Update> {
    let n = sources.len();
    for i in 0..n {
        let idx = (*next + i) % n;
        if let Poll::Ready(u) = sources[idx].poll_update(cx) {
            *next = (idx + 1) % n;
            return Poll::Ready(u);
        }
    }
    Poll::Pending
}
