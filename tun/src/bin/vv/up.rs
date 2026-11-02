//! `vv up`: the tunnel device, addresses, resolver and the node (vv-07 §5.2).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, UdpSocket};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use vardevall::SocketMark;
use vardevall::view::Route;
use vardevall::{LogLevel, PeerState, Reason, SwitchFailure, SwitchState, Trust};
use vardevall_proto::addr::reverse_zone;
use vardevall_proto::ip::site::Site;
use vardevall_proto::keys::NodePublic;
use vardevall_tun::config::Config;
use vardevall_tun::dns::{Forwarder, serve_tcp, serve_udp};
use vardevall_tun::embed::{
    Callbacks, Event, ExitUse, StartOptions, Status, Tunnel, exits_from_json,
};
use vardevall_tun::files::{self, hostname};
use vardevall_tun::numbering::Numbering;

use crate::control;
use crate::netcfg::{Resolver, configure_interface};
use crate::resolv;
use crate::tun::Tun;
use crate::uplink;

/// macOS sends packets for the interface's own addresses into the tunnel instead of looping them
/// back, so the resolver reads its queries from the packet stream; elsewhere it binds a socket.
const INTERCEPT_DNS: bool = cfg!(target_os = "macos");

/// The log line of the engine when a change of the host's addresses has settled.
const PATH_CHANGED: &str = "local path changed";

/// Loads and validates the file of an interface name or path.
pub fn load(target: &str) -> Result<Config> {
    Ok(files::load(target)?)
}

fn short(key: &str) -> &str {
    &key[..key.len().min(8)]
}

fn who(key: &NodePublic, name: &Option<String>) -> String {
    name.clone()
        .unwrap_or_else(|| short(&key.to_base32()).to_owned())
}

fn describe(f: SwitchFailure) -> &'static str {
    match f {
        SwitchFailure::Unreachable => "unreachable, retrying",
        SwitchFailure::Untrusted => "the switch does not present the configured key",
        SwitchFailure::TokenRejected => "operator token missing or wrong",
        SwitchFailure::Rejected => "registration refused, check the network secret",
        SwitchFailure::RateLimited => "rate limited, retrying",
        SwitchFailure::Replaced => "another client uses this node key",
        SwitchFailure::Protocol => "unexpected answer",
    }
}

fn why(r: Reason) -> &'static str {
    match r {
        Reason::Idle => "idle",
        Reason::Unreachable => "unreachable",
    }
}

fn print_event(verbose: bool, e: &Event) {
    match e {
        Event::Status(Status::Started { listen_port }) => {
            eprintln!("listening on UDP port {listen_port}")
        }
        Event::Status(Status::Stopped) => eprintln!("stopped"),
        Event::Added {
            key,
            name,
            addr,
            trust,
        } => {
            let what = match trust {
                Trust::Key => "added (configured)",
                Trust::Member => "added (member)",
            };
            eprintln!("peer {} [{addr}]: {what}", who(key, name));
        }
        Event::Removed { key, name, addr } => {
            eprintln!("peer {} [{addr}]: removed", who(key, name));
        }
        Event::Peer {
            key,
            name,
            addr,
            state,
        } => {
            let what = match state {
                PeerState::Idle => "idle".to_owned(),
                PeerState::Connecting => "connecting".to_owned(),
                PeerState::Up { initiator } => {
                    format!(
                        "up ({})",
                        if *initiator { "initiator" } else { "responder" }
                    )
                }
                PeerState::Down(r) => format!("down ({})", why(*r)),
            };
            eprintln!("peer {} [{addr}]: {what}", who(key, name));
        }
        Event::Route {
            key,
            name,
            addr,
            route,
        } => {
            let what = match route {
                None => "no route".to_owned(),
                Some(Route::Lan(a)) => format!("route lan {a}"),
                Some(Route::Internet(a)) => format!("route internet {a}"),
                Some(Route::PeerRelay(a)) => format!("route peer relay {a}"),
                Some(Route::OwnRelay(a)) => format!("route own relay {a}"),
                Some(Route::Switch(id)) => format!("route via switch {}", id.0 + 1),
            };
            eprintln!("peer {} [{addr}]: {what}", who(key, name));
        }
        Event::Exit {
            site,
            via,
            addr,
            ipv4,
        } => match via {
            Some(k) => eprintln!(
                "exit {site}: via {} [{addr}]{}",
                who(k, &None),
                ipv4.map_or(String::new(), |a| format!(", IPv4 {a}"))
            ),
            None => eprintln!("exit {site}: none left"),
        },
        Event::Exits { offers } => {
            if verbose {
                eprintln!("exits remembered: {}", offers.len());
            }
        }
        Event::Switch {
            address,
            kind,
            state,
        } => {
            let what = match state {
                SwitchState::Connecting => "connecting".to_owned(),
                SwitchState::Registered => "registered".to_owned(),
                SwitchState::Disconnected(f) => format!("not registered: {}", describe(*f)),
            };
            eprintln!("switch {address} ({}): {what}", kind.name());
        }
        Event::Budget { transport, budget } => match budget {
            Some(b) => eprintln!(
                "transport {transport}: budget {} of {} bytes left ({:?})",
                b.remaining,
                b.total,
                b.level()
            ),
            None => eprintln!("transport {transport}: no budget"),
        },
        // Drawn by the apps; a text rendering for `vv` is still to come.
        Event::View { .. } => {}
        Event::Log { level, message } => {
            if verbose || *level >= LogLevel::Info {
                eprintln!("{level:?}: {message}");
            }
        }
    }
}

/// What `vv up` was asked beyond the interface.
pub struct Options {
    /// Log debug lines.
    pub verbose: bool,
    /// Use an exit from the start: the site, or empty for the network's only one.
    pub exit: Option<String>,
    /// The firewall mark of the engine's sockets (Linux); none takes the interface's own
    ///.
    pub fwmark: Option<u32>,
    /// The control socket, if not the default.
    pub control_socket: Option<PathBuf>,
}

/// The name of the interface a name or path stands for.
pub fn interface_name(target: &str) -> Result<String> {
    Ok(files::locate(target)?.1)
}

fn exit_use(text: &str) -> Result<ExitUse> {
    let site = (!text.is_empty())
        .then(|| text.parse::<Site>())
        .transpose()
        .with_context(|| format!("--exit {text}"))?;
    Ok(ExitUse { site })
}

/// Where the offers remembered across restarts are kept: the directory systemd
/// gives the unit (`StateDirectory=`), else `/var/lib/vardevall`.
fn exits_path(interface: &str) -> PathBuf {
    let dir = std::env::var_os("STATE_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/vardevall"));
    dir.join(format!("{interface}.exits.json"))
}

/// Keeps the last `view` event and its sites for the control socket, and writes the offers of the
/// `exits` events to `exits`; a failure to write is logged and changes nothing else.
fn notice(
    sites: &Mutex<Vec<serde_json::Value>>,
    view: &Mutex<Option<Event>>,
    exits: &Path,
    network: &str,
    e: &Event,
) {
    let json = || match serde_json::from_str(&e.to_json(network)) {
        Ok(serde_json::Value::Object(v)) => Some(v),
        _ => None,
    };
    match e {
        Event::View { .. } => {
            *view.lock().unwrap_or_else(PoisonError::into_inner) = Some(e.clone());
            if let Some(mut v) = json()
                && let Some(serde_json::Value::Array(list)) = v.remove("sites")
            {
                *sites.lock().unwrap_or_else(PoisonError::into_inner) = list;
            }
        }
        Event::Exits { .. } => {
            let Some(offers) = json().and_then(|mut v| v.remove("offers")) else {
                return;
            };
            let written = exits
                .parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| std::fs::write(exits, offers.to_string()));
            if let Err(err) = written {
                eprintln!(
                    "warning: cannot keep the exits in {}: {err}",
                    exits.display()
                );
            }
        }
        _ => {}
    }
}

/// The offers an earlier run kept, if any.
fn remembered(exits: &Path) -> Vec<(NodePublic, Site)> {
    let Ok(text) = std::fs::read_to_string(exits) else {
        return Vec::new();
    };
    exits_from_json(&text).unwrap_or_else(|err| {
        eprintln!("warning: {}: {err}", exits.display());
        Vec::new()
    })
}

pub fn run(target: &str, options: Options) -> Result<()> {
    let verbose = options.verbose;
    let (path, name) = files::locate(target)?;
    let text = files::read_checked(&path)?;
    let config = files::parse(&text, &path, &name)?;
    let fwmark = options
        .fwmark
        .unwrap_or_else(|| Numbering::for_interface(&name).mark());
    let addrs = config.own_addrs();
    let start_use = options.exit.as_deref().map(exit_use).transpose()?;
    let socket_path = options
        .control_socket
        .unwrap_or_else(|| control::default_path(&name));

    let tun =
        Arc::new(Tun::create(&config.name).context("creating the tunnel device (needs root)")?);
    configure_interface(tun.name(), &addrs, config.mtu)?;
    if let Some(serve) = &config.exit {
        eprintln!(
            "serving the exit of site {}: vv does not set the host up, `vv-quick up {name}` does",
            serve.site
        );
    }
    eprintln!(
        "interface {} up: {} and {}, domain {}",
        tun.name(),
        addrs.ula,
        addrs.link_local,
        config.domain
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let (listener, _socket) = control::bind(&socket_path)?;
        let (path_changed, path_wake) = mpsc::channel::<()>(1);
        let sites = Arc::new(Mutex::new(Vec::new()));
        let view = Arc::new(Mutex::new(None));
        let exits = exits_path(&name);

        let writer = tun.clone();
        let (seen_sites, seen_view, seen_exits, network) =
            (sites.clone(), view.clone(), exits.clone(), name.clone());
        let callbacks = Callbacks {
            packets: Box::new(move |packets| {
                for p in packets {
                    let _ = writer.write(p);
                }
            }),
            event: Box::new(move |_, e| {
                notice(&seen_sites, &seen_view, &seen_exits, &network, e);
                if matches!(e, Event::Log { message, .. } if message == PATH_CHANGED) {
                    let _ = path_changed.try_send(());
                }
                print_event(verbose, e)
            }),
            mdns: None,
        };
        let mark = cfg!(target_os = "linux").then_some(fwmark);
        let start = StartOptions {
            interface_name: name.clone(),
            hostname: hostname(),
            intercept_dns: INTERCEPT_DNS,
            mdns_exclude: vec![tun.name().to_owned()],
            resolvers: resolv::system_resolvers(),
            fwmark: mark,
            watch_network: true,
        };
        let tunnel = Arc::new(Tunnel::start(
            &tokio::runtime::Handle::current(),
            &text,
            start,
            callbacks,
        )?);

        let reader = tunnel.clone();
        let source = tun.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65_536];
            while let Ok(n) = source.read(&mut buf) {
                reader.packet_in(&buf[..n]);
            }
        });

        let forwarder = Arc::new(
            Forwarder::new(
                tunnel.config().upstreams(),
                tokio::runtime::Handle::current(),
            )
            .with_mark(mark.map_or(SocketMark::NONE, SocketMark::new)),
        );
        let (_resolver, dns_port) = if INTERCEPT_DNS {
            (install_resolver(&config, &tun, 53), Some(53))
        } else {
            serve_dns(&tunnel, &config, &tun, forwarder.clone()).await
        };

        let shared =
            control::Shared::new(name.clone(), tun.name().to_owned(), tunnel.clone(), sites)
                .with_view(view);
        shared.set_dns_port(dns_port);
        shared.set_forwarder(forwarder);
        let stop = shared.stop.clone();
        let shared = Arc::new(shared);
        tunnel.remember_exits(remembered(&exits));
        check_uplink(&shared, tun.name(), fwmark).await;
        let uplink = tokio::spawn(uplink_task(
            path_wake,
            shared.clone(),
            tun.name().to_owned(),
            fwmark,
        ));
        let serving = tokio::spawn(control::serve(listener, shared.clone()));
        if let Some(using) = start_use {
            shared.set_use(Some(using));
        }

        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
            () = stop.notified() => {}
        }
        eprintln!("stopping");
        serving.abort();
        uplink.abort();
        tunnel.stop_async().await;
        Ok::<(), anyhow::Error>(())
    })
}

/// How often an exit looks again at its host's IPv6 route, since the path watcher sees addresses
/// and not routes.
const UPLINK_PERIOD: Duration = Duration::from_secs(30);

/// Looks at the host's IPv6 route and tells the tunnel, saying so when it changes.
async fn check_uplink(shared: &Arc<control::Shared>, device: &str, mark: u32) {
    if shared.tunnel.config().exit.is_none() {
        return;
    }
    let device = device.to_owned();
    let found = tokio::task::spawn_blocking(move || uplink::probe(&device, mark))
        .await
        .ok()
        .flatten();
    let Some(on) = found else { return };
    if shared.set_ipv6_uplink(on) {
        eprintln!(
            "{}",
            if on {
                "exit: IPv6 uplink present, answering as usual"
            } else {
                "exit: no IPv6 uplink, native IPv6 is answered with no route"
            }
        );
    }
}

/// Looks again whenever the path watcher reports a change, and every [`UPLINK_PERIOD`].
async fn uplink_task(
    mut path: mpsc::Receiver<()>,
    shared: Arc<control::Shared>,
    device: String,
    mark: u32,
) {
    let mut tick = tokio::time::interval(UPLINK_PERIOD);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            seen = path.recv() => if seen.is_none() { return },
        }
        check_uplink(&shared, &device, mark).await;
    }
}

/// Binds the resolver on port 53 of the overlay address, or on another port where the system
/// already holds the wildcard port 53, and routes the overlay domains to it.
async fn serve_dns(
    tunnel: &Tunnel,
    config: &Config,
    tun: &Tun,
    forwarder: Arc<Forwarder>,
) -> (Option<Resolver>, Option<u16>) {
    let ula = config.own_addrs().ula;
    let mut sockets = None;
    let mut last = None;
    for port in [53, 0] {
        for _ in 0..if port == 53 { 10 } else { 1 } {
            match UdpSocket::bind((ula, port)).await {
                Ok(udp) => {
                    let actual = udp.local_addr().map(|a| a.port()).unwrap_or(port);
                    let tcp = TcpListener::bind((ula, actual)).await.ok();
                    sockets = Some((udp, tcp, actual));
                    break;
                }
                Err(e) => last = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if sockets.is_some() {
            break;
        }
    }
    let Some((udp, tcp, port)) = sockets else {
        let why = last.map(|e| e.to_string()).unwrap_or_default();
        eprintln!("warning: cannot bind the resolver on [{ula}] ({why}), overlay DNS is off");
        return (None, None);
    };
    if port != 53 {
        eprintln!("note: port 53 is taken on this host, overlay DNS listens on port {port}");
    }
    let responder = tunnel.responder();
    tokio::spawn(serve_udp(responder.clone(), forwarder.clone(), udp));
    if let Some(tcp) = tcp {
        tokio::spawn(serve_tcp(responder, forwarder, tcp));
    }
    (install_resolver(config, tun, port), Some(port))
}

fn install_resolver(config: &Config, tun: &Tun, port: u16) -> Option<Resolver> {
    let domains = [config.domain.clone(), reverse_zone(&config.network_id)];
    match Resolver::install(tun.name(), &domains, &config.own_addrs().ula, port) {
        Ok(r) => Some(r),
        Err(e) => {
            eprintln!("warning: resolver scoping failed: {e}");
            None
        }
    }
}
