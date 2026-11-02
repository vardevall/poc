//! The engine of the app: the networks of `vardevall-tun` on a thread of their own, with the
//! descriptor of the interface read and written here and events handed to a sink.

use std::io;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::task::JoinHandle;
use vardevall_tun::embed::{
    self, Callbacks, Host, HostDns, MdnsFn, NetworkSpec, Networks, StartOptions,
};

use crate::tunfd::{TunFd, TunSlot, read_loop};

/// Receives a JSON document: an event, or a request for the mDNS backend.
pub type Sink = Box<dyn FnMut(&str) + Send>;

/// Where the engine delivers what it has to tell the host.
pub struct Sinks {
    /// Events, as `vv_event_cb` documents them.
    pub event: Sink,
    /// Requests for an mDNS backend of the host; `None`: the engine runs its own mDNS sockets.
    pub mdns: Option<Sink>,
}

/// A running engine.
pub struct Engine {
    host: Host,
    tun: Arc<TunSlot>,
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl Engine {
    /// Starts the networks of `specs` on the interface `tun`.
    ///
    /// The packets of the engine are written to the interface and the packets read from it are
    /// handed to the engine, both here; DNS queries to the resolver alias are answered and names
    /// outside every overlay are relayed to the resolvers set with [`Engine::set_resolvers`]
    ///.
    pub fn start(specs: Vec<NetworkSpec>, tun: OwnedFd, sinks: Sinks) -> Result<Engine, String> {
        let first = specs.first().ok_or("no networks")?;
        let tun = Arc::new(TunFd::new(tun).map_err(|e| format!("interface: {e}"))?);
        let mut options = StartOptions {
            interface_name: first.name.clone(),
            hostname: None,
            intercept_dns: true,
            mdns_exclude: Vec::new(),
            resolvers: Vec::new(),
            fwmark: None,
            watch_network: false,
        };
        if sinks.mdns.is_none() {
            options.mdns_exclude.extend(tun.interface_name());
        }
        let slot = Arc::new(TunSlot::default());
        slot.replace(tun.clone());

        let (mut event, mdns) = (sinks.event, sinks.mdns);
        let writer = slot.clone();
        let callbacks = Callbacks {
            packets: Box::new(move |packets| writer.write(packets)),
            event: Box::new(move |network, e| event(&e.to_json(network))),
            mdns: mdns.map(|mut sink| -> MdnsFn {
                Box::new(move |request| sink(&embed::request_to_json(request)))
            }),
        };
        let dns = HostDns {
            resolver_alias: true,
            relay: true,
        };
        let host = Host::start(specs, options, dns, callbacks)?;
        let engine = Engine {
            host,
            tun: slot,
            reader: Mutex::new(None),
        };
        engine.read_from(tun);
        Ok(engine)
    }

    fn read_from(&self, tun: Arc<TunFd>) {
        let networks = self.host.shared_networks();
        let task = self.host.runtime().spawn(async move {
            let _ = read_loop(tun, networks).await;
        });
        let old = self
            .reader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(task);
        if let Some(old) = old {
            old.abort();
        }
    }

    /// Makes `fd`, a new interface of the same service, the one packets are read from and written
    /// to. The sessions of the engine are kept; the old interface is closed.
    pub fn set_tun(&self, fd: OwnedFd) -> io::Result<()> {
        let tun = Arc::new(TunFd::new(fd)?);
        self.tun.replace(tun.clone());
        self.read_from(tun);
        Ok(())
    }

    /// The networks.
    pub fn networks(&self) -> &Networks {
        self.host.networks()
    }

    /// Sets the resolvers of the underlying network, in the order they are tried.
    pub fn set_resolvers(&self, resolvers: &[std::net::SocketAddr]) {
        self.host.networks().set_resolvers(resolvers);
    }

    /// Stops the networks; after it returns no callback runs. Called from a callback it does not
    /// wait for the networks to say goodbye.
    pub fn stop(self) {
        self.host.stop();
    }
}
