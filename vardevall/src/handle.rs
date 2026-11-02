//! The embedder's handle on a running node.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{Notify, mpsc};
use vardevall_proto::ip::exit::ExitUse;
use vardevall_proto::ip::service::{MAX_SERVICES, Proto, Provider, Service, ServiceError};
use vardevall_proto::ip::site::Site;
use vardevall_proto::keys::NodePublic;
use vardevall_proto::route::Families;

use crate::candidates::SourceInput;
use crate::config::LiveUpdate;
use crate::mdns::MdnsEvent;
use crate::node::{ExitShared, Shared};

/// Capacity of the packet queue; packets beyond it are dropped, as a full link would.
pub(crate) const PACKET_QUEUE: usize = 256;
/// Capacity of the control queue.
pub(crate) const CONTROL_QUEUE: usize = 256;

/// Bit of [`Signals::changed`] for IPv4.
const V4: u8 = 1;
/// Bit of [`Signals::changed`] for IPv6.
const V6: u8 = 2;

#[derive(Default)]
pub(crate) struct Signals {
    /// The address families of local change notifications not yet taken (`V4`, `V6`).
    changed: AtomicU8,
    pub(crate) metered: AtomicBool,
    pub(crate) metered_changed: AtomicBool,
    pub(crate) stop: AtomicBool,
    pub(crate) notify: Notify,
}

impl Signals {
    /// The families reported since the last call.
    pub(crate) fn take_changed(&self) -> Families {
        let bits = self.changed.swap(0, Ordering::SeqCst);
        Families {
            v4: bits & V4 != 0,
            v6: bits & V6 != 0,
        }
    }
}

/// A cloneable handle: usable from any thread, without entering the runtime.
#[derive(Clone)]
pub struct Handle {
    packets: mpsc::Sender<(NodePublic, Vec<u8>)>,
    control: mpsc::Sender<SourceInput>,
    signals: Arc<Signals>,
    listen: SocketAddr,
    services: Arc<Mutex<Shared>>,
    exit: Arc<Mutex<ExitShared>>,
}

pub(crate) struct Receivers {
    pub(crate) packets: mpsc::Receiver<(NodePublic, Vec<u8>)>,
    pub(crate) control: mpsc::Receiver<SourceInput>,
    pub(crate) signals: Arc<Signals>,
}

pub(crate) fn channel(
    listen: SocketAddr,
    services: Arc<Mutex<Shared>>,
    exit: Arc<Mutex<ExitShared>>,
) -> (Handle, Receivers) {
    let (ptx, prx) = mpsc::channel(PACKET_QUEUE);
    let (ctx, crx) = mpsc::channel(CONTROL_QUEUE);
    let signals = Arc::new(Signals::default());
    (
        Handle {
            packets: ptx,
            control: ctx,
            signals: signals.clone(),
            listen,
            services,
            exit,
        },
        Receivers {
            packets: prx,
            control: crx,
            signals,
        },
    )
}

impl Handle {
    /// The local address of the node's socket.
    pub fn local_addr(&self) -> SocketAddr {
        self.listen
    }

    /// Queues an IPv6 packet for `peer`; returns `false` if the queue is full or the node
    /// stopped, in which case the packet is dropped.
    pub fn send_packet(&self, peer: &NodePublic, packet: &[u8]) -> bool {
        self.packets.try_send((*peer, packet.to_vec())).is_ok()
    }

    /// Reports that the set of usable local paths changed, in both address families (vv-05
    /// §4.6). A burst of reports is one change, which the node acts on once it has settled
    /// (vv-05 §3.2).
    pub fn path_changed(&self) {
        self.path_changed_for(Families::BOTH);
    }

    /// Reports a change that affects only some address families, whose addresses are then
    /// gathered again; the others keep their results.
    pub fn path_changed_for(&self, families: Families) {
        let bits = (u8::from(families.v4) * V4) | (u8::from(families.v6) * V6);
        if bits != 0 {
            self.signals.changed.fetch_or(bits, Ordering::SeqCst);
            self.signals.notify.notify_one();
        }
    }

    /// Reports whether the platform marks the interface in use as expensive or constrained, such
    /// as a cellular link or a personal hotspot; the `punch` candidates are then sent as metered
    /// (vv-05 §2.2).
    pub fn set_metered(&self, metered: bool) {
        self.signals.metered.store(metered, Ordering::SeqCst);
        self.signals.metered_changed.store(true, Ordering::SeqCst);
        self.signals.notify.notify_one();
    }

    /// Delivers a browse result of the external mDNS transport; returns `false` if the control
    /// queue is full.
    pub fn mdns_event(&self, event: MdnsEvent) -> bool {
        self.control.try_send(SourceInput::Mdns(event)).is_ok()
    }

    /// Announces a service to the peers, replacing one of the same name and transport (vve-14
    /// §2.1). Fails for an invalid name or port, or when 16 services are announced already.
    pub fn announce(&self, name: &str, port: u16, proto: Proto) -> Result<(), ServiceError> {
        let service = Service::new(name, port, proto)?;
        let mut shared = lock(&self.services);
        match shared
            .own
            .iter()
            .position(|s| s.name() == name && s.proto() == proto)
        {
            Some(i) => shared.own[i] = service,
            None if shared.own.len() >= MAX_SERVICES => return Err(ServiceError::TooMany),
            None => shared.own.push(service),
        }
        shared.own_changed = true;
        drop(shared);
        self.signals.notify.notify_one();
        Ok(())
    }

    /// Says whether an exit of this network is in use and which site: the
    /// node then initiates toward the peers held by key, and keeps the exits of the site
    /// connected until the use ends.
    pub fn set_exit(&self, using: Option<ExitUse>) {
        let mut shared = lock(&self.exit);
        shared.using = using;
        shared.changed = true;
        drop(shared);
        self.signals.notify.notify_one();
    }

    /// Replaces the peers, the exit served and the configured STUN and TURN servers while the
    /// node runs. A peer whose entry is unchanged keeps its session; one that is gone is removed
    /// with its sessions; one that is new is added as a key-trusted peer.
    pub fn update(&self, update: LiveUpdate) {
        lock(&self.services).update = Some(update);
        self.signals.notify.notify_one();
    }

    /// Gives back the offers of an earlier run, as [`NodeEvent::Remembered`](crate::NodeEvent)
    /// reported them: the node knows those exits before any handshake, and a use
    /// reaches them first. Offers of peers that are not held by key are ignored.
    pub fn remember_exits(&self, offers: Vec<(NodePublic, Site)>) {
        lock(&self.exit).remembered.extend(offers);
        self.signals.notify.notify_one();
    }

    /// Withdraws every service of that name; returns whether there was one.
    pub fn withdraw(&self, name: &str) -> bool {
        let mut shared = lock(&self.services);
        let before = shared.own.len();
        shared.own.retain(|s| s.name() != name);
        let any = shared.own.len() != before;
        shared.own_changed |= any;
        drop(shared);
        self.signals.notify.notify_one();
        any
    }

    /// The providers of service `name`, at most 8: this node first, then peers with a session
    /// ordered by their active route, then peers known from before (vve-14 §3), as the engine last
    /// saw them.
    pub fn providers(&self, name: &str) -> Vec<Provider> {
        lock(&self.services)
            .providers
            .get(name)
            .map(|p| p.any.clone())
            .unwrap_or_default()
    }

    /// Like [`Handle::providers`], for services of one transport (an SRV answer).
    pub fn providers_for(&self, name: &str, proto: Proto) -> Vec<Provider> {
        lock(&self.services)
            .providers
            .get(name)
            .map(|p| match proto {
                Proto::Tcp => p.tcp.clone(),
                Proto::Udp => p.udp.clone(),
            })
            .unwrap_or_default()
    }

    /// Asks the node to stop. [`crate::Node::run`] then asks its candidate sources to stop (the
    /// mDNS source withdraws its announcement with a goodbye and stops browsing), aborts the
    /// switch and server-resolution tasks, reports [`crate::Status::Stopped`] and returns. A
    /// switch sees the connection drop, not a sign-off; peers and the TURN server are told
    /// nothing, so routes and the allocation lapse on their own timers.
    pub fn stop(&self) {
        self.signals.stop.store(true, Ordering::SeqCst);
        self.signals.notify.notify_one();
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
