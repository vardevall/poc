//! Builds the [`View`] from the engine's state and reports it when it changes.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::time::Instant as TokioInstant;
use vardevall_proto::meter::Meter;
use vardevall_proto::node::RouteView;
use vardevall_proto::route::{Next, RouteClass, RouteInfo};
use vardevall_proto::transport::{Path, Remote};

use super::Node;
use crate::event::{NodeEvent, SwitchState};
use crate::switch::{HttpTransport as Transport, SwitchId};
use crate::view::{self, ExitSite, Local, Nat, Peer, PeerNat, PeerRoute, Route, RouteNext, View};
use vardevall_switch_proto::reflexive::Mapping;

/// The switch states the engine was told about, for the view.
#[derive(Default)]
pub(super) struct Switches(BTreeMap<u32, view::Switch>);

impl Switches {
    pub(super) fn set_state(
        &mut self,
        id: SwitchId,
        address: String,
        state: SwitchState,
        retry_at: Option<TokioInstant>,
    ) {
        let e = self.0.entry(id.0).or_insert_with(|| view::Switch {
            id,
            address: address.clone(),
            state,
            transport: None,
            retry_at,
        });
        e.address = address;
        e.state = state;
        e.retry_at = retry_at;
    }

    pub(super) fn set_transport(&mut self, id: SwitchId, transport: Transport) {
        if let Some(e) = self.0.get_mut(&id.0) {
            e.transport = Some(match transport {
                Transport::Http3 => "http3",
                Transport::Http2 => "http2",
                Transport::Http1 => "http1",
            });
        }
    }
}

/// Throttling of [`NodeEvent::View`].
pub(super) struct Reporter {
    pub switches: Switches,
    /// The last view reported.
    last: Option<View>,
    next: TokioInstant,
    pending: bool,
    /// When the last view was reported, with the meters it carried.
    reported_at: TokioInstant,
    /// When a view that differs only in meters is due, if the engine saw one.
    meters_due: Option<TokioInstant>,
}

impl Reporter {
    pub(super) fn new() -> Self {
        Reporter {
            switches: Switches::default(),
            last: None,
            next: TokioInstant::now(),
            pending: false,
            reported_at: TokioInstant::now(),
            meters_due: None,
        }
    }

    /// When the engine must wake to report a change it may have missed.
    pub(super) fn wake(&self) -> Option<TokioInstant> {
        self.pending
            .then_some(self.next)
            .into_iter()
            .chain(self.meters_due.map(|d| d.max(self.next)))
            .min()
    }
}

/// `v` without what changes with every datagram or pong: the meters, what is left of the budgets
/// and the value of the round-trip times (that one was measured is kept).
fn without_meters(v: &View) -> View {
    let mut v = v.clone();
    for t in &mut v.local.transports {
        t.meter = Meter::default();
        if let Some(b) = &mut t.budget {
            b.remaining = 0;
        }
    }
    for p in &mut v.peers {
        p.meter = None;
        p.rtt = p.rtt.map(|_| Duration::ZERO);
        for r in &mut p.routes {
            r.rtt = r.rtt.map(|_| Duration::ZERO);
        }
    }
    v
}

/// `d` to the nearest millisecond, so that jitter below it does not make a new view.
fn round_ms(d: Duration) -> Duration {
    Duration::from_millis(((d.as_micros() + 500) / 1000) as u64)
}

fn nat(m: Option<Mapping>) -> Nat {
    match m {
        None => Nat::Unknown,
        Some(Mapping::Punchable(a)) => Nat::Punchable(a),
        Some(Mapping::Symmetric) => Nat::Symmetric,
        Some(Mapping::Blocked) => Nat::Blocked,
    }
}

impl Node {
    /// Called once per turn of the engine loop: reports the view if it changed, at most every
    /// [`view::VIEW_INTERVAL`].
    pub(super) fn view_tick(&mut self) {
        let now = TokioInstant::now();
        if now < self.view.next {
            self.view.pending = true;
            return;
        }
        self.view.pending = false;
        self.view.next = now + view::VIEW_INTERVAL;
        let v = self.build_view();
        let emit = match &self.view.last {
            None => true,
            Some(last) if without_meters(last) != without_meters(&v) => true,
            Some(last) if *last != v => {
                let due = self.view.reported_at + view::METER_INTERVAL;
                self.view.meters_due = Some(due);
                now >= due
            }
            Some(_) => {
                self.view.meters_due = None;
                false
            }
        };
        if emit {
            self.view.last = Some(v.clone());
            self.view.reported_at = now;
            self.view.meters_due = None;
            self.sink.event(NodeEvent::View(v));
        }
    }

    /// The class of a route, for events and views alike; `None` for a transport the engine
    /// does not know.
    pub(super) fn route(&self, r: &RouteView) -> Option<Route> {
        self.classify(r.path, r.label, r.class)
    }

    fn classify(&self, path: Path, label: &str, class: RouteClass) -> Option<Route> {
        Some(match path.to {
            Remote::Peer(_) => Route::Switch(self.media.switch_id(path.via)?),
            Remote::Addr(addr) => Route::to_addr(addr, path.via == self.media.turn, label, class),
        })
    }

    fn peer_route(&self, r: &RouteInfo) -> Option<PeerRoute> {
        let route = self.classify(r.path, r.label, r.class)?;
        Some(PeerRoute {
            route,
            status: r.status,
            rtt: r.srtt.map(round_ms),
            active: r.active,
            metered: route.metered() || r.class.metered,
            next: r.next.map(|n| match n {
                Next::Retry(at) => RouteNext::Retry(self.clock.tokio_instant(at)),
                Next::Forget(at) => RouteNext::Forget(self.clock.tokio_instant(at)),
            }),
        })
    }

    fn build_view(&self) -> View {
        let snapshot = self.stun.snapshot();
        let relay = self.turn.relay();
        let local = Local {
            v6: nat(snapshot.and_then(|s| s.v6)),
            v4: nat(snapshot.and_then(|s| s.v4)),
            relay,
            switches: self.view.switches.0.values().cloned().collect(),
            transports: self
                .core
                .transports()
                .into_iter()
                .map(|t| view::Transport {
                    name: t.name,
                    usable: t.usable,
                    meter: t.meter,
                    budget: t.budget,
                })
                .collect(),
        };
        let mut keys: Vec<_> = self.core.peers().copied().collect();
        keys.sort();
        let peers = keys
            .into_iter()
            .filter_map(|k| self.core.peer_view(&k).map(|v| (k, v)))
            .map(|(peer, v)| {
                let active = v.active;
                let route = active.as_ref().and_then(|a| self.route(a));
                let mut candidates = v.shared.clone();
                for c in v.found {
                    if !candidates.iter().any(|x| x.addr == c.addr) {
                        candidates.push(c);
                    }
                }
                let routes: Vec<PeerRoute> =
                    v.routes.iter().filter_map(|r| self.peer_route(r)).collect();
                let rtt = routes.iter().find(|r| r.active).and_then(|r| r.rtt);
                Peer {
                    peer,
                    state: v.link,
                    route,
                    metered: active.is_some_and(|a| a.class.metered),
                    degraded: active.is_some() && v.degraded,
                    nat: PeerNat::from_candidates(&v.shared),
                    candidates,
                    switches: v
                        .reporting
                        .iter()
                        .filter_map(|t| self.media.switch_id(*t))
                        .collect(),
                    probing: v.probing,
                    fallback: v.fallback,
                    meter: active.map(|a| a.meter),
                    rtt,
                    routes,
                }
            })
            .collect();
        let sites = self
            .core
            .sites()
            .into_iter()
            .map(|s| ExitSite {
                addr: self.core.site_addr(&s.site),
                site: s.site,
                peers: s.peers,
                chosen: s.chosen,
            })
            .collect();
        View {
            local,
            peers,
            sites,
        }
    }
}
