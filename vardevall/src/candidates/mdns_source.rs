//! The mDNS candidate source: [`Discovery`] on top of a [`MdnsTransport`] (vv-09).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::time::{Sleep, sleep};
use vardevall_proto::keys::NodePublic;

use super::{CandidateSource, SourceInput, Update};
use crate::clock::unix_seconds;
use crate::config::PeerSpec;
use crate::mdns::{Discovery, MdnsTransport};
use crate::net::rng::{OsRng, os_rng};

/// The name of the source in [`super::SourceKey::Discovery`] and logs.
pub(crate) const NAME: &str = "mdns";

/// Candidates from LAN announcements.
pub(crate) struct MdnsSource {
    discovery: Discovery,
    transport: Box<dyn MdnsTransport>,
    tick: Pin<Box<Sleep>>,
    rng: OsRng,
}

fn host_addrs() -> Vec<std::net::IpAddr> {
    if_addrs::get_if_addrs()
        .map(|v| v.into_iter().map(|i| i.ip()).collect())
        .unwrap_or_default()
}

impl MdnsSource {
    /// Starts announcing and browsing through `transport`.
    pub(crate) fn new(mut discovery: Discovery, transport: Box<dyn MdnsTransport>) -> Self {
        let mut rng = os_rng();
        let now = unix_seconds();
        discovery.set_host_addrs(host_addrs());
        discovery.start(now, &mut rng);
        let wait = discovery.next_tick_in(now);
        MdnsSource {
            discovery,
            transport,
            tick: Box::pin(sleep(wait)),
            rng,
        }
    }

    fn rearm(&mut self) {
        let wait = self.discovery.next_tick_in(unix_seconds());
        self.tick.as_mut().reset(tokio::time::Instant::now() + wait);
    }

    fn pump(&mut self) {
        while let Some(r) = self.discovery.pop_request() {
            self.transport.request(r);
        }
    }
}

impl CandidateSource for MdnsSource {
    fn name(&self) -> &'static str {
        NAME
    }

    fn poll_update(&mut self, cx: &mut Context<'_>) -> Poll<Update> {
        loop {
            self.pump();
            if let Some(u) = self.discovery.pop_update() {
                return Poll::Ready(u);
            }
            if self.tick.as_mut().poll(cx).is_ready() {
                self.discovery.tick(unix_seconds(), &mut self.rng);
                self.rearm();
                continue;
            }
            match self.transport.poll_event(cx) {
                Poll::Ready(ev) => {
                    self.discovery.event(ev, unix_seconds());
                    self.rearm();
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn input(&mut self, input: SourceInput) {
        let SourceInput::Mdns(ev) = input;
        self.discovery.event(ev, unix_seconds());
        self.rearm();
    }

    fn route_failed(&mut self, peer: &NodePublic, addr: SocketAddr) {
        self.discovery.route_failed(peer, addr);
    }

    fn peers_changed(&mut self, peers: &[PeerSpec]) {
        self.discovery
            .set_peers(peers.iter().map(|p| p.public).collect(), unix_seconds());
    }

    fn path_changed(&mut self) {
        self.discovery.set_host_addrs(host_addrs());
        self.discovery.refresh(unix_seconds(), &mut self.rng);
        self.transport.path_changed();
        self.pump();
    }

    fn stop(&mut self) {
        self.discovery.stop();
        self.pump();
    }
}
