//! The services of this node and of its peers (vve-14): following what the embedder announces
//! and publishing the providers for [`Handle::providers`](crate::Handle::providers).

use std::collections::HashMap;

use vardevall_proto::ip::service::{Proto, Provider, Service};

use super::Node;
use crate::config::LiveUpdate;

/// What the embedder's handle and the engine share about services.
#[derive(Default)]
pub(crate) struct Shared {
    /// The services the embedder wants announced; the engine follows it.
    pub own: Vec<Service>,
    /// Whether `own` changed since the engine looked.
    pub own_changed: bool,
    /// The providers of each service name, as the engine last computed them.
    pub providers: HashMap<String, Providers>,
    /// A replacement of the peers, exit and servers the engine has not taken yet.
    pub update: Option<LiveUpdate>,
}

/// The providers of one name: of any transport, and of each one.
#[derive(Default)]
pub(crate) struct Providers {
    pub any: Vec<Provider>,
    pub tcp: Vec<Provider>,
    pub udp: Vec<Provider>,
}

impl Node {
    /// Brings the announced services in line with what the embedder asked for.
    pub(super) fn sync_services(&mut self) {
        let want = {
            let mut shared = self.shared_services();
            if !std::mem::take(&mut shared.own_changed) {
                return;
            }
            shared.own.clone()
        };
        let now = self.clock.now();
        self.core.set_services(now, &mut self.rng, want);
        self.drain();
    }

    /// Recomputes the providers the handle reads.
    pub(super) fn publish_services(&mut self) {
        let providers = self
            .core
            .service_names()
            .into_iter()
            .map(|n| {
                let p = Providers {
                    any: self.core.providers(&n, None),
                    tcp: self.core.providers(&n, Some(Proto::Tcp)),
                    udp: self.core.providers(&n, Some(Proto::Udp)),
                };
                (n, p)
            })
            .collect();
        self.shared_services().providers = providers;
    }

    pub(super) fn shared_services(&self) -> std::sync::MutexGuard<'_, Shared> {
        self.shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
