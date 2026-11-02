//! What the router knows of exits.

use std::collections::{BTreeMap, BTreeSet};

use vardevall_proto::ip::exit::ExitServe;
pub use vardevall_proto::ip::exit::{Chosen, ExitUse};
use vardevall_proto::ip::site::Site;

/// The exits this node serves, uses and has chosen.
#[derive(Debug, Default)]
pub(super) struct ExitState {
    using: Option<ExitUse>,
    known: BTreeSet<Site>,
    chosen: BTreeMap<Site, Chosen>,
    serving: Option<ExitServe>,
}

impl ExitState {
    pub(super) fn set_use(&mut self, using: Option<ExitUse>) {
        self.using = using;
    }

    pub(super) fn set_known(&mut self, sites: impl IntoIterator<Item = Site>) {
        self.known = sites.into_iter().collect();
    }

    pub(super) fn set_chosen(&mut self, site: Site, via: Option<Chosen>) {
        match via {
            Some(k) => self.chosen.insert(site, k),
            None => self.chosen.remove(&site),
        };
    }

    pub(super) fn set_serving(&mut self, serving: Option<ExitServe>) {
        self.serving = serving;
    }

    pub(super) fn serving(&self) -> Option<&ExitServe> {
        self.serving.as_ref()
    }

    /// The site in use and its chosen exit.
    pub(super) fn used(&self) -> Option<(&Site, &Chosen)> {
        let using = self.using.as_ref()?;
        let site = using.resolve(self.known.iter().chain(self.chosen.keys()))?;
        self.chosen.get_key_value(site)
    }
}
