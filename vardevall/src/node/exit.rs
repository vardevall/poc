//! The exit the embedder makes this network carry and the offers it kept,
//! shared between the [`Handle`](crate::Handle) and the engine apart from the services.

use vardevall_proto::ip::exit::ExitUse;
use vardevall_proto::ip::site::Site;
use vardevall_proto::keys::NodePublic;

use super::Node;

/// What the embedder's handle and the engine share about the exit.
#[derive(Default)]
pub(crate) struct ExitShared {
    /// The exit the embedder makes this network carry.
    pub using: Option<ExitUse>,
    /// Whether `using` changed since the engine looked.
    pub changed: bool,
    /// Offers the embedder kept from an earlier run, until the engine takes them.
    pub remembered: Vec<(NodePublic, Site)>,
}

impl Node {
    /// Takes the offers the embedder remembered, then brings the use of an exit in line with what
    /// it asked for, so that a use set with them reaches the known exits first.
    pub(super) fn sync_exit(&mut self) {
        let (remembered, want) = {
            let mut shared = self.shared_exit();
            let remembered = std::mem::take(&mut shared.remembered);
            let want = std::mem::take(&mut shared.changed).then(|| shared.using.clone());
            (remembered, want)
        };
        if remembered.is_empty() && want.is_none() {
            return;
        }
        let now = self.clock.now();
        if !remembered.is_empty() {
            self.core.remember(now, &mut self.rng, &remembered);
        }
        if let Some(want) = want {
            self.core.set_exit_use(now, &mut self.rng, want);
        }
        self.drain();
    }

    pub(super) fn shared_exit(&self) -> std::sync::MutexGuard<'_, ExitShared> {
        self.exit_shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
