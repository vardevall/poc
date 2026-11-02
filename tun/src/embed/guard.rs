//! Serialises callbacks and guarantees none runs after `stop` (vv.h `vv_stop`).

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use vardevall::MdnsRequest;

use super::Event;

thread_local! {
    static IN_CALLBACK: Cell<bool> = const { Cell::new(false) };
}

/// Receives the IP packets the tunnel must write, in order; the first nibble of a packet is its
/// version, 6 or 4. The slices are call-scoped.
pub type PacketsFn = Box<dyn FnMut(&[&[u8]]) + Send>;
/// Receives events, each with the name of the network it belongs to.
pub type EventFn = Box<dyn FnMut(&str, &Event) + Send>;
/// Receives requests for an external mDNS backend.
pub type MdnsFn = Box<dyn FnMut(&MdnsRequest) + Send>;

/// The embedder's callbacks.
pub struct Callbacks {
    /// Packets for the tunnel to write, a batch per call.
    pub packets: PacketsFn,
    /// Events.
    pub event: EventFn,
    /// Requests for an external mDNS backend; `None` selects the built-in transport.
    pub mdns: Option<MdnsFn>,
}

pub(super) struct Guard {
    callbacks: Mutex<Option<Callbacks>>,
    closed: AtomicBool,
}

struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        IN_CALLBACK.with(|c| c.set(false));
    }
}

impl Guard {
    pub(super) fn new(callbacks: Callbacks) -> Self {
        Guard {
            callbacks: Mutex::new(Some(callbacks)),
            closed: AtomicBool::new(false),
        }
    }

    pub(super) fn has_external_mdns(&self) -> bool {
        self.callbacks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|c| c.mdns.is_some())
    }

    pub(super) fn with(&self, f: impl FnOnce(&mut Callbacks)) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let mut slot = self
            .callbacks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(cb) = slot.as_mut() else { return };
        IN_CALLBACK.with(|c| c.set(true));
        let _reset = Reset;
        f(cb);
    }

    /// Stops all callbacks. Blocks until a running callback returns, unless called from inside
    /// one, where the lock is already held by this thread and later callbacks are suppressed.
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        if IN_CALLBACK.with(Cell::get) {
            return;
        }
        let mut slot = self
            .callbacks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *slot = None;
    }
}
