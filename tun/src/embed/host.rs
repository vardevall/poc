//! The networks of a tunnel on a single-threaded runtime of their own thread.

use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle, ThreadId};

use tokio::runtime::{Builder, Handle};
use tokio::sync::oneshot;

use super::{Callbacks, HostDns, NetworkSpec, Networks, StartOptions};

/// The running networks and the thread that drives their runtime.
pub struct Host {
    networks: Arc<Networks>,
    runtime: Handle,
    shutdown: oneshot::Sender<()>,
    thread: JoinHandle<()>,
}

impl Host {
    /// Starts the networks of `specs`, the first being the one whose address the OS resolves
    /// through. The callbacks run on the thread of the runtime.
    pub fn start(
        specs: Vec<NetworkSpec>,
        options: StartOptions,
        dns: HostDns,
        callbacks: Callbacks,
    ) -> Result<Host, String> {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (shutdown, stopped) = oneshot::channel::<()>();
        let thread = thread::Builder::new()
            .name("vv-runtime".into())
            .spawn(move || {
                let runtime = match Builder::new_current_thread().enable_all().build() {
                    Ok(r) => r,
                    Err(e) => return drop(ready_tx.send(Err(e.to_string()))),
                };
                let _ = ready_tx.send(Ok(runtime.handle().clone()));
                runtime.block_on(async {
                    let _ = stopped.await;
                });
            })
            .map_err(|e| e.to_string())?;
        let runtime = ready_rx
            .recv()
            .map_err(|_| "runtime thread failed".to_owned())??;

        match Networks::start_with(&runtime, specs, options, dns, callbacks) {
            Ok(networks) => Ok(Host {
                networks: Arc::new(networks),
                runtime,
                shutdown,
                thread,
            }),
            Err(e) => {
                let _ = shutdown.send(());
                let _ = thread.join();
                Err(e.to_string())
            }
        }
    }

    /// The networks.
    pub fn networks(&self) -> &Networks {
        &self.networks
    }

    /// The networks, for tasks of the host that run on [`Host::runtime`] and end with it.
    pub fn shared_networks(&self) -> Arc<Networks> {
        self.networks.clone()
    }

    /// The runtime the networks run on, for tasks of the host that belong with them.
    pub fn runtime(&self) -> &Handle {
        &self.runtime
    }

    /// The id of the thread that runs callbacks.
    pub fn runtime_thread(&self) -> ThreadId {
        self.thread.thread().id()
    }

    /// Stops the networks and their thread. Called from a callback, it suppresses later callbacks and
    /// lets the thread finish on its own.
    pub fn stop(self) {
        let inside = thread::current().id() == self.runtime_thread();
        self.networks.stop();
        let _ = self.shutdown.send(());
        if !inside {
            let _ = self.thread.join();
        }
    }
}
