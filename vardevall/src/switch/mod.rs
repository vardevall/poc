//! The switch client (vv-04, vv-05 §4.2).
//!
//! A [`Switches`] runs one task per configured switch, which drives a
//! [`SwitchSession`](vardevall_switch_proto::session::SwitchSession): it registers, keeps the
//! events stream open, lists members and reconnects. The node learns presence, forwarded datagrams and status
//! through [`Switches::recv`], and sends datagrams with [`Switches::forward`].

mod http;
pub(crate) use http::Transport as HttpTransport;
mod session;
pub(crate) mod tls;
mod uri;

use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use vardevall_proto::keys::{NetworkSecret, NodePublic, NodeSecret};
use vardevall_proto::time::Instant;
use vardevall_switch_proto::turn::TurnOffer;

use self::http::Target;
use self::session::{Channels, Link};
use crate::clock::Clock;
use crate::config::SwitchSpec;
use crate::error::NodeError;
use crate::event::SwitchState;
use crate::net::mark::SocketMark;

pub(crate) use vardevall_switch_proto::origin::Origin;
pub use vardevall_switch_proto::origin::SwitchId;
pub(crate) use vardevall_switch_proto::pacing::Traffic;

/// Datagrams queued towards one switch; more are dropped, as a full link would.
const COMMAND_QUEUE: usize = 32;
/// Capacity of the queues from the tasks to the engine.
const INBOUND_QUEUE: usize = 128;

/// A request from the engine to a switch task.
pub(crate) enum Command {
    /// Forward a datagram to a member (vv-04 §6); `at` is when the engine sent it.
    Forward {
        to: NodePublic,
        msg: Vec<u8>,
        traffic: Traffic,
        at: Instant,
    },
    /// Drop the connection and reconnect, keeping the session (vv-05 §4.6).
    Reconnect,
    /// Fetch TURN credentials now, because the server rejected the last (vv-04 §4.5).
    RefreshTurn,
}

/// A message from a switch task to the engine.
pub(crate) enum Inbound {
    /// The protocol that carried a new connection (vv-04 §2.2).
    Transport {
        id: SwitchId,
        transport: http::Transport,
    },
    /// The STUN servers of the switch (vv-04 §3.4), resolved; `required` says they answer only
    /// requests with the credential of vv-04 §4.7.
    Stun {
        origin: Origin,
        servers: Vec<SocketAddr>,
        required: bool,
    },
    /// The short-term credential for the STUN servers (vv-04 §4.7): the `username` and the key
    /// of MESSAGE-INTEGRITY, valid for `ttl` (always, if none).
    StunCredentials {
        origin: Origin,
        username: String,
        key: Vec<u8>,
        ttl: Option<Duration>,
    },
    /// Fresh TURN credentials (vv-04 §4.4, §4.5).
    Turn { origin: Origin, offer: TurnOffer },
    /// The registration state changed; while disconnected, with when the next attempt starts.
    State(SwitchId, SwitchState, Option<tokio::time::Instant>),
    /// A new registration: the volume the switch lets the session forward.
    Budget { id: SwitchId, bytes: Option<u64> },
    /// A member came online or went offline on the switch (vv-04 §5, §7).
    Presence {
        id: SwitchId,
        node: NodePublic,
        online: bool,
    },
    /// A `forward` event arrived (vv-04 §7.2).
    Forward {
        id: SwitchId,
        from: NodePublic,
        msg: Vec<u8>,
    },
}

struct Handle {
    commands: mpsc::Sender<Command>,
    address: String,
}

/// The tasks of all configured switches.
pub(crate) struct Switches {
    handles: Vec<Handle>,
    inbound: mpsc::Receiver<Inbound>,
    _keep: mpsc::Sender<Inbound>,
    tasks: JoinSet<()>,
}

impl Switches {
    /// Starts a task for each of `specs`; the index of a spec is its [`SwitchId`].
    ///
    /// Fails if a switch address cannot be used. Must be called inside a tokio runtime.
    pub(crate) fn start(
        specs: &[SwitchSpec],
        node: &NodeSecret,
        network: &NetworkSecret,
        clock: Clock,
        mark: SocketMark,
    ) -> Result<Switches, NodeError> {
        let (inbound_tx, inbound) = mpsc::channel(INBOUND_QUEUE);
        let mut tasks = JoinSet::new();
        let mut handles = Vec::new();
        for (i, spec) in specs.iter().enumerate() {
            let id = SwitchId(u32::try_from(i).unwrap_or(u32::MAX));
            let host = spec.normal_host().ok_or(NodeError::Config(
                "switch host is not a DNS name or IP literal",
            ))?;
            let (Ok(connector), Ok(quic)) =
                (tls::connector(&spec.auth), http::quic_config(&spec.auth))
            else {
                return Err(NodeError::Config("switch trust roots are not usable"));
            };
            let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_QUEUE);
            handles.push(Handle {
                commands: cmd_tx,
                address: spec.label(),
            });
            let target = Target {
                host: spec.host.clone(),
                port: spec.port,
                tls: connector,
                quic,
                mark,
            };
            let link = Link {
                id,
                spec: spec.clone(),
                host,
                node: node.clone(),
                network: network.clone(),
                mark,
            };
            let channels = Channels {
                commands: cmd_rx,
                inbound: inbound_tx.clone(),
            };
            tasks.spawn(session::run(link, channels, target, clock));
        }
        Ok(Switches {
            handles,
            inbound,
            _keep: inbound_tx,
            tasks,
        })
    }

    /// The next message from a switch task.
    pub(crate) async fn recv(&mut self) -> Option<Inbound> {
        self.inbound.recv().await
    }

    /// Queues `msg` for `to` on switch `id`; the session holds it back if the limits of the switch
    /// (vv-04 §3.4) say so. `false` if it was not queued: a full queue or an unknown switch.
    pub(crate) fn forward(
        &mut self,
        now: Instant,
        id: SwitchId,
        to: &NodePublic,
        msg: &[u8],
        traffic: Traffic,
    ) -> bool {
        let Some(h) = self.handles.get(id.0 as usize) else {
            return false;
        };
        h.commands
            .try_send(Command::Forward {
                to: *to,
                msg: msg.to_vec(),
                traffic,
                at: now,
            })
            .is_ok()
    }

    /// Asks switch `id` for TURN credentials now.
    pub(crate) fn refresh_turn(&self, origin: Origin) {
        let Origin::Switch(id) = origin else {
            return;
        };
        if let Some(h) = self.handles.get(id.0 as usize) {
            let _ = h.commands.try_send(Command::RefreshTurn);
        }
    }

    /// Reconnects every switch over the current local path, keeping the sessions.
    pub(crate) fn path_changed(&mut self) {
        for h in &self.handles {
            let _ = h.commands.try_send(Command::Reconnect);
        }
    }

    /// `host:port` of switch `id`.
    pub(crate) fn address(&self, id: SwitchId) -> String {
        self.handles
            .get(id.0 as usize)
            .map(|h| h.address.clone())
            .unwrap_or_default()
    }

    /// Stops every task.
    pub(crate) fn stop(&mut self) {
        self.tasks.abort_all();
    }
}
