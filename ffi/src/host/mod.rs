//! The networks of a tunnel, running on a single-threaded runtime of their own thread.

use vardevall_tun::config::{Config, Context};
use vardevall_tun::embed::{Callbacks, HostDns, NetworkSpec, StartOptions};

pub use vardevall_tun::embed::Host;

use crate::iface;

/// Name of the network of `vv_start`, which gives the default domain `vardevall.internal`.
pub const DEFAULT_NETWORK: &str = "vardevall";

/// Starts the networks of `specs`, the first being the one whose address the OS resolves
/// through.
pub fn start(specs: Vec<NetworkSpec>, callbacks: Callbacks) -> Result<Host, String> {
    let first = specs.first().ok_or("no networks")?;
    let ctx = Context {
        interface_name: first.name.clone(),
        hostname: None,
    };
    let parsed = Config::parse(&first.config_toml, &ctx).map_err(|e| e.to_string())?;
    let mut options = StartOptions {
        interface_name: first.name.clone(),
        hostname: None,
        intercept_dns: true,
        mdns_exclude: Vec::new(),
        resolvers: Vec::new(),
        fwmark: None,
        watch_network: false,
    };
    if callbacks.mdns.is_none() {
        options
            .mdns_exclude
            .extend(iface::holding(parsed.own_addrs().ula));
    }
    Host::start(specs, options, HostDns::default(), callbacks)
}
