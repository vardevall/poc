//! `vv-quick up` and `down`: a supervisor in the foreground around `vv up`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use tokio::signal::unix::{SignalKind, signal};
use vardevall_proto::addr::reverse_zone;
use vardevall_tun::config::Config;
use vardevall_tun::control_client::{ask, default_path, running};
use vardevall_tun::files;
use vardevall_tun::numbering::Numbering;

use crate::exec;
use crate::host::{Exec, Host, wanted};
use crate::plan::{self, Client, Cmd, Dns, Serve, Step};
use crate::state::{self, State};

/// What `vv-quick up` was asked.
pub struct UpOptions {
    /// An interface name or a path.
    pub interface: String,
    /// Use an exit from the start: the site, or empty for the network's only one.
    pub exit: Option<String>,
    /// Print the commands and apply nothing.
    pub dry_run: bool,
    /// The slot of the numbers, if not the one the name gives.
    pub slot: Option<u16>,
    /// The `vv` to start.
    pub vv: Option<PathBuf>,
    /// Print each command as it runs.
    pub verbose: bool,
}

/// Runs commands on the system.
struct System {
    verbose: bool,
}

impl Exec for System {
    fn run(&mut self, cmd: &Cmd) -> Result<()> {
        exec::run(cmd, self.verbose)
    }

    fn sysctl(&mut self, key: &str) -> Option<String> {
        exec::output("sysctl", &["-n", key])
    }

    fn device_exists(&mut self, device: &str) -> bool {
        Path::new("/sys/class/net").join(device).exists()
    }
}

fn numbering(interface: &str, slot: Option<u16>) -> Result<Numbering> {
    match slot {
        Some(s) => Numbering::from_slot(s)
            .with_context(|| format!("--slot is below {}", vardevall_tun::numbering::SLOTS)),
        None => Ok(Numbering::for_interface(interface)),
    }
}

/// Whether the host's DNS can be driven: `systemd-resolved` runs, and this is the initial network
/// namespace, since it knows interfaces by index and an index of a container is another interface
/// to it.
fn manages_dns() -> bool {
    use std::os::unix::fs::MetadataExt;
    /// `PROC_NET_INIT_INO`, the inode number of the initial network namespace.
    const INITIAL_NET_NS: u64 = 0xEFFF_FFFC;
    Path::new("/run/systemd/resolve/io.systemd.Resolve").exists()
        && std::fs::metadata("/proc/self/ns/net").is_ok_and(|m| m.ino() == INITIAL_NET_NS)
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|u| u.split_whitespace().next().map(|w| w == "0"))
            .unwrap_or(false)
    })
}

fn dns_plan(config: &Config, status: Option<&Value>) -> Option<Dns> {
    let port = status?["dns"]["port"].as_u64()?;
    Some(Dns::new(
        &config.name,
        config.own_addrs().ula,
        u16::try_from(port).ok()?,
        &config.domain,
        &config.network_id,
    ))
}

fn commented(cmd: &Cmd) -> String {
    cmd.to_string()
        .lines()
        .map(|l| format!("# {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The commands `up` would run for `config`, and the ones that take them back, as text.
fn dry_run_text(
    config: &Config,
    n: &Numbering,
    exit: bool,
    status: Option<&Value>,
    resolved: bool,
) -> String {
    let device = status
        .and_then(|s| s["device"].as_str())
        .unwrap_or(&config.name)
        .to_owned();
    let mut out = format!(
        "# vv-quick up {} (dry run): nothing is applied. Slot {}: mark {:#x}, table {}, priorities {}..{}.\n",
        config.name,
        n.slot(),
        n.mark(),
        n.table(),
        n.priorities().start,
        n.priorities().end - 1
    );
    let mut undo: Vec<Cmd> = Vec::new();
    let line = |out: &mut String, c: &Cmd| {
        out.push_str(&c.to_string());
        out.push('\n');
    };
    let mut cmds = |out: &mut String, steps: Vec<Step>| {
        for s in steps {
            match s {
                Step::Run { apply, undo: u } => {
                    line(out, &apply);
                    undo.extend(u);
                }
                Step::Sysctl { key, value } => {
                    line(out, &Cmd::new("sysctl", ["-w", &format!("{key}={value}")]));
                }
            }
        }
    };
    if let Some(serve) = &config.exit {
        let s = Serve::new(&device, &config.network_id, serve);
        out.push_str(&format!("\n# {}\n", s.title()));
        cmds(&mut out, s.steps());
    }
    let client = Client::new(&device, *n);
    let want = if exit {
        let mut w = status.map(wanted).unwrap_or_default();
        if !w.on {
            w.on = true;
            w.v4 = Some(vardevall::home_ipv4(&config.network_id, &config.public_key));
        }
        w
    } else {
        plan::Addrs::default()
    };
    if want.on {
        out.push_str(&format!(
            "\n# Using an exit on {device}. vv-quick applies the addresses again when the exit or its\n\
             # addresses change.\n"
        ));
        cmds(&mut out, client.rules());
        for c in client.addrs(&want, &plan::Addrs::default()) {
            line(&mut out, &c);
        }
    }
    let dns = dns_plan(config, status).or_else(|| {
        Some(Dns::new(
            &device,
            config.own_addrs().ula,
            53,
            &config.domain,
            &config.network_id,
        ))
    });
    if let Some(dns) = dns {
        out.push_str(&format!(
            "\n# The overlay's DNS ({}reverse zone {}):\n",
            if resolved {
                ""
            } else {
                "systemd-resolved is not driven on this host, so these are comments; "
            },
            reverse_zone(&config.network_id)
        ));
        let mut all = dns.base();
        if want.on && config.forward.is_empty() {
            all.extend(dns.all_names());
        }
        for c in all {
            if resolved {
                line(&mut out, &c);
            } else {
                out.push_str(&commented(&c));
                out.push('\n');
            }
        }
    }
    out.push_str("\n# Off again, in this order (vv-quick runs them when it stops):\n");
    if want.on {
        for c in client.off_addrs(&want).iter().chain(&client.flush()) {
            out.push_str(&commented(c));
            out.push('\n');
        }
    }
    for c in undo.iter().rev() {
        out.push_str(&commented(c));
        out.push('\n');
    }
    out
}

fn status_of(interface: &str) -> Option<Value> {
    ask(&default_path(interface), &json!({"request": "status"})).ok()
}

fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    done()
}

/// Removes what an earlier run of this interface left: stops its `vv up` if the state file names
/// it, puts back its sysctls, and takes its rules, routes, tables and DNS away by number and name.
fn sweep(interface: &str, device: &str, n: &Numbering, verbose: bool) -> Result<()> {
    let file = state::path(interface);
    if let Some(old) = state::read(&file) {
        if state::is_quick(old.pid) && old.pid != std::process::id() {
            bail!("vv-quick already runs {interface} (pid {})", old.pid);
        }
        let socket = default_path(interface);
        if state::is_vv_of(old.child, interface)
            && ask(&socket, &json!({"request": "down"})).is_ok()
        {
            eprintln!("stopping the vv of an earlier run");
            wait_until(Duration::from_secs(10), || !socket.exists());
        }
        for (key, prev) in &old.sysctls {
            let c = Cmd::new("sysctl", ["-w", &format!("{key}={prev}")]);
            let _ = exec::run(&c, verbose);
        }
    } else if status_of(interface).is_some() {
        bail!("a vv already runs {interface}: stop it first, or let vv-quick start it");
    }
    for c in plan::sweep(device, n) {
        exec::run_quiet(&c);
        if c.args.windows(2).any(|w| w == ["rule", "del"]) {
            for _ in 0..8 {
                if !exec::run_quiet(&c) {
                    break;
                }
            }
        }
    }
    let _ = std::fs::remove_file(&file);
    Ok(())
}

/// Another running interface with the same slot would share its numbers.
fn check_slot_free(interface: &str, n: &Numbering) -> Result<()> {
    for other in running() {
        if other == interface {
            continue;
        }
        let same = state::read(&state::path(&other))
            .map_or_else(
                || Numbering::for_interface(&other),
                |s| Numbering::from_slot(s.slot).unwrap_or(*n),
            )
            .slot()
            == n.slot();
        if same {
            bail!(
                "{other} runs with the same numbers (slot {}): start one of them with --slot",
                n.slot()
            );
        }
    }
    Ok(())
}

fn vv_program(option: Option<&Path>) -> PathBuf {
    if let Some(p) = option {
        return p.to_owned();
    }
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("vv")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("vv"))
}

fn start_vv(o: &UpOptions, mark: u32) -> Result<Child> {
    let mut cmd = Command::new(vv_program(o.vv.as_deref()));
    cmd.args(["up", &o.interface, "--fwmark", &mark.to_string()]);
    if o.verbose {
        cmd.arg("--verbose");
    }
    match o.exit.as_deref() {
        None => {}
        Some("") => {
            cmd.arg("--exit");
        }
        Some(site) => {
            cmd.args(["--exit", site]);
        }
    }
    cmd.spawn().context("starting vv")
}

fn stop_vv(child: &mut Child, interface: &str) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = ask(&default_path(interface), &json!({"request": "down"}));
        let ended = wait_until(Duration::from_secs(10), || {
            child.try_wait().ok().flatten().is_some()
        });
        if !ended {
            let _ = child.kill();
        }
    }
    let _ = child.wait();
}

/// `vv-quick up`.
pub fn up(o: UpOptions) -> Result<()> {
    let config = files::load(&o.interface)?;
    let n = numbering(&config.name, o.slot)?;
    let use_exit = o.exit.is_some();
    if o.dry_run {
        let status = status_of(&config.name);
        print!(
            "{}",
            dry_run_text(&config, &n, use_exit, status.as_ref(), manages_dns())
        );
        return Ok(());
    }
    if !cfg!(target_os = "linux") {
        bail!("vv-quick works on Linux only; `vv-quick up --dry-run` prints what it would run");
    }
    if !is_root() {
        bail!("vv-quick needs root");
    }
    let interface = config.name.clone();
    check_slot_free(&interface, &n)?;
    sweep(&interface, &interface, &n, o.verbose)?;

    let mut child = start_vv(&o, n.mark())?;
    let socket = default_path(&interface);
    let ready = wait_until(Duration::from_secs(30), || {
        child.try_wait().ok().flatten().is_some()
            || ask(&socket, &json!({"request": "status"})).is_ok()
    });
    if !ready || child.try_wait()?.is_some() {
        stop_vv(&mut child, &interface);
        bail!("vv did not come up");
    }
    let state_file = state::path(&interface);
    let mut st = State {
        pid: std::process::id(),
        child: child.id(),
        slot: n.slot(),
        sysctls: Vec::new(),
    };
    state::write(&state_file, &st)?;

    let status = status_of(&interface);
    let dns = if manages_dns() {
        dns_plan(&config, status.as_ref())
    } else {
        eprintln!(
            "warning: systemd-resolved is not driven here: the overlay's names are not set up"
        );
        None
    };
    let mut host = Host::new(
        System { verbose: o.verbose },
        Client::new(&interface, n),
        dns,
        !config.forward.is_empty(),
    );
    let applied = match &config.exit {
        Some(serve) => host.serve(Serve::new(&interface, &config.network_id, serve).steps()),
        None => Ok(()),
    };
    st.sysctls.clone_from(&host.sysctls);
    state::write(&state_file, &st)?;
    if let Err(e) = applied {
        host.teardown();
        stop_vv(&mut child, &interface);
        let _ = std::fs::remove_file(&state_file);
        return Err(e.context("serving the exit"));
    }
    host.start_dns();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let why = rt.block_on(async {
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = int.recv() => break Ok::<&str, std::io::Error>("interrupted"),
                _ = term.recv() => break Ok("terminated"),
                _ = tick.tick() => {
                    if child.try_wait()?.is_some() {
                        break Ok("vv ended");
                    }
                    if let Ok(status) = ask(&socket, &json!({"request": "status"})) {
                        host.reconcile(&status);
                    }
                }
            }
        }
    })?;
    eprintln!("vv-quick: {why}, taking the host's side away");
    host.teardown();
    stop_vv(&mut child, &interface);
    let _ = std::fs::remove_file(&state_file);
    Ok(())
}

/// `vv-quick down`: ends the running `vv-quick` of the interface, which undoes its changes; a
/// run that was killed is cleaned up here instead.
pub fn down(interface: &str, slot: Option<u16>, verbose: bool) -> Result<()> {
    let name = files::locate(interface)?.1;
    let n = numbering(&name, slot)?;
    let file = state::path(&name);
    match state::read(&file) {
        Some(st) if state::is_quick(st.pid) => {
            let socket = default_path(&name);
            let _ = ask(&socket, &json!({"request": "down"}));
            if !wait_until(Duration::from_secs(20), || !state::is_quick(st.pid)) {
                let _ = exec::run(&Cmd::new("kill", [st.pid.to_string()]), verbose);
                if !wait_until(Duration::from_secs(10), || !state::is_quick(st.pid)) {
                    bail!("vv-quick (pid {}) did not end", st.pid);
                }
            }
            eprintln!("{name} is down");
        }
        Some(_) => {
            eprintln!("{name}: the earlier vv-quick is gone, cleaning up");
            sweep(&name, &name, &n, verbose)?;
        }
        None => {
            if status_of(&name).is_some() {
                bail!("{name} was not started by vv-quick: use `vv down {name}`");
            }
            sweep(&name, &name, &n, verbose)?;
            eprintln!("{name}: nothing was running; leftovers of its numbers are removed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use vardevall_tun::config::Context;
    use vardevall_tun::keys;

    use super::*;

    fn config(extra: &str) -> Config {
        let text = format!(
            "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{}\"\nname = \"me\"\n{extra}",
            keys::generate_node_key(),
            keys::generate_network_secret()
        );
        Config::parse(
            &text,
            &Context {
                interface_name: "home".into(),
                hostname: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn the_dry_run_of_a_client_prints_the_rules_the_addresses_the_dns_and_the_way_back() {
        let c = config("");
        let n = Numbering::from_slot(308).unwrap();
        let t = dry_run_text(&c, &n, true, None, true);
        assert!(t.contains("Slot 308: mark 0x76640134, table 30308"));
        assert!(t.contains(&format!(
            "ip -4 rule add table main suppress_prefixlength 0 priority {}",
            n.suppress_priority()
        )));
        assert!(t.contains("ip -4 addr replace 198.1"));
        assert!(t.contains("resolvectl dns home fd"));
        assert!(t.contains("'~.'"));
        assert!(t.contains("# Off again"));
        assert!(t.contains("# ip -4 route flush table 30308"));
        assert!(t.contains(&format!(
            "# ip -4 rule del table main suppress_prefixlength 0 priority {}",
            n.suppress_priority()
        )));
        assert_eq!(t.matches(" rule del ").count(), 8, "each rule once");
        let plain: Vec<&str> = t
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();
        assert!(plain.iter().all(|l| !l.contains(" del ")), "{plain:?}");
        assert!(!t.contains("nft"), "a client serves nothing");
    }

    #[test]
    fn the_dry_run_of_a_server_without_an_exit_in_use_prints_the_host_side_of_serving() {
        let c = config("\n[exit]\nsite = \"it/home\"\n");
        let n = Numbering::from_slot(1).unwrap();
        let t = dry_run_text(&c, &n, false, None, false);
        assert!(t.contains("# Serving the exit of site it/home on home"));
        assert!(t.contains("sysctl -w net.ipv6.conf.all.forwarding=1"));
        assert!(t.contains("nft -f - <<'EOF'\ntable inet vv_home {"));
        assert!(t.contains("# nft delete table inet vv_home"));
        assert!(!t.contains("rule add"));
        assert!(
            t.contains("\n# resolvectl dns home fd"),
            "without systemd-resolved the DNS lines are comments"
        );
    }

    #[test]
    fn a_slot_outside_the_range_is_refused() {
        assert!(numbering("home", Some(1000)).is_err());
        assert_eq!(numbering("home", Some(3)).unwrap().slot(), 3);
        assert_eq!(
            numbering("home", None).unwrap(),
            Numbering::for_interface("home")
        );
    }
}
