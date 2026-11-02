//! An exit and a client of it on Linux, end to end in two network namespaces.
//!
//! Needs root (or `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`), `ip`, `nft`, `ping` and `/dev/net/tun`, so
//! it is `#[ignore]`d. Build it as yourself and run the binary as root:
//!
//! ```text
//! cargo test -p vardevall-tun --test linux_exit --no-run
//! sudo target/debug/deps/linux_exit-<hash> --ignored --nocapture
//! ```
//!
//! A test binary built elsewhere takes the paths of `vv` and `vv-quick` from `VV_BIN` and
//! `VV_QUICK_BIN`.
//!
//! The lab is a client namespace `vvt-c` and an exit namespace `vvt-x` joined by a veth pair that
//! stands for the physical network (`10.99.0.0/24`, `fd99::/64`), with no other route. The exit
//! serves the site `it/home` with IPv4 and owns, on its loopback, `2001:db8:100::1` and
//! `192.0.2.1`, which stand for the internet. `vv-quick` applies the host's side in each
//! namespace. Both namespaces and everything in them are removed at the end,
//! whether it passes or not. Nothing is changed in the host's own namespace.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use vardevall_tun::control_client::default_path;
use vardevall_tun::keys;
use vardevall_tun::numbering::Numbering;

const VV: &str = env!("CARGO_BIN_EXE_vv");
const VV_QUICK: &str = env!("CARGO_BIN_EXE_vv-quick");

/// The `vv` binary: `VV_BIN` when set, for a test binary built on another machine.
fn vv() -> String {
    std::env::var("VV_BIN").unwrap_or_else(|_| VV.to_string())
}

/// The `vv-quick` binary: `VV_QUICK_BIN` when set.
fn vv_quick() -> String {
    std::env::var("VV_QUICK_BIN").unwrap_or_else(|_| VV_QUICK.to_string())
}
const CLIENT_NS: &str = "vvt-c";
const EXIT_NS: &str = "vvt-x";
const OUTSIDE6: &str = "2001:db8:100::1";
const OUTSIDE4: &str = "192.0.2.1";

fn run(program: &str, args: &[&str]) -> Output {
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{program}: {e}"))
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Runs `program` inside namespace `ns`.
fn within(ns: &str, program: &str, args: &[&str]) -> Output {
    let mut all = vec!["netns", "exec", ns, program];
    all.extend_from_slice(args);
    run("ip", &all)
}

fn within_ok(ns: &str, program: &str, args: &[&str]) -> String {
    let out = within(ns, program, args);
    assert!(
        out.status.success(),
        "{program} {args:?} in {ns}: {}",
        text(&out)
    );
    text(&out)
}

fn eventually(what: &str, seconds: u64, mut check: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < end {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("gave up waiting for {what}");
}

/// The namespaces, the daemons in them and the files; all gone when dropped.
struct Lab {
    dir: PathBuf,
    children: Vec<Child>,
}

impl Drop for Lab {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = run("kill", &["-TERM", &c.id().to_string()]);
            let end = Instant::now() + Duration::from_secs(10);
            while Instant::now() < end && matches!(c.try_wait(), Ok(None)) {
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = c.kill();
            let _ = c.wait();
        }
        for ns in [CLIENT_NS, EXIT_NS] {
            let _ = run("ip", &["netns", "del", ns]);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn file(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(format!("{name}.toml"));
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn build_namespaces() {
    for ns in [CLIENT_NS, EXIT_NS] {
        let _ = run("ip", &["netns", "del", ns]);
        assert!(
            run("ip", &["netns", "add", ns]).status.success(),
            "ip netns add"
        );
    }
    let ip = |args: &[&str]| {
        let out = run("ip", args);
        assert!(out.status.success(), "ip {args:?}: {}", text(&out));
    };
    ip(&[
        "link", "add", "vvt-c0", "type", "veth", "peer", "name", "vvt-x0",
    ]);
    ip(&["link", "set", "vvt-c0", "netns", CLIENT_NS]);
    ip(&["link", "set", "vvt-x0", "netns", EXIT_NS]);
    for (ns, dev, v4, v6) in [
        (CLIENT_NS, "vvt-c0", "10.99.0.1/24", "fd99::1/64"),
        (EXIT_NS, "vvt-x0", "10.99.0.2/24", "fd99::2/64"),
    ] {
        within_ok(ns, "ip", &["link", "set", "lo", "up"]);
        within_ok(ns, "ip", &["link", "set", dev, "up"]);
        within_ok(ns, "ip", &["-4", "addr", "add", v4, "dev", dev]);
        within_ok(ns, "ip", &["-6", "addr", "add", v6, "dev", dev, "nodad"]);
    }
    within_ok(
        EXIT_NS,
        "ip",
        &[
            "-6", "route", "add", "default", "via", "fd99::1", "dev", "vvt-x0",
        ],
    );
    within_ok(
        EXIT_NS,
        "ip",
        &["-6", "addr", "add", &format!("{OUTSIDE6}/128"), "dev", "lo"],
    );
    within_ok(
        EXIT_NS,
        "ip",
        &["-4", "addr", "add", &format!("{OUTSIDE4}/32"), "dev", "lo"],
    );
}

/// `vv-quick up <config>` in `ns`: it starts `vv` and applies the host's side.
fn spawn(ns: &str, config: &Path, extra: &[&str]) -> Child {
    Command::new("ip")
        .args(["netns", "exec", ns, &vv_quick(), "up"])
        .arg(config)
        .arg("--vv")
        .arg(vv())
        .args(extra)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("starting vv-quick")
}

/// `vv exit <config> <args>`, which asks the control socket of the interface.
fn vv_exit(config: &Path, args: &[&str]) -> Output {
    Command::new(vv())
        .arg("exit")
        .arg(config)
        .args(args)
        .output()
        .expect("vv exit")
}

fn rules(ns: &str) -> String {
    format!(
        "{}{}",
        within_ok(ns, "ip", &["-4", "rule", "show"]),
        within_ok(ns, "ip", &["-6", "rule", "show"])
    )
}

fn pings(ns: &str, version: &str, to: &str) -> bool {
    within(ns, "ping", &[version, "-c", "3", "-W", "3", to])
        .status
        .success()
}

fn tx_packets(ns: &str, dev: &str) -> u64 {
    within_ok(
        ns,
        "cat",
        &[&format!("/sys/class/net/{dev}/statistics/tx_packets")],
    )
    .trim()
    .parse()
    .unwrap()
}

#[test]
#[ignore = "needs root: see the header of this file"]
fn an_exit_in_use_carries_ipv6_and_ipv4_natively_and_the_tunnel_does_not_loop() {
    let id = run("id", &["-u"]);
    assert_eq!(text(&id).trim(), "0", "run this test as root");
    let dir = std::env::temp_dir().join(format!("vv-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut lab = Lab {
        dir: dir.clone(),
        children: Vec::new(),
    };
    build_namespaces();

    let net = keys::generate_network_secret();
    let (client_key, exit_key) = (keys::generate_node_key(), keys::generate_node_key());
    let client_pub = keys::public_key(&client_key).unwrap();
    let exit_pub = keys::public_key(&exit_key).unwrap();
    let client_toml = file(
        &dir,
        "vvtc",
        &format!(
            "[interface]\nprivate_key = \"{client_key}\"\nnetwork_secret = \"{net}\"\n\
             listen_port = 51820\nmdns = false\n\n\
             [[peer]]\npublic_key = \"{exit_pub}\"\nendpoint = \"10.99.0.2:51821\"\n"
        ),
    );
    let exit_toml = file(
        &dir,
        "vvtx",
        &format!(
            "[interface]\nprivate_key = \"{exit_key}\"\nnetwork_secret = \"{net}\"\n\
             listen_port = 51821\nmdns = false\n\n\
             [exit]\nsite = \"it/home\"\n\n\
             [[peer]]\npublic_key = \"{client_pub}\"\n"
        ),
    );
    let numbering = Numbering::for_interface("vvtc");
    let (mark, table) = (numbering.mark().to_string(), numbering.table().to_string());
    let exit_sock = default_path("vvtx");

    lab.children.push(spawn(EXIT_NS, &exit_toml, &[]));
    lab.children
        .push(spawn(CLIENT_NS, &client_toml, &["--exit", "it/home"]));
    eventually("the exit's control socket", 10, || exit_sock.exists());
    eventually("the exit to be served", 20, || {
        text(&within(EXIT_NS, "nft", &["list", "tables"])).contains("vv_vvtx")
    });
    eventually("the client to choose the exit", 40, || {
        let out = vv_exit(&client_toml, &[]);
        out.status.success() && text(&out).contains("via ")
    });
    let status = text(&vv_exit(&client_toml, &[]));
    let mine4 = status
        .split("IPv4 ")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .expect("the exit gave an IPv4 address")
        .to_owned();
    assert!(mine4.starts_with("198.1"), "{status}");
    eventually("vv-quick to put the exit in use", 20, || {
        rules(CLIENT_NS).contains(&format!("lookup {table}"))
    });

    // The default routes of the exit in use take the internet into the tunnel ...
    let v4 = within_ok(CLIENT_NS, "ip", &["-4", "route", "get", OUTSIDE4]);
    assert!(
        v4.contains("dev vvtc") && v4.contains(&format!("src {mine4}")),
        "{v4}"
    );
    let v6 = within_ok(CLIENT_NS, "ip", &["-6", "route", "get", OUTSIDE6]);
    assert!(v6.contains("dev vvtc") && v6.contains("src fd"), "{v6}");
    // ... the local network keeps working, and what carries the mark leaves by the physical
    // interface: the encapsulated packets do not loop into the tunnel.
    let lan = within_ok(CLIENT_NS, "ip", &["-4", "route", "get", "10.99.0.2"]);
    assert!(lan.contains("dev vvt-c0"), "{lan}");
    let marked = within_ok(
        CLIENT_NS,
        "ip",
        &["-4", "route", "get", "10.99.0.2", "mark", &mark],
    );
    assert!(marked.contains("dev vvt-c0"), "{marked}");
    let unreachable = within(
        CLIENT_NS,
        "ip",
        &["-4", "route", "get", OUTSIDE4, "mark", &mark],
    );
    assert!(
        !unreachable.status.success(),
        "a marked packet has no way to the internet in the lab, so it cannot enter the tunnel: {}",
        text(&unreachable)
    );

    // Traffic through the exit: IPv6 and IPv4, each as it is.
    let before = tx_packets(CLIENT_NS, "vvt-c0");
    assert!(pings(CLIENT_NS, "-6", OUTSIDE6), "IPv6 through the exit");
    assert!(pings(CLIENT_NS, "-4", OUTSIDE4), "IPv4 through the exit");
    assert!(
        tx_packets(CLIENT_NS, "vvt-c0") >= before + 6,
        "the encapsulated packets leave by the physical interface"
    );

    // Off: the use ends and vv-quick takes the rules away; the local network works.
    let off = vv_exit(&client_toml, &["off"]);
    assert!(off.status.success(), "{}", text(&off));
    eventually("vv-quick to take the rules away", 20, || {
        !rules(CLIENT_NS).contains("suppress_prefixlength")
    });
    assert!(
        within_ok(CLIENT_NS, "ip", &["-4", "route", "show", "table", &table])
            .trim()
            .is_empty()
    );
    assert!(
        !pings(CLIENT_NS, "-6", OUTSIDE6),
        "no route once the use ends"
    );
    assert!(
        pings(CLIENT_NS, "-4", "10.99.0.2"),
        "the local network still works"
    );

    // Stopping vv-quick stops vv, removes its control socket and leaves no rule behind.
    let client_sock = default_path("vvtc");
    let mut client = lab.children.pop().unwrap();
    let _ = run("kill", &["-TERM", &client.id().to_string()]);
    let status = client.wait().unwrap();
    assert!(
        status.success(),
        "vv-quick stops cleanly on SIGTERM: {status}"
    );
    assert!(!client_sock.exists(), "the control socket is removed");
    assert!(rules(CLIENT_NS).lines().all(|l| !l.contains("fwmark")));
}
