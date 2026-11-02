//! Addresses and resolver scoping for the tunnel interface (vv-06 §2.1, §4.4).

use std::io;
use std::net::Ipv6Addr;
use std::process::Command;

use anyhow::{Context, Result, bail};
use vardevall_proto::addr::OverlayAddrs;

pub fn run(program: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if !out.status.success() {
        bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn best_effort(program: &str, args: &[&str]) {
    if let Err(e) = run(program, args) {
        eprintln!("warning: {e:#}");
    }
}

/// Gives the interface its `ula/64` and `link_local/64` and its MTU.
pub fn configure_interface(ifname: &str, addrs: &OverlayAddrs, mtu: u16) -> Result<()> {
    let mtu = mtu.to_string();
    #[cfg(target_os = "macos")]
    {
        run("ifconfig", &[ifname, "mtu", &mtu])?;
        run(
            "ifconfig",
            &[
                ifname,
                "inet6",
                &format!("{}%{ifname}", addrs.link_local),
                "prefixlen",
                "64",
            ],
        )?;
        run(
            "ifconfig",
            &[ifname, "inet6", &addrs.ula.to_string(), "prefixlen", "64"],
        )?;
        strip_foreign_link_locals(ifname, &addrs.link_local);
    }
    #[cfg(target_os = "linux")]
    {
        run("ip", &["link", "set", "dev", ifname, "up", "mtu", &mtu])?;
        best_effort("ip", &["link", "set", "dev", ifname, "addrgenmode", "none"]);
        best_effort(
            "ip",
            &["-6", "addr", "flush", "dev", ifname, "scope", "link"],
        );
        run(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                &format!("{}/64", addrs.link_local),
                "dev",
                ifname,
                "nodad",
            ],
        )?;
        run(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                &format!("{}/64", addrs.ula),
                "dev",
                ifname,
                "nodad",
            ],
        )?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (ifname, addrs, mtu);
        bail!("interface configuration is not supported on this platform");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn strip_foreign_link_locals(ifname: &str, keep: &Ipv6Addr) {
    let Ok(out) = Command::new("ifconfig").arg(ifname).output() else {
        return;
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some(rest) = line.trim().strip_prefix("inet6 ") else {
            continue;
        };
        let token = rest.split_whitespace().next().unwrap_or("");
        let bare = token.split('%').next().unwrap_or("");
        if let Ok(a) = bare.parse::<Ipv6Addr>()
            && a.segments()[0] & 0xffc0 == 0xfe80
            && a != *keep
        {
            best_effort("ifconfig", &[ifname, "inet6", token, "-alias"]);
        }
    }
}

/// Routes the overlay domain and its reverse zone to the node's resolver on macOS, and undoes it
/// on drop. On Linux `vv-quick` does it with `systemd-resolved`.
pub struct Resolver {
    files: Vec<String>,
    #[allow(dead_code)]
    ifname: String,
    #[allow(dead_code)]
    domains: Vec<String>,
}

impl Resolver {
    /// Installs the split-DNS configuration.
    pub fn install(
        ifname: &str,
        domains: &[String],
        server: &Ipv6Addr,
        port: u16,
    ) -> io::Result<Resolver> {
        #[allow(unused_mut)]
        let mut r = Resolver {
            files: Vec::new(),
            ifname: ifname.to_owned(),
            domains: domains.to_vec(),
        };
        #[cfg(target_os = "macos")]
        {
            std::fs::create_dir_all("/etc/resolver")?;
            for d in domains {
                let path = format!("/etc/resolver/{d}");
                let port_line = if port == 53 {
                    String::new()
                } else {
                    format!("port {port}\n")
                };
                std::fs::write(
                    &path,
                    format!("# managed by vv, removed on exit\nnameserver {server}\n{port_line}"),
                )?;
                r.files.push(path);
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (domains, server, port);
        Ok(r)
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        for f in &self.files {
            let _ = std::fs::remove_file(f);
        }
    }
}
