//! What `vv-quick` runs on a Linux host, as data: commands to serve an exit and to
//! use one, the overlay's DNS, and what removes it all again. One small function runs them
//! (`exec.rs`); `--dry-run` prints them.

use std::fmt::{self, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr};

use vardevall_proto::addr;
use vardevall_proto::ip::exit::{EXIT_IPV4, ExitServe, IPV4_POOL};
use vardevall_proto::ip::private::PRIVATE_V4;
use vardevall_proto::ip::site::{self, Site};
use vardevall_proto::keys::NetworkId;
use vardevall_tun::numbering::Numbering;

/// One command: a program, its arguments and what it reads on its standard input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    /// The program, looked up in `PATH`.
    pub program: &'static str,
    /// Its arguments.
    pub args: Vec<String>,
    /// Text for its standard input.
    pub stdin: Option<String>,
}

impl Cmd {
    /// A command with no input.
    pub fn new<I, S>(program: &'static str, args: I) -> Cmd
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Cmd {
            program,
            args: args.into_iter().map(Into::into).collect(),
            stdin: None,
        }
    }

    fn with_stdin(mut self, text: String) -> Cmd {
        self.stdin = Some(text);
        self
    }
}

fn quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c));
    if plain {
        arg.to_owned()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.program)?;
        for a in &self.args {
            write!(f, " {}", quote(a))?;
        }
        if let Some(text) = &self.stdin {
            write!(f, " <<'EOF'\n{text}EOF")?;
        }
        Ok(())
    }
}

/// A step that has an undo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Run `apply`; `undo` takes it back.
    Run {
        /// What puts it in place.
        apply: Cmd,
        /// What takes it away, in order; none if nothing needs to.
        undo: Vec<Cmd>,
    },
    /// Set a sysctl to `value` if it is not; the previous value is what the undo restores.
    Sysctl {
        /// The key.
        key: &'static str,
        /// The value.
        value: &'static str,
    },
}

fn run(apply: Cmd, undo: Vec<Cmd>) -> Step {
    Step::Run { apply, undo }
}

fn ip(args: &[&str]) -> Cmd {
    Cmd::new("ip", args.iter().copied())
}

fn ip_s(args: Vec<String>) -> Cmd {
    Cmd::new("ip", args)
}

fn pool() -> String {
    format!("{}/{}", IPV4_POOL.0, IPV4_POOL.1)
}

/// The host side of one exit this node serves.
pub struct Serve {
    device: String,
    site: Site,
    site_net: Ipv6Addr,
    ipv4: bool,
}

impl Serve {
    /// The plan for the exit `serve` on `device`.
    pub fn new(device: &str, network_id: &NetworkId, serve: &ExitServe) -> Self {
        let mut octets = [0u8; 16];
        octets[..8].copy_from_slice(&site::site_prefix(network_id, &serve.site));
        Serve {
            device: device.to_owned(),
            site: serve.site.clone(),
            site_net: Ipv6Addr::from(octets),
            ipv4: serve.ipv4,
        }
    }

    /// The nftables ruleset, loadable with `nft -f`: a forward chain that clamps the TCP MSS and
    /// accepts what comes from or goes to the tunnel, and the masquerade of the site's `/64` and,
    /// with IPv4, of the pool.
    pub fn nft(&self) -> String {
        let dev = &self.device;
        let tables = Numbering::nft_tables(dev);
        let mut s = String::new();
        let _ = write!(
            s,
            "table inet {} {{\n\
             \tchain forward {{\n\
             \t\ttype filter hook forward priority filter; policy accept;\n\
             \t\tiifname \"{dev}\" tcp flags syn tcp option maxseg size set rt mtu\n\
             \t\toifname \"{dev}\" tcp flags syn tcp option maxseg size set rt mtu\n\
             \t\tiifname \"{dev}\" accept\n\
             \t\toifname \"{dev}\" ct state established,related accept\n\
             \t}}\n\
             }}\n\
             table ip6 {} {{\n\
             \tchain postrouting {{\n\
             \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
             \t\tip6 saddr {}/64 oifname != \"{dev}\" masquerade\n\
             \t}}\n\
             }}\n",
            tables[0].1, tables[1].1, self.site_net
        );
        if self.ipv4 {
            let _ = write!(
                s,
                "table ip {} {{\n\
                 \tchain postrouting {{\n\
                 \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
                 \t\tip saddr {} oifname != \"{dev}\" masquerade\n\
                 \t}}\n\
                 }}\n",
                tables[2].1,
                pool()
            );
        }
        s
    }

    /// The steps that make the host serve the exit, in order.
    pub fn steps(&self) -> Vec<Step> {
        let dev = &self.device;
        let mut steps = vec![Step::Sysctl {
            key: "net.ipv6.conf.all.forwarding",
            value: "1",
        }];
        if self.ipv4 {
            steps.push(Step::Sysctl {
                key: "net.ipv4.ip_forward",
                value: "1",
            });
        }
        let route = format!("{}/64", self.site_net);
        steps.push(run(
            ip(&["-6", "route", "replace", &route, "dev", dev]),
            vec![ip(&["-6", "route", "del", &route, "dev", dev])],
        ));
        if self.ipv4 {
            let a = format!("{EXIT_IPV4}/{}", IPV4_POOL.1);
            steps.push(run(
                ip(&["-4", "addr", "replace", &a, "dev", dev]),
                vec![ip(&["-4", "addr", "del", &a, "dev", dev])],
            ));
        }
        let tables = Numbering::nft_tables(dev);
        let shown = if self.ipv4 { 3 } else { 2 };
        let undo = tables[..shown]
            .iter()
            .map(|(family, name)| Cmd::new("nft", ["delete", "table", family, name]))
            .collect();
        let load = Cmd::new("nft", ["-f", "-"]).with_stdin(self.nft());
        steps.push(run(load, undo));
        steps
    }

    /// A comment saying what is served.
    pub fn title(&self) -> String {
        format!("Serving the exit of site {} on {}", self.site, self.device)
    }
}

/// The addresses a client configures for an exit in use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Addrs {
    /// The default routes and rules are in place.
    pub on: bool,
    /// This node's address in the site, once an exit is live.
    pub site6: Option<Ipv6Addr>,
    /// The IPv4 address: the exit's, or the home address while none is live.
    pub v4: Option<Ipv4Addr>,
    /// The exit carries no IPv4: IPv4 is dropped, never sent on the plain network.
    pub v4_blackhole: bool,
}

/// The host side of using an exit: addresses, default routes and rules on the device, as
/// `wg-quick` sets them. The default routes live in a table of their own, which
/// every packet without the engine's mark looks up; the main table answers first for everything
/// but a default route, and whole for the private IPv4 ranges, so the local networks keep
/// working. The rules have the explicit priorities of the interface's [`Numbering`].
pub struct Client {
    device: String,
    n: Numbering,
}

impl Client {
    /// The plan for `device`.
    pub fn new(device: &str, n: Numbering) -> Self {
        Client {
            device: device.to_owned(),
            n,
        }
    }

    fn rule(&self, add: &str, family: &str, selector: &[&str], priority: u32) -> Cmd {
        let mut args: Vec<String> = vec![family.into(), "rule".into(), add.into()];
        args.extend(selector.iter().map(|s| (*s).to_owned()));
        args.push("priority".into());
        args.push(priority.to_string());
        ip_s(args)
    }

    /// The rules, each with its undo; they stay while the use lasts.
    pub fn rules(&self) -> Vec<Step> {
        let n = &self.n;
        let table = n.table().to_string();
        let mark = format!("{:#x}/{:#x}", n.mark(), Numbering::mark_mask());
        let mut out = Vec::new();
        for family in ["-4", "-6"] {
            let sel: [&str; 4] = ["not", "fwmark", &mark, "table"];
            let mut apply = sel.to_vec();
            apply.push(&table);
            out.push(run(
                self.rule("add", family, &apply, n.table_priority()),
                vec![self.rule("del", family, &apply, n.table_priority())],
            ));
            let suppress = ["table", "main", "suppress_prefixlength", "0"];
            out.push(run(
                self.rule("add", family, &suppress, n.suppress_priority()),
                vec![self.rule("del", family, &suppress, n.suppress_priority())],
            ));
        }
        for (i, (net, len)) in (0u32..).zip(PRIVATE_V4) {
            let to = format!("{net}/{len}");
            let sel = ["to", to.as_str(), "lookup", "main"];
            out.push(run(
                self.rule("add", "-4", &sel, n.private_priority(i)),
                vec![self.rule("del", "-4", &sel, n.private_priority(i))],
            ));
        }
        out
    }

    /// The commands that bring the addresses and default routes from `have` to `want`: the new
    /// ones first, the routes replaced in one step, the old addresses last.
    pub fn addrs(&self, want: &Addrs, have: &Addrs) -> Vec<Cmd> {
        let (dev, table) = (&self.device, self.n.table().to_string());
        let mut out = Vec::new();
        if want.site6 != have.site6
            && let Some(a) = want.site6
        {
            out.push(ip_s(vec![
                "-6".into(),
                "addr".into(),
                "replace".into(),
                format!("{a}/128"),
                "dev".into(),
                dev.clone(),
                "nodad".into(),
            ]));
        }
        if want.v4 != have.v4
            && let Some(a) = want.v4
        {
            out.push(ip_s(vec![
                "-4".into(),
                "addr".into(),
                "replace".into(),
                format!("{a}/32"),
                "dev".into(),
                dev.clone(),
            ]));
        }
        if want != have {
            let mut r6: Vec<String> = ["-6", "route", "replace", "default", "dev"]
                .map(String::from)
                .into();
            r6.extend([dev.clone(), "table".into(), table.clone()]);
            if let Some(a) = want.site6 {
                r6.extend(["src".into(), a.to_string()]);
            }
            out.push(ip_s(r6));
            if let Some(a) = want.v4 {
                out.push(ip_s(vec![
                    "-4".into(),
                    "route".into(),
                    "replace".into(),
                    "default".into(),
                    "dev".into(),
                    dev.clone(),
                    "table".into(),
                    table.clone(),
                    "src".into(),
                    a.to_string(),
                ]));
            } else if want.v4_blackhole {
                out.push(ip_s(vec![
                    "-4".into(),
                    "route".into(),
                    "replace".into(),
                    "blackhole".into(),
                    "default".into(),
                    "table".into(),
                    table.clone(),
                ]));
            }
        }
        if let Some(o) = have.site6
            && want.site6 != have.site6
        {
            out.push(ip_s(vec![
                "-6".into(),
                "addr".into(),
                "del".into(),
                format!("{o}/128"),
                "dev".into(),
                dev.clone(),
            ]));
        }
        if let Some(o) = have.v4
            && want.v4 != have.v4
        {
            out.push(ip_s(vec![
                "-4".into(),
                "addr".into(),
                "del".into(),
                format!("{o}/32"),
                "dev".into(),
                dev.clone(),
            ]));
        }
        out
    }

    /// The commands that take the addresses of `have` off the device.
    pub fn off_addrs(&self, have: &Addrs) -> Vec<Cmd> {
        let dev = &self.device;
        let mut out = Vec::new();
        if let Some(a) = have.site6 {
            out.push(ip_s(vec![
                "-6".into(),
                "addr".into(),
                "del".into(),
                format!("{a}/128"),
                "dev".into(),
                dev.clone(),
            ]));
        }
        if let Some(a) = have.v4 {
            out.push(ip_s(vec![
                "-4".into(),
                "addr".into(),
                "del".into(),
                format!("{a}/32"),
                "dev".into(),
                dev.clone(),
            ]));
        }
        out
    }

    /// The commands that empty this interface's table.
    pub fn flush(&self) -> Vec<Cmd> {
        let table = self.n.table().to_string();
        ["-4", "-6"]
            .into_iter()
            .map(|family| ip(&[family, "route", "flush", "table", &table]))
            .collect()
    }

    /// The device the addresses and routes are on.
    pub fn device(&self) -> &str {
        &self.device
    }
}

/// The overlay's DNS in `systemd-resolved`: the overlay domain and its reverse zone go to the
/// node's resolver, and with an exit in use and no `forward`, every name does.
pub struct Dns {
    device: String,
    server: String,
    domains: Vec<String>,
}

impl Dns {
    /// The plan for the resolver at `address`, on `port`, of `domain` and `network_id`.
    pub fn new(
        device: &str,
        address: Ipv6Addr,
        port: u16,
        domain: &str,
        network_id: &NetworkId,
    ) -> Self {
        Dns {
            device: device.to_owned(),
            server: if port == 53 {
                address.to_string()
            } else {
                format!("[{address}]:{port}")
            },
            domains: vec![
                format!("~{domain}"),
                format!("~{}", addr::reverse_zone(network_id)),
            ],
        }
    }

    fn domain_cmd(&self, all: bool) -> Cmd {
        let mut args = vec!["domain".to_owned(), self.device.clone()];
        args.extend(self.domains.iter().cloned());
        if all {
            args.push("~.".into());
        }
        Cmd::new("resolvectl", args)
    }

    /// The overlay domains to the node's resolver.
    pub fn base(&self) -> Vec<Cmd> {
        vec![
            Cmd::new("resolvectl", ["dns", &self.device, &self.server]),
            self.domain_cmd(false),
        ]
    }

    /// Every name to the node's resolver, which relays them to the exit.
    pub fn all_names(&self) -> Vec<Cmd> {
        vec![
            self.domain_cmd(true),
            Cmd::new("resolvectl", ["default-route", &self.device, "yes"]),
        ]
    }

    /// Back to the overlay domains alone.
    pub fn overlay_only(&self) -> Vec<Cmd> {
        vec![
            self.domain_cmd(false),
            Cmd::new("resolvectl", ["default-route", &self.device, "no"]),
        ]
    }

    /// The command that takes all of it away.
    pub fn revert(&self) -> Cmd {
        Cmd::new("resolvectl", ["revert", &self.device])
    }
}

/// The commands that remove what an earlier run of the interface left behind, found by the
/// interface's own numbers and names only. A rule is deleted until none is left at the priority.
pub fn sweep(device: &str, n: &Numbering) -> Vec<Cmd> {
    let mut out = Vec::new();
    for family in ["-4", "-6"] {
        for p in n.priorities() {
            out.push(ip(&[family, "rule", "del", "priority", &p.to_string()]));
        }
        out.push(ip(&[
            family,
            "route",
            "flush",
            "table",
            &n.table().to_string(),
        ]));
    }
    for (family, name) in Numbering::nft_tables(device) {
        out.push(Cmd::new("nft", ["delete", "table", family, &name]));
    }
    out.push(Cmd::new("resolvectl", ["revert", device]));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> NetworkId {
        NetworkId::from_bytes([2; 32])
    }

    fn serve(ipv4: bool) -> Serve {
        Serve::new(
            "home",
            &net(),
            &ExitServe {
                site: "it/home".parse().unwrap(),
                ipv4,
            },
        )
    }

    fn texts(steps: &[Step]) -> Vec<String> {
        steps
            .iter()
            .map(|s| match s {
                Step::Run { apply, .. } => apply.to_string(),
                Step::Sysctl { key, value } => format!("sysctl {key}={value}"),
            })
            .collect()
    }

    #[test]
    fn an_exit_forwards_ipv6_and_masquerades_its_site() {
        let s = serve(false);
        let t = texts(&s.steps());
        assert_eq!(t[0], "sysctl net.ipv6.conf.all.forwarding=1");
        assert_eq!(
            t[1],
            "ip -6 route replace fdc6:a24b:ee63:cc8f::/64 dev home"
        );
        assert!(t[2].starts_with("nft -f - <<'EOF'\n"));
        let nft = s.nft();
        assert!(nft.contains("ip6 saddr fdc6:a24b:ee63:cc8f::/64 oifname != \"home\" masquerade"));
        assert!(
            nft.find("maxseg").unwrap() < nft.find("\"home\" accept").unwrap(),
            "the clamp comes before the accepts that end the chain"
        );
        assert!(!nft.contains("198.18") && !t.iter().any(|l| l.contains("ip_forward")));
    }

    #[test]
    fn ipv4_adds_forwarding_the_address_and_the_masquerade_of_the_pool() {
        let s = serve(true);
        let t = texts(&s.steps());
        assert!(t.contains(&"sysctl net.ipv4.ip_forward=1".to_owned()));
        assert!(t.contains(&"ip -4 addr replace 198.18.0.1/15 dev home".to_owned()));
        assert!(
            s.nft()
                .contains("ip saddr 198.18.0.0/15 oifname != \"home\" masquerade")
        );
    }

    #[test]
    fn serving_undoes_every_table_it_loads_by_name() {
        let undo: Vec<String> = serve(true)
            .steps()
            .into_iter()
            .flat_map(|s| match s {
                Step::Run { undo, .. } => undo.iter().map(ToString::to_string).collect(),
                Step::Sysctl { .. } => Vec::new(),
            })
            .collect();
        for want in [
            "nft delete table inet vv_home",
            "nft delete table ip6 vv_home_nat6",
            "nft delete table ip vv_home_nat4",
            "ip -6 route del fdc6:a24b:ee63:cc8f::/64 dev home",
        ] {
            assert!(undo.contains(&want.to_owned()), "{want}: {undo:?}");
        }
        assert_eq!(
            serve(false)
                .steps()
                .iter()
                .flat_map(|s| match s {
                    Step::Run { undo, .. } => undo.clone(),
                    Step::Sysctl { .. } => Vec::new(),
                })
                .filter(|u| u.program == "nft")
                .count(),
            2
        );
    }

    fn client() -> Client {
        Client::new("home", Numbering::from_slot(308).unwrap())
    }

    fn want() -> Addrs {
        Addrs {
            on: true,
            site6: Some("fd00:0:0:1::7".parse().unwrap()),
            v4: Some(Ipv4Addr::new(198, 18, 3, 4)),
            v4_blackhole: false,
        }
    }

    #[test]
    fn the_rules_have_explicit_priorities_in_the_order_the_exit_needs() {
        let n = Numbering::from_slot(308).unwrap();
        let rules: Vec<String> = client()
            .rules()
            .iter()
            .map(|s| match s {
                Step::Run { apply, .. } => apply.to_string(),
                Step::Sysctl { .. } => String::new(),
            })
            .collect();
        let mark = format!("{:#x}/{:#x}", n.mark(), Numbering::mark_mask());
        assert!(rules.contains(&format!(
            "ip -4 rule add not fwmark {mark} table {} priority {}",
            n.table(),
            n.table_priority()
        )));
        assert!(rules.contains(&format!(
            "ip -6 rule add table main suppress_prefixlength 0 priority {}",
            n.suppress_priority()
        )));
        assert!(rules.contains(&format!(
            "ip -4 rule add to 192.168.0.0/16 lookup main priority {}",
            n.private_priority(2)
        )));
        assert_eq!(rules.len(), 8);
        for r in &rules {
            let p: u32 = r.rsplit(' ').next().unwrap().parse().unwrap();
            assert!(n.priorities().contains(&p), "{r}");
        }
    }

    #[test]
    fn each_rule_has_an_undo_with_the_same_selector() {
        for s in client().rules() {
            let Step::Run { apply, undo } = s else {
                panic!()
            };
            let undo = &undo[0];
            assert_eq!(apply.args[1], "rule");
            assert_eq!(undo.args[2], "del");
            assert_eq!(apply.args[3..], undo.args[3..]);
        }
    }

    #[test]
    fn first_use_adds_the_addresses_and_default_routes_with_the_source() {
        let c = client().addrs(&want(), &Addrs::default());
        let t: Vec<String> = c.iter().map(ToString::to_string).collect();
        assert_eq!(t[0], "ip -6 addr replace fd00:0:0:1::7/128 dev home nodad");
        assert_eq!(t[1], "ip -4 addr replace 198.18.3.4/32 dev home");
        assert_eq!(
            t[2],
            "ip -6 route replace default dev home table 30308 src fd00:0:0:1::7"
        );
        assert_eq!(
            t[3],
            "ip -4 route replace default dev home table 30308 src 198.18.3.4"
        );
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn a_change_of_exit_adds_the_new_addresses_before_removing_the_old_ones() {
        let have = want();
        let next = Addrs {
            site6: Some("fd00:0:0:2::7".parse().unwrap()),
            v4: Some(Ipv4Addr::new(198, 18, 9, 9)),
            ..have.clone()
        };
        let t: Vec<String> = client()
            .addrs(&next, &have)
            .iter()
            .map(ToString::to_string)
            .collect();
        let pos = |what: &str| t.iter().position(|l| l.contains(what)).unwrap();
        assert!(
            pos("addr replace fd00:0:0:2::7")
                < pos("route replace default dev home table 30308 src fd00:0:0:2::7")
        );
        assert!(pos("route replace default") < pos("addr del fd00:0:0:1::7/128"));
        assert!(pos("-4 route replace") < pos("addr del 198.18.3.4/32"));
        assert!(client().addrs(&have, &have).is_empty(), "nothing changed");
    }

    #[test]
    fn an_exit_without_ipv4_drops_ipv4_and_no_live_exit_keeps_the_home_address() {
        let no_v4 = Addrs {
            v4: None,
            v4_blackhole: true,
            ..want()
        };
        let t: Vec<String> = client()
            .addrs(&no_v4, &Addrs::default())
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(t.contains(&"ip -4 route replace blackhole default table 30308".to_owned()));
        assert!(!t.iter().any(|l| l.contains("-4 addr")));

        let waiting = Addrs {
            on: true,
            site6: None,
            v4: Some(Ipv4Addr::new(198, 18, 1, 1)),
            v4_blackhole: false,
        };
        let t: Vec<String> = client()
            .addrs(&waiting, &Addrs::default())
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(t.contains(&"ip -6 route replace default dev home table 30308".to_owned()));
    }

    #[test]
    fn off_removes_the_addresses_and_flushes_the_table_of_this_interface_only() {
        let c = client();
        let t: Vec<String> = c
            .off_addrs(&want())
            .iter()
            .chain(&c.flush())
            .map(ToString::to_string)
            .collect();
        assert!(t.contains(&"ip -6 addr del fd00:0:0:1::7/128 dev home".to_owned()));
        assert!(t.contains(&"ip -4 route flush table 30308".to_owned()));
        assert!(t.contains(&"ip -6 route flush table 30308".to_owned()));
    }

    #[test]
    fn dns_scopes_the_overlay_and_optionally_every_name() {
        let d = Dns::new(
            "home",
            "fd00::1".parse().unwrap(),
            53,
            "home.internal",
            &net(),
        );
        let base: Vec<String> = d.base().iter().map(ToString::to_string).collect();
        assert_eq!(base[0], "resolvectl dns home fd00::1");
        assert!(base[1].starts_with("resolvectl domain home '~home.internal' '~"));
        assert!(!base[1].ends_with("~."));
        let all: Vec<String> = d.all_names().iter().map(ToString::to_string).collect();
        assert!(
            all[0].ends_with(" '~.'") || all[0].ends_with(" ~."),
            "{}",
            all[0]
        );
        assert_eq!(all[1], "resolvectl default-route home yes");
        assert_eq!(d.revert().to_string(), "resolvectl revert home");
        let odd = Dns::new(
            "home",
            "fd00::1".parse().unwrap(),
            5353,
            "home.internal",
            &net(),
        );
        assert_eq!(
            odd.base()[0].to_string(),
            "resolvectl dns home '[fd00::1]:5353'"
        );
    }

    #[test]
    fn the_sweep_removes_the_numbers_and_names_of_this_interface_and_nothing_else() {
        let n = Numbering::from_slot(5).unwrap();
        let cmds = sweep("home", &n);
        let t: Vec<String> = cmds.iter().map(ToString::to_string).collect();
        for p in n.priorities() {
            assert!(t.contains(&format!("ip -4 rule del priority {p}")));
            assert!(t.contains(&format!("ip -6 rule del priority {p}")));
        }
        assert!(t.contains(&format!("ip -4 route flush table {}", n.table())));
        assert!(t.contains(&"nft delete table inet vv_home".to_owned()));
        assert!(t.contains(&"nft delete table ip vv_home_nat4".to_owned()));
        assert_eq!(t.last().unwrap(), "resolvectl revert home");
        let other = Numbering::from_slot(6).unwrap();
        for p in other.priorities() {
            assert!(!t.iter().any(|l| l.ends_with(&format!("priority {p}"))));
        }
        assert!(!t.iter().any(|l| l.contains(&other.table().to_string())));
        for c in &cmds {
            assert!(
                ["ip", "nft", "resolvectl"].contains(&c.program),
                "no broad commands: {c}"
            );
            assert!(!c.to_string().contains("flush ruleset"));
        }
    }
}
