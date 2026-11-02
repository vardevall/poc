//! The host's state as `vv-quick` keeps it: what it has applied, what the running interface says
//! it should be, and the way back.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use serde_json::Value;

use crate::plan::{Addrs, Client, Cmd, Dns, Step};

/// What runs the commands; the system's in `vv-quick`, a recorder in the tests.
pub trait Exec {
    /// Runs `cmd`.
    fn run(&mut self, cmd: &Cmd) -> Result<()>;
    /// The current value of a sysctl.
    fn sysctl(&mut self, key: &str) -> Option<String>;
    /// Whether the network device exists.
    fn device_exists(&mut self, device: &str) -> bool;
}

/// The addresses a `status` answer says the host should have: none while no exit is in use; the
/// exit's while one is live; the home address and no address in the site until one is.
pub fn wanted(status: &Value) -> Addrs {
    let exit = &status["exit"];
    if !exit["network"].is_string() {
        return Addrs::default();
    }
    let chosen = &exit["chosen"];
    if chosen.is_object() {
        let v4 = chosen["ipv4"]
            .as_str()
            .and_then(|a| a.parse::<Ipv4Addr>().ok());
        Addrs {
            on: true,
            site6: chosen["addr"]
                .as_str()
                .and_then(|a| a.parse::<Ipv6Addr>().ok()),
            v4,
            v4_blackhole: v4.is_none(),
        }
    } else {
        Addrs {
            on: true,
            site6: None,
            v4: exit["ipv4_home"].as_str().and_then(|a| a.parse().ok()),
            v4_blackhole: false,
        }
    }
}

/// What `vv-quick` has applied to one host.
pub struct Host<E: Exec> {
    exec: E,
    client: Client,
    dns: Option<Dns>,
    forward: bool,
    undo: Vec<Cmd>,
    rule_undo: Vec<Cmd>,
    have: Addrs,
    dns_all: bool,
    /// The sysctls changed, with the values to put back.
    pub sysctls: Vec<(String, String)>,
}

fn warn(what: &Result<()>) {
    if let Err(e) = what {
        eprintln!("warning: {e:#}");
    }
}

impl<E: Exec> Host<E> {
    /// A host with nothing applied. `dns` is none where the system's DNS is left alone.
    pub fn new(exec: E, client: Client, dns: Option<Dns>, forward: bool) -> Self {
        Host {
            exec,
            client,
            dns,
            forward,
            undo: Vec::new(),
            rule_undo: Vec::new(),
            have: Addrs::default(),
            dns_all: false,
            sysctls: Vec::new(),
        }
    }

    /// Applies the steps that make the host serve an exit; the first failure stops them and is
    /// the error, with what was applied before it still to be taken back by [`Host::teardown`].
    pub fn serve(&mut self, steps: Vec<Step>) -> Result<()> {
        for step in steps {
            match step {
                Step::Run { apply, undo } => {
                    self.exec.run(&apply)?;
                    self.undo.extend(undo);
                }
                Step::Sysctl { key, value } => {
                    let before = self.exec.sysctl(key);
                    if before.as_deref() == Some(value) {
                        continue;
                    }
                    self.exec
                        .run(&Cmd::new("sysctl", ["-w", &format!("{key}={value}")]))?;
                    if let Some(prev) = before {
                        self.undo
                            .push(Cmd::new("sysctl", ["-w", &format!("{key}={prev}")]));
                        self.sysctls.push((key.to_owned(), prev));
                    }
                }
            }
        }
        Ok(())
    }

    /// Scopes the overlay's domains to the node's resolver, if the host's DNS is driven.
    pub fn start_dns(&mut self) {
        if let Some(dns) = &self.dns {
            for c in dns.base() {
                warn(&self.exec.run(&c));
            }
        }
    }

    /// Brings the host in line with what the running interface says (a `status` answer): the
    /// rules when an exit goes into use, the addresses and routes when its address or IPv4
    /// address changes, the DNS route for every name, and all of it back when the use ends.
    pub fn reconcile(&mut self, status: &Value) {
        let want = wanted(status);
        if want != self.have {
            if want.on && !self.have.on {
                for step in self.client.rules() {
                    if let Step::Run { apply, undo } = step {
                        warn(&self.exec.run(&apply));
                        self.rule_undo.extend(undo);
                    }
                }
            }
            if want.on {
                for c in self.client.addrs(&want, &self.have) {
                    warn(&self.exec.run(&c));
                }
            } else {
                self.stop_using();
            }
            self.have = want;
        }
        let all = self.have.on && !self.forward;
        if all != self.dns_all
            && let Some(dns) = &self.dns
        {
            let cmds = if all {
                dns.all_names()
            } else {
                dns.overlay_only()
            };
            for c in cmds {
                warn(&self.exec.run(&c));
            }
            self.dns_all = all;
        }
    }

    /// Runs `cmd` unless it is about the device and the device is gone, which took it along.
    fn run_unless_gone(&mut self, cmd: &Cmd, present: bool) {
        let device = self.client.device();
        let about = cmd.args.windows(2).any(|w| w[0] == "dev" && w[1] == device);
        if present || !about {
            warn(&self.exec.run(cmd));
        }
    }

    fn stop_using(&mut self) {
        let present = self.exec.device_exists(self.client.device());
        for c in self.client.off_addrs(&self.have) {
            self.run_unless_gone(&c, present);
        }
        for c in self.client.flush() {
            warn(&self.exec.run(&c));
        }
        for c in self.rule_undo.drain(..).rev() {
            warn(&self.exec.run(&c));
        }
    }

    /// Takes back everything applied, last first.
    pub fn teardown(&mut self) {
        if self.have.on {
            self.stop_using();
            self.have = Addrs::default();
        }
        let present = self.exec.device_exists(self.client.device());
        if let Some(dns) = &self.dns
            && present
        {
            warn(&self.exec.run(&dns.revert()));
        }
        for c in std::mem::take(&mut self.undo).iter().rev() {
            self.run_unless_gone(c, present);
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use vardevall_proto::ip::exit::ExitServe;
    use vardevall_proto::keys::NetworkId;
    use vardevall_tun::numbering::Numbering;

    use super::*;
    use crate::plan::Serve;

    #[derive(Default)]
    struct Recorder {
        log: Vec<String>,
        sysctls: Vec<(String, String)>,
        fail: Option<&'static str>,
        gone: bool,
    }

    impl Exec for Recorder {
        fn run(&mut self, cmd: &Cmd) -> Result<()> {
            let line = cmd.to_string();
            if self.fail.is_some_and(|f| line.contains(f)) {
                anyhow::bail!("{line} failed");
            }
            self.log.push(line);
            Ok(())
        }

        fn device_exists(&mut self, _: &str) -> bool {
            !self.gone
        }

        fn sysctl(&mut self, key: &str) -> Option<String> {
            self.sysctls
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
        }
    }

    fn host(recorder: Recorder, forward: bool) -> Host<Recorder> {
        let n = Numbering::from_slot(308).unwrap();
        let dns = Dns::new(
            "home",
            "fd00::1".parse().unwrap(),
            53,
            "home.internal",
            &NetworkId::from_bytes([2; 32]),
        );
        Host::new(recorder, Client::new("home", n), Some(dns), forward)
    }

    fn off() -> Value {
        json!({"exit": {"network": null, "site": null, "chosen": null, "ipv4_home": "198.18.1.1"}})
    }

    fn waiting() -> Value {
        json!({"exit": {"network": "home", "site": null, "chosen": null, "ipv4_home": "198.18.1.1"}})
    }

    fn live(addr: &str, ipv4: Value) -> Value {
        json!({"exit": {"network": "home", "site": "it/home", "ipv4_home": "198.18.1.1",
            "chosen": {"site": "it/home", "via": "VIA", "addr": addr, "ipv4": ipv4}}})
    }

    #[test]
    fn the_wanted_addresses_follow_the_status() {
        assert_eq!(wanted(&off()), Addrs::default());
        let w = wanted(&waiting());
        assert!(w.on && w.site6.is_none() && w.v4 == Some("198.18.1.1".parse().unwrap()));
        let l = wanted(&live("fd00:0:0:1::7", json!("198.18.3.4")));
        assert_eq!(l.site6, Some("fd00:0:0:1::7".parse().unwrap()));
        assert_eq!(l.v4, Some("198.18.3.4".parse().unwrap()));
        assert!(!l.v4_blackhole);
        assert!(wanted(&live("fd00:0:0:1::7", Value::Null)).v4_blackhole);
    }

    #[test]
    fn a_use_puts_in_the_rules_then_follows_the_exit_and_a_stop_takes_it_all_away() {
        let mut h = host(Recorder::default(), false);
        h.start_dns();
        h.reconcile(&off());
        assert_eq!(h.exec.log.len(), 2, "only the overlay's DNS so far");

        h.reconcile(&waiting());
        let log = h.exec.log.clone();
        let rules = log.iter().filter(|l| l.contains(" rule add ")).count();
        assert_eq!(rules, 8);
        assert!(log.contains(&"ip -4 addr replace 198.18.1.1/32 dev home".to_owned()));
        assert!(
            log.iter()
                .any(|l| l.starts_with("resolvectl domain home") && l.ends_with("'~.'"))
        );
        assert!(log.contains(&"resolvectl default-route home yes".to_owned()));

        h.exec.log.clear();
        h.reconcile(&live("fd00:0:0:1::7", json!("198.18.3.4")));
        assert!(
            !h.exec.log.iter().any(|l| l.contains(" rule ")),
            "rules stay"
        );
        assert!(
            h.exec
                .log
                .contains(&"ip -4 addr del 198.18.1.1/32 dev home".to_owned())
        );

        h.exec.log.clear();
        h.reconcile(&live("fd00:0:0:2::7", json!("198.18.9.9")));
        assert!(
            h.exec
                .log
                .contains(&"ip -6 addr replace fd00:0:0:2::7/128 dev home nodad".to_owned())
        );
        assert!(
            h.exec
                .log
                .contains(&"ip -6 addr del fd00:0:0:1::7/128 dev home".to_owned())
        );

        h.exec.log.clear();
        h.reconcile(&live("fd00:0:0:2::7", json!("198.18.9.9")));
        assert!(h.exec.log.is_empty(), "nothing changed, nothing run");

        h.reconcile(&off());
        let log = h.exec.log.clone();
        assert_eq!(log.iter().filter(|l| l.contains(" rule del ")).count(), 8);
        assert!(log.contains(&"ip -6 route flush table 30308".to_owned()));
        assert!(log.contains(&"resolvectl default-route home no".to_owned()));
        let flush = log.iter().position(|l| l.contains("route flush")).unwrap();
        let rule = log.iter().position(|l| l.contains(" rule del ")).unwrap();
        assert!(flush < rule, "routes go before the rules");
    }

    #[test]
    fn with_forward_the_names_stay_on_the_overlay_domains() {
        let mut h = host(Recorder::default(), true);
        h.reconcile(&waiting());
        assert!(
            !h.exec
                .log
                .iter()
                .any(|l| l.contains("'~.'") || l.contains("default-route"))
        );
    }

    #[test]
    fn serving_sets_what_is_not_set_and_teardown_puts_it_back_last_first() {
        let n = NetworkId::from_bytes([2; 32]);
        let steps = Serve::new(
            "home",
            &n,
            &ExitServe {
                site: "it/home".parse().unwrap(),
                ipv4: true,
            },
        )
        .steps();
        let rec = Recorder {
            sysctls: vec![
                ("net.ipv6.conf.all.forwarding".into(), "0".into()),
                ("net.ipv4.ip_forward".into(), "1".into()),
            ],
            ..Recorder::default()
        };
        let mut h = host(rec, false);
        h.serve(steps).unwrap();
        assert_eq!(
            h.sysctls,
            vec![("net.ipv6.conf.all.forwarding".to_owned(), "0".to_owned())],
            "the one already on is left alone and not restored"
        );
        assert!(
            h.exec
                .log
                .contains(&"sysctl -w net.ipv6.conf.all.forwarding=1".to_owned())
        );
        assert!(!h.exec.log.iter().any(|l| l.contains("ip_forward")));
        h.exec.log.clear();
        h.teardown();
        let log = &h.exec.log;
        assert_eq!(log[0], "resolvectl revert home");
        assert_eq!(
            log.last().unwrap(),
            "sysctl -w net.ipv6.conf.all.forwarding=0"
        );
        let nft = log
            .iter()
            .position(|l| l.starts_with("nft delete"))
            .unwrap();
        let route = log.iter().position(|l| l.contains("route del")).unwrap();
        assert!(nft < route, "undone in the opposite order");
        assert_eq!(
            log.iter().filter(|l| l.starts_with("nft delete")).count(),
            3
        );
    }

    #[test]
    fn a_failing_step_of_serving_is_the_error_and_the_rest_is_not_run() {
        let n = NetworkId::from_bytes([2; 32]);
        let steps = Serve::new(
            "home",
            &n,
            &ExitServe {
                site: "it/home".parse().unwrap(),
                ipv4: false,
            },
        )
        .steps();
        let mut h = host(
            Recorder {
                fail: Some("nft -f"),
                ..Recorder::default()
            },
            false,
        );
        assert!(h.serve(steps).is_err());
        h.exec.log.clear();
        h.teardown();
        assert!(
            h.exec.log.iter().any(|l| l.contains("route del")),
            "what was applied is taken back"
        );
    }

    #[test]
    fn when_the_device_is_gone_what_is_about_it_is_not_run_but_the_rest_still_is() {
        let mut h = host(Recorder::default(), false);
        h.reconcile(&live("fd00:0:0:1::7", json!("198.18.3.4")));
        h.exec.log.clear();
        h.exec.gone = true;
        h.teardown();
        let log = &h.exec.log;
        assert!(!log.iter().any(|l| l.contains(" dev home")), "{log:?}");
        assert!(log.contains(&"ip -4 route flush table 30308".to_owned()));
        assert_eq!(log.iter().filter(|l| l.contains(" rule del ")).count(), 8);
    }
}
