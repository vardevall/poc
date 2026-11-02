use std::time::Duration;

use vardevall::{Endpoint, SwitchAuth, WantBand, WantLatency};
use vardevall_proto::ip::service::Proto;
use vardevall_tun::config::{Config, ConfigError, Context, SwitchPath, TurnCredentials};
use vardevall_tun::keys;
use vardevall_tun::settings::TunnelSettings;

struct Keys {
    node: String,
    net: String,
    peer: String,
}

fn keys() -> Keys {
    Keys {
        node: keys::generate_node_key(),
        net: keys::generate_network_secret(),
        peer: keys::public_key(&keys::generate_node_key()).unwrap(),
    }
}

fn ctx(name: &str) -> Context {
    Context {
        interface_name: name.into(),
        hostname: Some("My Laptop.local".into()),
    }
}

fn minimal(k: &Keys) -> String {
    format!(
        "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{}\"\n",
        k.node, k.net
    )
}

fn err(text: &str) -> ConfigError {
    match Config::parse(text, &ctx("home")) {
        Ok(_) => panic!("accepted: {text}"),
        Err(e) => e,
    }
}

#[test]
fn defaults() {
    let k = keys();
    let c = Config::parse(&minimal(&k), &ctx("home")).unwrap();
    assert_eq!(c.name, "home");
    assert_eq!(c.listen_port, 0);
    assert_eq!(c.mtu, 1280);
    assert_eq!(c.domain, "home.internal");
    assert_eq!(c.own_name.as_deref(), Some("my-laptop"));
    assert_eq!(c.fallback_delay, vardevall::FALLBACK_DELAY);
    assert!(c.mdns && !c.accept_members);
    assert_eq!(c.switch_path, SwitchPath::On);
    assert_eq!(c.tun_class, vardevall::DeliveryClass::default());
    assert_eq!(c.detect_timeout, None);
    assert!(c.stun.is_empty() && c.services.is_empty());
    assert_eq!(c.network_id.to_base32(), keys::network_id(&k.net).unwrap());
    assert!(c.peers.is_empty() && c.switches.is_empty());
}

#[test]
fn full_example() {
    let k = keys();
    let sw = keys::public_key(&keys::generate_node_key()).unwrap();
    let text = format!(
        r#"
[interface]
private_key = "{n}"
network_secret = "{s}"
name = "laptop"
listen_port = 51820
mtu = 1400
domain = "Lab.Internal."
forward = ["[fd12:3456:789a::53]:53", "192.0.2.53:53"]
fallback_delay = "250ms"
accept_members = true
mdns = false
switch_path = "on"
tun_class = {{ band = "any", latency = "low", degrade = true }}
detect_timeout = "2s"

[[switch]]
address = "{sw}@switch.example.org:8443"
token = "t"

[[switch]]
address = "{sw}@switch.example.org"

[[switch]]
address = "web.example.org"

[[switch]]
address = "{sw}@[2001:db8::1]:8443"

[[turn]]
urls = ["turn:turn.example.com:3478", "turns:turn.example.com:443?transport=tcp"]
credentials_command = "cf-turn-creds"
priority = 2

[[turn]]
urls = ["turn:other.example.com"]
username = "u"
credential = "c"

[[stun]]
urls = ["stun:stun.example.com:3478", "stun:stun2.example.com:3478"]

[[stun]]
urls = ["stuns:stun.example.net"]
username = "u"
credential = "c"

[[service]]
name = "web"
port = 443

[[service]]
name = "dns"
port = 53
proto = "udp"

[[peer]]
public_key = "{p}"
name = "nas"
endpoint = "203.0.113.7:51820"

[[peer]]
public_key = "{q}"
endpoint = "nas2.example.org"
"#,
        n = k.node,
        s = k.net,
        p = k.peer,
        q = keys::public_key(&keys::generate_node_key()).unwrap()
    );
    let c = Config::parse(&text, &ctx("home")).unwrap();
    assert_eq!((c.listen_port, c.mtu), (51820, 1400));
    assert_eq!(c.domain, "lab.internal");
    assert_eq!(c.forward.len(), 2);
    assert_eq!(c.fallback_delay, Duration::from_millis(250));
    assert!(c.accept_members && !c.mdns);
    assert_eq!(c.switch_path, SwitchPath::On);
    let class = c.tun_class;
    assert_eq!(
        (class.band, class.latency),
        (WantBand::Any, WantLatency::Low)
    );
    assert!(class.degrade);
    assert_eq!(c.detect_timeout, Some(Duration::from_secs(2)));
    let nc = c.node_config(vardevall::MdnsMode::Off);
    assert_eq!(nc.fallback_delay, Duration::from_millis(250));
    assert_eq!(nc.detect_timeout, Some(Duration::from_secs(2)));
    assert_eq!(nc.tun_class, class);
    assert!(!nc.watch_network);
    assert_eq!((nc.stun.len(), nc.services.len()), (2, 2));
    assert_eq!(nc.stun[1].username.as_deref(), Some("u"));
    assert_eq!(nc.services[1].proto(), Proto::Udp);
    assert_eq!(c.switches[0].port, 8443);
    assert_eq!(c.switches[1].port, 443);
    assert_eq!(c.switches[0].token.as_deref(), Some("t"));
    assert!(matches!(c.switches[0].auth, SwitchAuth::Pinned(_)));
    assert!(matches!(c.switches[2].auth, SwitchAuth::Web { .. }));
    assert_eq!(
        (c.switches[2].host.as_str(), c.switches[2].port),
        ("web.example.org", 443)
    );
    assert_eq!(
        (c.switches[3].host.as_str(), c.switches[3].port),
        ("2001:db8::1", 8443)
    );
    assert!(matches!(c.switches[3].auth, SwitchAuth::Pinned(_)));
    let listed = &c.summary()["switches"];
    assert_eq!(listed[2]["address"], "web.example.org:443");
    assert_eq!(listed[2]["auth"], "web");
    assert_eq!(listed[3]["address"], "[2001:db8::1]:8443");
    assert_eq!(listed[3]["auth"], "pinned");
    assert!(!c.summary().to_string().contains("\"t\""), "no token");
    assert_eq!(c.turns[0].priority, 2);
    assert!(matches!(
        c.turns[0].credentials,
        TurnCredentials::Command(_)
    ));
    assert!(matches!(
        c.turns[1].credentials,
        TurnCredentials::Static { .. }
    ));
    assert_eq!(c.turns[1].priority, 1);
    assert_eq!(c.peers[0].name.as_deref(), Some("nas"));
    assert_eq!(
        c.peers[0].endpoints,
        vec![Endpoint::Addr("203.0.113.7:51820".parse().unwrap())]
    );
    assert!(matches!(c.peers[1].endpoints[0], Endpoint::Srv(_)));
}

#[test]
fn endpoint_local_marks_the_static_endpoints_of_a_peer_as_on_this_link() {
    let k = keys();
    let q = keys::public_key(&keys::generate_node_key()).unwrap();
    let text = format!(
        "{}[[peer]]\npublic_key = \"{}\"\nendpoint = \"192.168.1.20:51820\"\nendpoint_local = true\n\n\
         [[peer]]\npublic_key = \"{q}\"\nendpoint = \"203.0.113.7:51820\"\n",
        minimal(&k),
        k.peer
    );
    let c = Config::parse(&text, &ctx("home")).unwrap();
    assert!(c.peers[0].endpoint_local && !c.peers[1].endpoint_local);
    let specs = c.node_config(vardevall::MdnsMode::Off).peers;
    assert!(specs[0].endpoints_local && !specs[1].endpoints_local);

    let no_endpoint = format!(
        "{}[[peer]]\npublic_key = \"{}\"\nendpoint_local = true\n",
        minimal(&k),
        k.peer
    );
    assert!(err(&no_endpoint).to_string().contains("endpoint_local"));
    let wrong_type = format!(
        "{}[[peer]]\npublic_key = \"{}\"\nendpoint = \"192.168.1.20:1\"\nendpoint_local = \"yes\"\n",
        minimal(&k),
        k.peer
    );
    assert!(Config::parse(&wrong_type, &ctx("home")).is_err());
}

#[test]
fn unknown_keys_and_tables_are_rejected() {
    let k = keys();
    let m = minimal(&k);
    assert!(matches!(
        err(&format!("{m}colour = 1\n")),
        ConfigError::Syntax(_)
    ));
    assert!(matches!(
        err(&format!("{m}[extra]\nx = 1\n")),
        ConfigError::Syntax(_)
    ));
    assert!(matches!(
        err(&format!(
            "{m}[[peer]]\npublic_key = \"{}\"\nnmae = \"x\"\n",
            k.peer
        )),
        ConfigError::Syntax(_)
    ));
    assert!(matches!(err("[switch]\n"), ConfigError::Syntax(_)));
}

#[test]
fn reserved_keys_are_recognised_and_rejected() {
    let k = keys();
    let m = minimal(&k);
    for (extra, name) in [
        ("roster = \"home.roster\"\n", "roster"),
        ("roster_key = \"RWQ\"\n", "roster_key"),
    ] {
        match err(&format!("{m}{extra}")) {
            ConfigError::Reserved(n) => assert_eq!(n, name),
            e => panic!("{e}"),
        }
    }
    let with_routes = format!("{m}[[peer]]\npublic_key = \"{}\"\nroutes = []\n", k.peer);
    assert!(
        matches!(err(&with_routes), ConfigError::Syntax(_)),
        "there is no peer routes"
    );
    assert!(matches!(
        err(&format!("{m}exit = true\n")),
        ConfigError::Syntax(_)
    ));
}

#[test]
fn keys_must_be_base32() {
    let k = keys();
    let bad = format!(
        "[interface]\nprivate_key = \"nope\"\nnetwork_secret = \"{}\"\n",
        k.net
    );
    assert!(matches!(
        err(&bad),
        ConfigError::Key {
            field: "private_key"
        }
    ));
    let bad = format!(
        "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"1{}\"\n",
        k.node,
        &k.net[1..]
    );
    assert!(matches!(
        err(&bad),
        ConfigError::Key {
            field: "network_secret"
        }
    ));
    let missing = format!("[interface]\nprivate_key = \"{}\"\n", k.node);
    assert!(matches!(err(&missing), ConfigError::Syntax(_)));
}

#[test]
fn value_ranges() {
    let k = keys();
    let m = minimal(&k);
    for bad in [
        "mtu = 1279\n",
        "mtu = 70000\n",
        "listen_port = 70000\n",
        "fallback_delay = \"3\"\n",
        "fallback_delay = 3\n",
        "relay_timeout = \"3s\"\n",
        "switch_grace = \"500ms\"\n",
        "switch_path = \"sometimes\"\n",
        "switch_path = \"low\"\n",
        "switch_path = \"all\"\n",
        "tun_class = { band = \"wide\" }\n",
        "tun_class = { latency = \"fast\" }\n",
        "tun_class = { colour = 1 }\n",
        "tun_class = { degrade = \"yes\" }\n",
        "detect_timeout = 0\n",
        "detect_timeout = \"0\"\n",
        "detect_timeout = \"10001ms\"\n",
        "detect_timeout = \"1m\"\n",
        "detect_timeout = 3\n",
        "fallback_delay = \"soon\"\n",
        "domain = \"a..b\"\n",
        "name = \"Not A Label\"\n",
        "forward = [\"nope\"]\n",
    ] {
        let e = Config::parse(&format!("{m}{bad}"), &ctx("home"));
        assert!(e.is_err(), "{bad}");
    }
    for ok in [
        "fallback_delay = 0\n",
        "fallback_delay = \"1h\"\n",
        "switch_path = \"off\"\n",
        "tun_class = {}\n",
        "detect_timeout = \"10s\"\n",
    ] {
        assert!(
            Config::parse(&format!("{m}{ok}"), &ctx("home")).is_ok(),
            "{ok}"
        );
    }
    let off = Config::parse(&format!("{m}switch_path = \"off\"\n"), &ctx("home")).unwrap();
    assert_eq!(off.switch_path, SwitchPath::Off);
}

#[test]
fn peer_errors_of_vv07() {
    let k = keys();
    let m = minimal(&k);
    let own = keys::public_key(&k.node).unwrap();
    let dup = format!(
        "{m}[[peer]]\npublic_key = \"{0}\"\n[[peer]]\npublic_key = \"{0}\"\n",
        k.peer
    );
    assert!(matches!(err(&dup), ConfigError::Peer(_)));
    let selfp = format!("{m}[[peer]]\npublic_key = \"{own}\"\n");
    assert!(matches!(err(&selfp), ConfigError::Peer(_)));
    let other = keys::public_key(&keys::generate_node_key()).unwrap();
    let names = format!(
        "{m}[[peer]]\npublic_key = \"{}\"\nname = \"nas\"\n[[peer]]\npublic_key = \"{other}\"\nname = \"nas\"\n",
        k.peer
    );
    assert!(matches!(err(&names), ConfigError::Peer(_)));
    let own_name = format!(
        "{m}name = \"nas\"\n[[peer]]\npublic_key = \"{}\"\nname = \"nas\"\n",
        k.peer
    );
    let _ = own_name;
    let clash = format!(
        "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{}\"\nname = \"nas\"\n[[peer]]\npublic_key = \"{}\"\nname = \"nas\"\n",
        k.node, k.net, k.peer
    );
    assert!(matches!(err(&clash), ConfigError::Peer(_)));
    let long = "a".repeat(52);
    let bad_name = format!(
        "{m}[[peer]]\npublic_key = \"{}\"\nname = \"{long}\"\n",
        k.peer
    );
    assert!(matches!(err(&bad_name), ConfigError::Peer(_)));
    let no_key = format!("{m}[[peer]]\nname = \"x\"\n");
    assert!(matches!(err(&no_key), ConfigError::Syntax(_)));
    let bad_ep = format!(
        "{m}[[peer]]\npublic_key = \"{}\"\nendpoint = \"203.0.113.7\"\n",
        k.peer
    );
    assert!(err(&bad_ep).to_string().contains("endpoint"));
}

#[test]
fn turn_and_switch_validation() {
    let k = keys();
    let m = minimal(&k);
    for bad in [
        "[[turn]]\nurls = []\nusername = \"u\"\ncredential = \"c\"\n",
        "[[turn]]\nurls = [\"http://x\"]\nusername = \"u\"\ncredential = \"c\"\n",
        "[[turn]]\nurls = [\"turn:x\"]\n",
        "[[turn]]\nurls = [\"turn:x\"]\nusername = \"u\"\ncredential = \"c\"\ncredentials_command = \"c\"\n",
        "[[switch]]\naddress = \"zzz@example.org\"\n",
        "[[switch]]\naddress = \"192.0.2.1\"\n",
        "[[switch]]\naddress = \"[2001:db8::1]:443\"\n",
        "[[switch]]\naddress = \"switch.example.org:0\"\n",
        "[[switch]]\naddress = \"switch.example.org:70000\"\n",
        "[[switch]]\naddress = \"\"\n",
        "[[switch]]\naddress = \"a b.example.org\"\n",
        "[[switch]]\n",
    ] {
        assert!(
            Config::parse(&format!("{m}{bad}"), &ctx("home")).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn switch_addresses() {
    let k = keys();
    let m = minimal(&k);
    let sw = keys::public_key(&keys::generate_node_key()).unwrap();
    let parse = |address: &str| {
        let text = format!("{m}[[switch]]\naddress = \"{address}\"\ntoken = \"t\"\n");
        Config::parse(&text, &ctx("home")).map(|c| c.switches.into_iter().next().unwrap())
    };
    let web = parse("switch.example.net").unwrap();
    assert!(matches!(web.auth, SwitchAuth::Web { .. }));
    assert_eq!((web.host.as_str(), web.port), ("switch.example.net", 443));
    assert_eq!(web.token.as_deref(), Some("t"));
    let web = parse("switch.example.net:8443").unwrap();
    assert_eq!(web.port, 8443);
    let pinned = parse(&format!("{sw}@switch.example.net")).unwrap();
    assert!(matches!(pinned.auth, SwitchAuth::Pinned(_)));
    let literal = parse(&format!("{sw}@192.0.2.1:4455")).unwrap();
    assert_eq!((literal.host.as_str(), literal.port), ("192.0.2.1", 4455));
    assert!(matches!(
        parse("192.0.2.1:443"),
        Err(ConfigError::Switch(vardevall::AddressError::WebLiteral))
    ));
    assert!(matches!(
        parse("nokey@switch.example.net"),
        Err(ConfigError::Switch(vardevall::AddressError::Key))
    ));
}

#[test]
fn stun_entries() {
    let k = keys();
    let m = minimal(&k);
    for bad in [
        "[[stun]]\nurls = []\n",
        "[[stun]]\nurls = [\"turn:x\"]\n",
        "[[stun]]\nurls = [\"stun:x\"]\nusername = \"u\"\n",
        "[[stun]]\nurls = [\"stun:x\"]\ncredential = \"c\"\n",
        "[[stun]]\n",
        "[[stun]]\nurls = [\"stun:x\"]\npriority = 1\n",
    ] {
        assert!(
            Config::parse(&format!("{m}{bad}"), &ctx("home")).is_err(),
            "{bad}"
        );
    }
    let c = Config::parse(
        &format!("{m}[[stun]]\nurls = [\"stun:x\", \"stun:y:3479\"]\n"),
        &ctx("home"),
    )
    .unwrap();
    assert_eq!(c.stun[0].urls.len(), 2);
    assert!(c.stun[0].username.is_none());
}

#[test]
fn service_entries() {
    let k = keys();
    let m = minimal(&k);
    let one = |body: &str| format!("{m}[[service]]\n{body}\n");
    for bad in [
        one("name = \"web\""),
        one("port = 80"),
        one("name = \"web\"\nport = 0"),
        one("name = \"web\"\nport = 70000"),
        one("name = \"Web!\"\nport = 80"),
        one(&format!("name = \"{}\"\nport = 80", "a".repeat(52))),
        one("name = \"web\"\nport = 80\nproto = \"sctp\""),
        format!(
            "{}{}",
            one("name = \"web\"\nport = 80"),
            one("name = \"web\"\nport = 81\nproto = \"udp\"")
        ),
        (0..17).fold(m.clone(), |t, i| {
            format!("{t}[[service]]\nname = \"s{i}\"\nport = 80\n")
        }),
    ] {
        assert!(
            matches!(err(&bad), ConfigError::Service(_) | ConfigError::Syntax(_)),
            "{bad}"
        );
    }
    let c = Config::parse(
        &(0..16).fold(m.clone(), |t, i| {
            format!("{t}[[service]]\nname = \"s{i}\"\nport = 80\n")
        }),
        &ctx("home"),
    )
    .unwrap();
    assert_eq!(c.services.len(), 16);
    assert_eq!(c.summary()["services"][0]["proto"], "tcp");
}

#[test]
fn interface_names() {
    let k = keys();
    for bad in ["", "Home", "-x", "sixteen-chars-xx", "a.b"] {
        assert!(matches!(
            Config::parse(&minimal(&k), &ctx(bad)),
            Err(ConfigError::InterfaceName(_))
        ));
    }
    assert!(Config::parse(&minimal(&k), &ctx("a_b-1")).is_ok());
}

#[test]
fn summary_has_no_secrets() {
    let k = keys();
    let c = Config::parse(&minimal(&k), &ctx("home")).unwrap();
    let s = c.summary().to_string();
    assert!(!s.contains(&k.node) && !s.contains(&k.net));
    let v = c.summary();
    assert_eq!(v["public_key"], keys::public_key(&k.node).unwrap());
    assert_eq!(v["domain"], "home.internal");
}

#[test]
fn tunnel_settings_json() {
    let k = keys();
    let c = Config::parse(&minimal(&k), &ctx("home")).unwrap();
    let own = c.own_addrs();
    let s = TunnelSettings::for_config(&c);
    let v: serde_json::Value = serde_json::from_str(&s.to_json()).unwrap();
    assert_eq!(v["addrs"][0]["addr"], own.ula.to_string());
    assert_eq!(v["addrs"][0]["prefix"], 64);
    assert_eq!(v["addrs"][1]["addr"], own.link_local.to_string());
    assert_eq!(v["mtu"], 1280);
    assert_eq!(v["dns"]["servers"][0], own.ula.to_string());
    assert_eq!(v["dns"]["match_domains"][0], "home.internal");
    let reverse = v["dns"]["match_domains"][1].as_str().unwrap();
    assert!(reverse.ends_with(".ip6.arpa") && reverse.len() == 40);
    assert_eq!(v["routes"][0]["prefix"], 64);
    assert_eq!(
        v["routes"][0]["addr"]
            .as_str()
            .unwrap()
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()[..8],
        own.ula.octets()[..8]
    );
}

#[test]
fn the_exit_table_names_a_site_and_carries_ipv4_unless_told_not_to() {
    let k = keys();
    let m = minimal(&k);
    let c = Config::parse(&format!("{m}[exit]\nsite = \"IT/home\"\n"), &ctx("home")).unwrap();
    let e = c.exit.clone().expect("an exit");
    assert_eq!(e.site.to_string(), "it/home");
    assert!(e.ipv4);
    assert_eq!(c.summary()["exit"], "it/home");

    let c = Config::parse(
        &format!("{m}[exit]\nsite = \"de\"\nipv4 = false\n"),
        &ctx("home"),
    )
    .unwrap();
    assert!(!c.exit.unwrap().ipv4);

    let none = Config::parse(&m, &ctx("home")).unwrap();
    assert!(none.exit.is_none());
    assert!(none.summary()["exit"].is_null());
    assert!(none.node_config(vardevall::MdnsMode::Off).exit.is_none());
}

#[test]
fn a_bad_exit_table_is_rejected() {
    let k = keys();
    let m = minimal(&k);
    for extra in [
        "[exit]\n",
        "[exit]\nsite = \"italy\"\n",
        "[exit]\nsite = \"it/Home\"\n",
        "[exit]\nsite = \"it\"\nroutes = [\"::/0\"]\n",
        "[exit]\nsite = \"it\"\nnat64 = true\n",
        "[exit]\nsite = \"it\"\nipv4 = 1\n",
        "[exit]\nsite = \"it\"\nunknown = 1\n",
    ] {
        assert!(
            matches!(
                err(&format!("{m}{extra}")),
                ConfigError::Exit(_) | ConfigError::Syntax(_)
            ),
            "{extra}"
        );
    }
}
