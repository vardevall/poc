use super::{Config, ConfigDiff, Context};
use crate::keys;

struct Base {
    key: String,
    net: String,
    peer: String,
}

fn base() -> Base {
    Base {
        key: keys::generate_node_key(),
        net: keys::generate_network_secret(),
        peer: keys::public_key(&keys::generate_node_key()).unwrap(),
    }
}

fn parse(b: &Base, interface: &str, rest: &str) -> Config {
    let text = format!(
        "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{}\"\n{interface}\n{rest}",
        b.key, b.net
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

fn peer(b: &Base, extra: &str) -> String {
    format!("[[peer]]\npublic_key = \"{}\"\n{extra}\n", b.peer)
}

#[test]
fn the_same_file_differs_in_nothing() {
    let b = base();
    let a = parse(&b, "", &peer(&b, "name = \"x\""));
    let d = ConfigDiff::between(&a, &a.clone());
    assert!(d.is_empty() && !d.needs_restart() && d.lines().is_empty());
}

#[test]
fn peers_are_added_removed_renamed_and_changed() {
    let b = base();
    let none = parse(&b, "", "");
    let named = parse(&b, "", &peer(&b, "name = \"x\""));
    let d = ConfigDiff::between(&none, &named);
    assert_eq!(d.peers_added.len(), 1);
    assert_eq!(d.lines(), vec![format!("peer added: x ({})", &b.peer[..8])]);
    let d = ConfigDiff::between(&named, &none);
    assert_eq!(d.peers_removed.len(), 1);
    assert!(d.lines()[0].starts_with("peer removed: x"));

    let renamed = parse(&b, "", &peer(&b, "name = \"y\""));
    let d = ConfigDiff::between(&named, &renamed);
    assert_eq!(d.peers_renamed.len(), 1);
    assert!(d.peers_changed.is_empty() && d.lines()[0].ends_with("x -> y"));

    let moved = parse(
        &b,
        "",
        &peer(&b, "name = \"x\"\nendpoint = \"192.0.2.1:5\""),
    );
    let d = ConfigDiff::between(&named, &moved);
    assert_eq!(d.peers_changed.len(), 1);
    assert!(d.peers_renamed.is_empty());

    let psk = keys::generate_network_secret();
    let keyed = parse(
        &b,
        "",
        &peer(&b, &format!("name = \"x\"\npreshared_key = \"{psk}\"")),
    );
    assert_eq!(ConfigDiff::between(&named, &keyed).peers_changed.len(), 1);
}

#[test]
fn names_dns_servers_services_and_the_exit_are_live() {
    let b = base();
    let old = parse(&b, "", "");
    let new = parse(
        &b,
        "name = \"me\"\ndomain = \"lab.example\"\nforward = [\"192.0.2.53:53\"]",
        "[[stun]]\nurls = [\"stun:192.0.2.1:3478\"]\n\
         [[turn]]\nurls = [\"turn:192.0.2.2:3478\"]\nusername = \"u\"\ncredential = \"p\"\n\
         [[service]]\nname = \"web\"\nport = 80\n\
         [exit]\nsite = \"it/home\"\n",
    );
    let d = ConfigDiff::between(&old, &new);
    assert!(d.own_name && d.domain && d.forward && d.stun && d.turn && d.services && d.exit);
    assert!(!d.needs_restart());
    assert_eq!(d.lines().len(), 7);
}

#[test]
fn what_needs_a_restart_is_named() {
    let b = base();
    let old = parse(&b, "", "[[switch]]\naddress = \"web.example.org\"\n");
    let new = parse(
        &b,
        "listen_port = 4455\nmtu = 1400\nmdns = false\naccept_members = true\n\
         switch_path = \"off\"\nfallback_delay = \"7s\"\ndetect_timeout = \"3s\"\n\
         tun_class = { band = \"any\" }",
        "",
    );
    let d = ConfigDiff::between(&old, &new);
    assert_eq!(
        d.restart,
        vec![
            "listen_port",
            "mtu",
            "mdns",
            "accept_members",
            "fallback_delay",
            "switch_path",
            "tun_class",
            "detect_timeout",
            "switch"
        ]
    );
    let other = Base {
        key: keys::generate_node_key(),
        net: keys::generate_network_secret(),
        peer: b.peer.clone(),
    };
    let d = ConfigDiff::between(&old, &parse(&other, "", ""));
    assert!(d.restart.contains(&"private_key"));
    assert!(d.restart.contains(&"network_secret"));
    assert!(d.restart.contains(&"network_id"));
}
