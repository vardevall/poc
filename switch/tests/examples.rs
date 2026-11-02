//! The example configurations in `deploy/` parse, and say what the README says they do.

use std::path::{Path, PathBuf};

use vardevall_switch::config::{Binding, Config};

fn dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vv-examples-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("turn.secret"), "s3cret\n").unwrap();
    std::fs::write(dir.join("tokens.txt"), "token-one\n# comment\n").unwrap();
    dir
}

fn load(name: &str, dir: &Path) -> Config {
    let text = std::fs::read_to_string(Path::new("deploy").join(name)).unwrap();
    Config::parse(&text, dir).unwrap()
}

#[test]
fn the_documented_file_is_valid_as_it_stands() {
    let c = load("switch.toml", &dir());
    assert!(c.turn.is_none() && c.certificate.is_none() && c.tokens.is_empty());
    assert_eq!(c.served_hosts(), ["switch.example.org"]);
}

#[cfg(feature = "stun-turn")]
#[test]
fn the_personal_switch_has_tokens_stun_behind_them_and_silent_turn() {
    let c = load("personal.toml", &dir());
    assert_eq!(c.tokens, ["token-one"]);
    assert_eq!(c.served_hosts(), ["switch.example.org"]);
    assert!(c.stun.auth);
    let turn = c.turn.unwrap();
    assert!(turn.silent);
    let server = turn.server.unwrap();
    assert_eq!(
        server.relay_ipv4_public,
        Some("203.0.113.5".parse().unwrap())
    );
    assert_eq!(server.listen.len(), 2);
    assert!(c.certificate.is_none() && c.forwarded_header.is_none());
}

#[test]
fn the_public_switch_listens_on_loopback_only_and_has_no_stun_turn_or_tokens() {
    let c = load("public.toml", &dir());
    assert!(c.listen.is_empty());
    assert_eq!(c.plain_listen, ["127.0.0.1:8080".parse().unwrap()]);
    assert_eq!(c.binding, Binding::Challenge);
    assert_eq!(c.served_hosts(), ["vv.example.org"]);
    let header = c.forwarded_header.unwrap();
    assert_eq!(header.name.as_str(), "cf-connecting-ip");
    assert!(c.tokens.is_empty() && c.turn.is_none() && c.stun.uris.is_empty());
}

#[test]
fn the_container_file_is_valid() {
    let c = load("container.toml", &dir());
    assert_eq!(c.listen, ["[::]:8443".parse().unwrap()]);
    assert_eq!(c.served_hosts(), ["switch.example.org"]);
}
