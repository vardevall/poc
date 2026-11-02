//! Hot reload of the operator tokens (`reload`): the list, the open/closed state and the
//! sessions already admitted.

mod common;

use std::path::{Path, PathBuf};

use common::{Client, net_secret, node_key, register_body};
use http::{Method, StatusCode};
use vardevall_switch::config::Config;
use vardevall_switch::reload::reload;

/// A scratch directory holding the configuration and the token file.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        let dir = std::env::temp_dir().join(format!("vv-switch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir)
    }

    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.0.join(name), text).unwrap();
    }

    fn config(&self) -> PathBuf {
        self.0.join("switch.toml")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const HEAD: &str =
    "listen = [\"127.0.0.1:0\"]\nkey_file = \"switch.key\"\nnames = [\"switch.test\"]\n";
const FILE: &str = "[tokens]\nfile = \"tokens.txt\"\n";
const TURN: &str = "[turn]\nurls = [\"turn:t.example\"]\nsecret = \"s\"\n";

fn parse(path: &Path) -> Config {
    let text = std::fs::read_to_string(path).unwrap();
    Config::parse(&text, path.parent().unwrap()).unwrap()
}

/// Registers node `n` in its own network, with `token` if given.
async fn try_register(s: &common::TestSwitch, n: u8, token: Option<&str>) -> common::Reply {
    let mut c = Client::connect(s.addr, s.public).await;
    let body = register_body(&c, &s.public, &node_key(n), &net_secret(n));
    let auth = token.map(|t| format!("Bearer {t}"));
    let headers: Vec<(&str, &str)> = auth.iter().map(|a| ("authorization", a.as_str())).collect();
    c.request(Method::POST, "/v0/register", &headers, &body)
        .await
}

async fn token_required(s: &common::TestSwitch) -> bool {
    let mut c = Client::connect(s.addr, s.public).await;
    c.get("/v0/info", None).await.json()["token_required"]
        .as_bool()
        .unwrap()
}

async fn accepts(s: &common::TestSwitch, n: u8, token: &str) -> bool {
    let r = try_register(s, n, Some(token)).await;
    match r.status {
        StatusCode::OK => true,
        StatusCode::UNAUTHORIZED => {
            assert_eq!(r.error_code(), "urn:vardevall:error:token-required");
            false
        }
        other => panic!("{other}: {:?}", r.body),
    }
}

/// Registers node `n` with `token`, which must be accepted; returns the client and the session.
async fn register(s: &common::TestSwitch, n: u8, token: &str) -> (Client, String) {
    let mut c = Client::connect(s.addr, s.public).await;
    let body = register_body(&c, &s.public, &node_key(n), &net_secret(n));
    let auth = format!("Bearer {token}");
    let r = c
        .request(
            Method::POST,
            "/v0/register",
            &[("authorization", &auth)],
            &body,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.json()["turn"]["credential"].is_string());
    let session = r.json()["session"].as_str().unwrap().to_owned();
    (c, session)
}

async fn post(c: &mut Client, session: &str) -> common::Reply {
    c.request(Method::POST, "/v0/turn", &[("vv-session", session)], "")
        .await
}

#[tokio::test]
async fn the_list_follows_the_file() {
    let dir = Dir::new("list");
    dir.write("switch.toml", &format!("{HEAD}{FILE}"));
    dir.write("tokens.txt", "# operators\nalpha\nbeta\n");
    let s = common::start(parse(&dir.config())).await;
    let api = s.switch.api();

    assert!(accepts(&s, 1, "alpha").await);
    assert!(accepts(&s, 2, "beta").await);
    assert!(!accepts(&s, 3, "gamma").await);

    dir.write("tokens.txt", "beta\ngamma\n");
    assert_eq!(reload(api, &dir.config()).unwrap(), 2);
    assert!(!accepts(&s, 4, "alpha").await);
    assert!(accepts(&s, 5, "beta").await);
    assert!(accepts(&s, 6, "gamma").await);
    assert!(token_required(&s).await);

    // The accepted list inside the configuration file is reloaded too.
    dir.write(
        "switch.toml",
        &format!("{HEAD}[tokens]\nfile = \"tokens.txt\"\naccepted = [\"delta\"]\n"),
    );
    assert_eq!(reload(api, &dir.config()).unwrap(), 3);
    assert!(accepts(&s, 7, "delta").await);
}

#[tokio::test]
async fn a_bad_reload_keeps_the_previous_tokens() {
    let dir = Dir::new("bad");
    dir.write("switch.toml", &format!("{HEAD}{FILE}"));
    dir.write("tokens.txt", "alpha\n");
    let s = common::start(parse(&dir.config())).await;
    let api = s.switch.api();

    // Not TOML, an unknown key, a token that is not ASCII, a missing token file, a token file
    // with nothing in it.
    let bad = [
        ("switch.toml", format!("{HEAD}{FILE}[tokens"), "line 6"),
        ("switch.toml", format!("{HEAD}{FILE}bogus = 1\n"), "bogus"),
        (
            "switch.toml",
            format!("{HEAD}[tokens]\naccepted = [\"é\"]\n"),
            "ASCII",
        ),
        (
            "switch.toml",
            format!("{HEAD}[tokens]\nfile = \"nope.txt\"\n"),
            "nope.txt",
        ),
        ("switch.toml", format!("{HEAD}{FILE}"), "none were read"),
    ];
    for (n, (name, text, expect)) in (1u8..).zip(bad) {
        if expect == "none were read" {
            dir.write("tokens.txt", "# nobody\n");
        }
        dir.write(name, &text);
        let e = reload(api, &dir.config()).unwrap_err().to_string();
        assert!(e.contains(expect), "{e}");
        assert!(token_required(&s).await);
        assert!(accepts(&s, n, "alpha").await, "{e}");
    }

    std::fs::remove_file(dir.config()).unwrap();
    assert!(reload(api, &dir.config()).is_err());
    assert!(accepts(&s, 9, "alpha").await);
}

#[tokio::test]
async fn the_error_text_does_not_repeat_values() {
    let dir = Dir::new("quiet");
    dir.write("switch.toml", &format!("{HEAD}{FILE}"));
    dir.write("tokens.txt", "alpha\n");
    let s = common::start(parse(&dir.config())).await;
    dir.write(
        "switch.toml",
        &format!("{HEAD}[tokens]\naccepted = \"hunter2-token\"\n"),
    );
    let e = reload(s.switch.api(), &dir.config())
        .unwrap_err()
        .to_string();
    assert!(!e.contains("hunter2"), "{e}");
}

#[tokio::test]
async fn registration_opens_and_closes_with_the_file() {
    let dir = Dir::new("flip");
    dir.write("switch.toml", HEAD);
    let s = common::start(parse(&dir.config())).await;
    let api = s.switch.api();

    assert!(!token_required(&s).await);
    assert_eq!(try_register(&s, 1, None).await.status, StatusCode::OK);

    dir.write(
        "switch.toml",
        &format!("{HEAD}[tokens]\naccepted = [\"alpha\"]\n"),
    );
    assert_eq!(reload(api, &dir.config()).unwrap(), 1);
    assert!(token_required(&s).await);
    assert_eq!(
        try_register(&s, 2, None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert!(accepts(&s, 3, "alpha").await);

    dir.write("switch.toml", HEAD);
    assert_eq!(reload(api, &dir.config()).unwrap(), 0);
    assert!(!token_required(&s).await);
    assert_eq!(try_register(&s, 4, None).await.status, StatusCode::OK);
}

#[tokio::test]
async fn admitted_sessions_stay_but_get_no_more_turn_credentials() {
    let dir = Dir::new("session");
    dir.write("switch.toml", &format!("{HEAD}{FILE}{TURN}"));
    dir.write("tokens.txt", "alpha\nbeta\n");
    let s = common::start(parse(&dir.config())).await;

    let (mut ca, alpha) = register(&s, 1, "alpha").await;
    let (mut cb, beta) = register(&s, 2, "beta").await;

    dir.write("tokens.txt", "beta\n");
    reload(s.switch.api(), &dir.config()).unwrap();

    // Still admitted: the session works, the TURN credentials do not renew.
    assert_eq!(
        ca.get("/v0/members", Some(&alpha)).await.status,
        StatusCode::OK
    );
    let r = post(&mut ca, &alpha).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.error_code(), "urn:vardevall:error:token-required");
    assert_eq!(post(&mut cb, &beta).await.status, StatusCode::OK);
    assert!(!accepts(&s, 3, "alpha").await);

    // Registration opens: every session may fetch credentials again.
    dir.write("switch.toml", &format!("{HEAD}{TURN}"));
    reload(s.switch.api(), &dir.config()).unwrap();
    assert_eq!(post(&mut ca, &alpha).await.status, StatusCode::OK);
}
