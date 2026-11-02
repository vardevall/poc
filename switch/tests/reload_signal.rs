//! SIGHUP reaches the reloader. This file holds one test so that the signal is only ever raised
//! in a process that handles it.

mod common;

use std::path::Path;
use std::time::Duration;

use common::{Client, net_secret, node_key, register_body};
use http::{Method, StatusCode};
use vardevall_switch::config::Config;
use vardevall_switch::reload::Reloader;

fn hangup() {
    let status = std::process::Command::new("kill")
        .args(["-HUP", &std::process::id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

async fn token_required(s: &common::TestSwitch) -> bool {
    let mut c = Client::connect(s.addr, s.public).await;
    c.get("/v0/info", None).await.json()["token_required"]
        .as_bool()
        .unwrap()
}

/// Waits until `/v0/info` reports `token_required == want`.
async fn until(s: &common::TestSwitch, want: bool) {
    for _ in 0..100 {
        if token_required(s).await == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("token_required did not become {want}");
}

async fn status(s: &common::TestSwitch, n: u8, token: &str) -> StatusCode {
    let mut c = Client::connect(s.addr, s.public).await;
    let body = register_body(&c, &s.public, &node_key(n), &net_secret(n));
    let auth = format!("Bearer {token}");
    c.request(
        Method::POST,
        "/v0/register",
        &[("authorization", &auth)],
        &body,
    )
    .await
    .status
}

#[tokio::test]
async fn sighup_reloads_the_tokens() {
    let dir = std::env::temp_dir().join(format!("vv-switch-hup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("switch.toml");
    let write = |name: &str, text: &str| std::fs::write(dir.join(name), text).unwrap();
    let head = "listen = [\"127.0.0.1:0\"]\nkey_file = \"switch.key\"\nnames = [\"switch.test\"]\n";
    write("switch.toml", head);

    let s = common::start(Config::parse(head, Path::new(&dir)).unwrap()).await;
    let reloader = Reloader::new(s.switch.api().clone(), config.clone()).unwrap();
    let task = tokio::spawn(reloader.run());
    assert!(!token_required(&s).await);

    // Open to closed.
    write("tokens.txt", "alpha\nbeta\n");
    write(
        "switch.toml",
        &format!("{head}[tokens]\nfile = \"tokens.txt\"\n"),
    );
    hangup();
    until(&s, true).await;
    assert_eq!(status(&s, 1, "alpha").await, StatusCode::OK);

    // A token is replaced.
    write("tokens.txt", "beta\ngamma\n");
    hangup();
    for _ in 0..100 {
        if status(&s, 2, "alpha").await == StatusCode::UNAUTHORIZED {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(status(&s, 3, "alpha").await, StatusCode::UNAUTHORIZED);
    assert_eq!(status(&s, 4, "gamma").await, StatusCode::OK);

    // A broken file changes nothing and the process lives on.
    write("switch.toml", "this is not toml");
    hangup();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!task.is_finished());
    assert!(token_required(&s).await);
    assert_eq!(status(&s, 5, "gamma").await, StatusCode::OK);

    // Closed to open.
    write("switch.toml", head);
    hangup();
    until(&s, false).await;

    let _ = std::fs::remove_dir_all(&dir);
}
