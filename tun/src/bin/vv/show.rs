//! The text of `vv show`, as `wg show` prints: one interface per block, from the `show` answer of
//! the control socket.

use std::fmt::Write as _;

use serde_json::Value;

use crate::control::describe;

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("?")
}

fn wait(ms: &Value) -> String {
    match ms.as_u64() {
        Some(ms) if ms >= 1000 => format!("{} s", ms.div_ceil(1000)),
        Some(ms) => format!("{ms} ms"),
        None => "?".to_owned(),
    }
}

fn nat(n: &Value) -> String {
    match n["nat"].as_str() {
        Some("punchable") => format!("punchable {}", text(n, "addr")),
        Some("udp_blocked") => "UDP blocked".to_owned(),
        Some(other) => other.to_owned(),
        None => "?".to_owned(),
    }
}

fn route(r: &Value) -> String {
    let kind = match r["kind"].as_str() {
        Some("lan") => "lan",
        Some("internet") => "internet",
        Some("peer_relay") => "peer relay",
        Some("own_relay") => "own relay",
        Some("switch") => "switch",
        _ => "?",
    };
    match (r["addr"].as_str(), r["switch"].as_u64()) {
        (Some(a), _) => format!("{kind} {a}"),
        (None, Some(s)) => format!("{kind} {}", s + 1),
        _ => kind.to_owned(),
    }
}

fn peer(out: &mut String, p: &Value) {
    let name = p["name"]
        .as_str()
        .map(|n| format!(" ({n})"))
        .unwrap_or_default();
    let _ = writeln!(out, "peer: {}{name}", text(p, "key"));
    let _ = writeln!(out, "  address: {}", text(p, "addr"));
    let state = text(p, "state");
    let reason = p["reason"]
        .as_str()
        .map(|r| format!(" ({r})"))
        .unwrap_or_default();
    let _ = writeln!(out, "  state: {state}{reason}");
    if p["route"].is_object() {
        let rtt = p["rtt_ms"]
            .as_u64()
            .map(|ms| format!(", rtt {ms} ms"))
            .unwrap_or_default();
        let _ = writeln!(out, "  route: {}{rtt}", route(&p["route"]));
    }
    for r in p["routes"].as_array().into_iter().flatten() {
        let mut line = format!(
            "  {} {}",
            if r["active"] == true { "*" } else { "-" },
            route(r)
        );
        line.push_str(&format!(" {}", text(r, "status")));
        if let Some(ms) = r["rtt_ms"].as_u64() {
            let _ = write!(line, ", rtt {ms} ms");
        }
        if r["retry_in_ms"].is_u64() {
            let _ = write!(line, ", retry in {}", wait(&r["retry_in_ms"]));
        }
        if r["forget_in_ms"].is_u64() {
            let _ = write!(line, ", forgotten in {}", wait(&r["forget_in_ms"]));
        }
        if r["metered"] == true {
            line.push_str(", metered");
        }
        let _ = writeln!(out, "{line}");
    }
}

fn view(out: &mut String, v: &Value) {
    let local = &v["local"];
    for s in local["switches"].as_array().into_iter().flatten() {
        let state = match s["state"].as_str() {
            Some("disconnected") => format!(
                "not registered: {}{}",
                s["reason"].as_str().unwrap_or("?"),
                if s["retry_in_ms"].is_u64() {
                    format!(", retry in {}", wait(&s["retry_in_ms"]))
                } else {
                    String::new()
                }
            ),
            Some(other) => other.to_owned(),
            None => "?".to_owned(),
        };
        let transport = s["transport"]
            .as_str()
            .map(|t| format!(", {t}"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "switch: {} ({}): {state}{transport}",
            text(s, "address"),
            text(s, "auth")
        );
    }
    if let Some(r) = local["relay"].as_object() {
        let _ = writeln!(
            out,
            "relay: {} via {} ({})",
            r["addr"].as_str().unwrap_or("?"),
            r["server"].as_str().unwrap_or("?"),
            r["transport"].as_str().unwrap_or("?")
        );
    } else {
        let _ = writeln!(out, "relay: none");
    }
    let _ = writeln!(
        out,
        "nat: IPv6 {}, IPv4 {}",
        nat(&local["ipv6"]),
        nat(&local["ipv4"])
    );
    for t in local["transports"].as_array().into_iter().flatten() {
        if let Some(b) = t["budget"].as_object() {
            let _ = writeln!(
                out,
                "transport: {}: {} of {} bytes left ({})",
                text(t, "name"),
                b["remaining"],
                b["total"],
                b["level"].as_str().unwrap_or("?")
            );
        }
    }
    for p in v["peers"].as_array().into_iter().flatten() {
        out.push('\n');
        peer(out, p);
    }
}

/// The text for one `show` answer.
pub fn render(answer: &Value) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "interface: {}", text(answer, "interface"));
    let name = answer["name"]
        .as_str()
        .map(|n| format!(" ({n})"))
        .unwrap_or_default();
    let _ = writeln!(out, "  device: {}", text(answer, "device"));
    let _ = writeln!(out, "  public key: {}{name}", text(answer, "public_key"));
    let _ = writeln!(
        out,
        "  addresses: {}/64, {}/64",
        text(&answer["addresses"], "ula"),
        text(&answer["addresses"], "link_local")
    );
    let _ = writeln!(out, "  listening port: {}", answer["listen_port"]);
    let _ = writeln!(out, "  domain: {}", text(answer, "domain"));
    for line in describe(answer).lines() {
        let _ = writeln!(out, "  {line}");
    }
    if answer["view"].is_object() {
        view(&mut out, &answer["view"]);
    } else {
        let _ = writeln!(out, "  (no view yet: the engine has just started)");
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn answer() -> Value {
        json!({
            "interface": "home", "device": "home", "public_key": "KEY", "name": "me",
            "addresses": {"ula": "fd00::1", "link_local": "fe80::1"},
            "listen_port": 4455, "domain": "home.internal",
            "exit": {"network": "home", "site": "it/home", "chosen": {
                "site": "it/home", "via": "VIA", "addr": "fd00:0:0:1::7", "ipv4": "198.18.3.4"}},
            "serving": null,
            "view": {
                "local": {
                    "ipv6": {"nat": "unknown"},
                    "ipv4": {"nat": "punchable", "addr": "203.0.113.5:4455"},
                    "relay": {"addr": "192.0.2.9:50000", "server": "192.0.2.10:3478", "transport": "udp"},
                    "switches": [
                        {"index": 0, "address": "sw.example:443", "auth": "pinned", "state": "registered", "transport": "quic", "retry_in_ms": null},
                        {"index": 1, "address": "other.example:443", "auth": "web", "state": "disconnected", "reason": "unreachable", "retry_in_ms": 4200}
                    ],
                    "transports": [{"name": "turn", "usable": true, "meter": "metered",
                        "budget": {"total": 1000, "remaining": 400, "source": "turn", "level": "low"}}]
                },
                "peers": [{
                    "key": "PEER", "addr": "fd00::2", "name": "lab", "state": "up",
                    "route": {"kind": "internet", "addr": "198.51.100.1:4455"}, "rtt_ms": 12,
                    "routes": [
                        {"kind": "internet", "addr": "198.51.100.1:4455", "status": "verified", "rtt_ms": 12, "active": true, "metered": false, "retry_in_ms": null, "forget_in_ms": null},
                        {"kind": "switch", "switch": 0, "status": "failed", "rtt_ms": null, "active": false, "metered": true, "retry_in_ms": 8000, "forget_in_ms": null}
                    ]
                }]
            }
        })
    }

    #[test]
    fn show_lists_the_interface_switches_relay_nats_and_peers_with_their_routes() {
        let t = render(&answer());
        for want in [
            "interface: home",
            "public key: KEY (me)",
            "addresses: fd00::1/64, fe80::1/64",
            "exit: on, network home, site it/home",
            "switch: sw.example:443 (pinned): registered, quic",
            "switch: other.example:443 (web): not registered: unreachable, retry in 5 s",
            "relay: 192.0.2.9:50000 via 192.0.2.10:3478 (udp)",
            "nat: IPv6 unknown, IPv4 punchable 203.0.113.5:4455",
            "transport: turn: 400 of 1000 bytes left (low)",
            "peer: PEER (lab)",
            "state: up",
            "route: internet 198.51.100.1:4455, rtt 12 ms",
            "* internet 198.51.100.1:4455 verified, rtt 12 ms",
            "- switch 1 failed, retry in 8 s, metered",
        ] {
            assert!(t.contains(want), "{want:?} in\n{t}");
        }
    }

    #[test]
    fn show_before_the_first_view_says_so() {
        let mut a = answer();
        a["view"] = Value::Null;
        assert!(render(&a).contains("no view yet"));
    }
}
