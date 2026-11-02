//! Whether the host of an exit has an IPv6 route to the internet.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// A global IPv6 destination to look the route of up.
pub const PROBE: &str = "2001:4860:4860::8888";

/// The interface a line of `ip -6 route get` output says the route leaves by.
fn leaves_by(output: &str) -> Option<&str> {
    let mut words = output.split_whitespace();
    words.by_ref().find(|w| *w == "dev")?;
    words.next()
}

/// Whether `output` of `ip -6 route get` shows a route that leaves by an interface other than
/// `device`, the exit's own tunnel, and not by loopback.
pub fn is_uplink(output: &str, device: &str) -> bool {
    leaves_by(output).is_some_and(|d| d != device && d != "lo")
}

/// Whether the host has an IPv6 uplink, looked up as the engine's own sockets would be, with
/// `mark`, so that the routes of an exit in use on this host do not count. `None` if the host's
/// routes cannot be read.
#[cfg(target_os = "linux")]
pub fn probe(device: &str, mark: u32) -> Option<bool> {
    let out = std::process::Command::new("ip")
        .args(["-6", "route", "get", PROBE, "mark", &mark.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let none = ["unreachable", "prohibit", "Network is down"]
            .iter()
            .any(|w| stderr.contains(w));
        return none.then_some(false);
    }
    Some(is_uplink(&String::from_utf8_lossy(&out.stdout), device))
}

#[cfg(not(target_os = "linux"))]
pub fn probe(_device: &str, _mark: u32) -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_by_another_interface_is_an_uplink() {
        let out = "2001:4860:4860::8888 from :: via fe80::1 dev eth0 proto ra src 2001:db8::5 metric 1024 pref medium\n";
        assert!(is_uplink(out, "home"));
        assert!(!is_uplink(out, "eth0"));
    }

    #[test]
    fn a_route_into_the_tunnel_or_loopback_or_none_is_not() {
        let own = "2001:4860:4860::8888 dev home table 30308 src fd00::7 metric 1024 pref medium\n";
        assert!(!is_uplink(own, "home"));
        assert!(!is_uplink("local ::1 dev lo table local\n", "home"));
        assert!(!is_uplink("", "home"));
        assert!(!is_uplink(
            "RTNETLINK answers: Network is unreachable\n",
            "home"
        ));
    }
}
