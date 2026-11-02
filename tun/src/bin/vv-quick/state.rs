//! What a running `vv-quick` leaves in `/run/vardevall/<interface>.quick`, so that a later run
//! knows its numbers, the sysctls it changed and the processes that were its own.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use vardevall_tun::control_client::socket_dir;

/// The state file of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The `vv-quick` process.
    pub pid: u32,
    /// The `vv up` process it started.
    pub child: u32,
    /// The slot of the interface's numbers.
    pub slot: u16,
    /// The sysctls it changed, with the values to put back.
    pub sysctls: Vec<(String, String)>,
}

/// Where the state of `interface` is kept.
pub fn path(interface: &str) -> PathBuf {
    Path::new(socket_dir()).join(format!("{interface}.quick"))
}

/// The state at `path`, if there is a readable one.
pub fn read(path: &Path) -> Option<State> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Writes the state to `path`, mode 0600.
pub fn write(path: &Path, state: &State) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(serde_json::to_string(state)?.as_bytes())?;
    Ok(())
}

/// Whether `pid` is a running `vv-quick`.
pub fn is_quick(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .is_ok_and(|c| String::from_utf8_lossy(&c).contains("vv-quick"))
}

/// Whether `pid` is a running `vv up` of `interface`.
pub fn is_vv_of(pid: u32, interface: &str) -> bool {
    std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| {
        let words: Vec<String> = c
            .split(|b| *b == 0)
            .map(|w| String::from_utf8_lossy(w).into_owned())
            .collect();
        words.iter().any(|w| w == "up") && words.iter().any(|w| w == interface)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_round_trips_privately() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("vv-quick-state-{}", std::process::id()));
        let file = dir.join("home.quick");
        let state = State {
            pid: 7,
            child: 8,
            slot: 5,
            sysctls: vec![("net.ipv4.ip_forward".into(), "0".into())],
        };
        write(&file, &state).unwrap();
        assert_eq!(read(&file), Some(state));
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(read(&dir.join("none.quick")), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_such_process_is_neither() {
        assert!(!is_quick(u32::MAX));
        assert!(!is_vv_of(u32::MAX, "home"));
    }
}
