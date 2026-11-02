//! The client side of the control socket of a running interface: one unix socket
//! per interface, line-based JSON; the server is `vv up`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;

/// How long a client may take to send a line, and a server to answer one.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// A request to a control socket failed.
#[derive(Debug, Error)]
pub enum AskError {
    /// Nothing answers at the socket.
    #[error("connecting to {path}: is `vv up` running for this interface, as this user?")]
    Connect {
        /// The socket.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// The conversation broke off.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// The answer is not a JSON line.
    #[error("the answer is not JSON")]
    NotJson,
    /// The server refused the request.
    #[error("{0}")]
    Refused(String),
}

/// The directory of the control sockets.
pub fn socket_dir() -> &'static str {
    if cfg!(target_os = "linux") {
        "/run/vardevall"
    } else {
        "/var/run/vardevall"
    }
}

/// The socket of `interface`.
pub fn default_path(interface: &str) -> PathBuf {
    Path::new(socket_dir()).join(format!("{interface}.sock"))
}

/// The interfaces that have a control socket, sorted.
pub fn running() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(socket_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            name.strip_suffix(".sock").map(str::to_owned)
        })
        .collect();
    names.sort();
    names
}

/// Sends one request to the socket at `path` and returns the answer.
pub fn ask(path: &Path, request: &Value) -> Result<Value, AskError> {
    let mut stream = UnixStream::connect(path).map_err(|source| AskError::Connect {
        path: path.to_owned(),
        source,
    })?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    writeln!(stream, "{request}")?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    let answer: Value = serde_json::from_str(&line).map_err(|_| AskError::NotJson)?;
    if answer["ok"] == true {
        Ok(answer)
    } else {
        Err(AskError::Refused(
            answer["error"]
                .as_str()
                .unwrap_or("the request failed")
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_path_is_per_interface() {
        assert!(default_path("home").ends_with("vardevall/home.sock"));
    }

    #[test]
    fn asking_a_socket_nobody_listens_on_says_so() {
        let e = ask(Path::new("/nonexistent/vv.sock"), &serde_json::json!({})).unwrap_err();
        assert!(matches!(e, AskError::Connect { .. }));
        assert!(e.to_string().contains("is `vv up` running"));
    }
}
