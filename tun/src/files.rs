//! Finding and reading interface files on a host (vv-07 §2.1).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

use crate::config::{Config, ConfigError, Context};

/// Where the interface files of a system live.
pub const SYSTEM_DIR: &str = "/etc/vardevall/interfaces";

/// An interface file could not be found or read.
#[derive(Debug, Error)]
pub enum FileError {
    /// The path has no file name to take the interface name from.
    #[error("the interface file needs a name")]
    NoName,
    /// The file cannot be read.
    #[error("reading {path}: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// Other users can read the file, which holds secrets (vv-07 §2.2).
    #[error("{0} is readable by other users and holds secrets; run chmod 600 on it (vv-07 §2.2)")]
    Mode(PathBuf),
    /// The file is not a valid interface file.
    #[error("{path}: {source}")]
    Invalid {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: ConfigError,
    },
}

/// The file and the interface name `target` stands for: a path (it has a `/` or ends in `.toml`)
/// or the name of a file of [`SYSTEM_DIR`].
pub fn locate(target: &str) -> Result<(PathBuf, String), FileError> {
    let path = if target.contains('/') || target.ends_with(".toml") {
        PathBuf::from(target)
    } else {
        Path::new(SYSTEM_DIR).join(format!("{target}.toml"))
    };
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or(FileError::NoName)?
        .to_owned();
    Ok((path, name))
}

/// The OS host name, which gives the default own name.
pub fn hostname() -> Option<String> {
    let out = Command::new("hostname").output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_owned())
}

/// The text of the file at `path`, which must not be readable by other users.
pub fn read_checked(path: &Path) -> Result<String, FileError> {
    let read = |source| FileError::Read {
        path: path.to_owned(),
        source,
    };
    let meta = std::fs::metadata(path).map_err(read)?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(FileError::Mode(path.to_owned()));
    }
    std::fs::read_to_string(path).map_err(read)
}

/// Parses `text`, the content of the file at `path`, for the interface `name`.
pub fn parse(text: &str, path: &Path, name: &str) -> Result<Config, FileError> {
    let ctx = Context {
        interface_name: name.to_owned(),
        hostname: hostname(),
    };
    Config::parse(text, &ctx).map_err(|source| FileError::Invalid {
        path: path.to_owned(),
        source,
    })
}

/// Loads and validates the file of an interface name or path.
pub fn load(target: &str) -> Result<Config, FileError> {
    let (path, name) = locate(target)?;
    let text = read_checked(&path)?;
    parse(&text, &path, &name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_a_file_of_the_system_directory_and_a_path_is_itself() {
        let (path, name) = locate("home").unwrap();
        assert_eq!(path, Path::new("/etc/vardevall/interfaces/home.toml"));
        assert_eq!(name, "home");
        let (path, name) = locate("./lab.toml").unwrap();
        assert_eq!(path, Path::new("./lab.toml"));
        assert_eq!(name, "lab");
        assert_eq!(locate("lab.toml").unwrap().1, "lab");
        assert!(matches!(locate("/"), Err(FileError::NoName)));
    }

    #[test]
    fn a_file_other_users_can_read_is_refused() {
        let dir = std::env::temp_dir().join(format!("vv-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.toml");
        std::fs::write(&path, "secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(read_checked(&path), Err(FileError::Mode(_))));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_checked(&path).unwrap(), "secret");
        assert!(matches!(
            read_checked(&dir.join("none")),
            Err(FileError::Read { .. })
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
