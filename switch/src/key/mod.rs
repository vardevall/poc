//! The switch key file: a base32 Ed25519 seed (vv-07 §6).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;
use vardevall_proto::keys::SwitchSecret;
use zeroize::Zeroizing;

/// The key file could not be used.
#[derive(Debug, Error)]
pub enum KeyError {
    /// The file could not be read.
    #[error("reading {path}: {source}")]
    Read {
        /// The path.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// The file does not hold a base32 seed.
    #[error("{0}: not a base32 Ed25519 seed")]
    Format(PathBuf),
    /// Other users can read the file.
    #[error("{0}: readable by group or others; run chmod 600")]
    Permissions(PathBuf),
    /// No randomness is available.
    #[error("the system random number generator is unavailable")]
    NoRandomness,
}

/// A new random seed.
pub fn generate() -> Result<SwitchSecret, KeyError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| KeyError::NoRandomness)?;
    Ok(SwitchSecret::from_bytes(*seed))
}

/// Reads the seed in `path`, refusing a file that other users can read.
pub fn load(path: &Path) -> Result<SwitchSecret, KeyError> {
    let read = |source| KeyError::Read {
        path: path.to_owned(),
        source,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).map_err(read)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(KeyError::Permissions(path.to_owned()));
        }
    }
    let text = Zeroizing::new(fs::read_to_string(path).map_err(read)?);
    parse(&text).ok_or_else(|| KeyError::Format(path.to_owned()))
}

/// Parses the text form of a seed.
pub fn parse(text: &str) -> Option<SwitchSecret> {
    text.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_round_trip_through_text() {
        let k = generate().unwrap();
        let text = k.to_base32();
        assert_eq!(
            parse(&format!("{}\n", text.as_str())).unwrap().public(),
            k.public()
        );
        assert!(parse("not a key").is_none());
        assert!(parse("").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_files_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vv-switch-key-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k");
        let k = generate().unwrap();
        fs::write(&path, k.to_base32().as_str()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(load(&path), Err(KeyError::Permissions(_))));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load(&path).unwrap().public(), k.public());
        fs::write(&path, "junk").unwrap();
        assert!(matches!(load(&path), Err(KeyError::Format(_))));
        fs::remove_dir_all(&dir).unwrap();
    }
}
