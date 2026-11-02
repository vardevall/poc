//! `vv invite`: a new node's key and file, and its `[[peer]]` in this node's file
//!.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::json;
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, value};
use vardevall_tun::config::{Config, value as values};
use vardevall_tun::{files, keys};

use crate::control;

/// The two files an invitation makes.
pub struct Invitation {
    /// The new node's interface file; holds secrets.
    pub new_file: String,
    /// This node's file with the new `[[peer]]` added, the rest as it was.
    pub our_file: String,
    /// The new node's public key.
    pub public_key: String,
}

fn table_of(item: &Item) -> Option<&Table> {
    item.as_table()
}

/// Builds the invitation of `name`, with the private key `secret`, to the network of `ours`, the
/// text of this node's file, which parsed to `config`. `endpoint` is how the new node may reach
/// this one.
pub fn build(
    ours: &str,
    config: &Config,
    name: &str,
    secret: &str,
    endpoint: Option<&str>,
) -> Result<Invitation> {
    if !values::name_label(name) {
        bail!("{name:?} is not a valid name: use lowercase letters, digits and hyphens");
    }
    if config.own_name.as_deref() == Some(name)
        || config.peers.iter().any(|p| p.name.as_deref() == Some(name))
    {
        bail!("the name {name:?} is already used in this network");
    }
    if let Some(e) = endpoint
        && values::endpoint(e).is_none()
    {
        bail!("{e:?} is not a valid endpoint");
    }
    let public_key = keys::public_key(secret)?;
    let mut doc: DocumentMut = ours.parse().context("this node's file")?;

    let interface = doc
        .get("interface")
        .and_then(table_of)
        .context("the file has no [interface]")?;
    let mut new = DocumentMut::new();
    let mut head = Table::new();
    head["private_key"] = value(secret);
    head["network_secret"] = interface
        .get("network_secret")
        .cloned()
        .context("the file has no network_secret")?;
    if let Some(id) = interface.get("network_id") {
        head["network_id"] = id.clone();
    }
    head["name"] = value(name);
    head["domain"] = value(&config.domain);
    if config.accept_members {
        head["accept_members"] = value(true);
    }
    new["interface"] = Item::Table(head);
    for key in ["switch", "turn", "stun"] {
        if let Some(item) = doc.get(key) {
            new[key] = item.clone();
        }
    }
    let mut hub = Table::new();
    hub["public_key"] = value(config.public_key.to_base32());
    if let Some(n) = &config.own_name {
        hub["name"] = value(n);
    }
    if let Some(e) = endpoint {
        hub["endpoint"] = value(e);
    }
    let mut peers = ArrayOfTables::new();
    peers.push(hub);
    new["peer"] = Item::ArrayOfTables(peers);

    let mut entry = Table::new();
    entry["public_key"] = value(&public_key);
    entry["name"] = value(name);
    match doc.get_mut("peer") {
        Some(Item::ArrayOfTables(list)) => list.push(entry),
        Some(_) => bail!("`peer` in the file is not a list of [[peer]] tables"),
        None => {
            let mut list = ArrayOfTables::new();
            list.push(entry);
            doc["peer"] = Item::ArrayOfTables(list);
        }
    }
    Ok(Invitation {
        new_file: new.to_string(),
        our_file: doc.to_string(),
        public_key,
    })
}

/// Writes `text` to a new file at `path` with mode 0600; refuses to replace a file.
fn create_private(path: &Path, text: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(text.as_bytes())?;
    Ok(())
}

/// Replaces the file at `path` by `text` with the same mode, through a file next to it.
fn replace_file(path: &Path, text: &str) -> Result<()> {
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    let tmp = path.with_extension("toml.new");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

/// `vv invite <interface> <name> [--out <path>]`.
pub fn run(
    interface: &str,
    name: &str,
    out: Option<&str>,
    endpoint: Option<&str>,
    socket: &Path,
) -> Result<()> {
    let (path, _) = files::locate(interface)?;
    let ours = files::read_checked(&path)?;
    let config = files::load(interface)?;
    let secret = keys::generate_node_key();
    let invitation = build(&ours, &config, name, &secret, endpoint)?;

    let target = out.map_or_else(|| PathBuf::from(format!("{name}.toml")), PathBuf::from);
    let to_stdout = out == Some("-");
    if !to_stdout {
        create_private(&target, &invitation.new_file)?;
    }
    if let Err(e) = replace_file(&path, &invitation.our_file) {
        if !to_stdout {
            let _ = std::fs::remove_file(&target);
        }
        return Err(e);
    }
    eprintln!(
        "{name}: public key {}, added to {}",
        invitation.public_key,
        path.display()
    );
    match control::ask(
        socket,
        &json!({"request": "syncconf", "config": invitation.our_file}),
    ) {
        Ok(_) => eprintln!("{interface} is running: {name} is accepted now"),
        Err(_) => eprintln!("{interface} is not running: {name} is accepted at the next `vv up`"),
    }
    if to_stdout {
        print!("{}", invitation.new_file);
    } else {
        eprintln!(
            "wrote {} (mode 0600, holds secrets): give it to {name} and have them install it as an interface file",
            target.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use vardevall_tun::config::Context;

    use super::*;

    struct Ours {
        text: String,
        config: Config,
    }

    fn ours(extra: &str) -> Ours {
        let key = keys::generate_node_key();
        let text = format!(
            "# the hub of the network\n[interface]\nprivate_key = \"{key}\"  # secret\n\
             network_secret = \"{}\"\nname = \"hub\"\ndomain = \"lab.example\"\n{extra}\n\
             # my switch\n[[switch]]\naddress = \"web.example.org\"\ntoken = \"t0ken\"\n\n\
             [[peer]]\npublic_key = \"{}\"\nname = \"old\"  # first friend\n",
            keys::generate_network_secret(),
            keys::public_key(&keys::generate_node_key()).unwrap()
        );
        let config = Config::parse(
            &text,
            &Context {
                interface_name: "home".into(),
                hostname: None,
            },
        )
        .unwrap();
        Ours { text, config }
    }

    fn secret() -> String {
        keys::generate_node_key()
    }

    #[test]
    fn the_new_file_imports_unchanged_and_joins_the_network() {
        let o = ours("accept_members = true");
        let s = secret();
        let inv = build(&o.text, &o.config, "phone", &s, Some("203.0.113.1:4455")).unwrap();
        let theirs = Config::parse(
            &inv.new_file,
            &Context {
                interface_name: "net".into(),
                hostname: None,
            },
        )
        .unwrap();
        assert_eq!(theirs.network_id, o.config.network_id);
        assert_eq!(theirs.own_name.as_deref(), Some("phone"));
        assert_eq!(theirs.domain, "lab.example");
        assert!(theirs.accept_members);
        assert_eq!(theirs.switches, o.config.switches, "address and token");
        assert_eq!(theirs.peers.len(), 1);
        assert_eq!(theirs.peers[0].public_key, o.config.public_key);
        assert_eq!(theirs.peers[0].name.as_deref(), Some("hub"));
        assert_eq!(theirs.peers[0].endpoints.len(), 1);
        assert_eq!(theirs.public_key.to_base32(), inv.public_key);
        assert_eq!(keys::public_key(&s).unwrap(), inv.public_key);
        assert!(inv.new_file.contains("t0ken"));
    }

    #[test]
    fn our_file_gains_the_peer_and_keeps_its_comments_and_layout() {
        let o = ours("");
        let inv = build(&o.text, &o.config, "phone", &secret(), None).unwrap();
        assert!(inv.our_file.starts_with(&o.text.trim_end().to_owned()));
        for kept in [
            "# the hub of the network",
            "# secret",
            "# my switch",
            "# first friend",
        ] {
            assert!(inv.our_file.contains(kept), "{kept}");
        }
        let c = Config::parse(
            &inv.our_file,
            &Context {
                interface_name: "home".into(),
                hostname: None,
            },
        )
        .unwrap();
        assert_eq!(c.peers.len(), 2);
        assert_eq!(c.peers[1].name.as_deref(), Some("phone"));
        assert_eq!(c.peers[1].public_key.to_base32(), inv.public_key);
        assert_eq!(c.peers[0].name.as_deref(), Some("old"));
    }

    #[test]
    fn a_file_without_peers_gets_its_first_and_bad_names_are_refused() {
        let key = keys::generate_node_key();
        let text = format!(
            "[interface]\nprivate_key = \"{key}\"\nnetwork_secret = \"{}\"\n",
            keys::generate_network_secret()
        );
        let config = Config::parse(&text, &Context::default()).unwrap();
        let inv = build(&text, &config, "first", &secret(), None).unwrap();
        let c = Config::parse(&inv.our_file, &Context::default()).unwrap();
        assert_eq!(c.peers.len(), 1);

        let o = ours("");
        for bad in ["Phone", "", "hub", "old", "a b", "-x"] {
            assert!(
                build(&o.text, &o.config, bad, &secret(), None).is_err(),
                "{bad:?}"
            );
        }
        assert!(build(&o.text, &o.config, "ok", &secret(), Some("not an endpoint")).is_err());
    }

    #[test]
    fn files_are_private_and_never_replaced_without_notice() {
        let dir = std::env::temp_dir().join(format!("vv-invite-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let new = dir.join("phone.toml");
        create_private(&new, "secret").unwrap();
        assert_eq!(
            std::fs::metadata(&new).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            create_private(&new, "again").is_err(),
            "an existing file stays"
        );
        let ours = dir.join("home.toml");
        create_private(&ours, "old").unwrap();
        replace_file(&ours, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&ours).unwrap(), "new");
        assert_eq!(
            std::fs::metadata(&ours).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
