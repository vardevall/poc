//! Command-line parsing and the key commands (vv-07 §5.1).

use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use vardevall_tun::{files, keys};

use crate::{control, invite, setcmd, show, up};

/// vardevall interface tool. Like `wg`, it sets up the tunnel device and its overlay addresses
/// and nothing else on the host; `vv-quick` applies the host's routes, rules, firewall and DNS.
#[derive(Parser)]
#[command(name = "vv", version)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print a new node private key.
    Genkey,
    /// Read a private key on stdin, print its public key.
    Pubkey,
    /// Print a new network secret.
    Gennet,
    /// Read a network secret on stdin, print its network public key.
    Netid,
    /// Print the ula and link-local address of a key in a network.
    Addr {
        /// The node public key.
        key: String,
        /// The network ID.
        #[arg(long)]
        network: String,
    },
    /// Create the tunnel interface from its file and run until interrupted (needs root).
    Up {
        /// An interface name (`/etc/vardevall/interfaces/<name>.toml`) or a path.
        interface: String,
        /// Log debug lines.
        #[arg(short, long)]
        verbose: bool,
        /// Use the exit of this network from the start, of the given site or, without one, of its
        /// only site. The host's routes are not touched: `vv-quick up` applies them.
        #[arg(long, value_name = "SITE", num_args = 0..=1, default_missing_value = "")]
        exit: Option<String>,
        /// The firewall mark of the engine's sockets, which must not enter the tunnel (Linux).
        /// The default follows from the interface name, as `vv-quick` derives it.
        #[arg(long, value_name = "N")]
        fwmark: Option<u32>,
        /// The control socket, `/run/vardevall/<interface>.sock` by default.
        #[arg(long, value_name = "PATH")]
        control_socket: Option<PathBuf>,
    },
    /// Choose the exit a running interface uses, or show the exit state.
    Exit {
        /// An interface name or a path.
        interface: String,
        /// A site such as `it` or `it/home`, `auto` for the network's only site or `off`; none
        /// shows the exit state and the sites known.
        site: Option<String>,
        /// The control socket, `/run/vardevall/<interface>.sock` by default.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
        /// Print the answer as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show a running interface, or every running one: its keys and addresses, the exit, the
    /// switches, the relay, this node's NATs and each peer with its routes.
    Show {
        /// An interface name or a path; none shows every running interface.
        interface: Option<String>,
        /// The control socket, `/run/vardevall/<interface>.sock` by default.
        #[arg(long, value_name = "PATH", requires = "interface")]
        socket: Option<PathBuf>,
        /// Print the answer as JSON (a list when no interface is named).
        #[arg(long)]
        json: bool,
    },
    /// End a running `vv up`: the device goes and the process exits.
    Down {
        /// An interface name or a path.
        interface: String,
        /// The control socket, `/run/vardevall/<interface>.sock` by default.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Read the interface file again and apply the difference to the running interface, keeping
    /// the sessions of the peers that did not change. Changes that need a restart (the private
    /// key, the network secret, the port, the MTU, the switches, the mDNS and delivery settings)
    /// are refused with the names of their fields, and nothing changes.
    Syncconf {
        /// An interface name or a path.
        interface: String,
        /// The file to apply, the interface's own by default.
        file: Option<PathBuf>,
        /// Show the difference and apply nothing.
        #[arg(long)]
        dry_run: bool,
        /// The control socket, `/run/vardevall/<interface>.sock` by default.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
        /// Print the answer as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Change a running interface without touching its file (a later `syncconf` takes the file
    /// again): `vv set <interface> peer <key> [name <label>|none] [endpoint <host:port>|none]
    /// [remove] [peer <key> …]`. A key the interface does not know is added.
    Set {
        /// An interface name or a path.
        interface: String,
        /// The control socket, `/run/vardevall/<interface>.sock` by default.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
        /// Print the answer as JSON.
        #[arg(long)]
        json: bool,
        /// `peer <key> [name <label>|none] [endpoint <host:port>|none] [remove]`, once or more.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        changes: Vec<String>,
    },
    /// Make a key for a new node, write its interface file and add it to this interface's file
    /// and, if the interface runs, to the running interface.
    Invite {
        /// An interface name or a path.
        interface: String,
        /// The new node's name: a DNS label.
        name: String,
        /// Where to write the new node's file, `<name>.toml` by default; `-` is stdout. The file
        /// holds the network secret and the new private key and is created with mode 0600.
        #[arg(long, value_name = "PATH")]
        out: Option<String>,
        /// An endpoint of this node (`host:port`) to put in the new node's file.
        #[arg(long, value_name = "HOST:PORT")]
        endpoint: Option<String>,
        /// The control socket, `/run/vardevall/<interface>.sock` by default.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Print the key and ula of a name of an interface file.
    Resolve {
        /// An interface name or a path.
        interface: String,
        /// A label, `<label>.<domain>`, a key-id or `<key-id>.<domain>`.
        name: String,
    },
}

fn stdin_line() -> Result<String> {
    let mut s = String::new();
    std::io::stdin()
        .read_to_string(&mut s)
        .context("reading stdin")?;
    Ok(s.trim().to_owned())
}

/// The request of `vv exit`: the exit, or the status if no site is given.
fn exit_request(name: &str, site: Option<&str>) -> serde_json::Value {
    match site {
        None => json!({"request": "status"}),
        Some("off") => json!({"request": "exit", "network": null, "site": null}),
        Some("auto") => json!({"request": "exit", "network": name, "site": null}),
        Some(site) => json!({"request": "exit", "network": name, "site": site}),
    }
}

/// The socket of `interface`, the given one or the default.
fn socket_of(interface: &str, socket: Option<PathBuf>) -> Result<(String, PathBuf)> {
    let name = up::interface_name(interface)?;
    let path = socket.unwrap_or_else(|| control::default_path(&name));
    Ok((name, path))
}

/// `vv exit`: sets or shows the exit of a running interface through its control socket.
fn exit(interface: &str, site: Option<&str>, socket: Option<PathBuf>, json: bool) -> Result<()> {
    let (name, path) = socket_of(interface, socket)?;
    let answer = control::ask(&path, &exit_request(&name, site))?;
    if json {
        println!("{answer}");
    } else {
        print!("{}", control::describe(&answer));
    }
    Ok(())
}

fn show_command(interface: Option<&str>, socket: Option<PathBuf>, json: bool) -> Result<()> {
    let answers: Vec<Value> = match interface {
        Some(i) => {
            let (_, path) = socket_of(i, socket)?;
            vec![control::ask(&path, &json!({"request": "show"}))?]
        }
        None => control::running()
            .iter()
            .filter_map(|n| {
                control::ask(&control::default_path(n), &json!({"request": "show"})).ok()
            })
            .collect(),
    };
    if json {
        match interface {
            Some(_) => println!("{}", answers[0]),
            None => println!("{}", Value::Array(answers)),
        }
    } else if answers.is_empty() {
        eprintln!("no interface is running");
    } else {
        let text: Vec<String> = answers.iter().map(show::render).collect();
        print!("{}", text.join("\n"));
    }
    Ok(())
}

fn down(interface: &str, socket: Option<PathBuf>) -> Result<()> {
    let (name, path) = socket_of(interface, socket)?;
    control::ask(&path, &json!({"request": "down"}))?;
    let until = Instant::now() + Duration::from_secs(10);
    while path.exists() {
        if Instant::now() > until {
            bail!("{name} did not end in 10 s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("{name} is down");
    Ok(())
}

fn print_applied(answer: &Value, json: bool) {
    if json {
        println!("{answer}");
        return;
    }
    let changes = answer["changes"].as_array().cloned().unwrap_or_default();
    if changes.is_empty() {
        println!("nothing differs");
    }
    let verb = if answer["applied"] == true {
        ""
    } else {
        "would "
    };
    for c in changes {
        println!("{verb}{}", c.as_str().unwrap_or("?"));
    }
}

fn syncconf(
    interface: &str,
    file: Option<PathBuf>,
    dry_run: bool,
    socket: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let (_, path) = socket_of(interface, socket)?;
    let file = match file {
        Some(f) => f,
        None => files::locate(interface)?.0,
    };
    let text = files::read_checked(&file)?;
    let answer = control::ask(
        &path,
        &json!({"request": "syncconf", "config": text, "dry_run": dry_run}),
    )?;
    print_applied(&answer, json);
    Ok(())
}

fn set(interface: &str, changes: &[String], socket: Option<PathBuf>, json: bool) -> Result<()> {
    let peers = setcmd::parse(changes)?;
    let (_, path) = socket_of(interface, socket)?;
    let answer = control::ask(&path, &json!({"request": "set", "peers": peers}))?;
    print_applied(&answer, json);
    Ok(())
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        Command::Genkey => println!("{}", keys::generate_node_key()),
        Command::Pubkey => println!("{}", keys::public_key(&stdin_line()?)?),
        Command::Gennet => println!("{}", keys::generate_network_secret()),
        Command::Netid => println!("{}", keys::network_id(&stdin_line()?)?),
        Command::Addr { key, network } => {
            let a = keys::overlay_addrs(&key, &network)?;
            println!("{}\n{}", a.ula, a.link_local);
        }
        Command::Up {
            interface,
            verbose,
            exit,
            fwmark,
            control_socket,
        } => up::run(
            &interface,
            up::Options {
                verbose,
                exit,
                fwmark,
                control_socket,
            },
        )?,
        Command::Exit {
            interface,
            site,
            socket,
            json,
        } => exit(&interface, site.as_deref(), socket, json)?,
        Command::Show {
            interface,
            socket,
            json,
        } => show_command(interface.as_deref(), socket, json)?,
        Command::Down { interface, socket } => down(&interface, socket)?,
        Command::Syncconf {
            interface,
            file,
            dry_run,
            socket,
            json,
        } => syncconf(&interface, file, dry_run, socket, json)?,
        Command::Set {
            interface,
            socket,
            json,
            changes,
        } => set(&interface, &changes, socket, json)?,
        Command::Invite {
            interface,
            name,
            out,
            endpoint,
            socket,
        } => {
            let (_, path) = socket_of(&interface, socket)?;
            invite::run(
                &interface,
                &name,
                out.as_deref(),
                endpoint.as_deref(),
                &path,
            )?;
        }
        Command::Resolve { interface, name } => {
            let config = up::load(&interface)?;
            let responder = vardevall_tun::dns::Responder::from_config(&config);
            let Some(key) = responder.resolve(&name) else {
                bail!("{name}: not found");
            };
            let a = vardevall_proto::addr::OverlayAddrs::derive(&config.network_id, &key);
            println!("{}\n{}", key.to_base32(), a.ula);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::exit_request;

    #[test]
    fn exit_asks_for_the_exit_or_for_the_status() {
        assert_eq!(exit_request("home", None), json!({"request": "status"}));
        assert_eq!(
            exit_request("home", Some("it/home")),
            json!({"request": "exit", "network": "home", "site": "it/home"})
        );
        assert_eq!(
            exit_request("home", Some("auto")),
            json!({"request": "exit", "network": "home", "site": null})
        );
        assert_eq!(
            exit_request("home", Some("off")),
            json!({"request": "exit", "network": null, "site": null})
        );
    }
}
