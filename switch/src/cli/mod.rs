//! Command line of `vv-switch` (vv-07 §6).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio::net::{TcpListener, UdpSocket};
use vardevall_proto::keys::SwitchPublic;
use vardevall_switch::config::Config;
use vardevall_switch::reload::Reloader;
use vardevall_switch::{Sockets, Switch, key};

#[derive(Parser)]
#[command(name = "vv-switch", version, about = "The vardevall switch (vv-04)")]
struct Cli {
    /// Configuration file; without a subcommand the switch runs with it.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the switch.
    Run,
    /// Print a new switch key (an Ed25519 seed, base32).
    Genkey,
    /// Read a switch key on stdin and print its public key.
    Pubkey,
    /// Print the switch address `<key>@<host>` for the configured key (vv-04 §2.1).
    Address {
        /// Host name or address clients use, with `:port` if not 443.
        host: String,
    },
}

pub fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vv-switch: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        None | Some(Command::Run) => serve(&config_path(cli.config)?),
        Some(Command::Genkey) => {
            println!("{}", key::generate()?.to_base32().as_str());
            Ok(())
        }
        Some(Command::Pubkey) => {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text)?;
            let secret = key::parse(&text).context("stdin is not a base32 Ed25519 seed")?;
            println!("{}", secret.public());
            Ok(())
        }
        Some(Command::Address { host }) => {
            let config = load_config(&config_path(cli.config)?)?;
            let public: SwitchPublic = key::load(&config.key_file)?.public();
            println!("{public}@{host}");
            Ok(())
        }
    }
}

fn config_path(arg: Option<PathBuf>) -> Result<PathBuf> {
    match arg {
        Some(p) => Ok(p),
        None => bail!("no configuration file; pass -c <file>"),
    }
}

fn load_config(path: &Path) -> Result<Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let base = path.parent().unwrap_or(Path::new("."));
    Config::parse(&text, base).with_context(|| format!("{}", path.display()))
}

fn serve(path: &Path) -> Result<()> {
    let config = load_config(path)?;
    let secret = key::load(&config.key_file)?;
    let public = secret.public();
    let switch = Switch::new(&config, secret)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        // First, so that no SIGHUP after this point ends the process.
        let reloader = Reloader::new(switch.api().clone(), path.to_owned())
            .context("installing the SIGHUP handler")?
            .with_certificate(switch.file_certificate().cloned());
        let reload_task = tokio::spawn(reloader.run());
        let mut listeners = Vec::new();
        let mut h3 = Vec::new();
        for addr in &config.listen {
            let l = TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding {addr}"))?;
            eprintln!("vv-switch: listening on {}", l.local_addr()?);
            if let Ok(u) = UdpSocket::bind(l.local_addr()?).await {
                h3.push(u);
            } else {
                eprintln!(
                    "vv-switch: UDP {} busy, HTTP/3 is off there",
                    l.local_addr()?
                );
            }
            listeners.push(l);
        }
        let mut plain = Vec::new();
        for addr in &config.plain_listen {
            let l = TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding {addr}"))?;
            eprintln!("vv-switch: plain HTTP on {}", l.local_addr()?);
            plain.push(l);
        }
        if !plain.is_empty()
            && config.forwarded_header.is_none()
            && config.proxy_protocol.is_empty()
        {
            eprintln!(
                "vv-switch: warning: plain_listen without forwarded_header or proxy_protocol: \
                 every client is counted as the proxy's address"
            );
        }
        #[cfg(feature = "stun-turn")]
        let mut stun = Vec::new();
        #[cfg(feature = "stun-turn")]
        for addr in &config.stun.listen {
            let s = UdpSocket::bind(addr)
                .await
                .with_context(|| format!("binding STUN {addr}"))?;
            eprintln!("vv-switch: STUN on {}", s.local_addr()?);
            stun.push(s);
        }
        #[cfg(feature = "stun-turn")]
        let mut turn = Vec::new();
        #[cfg(feature = "stun-turn")]
        for addr in config
            .turn
            .iter()
            .filter_map(|t| t.server.as_ref())
            .flat_map(|s| &s.listen)
        {
            let s = UdpSocket::bind(addr)
                .await
                .with_context(|| format!("binding TURN {addr}"))?;
            eprintln!("vv-switch: TURN on {}", s.local_addr()?);
            turn.push(s);
        }
        eprintln!("vv-switch: key {public}");
        eprintln!(
            "vv-switch: serving hosts {}",
            config.served_hosts().join(", ")
        );
        if config.tokens.is_empty() {
            eprintln!("vv-switch: no operator tokens configured, registration is open");
        }
        let sockets = Sockets {
            tcp: listeners,
            plain,
            h3,
            #[cfg(feature = "stun-turn")]
            stun,
            #[cfg(feature = "stun-turn")]
            turn,
        };
        switch.run_with(sockets, shutdown_signal()).await;
        reload_task.abort();
        Ok(())
    })
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
