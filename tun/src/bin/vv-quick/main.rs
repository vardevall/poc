//! `vv-quick`: as `wg-quick`, applies the host's side of an interface that `vv` sets up and
//! removes it again. Linux only.

#![deny(unsafe_code)]

mod exec;
mod host;
mod plan;
mod quick;
mod state;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Brings an interface up with the host set up around it, and takes it all away again.
#[derive(Parser)]
#[command(name = "vv-quick", version)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start `vv up` in the foreground, apply the host's side (the exit this node serves, the
    /// exit it uses, the overlay's DNS), follow the exit as it changes, and on SIGINT, SIGTERM or
    /// the end of `vv` take it all away. A run that was killed is swept first.
    Up {
        /// An interface name (`/etc/vardevall/interfaces/<name>.toml`) or a path.
        interface: String,
        /// Use the exit of this network from the start, of the given site or, without one, of its
        /// only site.
        #[arg(long, value_name = "SITE", num_args = 0..=1, default_missing_value = "")]
        exit: Option<String>,
        /// Print the commands that would run, and those that take them back, and apply nothing.
        #[arg(long)]
        dry_run: bool,
        /// The slot the numbers (mark, table, rule priorities) come from, 0 to 999; by default
        /// the interface name gives it. Needed only if two running interfaces get the same one.
        #[arg(long, value_name = "N")]
        slot: Option<u16>,
        /// The `vv` to start, the one next to `vv-quick` by default.
        #[arg(long, value_name = "PATH")]
        vv: Option<PathBuf>,
        /// Print each command as it runs, and ask `vv` for debug lines.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Ask the running `vv-quick` of an interface to stop, which takes its changes away; if it
    /// was killed, remove what it left.
    Down {
        /// An interface name or a path.
        interface: String,
        /// The slot given to `up`, if one was.
        #[arg(long, value_name = "N")]
        slot: Option<u16>,
        /// Print each command as it runs.
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();
    let result = match args.command {
        Command::Up {
            interface,
            exit,
            dry_run,
            slot,
            vv,
            verbose,
        } => quick::up(quick::UpOptions {
            interface,
            exit,
            dry_run,
            slot,
            vv,
            verbose,
        }),
        Command::Down {
            interface,
            slot,
            verbose,
        } => quick::down(&interface, slot, verbose),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vv-quick: {e:#}");
            ExitCode::from(1)
        }
    }
}
