//! `vv`: key tools and `vv up` (vv-07 §5).

#![deny(unsafe_code)]

mod cli;
mod control;
mod invite;
mod netcfg;
mod resolv;
mod setcmd;
mod show;
#[allow(unsafe_code)]
mod tun;
mod up;
mod uplink;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let args = cli::Args::parse();
    match cli::run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vv: {e:#}");
            ExitCode::from(1)
        }
    }
}
