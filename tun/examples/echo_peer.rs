//! A peer without a tunnel device: it answers ICMPv6 echo requests addressed to its overlay
//! address, driving [`Tunnel`] only through `packet_in` and the packet callback.
//!
//! `cargo run --example echo_peer -- peer.toml`

use std::sync::Arc;

use tokio::sync::mpsc;
use vardevall_tun::embed::{Callbacks, StartOptions, Tunnel};
use vardevall_tun::packet::{self, HEADER_LEN, icmp};

const ECHO_REQUEST: u8 = 128;
const ECHO_REPLY: u8 = 129;

fn echo_reply(request: &[u8]) -> Option<Vec<u8>> {
    let h = packet::parse(request)?;
    if h.next != packet::ICMPV6 || request.get(HEADER_LEN) != Some(&ECHO_REQUEST) {
        return None;
    }
    let body = &request[HEADER_LEN + 4..HEADER_LEN + h.payload_len];
    let _ = icmp::DEST_UNREACHABLE;
    Some(packet::build_icmpv6(
        &h.dst, &h.src, ECHO_REPLY, 0, body, 64,
    ))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: echo_peer <config.toml>"))?;
    let text = std::fs::read_to_string(&path)?;
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let callbacks = Callbacks {
        packets: Box::new(move |packets| {
            for p in packets {
                let _ = tx.send(p.to_vec());
            }
        }),
        event: Box::new(|network, e| eprintln!("{}", e.to_json(network))),
        mdns: None,
    };
    let tunnel = Arc::new(Tunnel::start(
        &tokio::runtime::Handle::current(),
        &text,
        StartOptions::default(),
        callbacks,
    )?);
    eprintln!("echoing on {}", tunnel.config().own_addrs().ula);
    loop {
        tokio::select! {
            Some(p) = rx.recv() => {
                if let Some(r) = echo_reply(&p) {
                    tunnel.packet_in(&r);
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    tunnel.stop_async().await;
    Ok(())
}
