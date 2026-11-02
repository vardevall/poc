# vardevall: proof of concept

vardevall connects a person's or an organisation's devices into one private network, wherever they
are: phones, laptops and servers reach each other directly, end-to-end encrypted, through NATs and
across changes of network. The servers that help them find each other are untrusted: they never
see the traffic in clear, keep everything in memory and can be run by anyone.

This repository is the **proof of concept**. It works and shows that the design holds, but it is
frozen and not maintained: it is being replaced by hand-written implementations in the other
repositories of the project. Read "How this was made" before relying on any of it.

## Features

- **Sessions between peers** by their keys: a hybrid Noise IK handshake (X25519 and ML-KEM-1024,
  ChaCha20-Poly1305, BLAKE3) with the network's pre-shared keys, rekeys and replay protection.
- **Every path at once**: direct over the LAN or the internet (STUN and hole punching), through a
  TURN relay, or through the switch as a last resort. Routes are probed and the best one is
  chosen; peers roam and fail over without a new handshake.
- **Discovery**: switches, mDNS on the LAN, other nodes on the same host and static endpoints.
- **The switch**: introduces the nodes of a network, lists who is online, forwards handshakes and
  low-rate datagrams, and embeds a STUN and a TURN server. It runs over TLS 1.3 (hybrid
  X25519MLKEM768) on HTTP/3, HTTP/2 or HTTP/1.1, with a pinned key or a Web PKI certificate, and
  logs nothing about its users. Open or closed with tokens; rate limits and caps throughout.
- **Metering**: the volume a switch or TURN server allows is a budget; an exhausted transport is
  dropped from routing until it is refilled.
- **Interface mode**: a TUN device with an IPv6 address derived from each node's key, names under
  the interface's domain (`home.internal`) answered by the node's own DNS, and services published
  by name.
- **Exits**: a node can carry its peers' internet traffic (IPv6, and IPv4 behind NAT), for peers
  configured by key only, chosen by site (a country and a name).
- **Library mode**: no TUN and no IP; applications connect to a peer by key and a service name and
  talk over QUIC streams and datagrams, on the same sessions and routes.
- **Platforms**: Linux and macOS (`vv`), Android (`VpnService`), iOS and macOS (Network
  Extension). The protocol crates are sans-IO and build for `wasm32-unknown-unknown`.

## Layout

| Path | Package | Contents |
|---|---|---|
| `proto/` | `vardevall-proto` | sans-IO protocol: keys, handshake, sessions, frames, peers, paths and route selection, candidates, metering, addressing, interface-mode rules, a network simulator (feature `sim`); fuzz targets in `proto/fuzz/` |
| `switch-proto/` | `vardevall-switch-proto` | sans-IO switch client: API types, registration proofs, switch addresses, the STUN/TURN codec, the switch session and the TURN allocation |
| `vardevall/` | `vardevall` | the runtime: sockets, UDP, STUN, TURN and switch transports, candidate sources, library mode |
| `tun/` | `vardevall-tun` | interface mode: packet router, overlay DNS, interface files, the `vv` and `vv-quick` commands, the embedding API for the apps |
| `switch/` | `vardevall-switch` | `vv-switch`, the server; `switch/deploy/` holds example configurations, a container and a systemd unit |
| `tls-pq/` | `vardevall-tls-pq` | X25519MLKEM768 for rustls |
| `ffi/` | `vardevall-ffi` | C interface for the Apple apps (`apple/include/vardevall.h`) |
| `jni/` | `vardevall-jni` | JNI interface for the Android app |
| `apple/` | | SwiftUI app and packet tunnel extension for iOS and macOS |
| `android/` | | Compose app and `VpnService` |

## Try it

Build the commands (Linux; `vv` alone also builds on macOS):

```sh
cargo build --release -p vardevall-tun --bin vv --bin vv-quick
cargo build --release -p vardevall-switch --bin vv-switch
```

Run a switch on a host with a public address (every setting is in `switch/deploy/switch.toml`):

```sh
vv-switch genkey > switch.key && chmod 600 switch.key
vv-switch -c switch.toml address switch.example.org    # prints <key>@switch.example.org
vv-switch -c switch.toml
```

Make a network on the first node. Every node has a private key; all nodes of a network share the
network secret. Both are secret.

```sh
vv gennet                       # the network secret, once per network
vv genkey                       # a private key, one per node
```

`/etc/vardevall/interfaces/home.toml` (mode `0600`) makes the interface `home` and the domain
`home.internal`:

```toml
[interface]
private_key = "<output of vv genkey>"
network_secret = "<output of vv gennet>"
name = "laptop"

[[switch]]
address = "<key>@switch.example.org"
```

Invite the other devices, which writes a file for each (it holds secrets: send it as a password):

```sh
sudo vv invite home phone --out phone.toml
sudo vv invite home server --out server.toml
```

On another Linux node, as root:

```sh
install -m 600 server.toml /etc/vardevall/interfaces/home.toml
vv-quick up home                # Ctrl-C leaves; tun/dist/vv-quick@.service for boot
vv show home                    # the switch, the NATs, each peer and its routes
ping6 laptop.home.internal
```

On a phone, give `phone.toml` to the app. To build the apps:

```sh
# Android: JDK 21, the Android SDK with NDK 27, cargo-ndk
cd android && ./gradlew assembleDebug

# Apple: Xcode, xcodegen; set DEVELOPMENT_TEAM and BUNDLE_ID_PREFIX in Local.xcconfig
cd apple && cp Local.xcconfig.example Local.xcconfig && scripts/build-xcframework.sh && xcodegen generate
```

A Linux node becomes an exit with `[exit] site = "it/home"` in its file; a client uses it with
`vv exit home it/home`, or "Send my internet through" in the apps.

## Tests

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p vardevall-proto --target wasm32-unknown-unknown
```

The protocol behaviour is tested on the simulator in `proto/tests/`; the runtime and the switch are
tested together in `vardevall/tests/`. One of those, `a_switch_volume_that_runs_out_ends_the_use_of_the_switch`,
is timing-sensitive and fails intermittently.

## Known rough edges

- After a change of network, a peer can stay on the relay when a direct path would work again;
  restarting one side brings it back.
- `vv syncconf` cannot change the `[[switch]]` list of a running node: restart it.
- The site in `vv exit` must be written in full (`it/home`, not `it`).
- On Android, DNS is flaky across maufacturers.
- Comments cite the earlier protocol specification as `vv-NN §N`.

## How this was made

This proof of concept has been developed entirely thourgh LLMs (Claude Code Opus 5.5 in paticular) 
under several session, starting from an even earlier document with ideas 
and planning which might be referenced across comments left by LLMs.
It _works_ in practice, but has **not** been reviewed to any satisfiable degree,
and to the degree that it has code quality is okay at best.

## Licence

MPL-2.0 (`LICENSE`), except `switch/`, which is AGPL-3.0-only (`switch/LICENSE`). Most of this code
was generated by AI coding assistants; whether, and how far, copyright subsists in it is uncertain,
and the licences apply to the extent it does.
