//! The control socket of a running interface: one unix socket per interface,
//! line-based JSON.
//!
//! A request is a JSON object with a `"request"` member that names an entry of [`REQUESTS`]; the
//! answer is one line, an object with `"ok":true` and the members of the request's result, or
//! `"ok":false` and `"error"`. Entries are added to the table, not special-cased.
//!
//! The requests, each with its JSON:
//!
//! - `{"request":"status"}`: the exit state, the sites known and what a tool that sets the host up
//!   needs (see [`use_json`]), with `"interface"`, `"device"`, `"domain"`, `"forward"` and
//!   `"dns":{"address":"<ula>","port":53|null}`.
//! - `{"request":"exit","network":"<name>"|null,"site":"<site>"|null}`: use the exit of the
//!   network, of a site or of its only one; `network` null is off. Answers as `status`.
//! - `{"request":"show"}`: what `vv show` prints: `"interface"`, `"device"`, `"public_key"`,
//!   `"network_id"`, `"name"`, `"addresses":{"ula","link_local"}`, `"listen_port"`, `"mtu"`,
//!   `"domain"`, `"serving"`, `"exit"`, `"switches"` (the configured ones), `"view"` (the JSON of
//!   the last `view` event of `tun::embed`, with the countdowns taken at the request) or null
//!   before the first.
//! - `{"request":"down"}`: the interface ends as on SIGTERM: the answer comes first.
//! - `{"request":"syncconf","config":"<interface file text>","dry_run":false}`: apply the file to
//!   the running interface (`Tunnel::apply`). Answers `"applied"` and `"changes"` (one line each).
//!   A field that needs a restart refuses the file: `"ok":false` and the names in `"error"`.
//!   With `dry_run` nothing is applied.
//! - `{"request":"set","peers":[{"key":"<key>","name":"<label>"|null,"endpoint":"<host:port>"|null,
//!   "remove":false}]}`: change peers of the running interface without the file (a missing member
//!   is left alone, null clears it; an unknown key is added). Answers as `syncconf`.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::UnixListener;
use vardevall_proto::ip::site::Site;
use vardevall_proto::keys::NodePublic;
use vardevall_tun::config::{Config, ConfigDiff, Context as ConfigContext, Field, PeerChange};
use vardevall_tun::dns::Forwarder;
use vardevall_tun::embed::{ApplyError, Event, ExitInUse, ExitUse, Tunnel};
use vardevall_tun::files;

/// Longest request line.
const MAX_LINE: u64 = 64 * 1024;
/// Requests answered on one connection.
const MAX_REQUESTS: usize = 16;
/// How long a client may take to send a line, and a server to answer one.
const TIMEOUT: Duration = Duration::from_secs(5);

/// What the requests act on.
pub struct Shared {
    /// The interface, which is also the name of its network.
    pub interface: String,
    /// The tunnel device.
    pub device: String,
    /// The running tunnel.
    pub tunnel: Arc<Tunnel>,
    /// The exit in use: `None` is off.
    using: Mutex<Option<ExitUse>>,
    /// Whether the host has an IPv6 uplink, once looked at.
    ipv6_uplink: Mutex<Option<bool>>,
    /// The sites of the last `view` event, as the events show them.
    sites: Arc<Mutex<Vec<Value>>>,
    /// The last `view` event, rendered again at each `show` so that its countdowns are current.
    view: Arc<Mutex<Option<Event>>>,
    /// The port the overlay resolver listens on, if it could bind.
    dns_port: Mutex<Option<u16>>,
    /// The forwarder of the resolver the process runs, which follows `forward` of the file.
    forwarder: Mutex<Option<Arc<Forwarder>>>,
    /// Woken when a `down` request asks the process to end.
    pub stop: Arc<tokio::sync::Notify>,
}

impl Shared {
    /// The state around `tunnel` on `device`; `sites` is filled by the events.
    pub fn new(
        interface: String,
        device: String,
        tunnel: Arc<Tunnel>,
        sites: Arc<Mutex<Vec<Value>>>,
    ) -> Shared {
        Shared {
            interface,
            device,
            tunnel,
            using: Mutex::new(None),
            ipv6_uplink: Mutex::new(None),
            sites,
            view: Arc::new(Mutex::new(None)),
            dns_port: Mutex::new(None),
            forwarder: Mutex::new(None),
            stop: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// The slot the last `view` event is kept in.
    pub fn with_view(mut self, view: Arc<Mutex<Option<Event>>>) -> Self {
        self.view = view;
        self
    }

    /// Tells the requests which port the overlay resolver listens on.
    pub fn set_dns_port(&self, port: Option<u16>) {
        *self.dns_port.lock().unwrap_or_else(PoisonError::into_inner) = port;
    }

    /// Tells the requests which forwarder to point at the new upstreams after `syncconf`.
    pub fn set_forwarder(&self, forwarder: Arc<Forwarder>) {
        *self
            .forwarder
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(forwarder);
    }

    /// Makes this network carry the exit, or none.
    pub fn set_use(&self, using: Option<ExitUse>) {
        self.tunnel.set_exit(using.clone());
        *self.using.lock().unwrap_or_else(PoisonError::into_inner) = using;
    }

    /// Tells the tunnel whether the host has an IPv6 uplink; returns whether that
    /// differs from what it was told last, a first time included.
    pub fn set_ipv6_uplink(&self, on: bool) -> bool {
        self.tunnel.set_ipv6_uplink(on);
        let mut last = self
            .ipv6_uplink
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        last.replace(on) != Some(on)
    }

    fn using(&self) -> Option<ExitUse> {
        self.using
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

type Handler = fn(&Shared, &Map<String, Value>) -> Result<Value, String>;

/// The requests, by name.
const REQUESTS: &[(&str, Handler)] = &[
    ("exit", exit),
    ("status", status),
    ("show", show),
    ("down", down),
    ("syncconf", syncconf),
    ("set", set),
];

/// Answers one request line.
pub fn dispatch(shared: &Shared, line: &str) -> String {
    let result = serde_json::from_str::<Value>(line.trim())
        .map_err(|e| format!("not JSON: {e}"))
        .and_then(|v| match v {
            Value::Object(o) => Ok(o),
            _ => Err("the request is not an object".to_owned()),
        })
        .and_then(|o| {
            let name = o
                .get("request")
                .and_then(Value::as_str)
                .ok_or("no \"request\"")?;
            let (_, handler) = REQUESTS
                .iter()
                .find(|(n, _)| *n == name)
                .ok_or_else(|| format!("unknown request {name:?}"))?;
            handler(shared, &o)
        });
    let mut out = match result {
        Ok(Value::Object(o)) => o,
        Ok(other) => Map::from_iter([("result".to_owned(), other)]),
        Err(e) => {
            let mut o = Map::new();
            o.insert("ok".into(), false.into());
            o.insert("error".into(), e.into());
            return Value::Object(o).to_string();
        }
    };
    out.insert("ok".into(), true.into());
    Value::Object(out).to_string()
}

/// `{"request":"exit","network":"<name>"|null,"site":"<site>"|null}`: use the exit of the network,
/// of a site or of its only one; `network` null is off.
fn exit(shared: &Shared, request: &Map<String, Value>) -> Result<Value, String> {
    let network = match request.get("network") {
        None | Some(Value::Null) => None,
        Some(Value::String(n)) => Some(n.as_str()),
        Some(_) => return Err("\"network\" is a name or null".to_owned()),
    };
    let site = match request.get("site") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.parse::<Site>().map_err(|e| format!("site: {e}"))?),
        Some(_) => return Err("\"site\" is a site or null".to_owned()),
    };
    let using = match network {
        None if site.is_some() => return Err("a site needs its network".to_owned()),
        None => None,
        Some(n) if n == shared.interface => Some(ExitUse { site }),
        Some(n) => {
            return Err(format!(
                "this interface is the network {:?}, not {n:?}",
                shared.interface
            ));
        }
    };
    shared.set_use(using);
    Ok(use_json(shared))
}

/// `{"request":"status"}`: the exit state and the sites known.
fn status(shared: &Shared, _: &Map<String, Value>) -> Result<Value, String> {
    let mut v = use_json(shared);
    let config = shared.tunnel.config();
    v["interface"] = shared.interface.clone().into();
    v["device"] = shared.device.clone().into();
    v["domain"] = config.domain.clone().into();
    v["forward"] = (!config.forward.is_empty()).into();
    v["dns"] = dns_json(shared);
    v["sites"] = Value::Array(
        shared
            .sites
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone(),
    );
    Ok(v)
}

fn dns_json(shared: &Shared) -> Value {
    json!({
        "address": shared.tunnel.config().own_addrs().ula.to_string(),
        "port": *shared.dns_port.lock().unwrap_or_else(PoisonError::into_inner),
    })
}

/// `{"request":"show"}`: see the module documentation.
fn show(shared: &Shared, _: &Map<String, Value>) -> Result<Value, String> {
    let config = shared.tunnel.config();
    let addrs = config.own_addrs();
    let mut v = use_json(shared);
    v["interface"] = shared.interface.clone().into();
    v["device"] = shared.device.clone().into();
    v["public_key"] = config.public_key.to_base32().into();
    v["network_id"] = config.network_id.to_base32().into();
    v["name"] = config.own_name.clone().into();
    v["addresses"] =
        json!({"ula": addrs.ula.to_string(), "link_local": addrs.link_local.to_string()});
    v["listen_port"] = shared.tunnel.listen_port().into();
    v["mtu"] = config.mtu.into();
    v["domain"] = config.domain.clone().into();
    v["forward"] = (!config.forward.is_empty()).into();
    v["dns"] = dns_json(shared);
    v["switches"] = config
        .switches
        .iter()
        .map(|s| json!({"address": s.label()}))
        .collect::<Vec<_>>()
        .into();
    let view = shared
        .view
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .and_then(|e| serde_json::from_str::<Value>(&e.to_json(&shared.interface)).ok())
        .map(|mut view| {
            if let Some(o) = view.as_object_mut() {
                o.remove("type");
                o.remove("network");
            }
            view
        });
    v["view"] = view.unwrap_or(Value::Null);
    Ok(v)
}

/// `{"request":"down"}`: wakes the process's main task, a moment later so that the answer is out.
fn down(shared: &Shared, _: &Map<String, Value>) -> Result<Value, String> {
    let stop = shared.stop.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop.notify_one();
    });
    Ok(json!({"stopping": true}))
}

fn applied(shared: &Shared, config: Config, dry_run: bool) -> Result<Value, String> {
    let diff = if dry_run {
        let diff = ConfigDiff::between(&shared.tunnel.config(), &config);
        if diff.needs_restart() {
            return Err(ApplyError::NeedsRestart(diff.restart).to_string());
        }
        diff
    } else {
        let diff = shared.tunnel.apply(config).map_err(|e| e.to_string())?;
        if let Some(f) = shared
            .forwarder
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            f.set_upstreams(shared.tunnel.config().upstreams());
        }
        diff
    };
    Ok(json!({"applied": !dry_run, "changes": diff.lines()}))
}

/// `{"request":"syncconf","config":"<text>","dry_run":bool}`.
fn syncconf(shared: &Shared, request: &Map<String, Value>) -> Result<Value, String> {
    let text = request
        .get("config")
        .and_then(Value::as_str)
        .ok_or("\"config\" is the text of the interface file")?;
    let dry_run = request
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let config = Config::parse(
        text,
        &ConfigContext {
            interface_name: shared.interface.clone(),
            hostname: files::hostname(),
        },
    )
    .map_err(|e| e.to_string())?;
    applied(shared, config, dry_run)
}

fn field(entry: &Map<String, Value>, name: &str) -> Result<Field, String> {
    match entry.get(name) {
        None => Ok(Field::Keep),
        Some(Value::Null) => Ok(Field::Clear),
        Some(Value::String(s)) => Ok(Field::Set(s.clone())),
        Some(_) => Err(format!("\"{name}\" is a string or null")),
    }
}

/// `{"request":"set","peers":[{"key":…,"name":…,"endpoint":…,"remove":…}]}`.
fn set(shared: &Shared, request: &Map<String, Value>) -> Result<Value, String> {
    let list = request
        .get("peers")
        .and_then(Value::as_array)
        .ok_or("\"peers\" is a list")?;
    let mut changes = Vec::new();
    for entry in list {
        let entry = entry.as_object().ok_or("a peer is an object")?;
        let key: NodePublic = entry
            .get("key")
            .and_then(Value::as_str)
            .and_then(|k| k.parse().ok())
            .ok_or("\"key\" is a node public key")?;
        let mut change = PeerChange::new(key);
        change.name = field(entry, "name")?;
        change.endpoint = field(entry, "endpoint")?;
        change.remove = entry
            .get("remove")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        changes.push(change);
    }
    let config = shared
        .tunnel
        .config()
        .with_peer_changes(&changes)
        .map_err(|e| e.to_string())?;
    applied(shared, config, false)
}

fn chosen_json(e: &ExitInUse) -> Value {
    json!({
        "site": e.site.to_string(),
        "via": e.via.to_base32(),
        "addr": e.addr.to_string(),
        "ipv4": e.ipv4.map(|a| a.to_string()),
    })
}

/// What a tool that sets the host up needs:
/// `{"exit":{"network":…,"site":…,"chosen":null|{"site","via","addr","ipv4"},"ipv4_home":…,
/// "offered":["<site>",…]},"serving":null|{"site":…,"ipv4":bool,"ipv6_uplink":bool|null}}`.
/// `ipv4_home` is the address to configure until an exit gives one; `offered` holds the sites
/// some peer has offered, live or not.
fn use_json(shared: &Shared) -> Value {
    let using = shared.using();
    let offered: Vec<Value> = shared
        .sites
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter_map(|s| s.get("site").cloned())
        .collect();
    let serving = shared.tunnel.config().exit.as_ref().map(|serve| {
        json!({
            "site": serve.site.to_string(),
            "ipv4": serve.ipv4,
            "ipv6_uplink": *shared.ipv6_uplink.lock().unwrap_or_else(PoisonError::into_inner),
        })
    });
    json!({
        "serving": serving,
        "exit": {
            "network": using.as_ref().map(|_| shared.interface.clone()),
            "site": using.as_ref().and_then(|u| u.site.as_ref()).map(Site::to_string),
            "chosen": using.as_ref().and_then(|_| shared.tunnel.exit_in_use()).as_ref().map(chosen_json),
            "ipv4_home": shared.tunnel.home_ipv4().to_string(),
            "offered": offered,
        }
    })
}

/// Why no exit is chosen yet: the site asked for is not among those offered, or none was named
/// while several are.
fn no_exit_reason(exit: &Value) -> String {
    let offered: Vec<&str> = exit["offered"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    match exit["site"].as_str() {
        Some(site) if !offered.is_empty() && !offered.contains(&site) => {
            format!("no peer offers {site}; offered: {}", offered.join(", "))
        }
        None if offered.len() > 1 => {
            format!(
                "several sites are offered, name one: {}",
                offered.join(", ")
            )
        }
        _ => "no live exit yet".to_owned(),
    }
}

/// Removes the socket file when dropped.
pub struct Socket {
    path: PathBuf,
}

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Binds the socket at `path`, mode `0600`, replacing a stale file but not a live socket.
pub fn bind(path: &Path) -> Result<(UnixListener, Socket)> {
    if let Some(dir) = path.parent()
        && !dir.exists()
    {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            bail!("{} is in use: is the interface already up?", path.display());
        }
        std::fs::remove_file(path)
            .with_context(|| format!("removing the stale {}", path.display()))?;
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok((
        listener,
        Socket {
            path: path.to_owned(),
        },
    ))
}

/// Answers the connections one after the other, each for a few requests.
pub async fn serve(listener: UnixListener, shared: Arc<Shared>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let _ = tokio::time::timeout(TIMEOUT * 2, talk(stream, &shared)).await;
    }
}

async fn talk(stream: tokio::net::UnixStream, shared: &Shared) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut read = AsyncBufReader::new(read.take(MAX_LINE * MAX_REQUESTS as u64));
    for _ in 0..MAX_REQUESTS {
        let mut line = String::new();
        let n = tokio::time::timeout(TIMEOUT, (&mut read).take(MAX_LINE).read_line(&mut line))
            .await
            .map_err(|_| std::io::ErrorKind::TimedOut)??;
        if n == 0 {
            break;
        }
        let mut answer = dispatch(shared, &line);
        answer.push('\n');
        write.write_all(answer.as_bytes()).await?;
    }
    Ok(())
}

pub use vardevall_tun::control_client::{ask, default_path, running};

/// The text of a `status` or `exit` answer.
pub fn describe(answer: &Value) -> String {
    let mut out = String::new();
    let exit = &answer["exit"];
    match exit["network"].as_str() {
        None => out.push_str("exit: off\n"),
        Some(net) => {
            let site = exit["site"].as_str().unwrap_or("the only site");
            out.push_str(&format!("exit: on, network {net}, site {site}\n"));
            match exit["chosen"].as_object() {
                Some(c) => out.push_str(&format!(
                    "  via {} (address {}, {})\n",
                    c["via"].as_str().unwrap_or("?"),
                    c["addr"].as_str().unwrap_or("?"),
                    match c["ipv4"].as_str() {
                        Some(a) => format!("IPv4 {a}"),
                        None => "no IPv4".to_owned(),
                    }
                )),
                None => out.push_str(&format!("  {}\n", no_exit_reason(exit))),
            }
        }
    }
    if let Some(serving) = answer["serving"].as_object() {
        let site = serving["site"].as_str().unwrap_or("?");
        let ipv4 = if serving["ipv4"] == true {
            "IPv4"
        } else {
            "no IPv4"
        };
        out.push_str(&match serving["ipv6_uplink"].as_bool() {
            Some(true) => format!("serving {site}: {ipv4}, IPv6 uplink present\n"),
            Some(false) => format!("serving {site}: {ipv4}, no IPv6 uplink\n"),
            None => format!("serving {site}: {ipv4}, IPv6 uplink not looked at yet\n"),
        });
    }
    if let Some(sites) = answer["sites"].as_array() {
        out.push_str(&format!("sites known: {}\n", sites.len()));
        for s in sites {
            let live = s["peers"].as_array().map_or(0, Vec::len);
            let down = s["down"].as_array().map_or(0, Vec::len);
            out.push_str(&format!(
                "  {}: {live} live, {down} down, {}\n",
                s["site"].as_str().unwrap_or("?"),
                match s["chosen"].as_str() {
                    Some(k) => format!("chosen {k}"),
                    None => "none chosen".to_owned(),
                }
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use vardevall_tun::embed::{Callbacks, StartOptions};
    use vardevall_tun::keys;

    use super::*;

    fn tunnel() -> Arc<Tunnel> {
        let text = format!(
            "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{}\"\nlisten_port = 0\nmdns = false\n",
            keys::generate_node_key(),
            keys::generate_network_secret()
        );
        let callbacks = Callbacks {
            packets: Box::new(|_| {}),
            event: Box::new(|_, _| {}),
            mdns: None,
        };
        let options = StartOptions {
            interface_name: "home".into(),
            ..StartOptions::default()
        };
        Arc::new(
            Tunnel::start(
                &tokio::runtime::Handle::current(),
                &text,
                options,
                callbacks,
            )
            .unwrap(),
        )
    }

    fn shared() -> Arc<Shared> {
        let sites = Arc::new(Mutex::new(vec![json!({
            "site": "it/home", "peers": ["aaa"], "down": [], "chosen": "aaa", "addr": "fd00::1"
        })]));
        Arc::new(Shared::new("home".into(), "home".into(), tunnel(), sites))
    }

    fn call(shared: &Shared, request: Value) -> Value {
        serde_json::from_str(&dispatch(shared, &request.to_string())).unwrap()
    }

    #[test]
    fn the_requests_have_distinct_names() {
        let mut names: Vec<_> = REQUESTS.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), REQUESTS.len());
    }

    #[tokio::test]
    async fn bad_requests_are_refused_with_a_reason() {
        let shared = shared();
        for line in ["", "nonsense", "[1]", "{}", r#"{"request":"nope"}"#] {
            let answer: Value = serde_json::from_str(&dispatch(&shared, line)).unwrap();
            assert_eq!(answer["ok"], false, "{line}");
            assert!(answer["error"].is_string(), "{line}");
        }
        for request in [
            json!({"request":"exit","network":"work","site":null}),
            json!({"request":"exit","network":null,"site":"it"}),
            json!({"request":"exit","network":"home","site":"italy"}),
            json!({"request":"exit","network":3}),
            json!({"request":"exit","network":"home","site":7}),
        ] {
            let answer = call(&shared, request.clone());
            assert_eq!(answer["ok"], false, "{request}");
        }
        assert_eq!(
            call(&shared, json!({"request":"status"}))["exit"]["network"],
            Value::Null
        );
    }

    #[tokio::test]
    async fn status_shows_the_exit_state_and_the_sites() {
        let shared = shared();
        let answer = call(&shared, json!({"request":"status"}));
        assert_eq!(answer["ok"], true);
        assert_eq!(answer["interface"], "home");
        assert_eq!(answer["exit"]["network"], Value::Null);
        assert_eq!(answer["sites"][0]["site"], "it/home");
        let text = describe(&answer);
        assert!(text.contains("exit: off"));
        assert!(text.contains("it/home: 1 live, 0 down, chosen aaa"));
    }

    #[tokio::test]
    async fn the_exit_request_turns_the_use_on_and_off() {
        let shared = shared();
        let on = call(
            &shared,
            json!({"request":"exit","network":"home","site":"it/home"}),
        );
        assert_eq!(on["ok"], true);
        let status = call(&shared, json!({"request":"status"}));
        assert_eq!(status["device"], "home");
        assert_eq!(status["exit"]["network"], "home");
        assert_eq!(status["exit"]["site"], "it/home");
        assert_eq!(status["exit"]["chosen"], Value::Null, "no exit is live");
        assert_eq!(
            status["exit"]["ipv4_home"],
            shared.tunnel.home_ipv4().to_string()
        );
        assert!(describe(&status).contains("no live exit yet"));

        let off = call(
            &shared,
            json!({"request":"exit","network":null,"site":null}),
        );
        assert_eq!(off["ok"], true);
        assert_eq!(off["exit"]["network"], Value::Null);
    }

    #[tokio::test]
    async fn a_site_nobody_offers_is_named_with_the_sites_offered() {
        let shared = shared();
        let on = call(
            &shared,
            json!({"request":"exit","network":"home","site":"it"}),
        );
        assert_eq!(on["exit"]["offered"], json!(["it/home"]));
        assert!(describe(&on).contains("no peer offers it; offered: it/home"));

        let several = json!({"network": "home", "site": null, "chosen": null,
            "offered": ["de/lab", "it/home"]});
        assert_eq!(
            no_exit_reason(&several),
            "several sites are offered, name one: de/lab, it/home"
        );
        let offered = json!({"network": "home", "site": "it/home", "chosen": null,
            "offered": ["it/home"]});
        assert_eq!(no_exit_reason(&offered), "no live exit yet");
    }

    #[test]
    fn a_chosen_exit_is_described_with_its_ipv4_address() {
        let text = |ipv4: Value| {
            describe(
                &json!({"exit": {"network": "home", "site": null, "chosen": {
                    "site": "it/home", "via": "aaa", "addr": "fd00::5", "ipv4": ipv4
                }}}),
            )
        };
        assert!(text(json!("198.18.3.4")).contains("via aaa (address fd00::5, IPv4 198.18.3.4)"));
        assert!(text(Value::Null).contains("no IPv4"));
    }

    #[tokio::test]
    async fn the_socket_is_private_replaces_a_stale_file_and_refuses_a_live_one() {
        let dir = std::env::temp_dir().join(format!("vv-control-{}", std::process::id()));
        let path = dir.join("home.sock");
        let shared = shared();
        {
            let (listener, guard) = bind(&path).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            assert_eq!(
                std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert!(bind(&path).is_err(), "a live socket is not replaced");
            tokio::spawn(serve(listener, shared.clone()));

            let p = path.clone();
            let answer = tokio::task::spawn_blocking(move || ask(&p, &json!({"request":"status"})))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(answer["interface"], "home");
            let p = path.clone();
            let refused = tokio::task::spawn_blocking(move || {
                ask(&p, &json!({"request":"exit","network":"work"}))
            })
            .await
            .unwrap();
            assert!(refused.unwrap_err().to_string().contains("not \"work\""));
            drop(guard);
            assert!(!path.exists(), "removed when dropped");
        }
        std::fs::write(&path, b"stale").unwrap();
        let (_listener, _guard) = bind(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn file_text(extra: &str) -> String {
        format!(
            "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{}\"\nlisten_port = 0\nmdns = false\nname = \"me\"\n{extra}\n",
            keys::generate_node_key(),
            keys::generate_network_secret()
        )
    }

    fn shared_from(text: &str) -> Arc<Shared> {
        let callbacks = Callbacks {
            packets: Box::new(|_| {}),
            event: Box::new(|_, _| {}),
            mdns: None,
        };
        let options = StartOptions {
            interface_name: "home".into(),
            ..StartOptions::default()
        };
        let tunnel =
            Tunnel::start(&tokio::runtime::Handle::current(), text, options, callbacks).unwrap();
        Arc::new(Shared::new(
            "home".into(),
            "home".into(),
            Arc::new(tunnel),
            Arc::new(Mutex::new(Vec::new())),
        ))
    }

    #[tokio::test]
    async fn show_gives_the_interface_and_a_null_view_before_the_first() {
        let shared = shared();
        shared.set_dns_port(Some(53));
        let a = call(&shared, json!({"request":"show"}));
        assert_eq!(a["ok"], true);
        assert_eq!(a["interface"], "home");
        assert_eq!(a["domain"], "home.internal");
        assert_eq!(a["view"], Value::Null);
        assert_eq!(a["dns"]["port"], 53);
        assert_eq!(a["addresses"]["ula"], a["dns"]["address"]);
        assert!(a["public_key"].is_string() && a["switches"].is_array());
        let status = call(&shared, json!({"request":"status"}));
        assert_eq!(status["forward"], false);
        assert_eq!(status["domain"], "home.internal");
    }

    #[tokio::test]
    async fn syncconf_applies_a_file_dry_runs_it_and_refuses_what_needs_a_restart() {
        let text = file_text("");
        let shared = shared_from(&text);
        let peer = keys::public_key(&keys::generate_node_key()).unwrap();
        let with_peer = format!("{text}\n[[peer]]\npublic_key = \"{peer}\"\nname = \"lab\"\n");

        let dry = call(
            &shared,
            json!({"request":"syncconf","config":with_peer,"dry_run":true}),
        );
        assert_eq!(dry["ok"], true);
        assert_eq!(dry["applied"], false);
        assert_eq!(dry["changes"].as_array().unwrap().len(), 1);
        assert!(
            shared.tunnel.config().peers.is_empty(),
            "a dry run changes nothing"
        );

        let real = call(&shared, json!({"request":"syncconf","config":with_peer}));
        assert_eq!(real["applied"], true);
        assert!(
            real["changes"][0]
                .as_str()
                .unwrap()
                .starts_with("peer added: lab")
        );
        assert_eq!(shared.tunnel.config().peers.len(), 1);

        let restart = format!("{with_peer}\n").replace("mdns = false", "mdns = true\nmtu = 1400");
        let refused = call(&shared, json!({"request":"syncconf","config":restart}));
        assert_eq!(refused["ok"], false);
        assert_eq!(refused["error"], "needs a restart: mtu, mdns");
        assert_eq!(shared.tunnel.config().mtu, 1280);

        let bad = call(&shared, json!({"request":"syncconf","config":"nonsense ="}));
        assert_eq!(bad["ok"], false);
        assert_eq!(call(&shared, json!({"request":"syncconf"}))["ok"], false);
    }

    #[tokio::test]
    async fn set_adds_names_and_removes_peers_of_the_running_interface() {
        let shared = shared_from(&file_text(""));
        let key = keys::public_key(&keys::generate_node_key()).unwrap();
        let added = call(
            &shared,
            json!({"request":"set","peers":[{"key":key,"name":"lab","endpoint":"192.0.2.1:4455"}]}),
        );
        assert_eq!(added["ok"], true, "{added}");
        assert_eq!(shared.tunnel.config().peers[0].name.as_deref(), Some("lab"));
        let renamed = call(
            &shared,
            json!({"request":"set","peers":[{"key":key,"name":null}]}),
        );
        assert_eq!(renamed["ok"], true);
        assert_eq!(shared.tunnel.config().peers[0].name, None);
        assert_eq!(shared.tunnel.config().peers[0].endpoints.len(), 1);
        let gone = call(
            &shared,
            json!({"request":"set","peers":[{"key":key,"remove":true}]}),
        );
        assert_eq!(gone["ok"], true);
        assert!(shared.tunnel.config().peers.is_empty());
        for bad in [
            json!({"request":"set"}),
            json!({"request":"set","peers":[{"key":"nope"}]}),
            json!({"request":"set","peers":[{"key":key,"name":3}]}),
            json!({"request":"set","peers":[{"key":key,"remove":true}]}),
        ] {
            assert_eq!(call(&shared, bad.clone())["ok"], false, "{bad}");
        }
    }

    #[tokio::test]
    async fn down_wakes_the_main_task_after_the_answer() {
        let shared = shared();
        let stop = shared.stop.clone();
        let a = call(&shared, json!({"request":"down"}));
        assert_eq!(a["ok"], true);
        tokio::time::timeout(Duration::from_secs(2), stop.notified())
            .await
            .expect("woken");
    }

    #[test]
    fn the_default_path_is_per_interface() {
        assert!(default_path("home").ends_with("vardevall/home.sock"));
    }

    #[tokio::test]
    async fn status_shows_the_uplink_of_a_serving_exit_only() {
        let shared = shared();
        assert_eq!(
            call(&shared, json!({"request":"status"}))["serving"],
            Value::Null
        );
        assert!(shared.set_ipv6_uplink(false), "the first look is a change");
        assert!(!shared.set_ipv6_uplink(false));
        assert!(shared.set_ipv6_uplink(true));

        let text = |uplink: Value| {
            describe(&json!({"exit": {"network": null}, "serving": {
                "site": "it/home", "ipv4": true, "ipv6_uplink": uplink
            }}))
        };
        assert!(text(json!(false)).contains("serving it/home: IPv4, no IPv6 uplink"));
        assert!(text(json!(true)).contains("IPv6 uplink present"));
        assert!(text(Value::Null).contains("not looked at yet"));
    }
}
