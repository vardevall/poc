//! The task of one switch: it carries out what a [`SwitchSession`] asks (connections, requests,
//! the events stream, DNS) and tells the engine what the session reports.

use std::collections::VecDeque;
use std::future::pending;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method as HttpMethod};
use tokio::sync::mpsc;
use tokio::time::sleep_until;
use vardevall_proto::keys::{NetworkSecret, NodeSecret};
use vardevall_switch_proto::session::{
    CallId, HttpRequest, LinkError, Method, Out, SessionConfig, SwitchSession,
};

use super::http::{Conn, HttpError, Reply, Streaming, Target, Transport};
use super::{Command, Inbound, Origin, SwitchId, uri};
use crate::clock::Clock;
use crate::config::SwitchSpec;
use crate::net::mark::SocketMark;
use crate::net::rng::{OsRng, os_rng};

pub(super) struct Link {
    pub id: SwitchId,
    pub spec: SwitchSpec,
    /// The host of the address in the normal form registrations carry (vv-04 §4.3).
    pub host: String,
    pub node: NodeSecret,
    pub network: NetworkSecret,
    /// The mark of the sockets that look up the servers the switch names.
    pub mark: SocketMark,
}

pub(super) struct Channels {
    pub commands: mpsc::Receiver<Command>,
    pub inbound: mpsc::Sender<Inbound>,
}

type Fut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type Connected = Result<(Conn, [u8; 32], Transport), HttpError>;
type Called = (CallId, Conn, Result<Reply, HttpError>);
type Opened = (CallId, Result<(Conn, Streaming), HttpError>);

/// The events stream and the connection that carries it.
struct Live {
    id: CallId,
    _conn: Conn,
    body: Streaming,
}

/// What the loop woke up for.
enum Event {
    Timer,
    Connected(Connected),
    Called(Called),
    Opened(Opened),
    Chunk(CallId, Option<Bytes>),
    Command(Option<Command>),
}

struct Driver {
    link: Link,
    target: Target,
    ch: Channels,
    clock: Clock,
    session: SwitchSession,
    rng: OsRng,
    connecting: Option<Fut<Connected>>,
    /// The connection, unless a request runs on it.
    conn: Option<Conn>,
    running: Option<Fut<Called>>,
    queue: VecDeque<(CallId, HttpRequest)>,
    opening: Option<Fut<Opened>>,
    stream: Option<Live>,
}

fn link_error(e: &HttpError) -> LinkError {
    match e {
        HttpError::KeyMismatch => LinkError::Untrusted,
        HttpError::Connect | HttpError::Io => LinkError::Unreachable,
        HttpError::TooLarge => LinkError::Protocol,
    }
}

fn retry_after(headers: &HeaderMap) -> Option<u64> {
    headers.get("retry-after")?.to_str().ok()?.parse().ok()
}

/// The method and headers of `req`; `None` if a header value is not valid HTTP.
fn parts(req: &HttpRequest) -> Option<(HttpMethod, Vec<(HeaderName, HeaderValue)>)> {
    let method = match req.method {
        Method::Get => HttpMethod::GET,
        Method::Post => HttpMethod::POST,
    };
    let headers = req
        .headers
        .iter()
        .map(|(k, v)| Some((HeaderName::from_static(k), HeaderValue::from_str(v).ok()?)))
        .collect::<Option<_>>()?;
    Some((method, headers))
}

/// Waits for the future in `slot`, and empties the slot when it completes.
async fn finished<T>(slot: &mut Option<Fut<T>>) -> T {
    match slot.as_mut() {
        Some(f) => {
            let out = f.await;
            *slot = None;
            out
        }
        None => pending().await,
    }
}

async fn next_chunk(stream: &mut Option<Live>) -> (CallId, Option<Bytes>) {
    match stream {
        Some(live) => (live.id, live.body.chunk().await),
        None => pending().await,
    }
}

impl Driver {
    fn now(&self) -> vardevall_proto::time::Instant {
        self.clock.now().instant
    }

    async fn event(&mut self) -> Event {
        let deadline = self
            .session
            .poll_timeout()
            .map(|t| self.clock.tokio_instant(t));
        let idle = self.running.is_none() && self.queue.is_empty();
        tokio::select! {
            () = async {
                match deadline {
                    Some(t) => sleep_until(t).await,
                    None => pending().await,
                }
            } => Event::Timer,
            r = finished(&mut self.connecting) => Event::Connected(r),
            r = finished(&mut self.running) => Event::Called(r),
            r = finished(&mut self.opening) => Event::Opened(r),
            (id, data) = next_chunk(&mut self.stream) => Event::Chunk(id, data),
            c = self.ch.commands.recv(), if idle => Event::Command(c),
        }
    }

    async fn send(&mut self, msg: Inbound) {
        let _ = self.ch.inbound.send(msg).await;
    }

    async fn apply(&mut self, out: Out) {
        let id = self.link.id;
        match out {
            Out::Connect => {
                let target = self.target.clone();
                self.connecting = Some(Box::pin(async move { Conn::connect(&target).await }));
            }
            Out::Close => {
                self.connecting = None;
                self.conn = None;
                self.running = None;
                self.queue.clear();
                self.opening = None;
                self.stream = None;
                while self.ch.commands.try_recv().is_ok() {}
            }
            Out::Call { id, req } => self.queue.push_back((id, req)),
            Out::OpenStream { id, req } => self.open_stream(id, &req),
            Out::State(state) => {
                let retry_at = self
                    .session
                    .reconnect_at()
                    .map(|t| self.clock.tokio_instant(t));
                self.send(Inbound::State(id, state, retry_at)).await;
            }
            Out::Budget(bytes) => self.send(Inbound::Budget { id, bytes }).await,
            Out::Info { stun, stun_auth } => {
                let servers = uri::stun_servers(&stun, self.link.mark).await;
                self.send(Inbound::Stun {
                    origin: Origin::Switch(id),
                    servers,
                    required: stun_auth,
                })
                .await;
            }
            Out::StunCredentials(c) => {
                self.send(Inbound::StunCredentials {
                    origin: Origin::Switch(id),
                    username: c.username,
                    key: c.credential.into_bytes(),
                    ttl: Some(Duration::from_secs(c.ttl)),
                })
                .await;
            }
            Out::TurnCredentials(c) => {
                if let Some(offer) = uri::turn_offer(&c, &self.link.spec.auth, self.link.mark).await
                {
                    self.send(Inbound::Turn {
                        origin: Origin::Switch(id),
                        offer,
                    })
                    .await;
                }
            }
            Out::Presence { node, online } => {
                self.send(Inbound::Presence { id, node, online }).await;
            }
            Out::Forwarded { from, msg } => {
                let _ = self.ch.inbound.try_send(Inbound::Forward { id, from, msg });
            }
        }
    }

    /// Opens the events stream on a shared connection, or on a TCP one of its own if the
    /// protocol cannot share (HTTP/1.1).
    fn open_stream(&mut self, id: CallId, req: &HttpRequest) {
        let Some((method, headers)) = parts(req) else {
            let now = self.now();
            self.session
                .call_failed(now, &mut self.rng, id, LinkError::Protocol);
            return;
        };
        let shared = self.conn.as_ref().and_then(Conn::share);
        let target = self.target.clone();
        let path = req.path.clone();
        self.opening = Some(Box::pin(async move {
            let result = async {
                let mut conn = match shared {
                    Some(c) => c,
                    None => Conn::connect_tcp_only(&target).await?.0,
                };
                let body = conn.open(method, &path, &headers).await?;
                Ok((conn, body))
            }
            .await;
            (id, result)
        }));
    }

    /// Starts the next queued request if the connection is free; `true` if the request could
    /// not be started and the session has been told.
    fn start_call(&mut self) -> bool {
        if self.running.is_some() {
            return false;
        }
        let Some((id, req)) = self.queue.pop_front() else {
            return false;
        };
        let (Some(mut conn), Some((method, headers))) = (self.conn.take(), parts(&req)) else {
            let now = self.now();
            self.session
                .call_failed(now, &mut self.rng, id, LinkError::Unreachable);
            return true;
        };
        self.running = Some(Box::pin(async move {
            let reply = conn.call(method, &req.path, &headers, req.body).await;
            (id, conn, reply)
        }));
        false
    }

    async fn handle(&mut self, event: Event) -> bool {
        let now = self.now();
        match event {
            Event::Timer => self.session.handle_timeout(now),
            Event::Connected(Ok((conn, exporter, transport))) => {
                self.conn = Some(conn);
                let id = self.link.id;
                self.send(Inbound::Transport { id, transport }).await;
                self.session.connected(now, exporter);
            }
            Event::Connected(Err(e)) => {
                self.session
                    .connect_failed(now, &mut self.rng, link_error(&e));
            }
            Event::Called((id, conn, result)) => {
                self.conn = Some(conn);
                match result {
                    Ok(r) => self.session.response(
                        now,
                        &mut self.rng,
                        id,
                        r.status.as_u16(),
                        retry_after(&r.headers),
                        &r.body,
                    ),
                    Err(e) => self
                        .session
                        .call_failed(now, &mut self.rng, id, link_error(&e)),
                }
            }
            Event::Opened((id, Ok((conn, body)))) => {
                let (status, retry) = (body.status.as_u16(), retry_after(&body.headers));
                self.stream = Some(Live {
                    id,
                    _conn: conn,
                    body,
                });
                self.session
                    .response(now, &mut self.rng, id, status, retry, &[]);
            }
            Event::Opened((id, Err(e))) => {
                self.session
                    .call_failed(now, &mut self.rng, id, link_error(&e));
            }
            Event::Chunk(id, Some(data)) => self.session.stream_data(now, &mut self.rng, id, &data),
            Event::Chunk(id, None) => {
                self.stream = None;
                self.session.stream_ended(now, id);
            }
            Event::Command(None) => return false,
            Event::Command(Some(Command::Forward {
                to,
                msg,
                traffic,
                at,
            })) => {
                self.session.forward(at, &to, &msg, traffic);
            }
            Event::Command(Some(Command::RefreshTurn)) => self.session.refresh_turn(now),
            Event::Command(Some(Command::Reconnect)) => self.session.reconnect(now),
        }
        true
    }
}

/// Keeps `link` registered until the engine drops its command channel.
pub(super) async fn run(link: Link, ch: Channels, target: Target, clock: Clock) {
    let session = SwitchSession::new(SessionConfig {
        host: link.host.clone(),
        node: link.node.clone(),
        network: link.network.clone(),
        trust: link.spec.auth.clone(),
        token: link.spec.token.clone(),
    });
    let mut d = Driver {
        link,
        target,
        ch,
        clock,
        session,
        rng: os_rng(),
        connecting: None,
        conn: None,
        running: None,
        queue: VecDeque::new(),
        opening: None,
        stream: None,
    };
    loop {
        while let Some(out) = d.session.poll() {
            d.apply(out).await;
        }
        if d.start_call() {
            continue;
        }
        let event = d.event().await;
        if !d.handle(event).await {
            return;
        }
    }
}
