use vardevall_proto::keys::SwitchSecret;
use vardevall_proto::sim::SimRng;

use super::*;
use crate::api::{RequestBinding, parse_register_request, switch_proofs};

const T0: u64 = 1_000_000;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

struct H {
    s: SwitchSession,
    rng: SimRng,
    now: Instant,
    sw: SwitchSecret,
    node: NodePublic,
    exporter: [u8; 32],
    stream: Option<CallId>,
    /// Every [`Out::Budget`] polled so far.
    budgets: Vec<Option<u64>>,
}

fn keys(seed: u64) -> Vec<NodePublic> {
    let mut rng = SimRng::new(seed);
    let mut v: Vec<NodePublic> = (0..4)
        .map(|_| NodeSecret::generate(&mut rng).public())
        .collect();
    v.sort();
    v
}

impl H {
    fn with(web: bool, token: Option<&str>) -> H {
        let mut rng = SimRng::new(7);
        let node = NodeSecret::generate(&mut rng);
        let network = NetworkSecret::generate(&mut rng);
        let sw = SwitchSecret::from_bytes([5; 32]);
        let trust = if web {
            SwitchAuth::Web {
                extra_roots: Vec::new(),
            }
        } else {
            SwitchAuth::Pinned(sw.public())
        };
        H {
            node: node.public(),
            s: SwitchSession::new(SessionConfig {
                host: "sw.example".to_owned(),
                node,
                network,
                trust,
                token: token.map(str::to_owned),
            }),
            rng,
            now: Instant::from_millis(T0),
            sw,
            exporter: [3; 32],
            stream: None,
            budgets: Vec::new(),
        }
    }

    fn pinned() -> H {
        H::with(false, None)
    }

    fn outs(&mut self) -> Vec<Out> {
        let outs: Vec<Out> = std::iter::from_fn(|| self.s.poll()).collect();
        self.budgets.extend(outs.iter().filter_map(|o| match o {
            Out::Budget(b) => Some(*b),
            _ => None,
        }));
        outs
    }

    fn at(&mut self, d: Duration) {
        self.now = self.now + d;
        self.s.handle_timeout(self.now);
    }

    fn wait(&self) -> Duration {
        self.s.poll_timeout().expect("a timer") - self.now
    }

    fn connect(&mut self) -> Vec<Out> {
        self.s.connected(self.now, self.exporter);
        self.outs()
    }

    fn answer(&mut self, id: CallId, status: u16, body: &str) -> Vec<Out> {
        self.s
            .response(self.now, &mut self.rng, id, status, None, body.as_bytes());
        self.outs()
    }

    fn fail(&mut self, id: CallId, e: LinkError) -> Vec<Out> {
        self.s.call_failed(self.now, &mut self.rng, id, e);
        self.outs()
    }

    fn data(&mut self, data: &str) -> Vec<Out> {
        let id = self.stream.expect("a stream");
        self.s
            .stream_data(self.now, &mut self.rng, id, data.as_bytes());
        self.outs()
    }

    fn info(&self, key: bool, binding: &str, extra: &str) -> String {
        let key = if key {
            format!(
                "\"key\":\"{}\",",
                base32::encode(self.sw.public().as_bytes())
            )
        } else {
            String::new()
        };
        format!(
            "{{\"versions\":[\"v0\"],{key}\"binding\":\"{binding}\",\"token_required\":false,\
             \"max_forward_size\":4096,\"stun\":[\"stun:s.example:3478\"],\"turn\":true{extra}}}"
        )
    }

    fn register_reply(&self, req: &HttpRequest, tamper: bool) -> String {
        let r = parse_register_request(req.body.as_ref().expect("a body").as_bytes()).unwrap();
        assert_eq!(r.node, self.node);
        assert_eq!(r.host, "sw.example");
        let binding = match r.binding {
            RequestBinding::Exporter => Binding::Exporter(self.exporter),
            RequestBinding::Challenge(c) => Binding::Challenge(c),
        };
        let b = bound_data(&binding, &r.host, &r.node, &r.network, &self.sw.public()).unwrap();
        let mut proof = switch_proofs(&self.sw, &r.node, &r.network, &b)
            .unwrap()
            .switch_proof;
        if tamper {
            proof[0] ^= 1;
        }
        format!(
            "{{\"session\":\"{}\",\"switch_proof\":\"{}\",\
             \"turn\":{{\"urls\":[\"turn:t.example\"],\"username\":\"u\",\"credential\":\"c\",\"ttl\":600}},\
             \"stun\":{{\"username\":\"su\",\"credential\":\"sc\",\"ttl\":400}}}}",
            base32::encode(&[9u8; 32]),
            base32::encode(&proof),
        )
    }

    /// Runs a pinned session from `connected` to the first listing page.
    fn list_first(&mut self, info_extra: &str) -> CallId {
        assert_eq!(
            self.outs(),
            vec![Out::State(SwitchState::Connecting), Out::Connect]
        );
        let (id, _) = call(&self.connect());
        let outs = self.answer(id, 200, &self.info(false, "exporter", info_extra));
        let (id, req) = call(&outs);
        let reply = self.register_reply(&req, false);
        let outs = self.answer(id, 200, &reply);
        let Some(Out::OpenStream { id, .. }) = outs.last() else {
            panic!("no stream request in {outs:?}");
        };
        self.stream = Some(*id);
        let id = *id;
        let outs = self.answer(id, 200, "");
        call(&outs).0
    }

    /// Runs a pinned session to `Up`, listing `pages` (JSON bodies).
    fn up(&mut self, pages: &[String]) -> Vec<Out> {
        let mut page = self.list_first("");
        let mut last = Vec::new();
        for body in pages {
            last = self.answer(page, 200, body);
            if let Some((id, _)) = try_call(&last) {
                page = id;
            }
        }
        last
    }
}

fn page(members: &[NodePublic], truncated: bool) -> String {
    let list: Vec<String> = members
        .iter()
        .map(|m| format!("{{\"node\":\"{m}\",\"online_since\":1,\"gen\":1}}"))
        .collect();
    format!(
        "{{\"members\":[{}],\"truncated\":{truncated}}}",
        list.join(",")
    )
}

fn try_call(outs: &[Out]) -> Option<(CallId, HttpRequest)> {
    outs.iter().find_map(|o| match o {
        Out::Call { id, req } => Some((*id, req.clone())),
        _ => None,
    })
}

fn call(outs: &[Out]) -> (CallId, HttpRequest) {
    try_call(outs).unwrap_or_else(|| panic!("no request in {outs:?}"))
}

fn presence(outs: &[Out]) -> Vec<(NodePublic, bool)> {
    outs.iter()
        .filter_map(|o| match o {
            Out::Presence { node, online } => Some((*node, *online)),
            _ => None,
        })
        .collect()
}

fn state(outs: &[Out]) -> Vec<SwitchState> {
    outs.iter()
        .filter_map(|o| match o {
            Out::State(s) => Some(*s),
            _ => None,
        })
        .collect()
}

fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.as_str())
}

fn within(d: Duration, base: u64) {
    let b = secs(base);
    assert!(
        d >= b - b / 4 && d <= b + b / 4,
        "{d:?} is not {base} s with 25 % jitter"
    );
}

#[test]
fn a_pinned_session_registers_opens_the_stream_and_lists() {
    let mut h = H::with(false, Some("tok"));
    assert_eq!(
        h.outs(),
        vec![Out::State(SwitchState::Connecting), Out::Connect]
    );
    let (id, req) = call(&h.connect());
    assert_eq!((req.method, req.path.as_str()), (Method::Get, "/v0/info"));

    let outs = h.answer(id, 200, &h.info(false, "exporter", ""));
    assert_eq!(
        outs[0],
        Out::Info {
            stun: vec!["stun:s.example:3478".to_owned()],
            stun_auth: false
        }
    );
    let (id, req) = call(&outs);
    assert_eq!(req.path, "/v0/register");
    assert_eq!(header(&req, "authorization"), Some("Bearer tok"));

    let reply = h.register_reply(&req, false);
    let outs = h.answer(id, 200, &reply);
    assert_eq!(outs[0], Out::Budget(None));
    assert!(matches!(&outs[1], Out::StunCredentials(c) if c.username == "su"));
    assert!(matches!(&outs[2], Out::TurnCredentials(c) if c.ttl == 600));
    let Out::OpenStream { id, req } = &outs[3] else {
        panic!("{outs:?}");
    };
    assert_eq!(req.path, "/v0/events");
    assert_eq!(
        header(req, "vv-session"),
        Some(base32::encode(&[9u8; 32]).as_str())
    );
    assert_eq!(header(req, "accept"), Some("text/event-stream"));
    h.stream = Some(*id);

    let outs = h.answer(*id, 200, "");
    let (list, req) = call(&outs);
    assert_eq!(req.path, "/v0/members");
    assert_eq!(
        header(&req, "vv-session"),
        Some(base32::encode(&[9u8; 32]).as_str())
    );

    let k = keys(1);
    let outs = h.answer(list, 200, &page(&k[..2], false));
    assert_eq!(
        outs,
        vec![
            Out::Presence {
                node: k[0],
                online: true
            },
            Out::Presence {
                node: k[1],
                online: true
            },
            Out::State(SwitchState::Registered),
        ]
    );
}

#[test]
fn a_pinned_switch_is_registered_even_if_info_fails() {
    let mut h = H::pinned();
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 500, "");
    assert_eq!(call(&outs).1.path, "/v0/register");
}

#[test]
fn a_web_session_binds_to_the_challenge_the_switch_asks_for() {
    let mut h = H::with(true, None);
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 200, &h.info(true, "challenge", ""));
    let (id, req) = call(&outs);
    assert_eq!(req.path, "/v0/challenge");
    let challenge = format!(
        "{{\"challenge\":\"{}\",\"expires_in\":60}}",
        base32::encode(&[4u8; 40])
    );
    let outs = h.answer(id, 200, &challenge);
    let (id, req) = call(&outs);
    assert_eq!(req.path, "/v0/register");
    assert!(
        req.body
            .as_ref()
            .unwrap()
            .contains("\"binding\":\"challenge\"")
    );
    assert!(req.headers.is_empty());
    let reply = h.register_reply(&req, false);
    let outs = h.answer(id, 200, &reply);
    assert!(outs.iter().any(|o| matches!(o, Out::OpenStream { .. })));
}

#[test]
fn a_web_session_with_the_exporter_binding_needs_no_challenge() {
    let mut h = H::with(true, None);
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 200, &h.info(true, "exporter", ""));
    let (id, req) = call(&outs);
    assert_eq!(req.path, "/v0/register");
    let reply = h.register_reply(&req, false);
    assert!(
        h.answer(id, 200, &reply)
            .iter()
            .any(|o| matches!(o, Out::OpenStream { .. }))
    );
}

#[test]
fn a_web_switch_that_names_no_key_is_untrusted_and_one_that_fails_info_is_a_protocol_error() {
    let mut h = H::with(true, None);
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 200, &h.info(false, "exporter", ""));
    assert_eq!(
        state(&outs),
        vec![SwitchState::Disconnected(SwitchFailure::Untrusted)]
    );
    assert!(outs.contains(&Out::Close));
    within(h.wait(), 30);

    let mut h = H::with(true, None);
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 500, "");
    assert_eq!(
        state(&outs),
        vec![SwitchState::Disconnected(SwitchFailure::Protocol)]
    );
}

#[test]
fn a_bad_switch_proof_is_untrusted_and_opens_no_stream() {
    let mut h = H::pinned();
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 200, &h.info(false, "exporter", ""));
    let (id, req) = call(&outs);
    let reply = h.register_reply(&req, true);
    let outs = h.answer(id, 200, &reply);
    assert_eq!(
        state(&outs),
        vec![SwitchState::Disconnected(SwitchFailure::Untrusted)]
    );
    assert!(!outs.iter().any(|o| matches!(o, Out::OpenStream { .. })));
    assert!(
        !outs
            .iter()
            .any(|o| matches!(o, Out::TurnCredentials(_) | Out::StunCredentials(_)))
    );
    within(h.wait(), 30);
}

#[test]
fn registration_failures_map_to_their_causes() {
    let cases: [(u16, &str, SwitchFailure); 4] = [
        (
            401,
            "{\"type\":\"urn:vardevall:error:token-required\"}",
            SwitchFailure::TokenRejected,
        ),
        (403, "", SwitchFailure::Rejected),
        (401, "", SwitchFailure::Protocol),
        (500, "", SwitchFailure::Protocol),
    ];
    for (status, body, failure) in cases {
        let mut h = H::pinned();
        h.outs();
        let (id, _) = call(&h.connect());
        let outs = h.answer(id, 200, &h.info(false, "exporter", ""));
        let (id, _) = call(&outs);
        let outs = h.answer(id, status, body);
        assert_eq!(
            state(&outs),
            vec![SwitchState::Disconnected(failure)],
            "{status}"
        );
    }
}

#[test]
fn rate_limiting_waits_for_retry_after_capped_at_five_minutes() {
    let mut h = H::pinned();
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 200, &h.info(false, "exporter", ""));
    let (id, _) = call(&outs);
    h.s.response(h.now, &mut h.rng, id, 429, Some(7200), b"");
    assert_eq!(
        state(&h.outs()),
        vec![SwitchState::Disconnected(SwitchFailure::RateLimited)]
    );
    within(h.wait(), 300);

    let mut h = H::pinned();
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 200, &h.info(false, "exporter", ""));
    let (id, _) = call(&outs);
    h.s.response(h.now, &mut h.rng, id, 429, None, b"");
    h.outs();
    within(h.wait(), 1);
}

#[test]
fn a_session_that_the_switch_does_not_know_registers_again() {
    let mut h = H::pinned();
    let k = keys(2);
    h.up(&[page(&k[..1], false)]);
    h.at(secs(10));
    h.s.refresh_turn(h.now);
    let (id, req) = call(&h.outs());
    assert_eq!(req.path, "/v0/turn");
    let outs = h.answer(id, 401, "");
    assert!(outs.contains(&Out::Close));
    assert_eq!(presence(&outs), vec![(k[0], false)]);
    assert!(state(&outs).is_empty(), "the state stays Registered");
    assert_eq!(h.wait(), RESUME_DELAY);

    h.at(RESUME_DELAY);
    assert_eq!(
        h.outs(),
        vec![Out::State(SwitchState::Connecting), Out::Connect]
    );
    let outs = h.connect();
    let (id, _) = call(&outs);
    let outs = h.answer(id, 200, &h.info(false, "exporter", ""));
    assert_eq!(call(&outs).1.path, "/v0/register");
}

#[test]
fn a_401_on_a_forward_or_the_stream_registers_again_too() {
    let mut h = H::pinned();
    h.up(&[page(&[], false)]);
    let to = keys(3)[0];
    assert!(h.s.forward(h.now, &to, b"hello", Traffic::Data));
    let (id, req) = call(&h.outs());
    assert_eq!(req.path, "/v0/forward");
    assert!(req.body.as_ref().unwrap().contains(&to.to_string()));
    let outs = h.answer(id, 401, "");
    assert!(outs.contains(&Out::Close));
    h.at(RESUME_DELAY);
    h.outs();
    let (id, _) = call(&h.connect());
    assert_eq!(
        call(&h.answer(id, 200, &h.info(false, "exporter", "")))
            .1
            .path,
        "/v0/register"
    );

    let mut h = H::pinned();
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 200, &h.info(false, "exporter", ""));
    let (id, req) = call(&outs);
    let reply = h.register_reply(&req, false);
    let outs = h.answer(id, 200, &reply);
    let Some(Out::OpenStream { id, .. }) = outs.last() else {
        panic!()
    };
    let outs = h.answer(*id, 401, "");
    assert!(outs.contains(&Out::Close));
    h.at(RESUME_DELAY);
    h.outs();
    let (id, _) = call(&h.connect());
    assert_eq!(
        call(&h.answer(id, 200, &h.info(false, "exporter", "")))
            .1
            .path,
        "/v0/register"
    );
}

#[test]
fn replaced_ends_the_session_for_a_minute_and_registers_again() {
    let mut h = H::pinned();
    let k = keys(4);
    h.up(&[page(&k[..2], false)]);
    let outs = h.data("event: replaced\ndata: {}\n\n");
    assert_eq!(presence(&outs), vec![(k[0], false), (k[1], false)]);
    assert_eq!(
        state(&outs),
        vec![SwitchState::Disconnected(SwitchFailure::Replaced)]
    );
    assert!(outs.contains(&Out::Close));
    within(h.wait(), 60);

    let wait = h.wait();
    h.at(wait);
    h.outs();
    let (id, _) = call(&h.connect());
    assert_eq!(
        call(&h.answer(id, 200, &h.info(false, "exporter", "")))
            .1
            .path,
        "/v0/register"
    );
}

#[test]
fn failed_attempts_back_off_from_one_second_to_a_minute_with_jitter() {
    let run = |seed: u64| -> Vec<Duration> {
        let mut h = H::pinned();
        h.rng = SimRng::new(seed);
        h.outs();
        let mut waits = Vec::new();
        for i in 0..9 {
            h.s.connect_failed(h.now, &mut h.rng, LinkError::Unreachable);
            let outs = h.outs();
            assert_eq!(
                state(&outs),
                vec![SwitchState::Disconnected(SwitchFailure::Unreachable)],
                "attempt {i}"
            );
            waits.push(h.wait());
            assert_eq!(h.s.reconnect_at(), h.s.poll_timeout());
            let w = h.wait();
            h.at(w);
            assert_eq!(
                h.outs(),
                vec![Out::State(SwitchState::Connecting), Out::Connect]
            );
            assert_eq!(h.s.reconnect_at(), None);
        }
        waits
    };
    let a = run(11);
    for (w, base) in a.iter().zip([1, 2, 4, 8, 16, 32, 60, 60, 60]) {
        within(*w, base);
    }
    assert_eq!(a, run(11), "the same seed gives the same waits");
    assert_ne!(a, run(12));
}

#[test]
fn reaching_registered_starts_the_backoff_over() {
    let mut h = H::pinned();
    h.outs();
    for _ in 0..3 {
        h.s.connect_failed(h.now, &mut h.rng, LinkError::Unreachable);
        let w = h.wait();
        h.at(w);
    }
    h.outs();
    h.s.connect_failed(h.now, &mut h.rng, LinkError::Unreachable);
    within(h.wait(), 8);
    let w = h.wait();
    h.at(w);
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 200, &h.info(false, "exporter", ""));
    let (id, req) = call(&outs);
    let reply = h.register_reply(&req, false);
    let outs = h.answer(id, 200, &reply);
    let Some(Out::OpenStream { id, .. }) = outs.last() else {
        panic!()
    };
    h.stream = Some(*id);
    let outs = h.answer(*id, 200, "");
    h.answer(call(&outs).0, 200, &page(&[], false));
    let id = h.stream.unwrap();
    h.s.stream_ended(h.now, id);
    h.outs();
    h.at(RESUME_DELAY);
    h.outs();
    h.s.connect_failed(h.now, &mut h.rng, LinkError::Unreachable);
    within(h.wait(), 1);
}

#[test]
fn an_untrusted_or_oversize_failure_waits_a_fixed_time() {
    let mut h = H::pinned();
    h.outs();
    h.s.connect_failed(h.now, &mut h.rng, LinkError::Untrusted);
    assert_eq!(
        state(&h.outs()),
        vec![SwitchState::Disconnected(SwitchFailure::Untrusted)]
    );
    within(h.wait(), 30);
}

#[test]
fn a_path_change_ends_a_backoff_but_not_a_fixed_wait() {
    let mut h = H::pinned();
    h.outs();
    h.s.connect_failed(h.now, &mut h.rng, LinkError::Unreachable);
    h.outs();
    h.s.reconnect(h.now);
    assert_eq!(
        h.outs(),
        vec![Out::State(SwitchState::Connecting), Out::Connect]
    );

    h.s.connect_failed(h.now, &mut h.rng, LinkError::Untrusted);
    h.outs();
    h.s.reconnect(h.now);
    assert_eq!(h.outs(), vec![]);
    assert!(h.wait() > secs(20));
}

#[test]
fn a_path_change_on_a_registered_session_resumes_it() {
    let mut h = H::pinned();
    let k = keys(5);
    h.up(&[page(&k[..1], false)]);
    h.s.reconnect(h.now);
    let outs = h.outs();
    assert_eq!(
        outs,
        vec![
            Out::Close,
            Out::Presence {
                node: k[0],
                online: false
            }
        ]
    );
    assert_eq!(h.wait(), RESUME_DELAY);
    h.at(RESUME_DELAY);
    assert_eq!(
        h.outs(),
        vec![Out::State(SwitchState::Connecting), Out::Connect]
    );
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 200, &h.info(false, "exporter", ""));
    assert!(
        matches!(outs.last(), Some(Out::OpenStream { .. })),
        "the registration is kept: {outs:?}"
    );
}

#[test]
fn a_silent_stream_is_dropped_after_forty_five_seconds() {
    let mut h = H::pinned();
    let k = keys(6);
    h.up(&[page(&k[..1], false)]);
    assert_eq!(h.wait(), STREAM_IDLE);
    h.at(secs(44));
    assert!(h.outs().is_empty());
    assert!(h.data(": keep-alive\n\n").is_empty());
    h.at(secs(44));
    assert!(h.outs().is_empty(), "the data moved the deadline");
    h.at(secs(1));
    let outs = h.outs();
    assert_eq!(
        outs,
        vec![
            Out::Close,
            Out::Presence {
                node: k[0],
                online: false
            }
        ]
    );
    assert_eq!(h.wait(), RESUME_DELAY);
}

#[test]
fn a_stream_that_ends_resumes_without_a_failure() {
    let mut h = H::pinned();
    h.up(&[page(&[], false)]);
    let id = h.stream.unwrap();
    h.s.stream_ended(h.now, id);
    assert_eq!(h.outs(), vec![Out::Close]);
    assert_eq!(h.wait(), RESUME_DELAY);
}

#[test]
fn a_long_listing_is_read_page_by_page_and_reaches_registered_at_the_end() {
    let mut h = H::pinned();
    let k = keys(7);
    let first = h.list_first("");
    let outs = h.answer(first, 200, &page(&k[..2], true));
    assert!(state(&outs).is_empty());
    assert!(presence(&outs).is_empty());
    let (second, req) = call(&outs);
    assert_eq!(req.path, format!("/v0/members?after={}", k[1]));
    let outs = h.answer(second, 200, &page(&k[2..], false));
    assert_eq!(
        outs,
        vec![
            Out::Presence {
                node: k[0],
                online: true
            },
            Out::Presence {
                node: k[1],
                online: true
            },
            Out::Presence {
                node: k[2],
                online: true
            },
            Out::Presence {
                node: k[3],
                online: true
            },
            Out::State(SwitchState::Registered),
        ]
    );
}

#[test]
fn a_truncated_page_without_members_is_a_protocol_error() {
    let mut h = H::pinned();
    let first = h.list_first("");
    let outs = h.answer(first, 200, &page(&[], true));
    assert_eq!(
        state(&outs),
        vec![SwitchState::Disconnected(SwitchFailure::Protocol)]
    );
}

#[test]
fn presence_follows_the_events() {
    let mut h = H::pinned();
    let k = keys(8);
    h.up(&[page(&k[..1], false)]);
    let ev = format!(
        "event: online\ndata: {{\"node\":\"{}\",\"gen\":1}}\n\n",
        k[1]
    );
    assert_eq!(
        h.data(&ev),
        vec![Out::Presence {
            node: k[1],
            online: true
        }]
    );
    let ev = format!(
        "event: offline\ndata: {{\"node\":\"{}\",\"gen\":1}}\n\n",
        k[0]
    );
    assert_eq!(
        h.data(&ev),
        vec![Out::Presence {
            node: k[0],
            online: false
        }]
    );
    let ev = format!(
        "event: forward\ndata: {{\"from\":\"{}\",\"msg\":\"{}\"}}\n\nevent: future\ndata: {{}}\n\n",
        k[2],
        base32::encode(b"pkt")
    );
    assert_eq!(
        h.data(&ev),
        vec![Out::Forwarded {
            from: k[2],
            msg: b"pkt".to_vec()
        }]
    );
}

#[test]
fn events_that_arrive_while_listing_count_but_are_announced_once_up() {
    let mut h = H::pinned();
    let k = keys(9);
    let list = h.list_first("");
    let ev = format!(
        "event: online\ndata: {{\"node\":\"{}\",\"gen\":1}}\n\n",
        k[1]
    );
    assert!(h.data(&ev).is_empty());
    let outs = h.answer(list, 200, &page(&k[..1], false));
    assert_eq!(
        outs,
        vec![
            Out::Presence {
                node: k[0],
                online: true
            },
            Out::Presence {
                node: k[1],
                online: true
            },
            Out::State(SwitchState::Registered),
        ]
    );
}

#[test]
fn a_garbled_stream_is_a_protocol_error() {
    let mut h = H::pinned();
    h.up(&[page(&[], false)]);
    let junk = "x".repeat(40 * 1024);
    let outs = h.data(&junk);
    assert_eq!(
        state(&outs),
        vec![SwitchState::Disconnected(SwitchFailure::Protocol)]
    );
}

fn turn_call(outs: &[Out]) -> Option<(CallId, HttpRequest)> {
    outs.iter().find_map(|o| match o {
        Out::Call { id, req } if req.path == "/v0/turn" => Some((*id, req.clone())),
        _ => None,
    })
}

fn turn_json(ttl: u64) -> String {
    format!(
        "{{\"urls\":[\"turn:t.example\"],\"username\":\"u2\",\"credential\":\"c2\",\"ttl\":{ttl}}}"
    )
}

/// Moves time on in steps of 30 s with keep-alives until `target` after `start`.
fn run_until(h: &mut H, start: Instant, target: Duration) -> Vec<Out> {
    let mut outs = Vec::new();
    while h.now < start + target {
        let step = (start + target - h.now).min(secs(30));
        h.at(step);
        outs.extend(h.outs());
        outs.extend(h.data(": ka\n\n"));
    }
    outs
}

#[test]
fn credentials_are_refreshed_halfway_through_their_ttl() {
    let mut h = H::pinned();
    h.up(&[page(&[], false)]);
    let start = h.now;
    let outs = run_until(&mut h, start, secs(299));
    assert!(turn_call(&outs).is_none());
    let outs = run_until(&mut h, start, secs(300));
    let (id, req) = turn_call(&outs).expect("a turn request");
    assert_eq!((req.method, req.path.as_str()), (Method::Post, "/v0/turn"));
    assert!(header(&req, "vv-session").is_some());
    let outs = h.answer(id, 200, &turn_json(100));
    assert!(matches!(&outs[..], [Out::TurnCredentials(c)] if c.username == "u2"));
    let again = h.now;
    assert!(turn_call(&run_until(&mut h, again, secs(49))).is_none());
    let outs = run_until(&mut h, again, secs(50));
    assert_eq!(turn_call(&outs).expect("a turn request").1.path, "/v0/turn");
}

#[test]
fn stun_credentials_are_refreshed_halfway_through_their_ttl() {
    let mut h = H::pinned();
    h.up(&[page(&[], false)]);
    let start = h.now;
    let outs = run_until(&mut h, start, secs(200));
    let calls: Vec<_> = outs
        .iter()
        .filter_map(|o| match o {
            Out::Call { id, req } => Some((*id, req.path.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, "/v0/stun");
    let body = "{\"username\":\"su2\",\"credential\":\"sc2\",\"ttl\":60}";
    let outs = h.answer(calls[0].0, 200, body);
    assert!(matches!(&outs[..], [Out::StunCredentials(c)] if c.username == "su2"));
}

#[test]
fn a_failed_refresh_is_retried_every_thirty_seconds_and_a_404_stops_it() {
    let mut h = H::pinned();
    h.up(&[page(&[], false)]);
    let start = h.now;
    let outs = run_until(&mut h, start, secs(300));
    let (id, _) = turn_call(&outs).expect("a turn request");
    assert!(h.answer(id, 500, "").is_empty());
    let failed = h.now;
    assert!(turn_call(&run_until(&mut h, failed, secs(29))).is_none());
    let outs = run_until(&mut h, failed, secs(30));
    let (id, _) = turn_call(&outs).expect("a turn request");
    assert!(h.answer(id, 404, "").is_empty());
    let found = h.now;
    assert!(turn_call(&run_until(&mut h, found, secs(3600))).is_none());
}

#[test]
fn a_refresh_that_fails_to_reach_the_switch_resumes() {
    let mut h = H::pinned();
    h.up(&[page(&[], false)]);
    h.s.refresh_turn(h.now);
    let (id, _) = call(&h.outs());
    let outs = h.fail(id, LinkError::Unreachable);
    assert_eq!(outs, vec![Out::Close]);
    assert_eq!(h.wait(), RESUME_DELAY);
}

#[test]
fn a_turn_refresh_asked_before_the_session_is_up_runs_once_it_is() {
    let mut h = H::pinned();
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 200, &h.info(false, "exporter", ""));
    let (id, req) = call(&outs);
    let reply = h.register_reply(&req, false);
    h.answer(id, 200, &reply);
    h.s.refresh_turn(h.now);
    h.s.reconnect(h.now);
    h.outs();
    h.at(RESUME_DELAY);
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(id, 200, &h.info(false, "exporter", ""));
    let Some(Out::OpenStream { id, .. }) = outs.last() else {
        panic!("{outs:?}");
    };
    h.stream = Some(*id);
    let list = call(&h.answer(*id, 200, "")).0;
    let outs = h.answer(list, 200, &page(&[], false));
    assert_eq!(state(&outs), vec![SwitchState::Registered]);
    h.at(Duration::ZERO);
    let (_, req) = call(&h.outs());
    assert_eq!(req.path, "/v0/turn");
}

#[test]
fn the_rate_of_the_switch_paces_forwarding() {
    let mut h = H::pinned();
    let to = keys(10)[0];
    assert!(
        !h.s.forward(h.now, &to, b"early", Traffic::Signal),
        "not up"
    );
    let list = h.list_first(",\"forward_limits\":{\"bits_per_second\":64000}");
    h.answer(list, 200, &page(&[], false));
    assert!(h.s.forward(h.now, &to, &[0; 4000], Traffic::Data));
    assert!(h.s.forward(h.now, &to, &[0; 4000], Traffic::Data));
    assert!(
        !h.s.forward(h.now, &to, &[0; 1200], Traffic::Data),
        "the burst is used up"
    );
    assert!(
        h.s.forward(h.now, &to, &[0; 100], Traffic::Signal),
        "signals go regardless"
    );
    assert!(!h.s.forward(h.now, &to, &vec![0; MAX_FORWARD + 1], Traffic::Signal));
    let calls = h
        .outs()
        .into_iter()
        .filter(|o| matches!(o, Out::Call { req, .. } if req.path == "/v0/forward"))
        .count();
    assert_eq!(calls, 3);
}

#[test]
fn the_volume_of_the_switch_does_not_stop_forwarding() {
    let mut h = H::pinned();
    let to = keys(10)[0];
    let list = h.list_first(",\"forward_limits\":{\"bytes\":1000}");
    h.answer(list, 200, &page(&[], false));
    for _ in 0..3 {
        assert!(h.s.forward(h.now, &to, &[0; 900], Traffic::Data));
    }
}

#[test]
fn a_new_registration_reports_the_volume_of_the_switch_again() {
    let mut h = H::pinned();
    let list = h.list_first(",\"forward_limits\":{\"bytes\":1000}");
    h.answer(list, 200, &page(&[], false));
    assert_eq!(h.budgets, [Some(1000)]);
    h.data("event: replaced\ndata: {}\n\n");
    let w = h.wait();
    h.at(w);
    h.outs();
    let (id, _) = call(&h.connect());
    let info = h.info(false, "exporter", ",\"forward_limits\":{\"bytes\":1000}");
    let outs = h.answer(id, 200, &info);
    let (id, req) = call(&outs);
    let reply = h.register_reply(&req, false);
    let outs = h.answer(id, 200, &reply);
    let Some(Out::OpenStream { id, .. }) = outs.last() else {
        panic!()
    };
    h.stream = Some(*id);
    let outs = h.answer(*id, 200, "");
    h.answer(call(&outs).0, 200, &page(&[], false));
    assert_eq!(h.budgets, [Some(1000), Some(1000)]);
}

#[test]
fn a_registration_without_a_volume_reports_none() {
    let mut h = H::pinned();
    h.list_first("");
    assert_eq!(h.budgets, [None]);
}

#[test]
fn the_registration_states_the_volume_the_info_advertises_over_a_limit_without_bytes() {
    let mut h = H::pinned();
    h.list_first(",\"forward_limits\":{\"bits_per_second\":8000}");
    assert_eq!(h.budgets, [None]);
}

#[test]
fn a_resumed_session_reports_no_budget() {
    let mut h = H::pinned();
    let list = h.list_first(",\"forward_limits\":{\"bytes\":1000}");
    h.answer(list, 200, &page(&[], false));
    assert_eq!(h.budgets, [Some(1000)]);
    h.s.reconnect(h.now);
    h.outs();
    h.at(RESUME_DELAY);
    h.outs();
    let (id, _) = call(&h.connect());
    let outs = h.answer(
        id,
        200,
        &h.info(false, "exporter", ",\"forward_limits\":{\"bytes\":1000}"),
    );
    let Some(Out::OpenStream { id, .. }) = outs.last() else {
        panic!("{outs:?}");
    };
    h.stream = Some(*id);
    let list = call(&h.answer(*id, 200, "")).0;
    let outs = h.answer(list, 200, &page(&[], false));
    assert_eq!(state(&outs), vec![SwitchState::Registered]);
    assert_eq!(h.budgets, [Some(1000)], "the same session keeps its count");
}

#[test]
fn a_connection_that_never_trusts_the_switch_reports_it() {
    let mut h = H::pinned();
    h.outs();
    h.s.connect_failed(h.now, &mut h.rng, LinkError::Untrusted);
    assert!(h.outs().contains(&Out::State(SwitchState::Disconnected(
        SwitchFailure::Untrusted
    ))));
    let w = h.wait();
    h.at(w);
    assert_eq!(
        h.outs(),
        vec![Out::State(SwitchState::Connecting), Out::Connect]
    );
}
