//! The JSON the Swift apps read and write is a contract (`apple/include/vardevall.h`): these tests
//! pin its content. The order of members is not part of it, and a document that is malformed is
//! only required to fail.

use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use vardevall::view::{
    ExitSite, Local, Nat, Peer, PeerNat, PeerRoute, Relay, Route, RouteNext, Switch, Transport,
    View,
};
use vardevall::{
    Budget, BudgetSource, LogLevel, MdnsEvent, MdnsRequest, Meter, PeerState, Reason,
    SwitchFailure, SwitchId, SwitchState, Trust,
};
use vardevall_proto::discovery::candidate::Candidate;
use vardevall_proto::ip::exit::SitePeer;
use vardevall_proto::ip::site::Site;
use vardevall_proto::keys::NodePublic;
use vardevall_proto::route::Status as RouteStatus;
use vardevall_tun::embed::{
    Event, Status, SwitchKind, event_from_json, path_update_from_json, request_to_json,
};

fn key(n: u8) -> NodePublic {
    NodePublic::from_bytes([n; 32])
}

fn addr() -> Ipv6Addr {
    "fd00::1".parse().unwrap()
}

fn sock(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn budget(total: u64, spent: usize, source: BudgetSource) -> Budget {
    let mut b = Budget::new(total, source, true);
    b.spend(spent);
    b
}

const FAILURES: [SwitchFailure; 7] = [
    SwitchFailure::Unreachable,
    SwitchFailure::Untrusted,
    SwitchFailure::TokenRejected,
    SwitchFailure::Rejected,
    SwitchFailure::RateLimited,
    SwitchFailure::Replaced,
    SwitchFailure::Protocol,
];

fn switch_states() -> Vec<SwitchState> {
    let mut v = vec![SwitchState::Connecting, SwitchState::Registered];
    v.extend(FAILURES.map(SwitchState::Disconnected));
    v
}

fn routes() -> [Route; 5] {
    [
        Route::Lan(sock("192.168.1.2:7")),
        Route::Internet(sock("[2001:db8::1]:51820")),
        Route::PeerRelay(sock("84.46.243.47:49297")),
        Route::OwnRelay(sock("109.53.226.37:32298")),
        Route::Switch(SwitchId(3)),
    ]
}

fn states() -> [PeerState; 6] {
    [
        PeerState::Idle,
        PeerState::Connecting,
        PeerState::Up { initiator: true },
        PeerState::Up { initiator: false },
        PeerState::Down(Reason::Idle),
        PeerState::Down(Reason::Unreachable),
    ]
}

fn budgets() -> [Budget; 4] {
    [
        budget(1000, 0, BudgetSource::Reported),
        budget(1000, 600, BudgetSource::Relay),
        budget(1000, 950, BudgetSource::Reported),
        budget(1000, 1000, BudgetSource::Relay),
    ]
}

fn nat_local(v6: Nat, v4: Nat, relay: Option<Relay>) -> Local {
    Local {
        v6,
        v4,
        relay,
        switches: Vec::new(),
        transports: Vec::new(),
    }
}

fn view_peer(n: u8, state: PeerState, route: Option<Route>) -> Peer {
    Peer {
        peer: key(n),
        state,
        route,
        metered: false,
        degraded: false,
        nat: PeerNat::Unknown,
        candidates: Vec::new(),
        switches: Vec::new(),
        probing: false,
        fallback: false,
        meter: None,
        rtt: None,
        routes: Vec::new(),
    }
}

/// Every event type and every variant of each nested enum, in a fixed order.
fn events() -> Vec<Event> {
    let (k, a) = (key(1), addr());
    let mut out = vec![
        Event::Status(Status::Started { listen_port: 51820 }),
        Event::Status(Status::Started { listen_port: 0 }),
        Event::Status(Status::Stopped),
    ];
    for trust in [Trust::Key, Trust::Member] {
        out.push(Event::Added {
            key: k,
            addr: a,
            name: Some("nas".into()),
            trust,
        });
        out.push(Event::Added {
            key: k,
            addr: a,
            name: None,
            trust,
        });
    }
    out.push(Event::Removed {
        key: k,
        addr: a,
        name: Some("ñandú \"q\"".into()),
    });
    out.push(Event::Removed {
        key: k,
        addr: a,
        name: None,
    });
    for state in states() {
        out.push(Event::Peer {
            key: k,
            addr: a,
            name: Some("nas".into()),
            state,
        });
    }
    out.push(Event::Peer {
        key: k,
        addr: a,
        name: None,
        state: PeerState::Up { initiator: true },
    });
    for route in routes() {
        out.push(Event::Route {
            key: k,
            addr: a,
            name: Some("nas".into()),
            route: Some(route),
        });
    }
    out.push(Event::Route {
        key: k,
        addr: a,
        name: None,
        route: None,
    });
    for kind in [SwitchKind::Pinned, SwitchKind::Web] {
        for state in switch_states() {
            out.push(Event::Switch {
                address: "sw.example.org:443".into(),
                kind,
                state,
            });
        }
    }
    for b in budgets() {
        out.push(Event::Budget {
            transport: "udp".into(),
            budget: Some(b),
        });
    }
    out.push(Event::Budget {
        transport: "sw.example:4455".into(),
        budget: None,
    });
    out.push(Event::Budget {
        transport: "turn".into(),
        budget: None,
    });
    for level in [
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
    ] {
        out.push(Event::Log {
            level,
            message: "plain".into(),
        });
    }
    out.push(Event::Log {
        level: LogLevel::Info,
        message: "a\"b\\c\nd\u{1}é☃ </script> \u{7f}".into(),
    });
    out.push(Event::Log {
        level: LogLevel::Error,
        message: String::new(),
    });
    out.push(Event::Exit {
        site: "it/home".parse().unwrap(),
        via: Some(k),
        addr: "fd00:0:0:1::1".parse().unwrap(),
        ipv4: Some("198.18.3.4".parse().unwrap()),
    });
    out.push(Event::Exit {
        site: "de".parse().unwrap(),
        via: None,
        addr: "fd00:0:0:1::1".parse().unwrap(),
        ipv4: None,
    });
    out.push(Event::Exits {
        offers: vec![(k, "it/home".parse().unwrap())],
    });
    out
}

fn views() -> Vec<Event> {
    let mut out = Vec::new();

    let mut local = nat_local(Nat::Unknown, Nat::Unknown, None);
    out.push(Event::View {
        view: View {
            local: local.clone(),
            peers: Vec::new(),
            sites: Vec::new(),
        },
        peers: Vec::new(),
        switches: Vec::new(),
        exit: None,
    });

    for (v6, v4) in [
        (Nat::Unknown, Nat::Symmetric),
        (Nat::Blocked, Nat::Punchable(sock("193.205.81.9:51820"))),
        (Nat::Punchable(sock("[2001:db8::2]:4000")), Nat::Blocked),
    ] {
        for relay in [
            None,
            Some(Relay {
                addr: sock("84.46.243.47:49297"),
                server: sock("84.46.243.47:4455"),
                tls: true,
            }),
            Some(Relay {
                addr: sock("[2001:db8::9]:49297"),
                server: sock("[2001:db8::a]:4455"),
                tls: false,
            }),
        ] {
            out.push(Event::View {
                view: View {
                    local: nat_local(v6, v4, relay),
                    peers: Vec::new(),
                    sites: Vec::new(),
                },
                peers: Vec::new(),
                switches: Vec::new(),
                exit: None,
            });
        }
    }

    local.switches = switch_states()
        .into_iter()
        .enumerate()
        .map(|(i, state)| Switch {
            id: SwitchId(i as u32),
            address: format!("sw{i}.example:4455"),
            state,
            transport: [None, Some("http3"), Some("http2"), Some("http1")][i % 4],
            retry_at: matches!(state, SwitchState::Disconnected(_)).then(passed),
        })
        .collect();
    let kinds = (0..local.switches.len())
        .map(|i| {
            if i % 2 == 0 {
                SwitchKind::Pinned
            } else {
                SwitchKind::Web
            }
        })
        .collect();
    out.push(Event::View {
        view: View {
            local: local.clone(),
            peers: Vec::new(),
            sites: Vec::new(),
        },
        peers: Vec::new(),
        switches: kinds,
        exit: None,
    });

    local.transports = vec![
        Transport {
            name: "udp".into(),
            usable: true,
            meter: Meter {
                sent: 10,
                received: 20,
            },
            budget: None,
        },
        Transport {
            name: "turn".into(),
            usable: false,
            meter: Meter::default(),
            budget: Some(budget(1000, 1000, BudgetSource::Relay)),
        },
        Transport {
            name: "sw0.example:4455".into(),
            usable: true,
            meter: Meter {
                sent: u64::MAX,
                received: 1,
            },
            budget: Some(budget(1 << 40, 5, BudgetSource::Reported)),
        },
    ];
    for b in budgets() {
        local.transports.push(Transport {
            name: "level".into(),
            usable: !b.exhausted(),
            meter: Meter::default(),
            budget: Some(b),
        });
    }

    let ula = |n: u16| format!("fd00::{n:x}").parse::<Ipv6Addr>().unwrap();
    let mut peers = Vec::new();
    let mut names = Vec::new();
    for (i, state) in states().into_iter().enumerate() {
        peers.push(view_peer(10 + i as u8, state, None));
        names.push((ula(10 + i as u16), None));
    }
    for (i, route) in routes().into_iter().enumerate() {
        let mut p = view_peer(20 + i as u8, PeerState::Up { initiator: true }, Some(route));
        p.metered = route.metered();
        p.degraded = i % 2 == 1;
        p.nat = [PeerNat::Unknown, PeerNat::Punchable, PeerNat::RelayOnly][i % 3];
        p.meter = Some(Meter {
            sent: i as u64,
            received: 100 + i as u64,
        });
        peers.push(p);
        names.push((ula(20 + i as u16), Some(format!("peer{i}"))));
    }
    let mut full = view_peer(30, PeerState::Up { initiator: false }, Some(routes()[3]));
    full.metered = true;
    full.nat = PeerNat::Punchable;
    full.candidates = vec![
        Candidate::same_host(sock("127.0.0.1:1")),
        Candidate::lan(sock("192.168.1.2:2")),
        Candidate::static_(sock("203.0.113.5:3")),
        Candidate::static_local(sock("10.0.0.5:4")),
        Candidate::punch(sock("109.53.226.37:32298")),
        Candidate::relay(sock("[2001:db8::7]:5")),
        Candidate::lan(sock("192.168.2.2:6")).with_metered(true),
    ];
    full.switches = vec![SwitchId(0), SwitchId(2)];
    full.probing = true;
    full.fallback = true;
    full.meter = Some(Meter {
        sent: 3,
        received: 4,
    });
    peers.push(full);
    names.push((ula(30), Some("iphone".into())));
    let kinds = vec![SwitchKind::Web; local.switches.len()];
    let site: Site = "it/home".parse().unwrap();
    out.push(Event::View {
        view: View {
            local,
            peers,
            sites: vec![ExitSite {
                site: site.clone(),
                peers: vec![
                    SitePeer {
                        peer: key(1),
                        live: true,
                    },
                    SitePeer {
                        peer: key(2),
                        live: false,
                    },
                ],
                chosen: Some(key(1)),
                addr: "fd00:0:0:1::1".parse().unwrap(),
            }],
        },
        peers: names,
        switches: kinds,
        exit: Some((site, key(1))),
    });

    let mut traced = view_peer(40, PeerState::Up { initiator: true }, Some(routes()[1]));
    traced.rtt = Some(Duration::from_millis(12));
    traced.routes = vec![
        PeerRoute {
            route: routes()[1],
            status: RouteStatus::Verified,
            rtt: Some(Duration::from_millis(12)),
            active: true,
            metered: false,
            next: None,
        },
        PeerRoute {
            route: routes()[2],
            status: RouteStatus::Failed,
            rtt: None,
            active: false,
            metered: true,
            next: Some(RouteNext::Retry(passed())),
        },
        PeerRoute {
            route: routes()[4],
            status: RouteStatus::Dormant,
            rtt: Some(Duration::ZERO),
            active: false,
            metered: true,
            next: Some(RouteNext::Forget(passed())),
        },
    ];
    out.push(Event::View {
        view: View {
            local: nat_local(Nat::Unknown, Nat::Unknown, None),
            peers: vec![traced],
            sites: Vec::new(),
        },
        peers: vec![(ula(40), Some("laptop".into()))],
        switches: Vec::new(),
        exit: None,
    });
    out
}

/// An instant already past, which the JSON gives as 0 ms to go.
fn passed() -> tokio::time::Instant {
    tokio::time::Instant::now() - Duration::from_secs(1)
}

fn value(json: &str) -> serde_json::Value {
    serde_json::from_str(json).unwrap()
}

/// The JSON of an event of network `home`, which is what `EVENTS` lists plus that member.
fn expected(json: &str) -> serde_json::Value {
    let mut v = value(json);
    v["network"] = "home".into();
    v
}

fn all_events() -> Vec<Event> {
    let mut all = events();
    all.extend(views());
    all
}

#[test]
fn events_render_as_before() {
    let all = all_events();
    assert_eq!(all.len(), EVENTS.len());
    for (i, (event, json)) in all.iter().zip(EVENTS).enumerate() {
        assert_eq!(value(&event.to_json("home")), expected(json), "event {i}");
    }
}

fn mdns_requests() -> Vec<MdnsRequest> {
    vec![
        MdnsRequest::Register {
            instance: "abc".into(),
            service_type: "_vardevall._udp".into(),
            port: 51820,
            txt: vec![("v".into(), "0".into()), ("n".into(), "x".into())],
        },
        MdnsRequest::Register {
            instance: "a\"b\\c\n☃".into(),
            service_type: "_vardevall._udp".into(),
            port: 0,
            txt: vec![
                ("k\"".into(), "v\u{1}".into()),
                ("k\"".into(), "again".into()),
                (String::new(), String::new()),
            ],
        },
        MdnsRequest::Register {
            instance: "empty".into(),
            service_type: "_t._udp".into(),
            port: 65535,
            txt: Vec::new(),
        },
        MdnsRequest::Unregister {
            instance: "a\"b".into(),
        },
        MdnsRequest::Browse,
        MdnsRequest::StopBrowse,
    ]
}

#[test]
fn mdns_requests_render_as_before() {
    let all = mdns_requests();
    assert_eq!(all.len(), REQUESTS.len());
    for (i, (request, expected)) in all.iter().zip(REQUESTS).enumerate() {
        assert_eq!(
            value(&request_to_json(request)),
            value(expected),
            "request {i}"
        );
    }
}

fn mdns_inputs() -> Vec<&'static str> {
    vec![
        r#"{"op":"found","instance":"i","txt":{"v":"0","k":"x"},"port":9,"addrs":["192.168.1.2","fe80::1%en0"],"ifindex":4}"#,
        r#"{"op":"lost","instance":"i"}"#,
        r#"{"op":"lost","instance":"i","txt":5,"port":"x","extra":[1,2]}"#,
        r#"{"op":"lost","instance":"é☃\"\n"}"#,
        r#"{"op":"lost"}"#,
        r#"{"op":"lost","instance":null}"#,
        r#"{"op":"lost","instance":7}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{"z":"1","a":"2","m":"3"},"port":9,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{"s":"1","n":2,"u":null,"b":true,"o":{},"a":[],"t":"ok"},"port":9,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{"k":"1","k":"2"},"port":9,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":["::1%lo0","%en0","","nope",5,null,["1.1.1.1"],"10.0.0.1%a%b"," 1.1.1.1","[::1]","2001:db8::1"]}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":[],"ifindex":0}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":[],"ifindex":4294967295}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":[],"ifindex":4294967296}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":[],"ifindex":-1}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":[],"ifindex":2.0}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":[],"ifindex":"4"}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":[],"ifindex":null}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":[],"ifindex":[4]}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":0,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":65535,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":65536,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":-1,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":1.5,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9.0,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":1e1,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":"9","addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":null,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{},"addrs":[]}"#,
        r#"{"op":"found","instance":"i","port":9,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":null,"port":9,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":[],"port":9,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":[["k","v"]],"port":9,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":"k=v","port":9,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":null}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":{}}"#,
        r#"{"op":"found","instance":"i","txt":{},"port":9,"addrs":"1.1.1.1"}"#,
        r#"{"op":"found","txt":{},"port":9,"addrs":[]}"#,
        r#"{"op":"found","instance":3,"txt":{},"port":9,"addrs":[]}"#,
        r#"{"op":"found","instance":null,"txt":{},"port":9,"addrs":[]}"#,
        r#"{"op":"found","instance":"i","txt":5,"port":"x","addrs":5}"#,
        r#"{"op":"found","instance":5,"txt":{},"port":"x","addrs":5}"#,
        r#"{"op":"found","instance":5,"txt":{},"port":9,"addrs":5}"#,
        r#"{"op":"found","instance":5,"txt":{},"port":9,"addrs":[]}"#,
        r#"{"op":"found"}"#,
        r#"{"op":"found","instance":"i"}"#,
        r#"{"op":"found","instance":"first","instance":"second","txt":{},"port":9,"addrs":[]}"#,
        r#"{"op":"lost","op":"found","instance":"i","txt":{},"port":9,"addrs":[]}"#,
        r#"{"op":"found","op":"lost","instance":"i"}"#,
        r#"{"op":"dance"}"#,
        r#"{"op":"Found","instance":"i"}"#,
        r#"{"op":""}"#,
        r#"{"op":null}"#,
        r#"{"op":5}"#,
        r#"{"op":["found"]}"#,
        r#"{"instance":"i"}"#,
        r#"{}"#,
        r#"[]"#,
        r#"[1,2]"#,
        r#"["found","i"]"#,
        r#"5"#,
        r#"null"#,
        r#""found""#,
        r#"true"#,
        "nope",
        "",
        "{",
        r#"{"op":"lost","instance":"i"} x"#,
        r#"{"op":"lost","instance":"i"}{}"#,
        "  \n{\"op\":\"lost\",\"instance\":\"i\"}\n ",
    ]
}

fn mdns_outcome(text: &str) -> String {
    event_from_json(text).map_or("Err".into(), |event| format!("{event:?}"))
}

#[test]
fn mdns_results_parse_as_before() {
    let inputs = mdns_inputs();
    assert_eq!(inputs.len(), MDNS_RESULTS.len());
    for (input, expected) in inputs.iter().zip(MDNS_RESULTS) {
        assert_eq!(&mdns_outcome(input), expected, "{input}");
    }
    assert_eq!(
        event_from_json(r#"{"op":"lost","instance":"i"}"#).unwrap(),
        MdnsEvent::Lost {
            instance: "i".into()
        }
    );
}

fn path_inputs() -> Vec<&'static str> {
    vec![
        "{}",
        r#"{"changed":false,"metered":true,"interfaces":[{"name":"pdp_ip0","metered":true},{"name":"en0","metered":false}]}"#,
        r#"{"changed":true,"metered":false,"interfaces":[],"families":["v4","v6"]}"#,
        r#"{"changed":null,"metered":null,"interfaces":null,"families":null}"#,
        r#"{"changed":false}"#,
        r#"{"metered":true}"#,
        r#"{"unknown":1,"changed":false,"also":{"x":[1]}}"#,
        r#"{"changed":false,"changed":true}"#,
        r#"{"changed":true,"changed":false}"#,
        r#"{"changed":true,"changed":1}"#,
        r#"{"interfaces":[{"name":"en0","metered":false,"extra":1}]}"#,
        r#"{"interfaces":[{"name":"en0","metered":true},{"name":"en0","metered":false}]}"#,
        r#"{"interfaces":[{"name":"","metered":true}]}"#,
        r#"{"interfaces":[{"name":"en0"}]}"#,
        r#"{"interfaces":[{"metered":true}]}"#,
        r#"{"interfaces":[{"name":null,"metered":true}]}"#,
        r#"{"interfaces":[{"name":"en0","metered":null}]}"#,
        r#"{"interfaces":[{"name":5,"metered":true}]}"#,
        r#"{"interfaces":[{"name":"en0","metered":"true"}]}"#,
        r#"{"interfaces":[{"name":"en0","metered":1}]}"#,
        r#"{"interfaces":[null]}"#,
        r#"{"interfaces":[5]}"#,
        r#"{"interfaces":["en0"]}"#,
        r#"{"interfaces":[{}]}"#,
        r#"{"interfaces":{}}"#,
        r#"{"interfaces":"en0"}"#,
        r#"{"interfaces":5}"#,
        r#"{"interfaces":[{"name":"en0","metered":true},5]}"#,
        r#"{"families":["v4"]}"#,
        r#"{"families":["v6"]}"#,
        r#"{"families":["v6","v4"]}"#,
        r#"{"families":["v4","v4"]}"#,
        r#"{"families":[]}"#,
        r#"{"families":null}"#,
        r#"{"families":"v4"}"#,
        r#"{"families":["v5"]}"#,
        r#"{"families":["V4"]}"#,
        r#"{"families":[4]}"#,
        r#"{"families":[null]}"#,
        r#"{"families":["v4",null]}"#,
        r#"{"families":[["v4"]]}"#,
        r#"{"families":{}}"#,
        r#"{"families":{"v4":true}}"#,
        r#"{"families":5}"#,
        r#"{"families":true}"#,
        r#"{"changed":"yes"}"#,
        r#"{"changed":1}"#,
        r#"{"changed":0}"#,
        r#"{"changed":[]}"#,
        r#"{"changed":{}}"#,
        r#"{"metered":"yes"}"#,
        r#"{"metered":1}"#,
        r#"{"metered":[true]}"#,
        r#"{"metered":1,"changed":2}"#,
        r#"{"changed":true,"metered":1,"interfaces":1,"families":1}"#,
        r#"{"changed":true,"metered":true,"interfaces":1,"families":1}"#,
        r#"{"changed":true,"metered":true,"interfaces":[],"families":1}"#,
        r#"[]"#,
        r#"[true]"#,
        r#"5"#,
        r#"null"#,
        r#""changed""#,
        r#"true"#,
        "",
        "[]x",
        "{",
        "nope",
        r#"{"changed":true} x"#,
        r#"{"changed":false}{}"#,
        "  \n{\"changed\":false}\n ",
    ]
}

fn path_outcome(text: &str) -> String {
    path_update_from_json(text).map_or("Err".into(), |update| format!("{update:?}"))
}

#[test]
fn path_updates_parse_as_before() {
    let inputs = path_inputs();
    assert_eq!(inputs.len(), PATH_RESULTS.len());
    for (input, expected) in inputs.iter().zip(PATH_RESULTS) {
        assert_eq!(&path_outcome(input), expected, "{input}");
    }
}

const EVENTS: &[&str] = &[
    r##"{"listen_port":51820,"state":"started","type":"status"}"##,
    r##"{"listen_port":0,"state":"started","type":"status"}"##,
    r##"{"state":"stopped","type":"status"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","trust":"key","type":"added"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":null,"trust":"key","type":"added"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","trust":"member","type":"added"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":null,"trust":"member","type":"added"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"ñandú \"q\"","type":"removed"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":null,"type":"removed"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","state":"idle","type":"peer"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","state":"connecting","type":"peer"}"##,
    r##"{"addr":"fd00::1","initiator":true,"key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","state":"up","type":"peer"}"##,
    r##"{"addr":"fd00::1","initiator":false,"key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","state":"up","type":"peer"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","reason":"idle","state":"down","type":"peer"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","reason":"unreachable","state":"down","type":"peer"}"##,
    r##"{"addr":"fd00::1","initiator":true,"key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":null,"state":"up","type":"peer"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","route":{"addr":"192.168.1.2:7","kind":"lan"},"type":"route"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","route":{"addr":"[2001:db8::1]:51820","kind":"internet"},"type":"route"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","route":{"addr":"84.46.243.47:49297","kind":"peer_relay"},"type":"route"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","route":{"addr":"109.53.226.37:32298","kind":"own_relay"},"type":"route"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":"nas","route":{"kind":"switch","switch":3},"type":"route"}"##,
    r##"{"addr":"fd00::1","key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","name":null,"route":null,"type":"route"}"##,
    r##"{"address":"sw.example.org:443","auth":"pinned","state":"connecting","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"pinned","state":"registered","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"pinned","reason":"unreachable","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"pinned","reason":"untrusted","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"pinned","reason":"token_rejected","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"pinned","reason":"rejected","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"pinned","reason":"rate_limited","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"pinned","reason":"replaced","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"pinned","reason":"protocol","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"web","state":"connecting","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"web","state":"registered","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"web","reason":"unreachable","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"web","reason":"untrusted","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"web","reason":"token_rejected","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"web","reason":"rejected","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"web","reason":"rate_limited","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"web","reason":"replaced","state":"disconnected","type":"switch"}"##,
    r##"{"address":"sw.example.org:443","auth":"web","reason":"protocol","state":"disconnected","type":"switch"}"##,
    r##"{"level":"plenty","remaining":1000,"source":"switch","total":1000,"transport":"udp","type":"budget"}"##,
    r##"{"level":"half","remaining":400,"source":"turn","total":1000,"transport":"udp","type":"budget"}"##,
    r##"{"level":"low","remaining":50,"source":"switch","total":1000,"transport":"udp","type":"budget"}"##,
    r##"{"level":"exhausted","remaining":0,"source":"turn","total":1000,"transport":"udp","type":"budget"}"##,
    r##"{"budget":null,"transport":"sw.example:4455","type":"budget"}"##,
    r##"{"budget":null,"transport":"turn","type":"budget"}"##,
    r##"{"level":"debug","message":"plain","type":"log"}"##,
    r##"{"level":"info","message":"plain","type":"log"}"##,
    r##"{"level":"warn","message":"plain","type":"log"}"##,
    r##"{"level":"error","message":"plain","type":"log"}"##,
    r##"{"level":"info","message":"a\"b\\c\nd\u0001é☃ </script> ","type":"log"}"##,
    r##"{"level":"error","message":"","type":"log"}"##,
    r##"{"addr":"fd00:0:0:1::1","ipv4":"198.18.3.4","site":"it/home","type":"exit","via":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq"}"##,
    r##"{"addr":"fd00:0:0:1::1","ipv4":null,"site":"de","type":"exit","via":null}"##,
    r##"{"offers":[{"key":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","site":"it/home"}],"type":"exits"}"##,
    r##"{"local":{"ipv4":{"nat":"unknown"},"ipv6":{"nat":"unknown"},"relay":null,"switches":[],"transports":[]},"peers":[],"sites":[],"exit":null,"type":"view"}"##,
    r##"{"local":{"ipv4":{"nat":"symmetric"},"ipv6":{"nat":"unknown"},"relay":null,"switches":[],"transports":[]},"peers":[],"sites":[],"exit":null,"type":"view"}"##,
    r##"{"local":{"ipv4":{"nat":"symmetric"},"ipv6":{"nat":"unknown"},"relay":{"addr":"84.46.243.47:49297","server":"84.46.243.47:4455","transport":"tls"},"switches":[],"transports":[]},"peers":[],"sites":[],"exit":null,"type":"view"}"##,
    r##"{"local":{"ipv4":{"nat":"symmetric"},"ipv6":{"nat":"unknown"},"relay":{"addr":"[2001:db8::9]:49297","server":"[2001:db8::a]:4455","transport":"udp"},"switches":[],"transports":[]},"peers":[],"sites":[],"exit":null,"type":"view"}"##,
    r##"{"local":{"ipv4":{"addr":"193.205.81.9:51820","nat":"punchable"},"ipv6":{"nat":"udp_blocked"},"relay":null,"switches":[],"transports":[]},"peers":[],"sites":[],"exit":null,"type":"view"}"##,
    r##"{"local":{"ipv4":{"addr":"193.205.81.9:51820","nat":"punchable"},"ipv6":{"nat":"udp_blocked"},"relay":{"addr":"84.46.243.47:49297","server":"84.46.243.47:4455","transport":"tls"},"switches":[],"transports":[]},"peers":[],"sites":[],"exit":null,"type":"view"}"##,
    r##"{"local":{"ipv4":{"addr":"193.205.81.9:51820","nat":"punchable"},"ipv6":{"nat":"udp_blocked"},"relay":{"addr":"[2001:db8::9]:49297","server":"[2001:db8::a]:4455","transport":"udp"},"switches":[],"transports":[]},"peers":[],"sites":[],"exit":null,"type":"view"}"##,
    r##"{"local":{"ipv4":{"nat":"udp_blocked"},"ipv6":{"addr":"[2001:db8::2]:4000","nat":"punchable"},"relay":null,"switches":[],"transports":[]},"peers":[],"sites":[],"exit":null,"type":"view"}"##,
    r##"{"local":{"ipv4":{"nat":"udp_blocked"},"ipv6":{"addr":"[2001:db8::2]:4000","nat":"punchable"},"relay":{"addr":"84.46.243.47:49297","server":"84.46.243.47:4455","transport":"tls"},"switches":[],"transports":[]},"peers":[],"sites":[],"exit":null,"type":"view"}"##,
    r##"{"local":{"ipv4":{"nat":"udp_blocked"},"ipv6":{"addr":"[2001:db8::2]:4000","nat":"punchable"},"relay":{"addr":"[2001:db8::9]:49297","server":"[2001:db8::a]:4455","transport":"udp"},"switches":[],"transports":[]},"peers":[],"sites":[],"exit":null,"type":"view"}"##,
    r##"{"local":{"ipv4":{"nat":"unknown"},"ipv6":{"nat":"unknown"},"relay":null,"switches":[{"address":"sw0.example:4455","auth":"pinned","index":0,"state":"connecting","transport":null,"retry_in_ms":null},{"address":"sw1.example:4455","auth":"web","index":1,"state":"registered","transport":"http3","retry_in_ms":null},{"address":"sw2.example:4455","auth":"pinned","index":2,"reason":"unreachable","state":"disconnected","transport":"http2","retry_in_ms":0},{"address":"sw3.example:4455","auth":"web","index":3,"reason":"untrusted","state":"disconnected","transport":"http1","retry_in_ms":0},{"address":"sw4.example:4455","auth":"pinned","index":4,"reason":"token_rejected","state":"disconnected","transport":null,"retry_in_ms":0},{"address":"sw5.example:4455","auth":"web","index":5,"reason":"rejected","state":"disconnected","transport":"http3","retry_in_ms":0},{"address":"sw6.example:4455","auth":"pinned","index":6,"reason":"rate_limited","state":"disconnected","transport":"http2","retry_in_ms":0},{"address":"sw7.example:4455","auth":"web","index":7,"reason":"replaced","state":"disconnected","transport":"http1","retry_in_ms":0},{"address":"sw8.example:4455","auth":"pinned","index":8,"reason":"protocol","state":"disconnected","transport":null,"retry_in_ms":0}],"transports":[]},"peers":[],"sites":[],"exit":null,"type":"view"}"##,
    r##"{"local":{"ipv4":{"nat":"unknown"},"ipv6":{"nat":"unknown"},"relay":null,"switches":[{"address":"sw0.example:4455","auth":"web","index":0,"state":"connecting","transport":null,"retry_in_ms":null},{"address":"sw1.example:4455","auth":"web","index":1,"state":"registered","transport":"http3","retry_in_ms":null},{"address":"sw2.example:4455","auth":"web","index":2,"reason":"unreachable","state":"disconnected","transport":"http2","retry_in_ms":0},{"address":"sw3.example:4455","auth":"web","index":3,"reason":"untrusted","state":"disconnected","transport":"http1","retry_in_ms":0},{"address":"sw4.example:4455","auth":"web","index":4,"reason":"token_rejected","state":"disconnected","transport":null,"retry_in_ms":0},{"address":"sw5.example:4455","auth":"web","index":5,"reason":"rejected","state":"disconnected","transport":"http3","retry_in_ms":0},{"address":"sw6.example:4455","auth":"web","index":6,"reason":"rate_limited","state":"disconnected","transport":"http2","retry_in_ms":0},{"address":"sw7.example:4455","auth":"web","index":7,"reason":"replaced","state":"disconnected","transport":"http1","retry_in_ms":0},{"address":"sw8.example:4455","auth":"web","index":8,"reason":"protocol","state":"disconnected","transport":null,"retry_in_ms":0}],"transports":[{"budget":null,"meter":{"received":20,"sent":10},"name":"udp","usable":true},{"budget":{"level":"exhausted","remaining":0,"source":"turn","total":1000},"meter":{"received":0,"sent":0},"name":"turn","usable":false},{"budget":{"level":"plenty","remaining":1099511627771,"source":"switch","total":1099511627776},"meter":{"received":1,"sent":18446744073709551615},"name":"sw0.example:4455","usable":true},{"budget":{"level":"plenty","remaining":1000,"source":"switch","total":1000},"meter":{"received":0,"sent":0},"name":"level","usable":true},{"budget":{"level":"half","remaining":400,"source":"turn","total":1000},"meter":{"received":0,"sent":0},"name":"level","usable":true},{"budget":{"level":"low","remaining":50,"source":"switch","total":1000},"meter":{"received":0,"sent":0},"name":"level","usable":true},{"budget":{"level":"exhausted","remaining":0,"source":"turn","total":1000},"meter":{"received":0,"sent":0},"name":"level","usable":false}]},"peers":[{"addr":"fd00::a","candidates":[],"fallback":false,"key":"bifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifa","meter":null,"name":null,"nat":"unknown","probing":false,"route":null,"state":"idle","switches":[],"rtt_ms":null,"routes":[]},{"addr":"fd00::b","candidates":[],"fallback":false,"key":"bmfqwcylbmfqwcylbmfqwcylbmfqwcylbmfqwcylbmfqwcylbmfq","meter":null,"name":null,"nat":"unknown","probing":false,"route":null,"state":"connecting","switches":[],"rtt_ms":null,"routes":[]},{"addr":"fd00::c","candidates":[],"fallback":false,"key":"bqgaydambqgaydambqgaydambqgaydambqgaydambqgaydambqga","meter":null,"name":null,"nat":"unknown","probing":false,"route":null,"state":"up","switches":[],"rtt_ms":null,"routes":[]},{"addr":"fd00::d","candidates":[],"fallback":false,"key":"bugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbugq","meter":null,"name":null,"nat":"unknown","probing":false,"route":null,"state":"up","switches":[],"rtt_ms":null,"routes":[]},{"addr":"fd00::e","candidates":[],"fallback":false,"key":"byha4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha4dqobyha","meter":null,"name":null,"nat":"unknown","probing":false,"route":null,"state":"down","switches":[],"rtt_ms":null,"routes":[]},{"addr":"fd00::f","candidates":[],"fallback":false,"key":"b4hq6dypb4hq6dypb4hq6dypb4hq6dypb4hq6dypb4hq6dypb4hq","meter":null,"name":null,"nat":"unknown","probing":false,"route":null,"state":"down","switches":[],"rtt_ms":null,"routes":[]},{"addr":"fd00::14","candidates":[],"fallback":false,"key":"cqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqka","meter":{"received":100,"sent":0},"name":"peer0","nat":"unknown","probing":false,"route":{"addr":"192.168.1.2:7","degraded":false,"kind":"lan","metered":false},"state":"up","switches":[],"rtt_ms":null,"routes":[]},{"addr":"fd00::15","candidates":[],"fallback":false,"key":"cukrkfivcukrkfivcukrkfivcukrkfivcukrkfivcukrkfivcukq","meter":{"received":101,"sent":1},"name":"peer1","nat":"punchable","probing":false,"route":{"addr":"[2001:db8::1]:51820","degraded":true,"kind":"internet","metered":false},"state":"up","switches":[],"rtt_ms":null,"routes":[]},{"addr":"fd00::16","candidates":[],"fallback":false,"key":"cylbmfqwcylbmfqwcylbmfqwcylbmfqwcylbmfqwcylbmfqwcyla","meter":{"received":102,"sent":2},"name":"peer2","nat":"relay_only","probing":false,"route":{"addr":"84.46.243.47:49297","degraded":false,"kind":"peer_relay","metered":true},"state":"up","switches":[],"rtt_ms":null,"routes":[]},{"addr":"fd00::17","candidates":[],"fallback":false,"key":"c4lrofyxc4lrofyxc4lrofyxc4lrofyxc4lrofyxc4lrofyxc4lq","meter":{"received":103,"sent":3},"name":"peer3","nat":"unknown","probing":false,"route":{"addr":"109.53.226.37:32298","degraded":true,"kind":"own_relay","metered":true},"state":"up","switches":[],"rtt_ms":null,"routes":[]},{"addr":"fd00::18","candidates":[],"fallback":false,"key":"dambqgaydambqgaydambqgaydambqgaydambqgaydambqgaydama","meter":{"received":104,"sent":4},"name":"peer4","nat":"punchable","probing":false,"route":{"degraded":false,"kind":"switch","metered":true,"switch":3},"state":"up","switches":[],"rtt_ms":null,"routes":[]},{"addr":"fd00::1e","candidates":[{"addr":"127.0.0.1:1","kind":"local","local":true,"metered":false},{"addr":"192.168.1.2:2","kind":"lan","local":true,"metered":false},{"addr":"203.0.113.5:3","kind":"static","local":false,"metered":false},{"addr":"10.0.0.5:4","kind":"static","local":true,"metered":false},{"addr":"109.53.226.37:32298","kind":"punch","local":false,"metered":false},{"addr":"[2001:db8::7]:5","kind":"relay","local":false,"metered":true},{"addr":"192.168.2.2:6","kind":"lan","local":true,"metered":true}],"fallback":true,"key":"dypb4hq6dypb4hq6dypb4hq6dypb4hq6dypb4hq6dypb4hq6dypa","meter":{"received":4,"sent":3},"name":"iphone","nat":"punchable","probing":true,"route":{"addr":"109.53.226.37:32298","degraded":false,"kind":"own_relay","metered":true},"state":"up","switches":[0,2],"rtt_ms":null,"routes":[]}],"sites":[{"addr":"fd00:0:0:1::1","chosen":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq","down":["aibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaiba"],"peers":["aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq"],"site":"it/home"}],"exit":{"site":"it/home","via":"aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq"},"type":"view"}"##,
    r##"{"local":{"ipv4":{"nat":"unknown"},"ipv6":{"nat":"unknown"},"relay":null,"switches":[],"transports":[]},"peers":[{"key":"faucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaua","addr":"fd00::28","name":"laptop","state":"up","route":{"kind":"internet","addr":"[2001:db8::1]:51820","metered":false,"degraded":false},"nat":"unknown","candidates":[],"switches":[],"probing":false,"fallback":false,"meter":null,"rtt_ms":12,"routes":[{"kind":"internet","addr":"[2001:db8::1]:51820","status":"verified","rtt_ms":12,"active":true,"metered":false,"retry_in_ms":null,"forget_in_ms":null},{"kind":"peer_relay","addr":"84.46.243.47:49297","status":"failed","rtt_ms":null,"active":false,"metered":true,"retry_in_ms":0,"forget_in_ms":null},{"kind":"switch","switch":3,"status":"dormant","rtt_ms":0,"active":false,"metered":true,"retry_in_ms":null,"forget_in_ms":0}]}],"sites":[],"exit":null,"type":"view"}"##,
];

const REQUESTS: &[&str] = &[
    r##"{"op":"register","instance":"abc","type":"_vardevall._udp","port":51820,"txt":{"v":"0","n":"x"}}"##,
    r##"{"op":"register","instance":"a\"b\\c\n☃","type":"_vardevall._udp","port":0,"txt":{"k\"":"v\u0001","k\"":"again","":""}}"##,
    r##"{"op":"register","instance":"empty","type":"_t._udp","port":65535,"txt":{}}"##,
    r##"{"op":"unregister","instance":"a\"b"}"##,
    r##"{"op":"browse"}"##,
    r##"{"op":"stop_browse"}"##,
];

const MDNS_RESULTS: &[&str] = &[
    r##"Found(Found { instance: "i", txt: [("k", "x"), ("v", "0")], port: 9, addrs: [192.168.1.2, fe80::1], ifindex: 4 })"##,
    r##"Lost { instance: "i" }"##,
    r##"Lost { instance: "i" }"##,
    r##"Lost { instance: "é☃\"\n" }"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Found(Found { instance: "i", txt: [], port: 9, addrs: [], ifindex: 0 })"##,
    r##"Found(Found { instance: "i", txt: [("a", "2"), ("m", "3"), ("z", "1")], port: 9, addrs: [], ifindex: 0 })"##,
    r##"Found(Found { instance: "i", txt: [("s", "1"), ("t", "ok")], port: 9, addrs: [], ifindex: 0 })"##,
    r##"Found(Found { instance: "i", txt: [("k", "2")], port: 9, addrs: [], ifindex: 0 })"##,
    r##"Err"##,
    r##"Found(Found { instance: "i", txt: [], port: 9, addrs: [], ifindex: 0 })"##,
    r##"Found(Found { instance: "i", txt: [], port: 9, addrs: [], ifindex: 4294967295 })"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Found(Found { instance: "i", txt: [], port: 9, addrs: [], ifindex: 0 })"##,
    r##"Err"##,
    r##"Found(Found { instance: "i", txt: [], port: 0, addrs: [], ifindex: 0 })"##,
    r##"Found(Found { instance: "i", txt: [], port: 65535, addrs: [], ifindex: 0 })"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Lost { instance: "i" }"##,
];

const PATH_RESULTS: &[&str] = &[
    r##"PathUpdate { changed: true, metered: None, interfaces: [], families: Families { v4: true, v6: true } }"##,
    r##"PathUpdate { changed: false, metered: Some(true), interfaces: [("pdp_ip0", true), ("en0", false)], families: Families { v4: true, v6: true } }"##,
    r##"PathUpdate { changed: true, metered: Some(false), interfaces: [], families: Families { v4: true, v6: true } }"##,
    r##"PathUpdate { changed: true, metered: None, interfaces: [], families: Families { v4: true, v6: true } }"##,
    r##"PathUpdate { changed: false, metered: None, interfaces: [], families: Families { v4: true, v6: true } }"##,
    r##"PathUpdate { changed: true, metered: Some(true), interfaces: [], families: Families { v4: true, v6: true } }"##,
    r##"PathUpdate { changed: false, metered: None, interfaces: [], families: Families { v4: true, v6: true } }"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"PathUpdate { changed: true, metered: None, interfaces: [("en0", false)], families: Families { v4: true, v6: true } }"##,
    r##"PathUpdate { changed: true, metered: None, interfaces: [("en0", true), ("en0", false)], families: Families { v4: true, v6: true } }"##,
    r##"PathUpdate { changed: true, metered: None, interfaces: [("", true)], families: Families { v4: true, v6: true } }"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"PathUpdate { changed: true, metered: None, interfaces: [], families: Families { v4: true, v6: false } }"##,
    r##"PathUpdate { changed: true, metered: None, interfaces: [], families: Families { v4: false, v6: true } }"##,
    r##"PathUpdate { changed: true, metered: None, interfaces: [], families: Families { v4: true, v6: true } }"##,
    r##"PathUpdate { changed: true, metered: None, interfaces: [], families: Families { v4: true, v6: false } }"##,
    r##"PathUpdate { changed: true, metered: None, interfaces: [], families: Families { v4: false, v6: false } }"##,
    r##"PathUpdate { changed: true, metered: None, interfaces: [], families: Families { v4: true, v6: true } }"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"Err"##,
    r##"PathUpdate { changed: false, metered: None, interfaces: [], families: Families { v4: true, v6: true } }"##,
];
