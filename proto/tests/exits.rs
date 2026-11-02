//! The exits of a site, their failure and the client's choice: scenarios on
//! the simulator. A client holds sessions with the exits, which it keeps alive with
//! a packet stream, or, where it uses an exit, by the node itself.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use vardevall_proto::discovery::candidate::Candidate;
use vardevall_proto::ip::exit::{ExitServe, ExitUse};
use vardevall_proto::ip::site::{Site, site_id};
use vardevall_proto::node::{Event, PeerState, Trust};
use vardevall_proto::route::DeliveryClass;
use vardevall_proto::sim::*;
use vardevall_proto::time::Instant;

mod trace;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn link(n: u64) -> LinkConfig {
    LinkConfig::latency(Duration::from_millis(n))
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn serve(site: &str) -> ExitServe {
    ExitServe {
        site: site.parse().unwrap(),
        ipv4: true,
    }
}

struct World {
    sim: Sim,
    hosts: Vec<HostId>,
    addrs: Vec<IpAddr>,
    offline: Vec<HostId>,
    next: u8,
}

impl Drop for World {
    fn drop(&mut self) {
        trace::save(&self.sim, Instant::ZERO);
    }
}

impl World {
    fn new() -> Self {
        World {
            sim: Sim::new(7, link(5)),
            hosts: Vec::new(),
            addrs: Vec::new(),
            offline: Vec::new(),
            next: 1,
        }
    }

    /// A public host `ms` from the core, offering `site` if given.
    fn host(&mut self, ms: u64, site: Option<&str>) -> HostId {
        let s = self.sim.site(None, link(ms), link(1));
        let addr = ip(&format!("203.0.113.{}", self.next));
        self.next += 1;
        let h = self.sim.host(s, addr, |c| c.exit = site.map(serve));
        self.hosts.push(h);
        self.addrs.push(addr);
        h
    }

    /// `a` and `b` trust each other and know each other's address.
    fn link(&mut self, a: HostId, b: HostId) {
        self.sim.peer(a, b);
        let (to_b, to_a) = (self.sim.addr(b), self.sim.addr(a));
        self.sim.know(a, b, vec![Candidate::static_(to_b)]);
        self.sim.know(b, a, vec![Candidate::static_(to_a)]);
    }

    /// `a` and `b` trust each other and have no network but the switch.
    fn link_switch(&mut self, a: HostId, b: HostId) {
        for h in [a, b] {
            if !self.offline.contains(&h) {
                self.offline.push(h);
                self.sim.set_iface(h, self.addrs[h.0], false);
            }
            self.sim.register(h, link(5));
        }
        self.sim.peer(a, b);
    }

    /// The client keeps a session with `exit` up.
    fn keep(&mut self, client: HostId, exit: HostId) -> StreamId {
        self.sim
            .stream(client, exit, secs(5), DeliveryClass::default(), 40)
    }

    /// The exit events of `host`: when (s), the site and the host chosen.
    fn exits(&self, host: HostId) -> Vec<(u64, String, Option<HostId>)> {
        self.sim
            .events(host)
            .iter()
            .filter_map(|(t, e)| match e {
                Event::Exit { site, via, .. } => Some((
                    t.as_duration().as_secs(),
                    site.to_string(),
                    via.map(|k| self.who(&k)),
                )),
                _ => None,
            })
            .collect()
    }

    fn who(&self, key: &vardevall_proto::keys::NodePublic) -> HostId {
        *self
            .hosts
            .iter()
            .find(|h| self.sim.public(**h) == *key)
            .expect("a host")
    }

    fn collisions(&self, host: HostId) -> Vec<(Site, Site)> {
        self.sim
            .events(host)
            .iter()
            .filter_map(|(_, e)| match e {
                Event::ExitCollision { first, second } => Some((first.clone(), second.clone())),
                _ => None,
            })
            .collect()
    }

    fn cut(&mut self, a: HostId, b: HostId, on: bool) {
        self.sim.block(End::Host(a), End::Host(b), on);
        self.sim.block(End::Host(b), End::Host(a), on);
    }
}

fn names(who: &[(u64, String, Option<HostId>)]) -> Vec<(&str, Option<usize>)> {
    who.iter()
        .map(|(_, s, v)| (s.as_str(), v.map(|h| h.0)))
        .collect()
}

#[test]
fn exits_of_one_site_the_client_chooses_the_better_and_reports_once() {
    let mut w = World::new();
    let client = w.host(10, None);
    let far = w.host(40, Some("it/home"));
    let near = w.host(10, Some("it/home"));
    w.link(client, far);
    w.link(client, near);
    w.keep(client, far);
    w.keep(client, near);
    w.sim.run(secs(60));

    assert_eq!(names(&w.exits(client)), [("it/home", Some(near.0))]);
    let sites = w.sim.node(client).sites();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].chosen, Some(w.sim.public(near)));
    assert_eq!(sites[0].peers.len(), 2, "both are live");
    assert!(w.exits(near).is_empty() && w.exits(far).is_empty());
}

#[test]
fn an_exit_that_comes_up_later_does_not_take_the_choice() {
    let mut w = World::new();
    let client = w.host(10, None);
    let far = w.host(40, Some("it/home"));
    let near = w.host(10, Some("it/home"));
    w.link(client, far);
    w.link(client, near);
    w.keep(client, far);
    w.sim.run(secs(20));
    w.keep(client, near);
    w.sim.run(secs(60));

    assert_eq!(names(&w.exits(client)), [("it/home", Some(far.0))]);
    assert_eq!(w.sim.node(client).sites()[0].peers.len(), 2);
}

#[test]
fn the_chosen_exit_dies_the_client_moves_and_does_not_move_back() {
    let mut w = World::new();
    let client = w.host(10, None);
    let near = w.host(10, Some("it/home"));
    let far = w.host(40, Some("it/home"));
    w.link(client, near);
    w.link(client, far);
    w.keep(client, near);
    w.keep(client, far);
    w.sim.run(secs(30));
    assert_eq!(names(&w.exits(client)), [("it/home", Some(near.0))]);

    w.cut(client, near, true);
    w.sim.run(secs(300));
    let got = w.exits(client);
    assert_eq!(
        names(&got),
        [("it/home", Some(near.0)), ("it/home", Some(far.0))]
    );
    assert!(got[1].0 < 30 + 120, "the move took {} s", got[1].0 - 30);

    w.cut(client, near, false);
    w.sim.run(secs(300));
    assert_eq!(
        w.exits(client).len(),
        2,
        "the first exit coming back moves nothing"
    );
    let sites = w.sim.node(client).sites();
    assert_eq!(sites[0].chosen, Some(w.sim.public(far)));
    assert_eq!(sites[0].peers.len(), 2, "it is live again");

    w.cut(client, far, true);
    w.sim.run(secs(300));
    assert_eq!(
        names(&w.exits(client))[2..],
        [("it/home", Some(near.0))],
        "when the second dies in turn, the first is taken again"
    );
}

#[test]
fn a_site_with_no_live_exit_is_reported_gone_once() {
    let mut w = World::new();
    let client = w.host(10, None);
    let only = w.host(10, Some("it/home"));
    w.link(client, only);
    w.keep(client, only);
    w.sim.run(secs(30));
    w.cut(client, only, true);
    w.sim.run(secs(300));
    assert_eq!(
        names(&w.exits(client)),
        [("it/home", Some(only.0)), ("it/home", None)]
    );
    let sites = w.sim.node(client).sites();
    assert_eq!(sites.len(), 1, "the offer is remembered");
    assert_eq!(sites[0].chosen, None);
    assert!(!sites[0].peers[0].live);
}

#[test]
fn a_second_site_is_chosen_by_its_own_site() {
    let mut w = World::new();
    let client = w.host(10, None);
    let home = w.host(30, Some("it/home"));
    let work = w.host(10, Some("de"));
    w.link(client, home);
    w.link(client, work);
    w.keep(client, home);
    w.keep(client, work);
    w.sim.run(secs(30));

    let got = w.exits(client);
    assert_eq!(got.len(), 2);
    assert!(names(&got).contains(&("it/home", Some(home.0))));
    assert!(names(&got).contains(&("de", Some(work.0))));
    let node = w.sim.node(client);
    assert_eq!(
        node.exit_for(&"it/home".parse().unwrap()),
        Some(w.sim.public(home))
    );
    assert_eq!(
        node.exit_for(&"de".parse().unwrap()),
        Some(w.sim.public(work))
    );
    assert_ne!(
        node.site_addr(&"it/home".parse().unwrap()),
        node.site_addr(&"de".parse().unwrap())
    );

    w.cut(client, work, true);
    w.sim.run(secs(300));
    let got = w.exits(client);
    assert_eq!(got.len(), 3);
    assert_eq!(names(&got)[2], ("de", None), "the other site is untouched");
}

#[test]
fn an_offer_from_a_member_trusted_peer_is_ignored() {
    let mut w = World::new();
    let client = w.sim_member_client();
    let exit = w.host(10, Some("it/home"));
    w.sim.trust(exit, client);
    let to_client = w.sim.addr(client);
    w.sim
        .know(exit, client, vec![Candidate::static_(to_client)]);
    w.keep(exit, client);
    w.sim.run(secs(60));

    let node = w.sim.node(client);
    let view = node.peer_view(&w.sim.public(exit)).expect("a member");
    assert_eq!(view.trust, Trust::Member);
    assert!(matches!(
        view.link,
        vardevall_proto::node::PeerState::Up { .. }
    ));
    assert_eq!(view.exit, None);
    assert!(node.sites().is_empty());
    assert!(w.exits(client).is_empty());
}

impl World {
    fn sim_member_client(&mut self) -> HostId {
        let s = self.sim.site(None, link(10), link(1));
        let addr = ip(&format!("203.0.113.{}", self.next));
        self.next += 1;
        let h = self.sim.host(s, addr, |c| c.accept_members = true);
        self.hosts.push(h);
        self.addrs.push(addr);
        h
    }
}

/// Two different names that share a site id in the world's network.
fn colliding(w: &World, of: HostId) -> (Site, Site) {
    let nid = *w.sim.node(of).network_id();
    let mut seen: BTreeMap<u16, Site> = BTreeMap::new();
    for i in 0..100_000u32 {
        let site: Site = format!("it/n{i}").parse().unwrap();
        if let Some(other) = seen.insert(site_id(&nid, &site), site.clone()) {
            return (other.clone().min(site.clone()), other.max(site));
        }
    }
    unreachable!("65535 ids")
}

#[test]
fn colliding_sites_are_both_ignored_and_logged_once() {
    let mut w = World::new();
    let client = w.host(10, None);
    let (a, b) = colliding(&w, client);
    let ea = w.host(10, Some(&a.to_string()));
    let eb = w.host(20, Some(&b.to_string()));
    let ok = w.host(15, Some("de"));
    for e in [ea, eb, ok] {
        w.link(client, e);
        w.keep(client, e);
    }
    w.sim.run(secs(60));

    assert_eq!(
        w.collisions(client),
        [(a.clone(), b.clone())],
        "logged once"
    );
    let got = w.exits(client);
    assert!(names(&got).contains(&("de", Some(ok.0))));
    let sites = w.sim.node(client).sites();
    assert_eq!(sites.len(), 1, "only the site without a collision is used");
    assert_eq!(sites[0].site.to_string(), "de");
    for site in [&a, &b] {
        let last = got.iter().rfind(|(_, s, _)| *s == site.to_string());
        assert!(
            last.is_none_or(|(_, _, via)| via.is_none()),
            "a site chosen before its twin arrived is reported gone: {got:?}"
        );
    }
}

#[test]
fn an_exit_that_hears_a_colliding_site_stops_offering_its_own() {
    let mut w = World::new();
    let client = w.host(10, None);
    let (a, b) = colliding(&w, client);
    let ea = w.host(10, Some(&a.to_string()));
    let eb = w.host(10, Some(&b.to_string()));
    w.link(ea, eb);
    w.keep(ea, eb);
    w.sim.run(secs(20));
    assert_eq!(
        w.collisions(ea).len(),
        1,
        "the exits found out through the handshake"
    );
    assert_eq!(w.collisions(eb).len(), 1);

    w.link(client, ea);
    w.link(client, eb);
    w.keep(client, ea);
    w.keep(client, eb);
    w.sim.run(secs(60));
    for e in [ea, eb] {
        let v = w.sim.node(client).peer_view(&w.sim.public(e)).unwrap();
        assert_eq!(v.exit, None, "neither offers any more");
    }
    assert!(w.exits(client).is_empty());
}

#[test]
fn an_offer_withdrawn_is_gone_at_the_clients_next_rekey() {
    let mut w = World::new();
    let client = w.host(10, None);
    let exit = w.host(10, Some("it/home"));
    w.link(client, exit);
    w.keep(client, exit);
    w.sim.run(secs(30));
    assert_eq!(names(&w.exits(client)), [("it/home", Some(exit.0))]);

    w.sim.set_exit(exit, None);
    w.sim.run(secs(60));
    assert_eq!(
        w.exits(client).len(),
        1,
        "the session in use still holds the offer"
    );

    w.sim.run(secs(120));
    assert_eq!(
        names(&w.exits(client)),
        [("it/home", Some(exit.0)), ("it/home", None)]
    );
    assert!(
        matches!(
            w.sim.states(client, exit).last(),
            Some((_, vardevall_proto::node::PeerState::Up { .. }))
        ),
        "the link itself stays up"
    );
}

#[test]
fn a_second_site_that_goes_down_does_not_make_the_first_the_only_site() {
    let mut w = World::new();
    let client = w.host(10, None);
    let home = w.host(30, Some("it/home"));
    let work = w.host(10, Some("de"));
    w.link(client, home);
    w.link(client, work);
    w.keep(client, home);
    w.keep(client, work);
    w.sim.run(secs(30));
    assert_eq!(w.sim.node(client).only_site(), None);

    w.cut(client, work, true);
    w.sim.run(secs(300));
    let node = w.sim.node(client);
    assert_eq!(node.exit_for(&"de".parse().unwrap()), None);
    assert_eq!(
        node.only_site(),
        None,
        "the offer of the second is remembered"
    );
    let sites = node.sites();
    assert_eq!(sites.len(), 2);
    assert_eq!(sites[0].site.to_string(), "de");
    assert_eq!(sites[0].chosen, None);
    assert!(!sites[0].peers[0].live);
    assert!(sites[1].peers[0].live);
    let view = node.peer_view(&w.sim.public(work)).unwrap();
    assert_eq!(view.exit.map(|o| o.site.to_string()).as_deref(), Some("de"));
}

#[test]
fn a_remembered_offer_is_gone_when_the_peers_next_handshake_carries_none() {
    let mut w = World::new();
    let client = w.host(10, None);
    let exit = w.host(10, Some("it/home"));
    w.link(client, exit);
    w.keep(client, exit);
    w.sim.run(secs(30));
    assert_eq!(
        w.sim.node(client).only_site(),
        Some("it/home".parse().unwrap())
    );

    w.cut(client, exit, true);
    w.sim.run(secs(300));
    assert_eq!(
        w.sim.node(client).only_site(),
        Some("it/home".parse().unwrap()),
        "remembered with its link down"
    );

    w.sim.set_exit(exit, None);
    w.cut(client, exit, false);
    w.sim.run(secs(120));
    let node = w.sim.node(client);
    let view = node.peer_view(&w.sim.public(exit)).unwrap();
    assert!(matches!(
        view.link,
        vardevall_proto::node::PeerState::Up { .. }
    ));
    assert_eq!(view.exit, None);
    assert_eq!(node.only_site(), None);
    assert!(node.sites().is_empty());
}

fn use_it(w: &mut World, client: HostId) {
    w.sim.use_exit(client, Some(ExitUse::default()));
}

fn ups(w: &World, client: HostId, exit: HostId) -> usize {
    w.sim
        .states(client, exit)
        .iter()
        .filter(|(_, s)| matches!(s, PeerState::Up { .. }))
        .count()
}

#[test]
fn with_the_use_set_the_client_connects_to_the_exits_without_any_traffic() {
    let mut w = World::new();
    let client = w.host(10, None);
    let far = w.host(40, Some("it/home"));
    let near = w.host(10, Some("it/home"));
    w.link(client, far);
    w.link(client, near);
    w.sim.run(secs(60));
    assert!(w.sim.states(client, near).is_empty(), "nothing started");

    use_it(&mut w, client);
    w.sim.run(secs(30));
    assert_eq!(ups(&w, client, far), 1);
    assert_eq!(ups(&w, client, near), 1);
    assert_eq!(names(&w.exits(client)), [("it/home", Some(near.0))]);
    assert_eq!(
        w.sim.node(client).only_site(),
        Some("it/home".parse().unwrap())
    );
}

/// A client with two exits of one site, reached directly or only through the switch.
fn two_exits(w: &mut World, switch: bool) -> (HostId, HostId, HostId) {
    let client = w.host(10, None);
    let near = w.host(10, Some("it/home"));
    let far = w.host(40, Some("it/home"));
    for exit in [near, far] {
        if switch {
            w.link_switch(client, exit);
        } else {
            w.link(client, exit);
        }
    }
    (client, near, far)
}

fn never_down(w: &World, client: HostId, exits: [HostId; 2]) {
    for exit in exits {
        let states = w.sim.states(client, exit);
        assert!(
            states
                .iter()
                .all(|(_, s)| !matches!(s, PeerState::Down(_) | PeerState::Idle)),
            "{states:?}"
        );
        assert!(matches!(states.last(), Some((_, PeerState::Up { .. }))));
    }
}

#[test]
fn the_session_of_a_standby_exit_survives_ten_minutes_of_silence() {
    for switch in [false, true] {
        let mut w = World::new();
        let (client, near, far) = two_exits(&mut w, switch);
        use_it(&mut w, client);
        w.sim.run(secs(600));
        never_down(&w, client, [near, far]);
        assert_eq!(
            names(&w.exits(client)),
            [("it/home", Some(near.0))],
            "switch: {switch}"
        );
        let sites = w.sim.node(client).sites();
        assert!(sites[0].peers.iter().all(|p| p.live));
    }
}

#[test]
fn without_the_use_the_sessions_idle_out() {
    let mut w = World::new();
    let (client, near, far) = two_exits(&mut w, true);
    use_it(&mut w, client);
    w.sim.run(secs(30));
    w.sim.use_exit(client, None);
    w.sim.run(secs(600));

    for exit in [near, far] {
        let states = w.sim.states(client, exit);
        assert!(
            matches!(
                states.last(),
                Some((_, PeerState::Down(_) | PeerState::Idle))
            ),
            "{states:?}"
        );
    }
    assert_eq!(
        names(&w.exits(client)),
        [("it/home", Some(near.0)), ("it/home", None)]
    );
}

#[test]
fn a_session_that_ends_while_the_use_lasts_is_started_again() {
    let mut w = World::new();
    let (client, near, far) = two_exits(&mut w, false);
    use_it(&mut w, client);
    w.sim.run(secs(30));
    w.cut(client, far, true);
    w.sim.run(secs(300));
    assert!(matches!(
        w.sim.states(client, far).last(),
        Some((_, PeerState::Connecting | PeerState::Down(_)))
    ));
    w.cut(client, far, false);
    w.sim.run(secs(120));
    never_down(&w, client, [near, near]);
    assert!(matches!(
        w.sim.states(client, far).last(),
        Some((_, PeerState::Up { .. }))
    ));
    assert_eq!(names(&w.exits(client)), [("it/home", Some(near.0))]);
    assert_eq!(w.sim.node(client).sites()[0].peers.len(), 2);
}

#[test]
fn a_chosen_exit_that_dies_fails_over_to_the_standby_at_once() {
    let mut w = World::new();
    let client = w.host(10, None);
    let near = w.host(10, Some("it/home"));
    let far = w.host(40, Some("it/home"));
    w.link(client, near);
    w.link(client, far);
    use_it(&mut w, client);
    w.sim.run(secs(300));
    assert_eq!(names(&w.exits(client)), [("it/home", Some(near.0))]);

    w.cut(client, near, true);
    w.sim.run(secs(120));
    let got = w.exits(client);
    assert_eq!(
        names(&got),
        [("it/home", Some(near.0)), ("it/home", Some(far.0))]
    );
    assert_eq!(ups(&w, client, far), 1, "the standby never went down");
}

#[test]
fn only_the_exits_of_the_site_in_use_are_kept_connected() {
    let mut w = World::new();
    let client = w.host(10, None);
    let home = w.host(10, Some("it/home"));
    let work = w.host(10, Some("de"));
    w.link_switch(client, home);
    w.link_switch(client, work);
    w.sim.use_exit(client, Some(ExitUse::default()));
    w.sim.run(secs(30));
    assert_eq!(w.sim.node(client).only_site(), None, "two sites");
    w.sim.use_exit(
        client,
        Some(ExitUse {
            site: Some("de".parse().unwrap()),
        }),
    );
    w.sim.run(secs(600));

    never_down(&w, client, [work, work]);
    assert!(
        matches!(
            w.sim.states(client, home).last(),
            Some((_, PeerState::Down(_) | PeerState::Idle))
        ),
        "the other site idles out"
    );
    let sites = w.sim.node(client).sites();
    assert_eq!(sites.len(), 2, "its offer is remembered");
}

/// Whether `client` started anything toward `peer`.
fn contacted(w: &World, client: HostId, peer: HostId) -> bool {
    !w.sim.states(client, peer).is_empty()
}

#[test]
fn a_use_with_a_remembered_exit_reaches_it_alone() {
    let mut w = World::new();
    let client = w.host(10, None);
    let exit = w.host(10, Some("it/home"));
    let other = w.host(10, None);
    w.link(client, exit);
    w.link(client, other);
    let offers = [(w.sim.public(exit), "it/home".parse().unwrap())];
    w.sim.remember(client, &offers);
    assert_eq!(
        w.sim.node(client).only_site(),
        Some("it/home".parse().unwrap()),
        "known before any handshake"
    );

    use_it(&mut w, client);
    w.sim.run(secs(30));
    assert_eq!(names(&w.exits(client)), [("it/home", Some(exit.0))]);
    assert!(
        !contacted(&w, client, other),
        "a peer not known as an exit is left alone"
    );
}

#[test]
fn a_remembered_exit_that_does_not_come_up_makes_the_use_reach_every_peer() {
    let mut w = World::new();
    let client = w.host(10, None);
    let gone = w.host(10, None);
    let exit = w.host(10, Some("it/home"));
    w.link(client, gone);
    w.link(client, exit);
    w.cut(client, gone, true);
    let offers = [(w.sim.public(gone), "it/home".parse().unwrap())];
    w.sim.remember(client, &offers);

    use_it(&mut w, client);
    w.sim.run(secs(4));
    assert!(!contacted(&w, client, exit), "the search waits first");
    w.sim.run(secs(30));
    assert_eq!(names(&w.exits(client)), [("it/home", Some(exit.0))]);
}

#[test]
fn a_use_with_nothing_remembered_reaches_every_peer_at_once() {
    let mut w = World::new();
    let client = w.host(10, None);
    let exit = w.host(10, Some("it/home"));
    w.link(client, exit);
    use_it(&mut w, client);
    w.sim.run(secs(1));
    assert!(contacted(&w, client, exit));
}

#[test]
fn the_offers_learned_are_reported_for_the_host_to_keep() {
    let mut w = World::new();
    let client = w.host(10, None);
    let exit = w.host(10, Some("it/home"));
    w.link(client, exit);
    w.keep(client, exit);
    w.sim.run(secs(30));
    let last = w
        .sim
        .events(client)
        .iter()
        .rev()
        .find_map(|(_, e)| match e {
            Event::Remembered { offers } => Some(offers.clone()),
            _ => None,
        });
    assert_eq!(
        last,
        Some(vec![(w.sim.public(exit), "it/home".parse().unwrap())])
    );
}

#[test]
fn a_remembered_offer_of_a_peer_not_held_by_key_or_unknown_is_ignored() {
    let mut w = World::new();
    let client = w.host(10, None);
    let stranger = w.host(10, Some("it/home"));
    let offers = [(w.sim.public(stranger), "it/home".parse().unwrap())];
    w.sim.remember(client, &offers);
    assert!(w.sim.node(client).sites().is_empty());
}
