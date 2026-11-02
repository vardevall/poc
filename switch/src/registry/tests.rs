use std::future::poll_fn;
use std::task::Poll;

use super::*;

const GRACE: Duration = Duration::from_secs(30);

fn net(n: u8) -> NetworkPublic {
    NetworkPublic::from_bytes([n; 32])
}

fn node(n: u8) -> NodePublic {
    NodePublic::from_bytes([n; 32])
}

fn registry(limits: Limits) -> Arc<Registry> {
    Registry::new(&limits, GRACE)
}

async fn drain(s: &mut EventStream) -> Vec<String> {
    let mut out = Vec::new();
    while let Poll::Ready(Some(b)) = poll_fn(|cx| Poll::Ready(s.poll_next(cx))).await {
        out.push(String::from_utf8(b.to_vec()).unwrap());
    }
    out
}

fn events(chunks: &[String]) -> Vec<(String, String)> {
    chunks
        .iter()
        .filter(|c| c.starts_with("id:"))
        .map(|c| {
            let mut event = String::new();
            let mut data = String::new();
            for line in c.lines() {
                if let Some(v) = line.strip_prefix("event: ") {
                    event = v.to_owned();
                } else if let Some(v) = line.strip_prefix("data: ") {
                    data = v.to_owned();
                }
            }
            (event, data)
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn registration_without_a_stream_goes_offline_after_the_grace_period() {
    let r = registry(Limits::default());
    let t0 = Instant::now();
    let reg = r.register(net(1), node(1), t0, 100).unwrap();
    assert_eq!(reg.generation, 100);
    assert!(r.lookup(&reg.session).is_ok());
    r.sweep(t0 + Duration::from_secs(29));
    assert!(r.lookup(&reg.session).is_ok());
    r.sweep(t0 + GRACE);
    assert_eq!(r.lookup(&reg.session), Err(SessionInvalid));
    assert_eq!(r.stats().registrations, 0);
    assert_eq!(r.stats().networks, 0);
}

#[tokio::test(start_paused = true)]
async fn a_stream_keeps_the_node_online_and_closing_it_starts_the_grace_period() {
    let r = registry(Limits::default());
    let t0 = Instant::now();
    let a = r.register(net(1), node(1), t0, 100).unwrap();
    let stream = r.open_stream(&a.session).unwrap();
    r.sweep(t0 + Duration::from_secs(3600));
    assert!(r.lookup(&a.session).is_ok());
    assert_eq!(r.stats().streams, 1);
    drop(stream);
    assert_eq!(r.stats().streams, 0);
    let t1 = Instant::now();
    r.sweep(t1 + Duration::from_secs(29));
    assert!(r.lookup(&a.session).is_ok());
    r.sweep(t1 + GRACE);
    assert!(r.lookup(&a.session).is_err());
}

#[tokio::test(start_paused = true)]
async fn reconnecting_within_the_grace_period_keeps_the_node_online() {
    let r = registry(Limits::default());
    let a = r.register(net(1), node(1), Instant::now(), 100).unwrap();
    let first = r.open_stream(&a.session).unwrap();
    drop(first);
    tokio::time::advance(Duration::from_secs(20)).await;
    let second = r.open_stream(&a.session).unwrap();
    tokio::time::advance(Duration::from_secs(60)).await;
    r.sweep(Instant::now());
    assert!(r.lookup(&a.session).is_ok());
    drop(second);
}

#[tokio::test(start_paused = true)]
async fn a_new_stream_closes_the_previous_one_without_starting_the_timer() {
    let r = registry(Limits::default());
    let a = r.register(net(1), node(1), Instant::now(), 100).unwrap();
    let mut first = r.open_stream(&a.session).unwrap();
    let second = r.open_stream(&a.session).unwrap();
    assert!(drain(&mut first).await.len() <= 1);
    assert!(poll_fn(|cx| first.poll_next(cx)).await.is_none());
    drop(first);
    tokio::time::advance(Duration::from_secs(120)).await;
    r.sweep(Instant::now());
    assert!(r.lookup(&a.session).is_ok());
    assert_eq!(r.stats().streams, 1);
    drop(second);
}

#[tokio::test(start_paused = true)]
async fn online_offline_and_replaced_events() {
    let r = registry(Limits::default());
    let t0 = Instant::now();
    let a = r.register(net(1), node(1), t0, 100).unwrap();
    let mut sa = r.open_stream(&a.session).unwrap();
    let b = r.register(net(1), node(2), t0, 101).unwrap();
    let mut sb = r.open_stream(&b.session).unwrap();
    let other = r.register(net(2), node(3), t0, 102).unwrap();
    let mut so = r.open_stream(&other.session).unwrap();

    let ev = events(&drain(&mut sa).await);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].0, "online");
    assert!(ev[0].1.contains(&node(2).to_base32()) && ev[0].1.contains("\"gen\":101"));
    assert!(events(&drain(&mut so).await).is_empty());

    let b2 = r.register(net(1), node(2), t0, 110).unwrap();
    assert_eq!(b2.generation, 110);
    assert!(r.lookup(&b.session).is_err());
    let evb = events(&drain(&mut sb).await);
    assert_eq!(evb.last().unwrap().0, "replaced");
    assert!(poll_fn(|cx| sb.poll_next(cx)).await.is_none());
    let eva = events(&drain(&mut sa).await);
    assert_eq!(eva[0].0, "online");
    assert!(eva[0].1.contains("\"gen\":110"));

    assert!(r.logout(&b2.session, t0));
    let eva = events(&drain(&mut sa).await);
    assert_eq!(eva[0].0, "offline");
    assert!(eva[0].1.contains("\"gen\":110"));
    assert!(!r.logout(&b2.session, t0));
}

#[tokio::test(start_paused = true)]
async fn the_generation_is_the_clock_in_milliseconds_and_never_goes_back() {
    let r = registry(Limits::default());
    let t0 = Instant::now();
    let a = r.register(net(1), node(1), t0, 1_789_300_000_412).unwrap();
    assert_eq!(a.generation, 1_789_300_000_412);
    let same = r.register(net(1), node(1), t0, 1_789_300_000_412).unwrap();
    assert_eq!(same.generation, 1_789_300_000_413);
    let stepped_back = r.register(net(1), node(1), t0, 1_789_000_000_000).unwrap();
    assert_eq!(stepped_back.generation, 1_789_300_000_414);
    let other = r.register(net(1), node(2), t0, 1_789_000_000_000).unwrap();
    assert_eq!(other.generation, 1_789_000_000_000);
}

#[tokio::test(start_paused = true)]
async fn generations_keep_increasing_across_offline_periods() {
    let r = registry(Limits::default());
    let t0 = Instant::now();
    let a = r.register(net(1), node(1), t0, 5_000).unwrap();
    assert!(r.logout(&a.session, t0));
    let again = r.register(net(1), node(1), t0, 1_000).unwrap();
    assert_eq!(again.generation, 5_001);
    let later = t0 + GEN_RETENTION + Duration::from_secs(1);
    assert!(r.logout(&again.session, t0));
    r.sweep(later);
    assert_eq!(
        r.register(net(1), node(1), later, 1_000)
            .unwrap()
            .generation,
        1_000
    );
}

#[tokio::test(start_paused = true)]
async fn forwarding_is_confined_to_the_network_and_requires_a_stream() {
    let r = registry(Limits::default());
    let t0 = Instant::now();
    let a = r.register(net(1), node(1), t0, 1).unwrap();
    let b = r.register(net(1), node(2), t0, 1).unwrap();
    let c = r.register(net(2), node(3), t0, 1).unwrap();
    let _sa = r.open_stream(&a.session).unwrap();
    let mut sb = r.open_stream(&b.session).unwrap();
    let _sc = r.open_stream(&c.session).unwrap();

    assert_eq!(r.forward(&a.session, &node(2), b"hello", t0), Ok(()));
    let ev = events(&drain(&mut sb).await);
    assert_eq!(ev[0].0, "forward");
    assert!(ev[0].1.contains(&node(1).to_base32()));
    assert!(ev[0].1.contains(&base32::encode(b"hello")));

    assert_eq!(
        r.forward(&a.session, &node(3), b"x", t0),
        Err(ForwardError::NotOnline)
    );
    assert_eq!(
        r.forward(&a.session, &node(9), b"x", t0),
        Err(ForwardError::NotOnline)
    );
    assert_eq!(
        r.forward(&[7; 32], &node(2), b"x", t0),
        Err(ForwardError::Session)
    );
    let d = r.register(net(1), node(4), t0, 1).unwrap();
    let _ = d;
    assert_eq!(
        r.forward(&a.session, &node(4), b"x", t0),
        Err(ForwardError::NotOnline)
    );
}

#[tokio::test(start_paused = true)]
async fn sender_rate_and_session_volume_are_limited() {
    let limits = Limits {
        sender_bytes_per_second: 100.0,
        sender_bytes_burst: 4096.0,
        session_bytes: 6000,
        ..Limits::default()
    };
    let r = registry(limits);
    let t0 = Instant::now();
    let a = r.register(net(1), node(1), t0, 1).unwrap();
    let b = r.register(net(1), node(2), t0, 1).unwrap();
    let _sb = r.open_stream(&b.session).unwrap();
    let msg = vec![0u8; 4096];
    assert!(r.forward(&a.session, &node(2), &msg, t0).is_ok());
    let Err(ForwardError::Limit(e)) = r.forward(&a.session, &node(2), &msg, t0) else {
        panic!("expected a limit");
    };
    assert!(e.retry_after >= 1);
    let later = t0 + Duration::from_secs(60);
    assert!(matches!(
        r.forward(&a.session, &node(2), &msg, later),
        Err(ForwardError::Limit(_))
    ));
    assert!(r.forward(&a.session, &node(2), &msg[..1000], later).is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_slow_reader_is_disconnected_and_its_grace_period_starts() {
    let r = registry(Limits::default());
    let t0 = Instant::now();
    let a = r.register(net(1), node(1), t0, 1).unwrap();
    let _slow = r.open_stream(&a.session).unwrap();
    for i in 0..(STREAM_QUEUE as u8 + 4) {
        let _ = r.register(net(1), node(10 + i), t0, 1);
    }
    assert_eq!(r.stats().streams, 0);
    r.sweep(t0 + GRACE);
    assert!(r.lookup(&a.session).is_err());
}

#[tokio::test(start_paused = true)]
async fn listing_is_sorted_paged_and_excludes_the_caller() {
    let r = registry(Limits {
        registrations_per_network: 1000,
        ..Limits::default()
    });
    let t0 = Instant::now();
    let me = r.register(net(1), node(0), t0, 5).unwrap();
    for i in 1..=255u8 {
        r.register(net(1), node(i), t0, 6).unwrap();
    }
    for i in 0..3u8 {
        let mut k = [0u8; 32];
        k[0] = 255;
        k[1] = i + 1;
        r.register(net(1), NodePublic::from_bytes(k), t0, 6)
            .unwrap();
    }
    let mut k = [0xab; 32];
    k[31] = 1;
    let stranger = NodePublic::from_bytes(k);
    r.register(net(2), stranger, t0, 6).unwrap();

    let (page, truncated) = r.members(&me.session, None).unwrap();
    assert_eq!(page.len(), MEMBERS_PAGE);
    assert!(truncated);
    assert!(page.windows(2).all(|w| w[0].node < w[1].node));
    assert!(page.iter().all(|m| m.node != node(0) && m.node != stranger));
    let (rest, truncated) = r
        .members(&me.session, Some(&page.last().unwrap().node))
        .unwrap();
    assert!(!truncated);
    assert_eq!(page.len() + rest.len(), 258);
    assert!(rest.iter().all(|m| m.node != stranger));
    assert!(r.member(&me.session, &node(200)).unwrap().is_some());
    assert!(r.member(&me.session, &stranger).unwrap().is_none());
    assert!(r.member(&[1; 32], &node(1)).is_err());
}

#[tokio::test(start_paused = true)]
async fn caps_refuse_new_registrations_but_not_replacements() {
    let limits = Limits {
        max_registrations: 3,
        max_networks: 2,
        registrations_per_network: 2,
        max_event_streams: 1,
        ..Limits::default()
    };
    let r = registry(limits);
    let t0 = Instant::now();
    let a = r.register(net(1), node(1), t0, 1).unwrap();
    r.register(net(1), node(2), t0, 1).unwrap();
    assert_eq!(r.register(net(1), node(3), t0, 1), Err(Full));
    let c = r.register(net(2), node(4), t0, 1).unwrap();
    assert_eq!(r.register(net(3), node(5), t0, 1), Err(Full));
    assert!(r.register(net(1), node(1), t0, 1).is_ok());
    assert_eq!(r.stats().registrations, 3);
    assert!(r.lookup(&a.session).is_err());
    let _s = r.open_stream(&c.session).unwrap();
    let again = r.register(net(1), node(2), t0, 1).unwrap();
    assert_eq!(r.open_stream(&again.session).err(), Some(OpenError::Full));
}
