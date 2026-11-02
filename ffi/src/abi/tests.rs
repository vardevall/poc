use super::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Sink {
    batches: Mutex<Vec<Vec<Vec<u8>>>>,
    events: Mutex<Vec<String>>,
    mdns: Mutex<Vec<String>>,
    stop_on_event: AtomicPtr<VvHandle>,
}

unsafe extern "C" fn on_packets(
    ctx: *mut c_void,
    packets: *const *const u8,
    lens: *const usize,
    n: usize,
) {
    let s = unsafe { &*(ctx as *const Sink) };
    let batch = (0..n)
        .map(|i| unsafe { std::slice::from_raw_parts(*packets.add(i), *lens.add(i)) }.to_vec())
        .collect();
    s.batches.lock().unwrap().push(batch);
}

unsafe extern "C" fn on_event(ctx: *mut c_void, j: *const c_char) {
    let s = unsafe { &*(ctx as *const Sink) };
    s.events
        .lock()
        .unwrap()
        .push(unsafe { CStr::from_ptr(j) }.to_str().unwrap().to_owned());
    let h = s.stop_on_event.swap(ptr::null_mut(), Ordering::SeqCst);
    if !h.is_null() {
        unsafe { vv_stop(h) };
    }
}

unsafe extern "C" fn on_mdns(ctx: *mut c_void, j: *const c_char) {
    let s = unsafe { &*(ctx as *const Sink) };
    s.mdns
        .lock()
        .unwrap()
        .push(unsafe { CStr::from_ptr(j) }.to_str().unwrap().to_owned());
}

fn sample() -> CString {
    CString::new(format!(
        "[interface]\nprivate_key = \"{}\"\nnetwork_secret = \"{}\"\nlisten_port = 0\n",
        keys::generate_node_key(),
        keys::generate_network_secret()
    ))
    .unwrap()
}

fn wait(mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

fn started(sink: &Sink) -> bool {
    sink.events
        .lock()
        .unwrap()
        .iter()
        .any(|e| e.contains("\"started\""))
}

#[test]
fn key_helpers() {
    unsafe {
        let mut err = ptr::null_mut();
        let sk = vv_generate_node_key(&mut err);
        let ns = vv_generate_network_secret(&mut err);
        assert!(!sk.is_null() && !ns.is_null() && err.is_null());
        let pk = vv_public_key(sk, &mut err);
        assert!(!pk.is_null());
        for p in [pk, sk, ns] {
            vv_string_free(p);
        }
        let bad = CString::new("nope").unwrap();
        assert!(vv_public_key(bad.as_ptr(), &mut err).is_null());
        assert!(!err.is_null());
        vv_string_free(err);
    }
}

#[test]
fn settings_and_validation() {
    let cfg = sample();
    unsafe {
        let mut err = ptr::null_mut();
        let s = vv_tunnel_settings(cfg.as_ptr(), &mut err);
        assert!(!s.is_null());
        let v: serde_json::Value =
            serde_json::from_str(CStr::from_ptr(s).to_str().unwrap()).unwrap();
        assert_eq!(v["mtu"], 1280);
        assert_eq!(v["routes"][0]["prefix"], 64);
        assert_eq!(v["dns"]["match_domains"][0], "vardevall.internal");
        vv_string_free(s);
        let s = vv_validate_config(cfg.as_ptr(), &mut err);
        assert!(!s.is_null());
        vv_string_free(s);
        assert!(vv_validate_config(ptr::null(), ptr::null_mut()).is_null());
    }
}

#[test]
fn start_requests_mdns_and_stops_cleanly() {
    let cfg = sample();
    let sink = Box::new(Sink::default());
    let ctx = &*sink as *const Sink as *mut c_void;
    unsafe {
        let h = vv_start(
            cfg.as_ptr(),
            Some(on_packets),
            Some(on_event),
            Some(on_mdns),
            ctx,
            ptr::null_mut(),
        );
        assert!(!h.is_null());
        assert!(wait(|| started(&sink)));
        assert!(wait(|| {
            let m = sink.mdns.lock().unwrap();
            m.iter().any(|r| r.contains("\"browse\""))
                && m.iter().any(|r| r.contains("\"register\""))
        }));
        let found = CString::new(r#"{"op":"lost","instance":"x"}"#).unwrap();
        vv_mdns_event(h, found.as_ptr());
        let metered =
            CString::new(r#"{"metered":true,"interfaces":[{"name":"pdp_ip0","metered":true}]}"#)
                .unwrap();
        let broken = CString::new("{").unwrap();
        vv_path_changed(h, metered.as_ptr());
        vv_path_changed(h, broken.as_ptr());
        vv_path_changed(h, ptr::null());
        vv_stop(h);
        let counts = (
            sink.events.lock().unwrap().len(),
            sink.mdns.lock().unwrap().len(),
        );
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            counts,
            (
                sink.events.lock().unwrap().len(),
                sink.mdns.lock().unwrap().len()
            )
        );
    }
}

#[test]
fn stop_from_inside_a_callback() {
    let cfg = sample();
    let sink = Box::new(Sink::default());
    let ctx = &*sink as *const Sink as *mut c_void;
    unsafe {
        let h = vv_start(
            cfg.as_ptr(),
            Some(on_packets),
            Some(on_event),
            None,
            ctx,
            ptr::null_mut(),
        );
        assert!(!h.is_null());
        sink.stop_on_event.store(h, Ordering::SeqCst);
        assert!(wait(|| sink.stop_on_event.load(Ordering::SeqCst).is_null()));
        std::thread::sleep(Duration::from_millis(100));
        let n = sink.events.lock().unwrap().len();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(n, sink.events.lock().unwrap().len());
    }
}

#[test]
fn services_roundtrip() {
    let cfg = sample();
    let sink = Box::new(Sink::default());
    let ctx = &*sink as *const Sink as *mut c_void;
    unsafe {
        let h = vv_start(
            cfg.as_ptr(),
            Some(on_packets),
            Some(on_event),
            None,
            ctx,
            ptr::null_mut(),
        );
        assert!(!h.is_null());
        assert!(wait(|| started(&sink)));
        let name = CString::new("web").unwrap();
        let tcp = CString::new("tcp").unwrap();
        let mut err = ptr::null_mut();
        assert_eq!(
            vv_announce(h, ptr::null(), name.as_ptr(), 8080, tcp.as_ptr(), &mut err),
            0
        );
        assert!(err.is_null());
        let bad = CString::new("sctp").unwrap();
        assert_eq!(
            vv_announce(h, ptr::null(), name.as_ptr(), 8080, bad.as_ptr(), &mut err),
            -1
        );
        assert!(!err.is_null());
        vv_string_free(err);
        err = ptr::null_mut();
        assert_eq!(
            vv_announce(h, ptr::null(), name.as_ptr(), 0, tcp.as_ptr(), &mut err),
            -1
        );
        vv_string_free(err);
        let p = vv_providers(h, ptr::null(), name.as_ptr(), ptr::null_mut());
        assert!(!p.is_null());
        let v: serde_json::Value =
            serde_json::from_str(CStr::from_ptr(p).to_str().unwrap()).unwrap();
        assert!(v.is_array());
        vv_string_free(p);
        assert_eq!(vv_withdraw(h, ptr::null(), name.as_ptr()), 1);
        assert_eq!(vv_withdraw(h, ptr::null(), name.as_ptr()), 0);
        assert_eq!(vv_withdraw(h, ptr::null(), ptr::null()), 0);
        let path = CString::new(r#"{"changed":true,"families":["v6"]}"#).unwrap();
        vv_path_changed(h, path.as_ptr());
        vv_stop(h);
    }
}

/// An echo request to an overlay address nobody has, whose body starts with `id`; the node
/// answers it with an ICMPv6 error that quotes it.
fn probe(own: std::net::Ipv6Addr, id: u8) -> Vec<u8> {
    let mut o = own.octets();
    o[15] ^= 0xff;
    o[14] ^= 0x55;
    vardevall_tun::packet::build_icmpv6(&own, &o.into(), 128, 0, &[id, 0, 0, 1], 64)
}

/// The `id` of the probe an error quotes.
fn answered(reply: &[u8]) -> u8 {
    assert_eq!((reply[40], reply[41]), (1, 3));
    reply[92]
}

fn replies(sink: &Sink) -> Vec<u8> {
    let batches = sink.batches.lock().unwrap();
    batches.iter().flatten().map(|p| answered(p)).collect()
}

#[test]
fn batches_in_give_batches_out_in_order() {
    let cfg = sample();
    let own = Config::parse(cfg.to_str().unwrap(), &Context::default())
        .unwrap()
        .own_addrs()
        .ula;
    let sink = Box::new(Sink::default());
    let ctx = &*sink as *const Sink as *mut c_void;
    let send = |h: *mut VvHandle, ids: &[u8]| {
        let packets: Vec<Vec<u8>> = ids.iter().map(|&i| probe(own, i)).collect();
        let ptrs: Vec<*const u8> = packets.iter().map(|p| p.as_ptr()).collect();
        let lens: Vec<usize> = packets.iter().map(Vec::len).collect();
        unsafe { vv_packets_in(h, ptrs.as_ptr(), lens.as_ptr(), ids.len()) };
    };
    unsafe {
        let h = vv_start(
            cfg.as_ptr(),
            Some(on_packets),
            Some(on_event),
            None,
            ctx,
            ptr::null_mut(),
        );
        assert!(!h.is_null());
        assert!(wait(|| started(&sink)));

        send(h, &[0, 1, 2, 3, 4]);
        assert!(wait(|| replies(&sink).len() == 5));
        assert_eq!(replies(&sink), [0, 1, 2, 3, 4]);

        let ids: Vec<u8> = (0..200).collect();
        send(h, &ids);
        assert!(wait(|| replies(&sink).len() == 205));
        assert_eq!(replies(&sink)[5..], ids);
        let sizes: Vec<usize> = sink.batches.lock().unwrap().iter().map(Vec::len).collect();
        assert!(sizes.iter().all(|&n| (1..=64).contains(&n)), "{sizes:?}");

        vv_stop(h);
    }
}

#[test]
fn empty_and_null_batches_are_harmless() {
    let cfg = sample();
    let own = Config::parse(cfg.to_str().unwrap(), &Context::default())
        .unwrap()
        .own_addrs()
        .ula;
    let sink = Box::new(Sink::default());
    let ctx = &*sink as *const Sink as *mut c_void;
    unsafe {
        let h = vv_start(
            cfg.as_ptr(),
            Some(on_packets),
            Some(on_event),
            None,
            ctx,
            ptr::null_mut(),
        );
        assert!(!h.is_null());
        assert!(wait(|| started(&sink)));

        let (p0, p2) = (probe(own, 10), probe(own, 12));
        let ptrs = [p0.as_ptr(), ptr::null(), p2.as_ptr()];
        let lens = [p0.len(), 0, p2.len()];
        vv_packets_in(ptr::null_mut(), ptrs.as_ptr(), lens.as_ptr(), 3);
        vv_packets_in(h, ptr::null(), lens.as_ptr(), 3);
        vv_packets_in(h, ptrs.as_ptr(), ptr::null(), 3);
        vv_packets_in(h, ptrs.as_ptr(), lens.as_ptr(), 0);
        vv_packets_in(h, ptr::null(), ptr::null(), 0);
        let empty = [0u8; 0];
        vv_packets_in(h, [empty.as_ptr()].as_ptr(), [0usize].as_ptr(), 1);
        std::thread::sleep(Duration::from_millis(100));
        assert!(replies(&sink).is_empty());

        vv_packets_in(h, ptrs.as_ptr(), lens.as_ptr(), 3);
        assert!(wait(|| replies(&sink).len() == 2));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(replies(&sink), [10, 12]);

        vv_stop(h);
    }
}

/// The names and configs of networks, and the arrays that point to them.
struct Set {
    names: Vec<CString>,
    configs: Vec<CString>,
}

impl Set {
    fn new(names: &[&str]) -> Set {
        Set {
            names: names.iter().map(|n| CString::new(*n).unwrap()).collect(),
            configs: names.iter().map(|_| sample()).collect(),
        }
    }

    fn pointers(&self) -> (Vec<*const c_char>, Vec<*const c_char>) {
        let ptrs = |v: &Vec<CString>| v.iter().map(|c| c.as_ptr()).collect();
        (ptrs(&self.names), ptrs(&self.configs))
    }
}

fn events_of(sink: &Sink, network: &str) -> Vec<serde_json::Value> {
    sink.events
        .lock()
        .unwrap()
        .iter()
        .map(|e| serde_json::from_str::<serde_json::Value>(e).unwrap())
        .filter(|e| e["network"] == network)
        .collect()
}

#[test]
fn two_networks_start_together_and_announce_separately() {
    let set = Set::new(&["home", "work"]);
    let (names, configs) = set.pointers();
    let sink = Box::new(Sink::default());
    let ctx = &*sink as *const Sink as *mut c_void;
    unsafe {
        let mut err = ptr::null_mut();
        let h = vv_start_networks(
            names.as_ptr(),
            configs.as_ptr(),
            2,
            Some(on_packets),
            Some(on_event),
            Some(on_mdns),
            ctx,
            &mut err,
        );
        assert!(!h.is_null() && err.is_null());
        assert!(wait(|| ["home", "work"].iter().all(|n| {
            events_of(&sink, n)
                .iter()
                .any(|e| e["type"] == "status" && e["state"] == "started")
        })));
        assert!(wait(|| {
            let m = sink.mdns.lock().unwrap();
            m.iter().filter(|r| r.contains("\"register\"")).count() == 2
        }));
        let browses = |sink: &Sink| {
            let m = sink.mdns.lock().unwrap();
            m.iter().filter(|r| r.contains("\"browse\"")).count()
        };
        assert_eq!(browses(&sink), 1);

        let db = CString::new("db").unwrap();
        let tcp = CString::new("tcp").unwrap();
        let work = CString::new("work").unwrap();
        let nowhere = CString::new("nowhere").unwrap();
        assert_eq!(
            vv_announce(h, work.as_ptr(), db.as_ptr(), 5432, tcp.as_ptr(), &mut err),
            0
        );
        assert_eq!(
            vv_announce(
                h,
                nowhere.as_ptr(),
                db.as_ptr(),
                5432,
                tcp.as_ptr(),
                &mut err
            ),
            -1
        );
        assert!(!err.is_null());
        vv_string_free(err);
        assert_eq!(vv_withdraw(h, ptr::null(), db.as_ptr()), 0);
        assert_eq!(vv_withdraw(h, work.as_ptr(), db.as_ptr()), 1);
        let p = vv_providers(h, nowhere.as_ptr(), db.as_ptr(), ptr::null_mut());
        assert!(p.is_null());
        let p = vv_providers(h, work.as_ptr(), db.as_ptr(), ptr::null_mut());
        assert!(!p.is_null());
        vv_string_free(p);

        vv_stop(h);
        let count = sink.events.lock().unwrap().len();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(count, sink.events.lock().unwrap().len());
        let m = sink.mdns.lock().unwrap();
        assert_eq!(
            m.iter().filter(|r| r.contains("\"stop_browse\"")).count(),
            1
        );
    }
}

#[test]
fn networks_are_checked_before_they_start() {
    let set = Set::new(&["home", "Home"]);
    let (names, configs) = set.pointers();
    let sink = Box::new(Sink::default());
    let ctx = &*sink as *const Sink as *mut c_void;
    unsafe {
        let start = |names: *const *const c_char, configs: *const *const c_char, n: usize| {
            let mut err = ptr::null_mut();
            let h = vv_start_networks(
                names,
                configs,
                n,
                Some(on_packets),
                Some(on_event),
                None,
                ctx,
                &mut err,
            );
            assert!(h.is_null());
            assert!(!err.is_null());
            vv_string_free(err);
        };
        start(names.as_ptr(), configs.as_ptr(), 2);
        start(names.as_ptr(), configs.as_ptr(), 0);
        start(names.as_ptr(), configs.as_ptr(), 9);
        start(ptr::null(), configs.as_ptr(), 2);
        start(names.as_ptr(), ptr::null(), 2);
        let same = Set {
            names: vec![CString::new("a").unwrap(), CString::new("b").unwrap()],
            configs: vec![sample(), sample()],
        };
        let (n, _) = same.pointers();
        let twice = [same.configs[0].as_ptr(), same.configs[0].as_ptr()];
        start(n.as_ptr(), twice.as_ptr(), 2);
    }
}

#[test]
fn settings_of_a_set_merge() {
    let set = Set::new(&["home", "work"]);
    let (names, configs) = set.pointers();
    unsafe {
        let mut err = ptr::null_mut();
        let s = vv_tunnel_settings_networks(names.as_ptr(), configs.as_ptr(), 2, &mut err);
        assert!(!s.is_null() && err.is_null());
        let v: serde_json::Value =
            serde_json::from_str(CStr::from_ptr(s).to_str().unwrap()).unwrap();
        assert_eq!(v["addrs"].as_array().unwrap().len(), 4);
        assert_eq!(v["routes"].as_array().unwrap().len(), 2);
        assert_eq!(v["dns"]["servers"].as_array().unwrap().len(), 1);
        assert_eq!(v["dns"]["match_domains"][0], "home.internal");
        assert_eq!(v["dns"]["match_domains"][2], "work.internal");
        vv_string_free(s);
        let none = vv_tunnel_settings_networks(names.as_ptr(), configs.as_ptr(), 0, &mut err);
        assert!(none.is_null());
        vv_string_free(err);
    }
}

#[test]
fn the_exit_is_chosen_by_network_and_site_and_turned_off_and_on() {
    let set = Set::new(&["home", "work"]);
    let (names, configs) = set.pointers();
    let sink = Box::new(Sink::default());
    let ctx = &*sink as *const Sink as *mut c_void;
    let home = CString::new("home").unwrap();
    let nowhere = CString::new("nowhere").unwrap();
    let site = CString::new("it/home").unwrap();
    let bad = CString::new("italy/home").unwrap();
    unsafe {
        let mut err = ptr::null_mut();
        let h = vv_start_networks(
            names.as_ptr(),
            configs.as_ptr(),
            2,
            Some(on_packets),
            Some(on_event),
            None,
            ctx,
            &mut err,
        );
        assert!(!h.is_null() && err.is_null());

        assert_eq!(vv_set_exit(h, nowhere.as_ptr(), ptr::null(), &mut err), -1);
        assert_eq!(
            CStr::from_ptr(err).to_str().unwrap(),
            "no network named \"nowhere\""
        );
        vv_string_free(err);
        err = ptr::null_mut();
        assert_eq!(vv_set_exit(h, home.as_ptr(), bad.as_ptr(), &mut err), -1);
        assert!(!err.is_null());
        vv_string_free(err);
        err = ptr::null_mut();
        assert_eq!(
            vv_set_exit(ptr::null_mut(), home.as_ptr(), ptr::null(), &mut err),
            -1
        );
        vv_string_free(err);

        for (network, site) in [
            (home.as_ptr(), ptr::null()),
            (ptr::null(), ptr::null()),
            (home.as_ptr(), site.as_ptr()),
            (ptr::null(), site.as_ptr()),
            (home.as_ptr(), ptr::null()),
        ] {
            err = ptr::null_mut();
            assert_eq!(vv_set_exit(h, network, site, &mut err), 0);
            assert!(err.is_null());
        }
        vv_stop(h);
    }
}

#[test]
fn no_exit_is_in_use_until_one_is_chosen_and_live() {
    let set = Set::new(&["home", "work"]);
    let (names, configs) = set.pointers();
    let sink = Box::new(Sink::default());
    let ctx = &*sink as *const Sink as *mut c_void;
    let home = CString::new("home").unwrap();
    unsafe {
        let mut err = ptr::null_mut();
        let h = vv_start_networks(
            names.as_ptr(),
            configs.as_ptr(),
            2,
            Some(on_packets),
            Some(on_event),
            None,
            ctx,
            &mut err,
        );
        assert!(!h.is_null() && err.is_null());
        let in_use = |h| {
            let s = vv_exit_in_use(h, ptr::null_mut());
            assert!(!s.is_null());
            let text = CStr::from_ptr(s).to_str().unwrap().to_owned();
            vv_string_free(s);
            text
        };
        assert_eq!(in_use(h), "null");
        assert_eq!(vv_set_exit(h, home.as_ptr(), ptr::null(), &mut err), 0);
        assert_eq!(in_use(h), "null", "no peer offers a site");
        assert!(vv_exit_in_use(ptr::null_mut(), &mut err).is_null());
        vv_string_free(err);
        vv_stop(h);
    }
}

#[test]
fn remembered_exits_are_taken_by_a_network_and_bad_ones_refused() {
    let set = Set::new(&["home", "work"]);
    let (names, configs) = set.pointers();
    let sink = Box::new(Sink::default());
    let ctx = &*sink as *const Sink as *mut c_void;
    let work = CString::new("work").unwrap();
    let nowhere = CString::new("nowhere").unwrap();
    let key = vardevall_tun::keys::public_key(&vardevall_tun::keys::generate_node_key()).unwrap();
    let good = CString::new(format!(r#"[{{"key":"{key}","site":"it/home"}}]"#)).unwrap();
    let bad = CString::new(r#"[{"key":"x","site":"it"}]"#).unwrap();
    unsafe {
        let mut err = ptr::null_mut();
        let h = vv_start_networks(
            names.as_ptr(),
            configs.as_ptr(),
            2,
            Some(on_packets),
            Some(on_event),
            None,
            ctx,
            &mut err,
        );
        assert!(!h.is_null() && err.is_null());
        assert_eq!(
            vv_remember_exits(h, ptr::null(), good.as_ptr(), &mut err),
            0
        );
        assert_eq!(
            vv_remember_exits(h, work.as_ptr(), good.as_ptr(), &mut err),
            0
        );
        assert!(err.is_null());
        for (net, json) in [
            (nowhere.as_ptr(), good.as_ptr()),
            (work.as_ptr(), bad.as_ptr()),
        ] {
            assert_eq!(vv_remember_exits(h, net, json, &mut err), -1);
            assert!(!err.is_null());
            vv_string_free(err);
            err = ptr::null_mut();
        }
        assert_eq!(
            vv_remember_exits(ptr::null_mut(), ptr::null(), good.as_ptr(), &mut err),
            -1
        );
        vv_string_free(err);
        vv_stop(h);
    }
}

#[test]
fn the_summary_says_whether_the_file_forwards() {
    let plain = sample();
    let forwarding = CString::new(format!(
        "{}forward = [\"9.9.9.9:53\"]\n",
        plain.to_str().unwrap()
    ))
    .unwrap();
    for (cfg, forwards) in [(plain, false), (forwarding, true)] {
        unsafe {
            let s = vv_validate_config(cfg.as_ptr(), ptr::null_mut());
            assert!(!s.is_null());
            let v: serde_json::Value =
                serde_json::from_str(CStr::from_ptr(s).to_str().unwrap()).unwrap();
            assert_eq!(v["forward"], forwards);
            let home: std::net::Ipv4Addr = v["ipv4_home"].as_str().unwrap().parse().unwrap();
            assert_eq!(home.octets()[..1], [198]);
            vv_string_free(s);
        }
    }
}
