//! Vectors of vv-09 and vv-10 (`09-mdns.json`, `10-same-host.json`) and vv-01 §5.4.

mod common;

use common::*;
use vardevall_proto::discovery::mdns::*;
use vardevall_proto::keys::base32;
use vardevall_proto::keys::*;

#[test]
fn tags_of_vv01() {
    let doc = load("01-keys.json");
    for v in group(&doc, "mdns_tags") {
        let i = &v["input"];
        let o = &v["output"];
        let net = NetworkSecret::from_bytes(h32(&i["net_sk"]));
        let node = NodePublic::from_bytes(h32(&i["node_pk"]));
        let w = window(i["unix_time_seconds"].as_u64().unwrap());
        assert_eq!(w, o["window"].as_u64().unwrap());
        assert_eq!(
            to_hex(&w.to_le_bytes()),
            o["window_bytes"].as_str().unwrap()
        );
        assert_eq!(net.mdns_key().to_vec(), hv(&o["mdns_key"]));
        assert_eq!(net_tag(&net, w).to_vec(), hv(&o["net_tag"]));
        assert_eq!(node_tag(&net, &node, w).to_vec(), hv(&o["node_tag"]));
        assert_eq!(
            base32::encode(&net_tag(&net, w)),
            o["net_tag_base32"].as_str().unwrap()
        );
        assert_eq!(
            base32::encode(&node_tag(&net, &node, w)),
            o["node_tag_base32"].as_str().unwrap()
        );
    }
}

#[test]
fn announcement() {
    let doc = load("09-mdns.json");
    for v in group(&doc, "mdns_announcement") {
        let i = &v["input"];
        let o = &v["output"];
        let net = NetworkSecret::from_bytes(h32(&i["net_sk"]));
        let node = NodePublic::from_bytes(h32(&i["node_pk"]));
        let nonce: [u8; 24] = hv(&i["seal_nonce"]).try_into().unwrap();
        let a = Announcement::new(
            &net,
            &node,
            i["unix_time_seconds"].as_u64().unwrap(),
            &nonce,
            i["port"].as_u64().unwrap() as u16,
        );
        assert_eq!(a.window, o["window"].as_u64().unwrap());
        assert_eq!(a.instance(), o["instance"].as_str().unwrap());
        assert_eq!(
            a.service_instance_name(),
            o["service_instance_name"].as_str().unwrap()
        );
        let want: Vec<&str> = o["txt_strings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert_eq!(a.txt_strings().to_vec(), want);
        assert_eq!(to_hex(&a.txt_rdata()), o["txt_rdata"].as_str().unwrap());
        assert_eq!(
            to_hex(&a.sealed),
            to_hex(&base32::decode(&want[3][2..]).unwrap())
        );
        assert_eq!(open_sealed(&net, a.window, &a.sealed), Some(node));
        assert_eq!(open_sealed(&net, a.window + 1, &a.sealed), None);
        let tags = parse_txt(&want).unwrap();
        assert_eq!(tags, parse_txt(&a.txt_strings()).unwrap());
    }
}

#[test]
fn matching() {
    let doc = load("09-mdns.json");
    let m = &group(&doc, "mdns_matching")[0];
    let i = &m["input"];
    let net = NetworkSecret::from_bytes(h32(&i["net_sk"]));
    let alice = NodePublic::from_bytes(h32(&i["alice_pk"]));
    let bob = NodePublic::from_bytes(h32(&i["bob_pk"]));
    let w = i["w"].as_u64().unwrap();
    for (window_name, tags) in m["output"]["windows"].as_object().unwrap() {
        let w_n: u64 = window_name.parse().unwrap();
        assert!((w - 1..=w + 1).contains(&w_n));
        assert_eq!(net_tag(&net, w_n).to_vec(), hv(&tags["net_tag"]));
        assert_eq!(
            node_tag(&net, &alice, w_n).to_vec(),
            hv(&tags["alice_node_tag"])
        );
        assert_eq!(
            node_tag(&net, &bob, w_n).to_vec(),
            hv(&tags["bob_node_tag"])
        );
    }
    let table = TagTable::new(&net, &[bob], false, w * 3600 + 17);
    let t = |window: u64, node: &NodePublic, sealed: &[u8]| Tags {
        n: base32::encode(&net_tag(&net, window)),
        k: base32::encode(&node_tag(&net, node, window)),
        p: base32::encode(sealed),
    };
    let nonce = [3u8; 24];
    let ann = Announcement::new(&net, &alice, w * 3600, &nonce, 1);
    for window in [w - 1, w, w + 1] {
        assert_eq!(table.matches(&t(window, &bob, &[])), Some(Match::Peer(bob)));
        assert_eq!(
            table.matches(&t(window, &alice, &ann.sealed)),
            None,
            "members are off"
        );
    }
    assert_eq!(table.matches(&t(w + 2, &bob, &[])), None);
    assert_eq!(table.matches(&t(w - 2, &bob, &[])), None);

    let members = TagTable::new(&net, &[bob], true, w * 3600);
    assert_eq!(
        members.matches(&ann.registry_entry().tags()),
        Some(Match::Member(alice))
    );
    let mut stale = ann.registry_entry().tags();
    stale.n = base32::encode(&net_tag(&net, w + 1));
    assert_eq!(
        members.matches(&stale),
        None,
        "p opens only with the matching window"
    );

    for v in group(&doc, "mdns_matching").iter().skip(1) {
        let i = &v["input"];
        let net = NetworkSecret::from_bytes(h32(&i["net_sk"]));
        let sealed = hv(&i["sealed"]);
        let opened = open_sealed(&net, i["window"].as_u64().unwrap(), &sealed);
        match v["output"].get("node_pk") {
            Some(pk) => assert_eq!(
                opened.unwrap().as_bytes().to_vec(),
                hv(pk),
                "{}",
                v["description"]
            ),
            None => assert!(opened.is_none(), "{}", v["description"]),
        }
    }
}

#[test]
fn registry() {
    let doc = load("10-same-host.json");
    for v in group(&doc, "registry_entry") {
        let i = &v["input"];
        let o = &v["output"];
        let net = NetworkSecret::from_bytes(h32(&i["net_sk"]));
        let node = NodePublic::from_bytes(h32(&i["node_pk"]));
        let nonce: [u8; 24] = hv(&i["seal_nonce"]).try_into().unwrap();
        let a = Announcement::new(
            &net,
            &node,
            i["unix_time_seconds"].as_u64().unwrap(),
            &nonce,
            i["port"].as_u64().unwrap() as u16,
        );
        let entry = a.registry_entry();
        assert_eq!(entry.file_name(), o["file_name"].as_str().unwrap());
        assert_eq!(entry.to_json(), o["content_json"].as_str().unwrap());
        assert_eq!(
            RegistryEntry::parse(entry.to_json().as_bytes()).unwrap(),
            entry
        );
        assert!(entry.is_current(entry.window) && entry.is_current(entry.window + 1));
        assert!(entry.is_current(entry.window.saturating_sub(1)));
        assert!(!entry.is_current(entry.window + 2));
        assert!(!entry.is_current(entry.window - 2));
        let content = &o["content"];
        assert_eq!(entry.n, content["n"].as_str().unwrap());
        assert_eq!(entry.p, content["p"].as_str().unwrap());
    }
}

#[test]
fn registry_rejects_garbage() {
    assert!(RegistryEntry::parse(b"{}").is_err());
    assert!(RegistryEntry::parse(br#"{"v":1,"window":1,"n":"","k":"","p":"","port":1}"#).is_err());
    assert!(
        RegistryEntry::parse(br#"{"v":0,"window":1,"n":"","k":"","p":"","port":70000}"#).is_err()
    );
    assert!(parse_txt(&["v=1", "n=a", "k=b", "p=c"]).is_none());
    assert!(parse_txt(&["n=a", "k=b", "p=c"]).is_none());
}

#[test]
fn registry_rejects_non_base32_instance_key() {
    let entry = |k: &str| format!(r#"{{"v":0,"window":1,"n":"a","k":"{k}","p":"a","port":1}}"#);
    assert!(RegistryEntry::parse(entry("abcdefghijklmnopqrstuvwxyz").as_bytes()).is_ok());
    assert!(RegistryEntry::parse(entry("aaaaaaaaaaaaaaaéaaaaaaaaaaa").as_bytes()).is_err());
    assert!(RegistryEntry::parse(entry("AAAA-1").as_bytes()).is_err());
}

#[test]
fn registry_window_extremes_do_not_overflow() {
    let entry = RegistryEntry {
        window: u64::MAX,
        n: String::new(),
        k: String::new(),
        p: String::new(),
        port: 1,
    };
    assert!(entry.is_current(u64::MAX));
    assert!(!entry.is_current(0));
    let low = RegistryEntry { window: 0, ..entry };
    assert!(!low.is_current(u64::MAX));
}
