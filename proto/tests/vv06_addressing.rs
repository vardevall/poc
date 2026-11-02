//! Vectors of vv-06 (`06-addressing-dns.json`) and the derivations of vv-01 §5.6–§5.7.

mod common;

use common::*;
use vardevall_proto::addr::*;
use vardevall_proto::keys::{NetworkId, NodePublic};

#[test]
fn prefix_and_iid() {
    let doc = load("01-keys.json");
    for v in group(&doc, "overlay_prefix_and_iid") {
        let nid = NetworkId::from_bytes(h32(&v["input"]["network_id"]));
        let o = &v["output"];
        assert_eq!(ula_prefix(&nid).to_vec(), hv(&o["ula_prefix"]));
        for who in ["alice", "bob"] {
            let pk = NodePublic::from_bytes(h32(&v["input"][format!("{who}_pk")]));
            assert_eq!(iid(&nid, &pk).to_vec(), hv(&o[format!("{who}_iid")]));
        }
    }
}

#[test]
fn addresses() {
    let doc = load("06-addressing-dns.json");
    for v in group(&doc, "addresses") {
        let nid = NetworkId::from_bytes(h32(&v["input"]["network_id"]));
        let pk = NodePublic::from_bytes(h32(&v["input"]["node_pk"]));
        let a = OverlayAddrs::derive(&nid, &pk);
        let o = &v["output"];
        assert_eq!(a.iid.to_vec(), hv(&o["iid"]));
        assert_eq!(a.ula.octets().to_vec(), hv(&o["ula"]));
        assert_eq!(a.ula.to_string(), o["ula_text"].as_str().unwrap());
        assert_eq!(a.link_local.octets().to_vec(), hv(&o["link_local"]));
        assert_eq!(
            a.link_local.to_string(),
            o["link_local_text"].as_str().unwrap()
        );
    }
}

#[test]
fn hostnames() {
    let doc = load("06-addressing-dns.json");
    for v in group(&doc, "hostname_sanitisation") {
        let got = sanitise_hostname(v["input"]["hostname"].as_str().unwrap());
        assert_eq!(
            got.as_deref(),
            v["output"]["name"].as_str(),
            "{}",
            v["description"]
        );
    }
}

#[test]
fn labels() {
    let doc = load("06-addressing-dns.json");
    for v in group(&doc, "name_labels") {
        let got = is_valid_label(v["input"]["label"].as_str().unwrap());
        assert_eq!(
            got,
            v["output"]["valid"].as_bool().unwrap(),
            "{}",
            v["description"]
        );
    }
}

#[test]
fn ptr_and_resolution() {
    let doc = load("06-addressing-dns.json");
    for v in group(&doc, "ptr_names") {
        let nid = NetworkId::from_bytes(h32(&v["input"]["network_id"]));
        let o = &v["output"];
        if let Some(pk) = v["input"].get("node_pk") {
            let pk = NodePublic::from_bytes(h32(pk));
            let domain = v["input"]["domain"].as_str().unwrap();
            let mut table = NameTable::new(nid, domain, false);
            table.add_key(pk);
            if let Some(name) = v["input"]["configured_name"].as_str() {
                assert!(table.add_name(name, pk));
            }
            let ula = OverlayAddrs::derive(&nid, &pk).ula;
            assert_eq!(ula.octets().to_vec(), hv(&o["ula"]));
            assert_eq!(ptr_name(&ula), o["ptr_query_name"].as_str().unwrap());
            assert_eq!(
                table.answer(o["ptr_query_name"].as_str().unwrap(), QueryType::Ptr),
                Answer::Ptr(o["ptr_answer"].as_str().unwrap().to_owned())
            );
            let by_id = o["aaaa_query_name_by_key_id"].as_str().unwrap();
            assert_eq!(table.answer(by_id, QueryType::Aaaa), Answer::Aaaa(ula));
            assert_eq!(table.resolve(by_id), Some(pk));
        } else {
            assert_eq!(ula_prefix(&nid).to_vec(), hv(&o["ula_prefix"]));
            assert_eq!(reverse_zone(&nid), o["reverse_zone"].as_str().unwrap());
        }
    }
}

#[test]
fn resolver_policy() {
    let doc = load("06-addressing-dns.json");
    let v = &group(&doc, "ptr_names")[0];
    let nid = NetworkId::from_bytes(h32(&v["input"]["network_id"]));
    let pk = NodePublic::from_bytes(h32(&v["input"]["node_pk"]));
    let mut t = NameTable::new(nid, "home.internal", false);
    t.add_name("nas", pk);
    assert_eq!(t.resolve("NAS.home.internal."), Some(pk));
    assert_eq!(t.resolve("nas"), Some(pk));
    assert_eq!(t.name(&pk), Some("nas"));
    assert_eq!(
        t.answer("other.home.internal", QueryType::Aaaa),
        Answer::NxDomain
    );
    assert_eq!(t.answer("example.org", QueryType::Aaaa), Answer::Refused);
    assert_eq!(
        t.answer("nas.home.internal", QueryType::Other),
        Answer::NoData
    );
    let f = NameTable::new(nid, "home.internal", true);
    assert_eq!(
        f.answer("other.home.internal", QueryType::Aaaa),
        Answer::Forward
    );
}

#[test]
fn reserved_iids() {
    assert!(is_reserved_iid(&[0; 8]));
    assert!(is_reserved_iid(&[
        0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    ]));
    assert!(is_reserved_iid(&[
        0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80
    ]));
    assert!(!is_reserved_iid(&[
        0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    ]));
    // Above the anycast range: not reserved.
    assert!(!is_reserved_iid(&[0xfe, 0, 0, 0, 0, 0, 0, 0]));
    assert!(!is_reserved_iid(&[0xff; 8]));
    assert!(!is_reserved_iid(&[
        0x6d, 0x0a, 0x8b, 0xf2, 0x5e, 0xcf, 0x91, 0xdd
    ]));
}
