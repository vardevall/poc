//! Vectors of vv-01 (`01-keys.json`).

mod common;

use common::*;
use vardevall_proto::keys::crypto;
use vardevall_proto::keys::*;
use vardevall_proto::{error::EncodingError, keys::base32};

#[test]
fn base32_encode() {
    let doc = load("01-keys.json");
    for v in group(&doc, "base32_encode") {
        let bytes = hv(&v["input"]["bytes"]);
        let text = base32::encode(&bytes);
        assert_eq!(
            text,
            v["output"]["text"].as_str().unwrap(),
            "{}",
            v["description"]
        );
        assert_eq!(text.len() as u64, v["output"]["length"].as_u64().unwrap());
    }
}

#[test]
fn base32_decode() {
    let doc = load("01-keys.json");
    for v in group(&doc, "base32_decode") {
        let text = v["input"]["text"].as_str().unwrap();
        let res = match v["input"]["fixed_size"].as_u64() {
            Some(32) => base32::decode_array::<32>(text).map(|a| a.to_vec()),
            Some(n) => panic!("unsupported size {n}"),
            None => base32::decode(text),
        };
        if v["output"]["valid"].as_bool().unwrap() {
            assert_eq!(
                res.unwrap(),
                hv(&v["output"]["bytes"]),
                "{}",
                v["description"]
            );
        } else {
            assert!(res.is_err(), "{}", v["description"]);
        }
    }
}

#[test]
fn base32_errors_are_distinct() {
    assert_eq!(base32::decode("m"), Err(EncodingError::InvalidLength));
    assert_eq!(base32::decode("mz"), Err(EncodingError::TrailingBits));
    assert_eq!(base32::decode("m0"), Err(EncodingError::InvalidCharacter));
}

#[test]
fn x25519() {
    let doc = load("01-keys.json");
    for v in group(&doc, "x25519") {
        let sk = h32(&v["input"]["sk"]);
        let out = &v["output"];
        match v["input"].get("pk") {
            None => assert_eq!(
                crypto::dh_pub(&sk).to_vec(),
                hv(&out["pk"]),
                "{}",
                v["description"]
            ),
            Some(pk) => {
                let res = crypto::dh(&sk, &h32(pk));
                if out["valid"].as_bool().unwrap() {
                    assert_eq!(
                        res.unwrap().to_vec(),
                        hv(&out["dh"]),
                        "{}",
                        v["description"]
                    );
                } else {
                    assert!(res.is_err(), "{}", v["description"]);
                }
            }
        }
    }
}

#[test]
fn ed_to_x_pub() {
    let doc = load("01-keys.json");
    for v in group(&doc, "ed_to_x_pub") {
        let res = crypto::ed_to_x_pub(&h32(&v["input"]["A"]));
        if v["output"]["valid"].as_bool().unwrap() {
            assert_eq!(
                res.unwrap().to_vec(),
                hv(&v["output"]["u"]),
                "{}",
                v["description"]
            );
        } else {
            assert!(res.is_err(), "{}", v["description"]);
        }
    }
}

#[test]
fn ed_to_x_sec() {
    let doc = load("01-keys.json");
    for v in group(&doc, "ed_to_x_sec") {
        let seed = h32(&v["input"]["seed"]);
        let o = &v["output"];
        assert_eq!(crypto::ed_public(&seed).to_vec(), hv(&o["A"]));
        let x_sk = crypto::ed_to_x_sec(&seed);
        assert_eq!(x_sk.to_vec(), hv(&o["x_sk"]));
        assert_eq!(crypto::dh_pub(&x_sk).to_vec(), hv(&o["DH_PUB(x_sk)"]));
        assert_eq!(
            crypto::ed_to_x_pub(&h32(&o["A"])).unwrap().to_vec(),
            hv(&o["DH_PUB(x_sk)"])
        );
    }
}

#[test]
fn network_keys_and_derivations() {
    let doc = load("01-keys.json");
    for v in group(&doc, "network_keys") {
        let net = NetworkSecret::from_bytes(h32(&v["input"]["net_sk"]));
        assert_eq!(net.dh_secret().to_vec(), hv(&v["output"]["net_dh_sk"]));
        assert_eq!(net.public().as_bytes().to_vec(), hv(&v["output"]["net_pk"]));
    }
    for v in group(&doc, "network_psk") {
        let net = NetworkSecret::from_bytes(h32(&v["input"]["net_sk"]));
        assert_eq!(net.psk().to_vec(), hv(&v["output"]["psk1"]));
    }
    for v in group(&doc, "handshake_mac_keys") {
        let net = NetworkSecret::from_bytes(h32(&v["input"]["net_sk"]));
        let r = NodePublic::from_bytes(h32(&v["input"]["R"]));
        assert_eq!(net.mac1_key(&r).to_vec(), hv(&v["output"]["mac1_key"]));
        assert_eq!(net.cookie_key(&r).to_vec(), hv(&v["output"]["cookie_key"]));
    }
}

#[test]
fn key_id_and_text_forms() {
    let doc = load("01-keys.json");
    for v in group(&doc, "key_id") {
        let pk = NodePublic::from_bytes(h32(&v["input"]["node_pk"]));
        assert_eq!(pk.key_id(), v["output"]["key_id"].as_str().unwrap());
        assert_eq!(pk.to_string().parse::<NodePublic>().unwrap(), pk);
    }
}

#[test]
fn secrets_do_not_print() {
    let net = NetworkSecret::from_bytes([7; 32]);
    assert!(!format!("{net:?}").contains("aaa"));
}

#[test]
fn switch_key_spki_round_trip() {
    let key = SwitchPublic::from_bytes([9; 32]);
    let spki = key.to_spki();
    assert_eq!(spki.len(), 44);
    assert_eq!(&spki[..4], &[0x30, 0x2a, 0x30, 0x05]);
    assert_eq!(SwitchPublic::from_spki(&spki), Some(key));
    assert_eq!(SwitchPublic::from_spki(&spki[..43]), None);
    let mut other = spki;
    other[8] ^= 1;
    assert_eq!(SwitchPublic::from_spki(&other), None);
}
