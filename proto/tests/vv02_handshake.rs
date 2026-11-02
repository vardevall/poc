//! Vectors of vv-02 (`02-handshake.json`).

mod common;

use common::*;
use serde_json::Value;
use vardevall_proto::handshake::message::*;
use vardevall_proto::handshake::{Initiator, LocalKeys, Responder};
use vardevall_proto::keys::crypto;
use vardevall_proto::keys::*;

fn local(sk: &Value, net: &Value) -> LocalKeys {
    LocalKeys::new(
        NodeSecret::from_bytes(h32(sk)),
        NetworkSecret::from_bytes(h32(net)),
    )
}

fn index(v: &Value) -> u32 {
    v.as_u64().unwrap() as u32
}

#[test]
fn transcripts() {
    let doc = load("02-handshake.json");
    for v in group(&doc, "transcripts") {
        let i = &v["input"];
        let o = &v["output"];
        let alice = local(&i["initiator_static_sk"], &i["net_sk"]);
        let bob = local(&i["responder_static_sk"], &i["net_sk"]);
        if let Some(pk) = i.get("initiator_static_pk") {
            assert_eq!(alice.public().as_bytes().to_vec(), hv(pk));
        }
        if let Some(psk0) = i.get("psk0") {
            assert_eq!(alice.psk0().to_vec(), hv(psk0));
        }
        let psk2 = PairPsk::from_bytes(h32(&i["psk2"]));
        let (index_i, index_r) = (
            index(&i["initiator_sender_index"]),
            index(&i["responder_sender_index"]),
        );

        let mut rng_i = ScriptedRng::new(&[
            &hv(&i["initiator_ephemeral_sk"]),
            &hv(&i["kem_keygen_d"]),
            &hv(&i["kem_keygen_z"]),
        ]);
        let (initiator, message1) = Initiator::start(
            &mut rng_i,
            &alice,
            bob.public(),
            index_i,
            &hv(&i["payload1"]),
        )
        .unwrap();
        assert!(rng_i.exhausted());
        assert_eq!(
            to_hex(&message1),
            o["message1"].as_str().unwrap(),
            "{}",
            v["description"]
        );
        assert_eq!(
            message1.len() as u64,
            o["message1_length"]
                .as_u64()
                .unwrap_or(message1.len() as u64)
        );

        let responder = Responder::read(&bob, &message1).unwrap();
        assert_eq!(responder.initiator(), alice.public());
        assert_eq!(responder.payload(), hv(&i["payload1"]));
        assert_eq!(responder.initiator_index(), index_i);

        let mut rng_r =
            ScriptedRng::new(&[&hv(&i["responder_ephemeral_sk"]), &hv(&i["kem_encaps_m"])]);
        let (message2, done_r) = responder
            .respond(&mut rng_r, &psk2, index_r, &hv(&i["payload2"]))
            .unwrap();
        assert!(rng_r.exhausted());
        assert_eq!(
            to_hex(&message2),
            o["message2"].as_str().unwrap(),
            "{}",
            v["description"]
        );

        let (done_i, peer_index) = initiator.finish(&alice, &psk2, &message2).unwrap();
        assert_eq!(peer_index, index_r);
        assert_eq!(done_i.payload, hv(&i["payload2"]));
        assert_eq!(done_i.handshake_hash.to_vec(), hv(&o["handshake_hash"]));
        assert_eq!(done_r.handshake_hash, done_i.handshake_hash);
        for done in [&done_i, &done_r] {
            assert_eq!(done.keys.k_i2r().to_vec(), hv(&o["k_i2r"]));
            assert_eq!(done.keys.k_r2i().to_vec(), hv(&o["k_r2i"]));
            let sk = &o["session_keys"];
            assert_eq!(done.keys.frame_i2r().to_vec(), hv(&sk["frame_i2r"]));
            assert_eq!(done.keys.frame_r2i().to_vec(), hv(&sk["frame_r2i"]));
        }
        assert_eq!(done_r.payload, hv(&i["payload1"]));

        let mut switch1 = vec![TYPE_MSG1];
        switch1.extend_from_slice(&message1);
        if let Some(d) = o.get("switch_datagram1") {
            assert_eq!(to_hex(&switch1), d.as_str().unwrap());
        }
        if let Some(d) = o.get("switch_datagram2") {
            let mut s = vec![TYPE_MSG2];
            s.extend_from_slice(&message2);
            assert_eq!(to_hex(&s), d.as_str().unwrap());
        }

        if i["psk2"] != Value::String("00".repeat(32)) {
            let resp = Responder::read(&bob, &message1).unwrap();
            assert!(
                o["message1_readable_by_responder_without_psk2"]
                    .as_bool()
                    .unwrap()
            );
            let mut rng =
                ScriptedRng::new(&[&hv(&i["responder_ephemeral_sk"]), &hv(&i["kem_encaps_m"])]);
            let (m2, _) = resp
                .respond(&mut rng, &PairPsk::none(), index_r, &hv(&i["payload2"]))
                .unwrap();
            let mut rng = ScriptedRng::new(&[
                &hv(&i["initiator_ephemeral_sk"]),
                &hv(&i["kem_keygen_d"]),
                &hv(&i["kem_keygen_z"]),
            ]);
            let (init2, _) =
                Initiator::start(&mut rng, &alice, bob.public(), index_i, &hv(&i["payload1"]))
                    .unwrap();
            assert!(
                init2.finish(&alice, &psk2, &m2).is_err(),
                "mismatched psk2 must fail"
            );
        }
    }
}

#[test]
fn fragments() {
    let doc = load("02-handshake.json");
    for v in group(&doc, "fragments") {
        let i = &v["input"];
        let message = hv(&i["message"]);
        let key: [u8; 32] = h32(&i["mac1_key"]);
        let number = if message.len() > 1690 && v["description"].as_str().unwrap().ends_with('1') {
            MessageNumber::One
        } else {
            MessageNumber::Two
        };
        let [f0, f1] =
            fragment_message(&message, number, index(&i["sender_index"]), &key, None).unwrap();
        assert_eq!(to_hex(&f0), v["output"]["fragment0"].as_str().unwrap());
        assert_eq!(to_hex(&f1), v["output"]["fragment1"].as_str().unwrap());
        assert_eq!(
            f0.len() as u64,
            v["output"]["fragment0_length"].as_u64().unwrap()
        );
        assert_eq!(
            (f0.len() + f1.len()) as u64,
            v["output"]["total_length"].as_u64().unwrap()
        );
        let p0 = parse_fragment(&f0).unwrap();
        let p1 = parse_fragment(&f1).unwrap();
        assert!(p0.mac1_valid(&key) && p1.mac1_valid(&key));
        assert_eq!([p0.data, p1.data].concat(), message);
        assert_eq!(p0.mac2, [0u8; 16]);
        assert_eq!(p0.sender_index, index(&i["sender_index"]));
    }
}

#[test]
fn cookies() {
    let doc = load("02-handshake.json");
    for v in group(&doc, "cookie") {
        let i = &v["input"];
        let o = &v["output"];
        if let Some(secret) = i.get("cookie_secret") {
            let net = NetworkSecret::from_bytes(h32(&i["net_sk"]));
            let bob = NodePublic::from_bytes(h32(&i["replying_node_pk"]));
            let mut src = hv(&i["source_ip"]);
            src.extend_from_slice(&(i["source_port"].as_u64().unwrap() as u16).to_be_bytes());
            assert_eq!(to_hex(&src), o["cookie_mac_input"].as_str().unwrap());
            let cookie: [u8; 32] = crypto::mac(&h32(secret), &[&src]);
            assert_eq!(cookie.to_vec(), hv(&o["cookie"]));
            let key = net.cookie_key(&bob);
            assert_eq!(key.to_vec(), hv(&o["cookie_key"]));
            let frags = [hv(&i["pending_fragment0"]), hv(&i["pending_fragment1"])];
            let n = i["triggering_fragment"].as_u64().unwrap() as usize;
            let trigger = parse_fragment(&frags[n]).unwrap();
            assert_eq!(trigger.mac1.to_vec(), hv(&o["ad"]));
            let nonce: [u8; 24] = hv(&i["nonce"]).try_into().unwrap();
            let reply =
                build_cookie_reply(trigger.sender_index, &nonce, &key, &cookie, &trigger.mac1);
            assert_eq!(to_hex(&reply), o["cookie_reply"].as_str().unwrap());
            let parsed = parse_cookie_reply(&reply).unwrap();
            assert_eq!(parsed.receiver_index, trigger.sender_index);
            let mut opened = None;
            for (idx, f) in frags.iter().enumerate() {
                let pf = parse_fragment(f).unwrap();
                if let Some(c) = parsed.open(&key, &pf.mac1) {
                    opened = Some((idx, c));
                    break;
                }
            }
            let (idx, c) = opened.unwrap();
            assert_eq!(
                idx as u64,
                o["opened_with_mac1_of_fragment"].as_u64().unwrap()
            );
            assert_eq!(c, cookie);
        } else {
            let alice = local(&i["initiator_static_sk"], &i["net_sk"]);
            let bob_pk = NodePublic::from_bytes(h32(&i["responder_static_pk"]));
            let mut rng = ScriptedRng::new(&[
                &hv(&i["initiator_ephemeral_sk"]),
                &hv(&i["kem_keygen_d"]),
                &hv(&i["kem_keygen_z"]),
            ]);
            let (_, message1) = Initiator::start(
                &mut rng,
                &alice,
                &bob_pk,
                index(&i["initiator_sender_index"]),
                &hv(&i["payload1"]),
            )
            .unwrap();
            assert_eq!(to_hex(&message1), o["message1"].as_str().unwrap());
            let key = alice.network().mac1_key(&bob_pk);
            let cookie = h32(&i["cookie"]);
            let [f0, f1] = fragment_message(
                &message1,
                MessageNumber::One,
                index(&i["initiator_sender_index"]),
                &key,
                Some(&cookie),
            )
            .unwrap();
            assert_eq!(to_hex(&f0), o["fragment0"].as_str().unwrap());
            assert_eq!(to_hex(&f1), o["fragment1"].as_str().unwrap());
            for f in [&f0, &f1] {
                let p = parse_fragment(f).unwrap();
                assert!(p.mac1_valid(&key) && p.mac2_valid(&cookie));
                assert!(!p.mac2_valid(&[0u8; 32]));
            }
            assert_eq!(
                to_hex(&parse_fragment(&f0).unwrap().mac2),
                o["mac2_fragment0"].as_str().unwrap()
            );
        }
    }
}

#[test]
fn mac1() {
    let doc = load("02-handshake.json");
    for v in group(&doc, "mac1") {
        let i = &v["input"];
        let net = NetworkSecret::from_bytes(h32(&i["net_sk"]));
        let recipient = NodePublic::from_bytes(h32(&i["recipient_pk"]));
        let ok = verify_mac1(&hv(&i["message"]), &net.mac1_key(&recipient));
        assert_eq!(
            ok,
            v["output"]["mac1_valid"].as_bool().unwrap(),
            "{}",
            v["description"]
        );
    }
}
