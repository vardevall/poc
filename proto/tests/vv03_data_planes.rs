//! Vectors of vv-03 (`03-data-planes.json`): demultiplexing and data frames.

mod common;

use common::*;
use vardevall_proto::plane::frame::*;

fn class_name(c: Class) -> &'static str {
    match c {
        Class::StunTurn => "stun-turn",
        Class::HandshakeFragment => "handshake-fragment",
        Class::CookieReply => "cookie-reply",
        Class::DataFrame => "data-frame",
        Class::TurnChannelData => "turn-channeldata",
        Class::Drop | Class::SwitchHandshake => "drop",
    }
}

#[test]
fn demux() {
    let doc = load("03-data-planes.json");
    for v in group(&doc, "demux") {
        let b = v["input"]["first_byte"].as_u64().unwrap() as u8;
        let turn = v["input"]["from_turn_server_with_allocation"]
            .as_bool()
            .unwrap();
        assert_eq!(
            class_name(classify(b, turn)),
            v["output"]["class"].as_str().unwrap(),
            "{}",
            v["description"]
        );
    }
    for b in 0..=255u8 {
        let c = classify_forwarded(b);
        assert_eq!(c == Class::SwitchHandshake, b == 10 || b == 11);
    }
}

#[test]
fn data_frames() {
    let doc = load("03-data-planes.json");
    for v in group(&doc, "data_frames") {
        let i = &v["input"];
        let o = &v["output"];
        if let Some(frame) = i.get("frame") {
            let key = h32(&i["frame_key"]);
            let f = hv(frame);
            let h = parse_header(&f).unwrap();
            assert_eq!(
                u64::from(h.receiver_index),
                o["receiver_index"].as_u64().unwrap()
            );
            assert_eq!(h.counter, o["counter"].as_u64().unwrap());
            assert_eq!(open(&key, &f).unwrap(), hv(&o["plaintext"]));
            continue;
        }
        let key = h32(&i["frame_key"]);
        let idx = i["receiver_index"].as_u64().unwrap() as u32;
        let counter = i["counter"].as_u64().unwrap();
        let plaintext = match i.get("ipv6_packet") {
            Some(p) => {
                let padded = pad(&hv(p), i["mtu"].as_u64().unwrap() as usize);
                assert_eq!(
                    to_hex(&padded),
                    o["plaintext"].as_str().unwrap(),
                    "{}",
                    v["description"]
                );
                assert_eq!(unpad(&padded).unwrap(), hv(p).as_slice());
                padded
            }
            None => i.get("plaintext").map(hv).unwrap_or_default(),
        };
        let frame = seal(&key, idx, counter, &plaintext);
        if let Some(f) = o.get("frame") {
            assert_eq!(to_hex(&frame), f.as_str().unwrap(), "{}", v["description"]);
            if let Some(l) = o.get("length") {
                assert_eq!(frame.len() as u64, l.as_u64().unwrap());
            }
        }
        if let Some(n) = o.get("nonce") {
            assert_eq!(
                to_hex(&vardevall_proto::keys::crypto::aead_nonce(counter)),
                n.as_str().unwrap()
            );
        }
        assert_eq!(open(&key, &frame).unwrap(), plaintext);
    }
}
