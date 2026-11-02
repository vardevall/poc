//! Properties of the parsers: no panics on arbitrary input, and round trips.

mod common;

use common::sim::*;
use proptest::prelude::*;
use vardevall_proto::addr;
use vardevall_proto::discovery::candidate::{self, Candidate};
use vardevall_proto::discovery::mdns;
use vardevall_proto::handshake::message;
use vardevall_proto::handshake::payload::{self, Hello};
use vardevall_proto::keys::base32;
use vardevall_proto::plane::frame;

fn candidate_strategy() -> impl Strategy<Value = Candidate> {
    (
        prop::bool::ANY,
        any::<[u8; 16]>(),
        any::<[u8; 4]>(),
        1u16..=u16::MAX,
        prop::bool::ANY,
    )
        .prop_map(|(v6, a6, a4, port, relay)| {
            let ip: std::net::IpAddr = if v6 { a6.into() } else { a4.into() };
            let addr = std::net::SocketAddr::new(ip, port);
            if relay {
                Candidate::relay(addr)
            } else {
                Candidate::punch(addr)
            }
        })
}

proptest! {
    #[test]
    fn base32_round_trips(data in proptest::collection::vec(any::<u8>(), 0..100)) {
        let text = base32::encode(&data);
        prop_assert_eq!(base32::decode(&text).unwrap(), data.clone());
        prop_assert_eq!(base32::decode(&text.to_uppercase()).unwrap(), data);
    }

    #[test]
    fn base32_accepts_only_canonical_encodings(text in "[a-z2-7]{0,60}") {
        if let Ok(bytes) = base32::decode(&text) {
            prop_assert_eq!(base32::encode(&bytes), text);
        }
    }

    #[test]
    fn parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..3000)) {
        let _ = payload::decode_msg1(&data);
        let _ = payload::decode_msg2(&data);
        let _ = candidate::decode_list(&data);
        let _ = message::parse_message1(&data);
        let _ = message::parse_message2(&data);
        let _ = message::parse_fragment(&data);
        let _ = message::parse_cookie_reply(&data);
        let _ = frame::parse_header(&data);
        let _ = frame::unpad(&data);
        let _ = mdns::RegistryEntry::parse(&data);
    }

    #[test]
    fn text_parsers_never_panic(s in "\\PC{0,200}") {
        let _ = base32::decode(&s);
        let _ = candidate::parse_addr(&s);
        let _ = addr::sanitise_hostname(&s);
        let _ = addr::parse_ptr_name(&s);
        if let Some(name) = addr::sanitise_hostname(&s) {
            prop_assert!(addr::is_valid_label(&name));
        }
        let _ = mdns::parse_txt(&[s.as_str()]);
    }

    #[test]
    fn json_with_arbitrary_structure_never_panics(s in "[\\[\\]{}\",:0-9a-z\\\\ .eE+-]{0,200}") {
        let _ = payload::decode_msg1(s.as_bytes());
        let _ = candidate::decode_list(s.as_bytes());
    }

    #[test]
    fn payload_round_trips(
        ts in any::<u64>(),
        cands in proptest::collection::vec(candidate_strategy(), 0..8),
    ) {
        let hello = Hello {
            candidates: cands,
            exit: None,
        };
        let bytes = payload::encode_msg1(ts, &hello, payload::MAX_PAYLOAD_1);
        prop_assert!(bytes.len() <= payload::MAX_PAYLOAD_1);
        let (ts2, got) = payload::decode_msg1(&bytes).unwrap();
        prop_assert_eq!(ts2, ts);
        prop_assert_eq!(&got.candidates[..], &hello.candidates[..got.candidates.len()]);
        let bytes2 = payload::encode_msg2(&hello, payload::MAX_PAYLOAD_2);
        let got2 = payload::decode_msg2(&bytes2).unwrap();
        prop_assert_eq!(&got2.candidates[..], &hello.candidates[..got2.candidates.len()]);
    }

    #[test]
    fn candidate_lists_round_trip(cands in proptest::collection::vec(candidate_strategy(), 0..8)) {
        let text = candidate::encode_list(&cands);
        prop_assert_eq!(candidate::decode_list(text.as_bytes()).unwrap(), cands);
    }

    #[test]
    fn padded_packets_unpad_to_the_original(payload_len in 0usize..1200, mtu in 1280usize..1500) {
        let packet = ipv6("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap(), &vec![7u8; payload_len]);
        prop_assume!(packet.len() <= mtu);
        let padded = frame::pad(&packet, mtu);
        prop_assert!(padded.len() <= mtu && (padded.len().is_multiple_of(16) || padded.len() == mtu));
        prop_assert_eq!(frame::unpad(&padded).unwrap(), &packet[..]);
    }

    #[test]
    fn frames_round_trip_and_reject_modification(
        key in any::<[u8; 32]>(),
        index in any::<u32>(),
        counter in 0u64..u64::MAX - 100,
        plaintext in proptest::collection::vec(any::<u8>(), 0..200),
        flip in any::<prop::sample::Index>(),
    ) {
        let f = frame::seal(&key, index, counter, &plaintext);
        let h = frame::parse_header(&f).unwrap();
        prop_assert_eq!((h.receiver_index, h.counter), (index, counter));
        prop_assert_eq!(frame::open(&key, &f).unwrap(), plaintext);
        let at = flip.index(f.len());
        if at >= 8 {
            let mut bad = f.clone();
            bad[at] ^= 1;
            prop_assert!(frame::open(&key, &bad).is_err());
        }
    }

    #[test]
    fn registry_entries_round_trip(window in any::<u32>(), port in any::<u16>(), n in "[a-z2-7]{26}", k in "[a-z2-7]{26}", p in "[a-z2-7]{116}") {
        let e = mdns::RegistryEntry { window: u64::from(window), n, k, p, port };
        prop_assert_eq!(mdns::RegistryEntry::parse(e.to_json().as_bytes()).unwrap(), e);
    }
}

fn first_flight() -> (Pair, Vec<Wire>) {
    let mut p = Pair::new();
    let pkt = ipv6(p.nodes[0].ula(), p.nodes[1].ula(), &[5; 16]);
    p.send(0, &pkt);
    let wires = p.collect();
    (p, wires)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn a_modified_message_1_fragment_is_never_accepted(which in 0usize..2, at in any::<prop::sample::Index>(), bit in 0u8..8) {
        let (mut p, mut wires) = first_flight();
        let len = wires[which].data.len();
        let pos = at.index(len);
        wires[which].data[pos] ^= 1 << bit;
        for w in wires {
            p.deliver(w);
        }
        p.pump();
        let tolerated = pos >= len - 16;
        let established = p.nodes[1].ups();
        prop_assert_eq!(established, usize::from(tolerated), "byte {} of fragment {}", pos, which);
    }

    #[test]
    fn a_modified_message_2_fragment_is_never_accepted(which in 0usize..2, at in any::<prop::sample::Index>(), bit in 0u8..8) {
        let (mut p, wires) = first_flight();
        for w in wires {
            p.deliver(w);
        }
        let mut wires = p.collect();
        wires.retain(|w| w.from == 1);
        let len = wires[which].data.len();
        let pos = at.index(len);
        wires[which].data[pos] ^= 1 << bit;
        for w in wires {
            p.deliver(w);
        }
        p.pump();
        let tolerated = pos >= len - 16;
        let established = p.nodes[0].ups();
        prop_assert_eq!(established, usize::from(tolerated), "byte {} of fragment {}", pos, which);
    }
}
