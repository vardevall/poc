#![no_main]

use libfuzzer_sys::fuzz_target;
use vardevall_proto::{discovery::candidate, handshake::payload};

fuzz_target!(|data: &[u8]| {
    if let Ok((_, hello)) = payload::decode_msg1(data) {
        let again = payload::encode_msg1(1, &hello, payload::MAX_PAYLOAD_1);
        assert!(payload::decode_msg1(&again).is_ok());
    }
    let _ = payload::decode_msg2(data);
    if let Ok(list) = candidate::decode_list(data) {
        assert!(list.len() <= candidate::MAX_CANDIDATES);
        let encoded = candidate::encode_list(&list);
        assert_eq!(candidate::decode_list(encoded.as_bytes()).unwrap(), list);
    }
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = candidate::parse_addr(text);
    }
});
