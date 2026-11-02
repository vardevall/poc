#![no_main]

use libfuzzer_sys::fuzz_target;
use vardevall_proto::handshake::message;

fuzz_target!(|data: &[u8]| {
    let _ = message::parse_message1(data);
    let _ = message::parse_message2(data);
    let _ = message::parse_cookie_reply(data);
    if let Ok(f) = message::parse_fragment(data) {
        let key = [7u8; 32];
        let _ = f.mac1_valid(&key);
        let _ = f.mac2_valid(&key);
    }
    let _ = message::verify_mac1(data, &[1u8; 32]);
});
