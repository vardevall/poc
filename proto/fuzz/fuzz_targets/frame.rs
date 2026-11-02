#![no_main]

use libfuzzer_sys::fuzz_target;
use vardevall_proto::ip::source;
use vardevall_proto::plane::frame;

fuzz_target!(|data: &[u8]| {
    let _ = frame::parse_header(data);
    let _ = frame::open(&[3u8; 32], data);
    if let Ok(packet) = frame::unpad(data) {
        let _ = source::ipv6_source(packet);
    }
    if let Some(&b) = data.first() {
        let _ = frame::classify(b, data.len() % 2 == 0);
        let _ = frame::classify_forwarded(b);
    }
    let padded = frame::pad(data, 1280);
    assert!(padded.len() >= data.len());
});
