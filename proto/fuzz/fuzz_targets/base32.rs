#![no_main]

use libfuzzer_sys::fuzz_target;
use vardevall_proto::keys::base32;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data) {
        if let Ok(bytes) = base32::decode(text) {
            assert_eq!(base32::decode(&base32::encode(&bytes)).unwrap(), bytes);
        }
        let _ = base32::decode_array::<32>(text);
    }
    assert_eq!(base32::decode(&base32::encode(data)).unwrap(), data);
});
