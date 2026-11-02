#![no_main]

use libfuzzer_sys::fuzz_target;
use vardevall_switch_proto::api as switch;

fuzz_target!(|data: &[u8]| {
    let _ = switch::parse_register_response(data);
    let _ = switch::parse_challenge_response(data);
    let _ = switch::parse_info(data);
    let _ = switch::parse_register_request(data);
    let _ = switch::parse_stun_response(data);
    let _ = switch::parse_turn_response(data);
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = switch::normalize_host(text);
    }
    let _ = switch::parse_members_page(data);
    let _ = switch::parse_event("forward", data);
    let _ = switch::parse_event("online", data);
    let _ = switch::parse_event("offline", data);
    let _ = switch::parse_event("replaced", data);
    let now = data.len() as u64;
    let _ = switch::verify_challenge(&[1u8; 32], data, now);
});
