//! No panics on arbitrary input in the switch parsers.

use proptest::prelude::*;
use vardevall_switch_proto::api;

proptest! {

    #[test]
    fn parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..3000)) {
        let _ = api::parse_register_response(&data);
        let _ = api::parse_challenge_response(&data);
        let _ = api::parse_info(&data);
        let _ = api::parse_members_page(&data);
        let _ = api::parse_event("forward", &data);
        let _ = api::parse_event("online", &data);
        let _ = api::verify_challenge(&[0; 32], &data, 0);
    }
}
