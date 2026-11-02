#![no_main]

use libfuzzer_sys::fuzz_target;
use vardevall_proto::addr::{self, NameTable, QueryType};
use vardevall_proto::keys::{NetworkId, NodePublic};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else { return };
    if let Some(name) = addr::sanitise_hostname(text) {
        assert!(addr::is_valid_label(&name));
    }
    let _ = addr::parse_ptr_name(text);
    let mut table = NameTable::new(NetworkId::from_bytes([2; 32]), "home.internal", false);
    table.add_name("nas", NodePublic::from_bytes([3; 32]));
    let _ = table.resolve(text);
    let _ = table.answer(text, QueryType::Aaaa);
    let _ = table.answer(text, QueryType::Ptr);
});
