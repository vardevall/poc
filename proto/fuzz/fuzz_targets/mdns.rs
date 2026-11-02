#![no_main]

use libfuzzer_sys::fuzz_target;
use vardevall_proto::keys::{NetworkSecret, NodePublic};
use vardevall_proto::discovery::mdns::{self, TagTable, Tags};

fuzz_target!(|data: &[u8]| {
    let _ = mdns::RegistryEntry::parse(data);
    let Ok(text) = core::str::from_utf8(data) else { return };
    let strings: Vec<&str> = text.split('\n').collect();
    let _ = mdns::parse_txt(&strings);
    let net = NetworkSecret::from_bytes([4; 32]);
    let table = TagTable::new(&net, &[NodePublic::from_bytes([8; 32])], true, 1_789_300_000);
    if let [n, k, p] = strings[..] {
        let _ = table.matches(&Tags { n: n.to_owned(), k: k.to_owned(), p: p.to_owned() });
    }
});
