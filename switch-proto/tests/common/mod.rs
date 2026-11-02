#![allow(dead_code)]

use serde_json::Value;

pub fn load(name: &str) -> Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap()
}

pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn h32(v: &Value) -> [u8; 32] {
    hex(v.as_str().unwrap()).try_into().unwrap()
}

pub fn hv(v: &Value) -> Vec<u8> {
    hex(v.as_str().unwrap())
}

pub fn group<'a>(doc: &'a Value, name: &str) -> &'a Vec<Value> {
    doc[name]
        .as_array()
        .unwrap_or_else(|| panic!("no group {name}"))
}
