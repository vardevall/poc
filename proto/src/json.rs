//! A strict JSON reader and compact writer for the I-JSON profile of vv-01 §3.3.

use core::fmt;

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};

use crate::error::ParseError;

const MAX_DEPTH: usize = 16;

/// A parsed JSON value.
pub use serde_json::Value;

/// Builds a [`Value`] and rejects an object with a repeated member name at any depth.
struct Unique(usize);

impl<'de> DeserializeSeed<'de> for Unique {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        if self.0 > MAX_DEPTH {
            return Err(D::Error::custom("nesting too deep"));
        }
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Unique {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }

    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }

    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number out of range"))
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Unique(self.0 + 1))? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = serde_json::Map::new();
        while let Some(name) = map.next_key::<String>()? {
            if members.contains_key(&name) {
                return Err(A::Error::custom("duplicate member name"));
            }
            let value = map.next_value_seed(Unique(self.0 + 1))?;
            members.insert(name, value);
        }
        Ok(Value::Object(members))
    }
}

/// Parses `bytes` as one JSON value with no unique-name violations (vv-01 §3.3).
pub fn parse(bytes: &[u8]) -> Result<Value, ParseError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = Unique(0)
        .deserialize(&mut de)
        .map_err(|_| ParseError::Json)?;
    de.end().map_err(|_| ParseError::Json)?;
    Ok(value)
}

/// Appends `s` as a JSON string literal.
pub fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicates_and_garbage() {
        assert!(parse(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse(br#"{"a":1} x"#).is_err());
        assert!(parse(b"\xef\xbb\xbf{}").is_err());
        assert!(parse(br#"{"a":"\ud800"}"#).is_err());
        assert!(parse(br#"{"a":01}"#).is_err());
        assert!(parse(br#"{"a":{"b":1,"b":2}}"#).is_err());
        assert!(parse(br#"{"a":[{"b":1,"c":2,"b":3}]}"#).is_err());
        assert!(parse(br#"{"a":1,"\u0061":2}"#).is_err());
        assert!(parse(br#"{"a":{"b":1},"c":{"b":2}}"#).is_ok());
    }

    #[test]
    fn accepts_whitespace_padding() {
        let v = parse(b" {\"a\" : [1, \"x\\u00e9\"] }   \n").unwrap();
        assert_eq!(v.get("a").unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    fn depth_is_bounded() {
        let deep = "[".repeat(1000);
        assert!(parse(deep.as_bytes()).is_err());
    }
}
