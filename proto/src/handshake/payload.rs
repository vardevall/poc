//! Handshake payloads (vv-02 §3.3).

use crate::discovery::candidate::{self, Candidate, MAX_CANDIDATES};
use crate::error::ParseError;
use crate::handshake::message::{MIN_MESSAGE1, MIN_MESSAGE2};
use crate::ip::exit::ExitOffer;
use crate::json::{self, Value};

/// Largest message 1 payload over UDP (vv-02 §5.1).
pub const MAX_PAYLOAD_1: usize = 620;
/// Largest message 2 payload over UDP (vv-02 §5.1).
pub const MAX_PAYLOAD_2: usize = 664;

/// The size a message 1 payload is padded to when the peer is held by key.
pub const PADDED_PAYLOAD_1: usize = 256;
/// Largest message 2 payload answering a padded message 1 over a fragmented framing: a reply may
/// be 44 bytes larger than the payload it answers.
pub const REPLY_PAYLOAD_2: usize = PADDED_PAYLOAD_1 + MIN_MESSAGE1 - MIN_MESSAGE2;

/// What a handshake message tells the peer about the sender.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Hello {
    /// Shareable candidates, `punch` and `relay` only.
    pub candidates: Vec<Candidate>,
    /// The sender's exit offer, if it makes one to this peer.
    pub exit: Option<ExitOffer>,
}

/// Encodes a message 1 payload, dropping trailing candidates until it fits `limit` bytes; an
/// offer that does not fit alone is left out.
pub fn encode_msg1(ts: u64, hello: &Hello, limit: usize) -> Vec<u8> {
    encode(Some(ts), hello, limit, 0).0
}

/// Like [`encode_msg1`], also returning how many candidates the payload carries.
pub fn encode_msg1_counted(ts: u64, hello: &Hello, limit: usize) -> (Vec<u8>, usize) {
    encode(Some(ts), hello, limit, 0)
}

/// Like [`encode_msg1_counted`], padding the payload with JSON whitespace to `pad` bytes; a
/// longer one is left as it is.
pub fn encode_msg1_padded(ts: u64, hello: &Hello, limit: usize, pad: usize) -> (Vec<u8>, usize) {
    encode(Some(ts), hello, limit, pad)
}

/// Encodes a message 2 payload, dropping trailing candidates until it fits `limit` bytes; an
/// offer that does not fit alone is left out.
pub fn encode_msg2(hello: &Hello, limit: usize) -> Vec<u8> {
    encode(None, hello, limit, 0).0
}

/// Like [`encode_msg2`], also returning how many candidates the payload carries.
pub fn encode_msg2_counted(hello: &Hello, limit: usize) -> (Vec<u8>, usize) {
    encode(None, hello, limit, 0)
}

fn encode(ts: Option<u64>, hello: &Hello, limit: usize, pad: usize) -> (Vec<u8>, usize) {
    let exit = hello.exit.as_ref().map(ExitOffer::encode);
    let body = |exit: Option<&str>, n: usize| {
        let mut members: Vec<String> = Vec::new();
        if let Some(ts) = ts {
            members.push(format!("\"ts\":\"{ts}\""));
        }
        if let Some(exit) = exit {
            members.push(format!("\"exit\":{exit}"));
        }
        if n > 0 {
            members.push(format!(
                "\"cand\":{}",
                candidate::encode_list(&hello.candidates[..n])
            ));
        }
        format!("{{{}}}", members.join(","))
    };
    let mut exit = exit.as_deref();
    if exit.is_some_and(|e| body(Some(e), 0).len() > limit) {
        exit = None;
    }
    let mut n = hello.candidates.len().min(MAX_CANDIDATES);
    loop {
        let mut s = body(exit, n);
        if s.len() <= limit || n == 0 {
            let room = pad.min(limit).saturating_sub(s.len());
            s.extend(std::iter::repeat_n(' ', room));
            return (s.into_bytes(), n);
        }
        n -= 1;
    }
}

fn parse_hello(v: &Value) -> Hello {
    let candidates = v.get("cand").map(candidate::usable).unwrap_or_default();
    let exit = v.get("exit").and_then(ExitOffer::decode);
    Hello { candidates, exit }
}

/// Decodes a message 1 payload into its `ts` and hello.
pub fn decode_msg1(bytes: &[u8]) -> Result<(u64, Hello), ParseError> {
    let v = json::parse(bytes)?;
    if !matches!(v, Value::Object(_)) {
        return Err(ParseError::Json);
    }
    let ts = parse_ts(
        v.get("ts")
            .and_then(Value::as_str)
            .ok_or(ParseError::Field)?,
    )?;
    Ok((ts, parse_hello(&v)))
}

/// Decodes a message 2 payload.
pub fn decode_msg2(bytes: &[u8]) -> Result<Hello, ParseError> {
    let v = json::parse(bytes)?;
    if !matches!(v, Value::Object(_)) {
        return Err(ParseError::Json);
    }
    Ok(parse_hello(&v))
}

fn parse_ts(s: &str) -> Result<u64, ParseError> {
    let b = s.as_bytes();
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) || (b.len() > 1 && b[0] == b'0') {
        return Err(ParseError::Field);
    }
    s.parse().map_err(|_| ParseError::Field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let hello = Hello {
            candidates: vec![Candidate::punch("[2001:db8::7]:51820".parse().unwrap())],
            exit: None,
        };
        let bytes = encode_msg1(1789300000123456789, &hello, MAX_PAYLOAD_1);
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            r#"{"ts":"1789300000123456789","cand":[{"kind":"punch","addr":"[2001:db8::7]:51820"}]}"#
        );
        assert_eq!(decode_msg1(&bytes).unwrap(), (1789300000123456789, hello));
    }

    #[test]
    fn payloads_without_candidates() {
        let hello = Hello::default();
        assert_eq!(encode_msg1(5, &hello, MAX_PAYLOAD_1), br#"{"ts":"5"}"#);
        assert_eq!(encode_msg2(&hello, MAX_PAYLOAD_2), b"{}");
        assert_eq!(decode_msg2(b"{}").unwrap(), hello);
    }

    #[test]
    fn rejects_bad_ts() {
        for ts in ["", "01", "-1", "18446744073709551616", "1.0", " 1"] {
            let p = format!("{{\"ts\":\"{ts}\"}}");
            assert!(decode_msg1(p.as_bytes()).is_err(), "{ts}");
        }
        assert!(decode_msg1(br#"{"ts":5}"#).is_err());
    }

    #[test]
    fn unknown_members_are_ignored() {
        let (_, h) =
            decode_msg1(br#"{"ts":"1","planes":["tun","x"],"exit":{"a":1},"zz":null}"#).unwrap();
        assert_eq!(h, Hello::default());
    }

    #[test]
    fn candidates_are_trimmed_to_fit() {
        let c = Candidate::relay(
            "[2001:db8:1234:5678:9abc:def0:1234:5678]:51820"
                .parse()
                .unwrap(),
        );
        let hello = Hello {
            candidates: vec![c; 8],
            exit: None,
        };
        let bytes = encode_msg1(u64::MAX, &hello, MAX_PAYLOAD_1);
        assert!(bytes.len() <= MAX_PAYLOAD_1);
        assert!(decode_msg1(&bytes).unwrap().1.candidates.len() < 8);
    }

    #[test]
    fn padding_reaches_the_size_asked_and_never_cuts() {
        let hello = Hello::default();
        let (bytes, _) = encode_msg1_padded(5, &hello, MAX_PAYLOAD_1, PADDED_PAYLOAD_1);
        assert_eq!(bytes.len(), PADDED_PAYLOAD_1);
        assert_eq!(decode_msg1(&bytes).unwrap(), (5, hello));
        let c = Candidate::relay(
            "[2001:db8:1234:5678:9abc:def0:1234:5678]:51820"
                .parse()
                .unwrap(),
        );
        let long = Hello {
            candidates: vec![c; 5],
            exit: None,
        };
        let plain = encode_msg1(5, &long, MAX_PAYLOAD_1);
        assert!(plain.len() > PADDED_PAYLOAD_1);
        let (bytes, _) = encode_msg1_padded(5, &long, MAX_PAYLOAD_1, PADDED_PAYLOAD_1);
        assert_eq!(bytes, plain, "a longer payload is left as it is");
    }

    #[test]
    fn padding_leaves_the_largest_candidates_and_offer_within_the_limit() {
        let c = Candidate::relay(
            "[2001:db8:1234:5678:9abc:def0:1234:5678]:51820"
                .parse()
                .unwrap(),
        );
        let hello = Hello {
            candidates: vec![c; MAX_CANDIDATES],
            exit: None,
        };
        let (bytes, _) = encode_msg1_padded(u64::MAX, &hello, MAX_PAYLOAD_1, PADDED_PAYLOAD_1);
        assert!(bytes.len() <= MAX_PAYLOAD_1);
        assert!(bytes.len() >= PADDED_PAYLOAD_1);
    }
}
