//! Control messages: pings and pongs, candidate updates and the service announcements
//! (vv-03 §3.2, vve-14 §2.2).

use std::net::SocketAddr;

use crate::discovery::candidate::{self, Candidate, MAX_CANDIDATES, format_addr, parse_addr};
use crate::ip::service::{self, Service};
use crate::json::{self, Value};

/// The first byte of the plaintext of a control message (vv-03 §3.2).
pub const CONTROL_MARKER: u8 = 0;

/// A control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// "Answer on the path this arrived on": verifies the path it went out on.
    Ping {
        /// The number the pong repeats; counted per [`crate::route::paths::Paths`].
        txid: u64,
    },
    /// The answer to a ping.
    Pong {
        /// The `txid` of the ping.
        txid: u64,
        /// The source address the ping arrived from, as the responder saw it.
        observed: Option<SocketAddr>,
    },
    /// The sender's shared candidates, all of them.
    Cand {
        /// The set number, increasing with each new set.
        seq: u64,
        /// The candidates.
        cand: Vec<Candidate>,
    },
    /// The greatest `seq` of a `cand` message the sender accepted.
    CandAck {
        /// The greatest accepted `seq`.
        seq: u64,
    },
    /// The sender's services, all of them (vve-14 §2.2).
    Svc {
        /// The set number, increasing with each new set.
        seq: u64,
        /// The services.
        services: Vec<Service>,
    },
    /// The greatest `seq` of a `svc` message the sender accepted (vve-14 §2.2).
    SvcAck {
        /// The greatest accepted `seq`.
        seq: u64,
    },
}

fn decimal(out: &mut String, n: u64) {
    out.push('"');
    out.push_str(&n.to_string());
    out.push('"');
}

/// The plaintext of a control message: the byte `0x00` and a compact JSON object (vv-05 §4.9).
pub fn encode_control(message: &Control) -> Vec<u8> {
    let mut s = String::new();
    match message {
        Control::Ping { txid } => {
            s.push_str("{\"t\":\"ping\",\"id\":");
            decimal(&mut s, *txid);
            s.push('}');
        }
        Control::Pong { txid, observed } => {
            s.push_str("{\"t\":\"pong\",\"id\":");
            decimal(&mut s, *txid);
            if let Some(a) = observed {
                s.push_str(",\"obs\":");
                json::write_string(&mut s, &format_addr(a));
            }
            s.push('}');
        }
        Control::CandAck { seq } => {
            s.push_str("{\"t\":\"candack\",\"seq\":");
            decimal(&mut s, *seq);
            s.push('}');
        }
        Control::Cand { seq, cand } => {
            s.push_str("{\"t\":\"cand\",\"seq\":");
            decimal(&mut s, *seq);
            s.push_str(",\"cand\":");
            s.push_str(&candidate::encode_list(
                &cand[..cand.len().min(MAX_CANDIDATES)],
            ));
            s.push('}');
        }
        Control::Svc { seq, services } => {
            s.push_str("{\"t\":\"svc\",\"seq\":");
            decimal(&mut s, *seq);
            s.push_str(",\"svc\":");
            service::write_list(&mut s, services);
            s.push('}');
        }
        Control::SvcAck { seq } => {
            s.push_str("{\"t\":\"svcack\",\"seq\":");
            decimal(&mut s, *seq);
            s.push('}');
        }
    }
    let mut out = Vec::with_capacity(1 + s.len());
    out.push(CONTROL_MARKER);
    out.extend_from_slice(s.as_bytes());
    out
}

/// A decimal string of vv-05 §4.9: digits only, no leading zeros, below 2^64.
fn parse_decimal(v: &Value) -> Option<u64> {
    let s = v.as_str()?;
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    s.parse().ok()
}

/// Parses a plaintext that starts with `0x00`; `None` if it is not a well-formed control message,
/// which the receiver drops (vv-03 §3.2, vv-05 §4.9).
pub fn parse_control(plaintext: &[u8]) -> Option<Control> {
    let (&marker, body) = plaintext.split_first()?;
    if marker != CONTROL_MARKER {
        return None;
    }
    let v = json::parse(body).ok()?;
    if !matches!(v, Value::Object(_)) {
        return None;
    }
    match v.get("t")?.as_str()? {
        "ping" => Some(Control::Ping {
            txid: parse_decimal(v.get("id")?)?,
        }),
        "pong" => {
            let observed = match v.get("obs") {
                None => None,
                Some(a) => Some(parse_addr(a.as_str()?)?),
            };
            Some(Control::Pong {
                txid: parse_decimal(v.get("id")?)?,
                observed,
            })
        }
        "candack" => Some(Control::CandAck {
            seq: parse_decimal(v.get("seq")?)?,
        }),
        "cand" => {
            let seq = parse_decimal(v.get("seq")?)?;
            let list = v.get("cand")?;
            list.as_array()?;
            Some(Control::Cand {
                seq,
                cand: candidate::usable(list),
            })
        }
        "svc" => {
            let seq = parse_decimal(v.get("seq")?)?;
            let list = v.get("svc")?.as_array()?;
            Some(Control::Svc {
                seq,
                services: service::usable(list),
            })
        }
        "svcack" => Some(Control::SvcAck {
            seq: parse_decimal(v.get("seq")?)?,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let c = Control::Cand {
            seq: u64::MAX,
            cand: vec![
                Candidate::punch("[2001:db8::7]:1".parse().unwrap()).with_metered(true),
                Candidate::relay("198.51.100.4:2".parse().unwrap()),
            ],
        };
        assert_eq!(parse_control(&encode_control(&c)), Some(c));
        let s = Control::Svc {
            seq: 9,
            services: vec![
                Service::new("web", 443, service::Proto::Tcp).unwrap(),
                Service::new("dns", 53, service::Proto::Udp).unwrap(),
            ],
        };
        assert_eq!(parse_control(&encode_control(&s)), Some(s));
        let a = Control::SvcAck { seq: 9 };
        assert_eq!(parse_control(&encode_control(&a)), Some(a));
    }

    #[test]
    fn ping_and_pong_round_trip_with_decimal_ids() {
        let ping = Control::Ping { txid: u64::MAX };
        assert_eq!(
            encode_control(&ping),
            b"\x00{\"t\":\"ping\",\"id\":\"18446744073709551615\"}"
        );
        assert_eq!(parse_control(&encode_control(&ping)), Some(ping));
        for observed in [
            None,
            Some("192.0.2.1:4000".parse().unwrap()),
            Some("[2001:db8::7]:1".parse().unwrap()),
        ] {
            let pong = Control::Pong { txid: 7, observed };
            assert_eq!(parse_control(&encode_control(&pong)), Some(pong));
        }
        assert_eq!(
            encode_control(&Control::Pong {
                txid: 7,
                observed: Some("192.0.2.1:4000".parse().unwrap()),
            }),
            b"\x00{\"t\":\"pong\",\"id\":\"7\",\"obs\":\"192.0.2.1:4000\"}"
        );
    }

    #[test]
    fn candack_round_trips() {
        let a = Control::CandAck { seq: 3 };
        assert_eq!(encode_control(&a), b"\x00{\"t\":\"candack\",\"seq\":\"3\"}");
        assert_eq!(parse_control(&encode_control(&a)), Some(a));
    }

    #[test]
    fn malformed_pings_pongs_and_acks_are_dropped() {
        for bad in [
            &b"{\"t\":\"ping\"}"[..],
            b"{\"t\":\"ping\",\"id\":7}",
            b"{\"t\":\"ping\",\"id\":\"07\"}",
            b"{\"t\":\"ping\",\"id\":\"18446744073709551616\"}",
            b"{\"t\":\"pong\",\"id\":\"7\",\"obs\":\"not an address\"}",
            b"{\"t\":\"pong\",\"id\":\"7\",\"obs\":4}",
            b"{\"t\":\"candack\"}",
            b"{\"t\":\"candack\",\"seq\":\"-1\"}",
        ] {
            let mut plaintext = vec![CONTROL_MARKER];
            plaintext.extend_from_slice(bad);
            assert_eq!(
                parse_control(&plaintext),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn at_most_eight_candidates_are_written() {
        let cand: Vec<Candidate> = (1..=10)
            .map(|i| Candidate::punch(format!("203.0.113.9:{i}").parse().unwrap()))
            .collect();
        let bytes = encode_control(&Control::Cand { seq: 1, cand });
        match parse_control(&bytes) {
            Some(Control::Cand { cand, .. }) => assert_eq!(cand.len(), MAX_CANDIDATES),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_questions_and_reports_of_the_old_format_are_dropped() {
        for old in [
            &b"{\"t\":\"ask\"}"[..],
            b"{\"t\":\"report\",\"rx\":[\"1\"],\"d\":0}",
        ] {
            let mut plaintext = vec![CONTROL_MARKER];
            plaintext.extend_from_slice(old);
            assert_eq!(parse_control(&plaintext), None);
        }
    }

    #[test]
    fn padding_and_unknown_members_are_ignored() {
        let want = Some(Control::Ping { txid: 1 });
        assert_eq!(parse_control(b"\x00{\"t\":\"ping\",\"id\":\"1\"}   "), want);
        assert_eq!(
            parse_control(b"\x00{\"t\":\"ping\",\"id\":\"1\",\"x\":1}"),
            want
        );
    }

    #[test]
    fn rejects_what_is_not_a_message() {
        assert_eq!(parse_control(b""), None);
        assert_eq!(parse_control(b"\x00"), None);
        assert_eq!(parse_control(b"\x00{\"t\":\"ping\",\"id\":\"1\"} x"), None);
        assert_eq!(parse_control(b"\x00\xff"), None);
    }
}
