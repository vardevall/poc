//! DNS-SD records of the `_vardevall._udp` service on the wire (vv-09 §2.1, RFC 6762/6763).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use simple_dns::rdata::{A, AAAA, PTR, RData, SRV, TXT};
use simple_dns::{CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, ResourceRecord, TYPE};

use crate::mdns::SERVICE_TYPE;

/// The mDNS UDP port.
pub(super) const MDNS_PORT: u16 = 5353;
/// The IPv4 multicast group.
pub(super) const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// The IPv6 multicast group.
pub(super) const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
/// Record TTL in seconds (vv-09 §2.1).
pub(super) const TTL: u32 = 120;

fn service_name() -> String {
    format!("{SERVICE_TYPE}.local")
}

fn instance_name(instance: &str) -> String {
    format!("{instance}.{}", service_name())
}

/// What a node announces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Registration {
    /// The instance label.
    pub instance: String,
    /// The SRV port.
    pub port: u16,
    /// TXT strings.
    pub txt: Vec<(String, String)>,
}

/// A query for the service's instances (vv-09 §2.1).
pub(super) fn build_query() -> Option<Vec<u8>> {
    let name = service_name();
    let mut p = Packet::new_query(0);
    p.questions.push(Question::new(
        Name::new(&name).ok()?,
        QTYPE::TYPE(TYPE::PTR),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    p.build_bytes_vec_compressed().ok()
}

/// An announcement of `reg` with the given addresses; `ttl` 0 makes it a goodbye.
pub(super) fn build_announcement(
    reg: &Registration,
    addrs: &[IpAddr],
    ttl: u32,
) -> Option<Vec<u8>> {
    let service = service_name();
    let full = instance_name(&reg.instance);
    let host = format!("{}.local", reg.instance);
    let mut p = Packet::new_reply(0);
    p.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
    p.answers.push(ResourceRecord::new(
        Name::new(&service).ok()?,
        CLASS::IN,
        ttl,
        RData::PTR(PTR(Name::new(&full).ok()?)),
    ));
    p.additional_records.push(
        ResourceRecord::new(
            Name::new(&full).ok()?,
            CLASS::IN,
            ttl,
            RData::SRV(SRV {
                priority: 0,
                weight: 0,
                port: reg.port,
                target: Name::new(&host).ok()?,
            }),
        )
        .with_cache_flush(true),
    );
    let mut txt = TXT::new();
    let strings: Vec<String> = reg.txt.iter().map(|(k, v)| format!("{k}={v}")).collect();
    for s in &strings {
        txt.add_string(s).ok()?;
    }
    p.additional_records.push(
        ResourceRecord::new(Name::new(&full).ok()?, CLASS::IN, ttl, RData::TXT(txt))
            .with_cache_flush(true),
    );
    for ip in addrs {
        let rdata = match ip {
            IpAddr::V4(a) => RData::A(A {
                address: u32::from(*a),
            }),
            IpAddr::V6(a) => RData::AAAA(AAAA {
                address: u128::from(*a),
            }),
        };
        p.additional_records.push(
            ResourceRecord::new(Name::new(&host).ok()?, CLASS::IN, ttl, rdata)
                .with_cache_flush(true),
        );
    }
    p.build_bytes_vec_compressed().ok()
}

/// TXT strings as `key`, `value` pairs.
pub(super) type TxtStrings = Vec<(String, String)>;

/// The records of a received message that concern the service.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Parsed {
    /// Whether the message asks for the service's PTR records.
    pub asks_for_service: bool,
    /// `(instance, ttl)` of PTR records of the service.
    pub ptrs: Vec<(String, u32)>,
    /// `(instance, target host, port, ttl)` of SRV records.
    pub srvs: Vec<(String, String, u16, u32)>,
    /// `(instance, strings, ttl)` of TXT records.
    pub txts: Vec<(String, TxtStrings, u32)>,
    /// `(host, address, ttl)` of A and AAAA records.
    pub addrs: Vec<(String, IpAddr, u32)>,
}

fn instance_of(name: &str) -> Option<String> {
    let suffix = format!(".{}", service_name());
    let lower = name.to_ascii_lowercase();
    let head = lower.strip_suffix(&suffix)?;
    (!head.is_empty() && !head.contains('.')).then(|| head.to_owned())
}

/// Parses a datagram; `None` if it is not DNS.
pub(super) fn parse(bytes: &[u8]) -> Option<Parsed> {
    let packet = Packet::parse(bytes).ok()?;
    let service = service_name();
    let mut out = Parsed::default();
    for q in &packet.questions {
        let is_ptr = matches!(q.qtype, QTYPE::TYPE(TYPE::PTR) | QTYPE::ANY);
        if is_ptr && q.qname.to_string().eq_ignore_ascii_case(&service) {
            out.asks_for_service = true;
        }
    }
    let records = packet
        .answers
        .iter()
        .chain(&packet.name_servers)
        .chain(&packet.additional_records);
    for r in records {
        let name = r.name.to_string();
        match &r.rdata {
            RData::PTR(PTR(target)) if name.eq_ignore_ascii_case(&service) => {
                if let Some(i) = instance_of(&target.to_string()) {
                    out.ptrs.push((i, r.ttl));
                }
            }
            RData::SRV(s) => {
                if let Some(i) = instance_of(&name) {
                    out.srvs
                        .push((i, s.target.to_string().to_ascii_lowercase(), s.port, r.ttl));
                }
            }
            RData::TXT(t) => {
                if let Some(i) = instance_of(&name) {
                    let strings = t
                        .iter_raw()
                        .map(|(k, v)| {
                            (
                                String::from_utf8_lossy(k).into_owned(),
                                v.map(|v| String::from_utf8_lossy(v).into_owned())
                                    .unwrap_or_default(),
                            )
                        })
                        .collect();
                    out.txts.push((i, strings, r.ttl));
                }
            }
            RData::A(a) => out.addrs.push((
                name.to_ascii_lowercase(),
                IpAddr::V4(Ipv4Addr::from(a.address)),
                r.ttl,
            )),
            RData::AAAA(a) => out.addrs.push((
                name.to_ascii_lowercase(),
                IpAddr::V6(Ipv6Addr::from(a.address)),
                r.ttl,
            )),
            _ => {}
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> Registration {
        Registration {
            instance: "abcdefghijklmnop".into(),
            port: 51820,
            txt: vec![
                ("v".into(), "0".into()),
                ("n".into(), "nn".into()),
                ("k".into(), "kk".into()),
                ("p".into(), "pp".into()),
            ],
        }
    }

    #[test]
    fn announcement_round_trips() {
        let addrs: Vec<IpAddr> = vec![
            "192.168.1.2".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        ];
        let bytes = build_announcement(&reg(), &addrs, TTL).unwrap();
        let p = parse(&bytes).unwrap();
        assert_eq!(p.ptrs, vec![("abcdefghijklmnop".to_owned(), TTL)]);
        assert_eq!(p.srvs[0].2, 51820);
        assert_eq!(p.srvs[0].1, "abcdefghijklmnop.local");
        assert_eq!(p.txts[0].1, reg().txt);
        assert_eq!(p.addrs.len(), 2);
        assert!(!p.asks_for_service);
    }

    #[test]
    fn goodbye_has_zero_ttl() {
        let bytes = build_announcement(&reg(), &[], 0).unwrap();
        assert_eq!(parse(&bytes).unwrap().ptrs[0].1, 0);
    }

    #[test]
    fn query_asks_for_service() {
        let p = parse(&build_query().unwrap()).unwrap();
        assert!(p.asks_for_service);
        assert!(p.ptrs.is_empty());
    }

    #[test]
    fn garbage_is_not_dns() {
        assert!(parse(&[1, 2, 3]).is_none());
        assert!(parse(&[]).is_none());
    }
}
