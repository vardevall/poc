//! DNS messages of the overlay resolver (vv-06 §4.3, vve-14 §3, RFC 1035).

use simple_dns::rdata::{AAAA, PTR, RData, SRV};
use simple_dns::{
    CLASS, Name, OPCODE, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, ResourceRecord, TYPE,
};

use super::Reply;
use super::names::{Decision, Kind, Names, SERVICE_TTL};

fn header_only(id: u16, rcode: RCODE) -> Option<Vec<u8>> {
    let mut p = Packet::new_reply(id);
    *p.rcode_mut() = rcode;
    p.build_bytes_vec().ok()
}

pub(super) fn reply_to(query: &Packet<'_>, rcode: RCODE, authoritative: bool) -> Packet<'static> {
    let mut p = Packet::new_reply(query.id());
    if query.has_flags(PacketFlag::RECURSION_DESIRED) {
        p.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    if authoritative {
        p.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
    }
    *p.rcode_mut() = rcode;
    for q in &query.questions {
        p.questions.push(q.clone().into_owned());
    }
    p
}

fn query_kind(q: &Question<'_>) -> Kind {
    match q.qtype {
        QTYPE::TYPE(TYPE::AAAA) => Kind::Aaaa,
        QTYPE::TYPE(TYPE::PTR) => Kind::Ptr,
        QTYPE::TYPE(TYPE::SRV) => Kind::Srv,
        _ => Kind::Other,
    }
}

fn aaaa(name: &Name<'_>, ttl: u32, ip: std::net::Ipv6Addr) -> ResourceRecord<'static> {
    ResourceRecord::new(
        name.clone().into_owned(),
        CLASS::IN,
        ttl,
        RData::AAAA(AAAA {
            address: u128::from(ip),
        }),
    )
}

/// Builds the response for a decision other than [`Decision::Forward`].
fn render(packet: &Packet<'_>, question: &Question<'_>, decision: Decision) -> Option<Vec<u8>> {
    let finish = |p: Packet<'static>| p.build_bytes_vec().ok();
    let qname = &question.qname;
    match decision {
        Decision::Addrs { addrs, ttl } => {
            let mut p = reply_to(packet, RCODE::NoError, true);
            for ip in addrs {
                p.answers.push(aaaa(qname, ttl, ip));
            }
            finish(p)
        }
        Decision::Ptr(target) => {
            let Ok(name) = Name::new(&target) else {
                return finish(reply_to(packet, RCODE::ServerFailure, true));
            };
            let mut p = reply_to(packet, RCODE::NoError, true);
            p.answers.push(ResourceRecord::new(
                qname.clone().into_owned(),
                CLASS::IN,
                vardevall_proto::addr::ANSWER_TTL,
                RData::PTR(PTR(name.into_owned())),
            ));
            finish(p)
        }
        Decision::Srv(records) => {
            let mut p = reply_to(packet, RCODE::NoError, true);
            for r in records {
                let Ok(target) = Name::new(&r.target) else {
                    return finish(reply_to(packet, RCODE::ServerFailure, true));
                };
                let target = target.into_owned();
                p.answers.push(ResourceRecord::new(
                    qname.clone().into_owned(),
                    CLASS::IN,
                    SERVICE_TTL,
                    RData::SRV(SRV {
                        priority: r.priority,
                        weight: 0,
                        port: r.port,
                        target: target.clone(),
                    }),
                ));
                p.additional_records
                    .push(aaaa(&target, SERVICE_TTL, r.addr));
            }
            finish(p)
        }
        Decision::NoData => finish(reply_to(packet, RCODE::NoError, true)),
        Decision::NxDomain => finish(reply_to(packet, RCODE::NameError, true)),
        Decision::Refused => finish(reply_to(packet, RCODE::Refused, false)),
        Decision::Forward => None,
    }
}

/// The name asked by the one question of a standard query.
pub fn question_name(bytes: &[u8]) -> Option<String> {
    let packet = Packet::parse(bytes).ok()?;
    if packet.has_flags(PacketFlag::RESPONSE) || packet.opcode() != OPCODE::StandardQuery {
        return None;
    }
    let [question] = packet.questions.as_slice() else {
        return None;
    };
    Some(question.qname.to_string())
}

/// Decides a query datagram against `names`.
pub fn respond(names: &Names<'_>, bytes: &[u8]) -> Reply {
    let packet = match Packet::parse(bytes) {
        Ok(p) => p,
        Err(_) => {
            if bytes.len() < 12 || bytes[2] & 0x80 != 0 {
                return Reply::Drop;
            }
            let id = u16::from_be_bytes([bytes[0], bytes[1]]);
            return header_only(id, RCODE::FormatError).map_or(Reply::Drop, Reply::Answer);
        }
    };
    if packet.has_flags(PacketFlag::RESPONSE) {
        return Reply::Drop;
    }
    let finish = |p: Packet<'static>| p.build_bytes_vec().map_or(Reply::Drop, Reply::Answer);
    if packet.opcode() != OPCODE::StandardQuery {
        return finish(reply_to(&packet, RCODE::NotImplemented, false));
    }
    let [question] = packet.questions.as_slice() else {
        return finish(reply_to(&packet, RCODE::FormatError, false));
    };
    if !matches!(question.qclass, QCLASS::CLASS(CLASS::IN) | QCLASS::ANY) {
        return finish(reply_to(&packet, RCODE::Refused, false));
    }
    match names.decide(&question.qname.to_string(), query_kind(question)) {
        Decision::Forward => Reply::Forward(bytes.to_vec()),
        d => render(&packet, question, d).map_or(Reply::Drop, Reply::Answer),
    }
}

/// The response to give for a forwarded `query` whose upstream answer was `response`: an
/// NXDOMAIN gives way to a name an extension answers (vv-06 §4.3).
pub fn after_forward(names: &Names<'_>, query: &[u8], response: Vec<u8>) -> Vec<u8> {
    const NXDOMAIN: u8 = 3;
    if response.len() < 12 || response[2] & 0x80 == 0 || response[3] & 0x0f != NXDOMAIN {
        return response;
    }
    let Ok(packet) = Packet::parse(query) else {
        return response;
    };
    let [question] = packet.questions.as_slice() else {
        return response;
    };
    names
        .extension(&question.qname.to_string(), query_kind(question))
        .and_then(|d| render(&packet, question, d))
        .unwrap_or(response)
}
