//! SRV lookups for an `endpoint` that names a service and no port (vv-07 §3.5, RFC 2782), and
//! address lookups whose sockets carry the node's mark.
//!
//! The system resolver API of the standard library answers A and AAAA only and opens sockets
//! that cannot be marked, so the query goes out directly to the resolvers of the configuration
//! or, failing that, those of `/etc/resolv.conf`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use simple_dns::rdata::RData;
use simple_dns::{CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, TYPE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use super::mark::SocketMark;
use super::socket::client_udp;
use super::tcp::connect_marked;

/// The service and protocol labels of the SRV name (vv-07 §3.5).
const SERVICE: &str = vardevall_proto::discovery::mdns::SERVICE_TYPE;
/// Time to wait for one resolver, over UDP and again over TCP.
const TIMEOUT: Duration = Duration::from_secs(2);
/// Most resolvers asked.
const MAX_RESOLVERS: usize = 3;
/// Most targets returned.
const MAX_TARGETS: usize = 8;
/// Largest response read.
const MAX_RESPONSE: usize = 4096;

/// The resolvers listed in `/etc/resolv.conf`; none where the file does not exist.
pub(crate) fn system_resolvers() -> Vec<SocketAddr> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    parse_resolv_conf(&text)
}

fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            (words.next()? == "nameserver").then_some(())?;
            let ip: IpAddr = words.next()?.parse().ok()?;
            Some(SocketAddr::new(ip, 53))
        })
        .collect()
}

fn query(name: &str, id: u16) -> Option<Vec<u8>> {
    let mut p = Packet::new_query(id);
    p.set_flags(PacketFlag::RECURSION_DESIRED);
    p.questions.push(Question::new(
        Name::new(name).ok()?,
        QTYPE::TYPE(TYPE::SRV),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    p.build_bytes_vec().ok()
}

/// What an answer says: the targets in the order to try.
struct Answer {
    targets: Vec<(String, u16)>,
}

fn parse_answer(bytes: &[u8], id: u16, name: &str) -> Option<Answer> {
    let p = Packet::parse(bytes).ok()?;
    if p.id() != id || !p.has_flags(PacketFlag::RESPONSE) {
        return None;
    }
    if p.rcode() != RCODE::NoError {
        return Some(Answer {
            targets: Vec::new(),
        });
    }
    let mut found: Vec<(u16, u16, String, u16)> = p
        .answers
        .iter()
        .filter(|r| r.name.to_string().eq_ignore_ascii_case(name))
        .filter_map(|r| match &r.rdata {
            RData::SRV(s) => Some((s.priority, s.weight, s.target.to_string(), s.port)),
            _ => None,
        })
        .filter(|(_, _, target, port)| !target.is_empty() && target != "." && *port != 0)
        .collect();
    found.sort_by_key(|(priority, weight, _, _)| (*priority, std::cmp::Reverse(*weight)));
    Some(Answer {
        targets: found
            .into_iter()
            .map(|(_, _, target, port)| (target, port))
            .take(MAX_TARGETS)
            .collect(),
    })
}

async fn over_udp(server: SocketAddr, request: &[u8], mark: SocketMark) -> Option<Vec<u8>> {
    let socket = UdpSocket::from_std(client_udp(server, mark).ok()?).ok()?;
    socket.send_to(request, server).await.ok()?;
    let mut buf = vec![0u8; MAX_RESPONSE];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await.ok()?;
        if from == server {
            buf.truncate(n);
            return Some(buf);
        }
    }
}

async fn over_tcp(server: SocketAddr, request: &[u8], mark: SocketMark) -> Option<Vec<u8>> {
    let mut stream = connect_marked(server, mark).await.ok()?;
    let len = u16::try_from(request.len()).ok()?;
    stream.write_all(&len.to_be_bytes()).await.ok()?;
    stream.write_all(request).await.ok()?;
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.ok()?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(head)).min(MAX_RESPONSE)];
    stream.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

/// The response of `server` to `request`, over TCP when UDP's was cut short.
async fn exchange(
    server: SocketAddr,
    request: &[u8],
    id: u16,
    mark: SocketMark,
) -> Option<Vec<u8>> {
    let udp = tokio::time::timeout(TIMEOUT, over_udp(server, request, mark))
        .await
        .ok()??;
    let p = Packet::parse(&udp).ok()?;
    if p.id() != id || !p.has_flags(PacketFlag::RESPONSE) {
        return None;
    }
    if !p.has_flags(PacketFlag::TRUNCATION) {
        return Some(udp);
    }
    tokio::time::timeout(TIMEOUT, over_tcp(server, request, mark))
        .await
        .ok()?
}

async fn ask(
    server: SocketAddr,
    request: &[u8],
    id: u16,
    name: &str,
    mark: SocketMark,
) -> Option<Vec<(String, u16)>> {
    let bytes = exchange(server, request, id, mark).await?;
    Some(parse_answer(&bytes, id, name)?.targets)
}

/// The SRV targets of `_vardevall._udp.<name>`, best first, as host names and ports; the first
/// resolver that answers decides. `resolvers` empty asks those of the system.
pub(crate) async fn srv(
    resolvers: &[SocketAddr],
    name: &str,
    mark: SocketMark,
) -> Vec<(String, u16)> {
    let name = format!(
        "{SERVICE}.{}",
        name.trim_end_matches('.').to_ascii_lowercase()
    );
    let mut id = [0u8; 2];
    let _ = getrandom::fill(&mut id);
    let id = u16::from_be_bytes(id);
    let Some(request) = query(&name, id) else {
        return Vec::new();
    };
    let system;
    let resolvers = if resolvers.is_empty() {
        system = system_resolvers();
        &system
    } else {
        resolvers
    };
    for server in resolvers.iter().take(MAX_RESOLVERS) {
        if let Some(targets) = ask(*server, &request, id, &name, mark).await {
            return targets;
        }
    }
    Vec::new()
}

fn address_query(name: &str, id: u16, kind: TYPE) -> Option<Vec<u8>> {
    let mut p = Packet::new_query(id);
    p.set_flags(PacketFlag::RECURSION_DESIRED);
    p.questions.push(Question::new(
        Name::new(name).ok()?,
        QTYPE::TYPE(kind),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    p.build_bytes_vec().ok()
}

/// The addresses of the A and AAAA records of an answer, whatever the chain of names.
fn parse_addresses(bytes: &[u8], id: u16) -> Vec<IpAddr> {
    let Ok(p) = Packet::parse(bytes) else {
        return Vec::new();
    };
    if p.id() != id || p.rcode() != RCODE::NoError {
        return Vec::new();
    }
    p.answers
        .iter()
        .filter_map(|r| match &r.rdata {
            RData::A(a) => Some(IpAddr::from(std::net::Ipv4Addr::from(a.address))),
            RData::AAAA(a) => Some(IpAddr::from(std::net::Ipv6Addr::from(a.address))),
            _ => None,
        })
        .collect()
}

async fn address_records(
    server: SocketAddr,
    name: &str,
    kind: TYPE,
    mark: SocketMark,
) -> Vec<IpAddr> {
    let mut id = [0u8; 2];
    let _ = getrandom::fill(&mut id);
    let id = u16::from_be_bytes(id);
    let Some(request) = address_query(name, id, kind) else {
        return Vec::new();
    };
    match exchange(server, &request, id, mark).await {
        Some(bytes) => parse_addresses(&bytes, id),
        None => Vec::new(),
    }
}

/// The addresses of `name` from the first resolver that has any, IPv6 first, asked with sockets
/// that carry `mark`. `resolvers` empty asks those of the system.
pub(crate) async fn addresses(
    resolvers: &[SocketAddr],
    name: &str,
    mark: SocketMark,
) -> Vec<IpAddr> {
    let system;
    let resolvers = if resolvers.is_empty() {
        system = system_resolvers();
        &system
    } else {
        resolvers
    };
    for server in resolvers.iter().take(MAX_RESOLVERS) {
        let (v6, v4) = tokio::join!(
            address_records(*server, name, TYPE::AAAA, mark),
            address_records(*server, name, TYPE::A, mark)
        );
        let mut out = v6;
        out.extend(v4);
        out.dedup();
        if !out.is_empty() {
            return out;
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use simple_dns::ResourceRecord;
    use simple_dns::rdata::SRV;

    use super::*;

    fn response(id: u16, name: &str, records: &[(u16, u16, &str, u16)]) -> Vec<u8> {
        let mut p = Packet::new_reply(id);
        p.questions.push(Question::new(
            Name::new(name).unwrap(),
            QTYPE::TYPE(TYPE::SRV),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        for (priority, weight, target, port) in records {
            p.answers.push(ResourceRecord::new(
                Name::new(name).unwrap(),
                CLASS::IN,
                60,
                RData::SRV(SRV {
                    priority: *priority,
                    weight: *weight,
                    port: *port,
                    target: Name::new(target).unwrap(),
                }),
            ));
        }
        p.build_bytes_vec().unwrap()
    }

    const NAME: &str = "_vardevall._udp.home.example";

    #[test]
    fn resolv_conf_nameservers() {
        let text = "# comment\nsearch example\nnameserver 192.0.2.53\nnameserver 2001:db8::53\nnameserver fe80::1%en0\noptions ndots:1\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec![
                "192.0.2.53:53".parse::<SocketAddr>().unwrap(),
                "[2001:db8::53]:53".parse().unwrap()
            ]
        );
    }

    #[test]
    fn targets_are_ordered_by_priority_then_weight() {
        let bytes = response(
            7,
            NAME,
            &[
                (10, 5, "b.example", 2),
                (5, 1, "a.example", 1),
                (10, 50, "c.example", 3),
                (5, 1, ".", 4),
            ],
        );
        let a = parse_answer(&bytes, 7, NAME).unwrap();
        assert_eq!(
            a.targets,
            vec![
                ("a.example".to_owned(), 1),
                ("c.example".to_owned(), 3),
                ("b.example".to_owned(), 2)
            ]
        );
    }

    #[test]
    fn answers_for_another_query_are_refused() {
        let bytes = response(7, NAME, &[(0, 0, "a.example", 1)]);
        assert!(parse_answer(&bytes, 8, NAME).is_none());
        assert!(parse_answer(&[1, 2, 3], 7, NAME).is_none());
        let other = response(7, "_other._udp.example", &[(0, 0, "a.example", 1)]);
        assert!(parse_answer(&other, 7, NAME).unwrap().targets.is_empty());
    }

    #[tokio::test]
    async fn a_resolver_is_asked_for_the_srv_name() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            let q = Packet::parse(&buf[..n]).unwrap();
            let asked = q.questions[0].qname.to_string();
            let reply = response(q.id(), &asked, &[(0, 0, "node.home.example", 51820)]);
            server.send_to(&reply, from).await.unwrap();
        });
        let targets = srv(&[addr], "Home.Example.", SocketMark::NONE).await;
        assert_eq!(targets, vec![("node.home.example".to_owned(), 51820)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_resolver_gives_nothing() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        assert!(
            srv(&[addr], "home.example", SocketMark::NONE)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_resolver_is_asked_for_both_address_families() {
        use simple_dns::rdata::{A, AAAA};
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, from) = server.recv_from(&mut buf).await.unwrap();
                let q = Packet::parse(&buf[..n]).unwrap();
                let qname = q.questions[0].qname.clone();
                let mut p = Packet::new_reply(q.id());
                p.questions.push(q.questions[0].clone());
                let rdata = if q.questions[0].qtype == QTYPE::TYPE(TYPE::A) {
                    RData::A(A {
                        address: u32::from(std::net::Ipv4Addr::new(192, 0, 2, 7)),
                    })
                } else {
                    RData::AAAA(AAAA {
                        address: u128::from("2001:db8::7".parse::<std::net::Ipv6Addr>().unwrap()),
                    })
                };
                p.answers
                    .push(simple_dns::ResourceRecord::new(qname, CLASS::IN, 60, rdata));
                server
                    .send_to(&p.build_bytes_vec().unwrap(), from)
                    .await
                    .unwrap();
            }
        });
        let found = addresses(&[addr], "node.example", SocketMark::NONE).await;
        assert_eq!(
            found,
            vec![
                "2001:db8::7".parse::<IpAddr>().unwrap(),
                "192.0.2.7".parse().unwrap()
            ]
        );
    }
}
