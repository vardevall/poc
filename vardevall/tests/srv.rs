//! A peer `endpoint` without a port is looked up through SRV records (vv-07 §3.5).

mod common;

use common::{Setup, ipv6};
use simple_dns::rdata::{RData, SRV};
use simple_dns::{CLASS, Name, Packet, ResourceRecord};
use tokio::net::UdpSocket;
use vardevall::{Endpoint, os_rng};
use vardevall_proto::keys::NetworkSecret;

/// Answers every SRV question with one record to `localhost:port` and remembers the names asked.
async fn resolver(
    port: u16,
) -> (
    std::net::SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (asked, names) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let Ok(query) = Packet::parse(&buf[..n]) else {
                continue;
            };
            let Some(question) = query.questions.first() else {
                continue;
            };
            let qname = question.qname.to_string();
            let _ = asked.send(qname.clone());
            let mut reply = Packet::new_reply(query.id());
            reply.questions.push(question.clone());
            reply.answers.push(ResourceRecord::new(
                Name::new(&qname).unwrap(),
                CLASS::IN,
                60,
                RData::SRV(SRV {
                    priority: 0,
                    weight: 0,
                    port,
                    target: Name::new("localhost").unwrap(),
                }),
            ));
            let _ = socket
                .send_to(&reply.build_bytes_vec().unwrap(), from)
                .await;
        }
    });
    (addr, names)
}

#[tokio::test]
async fn an_endpoint_without_a_port_reaches_the_peer_through_its_srv_record() {
    let net = NetworkSecret::generate(&mut os_rng());
    let b_setup = Setup::new(&net);
    let b_key = b_setup.public();
    let a_setup = Setup::new(&net);
    let a_key = a_setup.public();
    let mut b = b_setup.peer(a_key, None).start();
    let (dns, mut names) = resolver(b.loopback().port()).await;

    let mut a_setup = a_setup.endpoint(b_key, Endpoint::Srv("Home.Test.".to_owned()));
    a_setup.dns_servers = vec![dns];
    let a = a_setup.start();

    let packet = ipv6(a.overlay.ula, b.overlay.ula, b"through srv");
    assert!(a.handle.send_packet(&b_key, &packet));
    let (from, got) = b.packet().await;
    assert_eq!(from, a_key);
    assert_eq!(got, packet);
    assert_eq!(names.recv().await.unwrap(), "_vardevall._udp.home.test");
}
