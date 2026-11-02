//! Random loss, duplication and reordering between two interfaces.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::sim::*;
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Op {
    SendAb,
    SendBa,
    Advance(u16),
    Deliver,
    Drop,
    Duplicate,
    Reverse,
    Hold,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => Just(Op::SendAb),
        3 => Just(Op::SendBa),
        4 => (1u16..30_000).prop_map(Op::Advance),
        6 => Just(Op::Deliver),
        2 => Just(Op::Drop),
        2 => Just(Op::Duplicate),
        2 => Just(Op::Reverse),
        2 => Just(Op::Hold),
    ]
}

fn unique_packet(p: &Pair, from: usize, n: u32) -> Vec<u8> {
    let (src, dst) = if from == 0 {
        (p.nodes[0].ula(), p.nodes[1].ula())
    } else {
        (p.nodes[1].ula(), p.nodes[0].ula())
    };
    ipv6(src, dst, &n.to_le_bytes())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn nothing_is_delivered_twice_or_invented_and_the_link_heals(ops in proptest::collection::vec(op(), 1..40), switch in any::<bool>()) {
        let mut p = Pair::new();
        if switch {
            p.switch_mode();
        }
        let mut sent: [HashSet<Vec<u8>>; 2] = [HashSet::new(), HashSet::new()];
        let mut inflight: Vec<Wire> = Vec::new();
        let mut counter = 0u32;
        for op in ops {
            inflight.extend(p.collect());
            match op {
                Op::SendAb | Op::SendBa => {
                    let from = usize::from(matches!(op, Op::SendBa));
                    counter += 1;
                    let pkt = unique_packet(&p, from, counter);
                    sent[from].insert(pkt.clone());
                    p.send(from, &pkt);
                }
                Op::Advance(ms) => {
                    let end = p.ms + u64::from(ms);
                    p.set_time(end);
                    let now = p.now;
                    for n in &mut p.nodes {
                        n.node.handle_timeout(now, &mut n.rng);
                    }
                }
                Op::Deliver => for w in inflight.drain(..) { p.deliver(w) },
                Op::Drop => inflight.clear(),
                Op::Duplicate => { let copy = inflight.clone(); inflight.extend(copy); }
                Op::Reverse => inflight.reverse(),
                Op::Hold => {}
            }
        }
        inflight.extend(p.collect());
        for w in inflight.drain(..) { p.deliver(w); }
        p.pump();
        for (to, from) in [(0usize, 1usize), (1, 0)] {
            let got = p.nodes[to].packets();
            let unique: HashSet<&Vec<u8>> = got.iter().collect();
            prop_assert_eq!(unique.len(), got.len(), "duplicate delivery");
            for g in &got {
                prop_assert!(sent[from].contains(g), "invented packet");
            }
        }

        let final_packet = unique_packet(&p, 0, u32::MAX);
        p.send(0, &final_packet);
        p.advance(Duration::from_secs(400));
        let heal = unique_packet(&p, 0, u32::MAX - 1);
        p.send(0, &heal);
        p.advance(Duration::from_secs(30));
        prop_assert!(p.nodes[1].packets().contains(&heal), "the link did not heal");
        let s = p.nodes[0].node.stats();
        prop_assert!(s.indices <= 12, "index leak: {s:?}");
        prop_assert!(p.nodes[1].node.stats().indices <= 12);
    }
}
