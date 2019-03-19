#[macro_use]
extern crate criterion;

use criterion::Criterion;
use hycon_rust::account::account::Account;
use hycon_rust::account::db_state::DBState;
use hycon_rust::account::node_ref::NodeRef;
use hycon_rust::account::state_node::StateNode;
use hycon_rust::traits::{Decode, Encode};
use hycon_rust::util::hash::hash;

fn state_node_encode_benchmark(c: &mut Criterion) {
    let addr_slice = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];;
    let child = vec![
        0, 28, 0, 193, 0, 226, 0, 56, 0, 123, 0, 237, 0, 5, 0, 194, 0, 184, 0, 131, 0, 152, 0, 186,
        0, 70, 0, 162, 0, 115, 0, 42,
    ];
    let node_ref = NodeRef::new(&addr_slice, &child);
    let node_refs = vec![node_ref];
    let state_node = StateNode::new(node_refs);
    c.bench_function("StateNode Encode", move |b| {
        b.iter(|| state_node.encode().unwrap())
    });
}

fn state_node_decode_benchmark(c: &mut Criterion) {
    let encoding = vec![
        10, 56, 10, 20, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 32, 137,
        28, 167, 193, 135, 226, 96, 56, 197, 123, 221, 237, 249, 5, 134, 194, 38, 184, 100, 131,
        41, 152, 47, 186, 185, 70, 18, 162, 105, 115, 14, 42,
    ];
    c.bench_function("StateNode Decode", move |b| {
        b.iter(|| {
            let _state_node = StateNode::decode(&encoding);
        })
    });
}

fn db_state_encode_benchmark(c: &mut Criterion) {
    let addr_slice = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];;
    let child = vec![
        0, 28, 0, 193, 0, 226, 0, 56, 0, 123, 0, 237, 0, 5, 0, 194, 0, 184, 0, 131, 0, 152, 0, 186,
        0, 70, 0, 162, 0, 115, 0, 42,
    ];
    let node_ref = NodeRef::new(&addr_slice, &child);
    let node_refs = vec![node_ref];
    let state_node = StateNode::new(node_refs);
    let db_state = DBState::new(None, Some(state_node), 1);
    c.bench_function("DB State Encode", move |b| {
        b.iter(|| db_state.encode().unwrap())
    });
}

fn db_state_encode_worst_case_benchmark(c: &mut Criterion) {
    let mut accounts: Vec<NodeRef> = Vec::with_capacity(256);
    for i in 0..255 {
        let db_state = DBState::new(
            Some(Account {
                balance: i * 100,
                nonce: i as u32,
            }),
            None,
            1,
        );
        let hash = hash(db_state.encode().unwrap().as_ref(), 32);
        let location = vec![
            i as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let node_ref = NodeRef::new(&location, &hash);
        accounts.push(node_ref);
    }
    let state_node = StateNode::new(accounts);
    let db_state = DBState::new(None, Some(state_node), 1);
    c.bench_function("DB State Encode: Worst Case", move |b| {
        b.iter(|| db_state.encode().unwrap())
    });
}

criterion_group!(
    benches,
    state_node_encode_benchmark,
    state_node_decode_benchmark,
    db_state_encode_benchmark,
    db_state_encode_worst_case_benchmark
);
criterion_main!(benches);
