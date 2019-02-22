#[macro_use]
extern crate criterion;

use criterion::Criterion;
use hycon_rust::account::node_ref::NodeRef;
use hycon_rust::account::state_node::StateNode;
use hycon_rust::traits::Encode;

fn state_node_benchmark(c: &mut Criterion) {
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

criterion_group!(benches, state_node_benchmark);
criterion_main!(benches);
