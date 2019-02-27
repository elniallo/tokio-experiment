#[macro_use]
extern crate criterion;

use criterion::Criterion;
use hycon_rust::util::hash::hash;

fn blake2b_hash_benchmark(c: &mut Criterion) {
    let data = vec![
        0, 28, 0, 193, 0, 226, 0, 56, 0, 123, 0, 237, 0, 5, 0, 194, 0, 184, 0, 131, 0, 152, 0, 186,
        0, 70, 0, 162, 0, 115, 0, 42,
    ];
    c.bench_function("Blake2b Hash Benchmark", move |b| {
        b.iter(|| hash(&data,32))
    });
}

criterion_group!(
    benches,
    blake2b_hash_benchmark
);
criterion_main!(benches);