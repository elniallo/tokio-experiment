#[macro_use]
extern crate criterion;

use criterion::Criterion;
use hycon_rust::util::hash::{hash, hash_cryptonight};

fn blake2b_hash_benchmark(c: &mut Criterion) {
    let data = vec![
        0, 28, 0, 193, 0, 226, 0, 56, 0, 123, 0, 237, 0, 5, 0, 194, 0, 184, 0, 131, 0, 152, 0, 186,
        0, 70, 0, 162, 0, 115, 0, 42,
    ];
    c.bench_function("Blake2b Hash Benchmark", move |b| {
        b.iter(|| hash(&data, 32))
    });
}

fn cryptonight_hash_benchmark(c: &mut Criterion) {
    let data = vec![
        0, 28, 0, 193, 0, 226, 0, 56, 0, 123, 0, 237, 0, 5, 0, 194, 0, 184, 0, 131, 0, 152, 0, 186,
        0, 70, 0, 162, 0, 115, 0, 42, 90, 14, 21, 248, 16, 183, 136, 77, 231, 102, 80, 183, 192,
        177, 184, 19, 75, 226, 188, 134, 38, 218,
    ];
    let expected_prehash = vec![
        213, 155, 184, 6, 160, 192, 238, 37, 190, 172, 89, 224, 41, 36, 132, 38, 46, 5, 70, 193,
        159, 49, 130, 25, 220, 56, 238, 148, 167, 135, 240, 158, 162, 189, 223, 13, 85, 156, 251,
        105, 34, 21, 90, 14, 21, 248, 16, 183, 136, 77, 231, 102, 80, 183, 192, 177, 184, 19, 75,
        226, 188, 134, 38, 218,
    ];
    let expected_encoding = vec![
        10, 32, 223, 218, 236, 54, 245, 118, 35, 75, 80, 237, 79, 63, 61, 46, 46, 228, 77, 128,
        114, 163, 92, 252, 73, 201, 159, 108, 48, 48, 86, 233, 136, 20, 18, 32, 218, 175, 98, 56,
        136, 59, 157, 43, 178, 250, 66, 194, 50, 129, 87, 37, 147, 54, 157, 79, 238, 83, 118, 209,
        92, 202, 25, 32, 246, 230, 153, 39, 26, 32, 121, 132, 139, 154, 165, 229, 182, 152, 126,
        204, 58, 142, 150, 220, 236, 119, 144, 1, 181, 107, 19, 130, 67, 220, 241, 192, 46, 94, 69,
        215, 134, 11, 33, 0, 0, 0, 0, 0, 0, 0, 0, 40, 168, 184, 239, 233, 139, 44, 48, 0, 58, 20,
        213, 49, 13, 190, 194, 137, 35, 119, 16, 249, 57, 125, 207, 78, 117, 246, 36, 136, 151,
        210,
    ];
    let data_set = vec![data, expected_encoding, expected_prehash];
    c.bench_function_over_inputs(
        "Cryptonight Hash Benchmark",
        |b, input| b.iter(|| hash_cryptonight(&input, input.len())),
        data_set,
    );
}

criterion_group!(benches, blake2b_hash_benchmark, cryptonight_hash_benchmark);
criterion_main!(benches);
