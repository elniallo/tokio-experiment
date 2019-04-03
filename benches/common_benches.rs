#[macro_use]
extern crate criterion;

use criterion::Criterion;
use hycon_rust::common::address::Address;
use hycon_rust::traits::ValidAddress;

fn address_from_string_benchmark(c: &mut Criterion) {
    let address_string = "H2AekHdP6xu1i21taRty649EaV68oCfb9".to_string();
    c.bench_function("Address from string", move |b| {
        b.iter(|| Address::from_string(&address_string))
    });
}

criterion_group!(benches, address_from_string_benchmark);
criterion_main!(benches);
