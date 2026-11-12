//! Products of pairings with one final exponentiation, the check behind signature verification.
//!
//! Two pairs check one signature; `n + 1` pairs check an aggregate of `n` signatures over
//! distinct messages.

use super::utils::pairs;
use commonware_cryptography_bls12381::multi_pairing;
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// Pairs in a product.
const SIZES: [usize; 3] = [2, 16, 128];

fn bench_multi_pairing(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in SIZES {
        let pairs = pairs(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("n={n}"), |bencher| {
            bencher.iter(|| black_box(multi_pairing(black_box(&pairs))))
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_multi_pairing
}
