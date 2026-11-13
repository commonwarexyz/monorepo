//! Pairings with their own final exponentiations.
//!
//! One pairing uses one lane, so `n = 1` measures latency; larger `n` pair independent pairs,
//! filling every lane, as when verifying many signatures separately.

use super::utils::{pairs, strategies};
use commonware_cryptography_bls12381::{GT, pairing, pairings};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// Pair counts of the pairings of many pairs.
const SIZES: [usize; 2] = [16, 128];

fn bench_pairing(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let all_pairs = pairs(SIZES[SIZES.len() - 1]);
    group.throughput(Throughput::Elements(1));
    group.bench_function("n=1", |bencher| {
        let (p, q) = all_pairs[0];
        bencher.iter(|| black_box(pairing(black_box(&p), black_box(&q))))
    });
    let strategies = strategies();
    for n in SIZES {
        let pairs = &all_pairs[..n];
        group.throughput(Throughput::Elements(n as u64));
        for (conc, strategy) in &strategies {
            group.bench_function(format!("n={n} conc={conc}"), |bencher| {
                bencher.iter(|| {
                    let mut outputs = vec![GT::ONE; n];
                    pairings(black_box(pairs), &mut outputs, strategy);
                    black_box(outputs)
                })
            });
        }
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_pairing
}
