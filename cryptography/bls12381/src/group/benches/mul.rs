//! Multiplying elements by secret scalars.
//!
//! One multiplication uses one lane, so `n = 1` measures latency; larger `n` multiply
//! independent elements by independent scalars, filling every lane, as when weighting the keys
//! of a batch of signatures.

use super::utils::{Curve, scalars};
use commonware_cryptography_bls12381::{G1, G2};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// Element counts.
const SIZES: [usize; 2] = [1, 128];

fn bench<C: Curve>(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let all_points = C::points(SIZES[SIZES.len() - 1], 5);
    let all_scalars = scalars(SIZES[SIZES.len() - 1], 6);
    for n in SIZES {
        let points = &all_points[..n];
        let scalars = &all_scalars[..n];
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("curve={} n={n}", C::NAME), |bencher| {
            if n == 1 {
                bencher.iter(|| black_box(black_box(points[0]) * black_box(&scalars[0])))
            } else {
                bencher.iter(|| {
                    let mut products = black_box(points).to_vec();
                    C::mul_each(&mut products, black_box(scalars));
                    black_box(products)
                })
            }
        });
    }
    group.finish();
}

fn bench_mul(c: &mut Criterion) {
    bench::<G1>(c);
    bench::<G2>(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_mul
}
