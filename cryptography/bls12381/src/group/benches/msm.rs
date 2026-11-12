//! Multi-scalar multiplication on one thread.

use super::utils::{Curve, scalars};
use commonware_cryptography_bls12381::{G1, G2};
use commonware_parallel::Sequential;
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// Element counts, as for threshold reconstruction and batch verification.
const SIZES: [usize; 7] = [1, 2, 8, 32, 128, 512, 2048];

fn bench<C: Curve>(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let all_points = C::points(SIZES[SIZES.len() - 1], 6);
    for n in SIZES {
        let points = &all_points[..n];
        let scalars = scalars(n, 7);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("curve={} n={n}", C::NAME), |bencher| {
            bencher.iter(|| black_box(C::msm(black_box(points), black_box(&scalars), &Sequential)))
        });
    }
    group.finish();
}

fn bench_msm(c: &mut Criterion) {
    bench::<G1>(c);
    bench::<G2>(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_msm
}
