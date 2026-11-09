//! Summing elements, as when aggregating keys or signatures, compared with blst's bulk addition.
//!
//! The sum holds one element per lane, so every size fills the lanes.

use super::utils::Curve;
use commonware_cryptography_bls12381::{G1, G2};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// Element counts.
const SIZES: [usize; 3] = [128, 1024, 16384];

fn bench<C: Curve>(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let (all_points, all_blst_points) = C::points(SIZES[SIZES.len() - 1], 8);
    for n in SIZES {
        let (points, blst_points) = (&all_points[..n], &all_blst_points[..n]);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(
            format!("curve={} impl=commonware n={n}", C::NAME),
            |bencher| bencher.iter(|| black_box(C::sum(black_box(points)))),
        );
        group.bench_function(format!("curve={} impl=blst n={n}", C::NAME), |bencher| {
            bencher.iter(|| black_box(C::blst_sum(black_box(blst_points))))
        });
    }
    group.finish();
}

fn bench_sum(c: &mut Criterion) {
    bench::<G1>(c);
    bench::<G2>(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sum
}
