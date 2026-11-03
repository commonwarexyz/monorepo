//! Summing elements one addition at a time, as when aggregating keys or signatures, compared with
//! blst.

use super::utils::Curve;
use commonware_cryptography_bls12381::group::{G1, G2};
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// Element counts.
const SIZES: [usize; 2] = [128, 1024];

fn bench<C: Curve>(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in SIZES {
        let (points, blst_points) = C::points(n, 8);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(
            format!("curve={} impl=commonware n={n}", C::NAME),
            |bencher| {
                bencher.iter(|| {
                    let mut sum = C::zero();
                    for point in black_box(&points) {
                        sum += point;
                    }
                    black_box(sum)
                })
            },
        );
        group.bench_function(format!("curve={} impl=blst n={n}", C::NAME), |bencher| {
            bencher.iter(|| {
                let mut sum = C::Blst::default();
                for point in black_box(&blst_points) {
                    sum = C::blst_add(&sum, point);
                }
                black_box(sum)
            })
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
