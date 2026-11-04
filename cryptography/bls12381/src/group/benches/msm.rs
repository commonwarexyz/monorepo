//! Multi-scalar multiplication on one thread, compared with blst's Pippenger method.

use super::utils::{Curve, le_bytes, scalars};
use commonware_cryptography_bls12381::group::{G1, G2};
use commonware_parallel::Sequential;
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

/// Element counts, as for threshold reconstruction and batch verification.
const SIZES: [usize; 7] = [1, 2, 8, 32, 128, 512, 2048];

fn bench<C: Curve>(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let (all_points, all_blst_points) = C::points(SIZES[SIZES.len() - 1], 6);
    for n in SIZES {
        let (points, blst_points) = (&all_points[..n], &all_blst_points[..n]);
        let scalars = scalars(n, 7);
        let blst_scalars: Vec<u8> = scalars.iter().flat_map(le_bytes).collect();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(
            format!("curve={} impl=commonware n={n}", C::NAME),
            |bencher| {
                bencher
                    .iter(|| black_box(C::msm(black_box(points), black_box(&scalars), &Sequential)))
            },
        );
        group.bench_function(format!("curve={} impl=blst n={n}", C::NAME), |bencher| {
            bencher.iter(|| {
                black_box(C::blst_msm(
                    black_box(blst_points),
                    black_box(&blst_scalars),
                ))
            })
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
