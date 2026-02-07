use commonware_math::{fields::goldilocks::F, poly::Interpolator};
use commonware_utils::{Faults, N3f1};
use core::num::NonZeroU32;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_interpolator_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("interpolator_creation");

    for &n in &[4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096] {
        let t = N3f1::quorum(n);
        let total = NonZeroU32::new(n).unwrap();

        let points: Vec<(u32, u32)> = (0..t).map(|i| (i, i + 1)).collect();

        group.bench_with_input(
            BenchmarkId::new("naive", n),
            &(&total, &points),
            |b, (total, points)| {
                b.iter(|| {
                    let _: Interpolator<u32, F> =
                        Interpolator::roots_of_unity_naive(**total, (*points).iter().copied());
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("fast", n),
            &(&total, &points),
            |b, (total, points)| {
                b.iter(|| {
                    let _: Interpolator<u32, F> =
                        Interpolator::roots_of_unity(**total, (*points).iter().copied());
                });
            },
        );
    }

    group.finish();
}

fn bench_interpolate_value(c: &mut Criterion) {
    use commonware_parallel::Sequential;
    use commonware_utils::ordered::Map;

    let mut group = c.benchmark_group("interpolate_value");

    for &n in &[4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096] {
        let t = N3f1::quorum(n);
        let total = NonZeroU32::new(n).unwrap();

        let points: Vec<(u32, u32)> = (0..t).map(|i| (i, i + 1)).collect();
        let interpolator_naive: Interpolator<u32, F> =
            Interpolator::roots_of_unity_naive(total, points.iter().copied());
        let interpolator_fast: Interpolator<u32, F> =
            Interpolator::roots_of_unity(total, points.iter().copied());

        let evals: Map<u32, F> =
            Map::from_iter_dedup(points.iter().map(|&(i, _)| (i, F::from(i as u64 + 1))));

        group.bench_with_input(
            BenchmarkId::new("naive_weights", n),
            &(&interpolator_naive, &evals),
            |b, (interpolator, evals)| {
                b.iter(|| {
                    let _: Option<F> = interpolator.interpolate(*evals, &Sequential);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("fast_weights", n),
            &(&interpolator_fast, &evals),
            |b, (interpolator, evals)| {
                b.iter(|| {
                    let _: Option<F> = interpolator.interpolate(*evals, &Sequential);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_interpolator_creation,
    bench_interpolate_value
);
criterion_main!(benches);
