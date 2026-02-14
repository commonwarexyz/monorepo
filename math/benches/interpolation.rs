use commonware_math::{fields::goldilocks::F, poly::Interpolator};
use commonware_utils::{Faults, N3f1};
use core::num::NonZeroU32;
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_interpolator_creation(c: &mut Criterion) {
    for &n in &[4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096] {
        let t = N3f1::quorum(n);
        let total = NonZeroU32::new(n).unwrap();

        let points: Vec<(u32, u32)> = (0..t).map(|i| (i, i + 1)).collect();

        let naive_label = format!(
            "{module}::interpolator_creation/type=naive n={n}",
            module = module_path!()
        );
        c.bench_function(&naive_label, |b| {
            b.iter(|| {
                let _: Interpolator<u32, F> =
                    Interpolator::roots_of_unity_naive(total, points.iter().copied());
            });
        });

        let fast_label = format!(
            "{module}::interpolator_creation/type=fast n={n}",
            module = module_path!()
        );
        c.bench_function(&fast_label, |b| {
            b.iter(|| {
                let _: Interpolator<u32, F> =
                    Interpolator::roots_of_unity(total, points.iter().copied());
            });
        });
    }
}

criterion_group!(benches, bench_interpolator_creation,);
criterion_main!(benches);
