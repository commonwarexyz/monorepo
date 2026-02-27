use commonware_math::{fields::goldilocks::F, poly::Interpolator};
use commonware_utils::{ordered::BiMap, Faults, N3f1, TryFromIterator};
use core::num::NonZeroU32;
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_interpolator_creation(c: &mut Criterion) {
    for bench_type in ["naive", "fast"] {
        for &n in &[4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096] {
            let t = N3f1::quorum(n);
            let total = NonZeroU32::new(n).unwrap();
            let points = BiMap::try_from_iter((0..t).map(|i| (i, i + 1)))
                .expect("points should be in bijection");

            let label = format!(
                "{module}::interpolator_creation/type={bench_type} n={n}",
                module = module_path!()
            );
            if bench_type == "naive" {
                c.bench_function(&label, |b| {
                    b.iter(|| {
                        let _: Interpolator<u32, F> =
                            Interpolator::roots_of_unity_naive(total, points.clone());
                    });
                });
            } else {
                c.bench_function(&label, |b| {
                    b.iter(|| {
                        let _: Interpolator<u32, F> =
                            Interpolator::roots_of_unity(total, points.clone());
                    });
                });
            }
        }
    }
}

criterion_group!(benches, bench_interpolator_creation,);
criterion_main!(benches);
