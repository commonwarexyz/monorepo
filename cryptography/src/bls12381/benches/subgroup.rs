use commonware_cryptography::bls12381::primitives::{
    group::{G1, Scalar},
    subgroup::batch_in_g1,
};
use commonware_math::algebra::{CryptoGroup, Random};
use commonware_utils::test_rng;
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

/// Compare batched subgroup verification against per-point checking.
fn bench_subgroup(c: &mut Criterion) {
    for n in [100usize, 1000, 6000] {
        let make = || {
            let mut rng = test_rng();
            (0..n)
                .map(|_| G1::generator() * &Scalar::random(&mut rng))
                .collect::<Vec<G1>>()
        };

        c.bench_function(&format!("{}/method=per_point n={n}", module_path!()), |b| {
            b.iter_batched(
                make,
                |points| black_box(points.iter().all(G1::in_subgroup)),
                BatchSize::SmallInput,
            );
        });

        c.bench_function(&format!("{}/method=batched n={n}", module_path!()), |b| {
            b.iter_batched(
                make,
                |points| black_box(batch_in_g1(&points, 128, &mut test_rng())),
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_subgroup
}
