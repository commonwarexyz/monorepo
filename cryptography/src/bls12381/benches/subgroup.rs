use commonware_cryptography::bls12381::primitives::{
    group::{G1, Scalar},
    subgroup::batch_in_g1,
};
use commonware_math::algebra::{CryptoGroup, Random};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use std::{hint::black_box, num::NonZeroUsize, thread::available_parallelism};

/// Compare batched subgroup verification (serial and parallel) against
/// per-point checking.
///
/// The batched check's advantage grows with the batch, so the sizes span from
/// below the per-point fallback threshold to a batch large enough for the cost
/// model to pick its widest round. Every method reads the same batch and
/// leaves it untouched, so it is built once per size rather than per iteration
/// — at the largest size, building it costs more than checking it.
fn bench_subgroup(c: &mut Criterion) {
    let threads = available_parallelism().unwrap_or(NonZeroUsize::new(1).unwrap());
    let rayon = Rayon::new(threads).unwrap();
    for n in [100usize, 1000, 6000, 100_000] {
        let mut rng = test_rng();
        let points: Vec<G1> = (0..n)
            .map(|_| G1::generator() * &Scalar::random(&mut rng))
            .collect();

        c.bench_function(&format!("{}/method=per_point n={n}", module_path!()), |b| {
            b.iter(|| black_box(points.iter().all(G1::in_subgroup)));
        });

        c.bench_function(&format!("{}/method=serial n={n}", module_path!()), |b| {
            b.iter(|| black_box(batch_in_g1(&points, 128, &Sequential, &mut test_rng())));
        });

        c.bench_function(&format!("{}/method=parallel n={n}", module_path!()), |b| {
            b.iter(|| black_box(batch_in_g1(&points, 128, &rayon, &mut test_rng())));
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_subgroup
}
