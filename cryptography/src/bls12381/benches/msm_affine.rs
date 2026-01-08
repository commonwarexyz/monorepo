use commonware_cryptography::bls12381::primitives::group::{Scalar, G1, G2};
use commonware_math::algebra::{CryptoGroup, Random};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

fn benchmark_msm_affine(c: &mut Criterion) {
    for n in [10, 50, 100, 200] {
        c.bench_function(&format!("{}/g1 n={}", module_path!(), n), |b| {
            b.iter_batched(
                || {
                    let mut rng = StdRng::seed_from_u64(0);
                    let points: Vec<G1> = (0..n)
                        .map(|_| G1::generator() * &Scalar::random(&mut rng))
                        .collect();
                    let affine = G1::batch_to_affine(&points);
                    let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                    (affine, scalars)
                },
                |(affine, scalars)| black_box(G1::msm_affine(&affine, &scalars, 255)),
                BatchSize::SmallInput,
            );
        });

        c.bench_function(&format!("{}/g2 n={}", module_path!(), n), |b| {
            b.iter_batched(
                || {
                    let mut rng = StdRng::seed_from_u64(0);
                    let points: Vec<G2> = (0..n)
                        .map(|_| G2::generator() * &Scalar::random(&mut rng))
                        .collect();
                    let affine = G2::batch_to_affine(&points);
                    let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                    (affine, scalars)
                },
                |(affine, scalars)| black_box(G2::msm_affine(&affine, &scalars, 255)),
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_msm_affine
}
