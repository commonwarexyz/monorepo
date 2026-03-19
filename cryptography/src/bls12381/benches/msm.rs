use commonware_cryptography::bls12381::primitives::group::{Scalar, G1, G2};
use commonware_math::algebra::{CryptoGroup, Random, Space};
use commonware_parallel::{Rayon, Sequential};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::{hint::black_box, num::NonZeroUsize};

fn bench_msm(c: &mut Criterion) {
    let par = Rayon::new(NonZeroUsize::new(8).unwrap()).unwrap();

    for n in [10, 50, 100, 200, 1000, 5000] {
        // G1 Sequential (conc=1)
        c.bench_function(
            &format!("{}/group=g1 n={} conc=1", module_path!(), n),
            |b| {
                b.iter_batched(
                    || {
                        let mut rng = StdRng::seed_from_u64(0);
                        let points: Vec<G1> = (0..n)
                            .map(|_| G1::generator() * &Scalar::random(&mut rng))
                            .collect();
                        let scalars: Vec<Scalar> =
                            (0..n).map(|_| Scalar::random(&mut rng)).collect();
                        (points, scalars)
                    },
                    |(points, scalars)| black_box(G1::msm(&points, &scalars, &Sequential)),
                    BatchSize::SmallInput,
                );
            },
        );

        // G1 Parallel (conc=8)
        c.bench_function(
            &format!("{}/group=g1 n={} conc=8", module_path!(), n),
            |b| {
                b.iter_batched(
                    || {
                        let mut rng = StdRng::seed_from_u64(0);
                        let points: Vec<G1> = (0..n)
                            .map(|_| G1::generator() * &Scalar::random(&mut rng))
                            .collect();
                        let scalars: Vec<Scalar> =
                            (0..n).map(|_| Scalar::random(&mut rng)).collect();
                        (points, scalars)
                    },
                    |(points, scalars)| black_box(G1::msm(&points, &scalars, &par)),
                    BatchSize::SmallInput,
                );
            },
        );

        // G2 Sequential (conc=1)
        c.bench_function(
            &format!("{}/group=g2 n={} conc=1", module_path!(), n),
            |b| {
                b.iter_batched(
                    || {
                        let mut rng = StdRng::seed_from_u64(0);
                        let points: Vec<G2> = (0..n)
                            .map(|_| G2::generator() * &Scalar::random(&mut rng))
                            .collect();
                        let scalars: Vec<Scalar> =
                            (0..n).map(|_| Scalar::random(&mut rng)).collect();
                        (points, scalars)
                    },
                    |(points, scalars)| black_box(G2::msm(&points, &scalars, &Sequential)),
                    BatchSize::SmallInput,
                );
            },
        );

        // G2 Parallel (conc=8)
        c.bench_function(
            &format!("{}/group=g2 n={} conc=8", module_path!(), n),
            |b| {
                b.iter_batched(
                    || {
                        let mut rng = StdRng::seed_from_u64(0);
                        let points: Vec<G2> = (0..n)
                            .map(|_| G2::generator() * &Scalar::random(&mut rng))
                            .collect();
                        let scalars: Vec<Scalar> =
                            (0..n).map(|_| Scalar::random(&mut rng)).collect();
                        (points, scalars)
                    },
                    |(points, scalars)| black_box(G2::msm(&points, &scalars, &par)),
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_msm
}
