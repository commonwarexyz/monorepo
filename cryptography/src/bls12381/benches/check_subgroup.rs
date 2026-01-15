use commonware_cryptography::bls12381::primitives::{
    group::{Scalar, SmallScalar, G1, G2},
    ops::check::{check_g1_subgroup, check_g2_subgroup},
};
use commonware_math::algebra::{CryptoGroup, Random, Space};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::NZUsize;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::thread_rng;
use std::hint::black_box;

fn bench_check_g1_subgroup_individual(c: &mut Criterion) {
    for n in [10, 100, 1000].into_iter() {
        // Sequential individual checks
        c.bench_function(
            &format!(
                "{}/group=g1 method=individual n={} strategy=sequential",
                module_path!(),
                n
            ),
            |b| {
                b.iter_batched(
                    || {
                        let mut rng = thread_rng();
                        (0..n)
                            .map(|_| G1::generator() * &Scalar::random(&mut rng))
                            .collect::<Vec<_>>()
                    },
                    |points| {
                        black_box(check_g1_subgroup(&points, &Sequential));
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        // Parallel individual checks
        c.bench_function(
            &format!(
                "{}/group=g1 method=individual n={} strategy=parallel",
                module_path!(),
                n
            ),
            |b| {
                let strategy = Rayon::new(NZUsize!(4)).unwrap();
                b.iter_batched(
                    || {
                        let mut rng = thread_rng();
                        (0..n)
                            .map(|_| G1::generator() * &Scalar::random(&mut rng))
                            .collect::<Vec<_>>()
                    },
                    |points| {
                        black_box(check_g1_subgroup(&points, &strategy));
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

fn bench_check_g1_subgroup_batch(c: &mut Criterion) {
    for n in [10, 100, 1000].into_iter() {
        // Batch check: MSM with random scalars + single subgroup check
        c.bench_function(
            &format!("{}/group=g1 method=batch_msm n={}", module_path!(), n),
            |b| {
                let strategy = Rayon::new(NZUsize!(4)).unwrap();
                b.iter_batched(
                    || {
                        let mut rng = thread_rng();
                        let points: Vec<G1> = (0..n)
                            .map(|_| G1::generator() * &Scalar::random(&mut rng))
                            .collect();
                        let scalars: Vec<SmallScalar> =
                            (0..n).map(|_| SmallScalar::random(&mut rng)).collect();
                        (points, scalars)
                    },
                    |(points, scalars)| {
                        // MSM to compute weighted sum
                        let sum = G1::msm(&points, &scalars, &strategy);
                        // Single subgroup check on the sum
                        let _ = black_box(sum.ensure_in_subgroup());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

fn bench_check_g2_subgroup_individual(c: &mut Criterion) {
    for n in [10, 100, 1000].into_iter() {
        // Sequential individual checks
        c.bench_function(
            &format!(
                "{}/group=g2 method=individual n={} strategy=sequential",
                module_path!(),
                n
            ),
            |b| {
                b.iter_batched(
                    || {
                        let mut rng = thread_rng();
                        (0..n)
                            .map(|_| G2::generator() * &Scalar::random(&mut rng))
                            .collect::<Vec<_>>()
                    },
                    |points| {
                        black_box(check_g2_subgroup(&points, &Sequential));
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        // Parallel individual checks
        c.bench_function(
            &format!(
                "{}/group=g2 method=individual n={} strategy=parallel",
                module_path!(),
                n
            ),
            |b| {
                let strategy = Rayon::new(NZUsize!(4)).unwrap();
                b.iter_batched(
                    || {
                        let mut rng = thread_rng();
                        (0..n)
                            .map(|_| G2::generator() * &Scalar::random(&mut rng))
                            .collect::<Vec<_>>()
                    },
                    |points| {
                        black_box(check_g2_subgroup(&points, &strategy));
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

fn bench_check_g2_subgroup_batch(c: &mut Criterion) {
    for n in [10, 100, 1000].into_iter() {
        // Batch check: MSM with random scalars + single subgroup check
        c.bench_function(
            &format!("{}/group=g2 method=batch_msm n={}", module_path!(), n),
            |b| {
                let strategy = Rayon::new(NZUsize!(4)).unwrap();
                b.iter_batched(
                    || {
                        let mut rng = thread_rng();
                        let points: Vec<G2> = (0..n)
                            .map(|_| G2::generator() * &Scalar::random(&mut rng))
                            .collect();
                        let scalars: Vec<SmallScalar> =
                            (0..n).map(|_| SmallScalar::random(&mut rng)).collect();
                        (points, scalars)
                    },
                    |(points, scalars)| {
                        // MSM to compute weighted sum
                        let sum = G2::msm(&points, &scalars, &strategy);
                        // Single subgroup check on the sum
                        let _ = black_box(sum.ensure_in_subgroup());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
        bench_check_g1_subgroup_individual,
        bench_check_g1_subgroup_batch,
        bench_check_g2_subgroup_individual,
        bench_check_g2_subgroup_batch
}
