use commonware_cryptography::bls12381::primitives::group::{Scalar, G1};
use commonware_math::{algebra::Random, poly::Poly};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{Faults, N3f1, NZUsize};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

fn bench_evaluate_point(c: &mut Criterion) {
    for &n in &[5, 10, 20, 50, 100, 250, 500] {
        let t = N3f1::quorum(n);
        for concurrency in [1, 8] {
            let strategy = Rayon::new(NZUsize!(concurrency)).unwrap();
            c.bench_function(
                &format!("{}/n={} t={} conc={}", module_path!(), n, t, concurrency),
                |b| {
                    b.iter_batched(
                        || {
                            let mut rng = StdRng::seed_from_u64(0);
                            let polynomial: Poly<G1> = Poly::commit(Poly::new(&mut rng, t - 1));
                            let scalar = Scalar::random(&mut rng);
                            (scalar, polynomial)
                        },
                        |(scalar, polynomial)| {
                            if concurrency > 1 {
                                black_box(polynomial.eval_msm(&scalar, &strategy));
                            } else {
                                black_box(polynomial.eval_msm(&scalar, &Sequential));
                            }
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_evaluate_point
}
