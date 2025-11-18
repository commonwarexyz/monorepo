use commonware_cryptography::bls12381::primitives::{
    group::G1,
    poly::{self, Poly},
};
use commonware_utils::quorum;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::hint::black_box;

fn benchmark_evaluate_point(c: &mut Criterion) {
    for &n in &[5, 10, 20, 50, 100, 250, 500] {
        let t = quorum(n);
        c.bench_function(&format!("{}/n={} t={}", module_path!(), n, t), |b| {
            b.iter_batched(
                || {
                    let mut rng = StdRng::seed_from_u64(0);
                    let polynomial: Poly<G1> = Poly::commit(poly::new_from(&mut rng, t - 1));
                    (rng, polynomial)
                },
                |(mut rng, polynomial)| {
                    let idx = rng.gen_range(0..n);
                    black_box(polynomial.evaluate(idx));
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_evaluate_point
}
