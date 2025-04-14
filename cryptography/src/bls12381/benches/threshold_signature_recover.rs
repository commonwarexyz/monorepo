use commonware_cryptography::bls12381::{dkg, primitives};
use commonware_utils::quorum;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use rayon::ThreadPoolBuilder;
use std::hint::black_box;

fn benchmark_threshold_signature_recover(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    let namespace = b"benchmark";
    let msg = b"hello";
    for &n in &[5, 10, 20, 50, 100, 250, 500, 1000, 1500, 2000] {
        let t = quorum(n).unwrap();
        for concurrency in [1, 2, 4, 8] {
            c.bench_function(
                &format!("{}/conc={} n={} t={}", module_path!(), concurrency, n, t),
                |b| {
                    b.iter_batched(
                        || {
                            // Create partials
                            let (_, shares) = dkg::ops::generate_shares(&mut rng, None, n, t);
                            let partials = shares
                                .iter()
                                .map(|s| {
                                    primitives::ops::partial_sign_message(s, Some(namespace), msg)
                                })
                                .collect::<Vec<_>>();

                            // Create thread pool
                            let pool = ThreadPoolBuilder::new()
                                .num_threads(concurrency)
                                .build()
                                .unwrap();
                            (partials, pool)
                        },
                        |(partials, pool)| {
                            black_box(
                                primitives::ops::threshold_signature_recover(
                                    t,
                                    partials,
                                    Some(&pool),
                                )
                                .unwrap(),
                            );
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_group!(benches, benchmark_threshold_signature_recover);
