use commonware_cryptography::bls12381::primitives::{self, variant::MinSig};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::NZUsize;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

fn benchmark_batch_verify_same_message(c: &mut Criterion) {
    let namespace = b"benchmark";
    let msg = b"hello";
    for n in [10, 50, 100, 200] {
        for concurrency in [1, 8] {
            let strategy = Rayon::new(NZUsize!(concurrency)).unwrap();
            c.bench_function(
                &format!("{}/n={} conc={}", module_path!(), n, concurrency),
                |b| {
                    b.iter_batched(
                        || {
                            let mut rng = StdRng::seed_from_u64(0);
                            let entries: Vec<_> = (0..n)
                                .map(|_| {
                                    let (private, public) =
                                        primitives::ops::keypair::<_, MinSig>(&mut rng);
                                    let sig = primitives::ops::sign_message::<MinSig>(
                                        &private, namespace, msg,
                                    );
                                    (public, sig)
                                })
                                .collect();
                            (rng, entries)
                        },
                        |(mut rng, entries)| {
                            let result = if concurrency == 1 {
                                black_box(
                                    primitives::ops::batch::verify_same_message::<_, MinSig, _>(
                                        &mut rng,
                                        namespace,
                                        msg,
                                        &entries,
                                        &Sequential,
                                    ),
                                )
                            } else {
                                black_box(
                                    primitives::ops::batch::verify_same_message::<_, MinSig, _>(
                                        &mut rng, namespace, msg, &entries, &strategy,
                                    ),
                                )
                            };
                            assert!(result.is_empty(), "all signatures should be valid");
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
    targets = benchmark_batch_verify_same_message
}
