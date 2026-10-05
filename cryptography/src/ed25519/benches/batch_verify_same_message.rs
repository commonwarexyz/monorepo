use commonware_cryptography::{BatchEntry, BatchVerifier, Signer as _, ed25519};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, TestRng, test_rng};
use criterion::{BatchSize, Criterion, criterion_group};
use rand::RngExt as _;
use std::hint::black_box;

fn bench_batch_verify_same_message(c: &mut Criterion) {
    let mut rng = test_rng();
    let mut verify_rng = TestRng::new(1);
    let namespace = b"namespace";
    let mut msg = [0u8; 32];
    rng.fill(&mut msg);
    for n_signers in [1, 10, 100, 1000, 10000].into_iter() {
        for concurrency in [1, 8] {
            let rayon = (concurrency > 1).then(|| Rayon::new(NZUsize!(concurrency)).unwrap());
            c.bench_function(
                &format!("{}/pks={} conc={}", module_path!(), n_signers, concurrency),
                |b| {
                    b.iter_batched(
                        || {
                            (0..n_signers)
                                .map(|_| {
                                    let signer = ed25519::PrivateKey::random(&mut rng);
                                    (signer.public_key(), signer.sign(namespace, &msg))
                                })
                                .collect::<Vec<_>>()
                        },
                        |batch| {
                            #[allow(clippy::option_if_let_else)]
                            if let Some(rayon) = rayon.as_ref() {
                                black_box(ed25519::Batch::verify(
                                    &mut verify_rng,
                                    &batch,
                                    |(public_key, signature)| BatchEntry {
                                        namespace,
                                        message: &msg,
                                        public_key,
                                        signature,
                                    },
                                    rayon,
                                ))
                            } else {
                                black_box(ed25519::Batch::verify(
                                    &mut verify_rng,
                                    &batch,
                                    |(public_key, signature)| BatchEntry {
                                        namespace,
                                        message: &msg,
                                        public_key,
                                        signature,
                                    },
                                    &Sequential,
                                ))
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
    targets = bench_batch_verify_same_message
}
