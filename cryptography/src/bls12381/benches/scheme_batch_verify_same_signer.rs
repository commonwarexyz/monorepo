use commonware_cryptography::{bls12381, BatchVerifier as _, Signer as _};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::NZUsize;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn bench_scheme_batch_verify_same_signer(c: &mut Criterion) {
    let namespace = b"namespace";
    for n_messages in [1, 10, 100, 1000, 10000].into_iter() {
        for concurrency in [1, 8] {
            let rayon = (concurrency > 1).then(|| Rayon::new(NZUsize!(concurrency)).unwrap());
            let mut msgs = Vec::with_capacity(n_messages);
            for _ in 0..n_messages {
                let mut msg = [0u8; 32];
                thread_rng().fill(&mut msg);
                msgs.push(msg);
            }
            c.bench_function(
                &format!(
                    "{}/msgs={} conc={}",
                    module_path!(),
                    n_messages,
                    concurrency
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let mut batch = bls12381::Batch::new();
                            let signer = bls12381::PrivateKey::random(&mut thread_rng());
                            for msg in msgs.iter() {
                                let sig = signer.sign(namespace, msg);
                                assert!(batch.add(namespace, msg, &signer.public_key(), &sig));
                            }
                            batch
                        },
                        |batch| {
                            #[allow(clippy::option_if_let_else)]
                            if let Some(rayon) = rayon.as_ref() {
                                black_box(batch.verify(&mut thread_rng(), rayon))
                            } else {
                                black_box(batch.verify(&mut thread_rng(), &Sequential))
                            }
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_scheme_batch_verify_same_signer
);
