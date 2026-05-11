use commonware_cryptography::{ed25519, BatchVerifier, Signer as _};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::NZUsize;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn bench_batch_verify_same_message(c: &mut Criterion) {
    let namespace = b"namespace";
    let mut msg = [0u8; 32];
    thread_rng().fill(&mut msg);
    for n_signers in [1, 10, 100, 1000, 10000].into_iter() {
        for concurrency in [1, 8] {
            c.bench_function(
                &format!("{}/pks={} conc={}", module_path!(), n_signers, concurrency),
                |b| {
                    b.iter_batched(
                        || {
                            let mut batch = ed25519::Batch::new();
                            for _ in 0..n_signers {
                                let signer = ed25519::PrivateKey::random(&mut thread_rng());
                                let sig = signer.sign(namespace, &msg);
                                assert!(batch.add(namespace, &msg, &signer.public_key(), &sig));
                            }
                            let strategy = Rayon::new(NZUsize!(concurrency)).unwrap();
                            (batch, strategy)
                        },
                        |(batch, rayon)| {
                            if concurrency > 1 {
                                black_box(batch.verify(&mut thread_rng(), &rayon))
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_batch_verify_same_message
}
