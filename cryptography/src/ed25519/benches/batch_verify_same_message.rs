use commonware_cryptography::{BatchVerifier, Signer as _, ed25519};
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
                            let mut batch = ed25519::Batch::new(n_signers);
                            for _ in 0..n_signers {
                                let signer = ed25519::PrivateKey::random(&mut rng);
                                let sig = signer.sign(namespace, &msg);
                                assert!(batch.add(namespace, &msg, &signer.public_key(), &sig));
                            }
                            batch
                        },
                        |batch| {
                            #[allow(clippy::option_if_let_else)]
                            if let Some(rayon) = rayon.as_ref() {
                                black_box(batch.verify(&mut verify_rng, rayon))
                            } else {
                                black_box(batch.verify(&mut verify_rng, &Sequential))
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
