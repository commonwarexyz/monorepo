use commonware_cryptography::{bls12381, BatchVerifier, Signer as _};
use commonware_math::algebra::Random;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn benchmark_batch_verify_multiple_public_keys(c: &mut Criterion) {
    let namespace = b"namespace";
    let mut msg = [0u8; 32];
    thread_rng().fill(&mut msg);
    for n_signers in [1, 10, 100, 1000, 10000].into_iter() {
        c.bench_function(&format!("{}/pks={}", module_path!(), n_signers), |b| {
            b.iter_batched(
                || {
                    let mut batch = bls12381::Batch::new();
                    for _ in 0..n_signers {
                        let signer = bls12381::PrivateKey::random(&mut thread_rng());
                        let sig = signer.sign(namespace, &msg);
                        assert!(batch.add(namespace, &msg, &signer.public_key(), &sig));
                    }
                    batch
                },
                |batch| {
                    black_box(batch.verify(&mut thread_rng()));
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_batch_verify_multiple_public_keys
);
