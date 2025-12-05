use commonware_cryptography::{ed25519, BatchVerifier, Signer as _};
use commonware_math::algebra::Random;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn benchmark_batch_verify_multiple_messages(c: &mut Criterion) {
    let namespace = b"namespace";
    for n_messages in [1, 10, 100, 1000, 10000].into_iter() {
        let mut msgs = Vec::with_capacity(n_messages);
        for _ in 0..n_messages {
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            msgs.push(msg);
        }
        c.bench_function(&format!("{}/msgs={}", module_path!(), n_messages), |b| {
            b.iter_batched(
                || {
                    let mut batch = ed25519::Batch::new();
                    let signer = ed25519::PrivateKey::random(&mut thread_rng());
                    for msg in msgs.iter() {
                        let sig = signer.sign(namespace, msg);
                        assert!(batch.add(namespace, msg, &signer.public_key(), &sig));
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_batch_verify_multiple_messages
}
