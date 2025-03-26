use commonware_cryptography::{ed25519::Ed25519Batch, BatchScheme, Ed25519, Signer};
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
                    let mut batch = Ed25519Batch::new();
                    let mut signer = Ed25519::new(&mut thread_rng());
                    for msg in msgs.iter() {
                        let sig = signer.sign(Some(namespace), msg);
                        assert!(batch.add(Some(namespace), msg, &signer.public_key(), &sig));
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
