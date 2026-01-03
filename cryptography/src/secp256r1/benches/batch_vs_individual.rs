use commonware_cryptography::{secp256r1, BatchVerifier, Signer as _, Verifier as _};
use commonware_math::algebra::Random;
use criterion::{criterion_group, BenchmarkId, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn benchmark_batch_vs_individual(c: &mut Criterion) {
    let namespace = b"namespace";
    let mut group = c.benchmark_group("secp256r1_batch_vs_individual");

    for n_signatures in [1, 2, 4, 8, 16, 32, 64, 128].iter() {
        let n = *n_signatures;

        let mut signers = Vec::with_capacity(n);
        let mut messages = Vec::with_capacity(n);
        let mut signatures = Vec::with_capacity(n);
        let mut public_keys = Vec::with_capacity(n);

        for _ in 0..n {
            let signer = secp256r1::recoverable::PrivateKey::random(&mut thread_rng());
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            let sig = signer.sign(namespace, &msg);
            public_keys.push(signer.public_key());
            signers.push(signer);
            messages.push(msg);
            signatures.push(sig);
        }

        group.bench_with_input(BenchmarkId::new("individual", n), &n, |b, _| {
            b.iter(|| {
                for i in 0..n {
                    black_box(public_keys[i].verify(namespace, &messages[i], &signatures[i]));
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("batch", n), &n, |b, _| {
            b.iter(|| {
                let mut batch = secp256r1::recoverable::Batch::new();
                for i in 0..n {
                    batch.add(namespace, &messages[i], &public_keys[i], &signatures[i]);
                }
                black_box(batch.verify(&mut thread_rng()));
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = benchmark_batch_vs_individual
}
