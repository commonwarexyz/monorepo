use commonware_cryptography::{bls12381::scheme::Bls12381, Scheme};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::hint::black_box;

fn benchmark_signature_generation(c: &mut Criterion) {
    let namespace = b"namespace";
    let msg = b"hello";
    c.bench_function(
        &format!("ns_len={} msg_len={}", namespace.len(), msg.len()),
        |b| {
            b.iter_batched(
                Bls12381::new,
                |mut signer| {
                    black_box(signer.sign(namespace, msg));
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, benchmark_signature_generation);
criterion_main!(benches);
