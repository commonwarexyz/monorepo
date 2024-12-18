use commonware_cryptography::{Bls12381, Scheme};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::thread_rng;
use std::hint::black_box;

fn benchmark_signature_verification(c: &mut Criterion) {
    let namespace = b"namespace";
    let msg = b"hello";
    c.bench_function(
        &format!("ns_len={} msg_len={}", namespace.len(), msg.len()),
        |b| {
            b.iter_batched(
                || {
                    let mut signer = Bls12381::new(&mut thread_rng());
                    let signature = signer.sign(Some(namespace), msg);
                    (signer, signature)
                },
                |(signer, signature)| {
                    black_box(Bls12381::verify(
                        Some(namespace),
                        msg,
                        &signer.public_key(),
                        &signature,
                    ));
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, benchmark_signature_verification);
criterion_main!(benches);
