use commonware_cryptography::{Ed25519, Scheme};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn benchmark_signature_verify(c: &mut Criterion) {
    let namespace = b"namespace";
    let mut msg = [0u8; 32];
    thread_rng().fill(&mut msg);
    c.bench_function(
        &format!(
            "{}/ns_len={} msg_len={}",
            module_path!(),
            namespace.len(),
            msg.len()
        ),
        |b| {
            b.iter_batched(
                || {
                    let mut signer = Ed25519::new(&mut thread_rng());
                    let signature = signer.sign(Some(namespace), &msg);
                    (signer, signature)
                },
                |(signer, signature)| {
                    black_box(Ed25519::verify(
                        Some(namespace),
                        &msg,
                        &signer.public_key(),
                        &signature,
                    ));
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_signature_verify
}
