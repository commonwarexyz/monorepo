use commonware_cryptography::{secp256r1, PrivateKeyExt, Verifier};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn benchmark_signature_verify<S: PrivateKeyExt>(variant: impl AsRef<str>, c: &mut Criterion) {
    let namespace = b"namespace";
    let mut msg = [0u8; 32];
    thread_rng().fill(&mut msg);
    c.bench_function(
        &format!(
            "{}/variant={} ns_len={} msg_len={}",
            module_path!(),
            variant.as_ref(),
            namespace.len(),
            msg.len()
        ),
        |b| {
            b.iter_batched(
                || {
                    let private_key = S::from_rng(&mut thread_rng());
                    let public_key = private_key.public_key();
                    let signature = private_key.sign(namespace, &msg);
                    (public_key, signature)
                },
                |(public_key, signature)| {
                    black_box(public_key.verify(namespace, &msg, &signature));
                },
                BatchSize::SmallInput,
            );
        },
    );
}

fn benchmark_standard_signature_verify(c: &mut Criterion) {
    benchmark_signature_verify::<secp256r1::standard::PrivateKey>("standard", c);
}

fn benchmark_recoverable_signature_verify(c: &mut Criterion) {
    benchmark_signature_verify::<secp256r1::recoverable::PrivateKey>("recoverable", c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_standard_signature_verify, benchmark_recoverable_signature_verify
}
