use commonware_cryptography::{secp256r1, PrivateKey, Verifier};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn bench_signature_verify<S: PrivateKey>(variant: impl AsRef<str>, c: &mut Criterion) {
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
                    let private_key = S::random(&mut thread_rng());
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

fn bench_standard_signature_verify(c: &mut Criterion) {
    bench_signature_verify::<secp256r1::standard::PrivateKey>("standard", c);
}

fn bench_recoverable_signature_verify(c: &mut Criterion) {
    bench_signature_verify::<secp256r1::recoverable::PrivateKey>("recoverable", c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_standard_signature_verify, bench_recoverable_signature_verify
}
