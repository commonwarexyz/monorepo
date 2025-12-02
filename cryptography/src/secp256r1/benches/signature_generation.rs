use commonware_cryptography::{secp256r1, PrivateKeyExt};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn benchmark_signature_generation<S: PrivateKeyExt>(variant: impl AsRef<str>, c: &mut Criterion) {
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
                || S::from_rng(&mut thread_rng()),
                |signer| {
                    black_box(signer.sign(namespace, &msg));
                },
                BatchSize::SmallInput,
            );
        },
    );
}

fn benchmark_standard_signature_generation(c: &mut Criterion) {
    benchmark_signature_generation::<secp256r1::standard::PrivateKey>("standard", c);
}

fn benchmark_recoverable_signature_generation(c: &mut Criterion) {
    benchmark_signature_generation::<secp256r1::recoverable::PrivateKey>("recoverable", c);
}

criterion_group!(
    benches,
    benchmark_standard_signature_generation,
    benchmark_recoverable_signature_generation
);
