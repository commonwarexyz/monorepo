use commonware_cryptography::{PrivateKey, secp256r1};
use commonware_utils::test_rng;
use criterion::{BatchSize, Criterion, criterion_group};
use rand::RngExt as _;
use std::hint::black_box;

fn bench_signature_generation<S: PrivateKey>(variant: impl AsRef<str>, c: &mut Criterion) {
    let mut rng = test_rng();
    let namespace = b"namespace";
    let mut msg = [0u8; 32];
    rng.fill(&mut msg);
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
                || S::random(&mut rng),
                |signer| {
                    black_box(signer.sign(namespace, &msg));
                },
                BatchSize::SmallInput,
            );
        },
    );
}

fn bench_standard_signature_generation(c: &mut Criterion) {
    bench_signature_generation::<secp256r1::standard::PrivateKey>("standard", c);
}

fn bench_recoverable_signature_generation(c: &mut Criterion) {
    bench_signature_generation::<secp256r1::recoverable::PrivateKey>("recoverable", c);
}

criterion_group!(
    benches,
    bench_standard_signature_generation,
    bench_recoverable_signature_generation
);
