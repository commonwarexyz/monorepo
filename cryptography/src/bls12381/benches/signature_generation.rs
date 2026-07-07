use commonware_cryptography::{bls12381, Signer as _};
use commonware_math::algebra::Random;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{rng, RngExt as _};
use std::hint::black_box;

fn bench_signature_generation(c: &mut Criterion) {
    let namespace = b"namespace";
    let mut msg = [0u8; 32];
    rng().fill(&mut msg);
    c.bench_function(
        &format!(
            "{}/ns_len={} msg_len={}",
            module_path!(),
            namespace.len(),
            msg.len()
        ),
        |b| {
            b.iter_batched(
                || bls12381::PrivateKey::random(rng()),
                |private_key| {
                    black_box(private_key.sign(namespace, &msg));
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_signature_generation);
