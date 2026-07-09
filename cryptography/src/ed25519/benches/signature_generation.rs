use commonware_cryptography::{ed25519, Signer as _};
use commonware_math::algebra::Random;
use commonware_utils::test_rng;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::RngExt as _;
use std::hint::black_box;

fn bench_signature_generation(c: &mut Criterion) {
    let mut rng = test_rng();
    let namespace = b"namespace";
    let mut msg = [0u8; 32];
    rng.fill(&mut msg);
    c.bench_function(
        &format!(
            "{}/ns_len={} msg_len={}",
            module_path!(),
            namespace.len(),
            msg.len()
        ),
        |b| {
            b.iter_batched(
                || ed25519::PrivateKey::random(&mut rng),
                |private_key| {
                    black_box(private_key.sign(namespace, &msg));
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_signature_generation);
