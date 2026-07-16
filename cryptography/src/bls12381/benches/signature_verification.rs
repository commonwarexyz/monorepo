use commonware_cryptography::{bls12381, Signer as _, Verifier as _};
use commonware_math::algebra::Random;
use commonware_utils::test_rng;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::RngExt as _;
use std::hint::black_box;

fn bench_signature_verification(c: &mut Criterion) {
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
                || {
                    let private_key = bls12381::PrivateKey::random(&mut rng);
                    let public_key = private_key.public_key();
                    let signature = private_key.sign(namespace, &msg);
                    (public_key, signature)
                },
                |(public_key, signature)| black_box(public_key.verify(namespace, &msg, &signature)),
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_signature_verification);
