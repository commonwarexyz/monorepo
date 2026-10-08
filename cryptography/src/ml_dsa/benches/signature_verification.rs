use commonware_cryptography::{Signer as _, Verifier as _, ml_dsa};
use commonware_math::algebra::Random;
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;
use std::hint::black_box;

fn bench_signature_verification(c: &mut Criterion) {
    let mut rng = test_rng();
    let namespace = b"namespace";
    let mut msg = [0u8; 32];
    rng.fill(&mut msg);
    let signer = ml_dsa::PrivateKey::random(&mut rng);
    let public_key = signer.public_key();
    let signature = signer.sign(namespace, &msg);
    c.bench_function(
        &format!(
            "{}/ns_len={} msg_len={}",
            module_path!(),
            namespace.len(),
            msg.len()
        ),
        |b| {
            b.iter(|| black_box(public_key.verify(namespace, &msg, &signature)));
        },
    );
}

criterion_group!(benches, bench_signature_verification);
