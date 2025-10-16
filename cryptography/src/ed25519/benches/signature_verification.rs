use commonware_cryptography::{PrivateKeyExt as _, Signer as _, Verifier as _, ed25519};
use criterion::{BatchSize, Criterion, criterion_group};
use rand::{Rng, thread_rng};
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
                    let private_key = ed25519::PrivateKey::from_rng(&mut thread_rng());
                    let public_key = private_key.public_key();
                    let signature = private_key.sign(Some(namespace), &msg);
                    (public_key, signature)
                },
                |(public_key, signature)| {
                    black_box(public_key.verify(Some(namespace), &msg, &signature));
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
