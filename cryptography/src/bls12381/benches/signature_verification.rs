use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops,
    },
    Bls12381, Scheme,
};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn benchmark_signature_verification(c: &mut Criterion) {
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
                    let mut signer = Bls12381::new(&mut thread_rng());
                    let signature = signer.sign(Some(namespace), &msg);
                    let public = group::Public::deserialize(signer.public_key().as_ref()).unwrap();
                    let signature = group::Signature::deserialize(signature.as_ref()).unwrap();
                    (public, signature)
                },
                |(public, signature)| {
                    black_box(ops::verify_message(
                        &public,
                        Some(namespace),
                        &msg,
                        &signature,
                    ))
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, benchmark_signature_verification);
