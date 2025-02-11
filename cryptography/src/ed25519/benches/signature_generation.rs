use commonware_cryptography::{Ed25519, Scheme};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn benchmark_signature_generation(c: &mut Criterion) {
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
                || Ed25519::new(&mut thread_rng()),
                |mut signer| {
                    black_box(signer.sign(Some(namespace), &msg));
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, benchmark_signature_generation);
