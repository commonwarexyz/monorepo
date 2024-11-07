use commonware_cryptography::bls12381::primitives::ops;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn benchmark_signature_aggregation(c: &mut Criterion) {
    let namespace = b"namespace";
    for n in [10, 100, 1000, 10000].into_iter() {
        let mut msgs = Vec::with_capacity(n);
        for _ in 0..n {
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            msgs.push(msg);
        }
        c.bench_function(&format!("msgs={}", msgs.len()), |b| {
            b.iter_batched(
                || {
                    let private = ops::keypair(&mut thread_rng()).0;
                    let mut signatures = Vec::with_capacity(n);
                    for msg in msgs.iter() {
                        let signature = ops::sign(&private, namespace, msg);
                        signatures.push(signature);
                    }
                    signatures
                },
                |signatures| {
                    black_box(ops::aggregate(&signatures));
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_signature_aggregation
}
criterion_main!(benches);
