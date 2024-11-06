use commonware_cryptography::bls12381::primitives::ops;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::{thread_rng, Rng};

fn benchmark_signature_verify_aggregation(c: &mut Criterion) {
    let namespace = b"namespace";
    for n in [10, 100, 1000, 10000].into_iter() {
        let mut msgs = Vec::with_capacity(n);
        for _ in 0..n {
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            msgs.push(msg);
        }
        let msgs = msgs.iter().map(|msg| msg.as_ref()).collect::<Vec<_>>();
        c.bench_function(&format!("msgs={}", msgs.len()), |b| {
            b.iter_batched(
                || {
                    let (private, public) = ops::keypair(&mut thread_rng());
                    let mut signatures = Vec::with_capacity(n);
                    for msg in msgs.iter() {
                        let signature = ops::sign(&private, namespace, msg);
                        signatures.push(signature);
                    }
                    (public, ops::aggregate(&signatures))
                },
                |(public, signature)| {
                    ops::verify_aggregate(&public, namespace, &msgs, &signature).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_signature_verify_aggregation
}
criterion_main!(benches);
