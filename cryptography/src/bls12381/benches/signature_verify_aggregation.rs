use crate::MODULE_NAME;
use commonware_cryptography::bls12381::primitives::ops;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::{thread_rng, Rng};

fn benchmark_signature_verify_aggregation(c: &mut Criterion) {
    let namespace = b"namespace";
    for n in [10, 100, 1000, 10000, 50000].into_iter() {
        let mut msgs = Vec::with_capacity(n);
        for _ in 0..n {
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            msgs.push(msg);
        }
        let msgs = msgs.iter().map(|msg| msg.as_ref()).collect::<Vec<_>>();
        for concurrency in [1, 2, 4, 8].into_iter() {
            c.bench_function(
                &format!(
                    "{} verify_aggregate: conc={} msgs={}",
                    MODULE_NAME,
                    concurrency,
                    msgs.len()
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let (private, public) = ops::keypair(&mut thread_rng());
                            let mut signatures = Vec::with_capacity(n);
                            for msg in msgs.iter() {
                                let signature = ops::sign(&private, Some(namespace), msg);
                                signatures.push(signature);
                            }
                            (public, ops::aggregate(&signatures))
                        },
                        |(public, signature)| {
                            ops::verify_aggregate(
                                &public,
                                Some(namespace),
                                &msgs,
                                &signature,
                                concurrency,
                            )
                            .unwrap();
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_signature_verify_aggregation
}
criterion_main!(benches);
