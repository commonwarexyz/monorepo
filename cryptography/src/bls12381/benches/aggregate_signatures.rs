use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn benchmark_aggregate_signatures(c: &mut Criterion) {
    let namespace = b"namespace";
    for n in [10, 100, 1000, 10000].into_iter() {
        let mut msgs = Vec::with_capacity(n);
        for _ in 0..n {
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            msgs.push(msg);
        }
        c.bench_function(&format!("{}/sigs={}", module_path!(), n), |b| {
            b.iter_batched(
                || {
                    let private = ops::keypair::<_, MinSig>(&mut thread_rng()).0;
                    let mut signatures = Vec::with_capacity(n);
                    for msg in msgs.iter() {
                        let signature = ops::sign_message::<MinSig>(&private, Some(namespace), msg);
                        signatures.push(signature);
                    }
                    signatures
                },
                |signatures| {
                    black_box(ops::aggregate_signatures::<MinSig, _>(&signatures));
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_aggregate_signatures
}
