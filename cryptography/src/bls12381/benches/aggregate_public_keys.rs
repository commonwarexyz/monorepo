use commonware_cryptography::bls12381::primitives::ops;
use criterion::{criterion_group, BatchSize, Criterion};
use rand::thread_rng;
use std::hint::black_box;

fn benchmark_aggregate_public_keys(c: &mut Criterion) {
    for n in [10, 100, 1000, 10000].into_iter() {
        c.bench_function(&format!("{}/pks={}", module_path!(), n), |b| {
            b.iter_batched(
                || {
                    let mut public_keys = Vec::with_capacity(n);
                    for _ in 0..n {
                        let public_key = ops::keypair(&mut thread_rng()).1;
                        public_keys.push(public_key);
                    }
                    public_keys
                },
                |public_keys| {
                    black_box(ops::aggregate_public_keys(&public_keys));
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_aggregate_public_keys
}
