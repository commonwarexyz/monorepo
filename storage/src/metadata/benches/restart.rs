use super::utils::{get_random_kvs, init};
use commonware_runtime::{
    Supervisor as _,
    benchmarks::{context, tokio},
};
use criterion::{Criterion, criterion_group};
use std::time::{Duration, Instant};

fn bench_restart(c: &mut Criterion) {
    for &num_keys in &[100, 1_000, 10_000, 100_000] {
        let initial_kvs = get_random_kvs(num_keys);
        let runner = tokio::Runner::default();
        c.bench_function(&format!("{}/keys={}", module_path!(), num_keys), |b| {
            b.to_async(&runner).iter_custom(|iters| {
                let initial_kvs = initial_kvs.clone();
                async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let mut metadata = init(ctx.child("setup")).await;
                        for (key, value) in &initial_kvs {
                            metadata.put(key.clone(), value.clone());
                        }
                        metadata = metadata.sync().await.unwrap();
                        metadata.sync().await.unwrap();

                        let start = Instant::now();
                        let metadata = init(ctx.child("measured")).await;
                        total += start.elapsed();

                        metadata.destroy().await.unwrap();
                    }
                    total
                }
            });
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_restart
}
