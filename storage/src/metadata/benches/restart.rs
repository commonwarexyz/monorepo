use super::utils::{get_random_kvs, init};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

fn bench_restart(c: &mut Criterion) {
    let cfg = Config::default();
    for &num_keys in &[100, 1_000, 10_000, 100_000] {
        // Create metadata and fill it.
        let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
        builder.start(|ctx| async move {
            let mut metadata = init(ctx).await;
            let kvs = get_random_kvs(num_keys);
            for (k, v) in kvs {
                metadata.put(k, v);
            }

            // Sync twice to ensure both blobs populated
            metadata.sync().await.unwrap();
            metadata.sync().await.unwrap();
        });

        // Benchmark
        let runner = tokio::Runner::new(cfg.clone());
        c.bench_function(&format!("{}/keys={}", module_path!(), num_keys), |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    // This is the benchmarked operation
                    let _metadata = init(ctx.clone()).await;
                    total += start.elapsed();
                }
                total
            });
        });

        // Teardown
        let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
        cleaner.start(|ctx| async move {
            let metadata = init(ctx).await;
            metadata.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_restart
}
