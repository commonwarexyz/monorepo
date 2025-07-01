//! Benchmark for `Metadata` restart performance.

use super::utils::{get_metadata, get_random_kvs};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

fn bench_restart(c: &mut Criterion) {
    let cfg = Config::default();
    for &num_keys in &[100, 1_000, 10_000] {
        // Setup: create metadata and fill it.
        let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
        builder.start(|ctx| async move {
            let mut metadata = get_metadata(ctx).await;
            let kvs = get_random_kvs(num_keys, 0);
            for (k, v) in kvs {
                metadata.put(k, v);
            }
            metadata.close().await.unwrap();
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
                    let metadata = get_metadata(ctx.clone()).await;
                    total += start.elapsed();
                    metadata.close().await.unwrap();
                }
                total
            });
        });

        // Teardown
        let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
        cleaner.start(|ctx| async move {
            let metadata = get_metadata(ctx).await;
            metadata.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_restart
}
