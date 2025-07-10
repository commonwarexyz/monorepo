use super::utils::{append_random, init};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

fn bench_restart(c: &mut Criterion) {
    let cfg = Config::default();
    for items in [10_000, 50_000, 100_000, 500_000] {
        // Populate the freezer with random keys
        let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
        builder.start(|ctx| async move {
            let mut store = init(ctx).await;
            append_random(&mut store, items).await;
            store.close().await.unwrap();
        });

        // Run the benchmarks
        let runner = tokio::Runner::new(cfg.clone());
        let label = format!("{}/items={}", module_path!(), items);
        c.bench_function(&label, |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let ctx = context::get::<commonware_runtime::tokio::Context>();
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    let store = init(ctx.clone()).await; // replay happens inside init
                    total += start.elapsed();
                    store.close().await.unwrap();
                }
                total
            });
        });

        // Tear down
        let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
        cleaner.start(|ctx| async move {
            let store = init(ctx).await;
            store.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_restart
}
