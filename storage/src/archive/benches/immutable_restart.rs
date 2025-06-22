use super::utils::{append_random, compression_label, get_immutable};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use commonware_storage::archive::Archive as _;
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

fn bench_immutable_restart(c: &mut Criterion) {
    // Create a config we can use across all benchmarks (with a fixed `storage_directory`).
    let cfg = Config::default();
    for compression in [None, Some(3)] {
        for items in [10_000, 50_000, 100_000, 500_000] {
            let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
            builder.start(|ctx| async move {
                let mut a = get_immutable(ctx, compression).await;
                append_random(&mut a, items).await;
                a.close().await.unwrap();
            });

            // Run the benchmarks
            let runner = tokio::Runner::new(cfg.clone());
            let label = format!(
                "{}/items={} comp={}",
                module_path!(),
                items,
                compression_label(compression)
            );
            c.bench_function(&label, |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        let a = get_immutable(ctx.clone(), compression).await; // replay happens inside init
                        total += start.elapsed();
                        a.close().await.unwrap();
                    }
                    total
                });
            });

            // Tear down
            let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
            cleaner.start(|ctx| async move {
                let a = get_immutable(ctx, compression).await;
                a.destroy().await.unwrap();
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_immutable_restart
}
