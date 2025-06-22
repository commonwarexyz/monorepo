use super::utils::{append_random, compression_label, create_benchmark_label, get_archive};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

fn bench_prunable_restart(c: &mut Criterion) {
    // Create a config we can use across all benchmarks (with a fixed `storage_directory`).
    let cfg = Config::default();
    for compression in [None, Some(3)] {
        for items in [10_000, 50_000, 100_000, 500_000] {
            let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
            builder.start(|ctx| async move {
                let mut a = get_archive(ctx, compression).await;
                append_random(&mut a, items).await;
                a.close().await.unwrap();
            });

            // Run the benchmarks
            let runner = tokio::Runner::new(cfg.clone());
            let label = create_benchmark_label(
                module_path!(),
                &[
                    ("items", items.to_string()),
                    ("comp", compression_label(compression)),
                ],
            );
            c.bench_function(&label, |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        let a = get_archive(ctx.clone(), compression).await; // replay happens inside init
                        total += start.elapsed();
                        a.close().await.unwrap();
                    }
                    total
                });
            });

            // Tear down
            let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
            cleaner.start(|ctx| async move {
                let a = get_archive(ctx, compression).await;
                a.destroy().await.unwrap();
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prunable_restart
}
