use super::utils::{append_random, ArchiveFactory, FastArchiveFactory, MinimalArchiveFactory};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use commonware_storage::archive::Archive;
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

fn bench_restart_for_factory<F: ArchiveFactory>(
    c: &mut Criterion,
    cfg: Config,
    compression: Option<u8>,
    impl_name: &str,
) {
    for items in [10_000, 50_000, 100_000, 500_000] {
        let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
        builder.start(|ctx| async move {
            let mut a = F::init(ctx, compression).await.unwrap();
            append_random(&mut a, items).await;
            a.close().await.unwrap();
        });

        // Run the benchmarks
        let runner = tokio::Runner::new(cfg.clone());
        c.bench_function(
            &format!(
                "{}/impl={} items={} comp={}",
                module_path!(),
                impl_name,
                items,
                compression
                    .map(|l| l.to_string())
                    .unwrap_or_else(|| "off".into())
            ),
            |b| {
                b.to_async(&runner).iter_custom(|iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        let a = F::init(ctx.clone(), compression).await.unwrap(); // replay happens inside init
                        total += start.elapsed();
                        a.close().await.unwrap();
                    }
                    total
                });
            },
        );

        // Tear down
        let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
        cleaner.start(|ctx| async move {
            let a = F::init(ctx, compression).await.unwrap();
            a.destroy().await.unwrap();
        });
    }
}

fn bench_restart(c: &mut Criterion) {
    // Create a config we can use across all benchmarks (with a fixed `storage_directory`).
    let cfg = Config::default();

    // Test fast implementation
    for compression in [None, Some(3)] {
        bench_restart_for_factory::<FastArchiveFactory>(c, cfg.clone(), compression, "fast");
    }

    // Test minimal implementation
    for compression in [None, Some(3)] {
        bench_restart_for_factory::<MinimalArchiveFactory>(c, cfg.clone(), compression, "minimal");
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_restart
}
