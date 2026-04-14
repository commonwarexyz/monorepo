use super::utils::{append_random, Archive, Variant};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use commonware_storage::archive::Archive as _;
use criterion::{criterion_group, Criterion};
use std::time::{Duration, Instant};

#[cfg(not(full_bench))]
const ITEMS: [u64; 1] = [10_000];
#[cfg(full_bench)]
const ITEMS: [u64; 4] = [10_000, 50_000, 100_000, 500_000];

fn bench_restart(c: &mut Criterion) {
    let cfg = Config::default();
    for variant in [Variant::Prunable, Variant::Immutable] {
        for compression in [None, Some(3)] {
            for items in ITEMS {
                let mut initialized = false;
                let runner = tokio::Runner::new(cfg.clone());
                c.bench_function(
                    &format!(
                        "{}/variant={} items={} comp={}",
                        module_path!(),
                        variant.name(),
                        items,
                        compression
                            .map(|l| l.to_string())
                            .unwrap_or_else(|| "off".into())
                    ),
                    |b| {
                        // Setup: populate database (once, on first sample).
                        if !initialized {
                            commonware_runtime::tokio::Runner::new(Config::default()).start(
                                |ctx| async move {
                                    let mut a = Archive::init(ctx, variant, compression).await;
                                    append_random(&mut a, items).await;
                                    a.sync().await.unwrap();
                                },
                            );
                            initialized = true;
                        }

                        // Benchmark: measure restart time.
                        b.to_async(&runner).iter_custom(|iters| async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                let start = Instant::now();
                                let _a = Archive::init(ctx.clone(), variant, compression).await;
                                total += start.elapsed();
                            }
                            total
                        });
                    },
                );

                // Cleanup: destroy database.
                if initialized {
                    commonware_runtime::tokio::Runner::new(cfg.clone()).start(|ctx| async move {
                        let a = Archive::init(ctx, variant, compression).await;
                        a.destroy().await.unwrap();
                    });
                }
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_restart
}
