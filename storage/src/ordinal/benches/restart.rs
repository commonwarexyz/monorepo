use super::utils::{ITEMS_PER_BLOB, append_random, init};
use commonware_runtime::{
    Runner, Supervisor as _,
    benchmarks::{context, tokio},
    tokio::Config,
};
use commonware_storage::utils::bits_for_indices;
use commonware_utils::NZU64;
use criterion::{Criterion, criterion_group};
use std::time::{Duration, Instant};

fn bench_restart(c: &mut Criterion) {
    // Create a config we can use across all benchmarks (with a fixed `storage_directory`).
    let cfg = Config::default();
    for items in [10_000, 50_000, 100_000, 500_000] {
        let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
        let bits = builder.start(|ctx| async move {
            let store = init(ctx, None).await;
            let (_, indices) = append_random(store, items).await;
            bits_for_indices(NZU64!(ITEMS_PER_BLOB), indices)
        });

        // Run the benchmarks
        let runner = tokio::Runner::new(cfg.clone());
        let label = format!("{}/items={}", module_path!(), items);
        c.bench_function(&label, |b| {
            b.to_async(&runner).iter_custom(|iters| {
                let bits = bits.clone();
                async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let bits = bits
                            .iter()
                            .map(|(section, bitmap)| (*section, bitmap))
                            .collect();
                        let start = Instant::now();
                        let _store = init(ctx.child("storage"), Some(bits)).await;
                        total += start.elapsed();
                    }
                    total
                }
            });
        });

        // Tear down
        let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
        cleaner.start(|ctx| async move {
            let store = init(ctx, None).await;
            store.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_restart
}
