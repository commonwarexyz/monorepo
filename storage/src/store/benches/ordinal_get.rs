//! Random index-lookup benchmark for Ordinal Store.

use super::utils::{
    append_random_ordinal, get_ordinal, read_concurrent_indices_ordinal,
    read_serial_indices_ordinal, select_indices,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use criterion::{criterion_group, Criterion};
use std::time::Instant;

/// Items pre-loaded into the store.
const ITEMS: u64 = 250_000;

fn bench_ordinal_get(c: &mut Criterion) {
    // Create a config we can use across all benchmarks (with a fixed `storage_directory`).
    let cfg = Config::default();

    // Create a shared on-disk store once so later setup is fast.
    let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
    builder.start(|ctx| async move {
        let mut store = get_ordinal(ctx).await;
        append_random_ordinal(&mut store, ITEMS).await;
        store.close().await.unwrap();
    });

    // Run the benchmarks.
    let runner = tokio::Runner::new(cfg.clone());
    for mode in ["serial", "concurrent"] {
        for reads in [1_000, 10_000, 50_000] {
            let label = format!("{}/mode={} reads={}", module_path!(), mode, reads);
            c.bench_function(&label, |b| {
                b.to_async(&runner).iter_custom(move |iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let store = get_ordinal(ctx).await;
                    let selected_indices = select_indices(reads, ITEMS);
                    let start = Instant::now();
                    for _ in 0..iters {
                        match mode {
                            "serial" => {
                                read_serial_indices_ordinal(&store, &selected_indices).await
                            }
                            "concurrent" => {
                                read_concurrent_indices_ordinal(&store, &selected_indices).await
                            }
                            _ => unreachable!(),
                        }
                    }
                    start.elapsed()
                });
            });
        }
    }

    // Clean up shared artifacts.
    let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
    cleaner.start(|ctx| async move {
        let store = get_ordinal(ctx).await;
        store.destroy().await.unwrap();
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_ordinal_get
}
