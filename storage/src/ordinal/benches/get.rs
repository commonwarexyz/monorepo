use super::utils::{append_random, init, Ordinal};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use criterion::{criterion_group, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{hint::black_box, time::Instant};

/// Items pre-loaded into the store.
const ITEMS: u64 = 250_000;

/// Select random indices for benchmarking.
pub fn select_indices(count: usize, items: u64) -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut selected_indices = Vec::with_capacity(count);
    for _ in 0..count {
        selected_indices.push(rng.gen_range(0..items));
    }
    selected_indices
}

/// Read indices serially from an ordinal store.
pub async fn read_serial_indices(store: &Ordinal, indices: &[u64]) {
    for idx in indices {
        black_box(store.get(*idx).await.unwrap().unwrap());
    }
}

/// Read indices concurrently from an ordinal store.
pub async fn read_concurrent_indices(store: &Ordinal, indices: &[u64]) {
    let mut futures = Vec::with_capacity(indices.len());
    for idx in indices {
        futures.push(store.get(*idx));
    }
    black_box(try_join_all(futures).await.unwrap());
}

fn bench_get(c: &mut Criterion) {
    // Create a config we can use across all benchmarks (with a fixed `storage_directory`).
    let cfg = Config::default();

    // Create a shared on-disk store once so later setup is fast.
    let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
    builder.start(|ctx| async move {
        let mut store = init(ctx).await;
        append_random(&mut store, ITEMS).await;
        store.sync().await.unwrap();
    });

    // Run the benchmarks.
    let runner = tokio::Runner::new(cfg.clone());
    for mode in ["serial", "concurrent"] {
        for reads in [1_000, 10_000, 50_000] {
            let label = format!("{}/mode={} reads={}", module_path!(), mode, reads);
            c.bench_function(&label, |b| {
                b.to_async(&runner).iter_custom(move |iters| async move {
                    let ctx = context::get::<commonware_runtime::tokio::Context>();
                    let store = init(ctx).await;
                    let selected_indices = select_indices(reads, ITEMS);
                    let start = Instant::now();
                    for _ in 0..iters {
                        match mode {
                            "serial" => read_serial_indices(&store, &selected_indices).await,
                            "concurrent" => {
                                read_concurrent_indices(&store, &selected_indices).await
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
    let cleaner = commonware_runtime::tokio::Runner::new(cfg);
    cleaner.start(|ctx| async move {
        let store = init(ctx).await;
        store.destroy().await.unwrap();
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_get
}
