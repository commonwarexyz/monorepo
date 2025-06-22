//! Random key-lookup benchmark for Immutable Store.

use crate::utils::{Immutable, Key};

use super::utils::{append_random_immutable, compression_label, get_immutable};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use criterion::{black_box, criterion_group, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::Instant;

/// Items pre-loaded into the store.
const ITEMS: u64 = 250_000;

/// Select random keys from a vec for benchmarking.
pub fn select_keys(keys: &[Key], count: usize, items: u64) -> Vec<Key> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut selected_keys = Vec::with_capacity(count);
    for _ in 0..count {
        selected_keys.push(keys[rng.gen_range(0..items as usize)].clone());
    }
    selected_keys
}

/// Read keys serially from an immutable store.
pub async fn read_serial_keys(store: &Immutable, reads: &[Key]) {
    for k in reads {
        black_box(store.get(k).await.unwrap().unwrap());
    }
}

/// Read keys concurrently from an immutable store.
pub async fn read_concurrent_keys(store: &Immutable, reads: Vec<Key>) {
    let futures = reads.iter().map(|k| store.get(k));
    black_box(try_join_all(futures).await.unwrap());
}

fn bench_immutable_get(c: &mut Criterion) {
    // Create a config we can use across all benchmarks (with a fixed `storage_directory`).
    let cfg = Config::default();
    for compression in [None, Some(3)] {
        // Create a shared on-disk store once so later setup is fast.
        let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
        let keys = builder.start(|ctx| async move {
            let mut store = get_immutable(ctx, compression).await;
            let keys = append_random_immutable(&mut store, ITEMS).await;
            store.close().await.unwrap();
            keys
        });

        // Run the benchmarks.
        let runner = tokio::Runner::new(cfg.clone());
        for mode in ["serial", "concurrent"] {
            for reads in [1_000, 10_000, 50_000] {
                let label = format!(
                    "{}/mode={} comp={} reads={}",
                    module_path!(),
                    mode,
                    compression_label(compression),
                    reads
                );
                c.bench_function(&label, |b| {
                    let keys = keys.clone();
                    b.to_async(&runner).iter_custom(move |iters| {
                        let keys = keys.clone();
                        async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let store = get_immutable(ctx, compression).await;
                            let selected_keys = select_keys(&keys, reads, ITEMS);
                            let start = Instant::now();
                            for _ in 0..iters {
                                match mode {
                                    "serial" => read_serial_keys(&store, &selected_keys).await,
                                    "concurrent" => {
                                        read_concurrent_keys(&store, selected_keys.clone()).await
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            start.elapsed()
                        }
                    });
                });
            }
        }

        // Clean up shared artifacts.
        let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
        cleaner.start(|ctx| async move {
            let store = get_immutable(ctx, compression).await;
            store.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_immutable_get
}
