use super::utils::{append_random, init, FreezerType, Key};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use commonware_storage::freezer::Identifier;
use criterion::{criterion_group, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{hint::black_box, time::Instant};

/// Items pre-loaded into the store.
const ITEMS: u64 = 250_000;

/// Select random keys for benchmarking.
pub fn select_keys(count: usize, keys: &[Key]) -> Vec<Key> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut selected_keys = Vec::with_capacity(count);
    for _ in 0..count {
        let idx = rng.gen_range(0..keys.len());
        selected_keys.push(keys[idx].clone());
    }
    selected_keys
}

/// Select recently added keys for benchmarking.
pub fn select_recent_keys(count: usize, keys: &[Key]) -> Vec<Key> {
    let start = if keys.len() > count {
        keys.len() - count
    } else {
        0
    };
    keys[start..].to_vec()
}

/// Read keys serially from a freezer store.
pub async fn read_serial_keys(store: &FreezerType, keys: &[Key]) {
    for key in keys {
        black_box(store.get(Identifier::Key(key)).await.unwrap().unwrap());
    }
}

/// Read keys concurrently from a freezer store.
pub async fn read_concurrent_keys(store: &FreezerType, keys: &[Key]) {
    let mut futures = Vec::with_capacity(keys.len());
    for key in keys {
        futures.push(store.get(Identifier::Key(key)));
    }
    black_box(try_join_all(futures).await.unwrap());
}

fn bench_get(c: &mut Criterion) {
    // Populate the freezer with random keys
    let cfg = Config::default();
    let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
    let keys = builder.start(|ctx| async move {
        let mut store = init(ctx).await;
        let keys = append_random(&mut store, ITEMS).await;
        store.close().await.unwrap();
        keys
    });

    // Run the benchmarks
    let runner = tokio::Runner::new(cfg.clone());
    for pattern in ["random", "recent"] {
        for mode in ["serial", "concurrent"] {
            for reads in [1_000, 10_000, 50_000] {
                let label = format!(
                    "{}/pattern={} mode={} reads={}",
                    module_path!(),
                    pattern,
                    mode,
                    reads
                );
                c.bench_function(&label, |b| {
                    b.to_async(&runner).iter_custom(|iters| {
                        let keys = keys.clone();
                        async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let store = init(ctx).await;
                            let selected_keys = match pattern {
                                "random" => select_keys(reads, &keys),
                                "recent" => select_recent_keys(reads, &keys),
                                _ => unreachable!(),
                            };
                            let start = Instant::now();
                            for _ in 0..iters {
                                match mode {
                                    "serial" => read_serial_keys(&store, &selected_keys).await,
                                    "concurrent" => {
                                        read_concurrent_keys(&store, &selected_keys).await
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
    }

    // Clean up shared artifacts
    let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
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
