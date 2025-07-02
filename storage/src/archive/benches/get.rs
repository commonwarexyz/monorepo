//! Random key-lookup benchmark for Archive.

use super::utils::{append_random, ArchiveFactory, FastArchiveFactory, Key, MinimalArchiveFactory};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use commonware_storage::archive::{Archive, Identifier};
use criterion::{black_box, criterion_group, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::Instant;

/// Items pre-loaded into the archive.
const ITEMS: u64 = 250_000;

fn select_keys(keys: &[Key], reads: usize) -> Vec<Key> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut selected_keys = Vec::with_capacity(reads);
    for _ in 0..reads {
        selected_keys.push(keys[rng.gen_range(0..ITEMS as usize)].clone());
    }
    selected_keys
}

fn select_indices(reads: usize) -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut selected_indices = Vec::with_capacity(reads);
    for _ in 0..reads {
        selected_indices.push(rng.gen_range(0..ITEMS));
    }
    selected_indices
}

async fn read_serial_keys<A: Archive<Key = Key>>(a: &A, reads: &[Key]) {
    for k in reads {
        black_box(a.get(Identifier::Key(k)).await.unwrap().unwrap());
    }
}

async fn read_serial_indices<A: Archive>(a: &A, indices: &[u64]) {
    for idx in indices {
        black_box(a.get(Identifier::Index(*idx)).await.unwrap().unwrap());
    }
}

async fn read_concurrent_keys<A: Archive<Key = Key>>(a: &A, reads: Vec<Key>) {
    let futures = reads.iter().map(|k| a.get(Identifier::Key(k)));
    black_box(try_join_all(futures).await.unwrap());
}

async fn read_concurrent_indices<A: Archive>(a: &A, indices: &[u64]) {
    let mut futs = Vec::with_capacity(indices.len());
    for idx in indices {
        futs.push(a.get(Identifier::Index(*idx)));
    }
    black_box(try_join_all(futs).await.unwrap());
}

fn bench_get_for_factory<F: ArchiveFactory>(
    c: &mut Criterion,
    cfg: Config,
    compression: Option<u8>,
    keys: &[Key],
    impl_name: &str,
) {
    let runner = tokio::Runner::new(cfg.clone());
    for pattern in ["key", "index"] {
        for mode in ["serial", "concurrent"] {
            for reads in [1_000, 10_000, 50_000] {
                let label = format!(
                    "{}/impl={} mode={} pattern={} comp={} reads={}",
                    module_path!(),
                    impl_name,
                    mode,
                    pattern,
                    compression
                        .map(|l| l.to_string())
                        .unwrap_or_else(|| "off".into()),
                    reads
                );
                c.bench_function(&label, |b| {
                    let keys = keys.to_vec();
                    b.to_async(&runner).iter_custom(move |iters| {
                        let keys = keys.clone();
                        async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let archive = F::init(ctx, compression).await.unwrap();
                            if pattern == "key" {
                                let selected_keys = select_keys(&keys, reads);
                                let start = Instant::now();
                                for _ in 0..iters {
                                    match mode {
                                        "serial" => {
                                            read_serial_keys(&archive, &selected_keys).await
                                        }
                                        "concurrent" => {
                                            read_concurrent_keys(&archive, selected_keys.clone())
                                                .await
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                                start.elapsed()
                            } else {
                                let selected_indices = select_indices(reads);
                                let start = Instant::now();
                                for _ in 0..iters {
                                    match mode {
                                        "serial" => {
                                            read_serial_indices(&archive, &selected_indices).await
                                        }
                                        "concurrent" => {
                                            read_concurrent_indices(&archive, &selected_indices)
                                                .await
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                                start.elapsed()
                            }
                        }
                    });
                });
            }
        }
    }

    // Clean up shared artifacts.
    let cleaner = commonware_runtime::tokio::Runner::new(cfg);
    cleaner.start(|ctx| async move {
        let a = F::init(ctx, compression).await.unwrap();
        a.destroy().await.unwrap();
    });
}

fn bench_get(c: &mut Criterion) {
    // Create a config we can use across all benchmarks (with a fixed `storage_directory`).
    let cfg = Config::default();

    // Test fast implementation
    for compression in [None, Some(3)] {
        // Create a shared on-disk archive once so later setup is fast.
        let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
        let keys = builder.start(|ctx| async move {
            let mut a = FastArchiveFactory::init(ctx, compression).await.unwrap();
            let keys = append_random(&mut a, ITEMS).await;
            a.close().await.unwrap();
            keys
        });

        // Run the benchmarks
        bench_get_for_factory::<FastArchiveFactory>(c, cfg.clone(), compression, &keys, "fast");
    }

    // Test minimal implementation
    for compression in [None, Some(3)] {
        // Create a shared on-disk archive once so later setup is fast.
        let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
        let keys = builder.start(|ctx| async move {
            let mut a = MinimalArchiveFactory::init(ctx, compression).await.unwrap();
            let keys = append_random(&mut a, ITEMS).await;
            a.close().await.unwrap();
            keys
        });

        // Run the benchmarks
        bench_get_for_factory::<MinimalArchiveFactory>(
            c,
            cfg.clone(),
            compression,
            &keys,
            "minimal",
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_get
}
