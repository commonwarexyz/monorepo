//! Random key-lookup benchmark for Archive.

use super::utils::{append_random, get_archive, ArchiveType, Key};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Config,
    Runner,
};
use commonware_storage::archive::Identifier;
use criterion::{black_box, criterion_group, Criterion};
use futures::future::try_join_all;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::{Duration, Instant};

/// Items pre-loaded into the archive.
const ITEMS: u64 = 1_000_000;

fn select_keys(keys: &[Key], reads: usize) -> Vec<Key> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut selected_keys = Vec::with_capacity(reads);
    for _ in 0..reads {
        selected_keys.push(keys[rng.gen_range(0..ITEMS as usize)].clone());
    }
    selected_keys
}

async fn read_serial(a: &ArchiveType, reads: Vec<Key>) {
    for k in reads {
        black_box(a.get(Identifier::Key(&k)).await.unwrap().unwrap());
    }
}

async fn read_concurrent(a: &ArchiveType, reads: Vec<Key>) {
    let futures = reads.iter().map(|k| a.get(Identifier::Key(k)));
    black_box(try_join_all(futures).await.unwrap());
}

fn bench_get_random_key(c: &mut Criterion) {
    // Create a config we can use across all benchmarks (with a fixed `storage_directory`).
    let cfg = Config::default();
    for compression in [None, Some(3)] {
        // Create a shared on-disk archive once so later setup is fast.
        let builder = commonware_runtime::tokio::Runner::new(cfg.clone());
        let keys = builder.start(|ctx| async move {
            let mut a = get_archive(ctx, compression).await;
            let keys = append_random(&mut a, ITEMS).await;
            a.close().await.unwrap();
            keys
        });

        // Run the benchmarks.
        let runner = tokio::Runner::new(cfg.clone());
        for mode in ["serial", "concurrent"] {
            for reads in [1_000, 10_000, 100_000] {
                let label = format!(
                    "{}/mode={} comp={} reads={}",
                    module_path!(),
                    mode,
                    compression
                        .map(|l| l.to_string())
                        .unwrap_or_else(|| "off".into()),
                    reads
                );
                let selected_keys = select_keys(&keys, reads);
                c.bench_function(&label, |b| {
                    let selected_keys = selected_keys.clone();
                    b.to_async(&runner).iter_custom(move |iters| {
                        let selected_keys = selected_keys.clone();
                        async move {
                            let ctx = context::get::<commonware_runtime::tokio::Context>();
                            let archive = get_archive(ctx, compression).await;
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                let start = Instant::now();
                                match mode {
                                    "serial" => read_serial(&archive, selected_keys.clone()).await,
                                    "concurrent" => {
                                        read_concurrent(&archive, selected_keys.clone()).await
                                    }
                                    _ => unreachable!(),
                                }
                                total += start.elapsed();
                            }
                            total
                        }
                    });
                });
            }
        }

        // Clean up shared artifacts.
        let cleaner = commonware_runtime::tokio::Runner::new(cfg.clone());
        cleaner.start(|ctx| async move {
            let a = get_archive(ctx, compression).await;
            a.destroy().await.unwrap();
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_get_random_key
}
