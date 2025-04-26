//! Random index-lookup benchmark for Archive.

use super::utils::{append_random, get_archive, ArchiveType};
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

fn select_indices(reads: usize) -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut selected_indices = Vec::with_capacity(reads);
    for _ in 0..reads {
        selected_indices.push(rng.gen_range(0..ITEMS));
    }
    selected_indices
}

async fn read_serial(a: &ArchiveType, indicies: Vec<u64>) {
    for idx in indicies {
        black_box(a.get(Identifier::Index(idx)).await.unwrap().unwrap());
    }
}

async fn read_concurrent(a: &ArchiveType, indicies: Vec<u64>) {
    let mut futs = Vec::with_capacity(indicies.len());
    for idx in indicies {
        futs.push(a.get(Identifier::Index(idx)));
    }
    black_box(try_join_all(futs).await.unwrap());
}

fn bench_get_random(c: &mut Criterion) {
    // Create a config we can use across all benchmarks (with a fixed `storage_directory`).
    let cfg = Config::default();
    for compression in [None, Some(3)] {
        // Pre-populate a shared archive once.
        let writer = commonware_runtime::tokio::Runner::new(cfg.clone());
        writer.start(|ctx| async move {
            let mut a = get_archive(ctx, compression).await;
            append_random(&mut a, ITEMS).await;
            a.close().await.unwrap();
        });

        // Run the benchmarks for different read modes.
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
                c.bench_function(&label, |b| {
                    b.to_async(&runner).iter_custom(move |iters| async move {
                        let ctx = context::get::<commonware_runtime::tokio::Context>();
                        let archive = get_archive(ctx, compression).await;
                        let mut total = Duration::ZERO;

                        let selected_indices = select_indices(reads);
                        for _ in 0..iters {
                            let start = Instant::now();
                            match mode {
                                "serial" => read_serial(&archive, selected_indices.clone()).await,
                                "concurrent" => {
                                    read_concurrent(&archive, selected_indices.clone()).await
                                }
                                _ => unreachable!(),
                            }
                            total += start.elapsed();
                        }
                        total
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
    targets = bench_get_random
}
